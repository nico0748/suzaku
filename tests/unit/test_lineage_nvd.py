"""NVD 取り込みのテスト。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import respx

from suzaku.lineage.egress import LineageEgressError
from suzaku.lineage.nvd import (
    NVD_API_BASE,
    NVDFilterError,
    fetch_nvd,
    load_nvd_feed,
    load_nvd_single,
    parse_cve_obj,
)


def _cve_obj(**overrides) -> dict:
    base = {
        "id": "CVE-2024-1234",
        "vulnStatus": "Modified",
        "descriptions": [{"lang": "en", "value": "An SSRF in widget"}],
        "weaknesses": [
            {"description": [{"value": "CWE-918"}]},
            {"description": [{"value": "NVD-CWE-noinfo"}]},
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                    }
                }
            ]
        },
        "references": [
            {"url": "https://github.com/example/x/commit/abc1234567890"},
            {"url": "https://example.com/advisory"},
        ],
        "published": "2024-01-01T00:00:00.000",
        "lastModified": "2024-02-01T00:00:00.000",
    }
    base.update(overrides)
    return base


class TestParseCveObj:
    def test_happy_path(self) -> None:
        record = parse_cve_obj(_cve_obj())
        assert record.cve_id == "CVE-2024-1234"
        assert "CWE-918" in record.cwe
        assert record.cvss_score == 7.5
        assert len(record.commit_urls) == 1

    def test_strict_public_filter(self) -> None:
        with pytest.raises(NVDFilterError):
            parse_cve_obj(_cve_obj(vulnStatus="Awaiting Analysis"))

    def test_invalid_cve_id_raises(self) -> None:
        with pytest.raises(NVDFilterError):
            parse_cve_obj(_cve_obj(id="not-a-cve"))


class TestLoadFromFile:
    def test_single_with_envelope(self, tmp_path: Path) -> None:
        envelope = {"vulnerabilities": [{"cve": _cve_obj()}]}
        p = tmp_path / "cve.json"
        p.write_text(json.dumps(envelope))
        record = load_nvd_single(p)
        assert record.cve_id == "CVE-2024-1234"

    def test_single_raw(self, tmp_path: Path) -> None:
        p = tmp_path / "cve.json"
        p.write_text(json.dumps(_cve_obj()))
        record = load_nvd_single(p)
        assert record.cve_id == "CVE-2024-1234"

    def test_feed_skips_filtered(self, tmp_path: Path) -> None:
        payload = {
            "vulnerabilities": [
                {"cve": _cve_obj()},
                {"cve": _cve_obj(id="CVE-2024-9999", vulnStatus="Awaiting Analysis")},
            ]
        }
        p = tmp_path / "feed.json"
        p.write_text(json.dumps(payload))
        records = load_nvd_feed(p)
        assert len(records) == 1
        assert records[0].cve_id == "CVE-2024-1234"


class TestFetchNvd:
    @respx.mock
    def test_happy_path(self) -> None:
        respx.get(NVD_API_BASE).respond(
            200,
            json={"vulnerabilities": [{"cve": _cve_obj()}]},
        )
        record = fetch_nvd("CVE-2024-1234")
        assert record.cve_id == "CVE-2024-1234"

    @respx.mock
    def test_4xx_raises(self) -> None:
        respx.get(NVD_API_BASE).respond(500, text="boom")
        with pytest.raises(NVDFilterError):
            fetch_nvd("CVE-2024-1234")

    @respx.mock
    def test_empty_raises(self) -> None:
        respx.get(NVD_API_BASE).respond(200, json={"vulnerabilities": []})
        with pytest.raises(NVDFilterError):
            fetch_nvd("CVE-2024-1234")


class TestFetchNvdGuard:
    def test_uses_egress_guard(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # NVD_API_BASE 自体は許可済みなので、別ホストに変えて拒否を確認
        monkeypatch.setattr(
            "suzaku.lineage.nvd.NVD_API_BASE", "https://api.openai.com/v1/cves"
        )
        with pytest.raises(LineageEgressError):
            fetch_nvd("CVE-2024-1234")
