"""dataset.py のテスト — 安全要件の検証を中心に。"""

from __future__ import annotations

import json
from pathlib import Path

from suzaku.reader.finetune.dataset import (
    build_from_findings,
    load_findings_jsonl,
    redact_pii,
    write_jsonl,
)


def _finding(**kw: object) -> dict:
    base = {
        "id": "F-001",
        "target_url": "https://github.com/x/y",
        "category": "ZipSlip",
        "severity": "high",
        "cwe": "CWE-22",
        "file_path": "src/extract.py",
        "line_number": 10,
        "snippet": "zipfile.ZipFile(p).extractall(dst)",
        "state": "published",
    }
    base.update(kw)
    return base


class TestRedactPII:
    def test_email(self) -> None:
        out = redact_pii("contact alice@example.com please")
        assert "alice@example.com" not in out
        assert "<REDACTED_EMAIL>" in out

    def test_jwt(self) -> None:
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.tokenpartABCDEF"
        out = redact_pii(f"token={token}")
        assert "<REDACTED_JWT>" in out

    def test_phone(self) -> None:
        out = redact_pii("call 090-1234-5678 now")
        assert "<REDACTED_PHONE>" in out


class TestBuildFromFindings:
    def test_excludes_unpublished(self) -> None:
        findings = [_finding(state="new"), _finding(state="published")]
        _samples, stats = build_from_findings(findings)
        assert stats.accepted == 1
        assert stats.excluded_not_published == 1

    def test_excludes_forbidden_phrase(self) -> None:
        findings = [
            _finding(snippet="zipfile.extract(p, d)"),
            _finding(
                id="F-002",
                snippet="zipfile.extract(p, d)  # pay first to get details",
            ),
        ]
        samples, stats = build_from_findings(findings)
        # 禁止語を含むサンプルは除外
        assert stats.excluded_forbidden_phrase == 1
        assert all(
            "pay first" not in s.input.lower() for s in samples
        )

    def test_excludes_missing_fields(self) -> None:
        bad = _finding(snippet="")
        bad.pop("cwe", None)
        findings = [bad, _finding()]
        _, stats = build_from_findings(findings)
        assert stats.excluded_missing_fields == 1
        assert stats.accepted == 1

    def test_redacts_pii_in_input(self) -> None:
        findings = [
            _finding(
                snippet="user_email = 'alice@example.com'\nzipfile.extractall(p)"
            )
        ]
        samples, _ = build_from_findings(findings)
        assert "alice@example.com" not in samples[0].input
        assert "<REDACTED_EMAIL>" in samples[0].input

    def test_output_is_valid_json(self) -> None:
        findings = [_finding()]
        samples, _ = build_from_findings(findings)
        payload = json.loads(samples[0].output)
        assert payload["cwe_candidates"] == ["CWE-22"]
        assert isinstance(payload["rationale"], str)

    def test_dataset_sha256_is_stable(self) -> None:
        findings = [_finding(), _finding(id="F-2", snippet="open(p).read()")]
        _, stats1 = build_from_findings(findings)
        _, stats2 = build_from_findings(findings)
        assert stats1.dataset_sha256 == stats2.dataset_sha256
        assert len(stats1.dataset_sha256) == 64

    def test_write_and_load_roundtrip(self, tmp_path: Path) -> None:
        findings = [_finding()]
        samples, _ = build_from_findings(findings)
        out = tmp_path / "data" / "sft.jsonl"
        write_jsonl(samples, out)
        loaded = load_findings_jsonl(out)
        assert len(loaded) == 1
        assert loaded[0]["instruction"]
