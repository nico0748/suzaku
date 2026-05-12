"""NVD CVE 取り込み。

責務:
- ローカル JSON ファイル (NVD feed / 単一 CVE) のパース
- (オプション) NVD API 2.0 経由のオンライン取得 (LineageEgressGuard 経由)
- references から GitHub commit URL を抽出
- ``vuln_status`` ホワイトリストでフィルタ
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from suzaku.lineage.egress import assert_allowed
from suzaku.lineage.models import CVERecord

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

PUBLIC_VULN_STATUSES: frozenset[str] = frozenset(
    {"Public", "Modified", "Analyzed", "Awaiting Analysis"}
)
STRICT_PUBLIC_VULN_STATUSES: frozenset[str] = frozenset({"Public", "Modified", "Analyzed"})

GITHUB_COMMIT_RE = re.compile(
    r"https?://github\.com/[\w.-]+/[\w.-]+/commit/[0-9a-fA-F]{7,40}",
    re.IGNORECASE,
)


class NVDFilterError(ValueError):
    """ホワイトリスト外 CVE / 必須フィールド欠落の検出。"""


def _to_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _extract_cwes(cve_obj: dict[str, Any]) -> list[str]:
    cwes: list[str] = []
    for weakness in cve_obj.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if isinstance(val, str) and val.startswith("CWE-"):
                cwes.append(val)
    return cwes


def _extract_cvss(cve_obj: dict[str, Any]) -> tuple[float | None, str | None]:
    metrics = cve_obj.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries and isinstance(entries, list):
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity")
            if isinstance(score, (int, float)):
                return float(score), severity if isinstance(severity, str) else None
    return None, None


def _extract_references(cve_obj: dict[str, Any]) -> tuple[list[str], list[str]]:
    refs: list[str] = []
    commits: list[str] = []
    for ref in cve_obj.get("references", []):
        url = ref.get("url")
        if not isinstance(url, str):
            continue
        refs.append(url)
        if GITHUB_COMMIT_RE.match(url):
            commits.append(url)
    return refs, commits


def parse_cve_obj(cve_obj: dict[str, Any], *, strict_public: bool = True) -> CVERecord:
    """NVD API 2.0 の ``cve`` オブジェクトを :class:`CVERecord` に変換。"""
    cve_id = cve_obj.get("id")
    if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
        raise NVDFilterError(f"missing/invalid CVE id: {cve_id!r}")

    status = str(cve_obj.get("vulnStatus", "Public"))
    allowed = STRICT_PUBLIC_VULN_STATUSES if strict_public else PUBLIC_VULN_STATUSES
    if status not in allowed:
        raise NVDFilterError(
            f"{cve_id}: vulnStatus {status!r} is not in {sorted(allowed)}"
        )

    descriptions = cve_obj.get("descriptions", [])
    description = ""
    if isinstance(descriptions, list):
        for d in descriptions:
            if isinstance(d, dict) and d.get("lang") == "en":
                description = str(d.get("value", ""))
                break

    score, severity = _extract_cvss(cve_obj)
    refs, commits = _extract_references(cve_obj)

    return CVERecord(
        cve_id=cve_id,
        description=description,
        cwe=_extract_cwes(cve_obj),
        cvss_score=score,
        severity_label=severity,
        references=refs,  # type: ignore[arg-type]
        commit_urls=commits,  # type: ignore[arg-type]
        published_at=_to_dt(cve_obj.get("published")),
        last_modified_at=_to_dt(cve_obj.get("lastModified")),
        vuln_status=status,
    )


def load_nvd_single(path: Path, *, strict_public: bool = True) -> CVERecord:
    """単一 CVE JSON (NVD API 2.0 の ``vulnerabilities[0].cve`` を期待)。"""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and "cve" in payload:
        payload = payload["cve"]
    if isinstance(payload, dict) and "vulnerabilities" in payload:
        items = payload["vulnerabilities"]
        if not items:
            raise NVDFilterError(f"empty vulnerabilities in {path}")
        first = items[0]
        if isinstance(first, dict) and "cve" in first:
            payload = first["cve"]
    if not isinstance(payload, dict):
        raise NVDFilterError(f"unexpected NVD payload shape in {path}")
    return parse_cve_obj(payload, strict_public=strict_public)


def load_nvd_feed(path: Path, *, strict_public: bool = True) -> list[CVERecord]:
    """NVD feed JSON (``vulnerabilities`` 配列) をパース。"""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise NVDFilterError(f"unexpected NVD feed shape in {path}")
    items = payload.get("vulnerabilities", [])
    if not isinstance(items, list):
        return []
    out: list[CVERecord] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        cve = item.get("cve")
        if not isinstance(cve, dict):
            continue
        try:
            out.append(parse_cve_obj(cve, strict_public=strict_public))
        except NVDFilterError:
            continue
    return out


def fetch_nvd(
    cve_id: str,
    *,
    client: httpx.Client | None = None,
    timeout: float = 30.0,
) -> CVERecord:
    """NVD API 2.0 から 1 件取得。``LineageEgressGuard`` 経由で接続。"""
    host = urlparse(NVD_API_BASE).hostname or ""
    assert_allowed(host)

    owns = False
    if client is None:
        client = httpx.Client(timeout=timeout)
        owns = True
    try:
        response = client.get(
            NVD_API_BASE,
            params={"cveId": cve_id},
            headers={"User-Agent": "suzaku-lineage/0.1"},
        )
    finally:
        if owns:
            client.close()

    if response.status_code != 200:
        raise NVDFilterError(
            f"NVD API HTTP {response.status_code} for {cve_id}: {response.text[:200]}"
        )
    payload = response.json()
    if not isinstance(payload, dict):
        raise NVDFilterError(f"NVD API returned non-dict for {cve_id}")
    items = payload.get("vulnerabilities", [])
    if not items:
        raise NVDFilterError(f"NVD API returned no records for {cve_id}")
    cve_obj = items[0].get("cve") if isinstance(items[0], dict) else None
    if not isinstance(cve_obj, dict):
        raise NVDFilterError(f"NVD API payload missing 'cve' for {cve_id}")
    return parse_cve_obj(cve_obj)


__all__ = [
    "GITHUB_COMMIT_RE",
    "NVD_API_BASE",
    "STRICT_PUBLIC_VULN_STATUSES",
    "NVDFilterError",
    "fetch_nvd",
    "load_nvd_feed",
    "load_nvd_single",
    "parse_cve_obj",
]
