"""Lineage の Pydantic モデル。"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, Field, HttpUrl

from suzaku.models import Severity

DEFAULT_VARIANT_SEVERITY = Severity.MEDIUM


class CVERecord(BaseModel):
    """NVD から取り込んだ CVE 1 件の正規化表現。"""

    cve_id: str
    description: str
    cwe: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    severity_label: str | None = None
    references: list[HttpUrl] = Field(default_factory=list)
    commit_urls: list[HttpUrl] = Field(default_factory=list)
    published_at: datetime | None = None
    last_modified_at: datetime | None = None
    vuln_status: str = "Public"


class PatchHunk(BaseModel):
    """1 ファイル 1 hunk 単位の diff 情報。"""

    commit_url: HttpUrl
    file_path: str
    language: str = "unknown"
    deleted_lines: list[str] = Field(default_factory=list)
    added_lines: list[str] = Field(default_factory=list)
    context_before: str = ""
    context_after: str = ""


class VariantRule(BaseModel):
    """削除行から導出した検索ルール。Compass で再利用可能。"""

    rule_id: str
    derived_from_cve: str
    cwe: str
    severity: Severity = DEFAULT_VARIANT_SEVERITY
    language: str
    grep: str
    must_not_contain: str | None = None
    source_commit: HttpUrl
    rationale: str = ""


class VariantFinding(BaseModel):
    """生成ルールで対象リポをスキャンしたヒット 1 件。"""

    rule_id: str
    derived_from_cve: str
    target_repo: str
    file_path: str
    line_number: int = Field(ge=0)
    snippet: str
    similarity: float = Field(default=1.0, ge=0.0, le=1.0)


def variant_rule_dump(rule: VariantRule) -> dict[str, object]:
    """互換用ヘルパ: VariantRule -> dict (Compass Rule 互換キー)。"""
    return {
        "id": rule.rule_id,
        "cwe": rule.cwe,
        "severity": rule.severity.value,
        "language": rule.language,
        "grep": rule.grep,
        "must_not_contain": rule.must_not_contain,
        "source_commit": str(rule.source_commit),
        "derived_from_cve": rule.derived_from_cve,
    }


def variant_rule_load(payload: dict[str, object], default_path: Path | None = None) -> VariantRule:
    """JSON dict から VariantRule を復元。"""
    return VariantRule.model_validate(
        {
            "rule_id": payload.get("rule_id") or payload.get("id"),
            "derived_from_cve": payload["derived_from_cve"],
            "cwe": payload["cwe"],
            "severity": payload.get("severity", DEFAULT_VARIANT_SEVERITY.value),
            "language": payload["language"],
            "grep": payload["grep"],
            "must_not_contain": payload.get("must_not_contain"),
            "source_commit": payload["source_commit"],
            "rationale": payload.get("rationale", ""),
        }
    )


__all__ = [
    "DEFAULT_VARIANT_SEVERITY",
    "CVERecord",
    "PatchHunk",
    "VariantFinding",
    "VariantRule",
    "variant_rule_dump",
    "variant_rule_load",
]
