"""Herald 5 点セット欠落チェック。

GHSA / CVE 申請に必要な 5 点を全て揃えてから submission を許可する。

5 点セット (SPEC.md §Herald):
1. 製品名・ベンダ・バージョン範囲 (semver-like)
2. CWE (CWE-79=XSS, CWE-89=SQLi, ...)
3. CVSS v3.1 ベクタ + スコア
4. PoC・再現手順 (steps.md パス)
5. 参考 URL (修正コミット / Issue / ブログ等)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from suzaku.herald.cvss import CVSSError, score_severity, score_vector

CWE_DATA_PATH = Path(__file__).parent / "data" / "cwe.json"
CWE_ID_PATTERN = re.compile(r"^CWE-\d+$")
VERSION_RANGE_PATTERN = re.compile(
    r"""^\s*
    (?:[<>]=?|=|~|\^)?         # 比較演算子 (任意)
    \s*\d+(?:\.\d+)*           # 数字版本
    (?:[-+][A-Za-z0-9.]+)?     # pre-release / build (任意)
    (?:\s*,\s*                 # 続きの範囲
       [<>]=?\s*\d+(?:\.\d+)*
       (?:[-+][A-Za-z0-9.]+)?
    )*
    \s*$""",
    re.VERBOSE,
)


class ChecklistError(ValueError):
    """5 点セットに欠落・誤りがある場合に発生。"""


@dataclass
class SubmissionInput:
    """5 点セット入力。validate_submission() で in-place 正規化される。"""

    product_name: str = ""
    vendor: str = ""
    affected_versions: str = ""
    cwe: str = ""
    cvss_vector: str = ""
    reproduction_steps_path: str = ""
    reference_urls: list[str] = field(default_factory=list)

    # 計算結果 (validate 後に埋まる)
    cvss_score: float = 0.0
    severity_label: str = ""


_cwe_cache: dict[str, dict[str, Any]] | None = None


def load_cwe_database() -> dict[str, dict[str, Any]]:
    """CWE 一覧を読み込む (キャッシュあり)。"""
    global _cwe_cache
    if _cwe_cache is None:
        _cwe_cache = json.loads(CWE_DATA_PATH.read_text(encoding="utf-8"))
    return _cwe_cache


def _normalize_cwe(value: str) -> str:
    """``"22"`` -> ``"CWE-22"``, 大文字化など。"""
    v = value.strip().upper()
    if v.isdigit():
        v = f"CWE-{v}"
    return v


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ChecklistError(message)


def validate_submission(data: SubmissionInput) -> None:
    """5 点セット完備を検証する。欠落があれば ``ChecklistError``。

    副作用: ``data.cwe`` を正規化し、``cvss_score`` / ``severity_label`` を埋める。
    """
    _require(bool(data.product_name.strip()), "Missing product_name")
    _require(bool(data.vendor.strip()), "Missing vendor")
    _require(bool(data.affected_versions.strip()), "Missing affected_versions")
    _require(
        VERSION_RANGE_PATTERN.match(data.affected_versions) is not None,
        f"Invalid version range: {data.affected_versions!r} (expect semver-like, e.g. '>=1.0.0,<1.2.3')",
    )

    _require(bool(data.cwe.strip()), "Missing cwe")
    data.cwe = _normalize_cwe(data.cwe)
    _require(
        CWE_ID_PATTERN.match(data.cwe) is not None,
        f"Invalid CWE id format: {data.cwe!r}",
    )
    db = load_cwe_database()
    _require(data.cwe in db, f"Unknown CWE id: {data.cwe!r}")

    _require(bool(data.cvss_vector.strip()), "Missing cvss_vector")
    try:
        data.cvss_score = score_vector(data.cvss_vector)
    except CVSSError as exc:
        raise ChecklistError(f"Invalid cvss_vector: {exc}") from exc
    data.severity_label = score_severity(data.cvss_score)

    _require(bool(data.reproduction_steps_path.strip()), "Missing reproduction_steps_path")

    _require(len(data.reference_urls) > 0, "At least one reference URL is required")
