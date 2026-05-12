"""SFT データセット構築。

入力: Suzaku の Finding JSON (Phase 1 出力) + (任意) Lineage NVD 抽出物
出力: JSON Lines 形式の SFT データセット

安全要件 (SPEC.md §Phase 2-A2):
- ``Finding.state == PUBLISHED`` 以外は除外 (未公開脆弱性流出防止)
- ``email_tmpl.FORBIDDEN_PHRASES`` を含むサンプルを除外
- 簡易 PII スクリーニング (メールアドレス・電話番号・JWT 風文字列を redact)
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from suzaku.herald.email_tmpl import FORBIDDEN_PHRASES

DEFAULT_INSTRUCTION = (
    "Analyze the following code excerpt for potential vulnerabilities. "
    "Return a JSON object with two keys: 'cwe_candidates' (an array of "
    "CWE-XXX strings, most-likely first, up to 3) and 'rationale' "
    "(a brief 1-2 sentence explanation). Do not include exploit code."
)


# 簡易 PII 検出 (誤検出はあるが学習除外には十分)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[\s-]?)?\(?\d{2,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")


class DatasetError(ValueError):
    """データセット構築の不変条件違反。"""


@dataclass
class DatasetSample:
    instruction: str
    input: str
    output: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_jsonl(self) -> str:
        return json.dumps(
            {
                "instruction": self.instruction,
                "input": self.input,
                "output": self.output,
                "metadata": self.metadata,
            },
            ensure_ascii=False,
        )


@dataclass
class BuildStats:
    """データセット構築の集計値。"""

    total_input: int = 0
    excluded_not_published: int = 0
    excluded_forbidden_phrase: int = 0
    excluded_missing_fields: int = 0
    accepted: int = 0
    dataset_sha256: str = ""


def redact_pii(text: str) -> str:
    """簡易 PII redact。誤検出多めだが学習データ用に十分。"""
    text = _JWT_RE.sub("<REDACTED_JWT>", text)
    text = _EMAIL_RE.sub("<REDACTED_EMAIL>", text)
    text = _PHONE_RE.sub("<REDACTED_PHONE>", text)
    return text


def _contains_forbidden(*chunks: str) -> bool:
    blob = " ".join(chunks).lower()
    return any(phrase in blob for phrase in FORBIDDEN_PHRASES)


def _hash_jsonl(samples: list[DatasetSample]) -> str:
    h = hashlib.sha256()
    for s in samples:
        h.update(s.to_jsonl().encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def build_from_findings(
    findings: list[dict[str, Any]],
    *,
    instruction: str = DEFAULT_INSTRUCTION,
    require_published: bool = True,
) -> tuple[list[DatasetSample], BuildStats]:
    """``Finding`` の dict 列から SFT サンプル列を組み立てる。

    入力 dict は :class:`~suzaku.models.Finding` を ``model_dump(mode='json')``
    した形を想定。Lineage 由来のレコードもこの形に正規化してから渡す。

    Returns:
        (samples, stats): 受理サンプルと集計値
    """
    stats = BuildStats(total_input=len(findings))
    samples: list[DatasetSample] = []

    for finding in findings:
        state = finding.get("state")
        if require_published and state != "published":
            stats.excluded_not_published += 1
            continue

        snippet = finding.get("snippet")
        cwe = finding.get("cwe")
        category = finding.get("category") or "unknown"
        if not isinstance(snippet, str) or not isinstance(cwe, str) or not snippet.strip():
            stats.excluded_missing_fields += 1
            continue

        rationale = finding.get("rationale") or f"Pattern indicative of {category}."
        if _contains_forbidden(snippet, rationale):
            stats.excluded_forbidden_phrase += 1
            continue

        clean_input = redact_pii(snippet.strip())
        clean_rationale = redact_pii(rationale.strip())

        output_obj = {
            "cwe_candidates": [cwe],
            "rationale": clean_rationale,
        }

        samples.append(
            DatasetSample(
                instruction=instruction,
                input=clean_input,
                output=json.dumps(output_obj, ensure_ascii=False),
                metadata={
                    "source": "finding",
                    "id": finding.get("id"),
                    "state": state,
                    "category": category,
                    "severity": finding.get("severity"),
                },
            )
        )

    stats.accepted = len(samples)
    stats.dataset_sha256 = _hash_jsonl(samples)
    return samples, stats


def write_jsonl(samples: list[DatasetSample], path: Path) -> Path:
    """``samples`` を JSON Lines として書き出す。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for s in samples:
            f.write(s.to_jsonl() + "\n")
    return path


def load_findings_jsonl(path: Path) -> list[dict[str, Any]]:
    """``Finding`` を 1 行 1 オブジェクトで含む JSON Lines を読む。"""
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        out.append(json.loads(line))
    return out


__all__ = [
    "DEFAULT_INSTRUCTION",
    "BuildStats",
    "DatasetError",
    "DatasetSample",
    "build_from_findings",
    "load_findings_jsonl",
    "redact_pii",
    "write_jsonl",
]
