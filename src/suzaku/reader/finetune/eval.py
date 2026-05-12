"""Fine-tuned モデルの評価 (Phase 2-A2)。

評価指標:
- CWE Top-1 / Top-3 accuracy: ground truth CWE が候補の N 位以内に含まれる率
- JSON parse rate: 応答が JSON object としてパースできた率
- Forbidden phrase rate: ``email_tmpl.FORBIDDEN_PHRASES`` 混入率 (0 必須)
- Hallucinated path rate: 応答に評価入力に無いファイルパスが含まれる率

入力は SFT データセットと同じ形式の eval JSONL。``output`` フィールドの
``cwe_candidates[0]`` を正解として扱う。

Ollama 推論呼び出しは :class:`OllamaClient` を通すので、Witness Guard が発動する。
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from suzaku.herald.email_tmpl import FORBIDDEN_PHRASES
from suzaku.reader.ollama import OllamaClient

CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)
PATH_PATTERN = re.compile(r"[A-Za-z0-9_./-]+\.(py|js|ts|java|go|cpp|c|php|rb|rs)")


@dataclass
class EvalResult:
    total: int = 0
    parsed: int = 0
    top1_hits: int = 0
    top3_hits: int = 0
    forbidden_phrase_hits: int = 0
    hallucinated_path_hits: int = 0
    per_sample: list[dict[str, Any]] = field(default_factory=list)

    @property
    def parse_rate(self) -> float:
        return self.parsed / self.total if self.total else 0.0

    @property
    def top1_accuracy(self) -> float:
        return self.top1_hits / self.total if self.total else 0.0

    @property
    def top3_accuracy(self) -> float:
        return self.top3_hits / self.total if self.total else 0.0

    @property
    def forbidden_phrase_rate(self) -> float:
        return self.forbidden_phrase_hits / self.total if self.total else 0.0

    @property
    def hallucinated_path_rate(self) -> float:
        return self.hallucinated_path_hits / self.total if self.total else 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "parse_rate": round(self.parse_rate, 4),
            "top1_accuracy": round(self.top1_accuracy, 4),
            "top3_accuracy": round(self.top3_accuracy, 4),
            "forbidden_phrase_rate": round(self.forbidden_phrase_rate, 4),
            "hallucinated_path_rate": round(self.hallucinated_path_rate, 4),
        }


def _ground_truth_cwes(sample: dict[str, Any]) -> list[str]:
    raw_output = sample.get("output", "")
    try:
        payload = json.loads(raw_output) if isinstance(raw_output, str) else raw_output
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict):
        return []
    cwes = payload.get("cwe_candidates", [])
    if not isinstance(cwes, list):
        return []
    return [str(c) for c in cwes if isinstance(c, str)]


def _parse_response(text: str) -> tuple[bool, list[str]]:
    """Ollama 応答を (parsed_ok, predicted_cwes) に分解する。"""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return False, []
    if not isinstance(payload, dict):
        return False, []
    cwes = payload.get("cwe_candidates", [])
    if not isinstance(cwes, list):
        return True, []
    return True, [str(c).upper() for c in cwes if isinstance(c, str) and CWE_PATTERN.fullmatch(str(c).upper())]


def _contains_forbidden(text: str) -> bool:
    lowered = text.lower()
    return any(phrase in lowered for phrase in FORBIDDEN_PHRASES)


def _has_hallucinated_path(input_text: str, output_text: str) -> bool:
    output_paths = set(PATH_PATTERN.findall(output_text))
    if not output_paths:
        return False
    input_paths = set(PATH_PATTERN.findall(input_text))
    # output に登場するパスが input に無ければハルシネーション扱い
    return bool(output_paths - input_paths)


def evaluate(
    samples: Iterable[dict[str, Any]],
    client: OllamaClient,
    *,
    record_per_sample: bool = False,
) -> EvalResult:
    """JSONL 風サンプル列に対し Ollama 推論を行い ``EvalResult`` を返す。"""
    result = EvalResult()
    for sample in samples:
        result.total += 1
        instruction = str(sample.get("instruction", ""))
        input_text = str(sample.get("input", ""))
        gt_cwes = [c.upper() for c in _ground_truth_cwes(sample)]

        prompt = f"{instruction}\n\n--- CODE ---\n{input_text}\n--- END ---"
        try:
            raw = client.generate(prompt)
        except Exception:
            raw = ""

        parsed_ok, predicted = _parse_response(raw)
        if parsed_ok:
            result.parsed += 1
        if gt_cwes and predicted:
            top1 = predicted[0]
            if top1 in gt_cwes:
                result.top1_hits += 1
            if any(p in gt_cwes for p in predicted[:3]):
                result.top3_hits += 1

        if _contains_forbidden(raw):
            result.forbidden_phrase_hits += 1
        if _has_hallucinated_path(input_text, raw):
            result.hallucinated_path_hits += 1

        if record_per_sample:
            result.per_sample.append(
                {
                    "ground_truth": gt_cwes,
                    "predicted": predicted,
                    "parsed_ok": parsed_ok,
                    "raw": raw[:400],
                }
            )

    return result


def load_eval_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        out.append(json.loads(line))
    return out


__all__ = [
    "CWE_PATTERN",
    "EvalResult",
    "evaluate",
    "load_eval_jsonl",
]
