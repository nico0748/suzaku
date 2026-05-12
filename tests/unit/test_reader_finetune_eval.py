"""eval.py のテスト (Ollama HTTP を respx でモック)。"""

from __future__ import annotations

import json

import pytest
import respx

from suzaku.reader.finetune.eval import (
    EvalResult,
    _has_hallucinated_path,
    _parse_response,
    evaluate,
)
from suzaku.reader.ollama import DEFAULT_BASE_URL, OllamaClient


def _eval_sample(cwe: str, snippet: str = "z.extractall(p)") -> dict:
    return {
        "instruction": "Analyze the code for vulnerabilities.",
        "input": snippet,
        "output": json.dumps({"cwe_candidates": [cwe], "rationale": "..."}),
    }


class TestParseResponse:
    def test_valid_json_with_cwe(self) -> None:
        ok, predicted = _parse_response('{"cwe_candidates": ["CWE-22"], "rationale": "x"}')
        assert ok is True
        assert predicted == ["CWE-22"]

    def test_invalid_json(self) -> None:
        ok, predicted = _parse_response("nope")
        assert ok is False
        assert predicted == []

    def test_non_object(self) -> None:
        ok, _predicted = _parse_response("[1,2,3]")
        assert ok is False

    def test_malformed_cwe_filtered(self) -> None:
        ok, predicted = _parse_response(
            '{"cwe_candidates": ["CWE-22", "notacwe", "CWE-79"]}'
        )
        assert ok is True
        assert predicted == ["CWE-22", "CWE-79"]


class TestHallucinatedPath:
    def test_no_paths_no_hallucination(self) -> None:
        assert _has_hallucinated_path("snippet", '{"x":1}') is False

    def test_output_path_not_in_input_is_hallucinated(self) -> None:
        assert _has_hallucinated_path(
            "no paths here",
            '{"rationale": "see src/secret.py"}',
        ) is True

    def test_output_path_in_input_ok(self) -> None:
        assert _has_hallucinated_path(
            "src/extract.py: zipfile.extractall",
            '{"rationale": "src/extract.py has the issue"}',
        ) is False


class TestEvaluate:
    @respx.mock
    def test_perfect_top1(self) -> None:
        respx.post(f"{DEFAULT_BASE_URL}/api/generate").respond(
            200,
            json={
                "response": json.dumps({"cwe_candidates": ["CWE-22"], "rationale": "..."}),
                "done": True,
            },
        )
        with OllamaClient() as client:
            result = evaluate([_eval_sample("CWE-22")], client)
        assert result.total == 1
        assert result.top1_hits == 1
        assert result.top3_hits == 1
        assert result.forbidden_phrase_hits == 0

    @respx.mock
    def test_top3_but_not_top1(self) -> None:
        respx.post(f"{DEFAULT_BASE_URL}/api/generate").respond(
            200,
            json={
                "response": json.dumps(
                    {"cwe_candidates": ["CWE-79", "CWE-89", "CWE-22"], "rationale": "..."}
                ),
                "done": True,
            },
        )
        with OllamaClient() as client:
            result = evaluate([_eval_sample("CWE-22")], client)
        assert result.top1_hits == 0
        assert result.top3_hits == 1

    @respx.mock
    def test_forbidden_phrase_counted(self) -> None:
        respx.post(f"{DEFAULT_BASE_URL}/api/generate").respond(
            200,
            json={
                "response": (
                    '{"cwe_candidates": ["CWE-22"], "rationale": "pay first or i will release"}'
                ),
                "done": True,
            },
        )
        with OllamaClient() as client:
            result = evaluate([_eval_sample("CWE-22")], client)
        assert result.forbidden_phrase_hits == 1

    @respx.mock
    def test_parse_failure_counts(self) -> None:
        respx.post(f"{DEFAULT_BASE_URL}/api/generate").respond(
            200, json={"response": "not-json", "done": True}
        )
        with OllamaClient() as client:
            result = evaluate([_eval_sample("CWE-22")], client)
        assert result.parsed == 0
        assert result.top1_hits == 0

    @respx.mock
    def test_summary_dict(self) -> None:
        respx.post(f"{DEFAULT_BASE_URL}/api/generate").respond(
            200,
            json={
                "response": json.dumps({"cwe_candidates": ["CWE-22"], "rationale": "x"}),
                "done": True,
            },
        )
        with OllamaClient() as client:
            result = evaluate(
                [_eval_sample("CWE-22"), _eval_sample("CWE-22")], client
            )
        summary = result.as_dict()
        assert summary["total"] == 2
        assert summary["top1_accuracy"] == 1.0


class TestEvalResult:
    def test_zero_total_rates(self) -> None:
        r = EvalResult()
        assert r.top1_accuracy == 0.0
        assert r.top3_accuracy == 0.0
        assert r.parse_rate == 0.0


@pytest.fixture(autouse=True)
def _no_color(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
