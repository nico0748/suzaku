"""Reader 4 stage のテスト (respx で Ollama HTTP モック)。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import respx

from suzaku.reader.models import (
    Entrypoint,
    EntrypointKind,
    RepoOverview,
    TrustBoundary,
)
from suzaku.reader.ollama import DEFAULT_BASE_URL, OllamaClient
from suzaku.reader.repo_summary import build_repo_summary
from suzaku.reader.stages import (
    ReaderParseError,
    read_repo,
    stage_entrypoints,
    stage_hypotheses,
    stage_overview,
    stage_trust_boundaries,
)


def _mock_generate(response_text: str) -> None:
    respx.post(f"{DEFAULT_BASE_URL}/api/generate").respond(
        200, json={"response": response_text, "done": True}
    )


def _write(p: Path, body: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    _write(tmp_path / "pyproject.toml", "[project]\nname = 'demo'\n")
    _write(tmp_path / "src" / "app.py", "def index(req):\n    return req.user\n")
    return tmp_path


class TestStageOverview:
    @respx.mock
    def test_returns_pydantic_model(self, sample_repo: Path) -> None:
        _mock_generate(
            json.dumps(
                {
                    "summary": "tiny python app",
                    "tech_stack": ["Python"],
                    "main_directories": ["src"],
                    "estimated_loc": 4,
                }
            )
        )
        with OllamaClient() as client:
            ov = stage_overview(sample_repo, client)
        assert isinstance(ov, RepoOverview)
        assert "Python" in ov.tech_stack

    @respx.mock
    def test_invalid_json_raises_parse_error(self, sample_repo: Path) -> None:
        _mock_generate("not-json")
        with OllamaClient() as client, pytest.raises(ReaderParseError):
            stage_overview(sample_repo, client)


class TestStageEntrypoints:
    @respx.mock
    def test_wrapper_object(self, sample_repo: Path) -> None:
        _mock_generate(
            json.dumps(
                {
                    "entrypoints": [
                        {
                            "kind": "http_route",
                            "file_path": "src/app.py",
                            "line_number": 1,
                            "description": "index endpoint",
                        }
                    ]
                }
            )
        )
        ov = RepoOverview(summary="x", tech_stack=["Python"], main_directories=["src"])
        with OllamaClient() as client:
            entries = stage_entrypoints(sample_repo, ov, client)
        assert len(entries) == 1
        assert entries[0].kind == EntrypointKind.HTTP_ROUTE

    @respx.mock
    def test_top_level_array_also_accepted(self, sample_repo: Path) -> None:
        _mock_generate(
            json.dumps(
                [
                    {
                        "kind": "cli",
                        "file_path": "main.py",
                        "line_number": 0,
                        "description": "argparse entry",
                    }
                ]
            )
        )
        ov = RepoOverview(summary="x")
        with OllamaClient() as client:
            entries = stage_entrypoints(sample_repo, ov, client)
        assert entries[0].kind == EntrypointKind.CLI

    @respx.mock
    def test_max_files_caps(self, sample_repo: Path) -> None:
        many = [
            {"kind": "cli", "file_path": f"f{i}.py", "line_number": 0, "description": "x"}
            for i in range(40)
        ]
        _mock_generate(json.dumps({"entrypoints": many}))
        ov = RepoOverview(summary="x")
        with OllamaClient() as client:
            entries = stage_entrypoints(sample_repo, ov, client, max_files=5)
        assert len(entries) == 5


class TestStageTrustBoundaries:
    @respx.mock
    def test_filters_out_of_range_indices(self, sample_repo: Path) -> None:
        _mock_generate(
            json.dumps(
                {
                    "trust_boundaries": [
                        {
                            "entrypoint_index": 0,
                            "sink_description": "SQL",
                            "flow_summary": "via raw query",
                        },
                        {
                            "entrypoint_index": 999,  # out of range
                            "sink_description": "X",
                            "flow_summary": "Y",
                        },
                    ]
                }
            )
        )
        entries = [
            Entrypoint(kind=EntrypointKind.HTTP_ROUTE, file_path="a.py", line_number=1, description="x")
        ]
        with OllamaClient() as client:
            out = stage_trust_boundaries(sample_repo, entries, client)
        assert len(out) == 1
        assert isinstance(out[0], TrustBoundary)

    def test_no_entrypoints_returns_empty(self, sample_repo: Path) -> None:
        with OllamaClient() as client:
            out = stage_trust_boundaries(sample_repo, [], client)
        assert out == []


class TestStageHypotheses:
    @respx.mock
    def test_unknown_cwe_filtered(self) -> None:
        _mock_generate(
            json.dumps(
                {
                    "hypotheses": [
                        {
                            "boundary_index": 0,
                            "cwe_candidates": ["CWE-22", "CWE-999999", "CWE-79"],
                            "rationale": "path traversal in upload",
                        }
                    ]
                }
            )
        )
        b = TrustBoundary(entrypoint_index=0, sink_description="zip extract", flow_summary="...")
        with OllamaClient() as client:
            out = stage_hypotheses([b], client)
        assert len(out) == 1
        # 未知 CWE-999999 は除外される
        assert "CWE-999999" not in out[0].cwe_candidates
        assert "CWE-22" in out[0].cwe_candidates

    @respx.mock
    def test_all_unknown_cwes_drops_hypothesis(self) -> None:
        _mock_generate(
            json.dumps(
                {
                    "hypotheses": [
                        {
                            "boundary_index": 0,
                            "cwe_candidates": ["CWE-99999"],
                            "rationale": "x",
                        }
                    ]
                }
            )
        )
        b = TrustBoundary(entrypoint_index=0, sink_description="x", flow_summary="y")
        with OllamaClient() as client:
            out = stage_hypotheses([b], client)
        assert out == []

    def test_no_boundaries_returns_empty(self) -> None:
        with OllamaClient() as client:
            out = stage_hypotheses([], client)
        assert out == []


class TestReadRepoEndToEnd:
    @respx.mock
    def test_full_pipeline_via_mock(self, sample_repo: Path) -> None:
        responses = iter(
            [
                json.dumps(
                    {
                        "summary": "demo",
                        "tech_stack": ["Python"],
                        "main_directories": ["src"],
                        "estimated_loc": 4,
                    }
                ),
                json.dumps(
                    {
                        "entrypoints": [
                            {
                                "kind": "http_route",
                                "file_path": "src/app.py",
                                "line_number": 1,
                                "description": "index",
                            }
                        ]
                    }
                ),
                json.dumps(
                    {
                        "trust_boundaries": [
                            {
                                "entrypoint_index": 0,
                                "sink_description": "subprocess shell=True",
                                "flow_summary": "user input flows into shell",
                            }
                        ]
                    }
                ),
                json.dumps(
                    {
                        "hypotheses": [
                            {
                                "boundary_index": 0,
                                "cwe_candidates": ["CWE-78"],
                                "rationale": "OS command injection",
                            }
                        ]
                    }
                ),
            ]
        )

        def _side_effect(request: object) -> dict[str, object]:
            return {"response": next(responses), "done": True}

        respx.post(f"{DEFAULT_BASE_URL}/api/generate").mock(
            side_effect=lambda req: __import__("httpx").Response(200, json=_side_effect(req))
        )
        with OllamaClient() as client:
            report = read_repo(sample_repo, client)
        assert len(report.entrypoints) == 1
        assert len(report.trust_boundaries) == 1
        assert len(report.hypotheses) == 1
        assert report.hypotheses[0].cwe_candidates == ["CWE-78"]


def test_build_summary_used_by_stage(sample_repo: Path) -> None:
    # repo_summary が import 可能で stage に渡せること
    s = build_repo_summary(sample_repo)
    assert s.root == sample_repo
