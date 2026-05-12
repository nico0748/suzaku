"""Reader 4 段階のコード読解。

各 stage は純粋関数として実装し、:class:`OllamaClient` を引数で受け取る。
LLM 応答は ``parse_*`` 経由で Pydantic 検証され、不正なら
:class:`ReaderParseError` を投げる。
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import ValidationError

from suzaku.herald.checklist import load_cwe_database
from suzaku.reader.models import (
    Entrypoint,
    Hypothesis,
    ReaderReport,
    RepoOverview,
    TrustBoundary,
    entrypoints_schema,
    hypotheses_schema,
    overview_schema,
    parse_entrypoints,
    parse_hypotheses,
    parse_trust_boundaries,
    trust_boundaries_schema,
)
from suzaku.reader.ollama import OllamaClient
from suzaku.reader.repo_summary import RepoSummary, build_repo_summary, render_for_prompt

PROMPTS_DIR = Path(__file__).parent / "data" / "prompts"

DEFAULT_MAX_BOUNDARIES = 12
DEFAULT_TOP_K_CWE = 3


class ReaderParseError(ValueError):
    """LLM 応答が期待する JSON 形式でない場合に発生。"""


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(PROMPTS_DIR)),
        autoescape=select_autoescape(disabled_extensions=("j2",)),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _allowed_cwe_ids() -> list[str]:
    db = load_cwe_database()
    return sorted(db.keys())


def stage_overview(
    repo: RepoSummary | Path,
    client: OllamaClient,
) -> RepoOverview:
    """Stage 1: リポジトリ概観の生成。"""
    summary = repo if isinstance(repo, RepoSummary) else build_repo_summary(repo)
    prompt = _env().get_template("overview.j2").render(repo_text=render_for_prompt(summary))
    response = client.generate(prompt, format=overview_schema())
    try:
        return RepoOverview.model_validate_json(response)
    except (ValidationError, json.JSONDecodeError) as exc:
        raise ReaderParseError(f"overview JSON parse failed: {exc}") from exc


def stage_entrypoints(
    repo: RepoSummary | Path,
    overview: RepoOverview,
    client: OllamaClient,
    max_files: int = 30,
) -> list[Entrypoint]:
    """Stage 2: 入口の特定。"""
    summary = repo if isinstance(repo, RepoSummary) else build_repo_summary(repo)
    prompt = (
        _env()
        .get_template("entrypoints.j2")
        .render(
            overview_json=overview.model_dump_json(indent=2),
            repo_text=render_for_prompt(summary),
        )
    )
    response = client.generate(prompt, format=entrypoints_schema())
    try:
        entries = parse_entrypoints(response)
    except (ValidationError, json.JSONDecodeError) as exc:
        raise ReaderParseError(f"entrypoints JSON parse failed: {exc}") from exc
    return entries[:max_files]


def stage_trust_boundaries(
    repo: RepoSummary | Path,
    entrypoints: list[Entrypoint],
    client: OllamaClient,
    max_boundaries: int = DEFAULT_MAX_BOUNDARIES,
) -> list[TrustBoundary]:
    """Stage 3: 信頼境界の追跡。"""
    if not entrypoints:
        return []
    summary = repo if isinstance(repo, RepoSummary) else build_repo_summary(repo)
    payload = json.dumps([e.model_dump(mode="json") for e in entrypoints], indent=2)
    prompt = (
        _env()
        .get_template("trust_boundaries.j2")
        .render(
            entrypoints_json=payload,
            repo_text=render_for_prompt(summary),
            max_boundaries=max_boundaries,
        )
    )
    response = client.generate(prompt, format=trust_boundaries_schema())
    try:
        boundaries = parse_trust_boundaries(response)
    except (ValidationError, json.JSONDecodeError) as exc:
        raise ReaderParseError(f"trust_boundaries JSON parse failed: {exc}") from exc
    valid = [b for b in boundaries if 0 <= b.entrypoint_index < len(entrypoints)]
    return valid[:max_boundaries]


def stage_hypotheses(
    boundaries: list[TrustBoundary],
    client: OllamaClient,
    top_k_cwe: int = DEFAULT_TOP_K_CWE,
) -> list[Hypothesis]:
    """Stage 4: 仮説生成 (boundary -> CWE トップ K)。"""
    if not boundaries:
        return []
    allowed = _allowed_cwe_ids()
    payload = json.dumps([b.model_dump(mode="json") for b in boundaries], indent=2)
    prompt = (
        _env()
        .get_template("hypotheses.j2")
        .render(
            boundaries_json=payload,
            top_k_cwe=top_k_cwe,
            allowed_cwes=", ".join(allowed),
        )
    )
    response = client.generate(prompt, format=hypotheses_schema())
    try:
        hypotheses = parse_hypotheses(response)
    except (ValidationError, json.JSONDecodeError) as exc:
        raise ReaderParseError(f"hypotheses JSON parse failed: {exc}") from exc

    allowed_set = set(allowed)
    validated: list[Hypothesis] = []
    for h in hypotheses:
        if not (0 <= h.boundary_index < len(boundaries)):
            continue
        # 未知 CWE は弾く
        filtered = [c for c in h.cwe_candidates if c in allowed_set]
        if not filtered:
            continue
        validated.append(
            Hypothesis(
                boundary_index=h.boundary_index,
                cwe_candidates=filtered[:top_k_cwe],
                rationale=h.rationale,
            )
        )
    return validated


def read_repo(
    repo_path: Path,
    client: OllamaClient,
    *,
    max_boundaries: int = DEFAULT_MAX_BOUNDARIES,
    top_k_cwe: int = DEFAULT_TOP_K_CWE,
) -> ReaderReport:
    """4 stage を順に実行して :class:`ReaderReport` を返す。"""
    summary = build_repo_summary(repo_path)
    overview = stage_overview(summary, client)
    entrypoints = stage_entrypoints(summary, overview, client)
    boundaries = stage_trust_boundaries(summary, entrypoints, client, max_boundaries=max_boundaries)
    hypotheses = stage_hypotheses(boundaries, client, top_k_cwe=top_k_cwe)
    return ReaderReport(
        overview=overview,
        entrypoints=entrypoints,
        trust_boundaries=boundaries,
        hypotheses=hypotheses,
        model=client.model,
        generated_at=datetime.now(UTC),
    )


def _to_jsonable(_summary: RepoSummary) -> dict[str, Any]:
    # ヘルパ (テストで使う可能性あり)
    return {}


__all__ = [
    "ReaderParseError",
    "read_repo",
    "stage_entrypoints",
    "stage_hypotheses",
    "stage_overview",
    "stage_trust_boundaries",
]
