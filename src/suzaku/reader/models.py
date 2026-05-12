"""Reader の出力データモデル (Pydantic v2)。

LLM 応答を `model_validate_json` でパースする。JSON Schema は
``Model.model_json_schema()`` で取得し、Ollama の ``format`` パラメータに
渡してハルシネーションを抑制する。
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)


class EntrypointKind(StrEnum):
    HTTP_ROUTE = "http_route"
    CLI = "cli"
    IPC = "ipc"
    RPC = "rpc"
    WEBSOCKET = "websocket"
    QUEUE = "queue"
    EVENT_HANDLER = "event_handler"


class RepoOverview(BaseModel):
    """Stage 1: リポジトリ概観。"""

    summary: str
    tech_stack: list[str] = Field(default_factory=list)
    main_directories: list[str] = Field(default_factory=list)
    estimated_loc: int = Field(default=0, ge=0)


class Entrypoint(BaseModel):
    """Stage 2: 入口の特定。"""

    kind: EntrypointKind
    file_path: str
    line_number: int = Field(ge=0)
    description: str


class TrustBoundary(BaseModel):
    """Stage 3: 信頼境界の追跡。"""

    entrypoint_index: int = Field(ge=0)
    sink_description: str
    flow_summary: str


class Hypothesis(BaseModel):
    """Stage 4: 仮説生成。"""

    boundary_index: int = Field(ge=0)
    cwe_candidates: list[str] = Field(default_factory=list, max_length=10)
    rationale: str


class ReaderReport(BaseModel):
    """4 stage の合算出力。"""

    overview: RepoOverview
    entrypoints: list[Entrypoint] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    model: str = ""
    generated_at: datetime = Field(default_factory=_utcnow)


# Stage 2/3/4 は配列を返すので、Ollama に渡す JSON Schema は wrapper object
# にする (一部のモデルがトップレベル array に弱いため)。


class _EntrypointList(BaseModel):
    entrypoints: list[Entrypoint]


class _TrustBoundaryList(BaseModel):
    trust_boundaries: list[TrustBoundary]


class _HypothesisList(BaseModel):
    hypotheses: list[Hypothesis]


def overview_schema() -> dict[str, object]:
    """Stage 1 用 JSON Schema。"""
    return RepoOverview.model_json_schema()


def entrypoints_schema() -> dict[str, object]:
    """Stage 2 用 JSON Schema (wrapper object)。"""
    return _EntrypointList.model_json_schema()


def trust_boundaries_schema() -> dict[str, object]:
    """Stage 3 用 JSON Schema (wrapper object)。"""
    return _TrustBoundaryList.model_json_schema()


def hypotheses_schema() -> dict[str, object]:
    """Stage 4 用 JSON Schema (wrapper object)。"""
    return _HypothesisList.model_json_schema()


def parse_entrypoints(text: str) -> list[Entrypoint]:
    payload = json.loads(text)
    if isinstance(payload, list):
        return [Entrypoint.model_validate(e) for e in payload]
    return _EntrypointList.model_validate(payload).entrypoints


def parse_trust_boundaries(text: str) -> list[TrustBoundary]:
    payload = json.loads(text)
    if isinstance(payload, list):
        return [TrustBoundary.model_validate(e) for e in payload]
    return _TrustBoundaryList.model_validate(payload).trust_boundaries


def parse_hypotheses(text: str) -> list[Hypothesis]:
    payload = json.loads(text)
    if isinstance(payload, list):
        return [Hypothesis.model_validate(e) for e in payload]
    return _HypothesisList.model_validate(payload).hypotheses


__all__ = [
    "Entrypoint",
    "EntrypointKind",
    "Hypothesis",
    "ReaderReport",
    "RepoOverview",
    "TrustBoundary",
    "entrypoints_schema",
    "hypotheses_schema",
    "overview_schema",
    "parse_entrypoints",
    "parse_hypotheses",
    "parse_trust_boundaries",
    "trust_boundaries_schema",
]
