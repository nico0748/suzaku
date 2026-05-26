"""Web API 用 Pydantic スキーマ。

既存の ``suzaku.*.models`` を再利用しつつ、HTTP に流すための薄いラッパだけ
ここに置く。
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from suzaku import __version__
from suzaku.web.deps import WebMode


class HealthResponse(BaseModel):
    """``GET /api/health`` のレスポンス。"""

    name: str = "suzaku-web"
    version: str = __version__
    mode: WebMode
    csrf_token: str = Field(description="以降の非 safe method で X-Suzaku-CSRF として送る")


class SentinelScanRequest(BaseModel):
    """``POST /api/sentinel/scan`` のリクエスト。"""

    language: str | None = None
    min_stars: int = 500
    pushed_after: str | None = Field(default=None, description="ISO 日付 (例: 2026-01-01)")
    topics: list[str] = Field(default_factory=list)
    top: int = Field(default=20, ge=1, le=100)
    token: str | None = Field(
        default=None, description="GitHub PAT。未指定なら SUZAKU_GITHUB_TOKEN を使う"
    )


class SentinelScanItem(BaseModel):
    """``POST /api/sentinel/scan`` のレスポンス配列要素。"""

    name: str
    url: str
    language: str | None
    stars: int
    score: float
    signals: dict[str, float]


class SentinelScanResponse(BaseModel):
    """``POST /api/sentinel/scan`` のレスポンス本体。"""

    query: str
    results: list[SentinelScanItem]


class SignalsResponse(BaseModel):
    """``GET /api/sentinel/signals`` のレスポンス。"""

    weights: dict[str, float]
    keywords: dict[str, list[str]]
    thresholds: dict[str, float]


class ErrorResponse(BaseModel):
    """共通エラー形式。"""

    error: str
    detail: Any | None = None


__all__ = [
    "ErrorResponse",
    "HealthResponse",
    "SentinelScanItem",
    "SentinelScanRequest",
    "SentinelScanResponse",
    "SignalsResponse",
]
