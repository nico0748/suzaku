"""``/api/sentinel/*`` — Sentinel ターゲット選定エンドポイント。"""

from __future__ import annotations

import os
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException

from suzaku.sentinel.scoring import DEFAULT_SIGNALS_PATH, ScoringConfig, score_repo
from suzaku.sentinel.search import (
    GitHubSearch,
    GitHubSearchError,
    build_search_query,
    signals_from_summary,
)
from suzaku.web.schemas import (
    SentinelScanItem,
    SentinelScanRequest,
    SentinelScanResponse,
    SignalsResponse,
)

router = APIRouter(prefix="/api/sentinel", tags=["sentinel"])


@router.get("/signals", response_model=SignalsResponse)
def get_signals() -> SignalsResponse:
    """``signals.yaml`` の重み / キーワード / 閾値を返す。"""
    cfg = ScoringConfig.load(DEFAULT_SIGNALS_PATH)
    return SignalsResponse(weights=cfg.weights, keywords=cfg.keywords, thresholds=cfg.thresholds)


@router.post("/scan", response_model=SentinelScanResponse)
def post_scan(req: SentinelScanRequest) -> SentinelScanResponse:
    """GitHub Search で候補を取り、8 シグナルでスコアリングする。

    ``token`` 未指定時は環境変数 ``SUZAKU_GITHUB_TOKEN`` を使う。両方無い場合は
    認証なしで叩くため API レート制限 (60req/h) に当たりやすい。
    """
    pushed_dt: datetime | None = None
    if req.pushed_after:
        try:
            pushed_dt = datetime.fromisoformat(req.pushed_after).replace(tzinfo=UTC)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"invalid pushed_after: {e}") from e

    token = req.token or os.environ.get("SUZAKU_GITHUB_TOKEN")
    config = ScoringConfig.load(DEFAULT_SIGNALS_PATH)
    query = build_search_query(
        language=req.language,
        min_stars=req.min_stars,
        pushed_after=pushed_dt,
        topics=req.topics,
    )

    try:
        with GitHubSearch(token=token) as gh:
            repos = gh.search_repositories(
                language=req.language,
                min_stars=req.min_stars,
                pushed_after=pushed_dt,
                topics=req.topics,
                top=req.top,
            )
    except GitHubSearchError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e

    items: list[SentinelScanItem] = []
    for r in repos:
        signals = signals_from_summary(r)
        per, score = score_repo(signals, config)
        items.append(
            SentinelScanItem(
                name=r.full_name,
                url=r.html_url,
                language=r.language,
                stars=r.stargazers_count,
                score=score,
                signals=per,
            )
        )
    items.sort(key=lambda x: x.score, reverse=True)
    return SentinelScanResponse(query=query, results=items)


__all__ = ["router"]
