"""``/api/health`` — 稼働確認 + CSRF トークン発行。"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from suzaku.web.deps import WebSettings, get_settings
from suzaku.web.schemas import HealthResponse

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health(settings: WebSettings = Depends(get_settings)) -> HealthResponse:
    """バージョン文字列と CSRF トークンを返す。

    フロントエンドは起動時にこのエンドポイントを叩き、得られた ``csrf_token``
    を以降の POST で ``X-Suzaku-CSRF`` ヘッダに乗せる。
    """
    return HealthResponse(mode=settings.mode, csrf_token=settings.csrf_token)


__all__ = ["router"]
