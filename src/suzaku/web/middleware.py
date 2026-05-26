"""Origin / CSRF / レート制限 middleware。

127.0.0.1 バインドが前提だが、UI が増えた将来も同一の防御層を通すために
明示的にミドルウェアとして実装する。
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from suzaku.web.deps import get_settings

# CSRF 保護を必要としないメソッド (RFC 7231 safe methods)。
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# ヘルスチェックは CSRF トークン発行元なので除外。
_BOOTSTRAP_PATHS = frozenset({"/api/health"})


def _origin_allowed(origin: str, allowed_prefixes: tuple[str, ...]) -> bool:
    """``Origin`` がローカル接続 prefix のいずれかと一致するか判定する。"""
    return any(origin == prefix or origin.startswith(prefix + ":") for prefix in allowed_prefixes)


class OriginCheckMiddleware(BaseHTTPMiddleware):
    """非 safe method で ``Origin`` が localhost prefix と一致しなければ 403。"""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.method in _SAFE_METHODS:
            return await call_next(request)
        origin = request.headers.get("origin")
        if origin is None:
            return await call_next(request)
        settings = get_settings()
        if not _origin_allowed(origin, settings.allowed_origins):
            return JSONResponse({"error": "origin_blocked", "origin": origin}, status_code=403)
        return await call_next(request)


class CSRFMiddleware(BaseHTTPMiddleware):
    """非 safe method で ``X-Suzaku-CSRF`` ヘッダが必要。"""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.method in _SAFE_METHODS:
            return await call_next(request)
        if request.url.path in _BOOTSTRAP_PATHS:
            return await call_next(request)
        settings = get_settings()
        token = request.headers.get("x-suzaku-csrf")
        if token != settings.csrf_token:
            return JSONResponse({"error": "csrf_missing_or_invalid"}, status_code=403)
        return await call_next(request)


__all__ = ["CSRFMiddleware", "OriginCheckMiddleware"]
