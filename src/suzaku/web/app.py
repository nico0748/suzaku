"""FastAPI アプリケーションファクトリ。

``suzaku web serve`` から ``create_app(WebSettings(...))`` を呼んで取得する。
テストでは ``create_app(WebSettings(mode='ro'))`` を直接渡す。
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from suzaku import __version__
from suzaku.chronicle.escalation import ACCSViolationError
from suzaku.compass.grep_runner import RipgrepNotFoundError
from suzaku.lineage.egress import LineageEgressError
from suzaku.lineage.nvd import NVDFilterError
from suzaku.web.deps import WebSettings, configure
from suzaku.web.middleware import CSRFMiddleware, OriginCheckMiddleware
from suzaku.web.routers import chronicle as chronicle_router
from suzaku.web.routers import compass as compass_router
from suzaku.web.routers import health as health_router
from suzaku.web.routers import lineage as lineage_router
from suzaku.web.routers import sentinel as sentinel_router


def _register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(NVDFilterError)
    async def _on_nvd_filter(_req: Request, exc: NVDFilterError) -> JSONResponse:
        return JSONResponse({"error": "nvd_filtered", "detail": str(exc)}, status_code=422)

    @app.exception_handler(LineageEgressError)
    async def _on_egress(_req: Request, exc: LineageEgressError) -> JSONResponse:
        return JSONResponse({"error": "egress_blocked", "detail": str(exc)}, status_code=403)

    @app.exception_handler(RipgrepNotFoundError)
    async def _on_rg_missing(_req: Request, exc: RipgrepNotFoundError) -> JSONResponse:
        return JSONResponse(
            {"error": "ripgrep_missing", "detail": str(exc)}, status_code=503
        )

    @app.exception_handler(ACCSViolationError)
    async def _on_accs(_req: Request, exc: ACCSViolationError) -> JSONResponse:
        return JSONResponse({"error": "accs_violation", "detail": str(exc)}, status_code=409)


def create_app(settings: WebSettings | None = None) -> FastAPI:
    """FastAPI インスタンスを構築する。

    ``settings`` を渡すと ``deps.configure()`` でプロセス全体の設定を上書きする。
    """
    if settings is not None:
        configure(settings)

    app = FastAPI(
        title="Suzaku Web API",
        version=__version__,
        description="朱雀 — OSS 脆弱性調査支援システム (Phase 3-A Web UI)",
    )

    # ミドルウェアは LIFO で実行されるため、後に追加したものが外側になる。
    # 外側に Origin チェック → 内側に CSRF チェック という順序で当てたいので、
    # まず CSRF を、次に Origin を add する。
    app.add_middleware(CSRFMiddleware)
    app.add_middleware(OriginCheckMiddleware)

    app.include_router(health_router.router)
    app.include_router(sentinel_router.router)
    app.include_router(compass_router.router)
    app.include_router(lineage_router.router)
    app.include_router(chronicle_router.router)

    _register_exception_handlers(app)
    return app


__all__ = ["create_app"]
