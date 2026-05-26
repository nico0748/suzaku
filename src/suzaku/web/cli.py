"""``suzaku web`` Typer サブコマンド。"""

from __future__ import annotations

import typer
import uvicorn
from rich.console import Console
from rich.panel import Panel

from suzaku.web.app import create_app
from suzaku.web.deps import WebSettings

SUZAKU_RED = "#B43E3E"
SUZAKU_DARK = "#8C1F1F"

app = typer.Typer(
    name="web",
    help="Web UI — FastAPI + React フロントの起動 (Phase 3-A)",
    no_args_is_help=True,
)
console = Console()


def _confirm_non_local_bind(host: str) -> None:
    """``127.0.0.1`` 以外にバインドする場合は人間に確認を取る。"""
    if host in {"127.0.0.1", "localhost", "::1"}:
        return
    console.print(
        Panel.fit(
            f"[bold {SUZAKU_DARK}]WARNING[/]\n"
            f"You are about to bind the web UI on [bold]{host}[/], which makes the\n"
            "API reachable from other hosts. Suzaku has no authentication layer.\n"
            "Make sure you trust the network you are exposing this on.",
            border_style=SUZAKU_DARK,
        )
    )
    if not typer.confirm("Continue?", default=False):
        raise typer.Abort()


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="bind host"),
    port: int = typer.Option(8765, "--port", help="bind port"),
    mode: str = typer.Option("ro", "--mode", help="ro (read-only) | rw (read-write)"),
    reload: bool = typer.Option(False, "--reload", help="uvicorn auto-reload (dev)"),
) -> None:
    """FastAPI サーバを uvicorn で起動する。"""
    if mode not in {"ro", "rw"}:
        raise typer.BadParameter("mode must be 'ro' or 'rw'")
    _confirm_non_local_bind(host)

    settings = WebSettings(mode=mode, host=host, port=port)  # type: ignore[arg-type]
    create_app(settings)

    console.print(
        Panel.fit(
            f"[bold {SUZAKU_RED}]Suzaku Web[/] starting...\n"
            f"  http://{host}:{port}\n"
            f"  mode = [bold]{mode}[/]\n"
            f"  CSRF token (dev) = {settings.csrf_token[:8]}…",
            border_style=SUZAKU_RED,
        )
    )

    uvicorn.run(
        "suzaku.web.app:create_app",
        host=host,
        port=port,
        reload=reload,
        factory=True,
    )


__all__ = ["app"]
