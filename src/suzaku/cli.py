"""Suzaku CLI エントリポイント (Typer)。

各モジュールのサブコマンドはここに統合される。Phase 1 完了時点で
sentinel / compass / witness / herald / chronicle が登録される。
"""

from __future__ import annotations

import typer
from rich.console import Console

from suzaku import __version__

SUZAKU_RED = "#B43E3E"

console = Console()
app = typer.Typer(
    name="suzaku",
    help="朱雀 — OSS 脆弱性調査支援システム (Phase 1 MVP)",
    no_args_is_help=True,
    rich_markup_mode="rich",
)


@app.command()
def version() -> None:
    """Suzaku のバージョンを表示する。"""
    console.print(f"[bold {SUZAKU_RED}]Suzaku[/] v{__version__}")


if __name__ == "__main__":
    app()
