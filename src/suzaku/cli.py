"""Suzaku CLI エントリポイント (Typer)。

5 モジュール (sentinel / compass / witness / herald / chronicle) を統合する。
``suzaku --help`` で全体のヘルプを表示する。出力は朱雀の朱色 ``#B43E3E``。
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel

from suzaku import __version__
from suzaku.chronicle.cli import app as chronicle_app
from suzaku.compass.cli import app as compass_app
from suzaku.herald.cli import app as herald_app
from suzaku.lineage.cli import app as lineage_app
from suzaku.mcp.cli import app as mcp_app
from suzaku.reader.cli import app as reader_app
from suzaku.sentinel.cli import app as sentinel_app
from suzaku.witness.cli import app as witness_app

SUZAKU_RED = "#B43E3E"
SUZAKU_DARK = "#8C1F1F"

console = Console()
app = typer.Typer(
    name="suzaku",
    help="朱雀 — OSS 脆弱性調査支援システム (Phase 1 MVP)",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
app.add_typer(sentinel_app, name="sentinel")
app.add_typer(compass_app, name="compass")
app.add_typer(witness_app, name="witness")
app.add_typer(herald_app, name="herald")
app.add_typer(chronicle_app, name="chronicle")
app.add_typer(reader_app, name="reader")
app.add_typer(lineage_app, name="lineage")
app.add_typer(mcp_app, name="mcp")


@app.command()
def version() -> None:
    """Suzaku のバージョンを表示する。"""
    console.print(
        Panel.fit(
            f"[bold {SUZAKU_RED}]Suzaku[/] v{__version__}\n"
            "OSS vulnerability research support — Phase 1 MVP\n"
            f"[{SUZAKU_DARK}]朱雀 — 広い空から異変を見つけ、社会に伝える[/]",
            border_style=SUZAKU_RED,
        )
    )


@app.callback()
def _banner() -> None:
    """グローバルなコールバック (現時点では何もしない)。"""


def main() -> None:
    app()


if __name__ == "__main__":
    main()
