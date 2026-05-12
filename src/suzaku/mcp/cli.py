"""``suzaku mcp`` サブコマンド."""

from __future__ import annotations

import anyio
import typer
from rich.console import Console
from rich.table import Table

from suzaku.mcp.tools import ToolMode, list_tool_specs

SUZAKU_RED = "#B43E3E"

app = typer.Typer(
    name="mcp",
    help="MCP (Model Context Protocol) サーバ — Claude Code から Suzaku を呼ぶ",
    no_args_is_help=True,
)
console = Console()


def _validate_mode(value: str) -> ToolMode:
    if value not in ("ro", "rw"):
        raise typer.BadParameter("mode must be 'ro' or 'rw'")
    return value  # type: ignore[return-value]


@app.command()
def serve(
    mode: str = typer.Option("ro", "--mode", "-m", help="ro (read-only) | rw"),
) -> None:
    """stdio トランスポートで MCP サーバを起動する (Claude Code/Desktop が呼ぶ)。"""
    tool_mode = _validate_mode(mode)
    from suzaku.mcp.server import serve_stdio

    anyio.run(serve_stdio, tool_mode)


@app.command(name="list-tools")
def list_tools_cmd(
    mode: str = typer.Option("ro", "--mode", "-m", help="ro | rw"),
) -> None:
    """現モードで公開されるツール一覧を表示する。"""
    tool_mode = _validate_mode(mode)
    specs = list_tool_specs(tool_mode)
    table = Table(title=f"[bold {SUZAKU_RED}]Suzaku MCP tools (mode={mode})[/]")
    table.add_column("Name")
    table.add_column("Mode", justify="right")
    table.add_column("Description")
    for spec in specs:
        table.add_row(spec.name, spec.mode, spec.description)
    console.print(table)
