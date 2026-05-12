"""Suzaku MCP Server — Model Context Protocol 経由でツールを公開する。

stdio transport で起動する。詳細仕様: ``docs/SPEC-phase2-mcp.md``。

責務:
- ``mcp.server.Server`` 上にツール一覧と call_tool ハンドラを登録
- ``tools.dispatch`` を呼び、結果を JSON テキストにシリアライズ
- Suzaku 固有例外 (Guard/ACCS/Checklist/Route/Extortion/CVSS/Rule) を
  ``isError=True`` の TextContent にラップ
"""

from __future__ import annotations

import json
from typing import Any

import mcp.types as mcp_types
from mcp.server import Server

from suzaku import __version__
from suzaku.mcp.tools import (
    SUZAKU_ERRORS,
    UnknownToolError,
    dispatch,
    list_tool_specs,
)
from suzaku.mcp.tools import (
    ToolMode as Mode,
)


def build_server(mode: Mode = "ro") -> Server:
    """``--mode`` 設定に応じた Suzaku MCP server を構築する。"""
    name = f"suzaku-{mode}"
    server: Server = Server(name=name, version=__version__)

    @server.list_tools()
    async def _list_tools() -> list[mcp_types.Tool]:
        specs = list_tool_specs(mode)
        return [
            mcp_types.Tool(
                name=spec.name,
                description=spec.description,
                inputSchema=spec.input_schema,
            )
            for spec in specs
        ]

    @server.call_tool()
    async def _call_tool(
        name: str, arguments: dict[str, Any] | None
    ) -> list[mcp_types.TextContent]:
        args = arguments or {}
        try:
            result = dispatch(name, args, mode)
        except UnknownToolError as e:
            return [_error("unknown_tool", str(e))]
        except SUZAKU_ERRORS as e:
            return [_error(e.__class__.__name__, str(e))]
        except Exception as e:
            return [_error("internal_error", f"{e.__class__.__name__}: {e}")]

        text = json.dumps(result, ensure_ascii=False, default=str, indent=2)
        return [mcp_types.TextContent(type="text", text=text)]

    return server


def _error(code: str, message: str) -> mcp_types.TextContent:
    body = json.dumps({"error": code, "message": message}, ensure_ascii=False)
    return mcp_types.TextContent(type="text", text=body)


async def serve_stdio(mode: Mode = "ro") -> None:
    """stdio トランスポートで MCP サーバを起動する (ブロッキング)。"""
    from mcp.server.stdio import stdio_server

    server = build_server(mode)
    async with stdio_server() as (read, write):
        await server.run(
            read,
            write,
            server.create_initialization_options(),
        )
