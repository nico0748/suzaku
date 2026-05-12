"""Suzaku MCP server の integration テスト (in-process MCP client)。"""

from __future__ import annotations

import json

import anyio
import pytest
from mcp.client.session import ClientSession
from mcp.shared.memory import create_connected_server_and_client_session

from suzaku.mcp.server import build_server


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def _connect(mode: str = "ro") -> tuple[ClientSession, anyio.abc.TaskGroup]:
    """テスト用 in-memory なクライアントセッションを返す。"""
    server = build_server(mode)  # type: ignore[arg-type]
    return server


@pytest.mark.anyio
async def test_list_tools_ro() -> None:
    server = build_server("ro")
    async with create_connected_server_and_client_session(server) as session:
        await session.initialize()
        result = await session.list_tools()
        names = {t.name for t in result.tools}
        assert "herald_cvss" in names
        assert "compass_list_rules" in names
        # rw ツールは出ない
        assert "witness_init" not in names
        assert "chronicle_init" not in names


@pytest.mark.anyio
async def test_list_tools_rw() -> None:
    server = build_server("rw")
    async with create_connected_server_and_client_session(server) as session:
        await session.initialize()
        result = await session.list_tools()
        names = {t.name for t in result.tools}
        assert "witness_init" in names
        assert "chronicle_init" in names
        # 永続的に非公開のものは出ない
        assert "witness_reproduce" not in names
        assert "chronicle_publish" not in names


@pytest.mark.anyio
async def test_call_herald_cvss() -> None:
    server = build_server("ro")
    async with create_connected_server_and_client_session(server) as session:
        await session.initialize()
        result = await session.call_tool(
            "herald_cvss",
            {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        )
        assert result.isError is None or result.isError is False
        assert result.content
        payload = json.loads(result.content[0].text)  # type: ignore[union-attr]
        assert payload["severity"] == "Critical"


@pytest.mark.anyio
async def test_call_witness_check_host_blocked() -> None:
    server = build_server("ro")
    async with create_connected_server_and_client_session(server) as session:
        await session.initialize()
        result = await session.call_tool(
            "witness_check_host", {"host": "github.com"}
        )
        payload = json.loads(result.content[0].text)  # type: ignore[union-attr]
        assert payload["allowed"] is False


@pytest.mark.anyio
async def test_call_unknown_tool_in_ro_mode() -> None:
    server = build_server("ro")
    async with create_connected_server_and_client_session(server) as session:
        await session.initialize()
        result = await session.call_tool("witness_init", {"finding_id": "X"})
        # rw ツールは ro mode で UnknownTool として返ってくる
        text = result.content[0].text  # type: ignore[union-attr]
        assert "rw" in text.lower() or "unknown" in text.lower()


@pytest.mark.anyio
async def test_call_invalid_cvss_returns_error_text() -> None:
    server = build_server("ro")
    async with create_connected_server_and_client_session(server) as session:
        await session.initialize()
        result = await session.call_tool("herald_cvss", {"vector": "garbage"})
        # MCP は process crash を避ける: TextContent 形式の error JSON
        text = result.content[0].text  # type: ignore[union-attr]
        assert "CVSSError" in text or "error" in text.lower()


@pytest.mark.anyio
async def test_rw_witness_init_creates_files(tmp_path: object) -> None:  # type: ignore[no-untyped-def]
    server = build_server("rw")
    async with create_connected_server_and_client_session(server) as session:
        await session.initialize()
        result = await session.call_tool(
            "witness_init",
            {
                "finding_id": "F-mcp-001",
                "pocs_dir": str(tmp_path / "pocs"),  # type: ignore[operator]
            },
        )
        payload = json.loads(result.content[0].text)  # type: ignore[union-attr]
        assert payload["finding_id"] == "F-mcp-001"
        assert "poc_dir" in payload
