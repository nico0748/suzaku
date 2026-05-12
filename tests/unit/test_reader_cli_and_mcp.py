"""Reader CLI と MCP 統合の最小テスト。"""

from __future__ import annotations

import httpx
import pytest
import respx
from typer.testing import CliRunner

from suzaku.cli import app
from suzaku.reader.ollama import DEFAULT_BASE_URL

runner = CliRunner()


class TestReaderCli:
    @respx.mock
    def test_check_unavailable(self) -> None:
        respx.get(f"{DEFAULT_BASE_URL}/api/tags").mock(
            side_effect=httpx.ConnectError("nope")
        )
        result = runner.invoke(app, ["reader", "check"])
        # health() returns False on ConnectError, so the CLI exits 7 (model not found)
        assert result.exit_code in {6, 7}

    @respx.mock
    def test_check_with_model_present(self) -> None:
        respx.get(f"{DEFAULT_BASE_URL}/api/tags").respond(
            200, json={"models": [{"name": "qwen2.5-coder:14b"}]}
        )
        result = runner.invoke(app, ["reader", "check"])
        assert result.exit_code == 0
        assert "OK" in result.stdout

    def test_check_blocks_public_host(self) -> None:
        result = runner.invoke(
            app, ["reader", "check", "--ollama-url", "http://api.openai.com"]
        )
        assert result.exit_code == 4  # ProductionAccessError -> exit 4

    @respx.mock
    def test_list_models(self) -> None:
        respx.get(f"{DEFAULT_BASE_URL}/api/tags").respond(
            200, json={"models": [{"name": "a:1"}, {"name": "b:2"}]}
        )
        result = runner.invoke(app, ["reader", "list-models"])
        assert result.exit_code == 0
        assert "a:1" in result.stdout
        assert "b:2" in result.stdout


class TestReaderInMcp:
    def test_reader_tools_in_ro_listing(self) -> None:
        from suzaku.mcp.tools import RO_TOOLS, list_tool_specs

        assert "reader_check" in RO_TOOLS
        assert "reader_overview" in RO_TOOLS
        assert "reader_read" in RO_TOOLS
        names = {s.name for s in list_tool_specs("ro")}
        for n in ("reader_check", "reader_overview", "reader_read"):
            assert n in names

    @respx.mock
    def test_reader_check_via_dispatch(self) -> None:
        from suzaku.mcp.tools import dispatch

        respx.get(f"{DEFAULT_BASE_URL}/api/tags").respond(
            200, json={"models": [{"name": "qwen2.5-coder:14b"}]}
        )
        result = dispatch("reader_check", {}, "ro")
        assert result["reachable"] is True


@pytest.fixture(autouse=True)
def _no_color(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
