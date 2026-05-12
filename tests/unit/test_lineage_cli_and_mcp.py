"""Lineage CLI と MCP 統合のテスト。"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from suzaku.cli import app

runner = CliRunner()


def _write_cve_record_json(tmp_path: Path) -> Path:
    rec = {
        "cve_id": "CVE-2024-1234",
        "description": "demo",
        "cwe": ["CWE-918"],
        "references": ["https://github.com/example/x/commit/abc1234"],
        "commit_urls": ["https://github.com/example/x/commit/abc1234"],
        "vuln_status": "Public",
    }
    p = tmp_path / "cve.json"
    p.write_text(json.dumps(rec))
    return p


class TestIngestFile:
    def test_ingest_from_local_json(self, tmp_path: Path) -> None:
        envelope = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-1234",
                        "vulnStatus": "Public",
                        "descriptions": [{"lang": "en", "value": "demo"}],
                        "weaknesses": [{"description": [{"value": "CWE-918"}]}],
                        "references": [
                            {"url": "https://github.com/example/x/commit/abc1234"}
                        ],
                    }
                }
            ]
        }
        src = tmp_path / "in.json"
        src.write_text(json.dumps(envelope))
        out = tmp_path / "out.json"
        result = runner.invoke(
            app, ["lineage", "ingest", str(src), "--out", str(out)]
        )
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["cve_id"] == "CVE-2024-1234"

    def test_ingest_neither_arg_nor_cve(self) -> None:
        result = runner.invoke(app, ["lineage", "ingest"])
        assert result.exit_code != 0


class TestExtractOffline:
    def test_offline_extract_with_no_hunks_yields_no_rules(
        self, tmp_path: Path
    ) -> None:
        cve_json = _write_cve_record_json(tmp_path)
        out = tmp_path / "rules.json"
        result = runner.invoke(
            app,
            [
                "lineage",
                "extract",
                str(cve_json),
                "--out",
                str(out),
                "--offline",
            ],
        )
        assert result.exit_code == 0
        assert json.loads(out.read_text()) == []


class TestDemo:
    def test_demo_runs_offline(self, tmp_path: Path) -> None:
        if shutil.which("rg") is None:
            pytest.skip("ripgrep not installed")
        (tmp_path / "vuln.py").write_text(
            "import urllib\nurllib.request.urlopen(user_input)\n"
        )
        result = runner.invoke(app, ["lineage", "demo", str(tmp_path)])
        assert result.exit_code == 0
        assert "rules" in result.stdout


class TestSubcommandListing:
    def test_lineage_listed_under_main(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "lineage" in result.stdout

    def test_subcommands(self) -> None:
        result = runner.invoke(app, ["lineage", "--help"])
        assert result.exit_code == 0
        for cmd in ("ingest", "extract", "scan", "demo"):
            assert cmd in result.stdout


class TestLineageInMcp:
    def test_lineage_tools_in_ro(self) -> None:
        from suzaku.mcp.tools import RO_TOOLS, list_tool_specs

        assert "lineage_extract_from_nvd" in RO_TOOLS
        assert "lineage_scan" in RO_TOOLS
        names = {s.name for s in list_tool_specs("ro")}
        assert "lineage_extract_from_nvd" in names
        assert "lineage_scan" in names

    def test_lineage_extract_dispatch(self) -> None:
        from suzaku.mcp.tools import dispatch

        result = dispatch(
            "lineage_extract_from_nvd",
            {
                "cve_record": {
                    "cve_id": "CVE-2024-1234",
                    "description": "x",
                    "cwe": ["CWE-918"],
                    "references": ["https://github.com/example/x/commit/abc1234"],
                    "commit_urls": ["https://github.com/example/x/commit/abc1234"],
                    "vuln_status": "Public",
                },
                "hunks": [
                    {
                        "commit_url": "https://github.com/example/x/commit/abc1234",
                        "file_path": "src/fetch.py",
                        "language": "python",
                        "deleted_lines": ["urllib.request.urlopen(user_url)"],
                        "added_lines": ["if not is_allowed_host(user_url): raise"],
                    }
                ],
            },
            "ro",
        )
        assert "rules" in result
        assert len(result["rules"]) >= 1


@pytest.fixture(autouse=True)
def _no_color(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
