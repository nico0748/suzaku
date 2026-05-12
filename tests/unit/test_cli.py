"""Suzaku CLI 統合テスト (typer.testing.CliRunner)。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from suzaku.cli import app

runner = CliRunner()


class TestRootHelp:
    def test_version(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "Suzaku" in result.stdout

    def test_help_lists_all_modules(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        for cmd in ["sentinel", "compass", "witness", "herald", "chronicle"]:
            assert cmd in result.stdout


class TestHeraldCli:
    def test_cvss_command(self) -> None:
        result = runner.invoke(
            app, ["herald", "cvss", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]
        )
        assert result.exit_code == 0
        assert "9.8" in result.stdout
        assert "Critical" in result.stdout

    def test_cvss_invalid_vector(self) -> None:
        result = runner.invoke(app, ["herald", "cvss", "garbage"])
        assert result.exit_code == 2

    def test_checklist_passes(self, tmp_path: Path) -> None:
        sub = {
            "product_name": "example-app",
            "vendor": "Example Inc.",
            "affected_versions": ">=1.0.0,<1.2.3",
            "cwe": "CWE-22",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "reproduction_steps_path": "./pocs/F-001/steps.md",
            "reference_urls": ["https://github.com/example/x/commit/abc"],
        }
        p = tmp_path / "sub.json"
        p.write_text(json.dumps(sub))
        result = runner.invoke(app, ["herald", "checklist", str(p)])
        assert result.exit_code == 0


class TestCompassCli:
    def test_list_rules_returns_zero(self) -> None:
        result = runner.invoke(app, ["compass", "list-rules"])
        assert result.exit_code == 0

    def test_show_rule(self) -> None:
        result = runner.invoke(app, ["compass", "show-rule", "ssrf"])
        assert result.exit_code == 0
        assert "CWE-918" in result.stdout

    def test_unknown_rule(self) -> None:
        result = runner.invoke(app, ["compass", "show-rule", "nope"])
        assert result.exit_code != 0


class TestWitnessCli:
    def test_init_creates_files(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            ["witness", "init", "F-001", "--pocs-dir", str(tmp_path / "pocs")],
        )
        assert result.exit_code == 0
        assert (tmp_path / "pocs" / "F-001" / "Dockerfile").exists()

    def test_check_host_allowed(self) -> None:
        result = runner.invoke(app, ["witness", "check-host", "127.0.0.1"])
        assert result.exit_code == 0
        assert "ALLOWED" in result.stdout

    def test_check_host_blocked(self) -> None:
        result = runner.invoke(app, ["witness", "check-host", "github.com"])
        assert result.exit_code != 0
        assert "BLOCKED" in result.stdout

    def test_record_and_verify(self, tmp_path: Path) -> None:
        evidence = tmp_path / "evidence"
        finding = "F-001"
        target = evidence / finding
        target.mkdir(parents=True)
        sample = target / "Dockerfile"
        sample.write_text("FROM alpine:3.20")
        result = runner.invoke(
            app,
            [
                "witness",
                "record",
                finding,
                str(sample),
                "--evidence-dir",
                str(evidence),
            ],
        )
        assert result.exit_code == 0
        verify = runner.invoke(
            app,
            ["witness", "verify", finding, "--evidence-dir", str(evidence)],
        )
        assert verify.exit_code == 0


class TestChronicleCli:
    def test_init_status_publish(self, tmp_path: Path) -> None:
        state = tmp_path / "chron"
        sid = "S-001"
        init = runner.invoke(app, ["chronicle", "init", sid, "--state-dir", str(state)])
        assert init.exit_code == 0
        assert (state / f"{sid}.json").exists()

        status = runner.invoke(
            app, ["chronicle", "status", sid, "--state-dir", str(state)]
        )
        assert status.exit_code == 0
        assert "Day 0" in status.stdout

        # Day 0 直後の公開試行は ACCS ガードで拒否されるはず
        publish = runner.invoke(
            app, ["chronicle", "publish", sid, "--state-dir", str(state)]
        )
        assert publish.exit_code == 5  # ACCSViolationError exit code
        assert "ACCS" in publish.stdout

    def test_set_vendor_and_list(self, tmp_path: Path) -> None:
        state = tmp_path / "chron"
        sid = "S-002"
        runner.invoke(app, ["chronicle", "init", sid, "--state-dir", str(state)])
        result = runner.invoke(
            app,
            ["chronicle", "set-vendor", sid, "acknowledged", "--state-dir", str(state)],
        )
        assert result.exit_code == 0
        listing = runner.invoke(app, ["chronicle", "list", "--state-dir", str(state)])
        assert listing.exit_code == 0
        assert sid in listing.stdout


class TestSentinelCli:
    def test_list_signals(self) -> None:
        result = runner.invoke(app, ["sentinel", "list-signals"])
        assert result.exit_code == 0
        assert "maintenance_inactivity" in result.stdout

    def test_show_with_synthetic_json(self, tmp_path: Path) -> None:
        data = [
            {
                "name": "example/x",
                "url": "https://github.com/example/x",
                "language": "python",
                "stars": 1234,
                "score": 7.2,
                "signals": {"maintenance_inactivity": 0.8, "monetary": 0.3},
            }
        ]
        p = tmp_path / "results.json"
        p.write_text(json.dumps(data))
        result = runner.invoke(app, ["sentinel", "show", str(p)])
        assert result.exit_code == 0
        assert "example/x" in result.stdout


@pytest.fixture(autouse=True)
def _no_color(monkeypatch: pytest.MonkeyPatch) -> None:
    """rich の色付けはテスト出力比較で邪魔なので無効化。"""
    monkeypatch.setenv("NO_COLOR", "1")
