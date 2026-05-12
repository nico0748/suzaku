"""suzaku reader finetune CLI のテスト。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from suzaku.cli import app

runner = CliRunner()


def _write(p: Path, body: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


@pytest.fixture
def findings_jsonl(tmp_path: Path) -> Path:
    rows = [
        {
            "id": "F-1",
            "target_url": "https://github.com/x/y",
            "category": "ZipSlip",
            "severity": "high",
            "cwe": "CWE-22",
            "file_path": "a.py",
            "line_number": 1,
            "snippet": "zipfile.extractall(p)",
            "state": "published",
        },
        {
            "id": "F-2",
            "target_url": "https://github.com/x/y",
            "category": "SSRF",
            "severity": "high",
            "cwe": "CWE-918",
            "file_path": "b.py",
            "line_number": 2,
            "snippet": "requests.get(user_url)",
            "state": "new",  # 未公開 -> 除外される想定
        },
    ]
    p = tmp_path / "findings.jsonl"
    _write(p, "\n".join(json.dumps(r) for r in rows))
    return p


class TestBuildDataset:
    def test_excludes_unpublished_by_default(self, findings_jsonl: Path, tmp_path: Path) -> None:
        out = tmp_path / "sft.jsonl"
        result = runner.invoke(
            app,
            [
                "reader",
                "finetune",
                "build-dataset",
                str(findings_jsonl),
                "--out",
                str(out),
            ],
        )
        assert result.exit_code == 0
        lines = out.read_text().strip().splitlines()
        assert len(lines) == 1  # F-1 のみ


class TestTrain:
    def test_dry_run(self, tmp_path: Path, findings_jsonl: Path) -> None:
        # まず dataset を作る
        out = tmp_path / "sft.jsonl"
        runner.invoke(
            app,
            [
                "reader",
                "finetune",
                "build-dataset",
                str(findings_jsonl),
                "--out",
                str(out),
            ],
        )
        result = runner.invoke(
            app,
            [
                "reader",
                "finetune",
                "train",
                str(out),
                "--output",
                str(tmp_path / "run-001"),
                "--dry-run",
            ],
        )
        assert result.exit_code == 0
        assert "command" in result.stdout
        assert "dry_run" in result.stdout


class TestSubcommandsListed:
    def test_finetune_subcommand_listed_under_reader(self) -> None:
        result = runner.invoke(app, ["reader", "--help"])
        assert result.exit_code == 0
        assert "finetune" in result.stdout

    def test_build_dataset_in_finetune_help(self) -> None:
        result = runner.invoke(app, ["reader", "finetune", "--help"])
        assert result.exit_code == 0
        assert "build-dataset" in result.stdout
        assert "train" in result.stdout
        assert "export" in result.stdout
        assert "eval" in result.stdout


@pytest.fixture(autouse=True)
def _no_color(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
