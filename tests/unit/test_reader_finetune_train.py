"""train.py のテスト (subprocess は CommandRunner で差替え)。"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from suzaku.reader.finetune.train import (
    TrainError,
    TrainPlan,
    build_command,
    run_training,
)


class _Runner:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.calls: list[Sequence[str]] = []
        self._returncode = returncode
        self._stdout = stdout
        self._stderr = stderr

    def __call__(self, cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(tuple(cmd))
        return subprocess.CompletedProcess(
            args=list(cmd), returncode=self._returncode, stdout=self._stdout, stderr=self._stderr
        )


@pytest.fixture
def dataset(tmp_path: Path) -> Path:
    p = tmp_path / "ds.jsonl"
    p.write_text('{"instruction":"x","input":"y","output":"z"}\n')
    return p


class TestBuildCommand:
    def test_includes_required_flags(self, dataset: Path, tmp_path: Path) -> None:
        plan = TrainPlan(base_model="qwen", dataset_path=dataset, output_dir=tmp_path / "out")
        cmd = build_command(plan)
        assert "--base" in cmd
        assert "qwen" in cmd
        assert "--dataset" in cmd
        assert str(dataset) in cmd
        assert "--epochs" in cmd

    def test_max_samples_appended(self, dataset: Path, tmp_path: Path) -> None:
        plan = TrainPlan(
            base_model="qwen",
            dataset_path=dataset,
            output_dir=tmp_path / "out",
            max_samples=100,
        )
        cmd = build_command(plan)
        assert "--max-samples" in cmd
        assert "100" in cmd


class TestRunTraining:
    def test_dry_run_does_not_invoke_runner(self, dataset: Path, tmp_path: Path) -> None:
        runner = _Runner()
        plan = TrainPlan(base_model="qwen", dataset_path=dataset, output_dir=tmp_path / "out")
        result = run_training(plan, dry_run=True, runner=runner)
        assert result["dry_run"] is True
        assert "command" in result
        # python --version を 1 度呼ぶ (環境チェック)
        assert any("--version" in " ".join(c) for c in runner.calls)

    def test_missing_dataset_raises(self, tmp_path: Path) -> None:
        plan = TrainPlan(
            base_model="qwen", dataset_path=tmp_path / "nope", output_dir=tmp_path / "out"
        )
        with pytest.raises(TrainError):
            run_training(plan, dry_run=True)

    def test_unsloth_missing_raises_on_real_run(self, dataset: Path, tmp_path: Path) -> None:
        runner = _Runner()
        plan = TrainPlan(base_model="qwen", dataset_path=dataset, output_dir=tmp_path / "out")
        # unsloth は未インストール環境を想定
        with pytest.raises(TrainError) as exc:
            run_training(plan, dry_run=False, runner=runner)
        assert "unsloth" in str(exc.value).lower() or "python3" in str(exc.value).lower()
