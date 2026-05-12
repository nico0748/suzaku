"""export.py のテスト (subprocess + which をモック)。"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from suzaku.reader.finetune.export import (
    ExportError,
    ExportPlan,
    export_model,
)


class _Runner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(tuple(cmd))
        # 最初の 2 回 (convert + quantize) は成功扱い、それ以降 (ollama create) も成功
        return subprocess.CompletedProcess(args=list(cmd), returncode=0, stdout="ok", stderr="")


def _which_returns_self(name: str) -> str | None:
    return f"/usr/bin/{name}"


def _which_none(_name: str) -> None:
    return None


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    d = tmp_path / "run"
    d.mkdir()
    (d / "adapter_config.json").write_text("{}")
    return d


class TestExportModel:
    def test_happy_path_no_ollama(
        self, run_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("suzaku.reader.finetune.export.shutil.which", _which_returns_self)
        runner = _Runner()
        plan = ExportPlan(
            run_dir=run_dir, output_dir=tmp_path / "out", tag="suzaku-x:14b"
        )
        result = export_model(plan, runner=runner)
        assert result["tag"] == "suzaku-x:14b"
        modelfile = Path(result["modelfile"])  # type: ignore[arg-type]
        assert modelfile.exists()
        content = modelfile.read_text()
        assert "FROM ./" in content
        assert "SYSTEM" in content

    def test_quantize_runs_when_quant_set(
        self, run_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("suzaku.reader.finetune.export.shutil.which", _which_returns_self)
        runner = _Runner()
        plan = ExportPlan(run_dir=run_dir, output_dir=tmp_path / "out", quant="q4_k_m")
        export_model(plan, runner=runner)
        commands = [" ".join(c) for c in runner.calls]
        assert any("convert_hf_to_gguf.py" in c for c in commands)
        assert any("llama-quantize" in c and "q4_k_m" in c for c in commands)

    def test_register_invokes_ollama(
        self, run_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("suzaku.reader.finetune.export.shutil.which", _which_returns_self)
        runner = _Runner()
        plan = ExportPlan(run_dir=run_dir, output_dir=tmp_path / "out")
        result = export_model(plan, register_with_ollama=True, runner=runner)
        assert result["ollama_registered"] is True
        commands = [" ".join(c) for c in runner.calls]
        assert any("ollama" in c and "create" in c for c in commands)

    def test_missing_binary_raises(
        self, run_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("suzaku.reader.finetune.export.shutil.which", _which_none)
        plan = ExportPlan(run_dir=run_dir, output_dir=tmp_path / "out")
        with pytest.raises(ExportError):
            export_model(plan, runner=_Runner())

    def test_missing_run_dir_raises(self, tmp_path: Path) -> None:
        plan = ExportPlan(run_dir=tmp_path / "missing", output_dir=tmp_path / "out")
        with pytest.raises(ExportError):
            export_model(plan, runner=_Runner())

    def test_convert_failure_raises(
        self, run_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("suzaku.reader.finetune.export.shutil.which", _which_returns_self)

        def failing(cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args=list(cmd), returncode=2, stdout="", stderr="boom"
            )

        plan = ExportPlan(run_dir=run_dir, output_dir=tmp_path / "out")
        with pytest.raises(ExportError) as exc:
            export_model(plan, runner=failing)
        assert "convert" in str(exc.value).lower() or "boom" in str(exc.value)
