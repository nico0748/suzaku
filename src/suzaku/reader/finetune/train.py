"""LoRA SFT 学習ラッパー (Phase 2-A2)。

Unsloth は重い optional dependency なので、本モジュールは:

1. 引数検証 + データセット存在確認
2. 環境チェック (`unsloth` import 可否 / GPU 検出)
3. `--dry-run` 時は実学習をスキップして TrainPlan を返す
4. 実学習時は Unsloth トレーニングスクリプトを subprocess で呼ぶ

学習スクリプト本体は ``unsloth/sft_train.py`` (本ツールの外部スクリプト
を想定) を呼び出す薄いラッパに留める。テストでは subprocess をモックする。
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


def _default_runner(cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(cmd), capture_output=True, text=True, check=False)


class TrainError(RuntimeError):
    """学習の前提条件が満たされない場合に発生。"""


@dataclass
class TrainPlan:
    base_model: str
    dataset_path: Path
    output_dir: Path
    epochs: int = 3
    lora_rank: int = 16
    lora_alpha: int = 32
    lora_dropout: float = 0.05
    learning_rate: float = 2e-4
    max_samples: int | None = None
    seed: int = 42

    extra_args: list[str] = field(default_factory=list)


def _env_has_unsloth() -> bool:
    try:
        import unsloth  # noqa: F401
    except Exception:
        return False
    return True


def _env_has_python(runner: CommandRunner) -> bool:
    python = shutil.which("python3") or shutil.which("python")
    if python is None:
        return False
    result = runner([python, "--version"])
    return result.returncode == 0


def check_environment(runner: CommandRunner = _default_runner) -> dict[str, bool]:
    """unsloth + python の存在を検査して dict で返す。"""
    return {
        "python_available": _env_has_python(runner),
        "unsloth_available": _env_has_unsloth(),
    }


def build_command(plan: TrainPlan) -> list[str]:
    """Unsloth 学習スクリプト呼出のコマンドラインを組み立てる。

    実スクリプトの位置はユーザ運用に依存するので ``-m suzaku_finetune_trainer``
    を仮置きする。本ツールに同梱はしない。
    """
    cmd: list[str] = [
        "python3",
        "-m",
        "suzaku_finetune_trainer",
        "--base",
        plan.base_model,
        "--dataset",
        str(plan.dataset_path),
        "--output",
        str(plan.output_dir),
        "--epochs",
        str(plan.epochs),
        "--lora-rank",
        str(plan.lora_rank),
        "--lora-alpha",
        str(plan.lora_alpha),
        "--lora-dropout",
        str(plan.lora_dropout),
        "--learning-rate",
        str(plan.learning_rate),
        "--seed",
        str(plan.seed),
    ]
    if plan.max_samples is not None:
        cmd.extend(["--max-samples", str(plan.max_samples)])
    cmd.extend(plan.extra_args)
    return cmd


def run_training(
    plan: TrainPlan,
    *,
    dry_run: bool = False,
    runner: CommandRunner = _default_runner,
) -> dict[str, object]:
    """学習を実行する。dry_run なら subprocess は呼ばず plan + cmd を返す。"""
    if not plan.dataset_path.exists():
        raise TrainError(f"Dataset not found: {plan.dataset_path}")
    plan.output_dir.mkdir(parents=True, exist_ok=True)

    cmd = build_command(plan)

    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "command": cmd,
            "environment": check_environment(runner),
        }

    env = check_environment(runner)
    if not env["python_available"]:
        raise TrainError("python3 not found in PATH")
    if not env["unsloth_available"]:
        raise TrainError(
            "unsloth not installed. Install with `pip install unsloth` "
            "in an environment with GPU support."
        )

    result = runner(cmd)
    return {
        "ok": result.returncode == 0,
        "dry_run": False,
        "command": cmd,
        "returncode": result.returncode,
        "stdout": result.stdout[-4000:] if result.stdout else "",
        "stderr": result.stderr[-4000:] if result.stderr else "",
    }


__all__ = [
    "CommandRunner",
    "TrainError",
    "TrainPlan",
    "build_command",
    "check_environment",
    "run_training",
]
