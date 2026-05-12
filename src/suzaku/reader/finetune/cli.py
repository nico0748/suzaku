"""``suzaku reader finetune`` サブコマンド (Phase 2-A2)。"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from suzaku.reader.finetune.dataset import (
    build_from_findings,
    load_findings_jsonl,
    write_jsonl,
)
from suzaku.reader.finetune.eval import EvalResult, evaluate, load_eval_jsonl
from suzaku.reader.finetune.export import (
    DEFAULT_QUANT,
    DEFAULT_TAG,
    ExportError,
    ExportPlan,
    export_model,
)
from suzaku.reader.finetune.train import TrainError, TrainPlan, run_training
from suzaku.reader.ollama import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    OllamaClient,
    OllamaError,
)
from suzaku.witness.guard import ProductionAccessError

SUZAKU_RED = "#B43E3E"

app = typer.Typer(
    name="finetune",
    help="LoRA fine-tuning pipeline for Reader (Phase 2-A2)",
    no_args_is_help=True,
)
console = Console()


@app.command(name="build-dataset")
def build_dataset(
    findings_jsonl: Path = typer.Argument(
        ..., exists=True, help="Finding を 1 行 1 JSON で含むファイル"
    ),
    out: Path = typer.Option(
        Path("./data/reader-sft.jsonl"),
        "--out",
        "-o",
        help="出力 JSONL",
    ),
    require_published: bool = typer.Option(
        True,
        "--require-published/--allow-unpublished",
        help="未公開 Finding を除外する (default true, 安全推奨)",
    ),
) -> None:
    """Finding JSON Lines から SFT データセットを構築する。"""
    findings = load_findings_jsonl(findings_jsonl)
    samples, stats = build_from_findings(findings, require_published=require_published)
    write_jsonl(samples, out)
    console.print(
        f"[bold {SUZAKU_RED}]dataset built[/] -> {out} "
        f"(accepted={stats.accepted}/{stats.total_input})"
    )
    console.print_json(
        data={
            "total_input": stats.total_input,
            "accepted": stats.accepted,
            "excluded_not_published": stats.excluded_not_published,
            "excluded_forbidden_phrase": stats.excluded_forbidden_phrase,
            "excluded_missing_fields": stats.excluded_missing_fields,
            "dataset_sha256": stats.dataset_sha256,
        }
    )


@app.command()
def train(
    dataset: Path = typer.Argument(..., exists=True),
    output_dir: Path = typer.Option(Path("./reader/finetuned/run-001"), "--output", "-o"),
    base_model: str = typer.Option("qwen2.5-coder:14b", "--base"),
    epochs: int = typer.Option(3, "--epochs"),
    max_samples: int | None = typer.Option(None, "--max-samples"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="実学習せず、コマンドラインと環境チェックのみ"
    ),
) -> None:
    """LoRA SFT を実行する (実 GPU 環境向け; --dry-run 推奨)。"""
    plan = TrainPlan(
        base_model=base_model,
        dataset_path=dataset,
        output_dir=output_dir,
        epochs=epochs,
        max_samples=max_samples,
    )
    try:
        result = run_training(plan, dry_run=dry_run)
    except TrainError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(9) from e
    console.print_json(data={k: str(v) if not isinstance(v, (bool, int, list, dict)) else v for k, v in result.items()})


@app.command()
def export(
    run_dir: Path = typer.Argument(..., exists=True),
    output_dir: Path = typer.Option(Path("./reader/finetuned/export"), "--output", "-o"),
    tag: str = typer.Option(DEFAULT_TAG, "--tag"),
    quant: str = typer.Option(DEFAULT_QUANT, "--quant"),
    register: bool = typer.Option(
        False, "--register", help="ollama create でローカル登録 (要 ollama / llama.cpp)"
    ),
) -> None:
    """LoRA -> GGUF -> Modelfile (-> Ollama 登録)。"""
    plan = ExportPlan(run_dir=run_dir, output_dir=output_dir, tag=tag, quant=quant)
    try:
        result = export_model(plan, register_with_ollama=register)
    except ExportError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(10) from e
    console.print_json(data=result)


@app.command(name="eval")
def eval_cmd(
    eval_jsonl: Path = typer.Argument(..., exists=True),
    ollama_url: str = typer.Option(
        DEFAULT_BASE_URL, "--ollama-url", envvar="SUZAKU_OLLAMA_BASE_URL"
    ),
    model: str = typer.Option(DEFAULT_MODEL, "--model"),
    record_per_sample: bool = typer.Option(False, "--per-sample"),
    out: Path | None = typer.Option(None, "--out"),
) -> None:
    """fine-tuned モデルを評価する。"""
    samples = load_eval_jsonl(eval_jsonl)
    try:
        client = OllamaClient(base_url=ollama_url, model=model)
    except ProductionAccessError as e:
        console.print(f"[red][!] {e}[/red]")
        raise typer.Exit(4) from e

    with client:
        try:
            result: EvalResult = evaluate(samples, client, record_per_sample=record_per_sample)
        except OllamaError as e:
            console.print(f"[red]{e}[/red]")
            raise typer.Exit(6) from e

    summary = result.as_dict()
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(
                {
                    "summary": summary,
                    "per_sample": result.per_sample if record_per_sample else [],
                    "model": model,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    console.print(f"[bold {SUZAKU_RED}]eval[/] model={model}")
    console.print_json(data=summary)


__all__ = ["app"]
