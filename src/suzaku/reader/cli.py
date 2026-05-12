"""``suzaku reader`` サブコマンド。"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from suzaku.reader.ollama import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    OllamaClient,
    OllamaError,
    OllamaUnavailableError,
)
from suzaku.reader.stages import (
    ReaderParseError,
    read_repo,
    stage_overview,
)
from suzaku.witness.guard import ProductionAccessError

SUZAKU_RED = "#B43E3E"

app = typer.Typer(
    name="reader",
    help="読眼 (Reader) — ローカル LLM (Ollama) によるコード読解 (Phase 2-A1)",
    no_args_is_help=True,
)
console = Console()


def _client(
    base_url: str, model: str
) -> OllamaClient:
    try:
        return OllamaClient(base_url=base_url, model=model)
    except ProductionAccessError as e:
        console.print(f"[red][!] {e}[/red]")
        raise typer.Exit(4) from e


@app.command()
def check(
    ollama_url: str = typer.Option(
        DEFAULT_BASE_URL, "--ollama-url", envvar="SUZAKU_OLLAMA_BASE_URL"
    ),
    model: str = typer.Option(DEFAULT_MODEL, "--model", envvar="SUZAKU_OLLAMA_MODEL"),
) -> None:
    """Ollama 疎通確認 + 指定モデルの存在チェック。"""
    with _client(ollama_url, model) as client:
        try:
            ok = client.health()
        except OllamaUnavailableError as e:
            console.print(f"[red]Ollama unavailable: {e}[/red]")
            raise typer.Exit(6) from e
        except OllamaError as e:
            console.print(f"[red]{e}[/red]")
            raise typer.Exit(6) from e
    if ok:
        console.print(f"[bold green]OK[/] — Ollama at {ollama_url}, model={model}")
    else:
        console.print(
            f"[yellow]Ollama reachable at {ollama_url} but model "
            f"'{model}' not found. Pull it with: ollama pull {model}[/yellow]"
        )
        raise typer.Exit(7)


@app.command(name="list-models")
def list_models_cmd(
    ollama_url: str = typer.Option(
        DEFAULT_BASE_URL, "--ollama-url", envvar="SUZAKU_OLLAMA_BASE_URL"
    ),
) -> None:
    """ローカル Ollama の利用可能モデル一覧。"""
    with _client(ollama_url, model=DEFAULT_MODEL) as client:
        try:
            names = client.list_models()
        except OllamaUnavailableError as e:
            console.print(f"[red]Ollama unavailable: {e}[/red]")
            raise typer.Exit(6) from e
    table = Table(title=f"[bold {SUZAKU_RED}]Ollama models @ {ollama_url}[/]")
    table.add_column("Model")
    for n in names:
        table.add_row(n)
    console.print(table)


@app.command()
def read(
    repo_path: Path = typer.Argument(..., exists=True, dir_okay=True, file_okay=False),
    stage: str = typer.Option(
        "all",
        "--stage",
        help="all / overview のいずれか (Phase 2-A1 では overview と all のみ)",
    ),
    ollama_url: str = typer.Option(
        DEFAULT_BASE_URL, "--ollama-url", envvar="SUZAKU_OLLAMA_BASE_URL"
    ),
    model: str = typer.Option(DEFAULT_MODEL, "--model", envvar="SUZAKU_OLLAMA_MODEL"),
    json_output: bool = typer.Option(False, "--json", help="JSON で出力"),
) -> None:
    """``repo_path`` を 4 段階で読解する (LLM 推論あり、数十秒〜数分かかる)。"""
    if stage not in {"all", "overview"}:
        raise typer.BadParameter("--stage must be 'all' or 'overview'")

    with _client(ollama_url, model) as client:
        try:
            if stage == "overview":
                result = stage_overview(repo_path, client)
                payload = result.model_dump_json(indent=2)
            else:
                report = read_repo(repo_path, client)
                payload = report.model_dump_json(indent=2)
        except OllamaUnavailableError as e:
            console.print(f"[red]Ollama unavailable: {e}[/red]")
            raise typer.Exit(6) from e
        except OllamaError as e:
            console.print(f"[red]{e}[/red]")
            raise typer.Exit(6) from e
        except ReaderParseError as e:
            console.print(f"[red]LLM produced invalid JSON: {e}[/red]")
            raise typer.Exit(8) from e

    if json_output:
        typer.echo(payload)
    else:
        console.print(f"[bold {SUZAKU_RED}]Reader result[/] (model={model})")
        console.print_json(payload)


__all__ = ["app"]
