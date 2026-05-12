"""``suzaku sentinel`` サブコマンド。"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from suzaku.sentinel.scoring import (
    DEFAULT_SIGNALS_PATH,
    ScoringConfig,
    score_repo,
)
from suzaku.sentinel.search import (
    GitHubSearch,
    signals_from_summary,
)

SUZAKU_RED = "#B43E3E"

app = typer.Typer(
    name="sentinel",
    help="斥候 (Sentinel) — 8 シグナル評価による OSS ターゲット選定",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    language: str = typer.Option(None, "--language", "-l", help="GitHub の language フィルタ"),
    min_stars: int = typer.Option(500, "--min-stars", help="最低スター数"),
    pushed_after: str | None = typer.Option(
        None, "--pushed-after", help="ISO 日付 (例: 2026-01-01)"
    ),
    topic: list[str] = typer.Option([], "--topic", help="GitHub topic フィルタ (複数可)"),
    top: int = typer.Option(20, "--top", help="上位 N 件を出力"),
    token: str | None = typer.Option(None, "--token", envvar="SUZAKU_GITHUB_TOKEN"),
    signals_path: Path = typer.Option(
        DEFAULT_SIGNALS_PATH, "--signals", help="signals.yaml のパス"
    ),
    json_output: bool = typer.Option(False, "--json", help="JSON 配列で出力"),
) -> None:
    """GitHub から候補リポジトリを取得し 8 シグナルでスコアリングする。"""
    pushed_dt = (
        datetime.fromisoformat(pushed_after).replace(tzinfo=UTC) if pushed_after else None
    )
    config = ScoringConfig.load(signals_path)

    with GitHubSearch(token=token) as gh:
        repos = gh.search_repositories(
            language=language,
            min_stars=min_stars,
            pushed_after=pushed_dt,
            topics=topic,
            top=top,
        )

    rows = []
    for r in repos:
        signals = signals_from_summary(r)
        per, score = score_repo(signals, config)
        rows.append((r, per, score))
    rows.sort(key=lambda x: x[2], reverse=True)

    if json_output:
        out = [
            {
                "name": r.full_name,
                "url": r.html_url,
                "language": r.language,
                "stars": r.stargazers_count,
                "score": score,
                "signals": per,
            }
            for r, per, score in rows
        ]
        console.print_json(data=out)
        return

    table = Table(title=f"[bold {SUZAKU_RED}]Suzaku Sentinel — top {top}[/]")
    table.add_column("Score", style=f"bold {SUZAKU_RED}", justify="right")
    table.add_column("Stars", justify="right")
    table.add_column("Name")
    table.add_column("Language")
    for r, _per, score in rows:
        table.add_row(
            f"{score:.2f}",
            str(r.stargazers_count),
            r.full_name,
            r.language or "-",
        )
    console.print(table)


@app.command(name="list-signals")
def list_signals(
    signals_path: Path = typer.Option(DEFAULT_SIGNALS_PATH, "--signals"),
) -> None:
    """signals.yaml の重みを表示する。"""
    cfg = ScoringConfig.load(signals_path)
    table = Table(title=f"[bold {SUZAKU_RED}]Signal weights[/]")
    table.add_column("Signal")
    table.add_column("Weight", justify="right")
    for name, weight in cfg.weights.items():
        table.add_row(name, f"{weight:.2f}")
    console.print(table)


@app.command()
def show(
    target_json: Path = typer.Argument(..., help="scoring 結果の JSON ファイル"),
) -> None:
    """過去スキャン結果を読み込んで詳細を表示する。"""
    data = json.loads(target_json.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise typer.BadParameter("Expected a JSON list of scan results")
    for entry in data:
        console.print(f"[bold {SUZAKU_RED}]{entry['name']}[/] ({entry['score']:.2f})")
        for k, v in entry.get("signals", {}).items():
            console.print(f"  - {k}: {v:.2f}")
