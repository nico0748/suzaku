"""``suzaku compass`` サブコマンド。"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from suzaku.compass.grep_runner import GrepRunner, RipgrepNotFoundError
from suzaku.compass.rules import (
    Rule,
    RuleError,
    load_all_rules,
    load_rule_by_id,
)
from suzaku.models import Finding

SUZAKU_RED = "#B43E3E"

app = typer.Typer(
    name="compass",
    help="羅針 (Compass) — 危険関数 grep + Semgrep ルールによる脆弱性検出",
    no_args_is_help=True,
)
console = Console()


def _print_findings_table(findings: list[Finding], rule_id: str) -> None:
    table = Table(title=f"[bold {SUZAKU_RED}]Compass — {rule_id} ({len(findings)} hits)[/]")
    table.add_column("Severity", style="bold")
    table.add_column("File")
    table.add_column("Line", justify="right")
    table.add_column("Snippet")
    for f in findings[:200]:
        table.add_row(
            f.severity.value.upper(),
            f.file_path,
            str(f.line_number),
            f.snippet[:120],
        )
    console.print(table)


@app.command()
def scan(
    repo_path: Path = typer.Argument(..., exists=True, dir_okay=True, help="対象 repo"),
    rule: str | None = typer.Option(
        None, "--rule", "-r", help="ルール ID または path/<name>"
    ),
    all_rules: bool = typer.Option(False, "--all", help="同梱ルールを全て実行"),
    json_output: bool = typer.Option(False, "--json", help="Finding を JSON で出力"),
) -> None:
    """``repo_path`` を grep ルールでスキャンする。"""
    if not rule and not all_rules:
        raise typer.BadParameter("Specify --rule or --all")

    rules: list[Rule]
    try:
        rules = load_all_rules() if all_rules else [load_rule_by_id(rule or "")]
    except RuleError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(2) from e

    runner = GrepRunner()
    all_findings = []
    for r in rules:
        try:
            findings = runner.scan(repo_path, r)
        except RipgrepNotFoundError as e:
            console.print(f"[red]{e}[/red]")
            raise typer.Exit(3) from e
        all_findings.extend(findings)
        if not json_output:
            _print_findings_table(findings, r.id)

    if json_output:
        console.print_json(
            data=[f.model_dump(mode="json") for f in all_findings]
        )


@app.command(name="list-rules")
def list_rules() -> None:
    """同梱ルール一覧を表示する。"""
    rules = load_all_rules()
    table = Table(title=f"[bold {SUZAKU_RED}]Compass — built-in rules[/]")
    table.add_column("ID")
    table.add_column("CWE")
    table.add_column("Severity", justify="right")
    table.add_column("Languages")
    for r in rules:
        langs = sorted({p.language for p in r.patterns})
        table.add_row(r.id, r.cwe, r.severity.value, ", ".join(langs))
    console.print(table)


@app.command(name="show-rule")
def show_rule(rule: str) -> None:
    """ルール定義を JSON で表示する。"""
    r = load_rule_by_id(rule)
    console.print_json(
        data={
            "id": r.id,
            "name": r.name,
            "cwe": r.cwe,
            "severity": r.severity.value,
            "patterns": [
                {"language": p.language, "grep": p.grep, "must_not_contain": p.must_not_contain}
                for p in r.patterns
            ],
            "references": r.references,
        }
    )
