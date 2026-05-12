"""``suzaku herald`` サブコマンド。"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from suzaku.herald.checklist import (
    ChecklistError,
    SubmissionInput,
    validate_submission,
)
from suzaku.herald.cvss import CVSSError, score_severity, score_vector
from suzaku.herald.email_tmpl import ExtortionLanguageError, render_email
from suzaku.herald.ghsa import Advisory, render_ghsa

SUZAKU_RED = "#B43E3E"

app = typer.Typer(
    name="herald",
    help="奏上 (Herald) — GHSA Markdown + CVSS 計算 + 報告メール生成",
    no_args_is_help=True,
)
console = Console()


@app.command()
def cvss(vector: str) -> None:
    """CVSS v3.1 ベクタからスコア・ラベルを計算する。"""
    try:
        score = score_vector(vector)
    except CVSSError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(2) from e
    label = score_severity(score)
    console.print(f"[bold {SUZAKU_RED}]CVSS 3.1[/] {score} / {label}")
    console.print(f"Vector: [bold]{vector}[/]")


@app.command()
def checklist(submission_json: Path) -> None:
    """``submission.json`` の 5 点セット欠落を検証する。"""
    data = json.loads(submission_json.read_text(encoding="utf-8"))
    sub = SubmissionInput(**data)
    try:
        validate_submission(sub)
    except ChecklistError as e:
        console.print(f"[red][missing] {e}[/red]")
        raise typer.Exit(1) from e
    console.print("[bold green]OK[/] 5-point checklist satisfied.")
    console.print(f"CVSS: {sub.cvss_score} ({sub.severity_label}) — CWE: {sub.cwe}")


@app.command()
def ghsa(advisory_json: Path) -> None:
    """Advisory JSON から GHSA Markdown を生成して stdout へ出力する。"""
    data = json.loads(advisory_json.read_text(encoding="utf-8"))
    submission_data = data.pop("submission", {})
    submission = SubmissionInput(**submission_data)
    advisory = Advisory(submission=submission, **data)
    try:
        md = render_ghsa(advisory)
    except ChecklistError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    typer.echo(md)


@app.command()
def email(advisory_json: Path) -> None:
    """vendor 向け coordinated-disclosure メール本文を生成する。"""
    data = json.loads(advisory_json.read_text(encoding="utf-8"))
    submission_data = data.pop("submission", {})
    submission = SubmissionInput(**submission_data)
    advisory = Advisory(submission=submission, **data)
    try:
        body = render_email(advisory)
    except (ChecklistError, ExtortionLanguageError) as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    typer.echo(body)
