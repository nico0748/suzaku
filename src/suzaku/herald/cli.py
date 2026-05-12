"""``suzaku herald`` サブコマンド。"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from suzaku.herald.checklist import (
    ChecklistError,
    SubmissionInput,
    validate_submission,
)
from suzaku.herald.cvss import CVSSError, score_severity, score_vector
from suzaku.herald.email_tmpl import ExtortionLanguageError, render_email
from suzaku.herald.ghsa import Advisory, render_ghsa
from suzaku.herald.routes import (
    ContactAttempt,
    RouteContext,
    RouteError,
    list_routes,
    render_for_route,
)
from suzaku.models import Route

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


def _build_route_context(context_path: Path | None) -> RouteContext:
    if context_path is None:
        return RouteContext()
    raw = json.loads(context_path.read_text(encoding="utf-8"))
    attempts = [
        ContactAttempt(
            attempted_at=datetime.fromisoformat(a["attempted_at"]),
            channel=str(a["channel"]),
            response=str(a["response"]),
            note=str(a.get("note", "")),
        )
        for a in raw.get("vendor_contact_attempts", [])
    ]
    return RouteContext(
        vendor_contact_attempts=attempts,
        huntr_package_name=raw.get("huntr_package_name"),
        huntr_package_ecosystem=raw.get("huntr_package_ecosystem"),
        huntr_repo_url=raw.get("huntr_repo_url"),
        jpcert_reporter_role=raw.get("jpcert_reporter_role", "security_researcher"),
        wp_plugin_slug=raw.get("wp_plugin_slug"),
        wp_active_installs=raw.get("wp_active_installs"),
        program_handle=raw.get("program_handle"),
        asset_identifier=raw.get("asset_identifier"),
    )


@app.command()
def submit(
    route: str = typer.Argument(..., help="ghsa / mitre / huntr / jpcert / wordfence / patchstack / hackerone / bugcrowd"),
    advisory_json: Path = typer.Argument(..., exists=True),
    context: Path | None = typer.Option(
        None, "--context", "-c", help="ルート別追加情報の JSON"
    ),
) -> None:
    """指定ルート向けの申請テンプレートを stdout に出力する。"""
    try:
        route_enum = Route(route.lower())
    except ValueError as e:
        console.print(f"[red]Unknown route: {route!r}[/red]")
        raise typer.Exit(2) from e

    raw = json.loads(advisory_json.read_text(encoding="utf-8"))
    submission_data = raw.pop("submission", {})
    submission = SubmissionInput(**submission_data)
    advisory = Advisory(submission=submission, **raw)
    ctx = _build_route_context(context)

    try:
        body = render_for_route(advisory, route_enum, ctx)
    except (ChecklistError, RouteError, ExtortionLanguageError) as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    typer.echo(body)


@app.command(name="list-routes")
def list_routes_cmd() -> None:
    """同梱ルート一覧 + 申請 URL を表示する。"""
    table = Table(title=f"[bold {SUZAKU_RED}]Herald — submission routes[/]")
    table.add_column("Route")
    table.add_column("Name")
    table.add_column("Submit URL")
    for route, meta in list_routes():
        table.add_row(route.value, str(meta.get("name", "")), str(meta.get("submit_url", "")))
    console.print(table)
