"""``suzaku chronicle`` サブコマンド。"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from suzaku.chronicle.escalation import (
    ACCSViolationError,
    check_publication_allowed,
    evaluate_alert,
)
from suzaku.chronicle.timeline import (
    build_timeline,
    current_milestone,
    days_elapsed,
)
from suzaku.models import VendorState

SUZAKU_RED = "#B43E3E"

app = typer.Typer(
    name="chronicle",
    help="歴記 (Chronicle) — 90 日開示タイムライン + ACCS ガード",
    no_args_is_help=True,
)
console = Console()


def _load_state(state_dir: Path, submission_id: str) -> dict[str, Any]:
    f = state_dir / f"{submission_id}.json"
    if not f.exists():
        raise typer.BadParameter(f"State file not found: {f}")
    payload: dict[str, Any] = json.loads(f.read_text(encoding="utf-8"))
    return payload


def _save_state(state_dir: Path, submission_id: str, payload: dict[str, Any]) -> Path:
    state_dir.mkdir(parents=True, exist_ok=True)
    f = state_dir / f"{submission_id}.json"
    f.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return f


@app.command()
def init(
    submission_id: str,
    state_dir: Path = typer.Option(Path("./.suzaku/chronicle"), "--state-dir"),
) -> None:
    """Day 0 を今日に設定して state ファイルを書き出す。"""
    tl = build_timeline(submission_id)
    payload = {
        "submission_id": submission_id,
        "day_0": tl.day_0.isoformat(),
        "vendor_state": VendorState.NO_RESPONSE.value,
        "milestones": {e.milestone.value: e.scheduled_at.isoformat() for e in tl.entries},
    }
    path = _save_state(state_dir, submission_id, payload)
    console.print(
        f"[bold {SUZAKU_RED}]Chronicle[/] initialised for {submission_id} (saved {path})"
    )


@app.command()
def status(
    submission_id: str,
    state_dir: Path = typer.Option(Path("./.suzaku/chronicle"), "--state-dir"),
) -> None:
    """現在のマイルストーン + 推奨アクションを表示する。"""
    state = _load_state(state_dir, submission_id)
    day_0 = datetime.fromisoformat(state["day_0"])
    tl = build_timeline(submission_id, day_0=day_0)
    vendor_state = VendorState(state.get("vendor_state", VendorState.NO_RESPONSE.value))
    now = datetime.now(UTC)
    milestone = current_milestone(tl, now=now)
    elapsed = days_elapsed(tl, now=now)
    alert = evaluate_alert(tl, vendor_state=vendor_state, now=now)

    table = Table(title=f"[bold {SUZAKU_RED}]Chronicle — {submission_id}[/]")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Day 0", day_0.isoformat())
    table.add_row("Days elapsed", str(elapsed))
    table.add_row("Current milestone", milestone.value)
    table.add_row("Vendor state", vendor_state.value)
    table.add_row("Alert level", alert.level.value)
    table.add_row("Action", alert.template)
    console.print(table)


@app.command(name="set-vendor")
def set_vendor(
    submission_id: str,
    state: str,
    state_dir: Path = typer.Option(Path("./.suzaku/chronicle"), "--state-dir"),
) -> None:
    """vendor_state を変更する (no_response/acknowledged/fixing/fixed/rejected)。"""
    payload = _load_state(state_dir, submission_id)
    payload["vendor_state"] = VendorState(state).value
    _save_state(state_dir, submission_id, payload)
    console.print(f"[bold {SUZAKU_RED}]Chronicle[/] vendor_state -> {state}")


@app.command()
def publish(
    submission_id: str,
    state_dir: Path = typer.Option(Path("./.suzaku/chronicle"), "--state-dir"),
    fixed_released_at: str | None = typer.Option(
        None, "--fixed-at", help="修正リリース日 (ISO)"
    ),
) -> None:
    """ACCS ガードを通過したら公開可能ステータスにする。"""
    state = _load_state(state_dir, submission_id)
    tl = build_timeline(submission_id, day_0=datetime.fromisoformat(state["day_0"]))
    vendor_state = VendorState(state.get("vendor_state", VendorState.NO_RESPONSE.value))
    fixed = (
        datetime.fromisoformat(fixed_released_at).replace(tzinfo=UTC)
        if fixed_released_at
        else None
    )
    try:
        check_publication_allowed(
            tl, vendor_state=vendor_state, fixed_released_at=fixed
        )
    except ACCSViolationError as e:
        console.print(f"[red][ACCS guard] {e}[/red]")
        raise typer.Exit(5) from e
    state["published_at"] = datetime.now(UTC).isoformat()
    _save_state(state_dir, submission_id, state)
    console.print(f"[bold green]Published[/] {submission_id}.")


@app.command(name="list")
def list_disclosures(
    state_dir: Path = typer.Option(Path("./.suzaku/chronicle"), "--state-dir"),
) -> None:
    """state_dir 内の全 disclosure 一覧。"""
    if not state_dir.exists():
        console.print("(no chronicle state yet)")
        return
    table = Table(title=f"[bold {SUZAKU_RED}]Chronicle entries[/]")
    table.add_column("Submission")
    table.add_column("Day 0")
    table.add_column("Vendor")
    table.add_column("Published")
    for f in sorted(state_dir.glob("*.json")):
        data = json.loads(f.read_text(encoding="utf-8"))
        table.add_row(
            data.get("submission_id", f.stem),
            data.get("day_0", "-"),
            data.get("vendor_state", "-"),
            data.get("published_at", "-"),
        )
    console.print(table)
