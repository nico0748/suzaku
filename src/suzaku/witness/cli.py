"""``suzaku witness`` サブコマンド。"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from suzaku.witness.evidence import EvidenceStore
from suzaku.witness.guard import ProductionAccessError, is_allowed_host
from suzaku.witness.reproducer import PoCContext, Reproducer

SUZAKU_RED = "#B43E3E"

app = typer.Typer(
    name="witness",
    help="証立 (Witness) — Docker 内 PoC 再現 + 本番アクセス完全ブロック",
    no_args_is_help=True,
)
console = Console()


def _pocs_dir(root: Path | None = None) -> Path:
    return (root or Path("./pocs")).resolve()


def _evidence_dir(root: Path | None = None) -> Path:
    return (root or Path("./evidence")).resolve()


@app.command()
def init(
    finding_id: str,
    category: str | None = typer.Option(None, "--category"),
    affected_version: str | None = typer.Option(None, "--affected-version"),
    commit_sha: str | None = typer.Option(None, "--commit"),
    target_url: str | None = typer.Option(None, "--target-url"),
    pocs_dir: Path = typer.Option(Path("./pocs"), "--pocs-dir"),
) -> None:
    """PoC テンプレを ``pocs_dir/<finding_id>/`` に展開する。"""
    repro = Reproducer(pocs_dir=pocs_dir)
    ctx = PoCContext(
        finding_id=finding_id,
        category=category,
        target_url=target_url,
        affected_version=affected_version,
        commit_sha=commit_sha or "(pending)",
    )
    path = repro.init_poc(ctx)
    console.print(
        f"[bold {SUZAKU_RED}]Witness[/] initialised PoC for [bold]{finding_id}[/]"
        f" at {path}"
    )


@app.command()
def reproduce(
    finding_id: str,
    target_host: str = typer.Option("localhost", "--target-host"),
    pocs_dir: Path = typer.Option(Path("./pocs"), "--pocs-dir"),
) -> None:
    """docker compose up でローカル再現を起動する。"""
    repro = Reproducer(pocs_dir=pocs_dir)
    try:
        result = repro.up(finding_id, target_host=target_host)
    except ProductionAccessError as e:
        console.print(f"[red][!] {e}[/red]")
        raise typer.Exit(4) from e
    if result.returncode != 0:
        console.print(f"[red]docker compose up failed: {result.stderr.strip()}[/red]")
        raise typer.Exit(result.returncode or 1)
    console.print(f"[bold {SUZAKU_RED}]Witness[/] is up (finding={finding_id})")


@app.command()
def stop(
    finding_id: str,
    pocs_dir: Path = typer.Option(Path("./pocs"), "--pocs-dir"),
) -> None:
    """docker compose down -v で停止する。"""
    repro = Reproducer(pocs_dir=pocs_dir)
    repro.down(finding_id)
    console.print(f"[bold {SUZAKU_RED}]Witness[/] stopped (finding={finding_id})")


@app.command()
def record(
    finding_id: str,
    files: list[Path] = typer.Argument(..., exists=True),
    evidence_dir: Path = typer.Option(Path("./evidence"), "--evidence-dir"),
) -> None:
    """指定ファイル群の SHA-256 を ``evidence.lock`` に追記する。"""
    store = EvidenceStore(base_dir=evidence_dir)
    digest = store.record(finding_id, files=list(files))
    console.print(f"[bold {SUZAKU_RED}]Recorded[/] aggregate hash: {digest}")


@app.command()
def verify(
    finding_id: str,
    evidence_dir: Path = typer.Option(Path("./evidence"), "--evidence-dir"),
) -> None:
    """evidence.lock のチェイン整合性を検証する。"""
    store = EvidenceStore(base_dir=evidence_dir)
    ok = store.verify(finding_id)
    if ok:
        console.print(f"[bold green]OK[/] — evidence chain for {finding_id} is intact.")
    else:
        console.print(f"[red]TAMPERED[/] — evidence chain for {finding_id} failed verification.")
        raise typer.Exit(1)


@app.command(name="check-host")
def check_host(host: str) -> None:
    """host がガード許可リストに該当するか確認する (CLI 単体テスト用)。"""
    allowed = is_allowed_host(host)
    color = "green" if allowed else "red"
    console.print(f"[{color}]{'ALLOWED' if allowed else 'BLOCKED'}[/] {host}")
    raise typer.Exit(0 if allowed else 1)
