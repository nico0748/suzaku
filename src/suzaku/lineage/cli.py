"""``suzaku lineage`` サブコマンド。"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from suzaku.lineage.egress import LineageEgressError
from suzaku.lineage.extract import hunks_to_rules
from suzaku.lineage.github_patches import GitHubPatchError, fetch_commit_diff
from suzaku.lineage.models import (
    CVERecord,
    VariantRule,
    variant_rule_dump,
    variant_rule_load,
)
from suzaku.lineage.nvd import NVDFilterError, fetch_nvd, load_nvd_single
from suzaku.lineage.scan import scan_with_variant_rules

SUZAKU_RED = "#B43E3E"

app = typer.Typer(
    name="lineage",
    help="継 (Lineage) — CVE 修正パッチからの variant analysis (Phase 2-C)",
    no_args_is_help=True,
)
console = Console()


def _save_json(data: object, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


@app.command()
def ingest(
    source: Path | None = typer.Argument(None, exists=True, help="NVD JSON ファイル"),
    cve: str | None = typer.Option(None, "--cve", help="単一 CVE id を NVD API から取得"),
    out: Path = typer.Option(Path("./cve_record.json"), "--out", "-o"),
) -> None:
    """NVD JSON 取り込み (ローカルファイル or オンライン)。"""
    if cve is None and source is None:
        raise typer.BadParameter("Either --cve or a NVD json path is required")

    try:
        record: CVERecord
        if cve is not None:
            record = fetch_nvd(cve)
        else:
            assert source is not None
            record = load_nvd_single(source)
    except NVDFilterError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(11) from e
    except LineageEgressError as e:
        console.print(f"[red][!] {e}[/red]")
        raise typer.Exit(12) from e

    _save_json(record.model_dump(mode="json"), out)
    console.print(
        f"[bold {SUZAKU_RED}]ingested[/] {record.cve_id} -> {out} "
        f"({len(record.commit_urls)} commit URLs found)"
    )


@app.command()
def extract(
    cve_record_json: Path = typer.Argument(..., exists=True),
    out: Path = typer.Option(Path("./variant_rules.json"), "--out", "-o"),
    max_rules: int = typer.Option(5, "--max-rules"),
    token: str | None = typer.Option(None, "--token", envvar="SUZAKU_GITHUB_TOKEN"),
    offline: bool = typer.Option(
        False, "--offline", help="オフライン: commit fetch をスキップ (テスト用)"
    ),
) -> None:
    """CVE record + commit diff から VariantRule を抽出する。"""
    payload = json.loads(cve_record_json.read_text(encoding="utf-8"))
    record = CVERecord.model_validate(payload)

    hunks_all = []
    if not offline:
        for commit_url in record.commit_urls:
            try:
                hunks_all.extend(fetch_commit_diff(str(commit_url), token=token))
            except (GitHubPatchError, LineageEgressError) as e:
                console.print(f"[yellow]skip {commit_url}: {e}[/yellow]")
                continue

    rules = hunks_to_rules(record, hunks_all, max_rules=max_rules)
    _save_json([variant_rule_dump(r) for r in rules], out)
    console.print(
        f"[bold {SUZAKU_RED}]extracted[/] {len(rules)} variant rules -> {out}"
    )


@app.command()
def scan(
    repo_path: Path = typer.Argument(..., exists=True, dir_okay=True, file_okay=False),
    rules_json: Path = typer.Option(..., "--rules", "-r", exists=True),
    out: Path | None = typer.Option(None, "--out"),
) -> None:
    """VariantRule[] で repo をスキャンする。"""
    payload = json.loads(rules_json.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise typer.BadParameter("rules JSON must be an array")
    rules: list[VariantRule] = [variant_rule_load(p) for p in payload]
    findings = scan_with_variant_rules(repo_path, rules)

    if out is not None:
        _save_json([f.model_dump(mode="json") for f in findings], out)

    table = Table(
        title=f"[bold {SUZAKU_RED}]Lineage scan — {len(findings)} variants[/]"
    )
    table.add_column("Rule")
    table.add_column("File")
    table.add_column("Line", justify="right")
    table.add_column("Snippet")
    for f in findings[:200]:
        table.add_row(f.rule_id, f.file_path, str(f.line_number), f.snippet[:100])
    console.print(table)


@app.command()
def demo(
    tmp_repo: Path = typer.Argument(..., exists=True, dir_okay=True, file_okay=False),
) -> None:
    """オフライン demo: 内蔵サンプル CVE で extract -> scan を実行する。"""
    from suzaku.lineage.models import PatchHunk

    sample_cve = CVERecord(
        cve_id="CVE-2099-0001",
        description="Demo SSRF in fetch handler",
        cwe=["CWE-918"],
        references=["https://github.com/example/x/commit/deadbeef1234"],  # type: ignore[list-item]
        commit_urls=["https://github.com/example/x/commit/deadbeef1234"],  # type: ignore[list-item]
        vuln_status="Public",
    )
    sample_hunks = [
        PatchHunk(
            commit_url="https://github.com/example/x/commit/deadbeef1234",  # type: ignore[arg-type]
            file_path="src/fetch.py",
            language="python",
            deleted_lines=["urllib.request.urlopen(user_url)"],
            added_lines=["if not is_allowed_host(user_url): raise"],
        )
    ]
    rules = hunks_to_rules(sample_cve, sample_hunks)
    findings = scan_with_variant_rules(tmp_repo, rules)
    console.print(
        f"[bold {SUZAKU_RED}]demo[/] rules={len(rules)}, findings={len(findings)}"
    )
    console.print_json(
        data={
            "rules": [variant_rule_dump(r) for r in rules],
            "findings": [f.model_dump(mode="json") for f in findings],
        }
    )


__all__ = ["app"]
