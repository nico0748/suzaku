"""Semgrep ラッパー。

Semgrep が未インストールなら :func:`scan_with_semgrep` は空リストを返し、
警告ログを残す (SPEC.md: "Semgrep が見つからなければ grep-only モード")。

本ラッパーは Phase 1 では薄い: Suzaku 独自の YAML ルール
(rules/) を Semgrep 形式ではないので、ここでは「ユーザ指定の semgrep
ルールパック」を実行するための窓口に留める。
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from suzaku.models import Finding, Severity


@dataclass
class SemgrepStatus:
    available: bool
    binary: str | None
    version: str | None = None


def detect_semgrep() -> SemgrepStatus:
    binary = shutil.which("semgrep")
    if binary is None:
        return SemgrepStatus(available=False, binary=None)
    proc = subprocess.run(
        [binary, "--version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    version = proc.stdout.strip() if proc.returncode == 0 else None
    return SemgrepStatus(available=True, binary=binary, version=version)


def scan_with_semgrep(
    repo_path: Path,
    config: str = "auto",
    target_url: str = "http://localhost/",
) -> list[Finding]:
    """semgrep を実行して Finding 配列を返す。未インストールなら ``[]``。"""
    status = detect_semgrep()
    if not status.available or status.binary is None:
        return []

    cmd = [status.binary, "--config", config, "--json", str(repo_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=300)
    if proc.returncode not in (0, 1):
        # 1 = findings present, 0 = no findings, anything else = error
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []

    return list(_parse_semgrep_results(data, target_url))


def _severity_from_semgrep(value: str) -> Severity:
    mapping = {
        "ERROR": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "INFO": Severity.INFO,
    }
    return mapping.get(value.upper(), Severity.INFO)


def _parse_semgrep_results(data: dict[str, object], target_url: str) -> list[Finding]:
    results = data.get("results")
    if not isinstance(results, list):
        return []
    out: list[Finding] = []
    for i, item in enumerate(results):
        if not isinstance(item, dict):
            continue
        check_id = str(item.get("check_id", f"semgrep-{i}"))
        path = str(item.get("path", "<unknown>"))
        start = item.get("start") if isinstance(item.get("start"), dict) else {}
        line = int(start.get("line", 0)) if isinstance(start, dict) else 0
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        message = ""
        severity_raw = "INFO"
        if isinstance(extra, dict):
            message = str(extra.get("message", "")).strip()
            severity_raw = str(extra.get("severity", "INFO"))
        out.append(
            Finding(
                id=f"F-sg-{i:06d}",
                target_url=target_url,  # type: ignore[arg-type]
                category=check_id,
                severity=_severity_from_semgrep(severity_raw),
                file_path=path,
                line_number=line,
                snippet=message[:200],
            )
        )
    return out
