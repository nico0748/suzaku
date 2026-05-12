"""ripgrep (``rg``) ラッパーによる Compass の初手スキャン。

責務:
- ルールの各 pattern を該当言語のファイルに対し ripgrep で検索
- ``must_not_contain`` が同ファイル内にあれば疑陽性として抑制
- マッチ結果を :class:`~suzaku.models.Finding` のリストに変換

ripgrep が未インストールなら :class:`RipgrepNotFoundError` を投げて
案内する (SPEC.md §Compass 受け入れ基準)。
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from suzaku.compass.rules import LANGUAGE_EXTENSIONS, Rule, RulePattern
from suzaku.models import Finding


class RipgrepNotFoundError(RuntimeError):
    """ripgrep (``rg``) が PATH 上に見つからない場合に発生する。"""


@dataclass
class GrepMatch:
    """ripgrep の生マッチ (テスト用)。"""

    path: Path
    line_number: int
    snippet: str


def _ensure_rg() -> str:
    rg = shutil.which("rg")
    if rg is None:
        raise RipgrepNotFoundError(
            "ripgrep ('rg') not found in PATH. "
            "Install via `cargo install ripgrep` or your package manager "
            "(`apt-get install ripgrep`, `brew install ripgrep`)."
        )
    return rg


def _run_rg(
    pattern: str,
    repo: Path,
    extensions: Sequence[str],
    rg_bin: str,
) -> list[GrepMatch]:
    """``rg`` を起動して ``path:line:snippet`` 形式の行を解析する。"""
    glob_args: list[str] = []
    for ext in extensions:
        glob_args.extend(["-g", f"*{ext}"])

    cmd = [
        rg_bin,
        "--pcre2",
        "--line-number",
        "--no-heading",
        "--color=never",
        "--regexp",
        pattern,
        *glob_args,
        str(repo),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    # rg exit codes: 0=found, 1=no matches, 2=error
    if proc.returncode == 1:
        return []
    if proc.returncode >= 2:
        raise RuntimeError(f"ripgrep failed: {proc.stderr.strip() or proc.stdout.strip()}")

    return list(_parse_rg_output(proc.stdout))


_RG_LINE = re.compile(r"^(?P<path>.+?):(?P<line>\d+):(?P<snippet>.*)$")


def _parse_rg_output(output: str) -> Iterable[GrepMatch]:
    for raw in output.splitlines():
        m = _RG_LINE.match(raw)
        if not m:
            continue
        yield GrepMatch(
            path=Path(m.group("path")),
            line_number=int(m.group("line")),
            snippet=m.group("snippet"),
        )


def _file_contains(path: Path, pattern: str) -> bool:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return re.search(pattern, content) is not None


def _finding_id(rule: Rule, match: GrepMatch) -> str:
    raw = f"{rule.id}:{match.path}:{match.line_number}:{match.snippet}"
    return f"F-{hashlib.sha1(raw.encode()).hexdigest()[:12]}"


class GrepRunner:
    """ルール 1 つに対して repo をスキャンするランナー。"""

    def __init__(self, target_url: str = "http://localhost/") -> None:
        # ripgrep の存在は scan 呼出時にチェック (テストでモック可)
        self._target_url = target_url

    def scan(
        self,
        repo_path: Path,
        rule: Rule,
        rg_bin: str | None = None,
    ) -> list[Finding]:
        """``repo_path`` を ``rule`` でスキャンして Finding を返す。"""
        binary = rg_bin or _ensure_rg()
        findings: list[Finding] = []
        suppressed_files: set[Path] = set()

        for pattern in rule.patterns:
            exts = LANGUAGE_EXTENSIONS.get(pattern.language, ())
            if not exts:
                continue
            matches = _run_rg(pattern.grep, repo_path, exts, binary)
            for m in matches:
                if pattern.must_not_contain is not None:
                    if m.path in suppressed_files:
                        continue
                    if _file_contains(m.path, pattern.must_not_contain):
                        suppressed_files.add(m.path)
                        continue
                findings.append(self._to_finding(rule, pattern, m))

        # 同一 (path, line) の重複を排除
        return _dedup_findings(findings)

    def _to_finding(self, rule: Rule, pattern: RulePattern, match: GrepMatch) -> Finding:
        return Finding(
            id=_finding_id(rule, match),
            target_url=self._target_url,  # type: ignore[arg-type]
            category=rule.id,
            severity=rule.severity,
            cwe=rule.cwe,
            file_path=str(match.path),
            line_number=match.line_number,
            snippet=match.snippet.strip(),
        )


def _dedup_findings(findings: Sequence[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.category, f.file_path, f.line_number)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
