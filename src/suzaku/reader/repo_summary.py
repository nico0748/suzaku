"""リポジトリの軽量サマリ生成。

ファイル丸ごとを LLM に送るとコンテキスト爆発 + ハルシネーションが
起きるので、Reader は ``RepoSummary`` (ファイル一覧 + head N 行) を
プロンプトに埋め込む。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

INTERESTING_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py", ".pyi",
        ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
        ".php",
        ".java", ".kt",
        ".go",
        ".rb",
        ".rs",
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp",
    }
)

CONFIG_FILES: frozenset[str] = frozenset(
    {
        "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "Pipfile",
        "package.json", "yarn.lock", "tsconfig.json",
        "composer.json",
        "pom.xml", "build.gradle", "build.gradle.kts",
        "go.mod", "go.sum",
        "Gemfile",
        "Cargo.toml",
        "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
        "Makefile",
    }
)

SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git", "node_modules", ".venv", "venv", "__pycache__",
        "dist", "build", "target", ".tox", ".mypy_cache", ".ruff_cache",
        "vendor", "third_party", "deps",
    }
)

DEFAULT_HEAD_LINES = 40
DEFAULT_MAX_FILES = 80
DEFAULT_MAX_BYTES_PER_FILE = 8192


@dataclass
class FileSnippet:
    path: str           # repo 相対パス
    head: str           # 先頭 N 行
    total_lines: int


@dataclass
class RepoSummary:
    root: Path
    config_files: list[FileSnippet] = field(default_factory=list)
    source_files: list[FileSnippet] = field(default_factory=list)
    directory_tree: list[str] = field(default_factory=list)
    total_loc: int = 0


def _iter_files(root: Path) -> list[Path]:
    paths: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        paths.append(p)
    return paths


def _read_head(path: Path, max_lines: int, max_bytes: int) -> tuple[str, int]:
    try:
        raw = path.read_bytes()[:max_bytes]
    except OSError:
        return "", 0
    try:
        text = raw.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return "", 0
    lines = text.splitlines()
    head = "\n".join(lines[:max_lines])
    return head, len(lines)


def _short_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def build_repo_summary(
    root: Path,
    *,
    head_lines: int = DEFAULT_HEAD_LINES,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes_per_file: int = DEFAULT_MAX_BYTES_PER_FILE,
) -> RepoSummary:
    """``root`` 配下を走査して ``RepoSummary`` を組み立てる。"""
    summary = RepoSummary(root=root)
    if not root.is_dir():
        return summary

    all_paths = _iter_files(root)

    # 設定ファイルは別枠 (優先抽出)
    for p in all_paths:
        if p.name in CONFIG_FILES:
            head, total = _read_head(p, head_lines, max_bytes_per_file)
            summary.config_files.append(
                FileSnippet(path=_short_path(p, root), head=head, total_lines=total)
            )

    # source 抽出 (拡張子フィルタ)
    source_paths = [p for p in all_paths if p.suffix in INTERESTING_EXTENSIONS]
    source_paths.sort(key=lambda p: (-p.stat().st_size, p.as_posix()))

    for p in source_paths[:max_files]:
        head, total = _read_head(p, head_lines, max_bytes_per_file)
        summary.source_files.append(
            FileSnippet(path=_short_path(p, root), head=head, total_lines=total)
        )
        summary.total_loc += total

    # 上位ディレクトリツリー (深さ 2 まで)
    dirs: set[str] = set()
    for p in all_paths:
        rel = p.relative_to(root)
        parts = rel.parts[:2]
        if parts:
            dirs.add("/".join(parts))
    summary.directory_tree = sorted(dirs)

    return summary


def render_for_prompt(summary: RepoSummary, max_chars: int = 12000) -> str:
    """LLM プロンプトに埋め込む形にレンダリングする (文字数キャップあり)。"""
    parts: list[str] = []
    parts.append("# Directory tree (top-level, up to 2 levels)\n")
    for d in summary.directory_tree[:60]:
        parts.append(f"- {d}\n")

    if summary.config_files:
        parts.append("\n# Config files\n")
        for f in summary.config_files[:20]:
            parts.append(f"\n## {f.path} ({f.total_lines} lines)\n```\n{f.head}\n```\n")

    if summary.source_files:
        parts.append("\n# Source file excerpts\n")
        for f in summary.source_files:
            parts.append(f"\n## {f.path} ({f.total_lines} lines)\n```\n{f.head}\n```\n")

    body = "".join(parts)
    if len(body) > max_chars:
        body = body[:max_chars] + "\n\n[...truncated by Suzaku Reader...]\n"
    return body


__all__ = [
    "CONFIG_FILES",
    "DEFAULT_HEAD_LINES",
    "DEFAULT_MAX_BYTES_PER_FILE",
    "DEFAULT_MAX_FILES",
    "INTERESTING_EXTENSIONS",
    "SKIP_DIRS",
    "FileSnippet",
    "RepoSummary",
    "build_repo_summary",
    "render_for_prompt",
]
