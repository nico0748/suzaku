"""GitHub commit diff フェッチと unified diff 解析。"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import httpx

from suzaku.lineage.egress import assert_allowed
from suzaku.lineage.models import PatchHunk

GITHUB_API_BASE = "https://api.github.com"
COMMIT_URL_RE = re.compile(
    r"github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)/commit/(?P<sha>[0-9a-fA-F]{7,40})"
)

EXT_TO_LANG: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".php": "php",
    ".java": "java",
    ".go": "go",
    ".c": "cpp",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".h": "cpp",
    ".hpp": "cpp",
    ".rb": "ruby",
    ".rs": "rust",
}

MAX_PATCH_LINES = 1000


class GitHubPatchError(RuntimeError):
    """GitHub API のエラー / 解析失敗。"""


def _detect_language(filename: str) -> str:
    for ext, lang in EXT_TO_LANG.items():
        if filename.lower().endswith(ext):
            return lang
    return "unknown"


def _build_api_url(commit_url: str) -> str:
    m = COMMIT_URL_RE.search(commit_url)
    if not m:
        raise GitHubPatchError(f"not a GitHub commit URL: {commit_url}")
    owner = m.group("owner")
    repo = m.group("repo")
    sha = m.group("sha")
    return f"{GITHUB_API_BASE}/repos/{owner}/{repo}/commits/{sha}"


def parse_unified_patch(
    patch: str,
    commit_url: str,
    filename: str,
    *,
    max_lines: int = MAX_PATCH_LINES,
) -> list[PatchHunk]:
    """unified diff 文字列を ``PatchHunk`` 列に分解する (最小実装)。"""
    if not patch.strip():
        return []
    language = _detect_language(filename)
    hunks: list[PatchHunk] = []
    current_added: list[str] = []
    current_deleted: list[str] = []
    seen_lines = 0

    def flush() -> None:
        if not current_added and not current_deleted:
            return
        hunks.append(
            PatchHunk(
                commit_url=commit_url,  # type: ignore[arg-type]
                file_path=filename,
                language=language,
                deleted_lines=list(current_deleted),
                added_lines=list(current_added),
            )
        )
        current_added.clear()
        current_deleted.clear()

    for raw_line in patch.splitlines():
        seen_lines += 1
        if seen_lines > max_lines:
            break
        if raw_line.startswith("@@"):
            flush()
            continue
        if raw_line.startswith("---") or raw_line.startswith("+++"):
            continue
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            current_added.append(raw_line[1:])
        elif raw_line.startswith("-") and not raw_line.startswith("---"):
            current_deleted.append(raw_line[1:])
        # ' '/context は無視
    flush()
    return hunks


def fetch_commit_diff(
    commit_url: str,
    *,
    token: str | None = None,
    client: httpx.Client | None = None,
    timeout: float = 30.0,
) -> list[PatchHunk]:
    """GitHub ``/repos/<o>/<r>/commits/<sha>`` を取得して PatchHunk[] を返す。"""
    api_url = _build_api_url(commit_url)
    host = urlparse(api_url).hostname or ""
    assert_allowed(host)

    headers: dict[str, str] = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "suzaku-lineage/0.1",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    owns = False
    if client is None:
        client = httpx.Client(timeout=timeout)
        owns = True
    try:
        response = client.get(api_url, headers=headers)
    finally:
        if owns:
            client.close()

    if response.status_code != 200:
        raise GitHubPatchError(
            f"GitHub API HTTP {response.status_code} for {api_url}: {response.text[:200]}"
        )

    payload: Any = response.json()
    if not isinstance(payload, dict):
        raise GitHubPatchError(f"unexpected payload shape from {api_url}")
    files = payload.get("files", [])
    if not isinstance(files, list):
        return []

    hunks: list[PatchHunk] = []
    for f in files:
        if not isinstance(f, dict):
            continue
        patch = f.get("patch")
        filename = f.get("filename")
        if not isinstance(patch, str) or not isinstance(filename, str):
            continue
        try:
            hunks.extend(parse_unified_patch(patch, commit_url=commit_url, filename=filename))
        except Exception:
            continue
    return hunks


__all__ = [
    "COMMIT_URL_RE",
    "EXT_TO_LANG",
    "GITHUB_API_BASE",
    "MAX_PATCH_LINES",
    "GitHubPatchError",
    "fetch_commit_diff",
    "parse_unified_patch",
]
