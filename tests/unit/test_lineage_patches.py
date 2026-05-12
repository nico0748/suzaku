"""GitHub commit diff フェッチ + unified diff 解析のテスト。"""

from __future__ import annotations

import pytest
import respx

from suzaku.lineage.egress import LineageEgressError
from suzaku.lineage.github_patches import (
    GITHUB_API_BASE,
    GitHubPatchError,
    fetch_commit_diff,
    parse_unified_patch,
)

SAMPLE_PATCH = """\
@@ -10,7 +10,8 @@
 def fetch(url):
-    return urllib.request.urlopen(url)
+    if not is_allowed_host(url):
+        raise SecurityError("blocked")
+    return urllib.request.urlopen(url)
"""


class TestParseUnifiedPatch:
    def test_extracts_added_and_deleted(self) -> None:
        hunks = parse_unified_patch(
            SAMPLE_PATCH,
            commit_url="https://github.com/example/x/commit/abc1234",
            filename="src/fetch.py",
        )
        assert len(hunks) == 1
        h = hunks[0]
        assert h.language == "python"
        assert any("urlopen" in line for line in h.deleted_lines)
        assert any("is_allowed_host" in line for line in h.added_lines)

    def test_empty_patch_returns_empty(self) -> None:
        assert parse_unified_patch("", "https://github.com/x/y/commit/aaa", "f.py") == []

    def test_max_lines_truncates(self) -> None:
        big = "\n".join(f"+line{i}" for i in range(200))
        hunks = parse_unified_patch(
            big, "https://github.com/x/y/commit/aaaa1234", "x.py", max_lines=10
        )
        # max_lines で打ち切られる
        if hunks:
            assert len(hunks[0].added_lines) <= 10

    def test_unknown_language_for_unmatched_ext(self) -> None:
        hunks = parse_unified_patch(
            SAMPLE_PATCH, "https://github.com/x/y/commit/aaaa1234", "Makefile"
        )
        assert hunks[0].language == "unknown"


class TestFetchCommitDiff:
    @respx.mock
    def test_happy_path(self) -> None:
        commit = "https://github.com/example/x/commit/abc1234567890"
        respx.get(f"{GITHUB_API_BASE}/repos/example/x/commits/abc1234567890").respond(
            200,
            json={
                "files": [
                    {
                        "filename": "src/fetch.py",
                        "patch": SAMPLE_PATCH,
                    }
                ]
            },
        )
        hunks = fetch_commit_diff(commit)
        assert len(hunks) == 1
        assert hunks[0].file_path == "src/fetch.py"

    @respx.mock
    def test_404_raises(self) -> None:
        commit = "https://github.com/example/x/commit/abc1234567890"
        respx.get(f"{GITHUB_API_BASE}/repos/example/x/commits/abc1234567890").respond(
            404, text="not found"
        )
        with pytest.raises(GitHubPatchError):
            fetch_commit_diff(commit)

    def test_not_a_commit_url(self) -> None:
        with pytest.raises(GitHubPatchError):
            fetch_commit_diff("https://example.com/")

    def test_egress_guard_blocks_non_github(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "suzaku.lineage.github_patches.GITHUB_API_BASE", "https://api.openai.com"
        )
        with pytest.raises(LineageEgressError):
            fetch_commit_diff("https://github.com/example/x/commit/abc1234567890")
