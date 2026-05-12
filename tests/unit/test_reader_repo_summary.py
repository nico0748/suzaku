"""repo_summary のテスト。"""

from __future__ import annotations

from pathlib import Path

from suzaku.reader.repo_summary import (
    DEFAULT_HEAD_LINES,
    build_repo_summary,
    render_for_prompt,
)


def _write(p: Path, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


class TestBuildRepoSummary:
    def test_collects_source_and_config(self, tmp_path: Path) -> None:
        _write(tmp_path / "pyproject.toml", "[project]\nname = 'demo'\n")
        _write(tmp_path / "src" / "app.py", "def f():\n    return 1\n" * 5)
        _write(tmp_path / "README.md", "ignored")

        s = build_repo_summary(tmp_path)
        config_paths = {f.path for f in s.config_files}
        source_paths = {f.path for f in s.source_files}
        assert "pyproject.toml" in config_paths
        assert "src/app.py" in source_paths
        assert s.total_loc > 0

    def test_skips_node_modules_and_venv(self, tmp_path: Path) -> None:
        _write(tmp_path / "node_modules" / "lib" / "junk.js", "x")
        _write(tmp_path / ".venv" / "lib" / "junk.py", "y")
        _write(tmp_path / "src" / "real.py", "print(1)\n")
        s = build_repo_summary(tmp_path)
        for f in s.source_files:
            assert "node_modules" not in f.path
            assert ".venv" not in f.path

    def test_head_lines_limit(self, tmp_path: Path) -> None:
        big = "\n".join(f"line-{i}" for i in range(200))
        _write(tmp_path / "src" / "big.py", big)
        s = build_repo_summary(tmp_path, head_lines=10)
        big_snippets = [f for f in s.source_files if f.path == "src/big.py"]
        assert big_snippets
        assert big_snippets[0].head.count("\n") <= 10

    def test_default_head_lines(self) -> None:
        assert DEFAULT_HEAD_LINES > 0

    def test_missing_root_returns_empty(self, tmp_path: Path) -> None:
        s = build_repo_summary(tmp_path / "does_not_exist")
        assert s.source_files == []


class TestRenderForPrompt:
    def test_contains_paths_and_truncates(self, tmp_path: Path) -> None:
        for i in range(5):
            _write(tmp_path / "src" / f"f{i}.py", f"# file {i}\n" * 10)
        s = build_repo_summary(tmp_path)
        text = render_for_prompt(s, max_chars=2000)
        assert "Directory tree" in text
        # truncation works
        assert len(text) <= 2200  # 末尾の truncated 文を考慮した余裕

    def test_no_source_files_still_renders_tree(self, tmp_path: Path) -> None:
        _write(tmp_path / "pyproject.toml", "[project]\nname='x'\n")
        s = build_repo_summary(tmp_path)
        text = render_for_prompt(s)
        assert "Config files" in text
