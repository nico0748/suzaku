"""extract + scan のテスト。"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from suzaku.lineage.extract import hunks_to_rules
from suzaku.lineage.models import CVERecord, PatchHunk
from suzaku.lineage.scan import scan_with_variant_rules


def _cve(**kw) -> CVERecord:
    base = {
        "cve_id": "CVE-2024-1234",
        "description": "Demo SSRF",
        "cwe": ["CWE-918"],
        "vuln_status": "Public",
        "references": ["https://github.com/example/x/commit/abc1234"],
        "commit_urls": ["https://github.com/example/x/commit/abc1234"],
    }
    base.update(kw)
    return CVERecord.model_validate(base)


def _hunk(**kw) -> PatchHunk:
    base = {
        "commit_url": "https://github.com/example/x/commit/abc1234",
        "file_path": "src/fetch.py",
        "language": "python",
        "deleted_lines": ["return urllib.request.urlopen(user_url)"],
        "added_lines": ["if not is_allowed_host(user_url): raise"],
    }
    base.update(kw)
    return PatchHunk.model_validate(base)


class TestHunksToRules:
    def test_generates_rule_for_known_cwe(self) -> None:
        rules = hunks_to_rules(_cve(), [_hunk()])
        assert len(rules) >= 1
        r = rules[0]
        assert r.derived_from_cve == "CVE-2024-1234"
        assert r.cwe == "CWE-918"
        assert r.language == "python"
        assert "urlopen" in r.grep
        assert r.must_not_contain is not None
        assert "is_allowed_host" in r.must_not_contain

    def test_unknown_cwe_returns_empty(self) -> None:
        rules = hunks_to_rules(_cve(cwe=["CWE-99999"]), [_hunk()])
        assert rules == []

    def test_max_rules_cap(self) -> None:
        hunks = [
            _hunk(
                deleted_lines=[f"call_{i}(user_input_{i})"],
                added_lines=[f"sanitize(call_{i}, user_input_{i})"],
                file_path=f"src/{i}.py",
            )
            for i in range(10)
        ]
        rules = hunks_to_rules(_cve(), hunks, max_rules=3)
        assert len(rules) == 3

    def test_noisy_lines_filtered(self) -> None:
        hunks = [
            _hunk(deleted_lines=["}", "# comment", "    "])
        ]
        rules = hunks_to_rules(_cve(), hunks)
        assert rules == []


class TestScan:
    def setup_method(self) -> None:
        if shutil.which("rg") is None:
            pytest.skip("ripgrep not installed")

    def test_finds_match_in_test_repo(self, tmp_path: Path) -> None:
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "fetch.py").write_text(
            "import urllib\n\ndef f(u):\n    return urllib.request.urlopen(u)\n"
        )
        rules = hunks_to_rules(_cve(), [_hunk()])
        findings = scan_with_variant_rules(tmp_path, rules)
        assert findings
        f = findings[0]
        assert f.rule_id.startswith("lineage_CVE-2024-1234_")
        assert f.derived_from_cve == "CVE-2024-1234"

    def test_must_not_contain_suppresses(self, tmp_path: Path) -> None:
        (tmp_path / "src").mkdir()
        # ファイル内に is_allowed_host が存在するので must_not_contain で抑制される
        (tmp_path / "src" / "safe.py").write_text(
            "def f(u):\n    if not is_allowed_host(u): raise\n"
            "    return urllib.request.urlopen(u)\n"
        )
        rules = hunks_to_rules(_cve(), [_hunk()])
        findings = scan_with_variant_rules(tmp_path, rules)
        assert findings == []

    def test_empty_rules(self, tmp_path: Path) -> None:
        assert scan_with_variant_rules(tmp_path, []) == []
