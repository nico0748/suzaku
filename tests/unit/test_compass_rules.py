"""ルール YAML ローダのテスト。"""

from __future__ import annotations

from pathlib import Path

import pytest

from suzaku.compass.rules import (
    RULES_DIR,
    Rule,
    RuleError,
    list_rule_paths,
    load_all_rules,
    load_rule,
    load_rule_by_id,
)
from suzaku.models import Severity


class TestLoadBundledRules:
    def test_loads_all_bundled_rules(self) -> None:
        paths = list_rule_paths()
        assert len(paths) >= 10  # 6 danger_funcs + 4 patterns

    def test_each_rule_parses_cleanly(self) -> None:
        rules = load_all_rules()
        ids = {r.id for r in rules}
        for expected in [
            "danger_funcs_php",
            "danger_funcs_python",
            "danger_funcs_nodejs",
            "danger_funcs_java",
            "danger_funcs_go",
            "danger_funcs_cpp",
            "jwt",
            "zip_slip",
            "proto_pollution",
            "ssrf",
        ]:
            assert expected in ids, f"missing rule {expected}"

    def test_every_pattern_has_known_language(self) -> None:
        rules = load_all_rules()
        for rule in rules:
            for p in rule.patterns:
                assert p.language in {
                    "php", "python", "javascript", "java", "go", "cpp", "any"
                }, f"rule {rule.id} has unknown language {p.language}"


class TestLoadRuleByPath:
    def test_load_by_relative_id(self) -> None:
        rule = load_rule_by_id("patterns/zip_slip")
        assert isinstance(rule, Rule)
        assert rule.id == "zip_slip"

    def test_load_by_unique_id(self) -> None:
        rule = load_rule_by_id("ssrf")
        assert rule.cwe == "CWE-918"

    def test_unknown_rule_raises(self) -> None:
        with pytest.raises(RuleError):
            load_rule_by_id("does_not_exist")


class TestRuleValidation:
    def test_missing_required_key(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("id: test\nname: Test\n")
        with pytest.raises(RuleError):
            load_rule(bad)

    def test_unknown_severity(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            "id: x\nname: X\ndescription: x\ncwe: CWE-22\nseverity: ohno\n"
            "patterns:\n  - language: python\n    grep: 'foo'\n"
        )
        with pytest.raises(RuleError):
            load_rule(bad)

    def test_unknown_language(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            "id: x\nname: X\ndescription: x\ncwe: CWE-22\nseverity: high\n"
            "patterns:\n  - language: cobol\n    grep: 'foo'\n"
        )
        with pytest.raises(RuleError):
            load_rule(bad)

    def test_empty_patterns_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            "id: x\nname: X\ndescription: x\ncwe: CWE-22\nseverity: high\n"
            "patterns: []\n"
        )
        with pytest.raises(RuleError):
            load_rule(bad)

    def test_severity_parsed_to_enum(self) -> None:
        rule = load_rule_by_id("ssrf")
        assert isinstance(rule.severity, Severity)
        assert rule.severity == Severity.HIGH


def test_rules_dir_exists() -> None:
    assert RULES_DIR.is_dir()
