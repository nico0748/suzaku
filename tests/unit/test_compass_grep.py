"""Compass の grep_runner を vulnerable_repo fixture で検証する。

ripgrep が無い環境では skip し、CI からの導入指示を案内する。
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from suzaku.compass.grep_runner import GrepRunner, RipgrepNotFoundError, _dedup_findings
from suzaku.compass.rules import load_rule_by_id
from suzaku.models import Finding, Severity

REPO = Path(__file__).resolve().parents[1] / "fixtures" / "vulnerable_repo"

pytestmark = pytest.mark.skipif(
    shutil.which("rg") is None,
    reason="ripgrep ('rg') is not installed; install it to run grep_runner tests",
)


@pytest.fixture
def runner() -> GrepRunner:
    return GrepRunner()


class TestRipgrepDetection:
    def test_missing_rg_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda _name: None)
        with pytest.raises(RipgrepNotFoundError):
            GrepRunner().scan(REPO, load_rule_by_id("ssrf"))


class TestDangerFuncsHits:
    @pytest.mark.parametrize(
        "rule_id,must_hit_substring",
        [
            ("danger_funcs_php", "eval"),
            ("danger_funcs_python", "pickle"),
            ("danger_funcs_nodejs", "Function"),
            ("danger_funcs_java", "readObject"),
            ("danger_funcs_go", "exec.Command"),
            ("danger_funcs_cpp", "strcpy"),
        ],
    )
    def test_rule_finds_intended_pattern(
        self, runner: GrepRunner, rule_id: str, must_hit_substring: str
    ) -> None:
        rule = load_rule_by_id(rule_id)
        findings = runner.scan(REPO, rule)
        assert findings, f"{rule_id} produced no findings"
        snippets = " | ".join(f.snippet for f in findings)
        assert must_hit_substring in snippets, (
            f"{rule_id} expected to hit {must_hit_substring!r}, got snippets: {snippets}"
        )


class TestPatternsHits:
    @pytest.mark.parametrize(
        "rule_id",
        ["zip_slip", "ssrf", "proto_pollution", "jwt"],
    )
    def test_pattern_rule_finds_hits(self, runner: GrepRunner, rule_id: str) -> None:
        rule = load_rule_by_id(rule_id)
        findings = runner.scan(REPO, rule)
        assert findings, f"{rule_id} produced no findings"


class TestFindingShape:
    def test_findings_are_pydantic_models(self, runner: GrepRunner) -> None:
        rule = load_rule_by_id("danger_funcs_python")
        findings = runner.scan(REPO, rule)
        for f in findings:
            assert isinstance(f, Finding)
            assert f.line_number >= 1
            assert f.severity == Severity.HIGH
            assert f.cwe is not None and f.cwe.startswith("CWE-")
            assert f.file_path.endswith(".py")

    def test_findings_id_is_stable(self, runner: GrepRunner) -> None:
        rule = load_rule_by_id("danger_funcs_python")
        a = runner.scan(REPO, rule)
        b = runner.scan(REPO, rule)
        ids_a = sorted(f.id for f in a)
        ids_b = sorted(f.id for f in b)
        assert ids_a == ids_b


class TestSafeYamlSuppression:
    """``must_not_contain`` がファイル内にあれば疑陽性として抑制される。"""

    def test_safe_yaml_file_is_not_flagged(
        self, runner: GrepRunner, tmp_path: Path
    ) -> None:
        # SafeLoader を含むファイルは yaml.load も含むが Finding を出さない
        safe = tmp_path / "safe.py"
        safe.write_text(
            "import yaml\n"
            "yaml.load('a: 1', Loader=yaml.SafeLoader)\n"
        )
        rule = load_rule_by_id("danger_funcs_python")
        findings = runner.scan(tmp_path, rule)
        yaml_findings = [f for f in findings if "yaml.load" in f.snippet]
        assert yaml_findings == []


class TestDedup:
    def test_dedup_same_path_line_category(self) -> None:
        # ヘルパー関数の単体テスト
        f1 = Finding(
            id="A",
            target_url="http://localhost/",
            category="x",
            severity=Severity.LOW,
            cwe="CWE-1",
            file_path="a.py",
            line_number=10,
            snippet="x",
        )
        f2 = Finding(
            id="B",
            target_url="http://localhost/",
            category="x",
            severity=Severity.LOW,
            cwe="CWE-1",
            file_path="a.py",
            line_number=10,
            snippet="x",
        )
        f3 = Finding(
            id="C",
            target_url="http://localhost/",
            category="x",
            severity=Severity.LOW,
            cwe="CWE-1",
            file_path="a.py",
            line_number=11,
            snippet="x",
        )
        out = _dedup_findings([f1, f2, f3])
        assert len(out) == 2
