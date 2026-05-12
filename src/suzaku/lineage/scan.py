"""VariantRule で repo を横断スキャンする。

既存の :class:`~suzaku.compass.grep_runner.GrepRunner` を再利用するため、
``VariantRule`` を Compass の ``Rule`` 型へ変換するアダプタを提供する。
"""

from __future__ import annotations

from pathlib import Path

from suzaku.compass.grep_runner import GrepRunner
from suzaku.compass.rules import Rule, RulePattern
from suzaku.lineage.models import VariantFinding, VariantRule
from suzaku.models import Severity


def _to_compass_rule(rule: VariantRule) -> Rule:
    return Rule(
        id=rule.rule_id,
        name=f"Lineage variant of {rule.derived_from_cve}",
        description=rule.rationale or "Variant rule derived by Suzaku Lineage.",
        cwe=rule.cwe,
        severity=rule.severity,
        patterns=[
            RulePattern(
                language=rule.language,
                grep=rule.grep,
                must_not_contain=rule.must_not_contain,
            )
        ],
        references=[str(rule.source_commit)],
    )


def scan_with_variant_rules(
    repo_path: Path,
    rules: list[VariantRule],
    *,
    rg_bin: str | None = None,
) -> list[VariantFinding]:
    """``repo_path`` を VariantRule[] でスキャンし VariantFinding[] を返す。"""
    if not rules:
        return []
    runner = GrepRunner()
    out: list[VariantFinding] = []
    for rule in rules:
        compass_rule = _to_compass_rule(rule)
        findings = runner.scan(repo_path, compass_rule, rg_bin=rg_bin)
        for f in findings:
            severity_value = (
                f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
            )
            similarity = 0.85 if rule.must_not_contain else 0.7
            out.append(
                VariantFinding(
                    rule_id=rule.rule_id,
                    derived_from_cve=rule.derived_from_cve,
                    target_repo=str(repo_path),
                    file_path=f.file_path,
                    line_number=f.line_number,
                    snippet=f.snippet,
                    similarity=similarity,
                )
            )
            # severity_value は将来 metadata に格納する想定 (現在は未使用)
            _ = severity_value
    return out


__all__ = ["scan_with_variant_rules"]
