"""Compass ルール YAML のロードとデータモデル。

ルール YAML フォーマット (SPEC.md §Compass):

.. code-block:: yaml

    id: zip_slip
    name: Zip Slip ...
    description: |
      ...
    cwe: CWE-22
    severity: high
    patterns:
      - language: python
        grep: 'zipfile\\.extract\\(|tarfile\\.extract'
        must_not_contain: 'realpath|abspath'
    references:
      - https://...
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from suzaku.models import Severity

RULES_DIR = Path(__file__).parent / "rules"

# ファイル拡張子からの言語推定 / scanner の type-filter にも使う。
LANGUAGE_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "php": (".php",),
    "python": (".py",),
    "javascript": (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"),
    "java": (".java",),
    "go": (".go",),
    "cpp": (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"),
    "any": (".php", ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".go", ".c", ".cpp"),
}


class RuleError(ValueError):
    """ルール YAML の形式が不正な場合に発生。"""


@dataclass
class RulePattern:
    language: str
    grep: str
    must_not_contain: str | None = None


@dataclass
class Rule:
    id: str
    name: str
    description: str
    cwe: str
    severity: Severity
    patterns: list[RulePattern]
    references: list[str] = field(default_factory=list)

    def extensions_for(self, language: str) -> tuple[str, ...]:
        return LANGUAGE_EXTENSIONS.get(language, ())


def _parse_severity(raw: Any) -> Severity:
    if isinstance(raw, str):
        try:
            return Severity(raw.lower())
        except ValueError as exc:
            raise RuleError(f"Unknown severity: {raw!r}") from exc
    raise RuleError(f"severity must be a string, got {type(raw).__name__}")


def load_rule(path: Path) -> Rule:
    """YAML ファイル 1 つを読み込んで :class:`Rule` を返す。"""
    with path.open("r", encoding="utf-8") as f:
        data: Any = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise RuleError(f"Rule {path} must be a mapping at top level")

    required = {"id", "name", "description", "cwe", "severity", "patterns"}
    missing = required - data.keys()
    if missing:
        raise RuleError(f"Rule {path} missing keys: {sorted(missing)}")

    patterns_raw = data["patterns"]
    if not isinstance(patterns_raw, list) or not patterns_raw:
        raise RuleError(f"Rule {path} must have non-empty 'patterns' list")

    patterns: list[RulePattern] = []
    for entry in patterns_raw:
        if not isinstance(entry, dict):
            raise RuleError(f"Each pattern must be a mapping, got {entry!r}")
        if "language" not in entry or "grep" not in entry:
            raise RuleError(f"Pattern missing language/grep in {path}")
        language = str(entry["language"])
        if language not in LANGUAGE_EXTENSIONS:
            raise RuleError(f"Unknown language {language!r} in {path}")
        patterns.append(
            RulePattern(
                language=language,
                grep=str(entry["grep"]),
                must_not_contain=(
                    str(entry["must_not_contain"]) if entry.get("must_not_contain") else None
                ),
            )
        )

    return Rule(
        id=str(data["id"]),
        name=str(data["name"]),
        description=str(data["description"]),
        cwe=str(data["cwe"]),
        severity=_parse_severity(data["severity"]),
        patterns=patterns,
        references=[str(u) for u in data.get("references", [])],
    )


def list_rule_paths(rules_dir: Path = RULES_DIR) -> list[Path]:
    """同梱ルールの全 YAML パスを返す。"""
    return sorted(rules_dir.rglob("*.yaml"))


def load_all_rules(rules_dir: Path = RULES_DIR) -> list[Rule]:
    """同梱ルールを全部ロードする。"""
    return [load_rule(p) for p in list_rule_paths(rules_dir)]


def load_rule_by_id(rule_id: str, rules_dir: Path = RULES_DIR) -> Rule:
    """``rule_id`` または ``category/name`` でルールを取得する。

    例:
        - ``"zip_slip"`` -> patterns/zip_slip.yaml
        - ``"danger_funcs/python"`` -> danger_funcs/python.yaml の id
        - ``"patterns/jwt"`` -> patterns/jwt.yaml の id
    """
    # path-like 指定
    candidate = rules_dir / f"{rule_id}.yaml"
    if candidate.exists():
        return load_rule(candidate)
    # id で検索
    for rule in load_all_rules(rules_dir):
        if rule.id == rule_id:
            return rule
    raise RuleError(f"Unknown rule id or path: {rule_id!r}")
