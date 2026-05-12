"""GHSA Markdown 生成。

入力は :class:`Advisory` (5 点セット + 開示内容)。検証済みの
:class:`~suzaku.herald.checklist.SubmissionInput` を受け取り、
``data/templates/ghsa.md.j2`` をレンダリングする。

5 点セットの欠落があれば ``ChecklistError`` で先に止まる。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from suzaku.herald.checklist import (
    ChecklistError,
    SubmissionInput,
    load_cwe_database,
    validate_submission,
)

TEMPLATES_DIR = Path(__file__).parent / "data" / "templates"

GHSA_TEMPLATE = "ghsa.md.j2"
EMAIL_TEMPLATE = "email.txt.j2"


@dataclass
class Advisory:
    """GHSA / 報告メール 用の全データ。

    ``submission`` は :func:`validate_submission` を通過した 5 点セットを
    想定する。``render_ghsa`` 内でも再検証されるので、明示呼び出しは不要。
    """

    submission: SubmissionInput
    summary: str
    impact_description: str
    mitigation: str
    steps: list[str]
    tested_version: str
    commit_sha: str
    fixed_version: str | None = None
    # report email 専用
    reporter_name: str = "Suzaku Reporter"
    reporter_contact: str = "(redacted — coordinate via vendor security@ first)"
    disclosure_window_days: int = 90

    extra_references: list[str] = field(default_factory=list)


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(disabled_extensions=("j2",)),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _build_context(advisory: Advisory) -> dict[str, object]:
    sub = advisory.submission
    validate_submission(sub)  # 副作用で cvss_score/severity_label が埋まる

    cwe_db = load_cwe_database()
    cwe_entry = cwe_db.get(sub.cwe, {})
    cwe_number = sub.cwe.removeprefix("CWE-")
    references = list(dict.fromkeys([*sub.reference_urls, *advisory.extra_references]))

    return {
        "product_name": sub.product_name,
        "vendor": sub.vendor,
        "affected_versions": sub.affected_versions,
        "fixed_version": advisory.fixed_version,
        "tested_version": advisory.tested_version,
        "commit_sha": advisory.commit_sha,
        "cvss_score": sub.cvss_score,
        "severity_label": sub.severity_label,
        "cvss_vector": sub.cvss_vector,
        "cwe": sub.cwe,
        "cwe_number": cwe_number,
        "cwe_name": cwe_entry.get("name", ""),
        "summary": advisory.summary,
        "impact_description": advisory.impact_description,
        "steps": advisory.steps,
        "reproduction_steps_path": sub.reproduction_steps_path,
        "mitigation": advisory.mitigation,
        "references": references,
        "reporter_name": advisory.reporter_name,
        "reporter_contact": advisory.reporter_contact,
        "disclosure_window_days": advisory.disclosure_window_days,
    }


def render_ghsa(advisory: Advisory) -> str:
    """GHSA Markdown を生成する。"""
    _require_non_empty(advisory.summary, "advisory.summary")
    _require_non_empty(advisory.impact_description, "advisory.impact_description")
    _require_non_empty(advisory.mitigation, "advisory.mitigation")
    _require_non_empty(advisory.commit_sha, "advisory.commit_sha")
    _require_non_empty(advisory.tested_version, "advisory.tested_version")
    if not advisory.steps:
        raise ChecklistError("advisory.steps must contain at least one step")

    context = _build_context(advisory)
    template = _env().get_template(GHSA_TEMPLATE)
    return template.render(**context)


def _require_non_empty(value: str, name: str) -> None:
    if not value or not value.strip():
        raise ChecklistError(f"Missing {name}")
