"""Suzaku MCP ツール — MCP SDK に依存しない純粋関数群。

各関数は MCP server からも、CLI からも、ユニットテストからも呼べる
形を取る。例外は呼び出し側 (``server.py``) が ``isError=True`` に
ラップする。

このモジュールは ``mcp`` パッケージを import しない (テスト時の
依存削減のため)。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from suzaku import __version__
from suzaku.chronicle.escalation import (
    ACCSViolationError,
    evaluate_alert,
)
from suzaku.chronicle.timeline import (
    Milestone,
    build_timeline,
    current_milestone,
    days_elapsed,
)
from suzaku.compass.grep_runner import GrepRunner, RipgrepNotFoundError
from suzaku.compass.rules import (
    RuleError,
    load_all_rules,
    load_rule_by_id,
)
from suzaku.herald.checklist import (
    ChecklistError,
    SubmissionInput,
    validate_submission,
)
from suzaku.herald.cvss import CVSSError, score_severity, score_vector
from suzaku.herald.email_tmpl import ExtortionLanguageError
from suzaku.herald.ghsa import Advisory
from suzaku.herald.routes import (
    ContactAttempt,
    RouteContext,
    RouteError,
    render_for_route,
)
from suzaku.herald.routes import (
    list_routes as herald_list_routes,
)
from suzaku.models import Route, VendorState
from suzaku.sentinel.scoring import (
    DEFAULT_SIGNALS_PATH,
    RepoSignals,
    ScoringConfig,
    score_repo,
)
from suzaku.witness.evidence import EvidenceStore
from suzaku.witness.guard import ProductionAccessError, is_allowed_host
from suzaku.witness.reproducer import PoCContext, Reproducer

ToolMode = Literal["ro", "rw"]


# ────────────────────────────────────────────────────────────────────
# Tool registry
# ────────────────────────────────────────────────────────────────────

RO_TOOLS: tuple[str, ...] = (
    "suzaku_version",
    "sentinel_list_signals",
    "sentinel_score",
    "compass_list_rules",
    "compass_show_rule",
    "compass_scan",
    "witness_check_host",
    "witness_verify",
    "herald_cvss",
    "herald_checklist",
    "herald_list_routes",
    "herald_render",
    "chronicle_status",
    "chronicle_list",
)

RW_TOOLS: tuple[str, ...] = (
    "witness_init",
    "witness_record",
    "chronicle_init",
    "chronicle_set_vendor",
)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    mode: ToolMode


def _semver_string(s: str) -> dict[str, Any]:
    return {"type": "string", "description": s}


TOOL_SPECS: dict[str, ToolSpec] = {
    "suzaku_version": ToolSpec(
        "suzaku_version",
        "Return the Suzaku version string.",
        {"type": "object", "properties": {}, "additionalProperties": False},
        "ro",
    ),
    "sentinel_list_signals": ToolSpec(
        "sentinel_list_signals",
        "List Sentinel signal weights from signals.yaml.",
        {"type": "object", "properties": {}, "additionalProperties": False},
        "ro",
    ),
    "sentinel_score": ToolSpec(
        "sentinel_score",
        "Score a repository given RepoSignals data (does not call GitHub).",
        {
            "type": "object",
            "properties": {
                "signals": {
                    "type": "object",
                    "description": "RepoSignals fields (issue_response_days, routes_count, ...)",
                }
            },
            "required": ["signals"],
        },
        "ro",
    ),
    "compass_list_rules": ToolSpec(
        "compass_list_rules",
        "List bundled Compass rules (10 rules across 6 languages + 4 patterns).",
        {"type": "object", "properties": {}, "additionalProperties": False},
        "ro",
    ),
    "compass_show_rule": ToolSpec(
        "compass_show_rule",
        "Show a single Compass rule definition as JSON.",
        {
            "type": "object",
            "properties": {"rule_id": _semver_string("Rule id (e.g. 'ssrf' or 'danger_funcs_php')")},
            "required": ["rule_id"],
        },
        "ro",
    ),
    "compass_scan": ToolSpec(
        "compass_scan",
        "Scan a local repo directory with a single Compass rule. Read-only filesystem access.",
        {
            "type": "object",
            "properties": {
                "repo_path": _semver_string("Absolute path to the repo to scan"),
                "rule_id": _semver_string("Rule id"),
            },
            "required": ["repo_path", "rule_id"],
        },
        "ro",
    ),
    "witness_check_host": ToolSpec(
        "witness_check_host",
        "Check whether a host would be allowed by the Witness production-access guard.",
        {
            "type": "object",
            "properties": {"host": _semver_string("Host or IP string")},
            "required": ["host"],
        },
        "ro",
    ),
    "witness_verify": ToolSpec(
        "witness_verify",
        "Verify evidence.lock SHA-256 chain integrity for a finding.",
        {
            "type": "object",
            "properties": {
                "finding_id": _semver_string("Finding id"),
                "evidence_dir": _semver_string("Evidence directory (default: ./evidence)"),
            },
            "required": ["finding_id"],
        },
        "ro",
    ),
    "herald_cvss": ToolSpec(
        "herald_cvss",
        "Compute CVSS v3.1 Base Score and severity label from a vector string.",
        {
            "type": "object",
            "properties": {"vector": _semver_string("CVSS:3.1/AV:N/...")},
            "required": ["vector"],
        },
        "ro",
    ),
    "herald_checklist": ToolSpec(
        "herald_checklist",
        "Validate the Herald 5-point checklist for a submission JSON.",
        {
            "type": "object",
            "properties": {"submission": {"type": "object"}},
            "required": ["submission"],
        },
        "ro",
    ),
    "herald_list_routes": ToolSpec(
        "herald_list_routes",
        "List the 8 bundled Herald submission routes with submit URLs.",
        {"type": "object", "properties": {}, "additionalProperties": False},
        "ro",
    ),
    "herald_render": ToolSpec(
        "herald_render",
        "Render an advisory for a given route (ghsa/mitre/huntr/jpcert/wordfence/patchstack/hackerone/bugcrowd).",
        {
            "type": "object",
            "properties": {
                "route": _semver_string("Route id"),
                "advisory": {"type": "object"},
                "context": {"type": "object", "description": "Optional RouteContext fields"},
            },
            "required": ["route", "advisory"],
        },
        "ro",
    ),
    "chronicle_status": ToolSpec(
        "chronicle_status",
        "Compute Chronicle milestone + alert for a submission.",
        {
            "type": "object",
            "properties": {
                "submission_id": _semver_string("Submission id"),
                "day_0": _semver_string("ISO datetime"),
                "vendor_state": _semver_string("no_response/acknowledged/fixing/fixed/rejected"),
            },
            "required": ["submission_id", "day_0"],
        },
        "ro",
    ),
    "chronicle_list": ToolSpec(
        "chronicle_list",
        "List Chronicle state files under a directory.",
        {
            "type": "object",
            "properties": {
                "state_dir": _semver_string("Chronicle state dir (default: ./.suzaku/chronicle)"),
            },
        },
        "ro",
    ),
    # ────── rw ──────
    "witness_init": ToolSpec(
        "witness_init",
        "Initialize a Witness PoC template at pocs/<finding_id>/ (rw).",
        {
            "type": "object",
            "properties": {
                "finding_id": _semver_string("Finding id"),
                "category": _semver_string("Vulnerability category"),
                "affected_version": _semver_string("Affected version range"),
                "commit_sha": _semver_string("Tested commit SHA"),
                "pocs_dir": _semver_string("PoC base dir (default: ./pocs)"),
            },
            "required": ["finding_id"],
        },
        "rw",
    ),
    "witness_record": ToolSpec(
        "witness_record",
        "Append SHA-256 of given files to evidence.lock (rw).",
        {
            "type": "object",
            "properties": {
                "finding_id": _semver_string("Finding id"),
                "files": {"type": "array", "items": {"type": "string"}},
                "evidence_dir": _semver_string("Evidence dir (default: ./evidence)"),
            },
            "required": ["finding_id", "files"],
        },
        "rw",
    ),
    "chronicle_init": ToolSpec(
        "chronicle_init",
        "Initialize Chronicle state for a submission (Day 0 = now) (rw).",
        {
            "type": "object",
            "properties": {
                "submission_id": _semver_string("Submission id"),
                "state_dir": _semver_string("State dir (default: ./.suzaku/chronicle)"),
            },
            "required": ["submission_id"],
        },
        "rw",
    ),
    "chronicle_set_vendor": ToolSpec(
        "chronicle_set_vendor",
        "Update vendor_state for a chronicle entry (rw).",
        {
            "type": "object",
            "properties": {
                "submission_id": _semver_string("Submission id"),
                "state": _semver_string("no_response/acknowledged/fixing/fixed/rejected"),
                "state_dir": _semver_string("State dir (default: ./.suzaku/chronicle)"),
            },
            "required": ["submission_id", "state"],
        },
        "rw",
    ),
}


def list_tool_specs(mode: ToolMode) -> list[ToolSpec]:
    """``mode`` で公開されるツール spec を返す。"""
    names: tuple[str, ...] = RO_TOOLS if mode == "ro" else (*RO_TOOLS, *RW_TOOLS)
    return [TOOL_SPECS[n] for n in names]


# ────────────────────────────────────────────────────────────────────
# Tool implementations
# ────────────────────────────────────────────────────────────────────


def t_suzaku_version() -> dict[str, Any]:
    return {"version": __version__, "name": "Suzaku"}


def t_sentinel_list_signals() -> dict[str, Any]:
    cfg = ScoringConfig.load(DEFAULT_SIGNALS_PATH)
    return {"weights": cfg.weights, "thresholds": cfg.thresholds}


def t_sentinel_score(signals: dict[str, Any]) -> dict[str, Any]:
    repo = RepoSignals(**signals)
    per, score = score_repo(repo)
    return {"score": score, "per_signal": per}


def t_compass_list_rules() -> dict[str, Any]:
    rules = load_all_rules()
    return {
        "rules": [
            {
                "id": r.id,
                "cwe": r.cwe,
                "severity": r.severity.value,
                "languages": sorted({p.language for p in r.patterns}),
            }
            for r in rules
        ]
    }


def t_compass_show_rule(rule_id: str) -> dict[str, Any]:
    r = load_rule_by_id(rule_id)
    return {
        "id": r.id,
        "name": r.name,
        "cwe": r.cwe,
        "severity": r.severity.value,
        "patterns": [
            {"language": p.language, "grep": p.grep, "must_not_contain": p.must_not_contain}
            for p in r.patterns
        ],
        "references": r.references,
    }


def t_compass_scan(repo_path: str, rule_id: str) -> dict[str, Any]:
    rule = load_rule_by_id(rule_id)
    runner = GrepRunner()
    findings = runner.scan(Path(repo_path), rule)
    return {"count": len(findings), "findings": [f.model_dump(mode="json") for f in findings]}


def t_witness_check_host(host: str) -> dict[str, Any]:
    return {"host": host, "allowed": is_allowed_host(host)}


def t_witness_verify(finding_id: str, evidence_dir: str = "./evidence") -> dict[str, Any]:
    store = EvidenceStore(base_dir=Path(evidence_dir))
    return {"finding_id": finding_id, "intact": store.verify(finding_id)}


def t_herald_cvss(vector: str) -> dict[str, Any]:
    score = score_vector(vector)
    return {"score": score, "severity": score_severity(score), "vector": vector}


def t_herald_checklist(submission: dict[str, Any]) -> dict[str, Any]:
    sub = SubmissionInput(**submission)
    validate_submission(sub)
    return {
        "ok": True,
        "cwe": sub.cwe,
        "cvss_score": sub.cvss_score,
        "severity": sub.severity_label,
    }


def t_herald_list_routes() -> dict[str, Any]:
    return {
        "routes": [
            {
                "id": route.value,
                "name": str(meta.get("name", "")),
                "submit_url": str(meta.get("submit_url", "")),
                "note": str(meta.get("note", "")),
            }
            for route, meta in herald_list_routes()
        ]
    }


def _build_advisory(advisory_dict: dict[str, Any]) -> Advisory:
    """JSON dict から Advisory を再構築する。"""
    data = dict(advisory_dict)
    submission_data = data.pop("submission", {})
    submission = SubmissionInput(**submission_data)
    return Advisory(submission=submission, **data)


def _build_route_context(ctx_dict: dict[str, Any] | None) -> RouteContext:
    if not ctx_dict:
        return RouteContext()
    attempts_raw = ctx_dict.get("vendor_contact_attempts", [])
    attempts = [
        ContactAttempt(
            attempted_at=datetime.fromisoformat(a["attempted_at"]),
            channel=str(a["channel"]),
            response=str(a["response"]),
            note=str(a.get("note", "")),
        )
        for a in attempts_raw
    ]
    return RouteContext(
        vendor_contact_attempts=attempts,
        huntr_package_name=ctx_dict.get("huntr_package_name"),
        huntr_package_ecosystem=ctx_dict.get("huntr_package_ecosystem"),
        huntr_repo_url=ctx_dict.get("huntr_repo_url"),
        jpcert_reporter_role=ctx_dict.get("jpcert_reporter_role", "security_researcher"),
        wp_plugin_slug=ctx_dict.get("wp_plugin_slug"),
        wp_active_installs=ctx_dict.get("wp_active_installs"),
        program_handle=ctx_dict.get("program_handle"),
        asset_identifier=ctx_dict.get("asset_identifier"),
    )


def t_herald_render(
    route: str, advisory: dict[str, Any], context: dict[str, Any] | None = None
) -> dict[str, Any]:
    route_enum = Route(route.lower())
    adv = _build_advisory(advisory)
    ctx = _build_route_context(context)
    body = render_for_route(adv, route_enum, ctx)
    return {"route": route_enum.value, "body": body}


def _coerce_dt(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def t_chronicle_status(
    submission_id: str,
    day_0: str,
    vendor_state: str = "no_response",
    now: str | None = None,
) -> dict[str, Any]:
    tl = build_timeline(submission_id, day_0=_coerce_dt(day_0))
    state = VendorState(vendor_state)
    nowdt = _coerce_dt(now) if now else datetime.now(UTC)
    milestone = current_milestone(tl, now=nowdt)
    elapsed = days_elapsed(tl, now=nowdt)
    alert = evaluate_alert(tl, vendor_state=state, now=nowdt)
    return {
        "submission_id": submission_id,
        "day_0": tl.day_0.isoformat(),
        "days_elapsed": elapsed,
        "milestone": milestone.value,
        "vendor_state": state.value,
        "alert": {
            "level": alert.level.value,
            "title": alert.title,
            "action": alert.template,
        },
    }


def t_chronicle_list(state_dir: str = "./.suzaku/chronicle") -> dict[str, Any]:
    sdir = Path(state_dir)
    if not sdir.exists():
        return {"entries": []}
    entries = []
    for f in sorted(sdir.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        entries.append(
            {
                "submission_id": data.get("submission_id", f.stem),
                "day_0": data.get("day_0"),
                "vendor_state": data.get("vendor_state"),
                "published_at": data.get("published_at"),
            }
        )
    return {"entries": entries}


# ────── rw tools ──────


def t_witness_init(
    finding_id: str,
    category: str | None = None,
    affected_version: str | None = None,
    commit_sha: str | None = None,
    pocs_dir: str = "./pocs",
) -> dict[str, Any]:
    repro = Reproducer(pocs_dir=Path(pocs_dir))
    ctx = PoCContext(
        finding_id=finding_id,
        category=category,
        affected_version=affected_version,
        commit_sha=commit_sha or "(pending)",
    )
    path = repro.init_poc(ctx)
    return {"finding_id": finding_id, "poc_dir": str(path)}


def t_witness_record(
    finding_id: str, files: list[str], evidence_dir: str = "./evidence"
) -> dict[str, Any]:
    store = EvidenceStore(base_dir=Path(evidence_dir))
    digest = store.record(finding_id, files=[Path(f) for f in files])
    return {"finding_id": finding_id, "aggregate_hash": digest}


def t_chronicle_init(
    submission_id: str, state_dir: str = "./.suzaku/chronicle"
) -> dict[str, Any]:
    sdir = Path(state_dir)
    sdir.mkdir(parents=True, exist_ok=True)
    tl = build_timeline(submission_id)
    payload = {
        "submission_id": submission_id,
        "day_0": tl.day_0.isoformat(),
        "vendor_state": VendorState.NO_RESPONSE.value,
        "milestones": {e.milestone.value: e.scheduled_at.isoformat() for e in tl.entries},
    }
    path = sdir / f"{submission_id}.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {"submission_id": submission_id, "state_file": str(path)}


def t_chronicle_set_vendor(
    submission_id: str, state: str, state_dir: str = "./.suzaku/chronicle"
) -> dict[str, Any]:
    sdir = Path(state_dir)
    path = sdir / f"{submission_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"Chronicle state not found: {path}")
    payload: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    payload["vendor_state"] = VendorState(state).value
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {"submission_id": submission_id, "vendor_state": state}


# ────────────────────────────────────────────────────────────────────
# Dispatcher
# ────────────────────────────────────────────────────────────────────


_DISPATCH: dict[str, Any] = {
    "suzaku_version": lambda **_: t_suzaku_version(),
    "sentinel_list_signals": lambda **_: t_sentinel_list_signals(),
    "sentinel_score": t_sentinel_score,
    "compass_list_rules": lambda **_: t_compass_list_rules(),
    "compass_show_rule": t_compass_show_rule,
    "compass_scan": t_compass_scan,
    "witness_check_host": t_witness_check_host,
    "witness_verify": t_witness_verify,
    "herald_cvss": t_herald_cvss,
    "herald_checklist": t_herald_checklist,
    "herald_list_routes": lambda **_: t_herald_list_routes(),
    "herald_render": t_herald_render,
    "chronicle_status": t_chronicle_status,
    "chronicle_list": t_chronicle_list,
    "witness_init": t_witness_init,
    "witness_record": t_witness_record,
    "chronicle_init": t_chronicle_init,
    "chronicle_set_vendor": t_chronicle_set_vendor,
}


class UnknownToolError(KeyError):
    """ツール名が見つからない / 現在のモードで非公開の場合に発生。"""


# Suzaku の既知例外群 (server.py から isError=True にマップする用)
SUZAKU_ERRORS: tuple[type[Exception], ...] = (
    ProductionAccessError,
    ACCSViolationError,
    ChecklistError,
    RouteError,
    ExtortionLanguageError,
    CVSSError,
    RuleError,
    RipgrepNotFoundError,
    FileNotFoundError,
    ValueError,
)


def dispatch(name: str, arguments: dict[str, Any], mode: ToolMode) -> dict[str, Any]:
    """ツール名 + 引数を受け取り、辞書結果を返す。

    Raises:
        UnknownToolError: ツール名が見つからない / モードで非公開
        SUZAKU_ERRORS の各例外: ツール固有のエラー
    """
    spec = TOOL_SPECS.get(name)
    if spec is None:
        raise UnknownToolError(f"Unknown tool: {name!r}")
    if mode == "ro" and spec.mode == "rw":
        raise UnknownToolError(
            f"Tool {name!r} requires mode='rw' (currently 'ro' — pass --mode rw to expose)"
        )
    fn = _DISPATCH[name]
    result = fn(**arguments)
    assert isinstance(result, dict)
    return result


__all__ = [
    "RO_TOOLS",
    "RW_TOOLS",
    "SUZAKU_ERRORS",
    "TOOL_SPECS",
    "Milestone",  # re-export for convenience
    "ToolMode",
    "ToolSpec",
    "UnknownToolError",
    "dispatch",
    "list_tool_specs",
]
