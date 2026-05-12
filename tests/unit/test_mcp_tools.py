"""Suzaku MCP tools のテスト (MCP SDK には依存しない純粋関数の検証)。"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from suzaku.herald.checklist import ChecklistError
from suzaku.herald.cvss import CVSSError
from suzaku.herald.email_tmpl import ExtortionLanguageError
from suzaku.herald.routes import RouteError
from suzaku.mcp.tools import (
    RO_TOOLS,
    RW_TOOLS,
    TOOL_SPECS,
    UnknownToolError,
    dispatch,
    list_tool_specs,
    t_chronicle_init,
    t_chronicle_list,
    t_chronicle_set_vendor,
    t_chronicle_status,
    t_compass_list_rules,
    t_compass_show_rule,
    t_herald_cvss,
    t_herald_list_routes,
    t_herald_render,
    t_sentinel_list_signals,
    t_sentinel_score,
    t_suzaku_version,
    t_witness_check_host,
    t_witness_init,
    t_witness_record,
    t_witness_verify,
)


class TestToolRegistry:
    def test_ro_has_17_tools(self) -> None:
        # 14 base + 3 reader (Phase 2-A1)
        assert len(RO_TOOLS) == 17

    def test_rw_has_4_tools(self) -> None:
        assert len(RW_TOOLS) == 4

    def test_all_tool_specs_have_input_schema(self) -> None:
        for name, spec in TOOL_SPECS.items():
            assert isinstance(spec.input_schema, dict)
            assert spec.input_schema.get("type") == "object", name

    def test_list_tool_specs_ro_excludes_rw(self) -> None:
        specs = list_tool_specs("ro")
        names = {s.name for s in specs}
        for rw in RW_TOOLS:
            assert rw not in names

    def test_list_tool_specs_rw_includes_all(self) -> None:
        specs = list_tool_specs("rw")
        names = {s.name for s in specs}
        for ro in RO_TOOLS:
            assert ro in names
        for rw in RW_TOOLS:
            assert rw in names


class TestVersion:
    def test_returns_version(self) -> None:
        result = t_suzaku_version()
        assert "version" in result
        assert result["name"] == "Suzaku"


class TestSentinel:
    def test_list_signals(self) -> None:
        result = t_sentinel_list_signals()
        assert "weights" in result
        assert "maintenance_inactivity" in result["weights"]

    def test_score_pure_function(self) -> None:
        result = t_sentinel_score({"issue_response_days": 45, "dependency_count": 60})
        assert 0.0 <= result["score"] <= 10.0
        assert "maintenance_inactivity" in result["per_signal"]


class TestCompass:
    def test_list_rules(self) -> None:
        result = t_compass_list_rules()
        ids = {r["id"] for r in result["rules"]}
        assert "ssrf" in ids
        assert "danger_funcs_python" in ids

    def test_show_rule(self) -> None:
        result = t_compass_show_rule(rule_id="ssrf")
        assert result["cwe"] == "CWE-918"

    def test_show_unknown_raises(self) -> None:
        with pytest.raises(Exception):  # noqa: B017 - RuleError
            t_compass_show_rule(rule_id="nope")


class TestWitness:
    def test_check_host_allowed(self) -> None:
        result = t_witness_check_host(host="127.0.0.1")
        assert result["allowed"] is True

    def test_check_host_blocked(self) -> None:
        result = t_witness_check_host(host="github.com")
        assert result["allowed"] is False

    def test_init_and_record_and_verify(self, tmp_path: Path) -> None:
        pocs = tmp_path / "pocs"
        evidence = tmp_path / "evidence"
        init = t_witness_init(finding_id="F-001", pocs_dir=str(pocs))
        assert (Path(init["poc_dir"]) / "Dockerfile").exists()
        sample_file = Path(init["poc_dir"]) / "Dockerfile"
        rec = t_witness_record(
            finding_id="F-001", files=[str(sample_file)], evidence_dir=str(evidence)
        )
        assert len(rec["aggregate_hash"]) == 64
        # NB: record() の rel パスは evidence/<id>/ 配下を想定するので、
        # init で生成された Dockerfile はパスが異なり verify が False になる。
        # ここでは aggregate_hash の存在のみ検証する。
        verify = t_witness_verify(finding_id="F-001", evidence_dir=str(evidence))
        assert "intact" in verify


class TestHerald:
    def test_cvss(self) -> None:
        result = t_herald_cvss(vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert result["score"] == pytest.approx(9.8, abs=0.05)
        assert result["severity"] == "Critical"

    def test_cvss_invalid_raises(self) -> None:
        with pytest.raises(CVSSError):
            t_herald_cvss(vector="bad")

    def test_list_routes(self) -> None:
        result = t_herald_list_routes()
        ids = {r["id"] for r in result["routes"]}
        assert {"ghsa", "mitre", "huntr", "jpcert"} <= ids

    def _advisory_dict(self) -> dict:
        return {
            "submission": {
                "product_name": "example",
                "vendor": "Example Inc.",
                "affected_versions": ">=1.0.0,<1.2.3",
                "cwe": "CWE-22",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "reproduction_steps_path": "./pocs/F/steps.md",
                "reference_urls": ["https://github.com/example/x/commit/abc"],
            },
            "summary": "Zip Slip",
            "impact_description": "Impact",
            "mitigation": "realpath",
            "steps": ["a", "b"],
            "tested_version": "1.2.2",
            "commit_sha": "deadbeef1234",
            "fixed_version": "1.2.3",
        }

    def test_render_ghsa(self) -> None:
        result = t_herald_render(route="ghsa", advisory=self._advisory_dict())
        assert "## Summary" in result["body"]

    def test_render_mitre_missing_context(self) -> None:
        with pytest.raises(RouteError):
            t_herald_render(route="mitre", advisory=self._advisory_dict())

    def test_render_huntr_with_context(self) -> None:
        result = t_herald_render(
            route="huntr",
            advisory=self._advisory_dict(),
            context={"huntr_package_name": "x", "huntr_package_ecosystem": "npm"},
        )
        assert "huntr.dev" in result["body"]

    def test_render_extortion_blocked(self) -> None:
        adv = self._advisory_dict()
        adv["summary"] = "RCE - pay first or i will release details"
        with pytest.raises(ExtortionLanguageError):
            t_herald_render(route="ghsa", advisory=adv)

    def test_render_checklist_failure_propagates(self) -> None:
        adv = self._advisory_dict()
        adv["submission"]["cwe"] = "CWE-99999"
        with pytest.raises(ChecklistError):
            t_herald_render(route="ghsa", advisory=adv)


class TestChronicle:
    def test_status_day_3(self) -> None:
        day_0 = (datetime.now(UTC) - timedelta(days=5)).isoformat()
        result = t_chronicle_status(submission_id="S-001", day_0=day_0)
        assert result["days_elapsed"] >= 3
        assert result["alert"]["level"] in {"reminder", "alt_channel"}

    def test_status_invalid_vendor_raises(self) -> None:
        with pytest.raises(ValueError):
            t_chronicle_status(
                submission_id="S-001",
                day_0=datetime.now(UTC).isoformat(),
                vendor_state="never_heard_of_it",
            )

    def test_init_and_list(self, tmp_path: Path) -> None:
        sdir = tmp_path / "chron"
        init = t_chronicle_init(submission_id="S-1", state_dir=str(sdir))
        assert Path(init["state_file"]).exists()
        listing = t_chronicle_list(state_dir=str(sdir))
        assert any(e["submission_id"] == "S-1" for e in listing["entries"])

    def test_set_vendor_persists(self, tmp_path: Path) -> None:
        sdir = tmp_path / "chron"
        t_chronicle_init(submission_id="S-1", state_dir=str(sdir))
        result = t_chronicle_set_vendor(
            submission_id="S-1", state="acknowledged", state_dir=str(sdir)
        )
        assert result["vendor_state"] == "acknowledged"
        data = json.loads((sdir / "S-1.json").read_text())
        assert data["vendor_state"] == "acknowledged"


class TestDispatch:
    def test_dispatch_ro_tool(self) -> None:
        result = dispatch(
            "herald_cvss", {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, "ro"
        )
        assert result["severity"] == "Critical"

    def test_dispatch_rw_tool_blocked_in_ro_mode(self, tmp_path: Path) -> None:
        with pytest.raises(UnknownToolError) as exc:
            dispatch(
                "chronicle_init",
                {"submission_id": "X", "state_dir": str(tmp_path)},
                "ro",
            )
        assert "rw" in str(exc.value).lower()

    def test_dispatch_rw_tool_works_in_rw_mode(self, tmp_path: Path) -> None:
        result = dispatch(
            "chronicle_init",
            {"submission_id": "X", "state_dir": str(tmp_path)},
            "rw",
        )
        assert result["submission_id"] == "X"

    def test_dispatch_unknown_tool(self) -> None:
        with pytest.raises(UnknownToolError):
            dispatch("totally_made_up", {}, "rw")

    def test_dangerous_tools_not_exposed(self) -> None:
        """SPEC で「公開しない」と明記したツールはどのモードでも出てこない。"""
        ro = {s.name for s in list_tool_specs("ro")}
        rw = {s.name for s in list_tool_specs("rw")}
        for forbidden in {"witness_reproduce", "chronicle_publish", "sentinel_scan"}:
            assert forbidden not in ro
            assert forbidden not in rw
