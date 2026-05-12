"""Herald 追加申請ルート (Phase 2-D) の integration テスト。"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from suzaku.herald.checklist import ChecklistError, SubmissionInput
from suzaku.herald.email_tmpl import ExtortionLanguageError
from suzaku.herald.ghsa import Advisory, render_ghsa
from suzaku.herald.routes import (
    ContactAttempt,
    RouteContext,
    RouteError,
    list_routes,
    load_routes_meta,
    render_for_route,
)
from suzaku.models import Route


def _submission() -> SubmissionInput:
    return SubmissionInput(
        product_name="example-app",
        vendor="Example Inc.",
        affected_versions=">=1.0.0,<1.2.3",
        cwe="CWE-22",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        reproduction_steps_path="./pocs/F-001/steps.md",
        reference_urls=["https://github.com/example/x/commit/abc123"],
    )


def _advisory(**overrides: object) -> Advisory:
    defaults: dict[str, object] = dict(
        submission=_submission(),
        summary="Zip Slip path traversal",
        impact_description="An attacker who can upload archives gains write access ...",
        mitigation="Validate each entry with os.path.realpath.",
        steps=["Send crafted zip", "Trigger import", "Observe traversal"],
        tested_version="1.2.2",
        commit_sha="deadbeefcafe1234567890",
        fixed_version="1.2.3",
    )
    defaults.update(overrides)
    return Advisory(**defaults)  # type: ignore[arg-type]


class TestRouteMetadata:
    def test_load_routes_meta_has_8_entries(self) -> None:
        meta = load_routes_meta()
        assert set(meta.keys()) >= {
            "ghsa", "mitre", "huntr", "jpcert",
            "wordfence", "patchstack", "hackerone", "bugcrowd",
        }

    def test_list_routes_returns_tuples(self) -> None:
        items = list_routes()
        assert len(items) >= 8
        for route, meta in items:
            assert isinstance(route, Route)
            assert "name" in meta
            assert "submit_url" in meta


class TestRenderGHSACompat:
    """既存 render_ghsa が render_for_route と同等の Markdown を返す。"""

    def test_via_dispatcher_returns_ghsa_markdown(self) -> None:
        md = render_for_route(_advisory(), Route.GHSA)
        assert "## Summary" in md
        assert "## Affected Versions" in md
        assert "## Impact" in md

    def test_existing_render_ghsa_still_works(self) -> None:
        md = render_ghsa(_advisory())
        assert "## Summary" in md  # 後方互換


class TestMITRE:
    def test_renders_with_contact_attempts(self) -> None:
        ctx = RouteContext(
            vendor_contact_attempts=[
                ContactAttempt(
                    attempted_at=datetime(2026, 1, 1, tzinfo=UTC),
                    channel="email security@example.com",
                    response="no_response",
                ),
                ContactAttempt(
                    attempted_at=datetime(2026, 1, 14, tzinfo=UTC),
                    channel="github_issue #42",
                    response="no_response",
                ),
            ]
        )
        md = render_for_route(_advisory(), Route.MITRE, ctx)
        assert "MITRE CNA-LR" in md
        assert "Vendor Contact Timeline" in md
        assert "2026-01-01" in md
        assert "github_issue" in md

    def test_missing_contact_attempts_raises(self) -> None:
        with pytest.raises(RouteError) as exc:
            render_for_route(_advisory(), Route.MITRE, RouteContext())
        assert "vendor_contact_attempts" in str(exc.value)


class TestHuntr:
    def test_renders_with_required_fields(self) -> None:
        ctx = RouteContext(
            huntr_package_name="example-plugin",
            huntr_package_ecosystem="npm",
            huntr_repo_url="https://github.com/example/x",
        )
        md = render_for_route(_advisory(), Route.HUNTR, ctx)
        assert "huntr.dev" in md
        assert "example-plugin" in md
        assert "Ecosystem" in md
        assert "npm" in md

    def test_missing_package_raises(self) -> None:
        ctx = RouteContext(huntr_package_ecosystem="npm")  # name 欠
        with pytest.raises(RouteError):
            render_for_route(_advisory(), Route.HUNTR, ctx)

    def test_missing_ecosystem_raises(self) -> None:
        ctx = RouteContext(huntr_package_name="lodash")  # ecosystem 欠
        with pytest.raises(RouteError):
            render_for_route(_advisory(), Route.HUNTR, ctx)


class TestJPCERT:
    def test_renders_japanese_text(self) -> None:
        text = render_for_route(_advisory(), Route.JPCERT)
        assert "JPCERT/CC" in text
        assert "報告者情報" in text
        assert "脆弱性情報" in text
        # 日本語フィールドが埋まる
        assert "影響を受ける版" in text


class TestWordfencePatchstack:
    def test_wordfence_renders_with_slug(self) -> None:
        ctx = RouteContext(wp_plugin_slug="example-plugin", wp_active_installs=12000)
        md = render_for_route(_advisory(), Route.WORDFENCE, ctx)
        assert "Wordfence" in md
        assert "example-plugin" in md
        assert "12000" in md

    def test_wordfence_missing_slug_raises(self) -> None:
        with pytest.raises(RouteError) as exc:
            render_for_route(_advisory(), Route.WORDFENCE, RouteContext())
        assert "wp_plugin_slug" in str(exc.value)

    def test_patchstack_renders_with_slug(self) -> None:
        ctx = RouteContext(wp_plugin_slug="example-plugin")
        md = render_for_route(_advisory(), Route.PATCHSTACK, ctx)
        assert "Patchstack" in md
        assert "example-plugin" in md

    def test_patchstack_missing_slug_raises(self) -> None:
        with pytest.raises(RouteError):
            render_for_route(_advisory(), Route.PATCHSTACK, RouteContext())


class TestHackerOneBugcrowd:
    def test_hackerone_renders_with_program(self) -> None:
        ctx = RouteContext(program_handle="github", asset_identifier="api.github.com")
        md = render_for_route(_advisory(), Route.HACKERONE, ctx)
        assert "HackerOne" in md
        assert "github" in md
        assert "api.github.com" in md

    def test_hackerone_missing_program_raises(self) -> None:
        with pytest.raises(RouteError):
            render_for_route(_advisory(), Route.HACKERONE, RouteContext())

    def test_bugcrowd_renders_with_program(self) -> None:
        ctx = RouteContext(program_handle="company-x")
        md = render_for_route(_advisory(), Route.BUGCROWD, ctx)
        assert "Bugcrowd" in md
        assert "company-x" in md

    def test_bugcrowd_missing_program_raises(self) -> None:
        with pytest.raises(RouteError):
            render_for_route(_advisory(), Route.BUGCROWD, RouteContext())


class TestForbiddenLanguageGuard:
    def test_extortion_in_summary_blocks_all_routes(self) -> None:
        adv = _advisory(summary="Critical RCE — pay first or I will release details.")
        for route in (Route.GHSA, Route.HUNTR, Route.HACKERONE):
            ctx = RouteContext(
                huntr_package_name="x",
                huntr_package_ecosystem="npm",
                program_handle="github",
            )
            with pytest.raises(ExtortionLanguageError):
                render_for_route(adv, route, ctx)


class TestChecklistPropagation:
    def test_missing_5point_raises_checklist_error(self) -> None:
        bad = _submission()
        bad.cwe = "CWE-99999"
        adv = _advisory(submission=bad)
        with pytest.raises(ChecklistError):
            render_for_route(adv, Route.GHSA)
