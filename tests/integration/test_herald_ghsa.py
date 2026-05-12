"""Herald GHSA Markdown + 報告メールの生成テスト。"""

from __future__ import annotations

import pytest

from suzaku.herald.checklist import ChecklistError, SubmissionInput
from suzaku.herald.email_tmpl import ExtortionLanguageError, render_email
from suzaku.herald.ghsa import Advisory, render_ghsa


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
        summary="Zip Slip path traversal during archive extraction",
        impact_description=(
            "An attacker who can upload a crafted archive can write files "
            "outside the extraction directory, potentially overwriting "
            "config or binaries."
        ),
        mitigation=(
            "Validate each extracted entry against the extraction root "
            "using `os.path.realpath` before write."
        ),
        steps=[
            "Send a zip containing an entry named `../../etc/cron.d/poc`",
            "Trigger the import endpoint",
            "Observe the file written outside the upload dir",
        ],
        tested_version="1.2.2",
        commit_sha="deadbeefcafe1234567890",
        fixed_version="1.2.3",
    )
    defaults.update(overrides)
    return Advisory(**defaults)  # type: ignore[arg-type]


class TestRenderGHSA:
    def test_renders_all_sections(self) -> None:
        md = render_ghsa(_advisory())
        assert "## Summary" in md
        assert "## Affected Versions" in md
        assert "## Impact" in md
        assert "## Reproduction Steps" in md
        assert "## Suggested Mitigation" in md
        assert "## References" in md

    def test_includes_cvss_score_and_severity(self) -> None:
        md = render_ghsa(_advisory())
        assert "9.8" in md
        assert "Critical" in md
        assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in md

    def test_includes_cwe_link_with_number(self) -> None:
        md = render_ghsa(_advisory())
        assert "[CWE-22]" in md
        assert "cwe.mitre.org/data/definitions/22.html" in md
        assert "Path Traversal" in md

    def test_truncates_commit_sha_to_short(self) -> None:
        md = render_ghsa(_advisory())
        # short commit sha is first 7 chars
        assert "`deadbee`" in md

    def test_lists_reproduction_steps_numbered(self) -> None:
        md = render_ghsa(_advisory())
        assert "1. Send a zip" in md
        assert "2. Trigger the import endpoint" in md
        assert "3. Observe the file written outside the upload dir" in md

    def test_fixed_version_pending_when_missing(self) -> None:
        md = render_ghsa(_advisory(fixed_version=None))
        assert "(pending)" in md

    def test_extra_references_appended_and_deduped(self) -> None:
        md = render_ghsa(
            _advisory(
                extra_references=[
                    "https://github.com/example/x/commit/abc123",  # 重複
                    "https://snyk.io/blog/zip-slip-vulnerability/",
                ]
            )
        )
        # 重複は1回だけ
        assert md.count("commit/abc123") == 1
        assert "snyk.io/blog/zip-slip-vulnerability" in md

    def test_missing_summary_raises(self) -> None:
        with pytest.raises(ChecklistError):
            render_ghsa(_advisory(summary=""))

    def test_missing_steps_raises(self) -> None:
        with pytest.raises(ChecklistError):
            render_ghsa(_advisory(steps=[]))

    def test_invalid_submission_propagates(self) -> None:
        sub = _submission()
        sub.cwe = "CWE-99999"
        with pytest.raises(ChecklistError):
            render_ghsa(_advisory(submission=sub))


class TestRenderEmail:
    def test_contains_iso29147_friendly_framing(self) -> None:
        email = render_email(_advisory(reporter_contact="reporter@example.test"))
        assert "Subject:" in email
        assert "coordinated" in email.lower()
        assert "29147" in email

    def test_contains_cvss_and_cwe(self) -> None:
        email = render_email(_advisory(reporter_contact="reporter@example.test"))
        assert "9.8" in email
        assert "Critical" in email
        assert "CWE-22" in email

    def test_disclosure_window_default_90(self) -> None:
        email = render_email(_advisory(reporter_contact="r@example.test"))
        assert "90" in email
        # Day 0 / Day 14 timeline が含まれる
        assert "Day 0" in email
        assert "Day 14" in email

    def test_disclosure_window_custom(self) -> None:
        email = render_email(
            _advisory(reporter_contact="r@example.test", disclosure_window_days=120)
        )
        assert "Day 120" in email

    def test_no_extortion_language(self) -> None:
        email = render_email(_advisory(reporter_contact="r@example.test"))
        lowered = email.lower()
        assert "pay first" not in lowered
        assert "ransom" not in lowered
        assert "or else" not in lowered
        assert "last warning" not in lowered

    def test_extortion_phrase_detection(self) -> None:
        """禁止語を含むよう細工された summary に対しガードが発火する。"""
        adv = _advisory(
            reporter_contact="r@example.test",
            summary="Critical RCE. PAY FIRST or I will release details.",
        )
        with pytest.raises(ExtortionLanguageError):
            render_email(adv)

    def test_missing_reporter_contact_raises(self) -> None:
        with pytest.raises(ChecklistError):
            render_email(_advisory(reporter_contact=""))

    def test_zero_disclosure_window_raises(self) -> None:
        with pytest.raises(ChecklistError):
            render_email(_advisory(reporter_contact="r@example.test", disclosure_window_days=0))
