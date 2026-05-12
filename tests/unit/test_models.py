"""共通モデルのバリデーションテスト。"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from suzaku.models import (
    Disclosure,
    Finding,
    FindingState,
    PoCArtifact,
    Route,
    Severity,
    Submission,
    Target,
    VendorState,
)


class TestTarget:
    def test_valid_target(self) -> None:
        target = Target(
            name="vuln-app",
            url="https://github.com/example/vuln-app",
            language="python",
            star_count=1234,
            last_commit_at=datetime(2026, 1, 1, tzinfo=UTC),
            score=7.5,
            signals={"maintenance_inactivity": 0.8, "thin_auth_layer": 0.6},
        )
        assert target.name == "vuln-app"
        assert target.score == 7.5
        assert target.evaluated_at.tzinfo is not None

    def test_score_out_of_range(self) -> None:
        with pytest.raises(ValidationError):
            Target(
                name="x",
                url="https://github.com/x/x",
                language="python",
                star_count=0,
                last_commit_at=datetime(2026, 1, 1, tzinfo=UTC),
                score=11.0,
                signals={},
            )

    def test_negative_stars_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Target(
                name="x",
                url="https://github.com/x/x",
                language="python",
                star_count=-1,
                last_commit_at=datetime(2026, 1, 1, tzinfo=UTC),
                score=5.0,
                signals={},
            )


class TestFinding:
    def test_default_state_is_new(self) -> None:
        f = Finding(
            id="F-001",
            target_url="https://github.com/example/x",
            category="ZipSlip",
            severity=Severity.HIGH,
            file_path="src/extract.py",
            line_number=42,
            snippet="zipfile.extract(member, dest)",
        )
        assert f.state == FindingState.NEW
        assert f.severity == Severity.HIGH
        assert f.cwe is None

    def test_negative_line_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Finding(
                id="F",
                target_url="https://github.com/x/x",
                category="X",
                severity=Severity.LOW,
                file_path="f",
                line_number=-1,
                snippet="",
            )


class TestPoCArtifact:
    def test_valid(self) -> None:
        a = PoCArtifact(
            finding_id="F-001",
            dockerfile_path="./pocs/F-001/Dockerfile",
            compose_path="./pocs/F-001/docker-compose.yml",
            steps_md_path="./pocs/F-001/steps.md",
            affected_version=">=1.0.0,<1.2.3",
            commit_sha="deadbeef",
            evidence_hash="a" * 64,
        )
        assert a.fixed_version is None


class TestSubmission:
    def test_valid_ghsa(self) -> None:
        s = Submission(
            finding_id="F-001",
            route=Route.GHSA,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_score=9.8,
            cwe="CWE-22",
            affected_versions=">=1.0.0,<1.2.3",
            reference_urls=["https://github.com/example/x/commit/abc"],
            poc_artifact_id="A-001",
        )
        assert s.route == Route.GHSA
        assert s.cve_id is None


class TestDisclosure:
    def test_default_state(self) -> None:
        d = Disclosure(
            submission_id="S-001",
            day_0=datetime(2026, 5, 12, tzinfo=UTC),
        )
        assert d.vendor_state == VendorState.NO_RESPONSE
        assert d.day_3_done is False
        assert d.day_90_done is False
