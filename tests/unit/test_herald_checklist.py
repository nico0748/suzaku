"""Herald Checklist (5点セット欠落チェック) のテスト。"""

from __future__ import annotations

import pytest

from suzaku.herald.checklist import (
    ChecklistError,
    SubmissionInput,
    load_cwe_database,
    validate_submission,
)


def _full_input() -> SubmissionInput:
    return SubmissionInput(
        product_name="example-app",
        vendor="Example Inc.",
        affected_versions=">=1.0.0,<1.2.3",
        cwe="CWE-22",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        reproduction_steps_path="./pocs/F-001/steps.md",
        reference_urls=["https://github.com/example/x/commit/abc123"],
    )


class TestLoadCweDatabase:
    def test_loads_known_cwe(self) -> None:
        db = load_cwe_database()
        assert "CWE-22" in db
        assert "Path Traversal" in db["CWE-22"]["name"]

    def test_includes_owasp_top10_categories(self) -> None:
        db = load_cwe_database()
        for k in ["CWE-79", "CWE-89", "CWE-78", "CWE-352", "CWE-918", "CWE-502", "CWE-1321"]:
            assert k in db


class TestValidateSubmission:
    def test_full_input_passes(self) -> None:
        validate_submission(_full_input())  # not raising

    @pytest.mark.parametrize(
        "field",
        [
            "product_name",
            "vendor",
            "affected_versions",
            "cwe",
            "cvss_vector",
            "reproduction_steps_path",
        ],
    )
    def test_missing_required_field_raises(self, field: str) -> None:
        data = _full_input()
        setattr(data, field, "")
        with pytest.raises(ChecklistError) as exc:
            validate_submission(data)
        assert field in str(exc.value).lower() or field.replace("_", " ") in str(exc.value).lower()

    def test_unknown_cwe_raises(self) -> None:
        data = _full_input()
        data.cwe = "CWE-99999"
        with pytest.raises(ChecklistError) as exc:
            validate_submission(data)
        assert "cwe" in str(exc.value).lower()

    def test_cwe_without_prefix_normalized(self) -> None:
        data = _full_input()
        data.cwe = "22"  # 数値だけでも CWE-22 として扱う
        validate_submission(data)
        assert data.cwe == "CWE-22"

    def test_invalid_cvss_vector_raises(self) -> None:
        data = _full_input()
        data.cvss_vector = "CVSS:3.1/AV:N"
        with pytest.raises(ChecklistError) as exc:
            validate_submission(data)
        assert "cvss" in str(exc.value).lower()

    def test_empty_reference_urls_raises(self) -> None:
        data = _full_input()
        data.reference_urls = []
        with pytest.raises(ChecklistError) as exc:
            validate_submission(data)
        assert "reference" in str(exc.value).lower()

    def test_validate_computes_cvss_score_and_severity(self) -> None:
        data = _full_input()
        validate_submission(data)
        assert data.cvss_score == pytest.approx(9.8, abs=0.05)
        assert data.severity_label == "Critical"

    def test_version_range_must_be_semver_like(self) -> None:
        data = _full_input()
        data.affected_versions = "very old version"
        with pytest.raises(ChecklistError) as exc:
            validate_submission(data)
        assert "version" in str(exc.value).lower()
