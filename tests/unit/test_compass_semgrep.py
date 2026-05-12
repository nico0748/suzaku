"""semgrep_runner の最小テスト (実 semgrep には依存しない)。"""

from __future__ import annotations

import shutil
from pathlib import Path

from suzaku.compass.semgrep_runner import (
    SemgrepStatus,
    _parse_semgrep_results,
    _severity_from_semgrep,
    detect_semgrep,
    scan_with_semgrep,
)
from suzaku.models import Severity


class TestDetect:
    def test_returns_status(self) -> None:
        s = detect_semgrep()
        assert isinstance(s, SemgrepStatus)


class TestScanGracefulWhenAbsent:
    def test_returns_empty_when_semgrep_missing(self, tmp_path: Path) -> None:
        if shutil.which("semgrep") is not None:
            return  # 環境に semgrep がある場合のみスキップ
        assert scan_with_semgrep(tmp_path) == []


class TestSeverityMapping:
    def test_known_levels(self) -> None:
        assert _severity_from_semgrep("ERROR") == Severity.HIGH
        assert _severity_from_semgrep("WARNING") == Severity.MEDIUM
        assert _severity_from_semgrep("INFO") == Severity.INFO
        assert _severity_from_semgrep("unknown") == Severity.INFO


class TestParseResults:
    def test_parses_minimal_payload(self) -> None:
        data = {
            "results": [
                {
                    "check_id": "rules.dangerous-eval",
                    "path": "/repo/a.py",
                    "start": {"line": 42},
                    "extra": {"severity": "ERROR", "message": "Use of eval()"},
                }
            ]
        }
        findings = _parse_semgrep_results(data, "http://localhost/")
        assert len(findings) == 1
        f = findings[0]
        assert f.category == "rules.dangerous-eval"
        assert f.line_number == 42
        assert f.severity == Severity.HIGH

    def test_handles_missing_results(self) -> None:
        assert _parse_semgrep_results({}, "http://localhost/") == []
