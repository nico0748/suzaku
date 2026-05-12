"""Witness Reproducer の integration テスト (docker 操作はモック)。"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from suzaku.witness.guard import ProductionAccessError
from suzaku.witness.reproducer import PoCContext, Reproducer


class _CallLog:
    def __init__(self) -> None:
        self.calls: list[tuple[Sequence[str], Path]] = []

    def __call__(
        self, cmd: Sequence[str], cwd: Path
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((tuple(cmd), cwd))
        return subprocess.CompletedProcess(args=list(cmd), returncode=0, stdout="", stderr="")


@pytest.fixture
def runner() -> _CallLog:
    return _CallLog()


@pytest.fixture
def repro(tmp_path: Path, runner: _CallLog) -> Reproducer:
    return Reproducer(pocs_dir=tmp_path / "pocs", runner=runner)


class TestInitPoc:
    def test_creates_three_files(self, repro: Reproducer) -> None:
        ctx = PoCContext(
            finding_id="F-001",
            category="ZipSlip",
            affected_version=">=1.0.0,<1.2.3",
            commit_sha="abcdef1234567890",
            steps=["Send a malicious zip", "Observe path traversal"],
        )
        path = repro.init_poc(ctx)

        assert (path / "Dockerfile").exists()
        assert (path / "docker-compose.yml").exists()
        assert (path / "steps.md").exists()

    def test_steps_md_renders_steps(self, repro: Reproducer) -> None:
        ctx = PoCContext(
            finding_id="F-002",
            steps=["Step A", "Step B"],
        )
        path = repro.init_poc(ctx)
        content = (path / "steps.md").read_text()
        assert "Step A" in content
        assert "Step B" in content
        assert "F-002" in content

    def test_compose_uses_loopback_port_binding(self, repro: Reproducer) -> None:
        ctx = PoCContext(finding_id="F-003", ports=[8080])
        path = repro.init_poc(ctx)
        compose = (path / "docker-compose.yml").read_text()
        assert "127.0.0.1:8080:8080" in compose


class TestUp:
    def test_up_invokes_docker_compose(self, repro: Reproducer, runner: _CallLog) -> None:
        repro.init_poc(PoCContext(finding_id="F-001"))
        result = repro.up("F-001")
        assert result.returncode == 0
        assert runner.calls, "runner should be called"
        cmd, _cwd = runner.calls[-1]
        assert list(cmd)[:2] == ["docker", "compose"]
        assert "up" in cmd
        assert "--build" in cmd

    def test_up_rejects_production_host(self, repro: Reproducer, runner: _CallLog) -> None:
        repro.init_poc(PoCContext(finding_id="F-001"))
        with pytest.raises(ProductionAccessError):
            repro.up("F-001", target_host="github.com")
        # ガードで拒否されたら docker は呼ばれない
        assert runner.calls == []

    def test_up_allows_localhost(self, repro: Reproducer) -> None:
        repro.init_poc(PoCContext(finding_id="F-001"))
        repro.up("F-001", target_host="127.0.0.1")  # not raising


class TestDownAndLogs:
    def test_down_invokes_docker_compose_down(
        self, repro: Reproducer, runner: _CallLog
    ) -> None:
        repro.init_poc(PoCContext(finding_id="F-001"))
        repro.down("F-001")
        cmd, _ = runner.calls[-1]
        assert "down" in cmd
        assert "-v" in cmd

    def test_logs_invokes_docker_compose_logs(
        self, repro: Reproducer, runner: _CallLog
    ) -> None:
        repro.init_poc(PoCContext(finding_id="F-001"))
        repro.logs("F-001")
        cmd, _ = runner.calls[-1]
        assert "logs" in cmd
