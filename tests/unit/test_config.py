"""設定 (pydantic-settings) のテスト。"""

from __future__ import annotations

from pathlib import Path

import pytest

from suzaku.config import Settings, get_settings, reset_settings


@pytest.fixture(autouse=True)
def _reset() -> None:
    reset_settings()


def test_defaults() -> None:
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.log_level == "INFO"
    assert s.data_dir == Path("./.suzaku")
    assert s.github_token is None


def test_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUZAKU_GITHUB_TOKEN", "ghp_test")
    monkeypatch.setenv("SUZAKU_LOG_LEVEL", "DEBUG")
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.github_token == "ghp_test"
    assert s.log_level == "DEBUG"


def test_get_settings_singleton() -> None:
    a = get_settings()
    b = get_settings()
    assert a is b
