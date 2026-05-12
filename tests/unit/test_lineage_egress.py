"""Lineage egress guard のテスト。"""

from __future__ import annotations

import pytest

from suzaku.lineage.egress import (
    LineageEgressError,
    allowed_hosts,
    assert_allowed,
    is_allowed_egress,
    reset_cache,
)


class TestAllowlistLoad:
    def setup_method(self) -> None:
        reset_cache()

    def test_contains_nvd_and_github(self) -> None:
        hosts = allowed_hosts()
        assert "api.github.com" in hosts
        assert "services.nvd.nist.gov" in hosts

    def test_is_allowed_normalizes_case_and_port(self) -> None:
        assert is_allowed_egress("API.GitHub.com") is True
        assert is_allowed_egress("api.github.com:443") is True

    def test_disallowed_hosts(self) -> None:
        assert is_allowed_egress("api.openai.com") is False
        assert is_allowed_egress("google.com") is False
        assert is_allowed_egress("") is False


class TestAssertAllowed:
    def test_passes_for_allowed(self) -> None:
        assert_allowed("api.github.com")

    def test_raises_for_blocked(self) -> None:
        with pytest.raises(LineageEgressError) as exc:
            assert_allowed("api.openai.com")
        assert "allow-list" in str(exc.value).lower()
