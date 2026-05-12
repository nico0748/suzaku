"""Sentinel search.py のテスト (respx で GitHub API をモック)。"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
import respx

from suzaku.sentinel.search import (
    GITHUB_API,
    GitHubSearch,
    GitHubSearchError,
    build_search_query,
    signals_from_summary,
)


class TestBuildSearchQuery:
    def test_basic_query(self) -> None:
        q = build_search_query(language="python", min_stars=500)
        assert "language:python" in q
        assert "stars:>=500" in q

    def test_with_pushed_after(self) -> None:
        q = build_search_query(pushed_after=datetime(2026, 1, 15, tzinfo=UTC))
        assert "pushed:>=2026-01-15" in q

    def test_with_topics(self) -> None:
        q = build_search_query(topics=["wordpress-plugin", "saas"])
        assert "topic:wordpress-plugin" in q
        assert "topic:saas" in q

    def test_default_when_empty(self) -> None:
        assert build_search_query() == "is:public"


class TestSearchRepositories:
    @respx.mock
    def test_returns_summary_objects(self) -> None:
        respx.get(f"{GITHUB_API}/search/repositories").respond(
            200,
            headers={"X-RateLimit-Remaining": "100", "X-RateLimit-Reset": "0"},
            json={
                "total_count": 1,
                "items": [
                    {
                        "full_name": "example/x",
                        "html_url": "https://github.com/example/x",
                        "language": "Python",
                        "stargazers_count": 1234,
                        "pushed_at": "2026-05-10T12:00:00Z",
                        "description": "an example",
                        "topics": ["security"],
                    }
                ],
            },
        )
        with GitHubSearch(token="t") as gh:
            results = gh.search_repositories(language="python", top=5)
        assert len(results) == 1
        assert results[0].full_name == "example/x"
        assert results[0].topics == ["security"]

    @respx.mock
    def test_top_limit_respected(self) -> None:
        items = [
            {
                "full_name": f"o/r{i}",
                "html_url": f"https://github.com/o/r{i}",
                "language": "Python",
                "stargazers_count": 0,
                "pushed_at": "2026-01-01T00:00:00Z",
                "description": None,
                "topics": [],
            }
            for i in range(20)
        ]
        respx.get(f"{GITHUB_API}/search/repositories").respond(
            200,
            headers={"X-RateLimit-Remaining": "100", "X-RateLimit-Reset": "0"},
            json={"total_count": 20, "items": items},
        )
        with GitHubSearch() as gh:
            r = gh.search_repositories(top=5)
        assert len(r) == 5

    @respx.mock
    def test_api_error_raises(self) -> None:
        respx.get(f"{GITHUB_API}/search/repositories").respond(
            500, json={"message": "boom"}
        )
        with GitHubSearch() as gh, pytest.raises(GitHubSearchError):
            gh.search_repositories()


class TestRateLimit:
    @respx.mock
    def test_low_remaining_triggers_sleep(self) -> None:
        slept: list[float] = []
        respx.get(f"{GITHUB_API}/search/repositories").respond(
            200,
            headers={
                "X-RateLimit-Remaining": "1",
                "X-RateLimit-Reset": str(int(datetime.now(UTC).timestamp()) + 5),
            },
            json={"total_count": 0, "items": []},
        )
        with GitHubSearch(sleeper=slept.append) as gh:
            gh.search_repositories()
        assert slept, "expected sleeper to be invoked when remaining is low"
        assert max(slept) > 0

    @respx.mock
    def test_high_remaining_no_sleep(self) -> None:
        slept: list[float] = []
        respx.get(f"{GITHUB_API}/search/repositories").respond(
            200,
            headers={"X-RateLimit-Remaining": "4000", "X-RateLimit-Reset": "0"},
            json={"total_count": 0, "items": []},
        )
        with GitHubSearch(sleeper=slept.append) as gh:
            gh.search_repositories()
        assert slept == []

    @respx.mock
    def test_403_rate_limit_retry(self) -> None:
        slept: list[float] = []
        # 最初は 403、次は 200
        route = respx.get(f"{GITHUB_API}/search/repositories")
        route.side_effect = [
            httpx.Response(
                403,
                headers={
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(datetime.now(UTC).timestamp()) + 2),
                },
                text="API rate limit exceeded",
            ),
            httpx.Response(
                200,
                headers={"X-RateLimit-Remaining": "100", "X-RateLimit-Reset": "0"},
                json={"total_count": 0, "items": []},
            ),
        ]
        with GitHubSearch(sleeper=slept.append) as gh:
            results = gh.search_repositories()
        assert results == []
        assert slept, "expected sleeper to be invoked on 403"


class TestSignalsFromSummary:
    def test_assembles_signals(self) -> None:
        from suzaku.sentinel.search import RepoSummary

        s = RepoSummary(
            full_name="example/billing-app",
            html_url="https://github.com/example/billing-app",
            language="Python",
            stargazers_count=900,
            pushed_at=datetime.now(UTC),
            description="A billing platform with stripe and paypal",
            topics=["payment"],
        )
        signals = signals_from_summary(
            s, dependency_count=42, self_implemented_dirs=["crypto"]
        )
        assert signals.dependency_count == 42
        assert "billing" in signals.text_corpus.lower()
        assert signals.self_implemented_dirs == ["crypto"]
        assert signals.days_since_last_release < 1.0
