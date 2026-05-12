"""GitHub Search API ラッパー (Sentinel のターゲット選定用)。

責務:
- ``/search/repositories`` クエリビルダ
- 5000/h のレートリミット消費を尊重し、Remaining が閾値以下なら待機
- 1 リポジトリ分の :class:`RepoSignals` を組み立てる (実 API 呼び出しは
  メソッドを差し替え可能にして、テストではモック)

実 API 呼び出しを呼ばないテストのために、HTTP は httpx.Client で抽象化し
コンストラクタで差し替え可能。
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from suzaku.sentinel.scoring import RepoSignals

GITHUB_API = "https://api.github.com"
DEFAULT_TIMEOUT = 30.0
RATE_LIMIT_LOW_WATERMARK = 5  # Remaining がこの値以下なら待機


class GitHubSearchError(RuntimeError):
    """API 呼び出しで回復不能なエラーが発生した場合に投げる。"""


@dataclass
class RepoSummary:
    """``/search/repositories`` の各 hit。"""

    full_name: str
    html_url: str
    language: str | None
    stargazers_count: int
    pushed_at: datetime
    description: str | None
    topics: list[str]


def build_search_query(
    *,
    language: str | None = None,
    min_stars: int = 0,
    pushed_after: datetime | None = None,
    topics: Iterable[str] = (),
) -> str:
    """``q`` パラメータ用の検索クエリ文字列を組み立てる。"""
    parts: list[str] = []
    if language:
        parts.append(f"language:{language}")
    if min_stars > 0:
        parts.append(f"stars:>={min_stars}")
    if pushed_after is not None:
        parts.append(f"pushed:>={pushed_after.strftime('%Y-%m-%d')}")
    for topic in topics:
        parts.append(f"topic:{topic}")
    if not parts:
        parts.append("is:public")
    return " ".join(parts)


def _parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _to_summary(item: dict[str, Any]) -> RepoSummary:
    return RepoSummary(
        full_name=str(item.get("full_name", "")),
        html_url=str(item.get("html_url", "")),
        language=item.get("language"),
        stargazers_count=int(item.get("stargazers_count", 0)),
        pushed_at=_parse_datetime(str(item.get("pushed_at", "1970-01-01T00:00:00Z"))),
        description=item.get("description"),
        topics=list(item.get("topics", []) or []),
    )


class GitHubSearch:
    """GitHub Search API の薄いラッパー (httpx ベース)。"""

    def __init__(
        self,
        token: str | None = None,
        client: httpx.Client | None = None,
        sleeper: Any = time.sleep,
    ) -> None:
        self._token = token
        self._client = client or httpx.Client(timeout=DEFAULT_TIMEOUT)
        self._owns_client = client is None
        self._sleeper = sleeper

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> GitHubSearch:
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "suzaku-sentinel/0.1.0",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _maybe_wait_for_rate_limit(self, response: httpx.Response) -> None:
        remaining_raw = response.headers.get("X-RateLimit-Remaining")
        reset_raw = response.headers.get("X-RateLimit-Reset")
        if remaining_raw is None or reset_raw is None:
            return
        try:
            remaining = int(remaining_raw)
            reset = int(reset_raw)
        except ValueError:
            return
        if remaining > RATE_LIMIT_LOW_WATERMARK:
            return
        now = int(datetime.now(UTC).timestamp())
        wait = max(0, reset - now) + 1
        self._sleeper(wait)

    def _request(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{GITHUB_API}{path}"
        for _attempt in range(3):
            response = self._client.get(url, headers=self._headers(), params=params)
            if response.status_code == 403 and "rate limit" in response.text.lower():
                self._maybe_wait_for_rate_limit(response)
                continue
            if response.status_code >= 400:
                raise GitHubSearchError(
                    f"GitHub API error {response.status_code} for {path}: {response.text[:200]}"
                )
            self._maybe_wait_for_rate_limit(response)
            data: Any = response.json()
            if not isinstance(data, dict):
                raise GitHubSearchError(f"Unexpected response shape for {path}")
            return data
        raise GitHubSearchError(f"Exceeded retry budget for {path}")

    def search_repositories(
        self,
        *,
        language: str | None = None,
        min_stars: int = 0,
        pushed_after: datetime | None = None,
        topics: Iterable[str] = (),
        top: int = 20,
    ) -> list[RepoSummary]:
        query = build_search_query(
            language=language,
            min_stars=min_stars,
            pushed_after=pushed_after,
            topics=topics,
        )
        per_page = min(top, 100)
        data = self._request(
            "/search/repositories",
            params={"q": query, "sort": "stars", "order": "desc", "per_page": per_page},
        )
        items = data.get("items", [])
        if not isinstance(items, list):
            return []
        return [_to_summary(item) for item in items[:top]]


def signals_from_summary(
    summary: RepoSummary,
    *,
    issue_response_days: float = 365.0,
    routes_count: int = 0,
    auth_middleware_count: int = 0,
    recent_complex_feature_commits: int = 0,
    docker_compose_services: int = 0,
    dependency_count: int = 0,
    self_implemented_dirs: Iterable[str] = (),
    extra_text: str = "",
) -> RepoSignals:
    """``RepoSummary`` + メタデータから :class:`RepoSignals` を組み立てる。

    `extra_text` には package.json / composer.json / README の連結を渡す。
    """
    pushed = summary.pushed_at
    if pushed.tzinfo is None:
        pushed = pushed.replace(tzinfo=UTC)
    days_since_release = (datetime.now(UTC) - pushed).total_seconds() / 86400
    text_corpus = " ".join(
        filter(None, [summary.description or "", " ".join(summary.topics), extra_text])
    )
    return RepoSignals(
        issue_response_days=issue_response_days,
        routes_count=routes_count,
        auth_middleware_count=auth_middleware_count,
        recent_complex_feature_commits=recent_complex_feature_commits,
        days_since_last_release=days_since_release,
        docker_compose_services=docker_compose_services,
        dependency_count=dependency_count,
        self_implemented_dirs=list(self_implemented_dirs),
        text_corpus=text_corpus,
    )
