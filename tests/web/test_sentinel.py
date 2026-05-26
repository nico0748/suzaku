"""``/api/sentinel/*`` エンドポイントのテスト。"""

from __future__ import annotations

import respx
from fastapi.testclient import TestClient

from suzaku.sentinel.search import GITHUB_API

CSRF = "test-csrf-token-fixed"


class TestSignals:
    def test_returns_weight_keys(self, client: TestClient) -> None:
        resp = client.get("/api/sentinel/signals")
        assert resp.status_code == 200
        body = resp.json()
        # 8 シグナル分の重みが返る
        assert "maintenance_inactivity" in body["weights"]
        assert "monetary" in body["weights"]
        assert isinstance(body["keywords"], dict)
        assert isinstance(body["thresholds"], dict)


class TestScan:
    @respx.mock
    def test_scan_returns_scored_results(self, client: TestClient) -> None:
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
        resp = client.post(
            "/api/sentinel/scan",
            headers={"x-suzaku-csrf": CSRF},
            json={
                "language": "python",
                "min_stars": 100,
                "top": 5,
                "token": "fake-pat",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["query"]
        assert len(body["results"]) == 1
        first = body["results"][0]
        assert first["name"] == "example/x"
        assert first["stars"] == 1234
        assert "signals" in first
        assert isinstance(first["score"], float)

    def test_invalid_pushed_after_yields_400(self, client: TestClient) -> None:
        resp = client.post(
            "/api/sentinel/scan",
            headers={"x-suzaku-csrf": CSRF},
            json={
                "language": "python",
                "min_stars": 100,
                "top": 5,
                "pushed_after": "not-a-date",
            },
        )
        assert resp.status_code == 400
        assert "invalid pushed_after" in resp.json()["detail"]

    @respx.mock
    def test_github_failure_yields_502(self, client: TestClient) -> None:
        respx.get(f"{GITHUB_API}/search/repositories").respond(500, json={})
        resp = client.post(
            "/api/sentinel/scan",
            headers={"x-suzaku-csrf": CSRF},
            json={
                "language": "python",
                "min_stars": 100,
                "top": 5,
                "token": "fake-pat",
            },
        )
        assert resp.status_code == 502
