"""Origin / CSRF middleware のテスト。"""

from __future__ import annotations

from fastapi.testclient import TestClient

CSRF = "test-csrf-token-fixed"


class TestOriginCheck:
    def test_post_without_origin_is_allowed(self, client: TestClient) -> None:
        # Origin ヘッダ未付与は許可 (curl 等の non-browser を想定)
        resp = client.post(
            "/api/sentinel/scan",
            headers={"x-suzaku-csrf": CSRF},
            json={"language": "python", "min_stars": 1000, "top": 1},
        )
        # 502 (GitHub Search を実際に叩いて失敗) は許容、403 (origin) は NG
        assert resp.status_code != 403 or resp.json().get("error") != "origin_blocked"

    def test_post_with_localhost_origin_passes(self, client: TestClient) -> None:
        resp = client.post(
            "/api/sentinel/scan",
            headers={"origin": "http://localhost:5173", "x-suzaku-csrf": CSRF},
            json={"language": "python", "min_stars": 1000, "top": 1},
        )
        assert resp.status_code != 403 or resp.json().get("error") != "origin_blocked"

    def test_post_with_127_origin_passes(self, client: TestClient) -> None:
        resp = client.post(
            "/api/sentinel/scan",
            headers={"origin": "http://127.0.0.1:8765", "x-suzaku-csrf": CSRF},
            json={"language": "python", "min_stars": 1000, "top": 1},
        )
        assert resp.status_code != 403 or resp.json().get("error") != "origin_blocked"

    def test_post_with_evil_origin_is_blocked(self, client: TestClient) -> None:
        resp = client.post(
            "/api/sentinel/scan",
            headers={"origin": "https://evil.test", "x-suzaku-csrf": CSRF},
            json={"language": "python", "min_stars": 1000, "top": 1},
        )
        assert resp.status_code == 403
        assert resp.json()["error"] == "origin_blocked"


class TestCSRF:
    def test_post_without_csrf_is_blocked(self, client: TestClient) -> None:
        resp = client.post(
            "/api/sentinel/scan",
            json={"language": "python", "min_stars": 1000, "top": 1},
        )
        assert resp.status_code == 403
        assert resp.json()["error"] == "csrf_missing_or_invalid"

    def test_post_with_wrong_csrf_is_blocked(self, client: TestClient) -> None:
        resp = client.post(
            "/api/sentinel/scan",
            headers={"x-suzaku-csrf": "WRONG"},
            json={"language": "python", "min_stars": 1000, "top": 1},
        )
        assert resp.status_code == 403
        assert resp.json()["error"] == "csrf_missing_or_invalid"

    def test_health_does_not_require_csrf(self, client: TestClient) -> None:
        # GET /api/health は safe method なので素通り
        assert client.get("/api/health").status_code == 200
