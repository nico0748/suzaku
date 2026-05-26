"""``GET /api/health`` のテスト。"""

from __future__ import annotations

from fastapi.testclient import TestClient


class TestHealth:
    def test_returns_200_with_version(self, client: TestClient) -> None:
        resp = client.get("/api/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == "suzaku-web"
        assert body["version"]  # 何かしらのバージョン文字列
        assert body["mode"] == "ro"

    def test_csrf_token_is_present(self, client: TestClient) -> None:
        body = client.get("/api/health").json()
        assert body["csrf_token"] == "test-csrf-token-fixed"

    def test_safe_method_does_not_require_csrf_or_origin(self, client: TestClient) -> None:
        # Origin ヘッダなし + CSRF ヘッダなしでも GET は通る
        resp = client.get("/api/health")
        assert resp.status_code == 200
