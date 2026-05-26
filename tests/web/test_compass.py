"""``/api/compass/*`` エンドポイントのテスト。"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

CSRF = "test-csrf-token-fixed"
VULN_REPO = Path(__file__).resolve().parents[1] / "fixtures" / "vulnerable_repo"


class TestRules:
    def test_rules_listing_contains_built_ins(self, client: TestClient) -> None:
        resp = client.get("/api/compass/rules")
        assert resp.status_code == 200
        body = resp.json()
        ids = [r["id"] for r in body]
        assert "danger_funcs_python" in ids
        # languages フィールドが list[str]
        py = next(r for r in body if r["id"] == "danger_funcs_python")
        assert "python" in py["languages"]
        assert py["cwe"]


class TestScan:
    def test_scan_with_single_rule(self, client: TestClient) -> None:
        resp = client.post(
            "/api/compass/scan",
            headers={"x-suzaku-csrf": CSRF},
            json={
                "repo_path": str(VULN_REPO),
                "rule_ids": ["danger_funcs_python"],
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["rules_run"] == ["danger_funcs_python"]
        # vulnerable_repo は意図的に脆弱コードを含む
        assert len(body["findings"]) > 0

    def test_scan_unknown_rule_yields_400(self, client: TestClient) -> None:
        resp = client.post(
            "/api/compass/scan",
            headers={"x-suzaku-csrf": CSRF},
            json={
                "repo_path": str(VULN_REPO),
                "rule_ids": ["does_not_exist"],
            },
        )
        assert resp.status_code == 400

    def test_scan_nonexistent_repo_yields_400(self, client: TestClient) -> None:
        resp = client.post(
            "/api/compass/scan",
            headers={"x-suzaku-csrf": CSRF},
            json={
                "repo_path": "/tmp/this/path/should/not/exist/xyzzy",
                "rule_ids": [],
            },
        )
        assert resp.status_code == 400
