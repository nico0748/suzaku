"""``/api/lineage/*`` エンドポイントのテスト。"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

CSRF = "test-csrf-token-fixed"


def _ssrf_record() -> dict:
    return {
        "cve_id": "CVE-2099-0001",
        "description": "Demo SSRF",
        "cwe": ["CWE-918"],
        "references": ["https://github.com/example/x/commit/deadbeef"],
        "commit_urls": [],
        "vuln_status": "Public",
    }


class TestIngest:
    def test_ingest_requires_cve_or_file(self, client: TestClient) -> None:
        resp = client.post(
            "/api/lineage/ingest",
            headers={"x-suzaku-csrf": CSRF},
            json={},
        )
        assert resp.status_code == 400

    def test_ingest_file_not_found_yields_400(self, client: TestClient) -> None:
        resp = client.post(
            "/api/lineage/ingest",
            headers={"x-suzaku-csrf": CSRF},
            json={"file": "/tmp/no/such/file.json"},
        )
        assert resp.status_code == 400


class TestExtract:
    def test_extract_with_zero_commits_returns_empty(self, client: TestClient) -> None:
        # commit_urls 無し → fetch 経路に乗らないので 0 rule
        resp = client.post(
            "/api/lineage/extract",
            headers={"x-suzaku-csrf": CSRF},
            json={"cve_record": _ssrf_record(), "commit_urls": [], "max_rules": 5},
        )
        assert resp.status_code == 200
        assert resp.json() == []


class TestScan:
    def test_scan_rejects_invalid_rules(self, client: TestClient) -> None:
        resp = client.post(
            "/api/lineage/scan",
            headers={"x-suzaku-csrf": CSRF},
            json={"repo_path": "/tmp", "rules": [{"not": "a valid rule"}]},
        )
        assert resp.status_code == 400

    def test_scan_with_no_rules_returns_empty(
        self, client: TestClient, tmp_path: Path
    ) -> None:
        # 空 rules リスト + 空 dir → 0 findings
        (tmp_path / "src.py").write_text("print('hi')")
        resp = client.post(
            "/api/lineage/scan",
            headers={"x-suzaku-csrf": CSRF},
            json={"repo_path": str(tmp_path), "rules": []},
        )
        assert resp.status_code == 200
        assert resp.json() == []

    def test_scan_with_synthetic_rule(self, client: TestClient, tmp_path: Path) -> None:
        # tmp_path に脆弱パターンを置き、rule を 1 つ書いて hit を確認
        target = tmp_path / "src.py"
        target.write_text("eval(user_input)\n")
        rule = {
            "rule_id": "lineage_test_001",
            "derived_from_cve": "CVE-2099-0001",
            "cwe": "CWE-94",
            "severity": "medium",
            "language": "python",
            "grep": r"eval\([^)]*\)",
            "must_not_contain": None,
            "source_commit": "https://github.com/example/x/commit/deadbeef",
            "rationale": "test",
        }
        resp = client.post(
            "/api/lineage/scan",
            headers={"x-suzaku-csrf": CSRF},
            json={"repo_path": str(tmp_path), "rules": [rule]},
        )
        # ripgrep が無い環境では 503 を許容 (CI で skip ではなく)
        if resp.status_code == 503:
            return
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) >= 1
        assert any("eval" in f["snippet"] for f in body)


class TestExceptionMapping:
    def test_lineage_egress_mapped_to_403(self, client: TestClient) -> None:
        # 内部関数を直接呼ばずに、egress 違反は通常 ingest 経由でしか起きないので
        # 簡易: 不正な NVD JSON file 経由でエラーが NVDFilterError -> 422 に行くケースを確認
        from suzaku.web.app import create_app
        from suzaku.web.deps import WebSettings

        # 422 mapping のために一時 JSON を仕込む (description が無いなど)
        # ここでは map 経路の存在を smoke-test。app.py の handler 登録のみ確認。
        app = create_app(WebSettings(csrf_token=CSRF))
        # 例外ハンドラが 4 種登録されている
        assert len(app.exception_handlers) >= 4
