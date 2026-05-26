"""``/api/chronicle/*`` エンドポイントのテスト。"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from suzaku.chronicle.timeline import build_timeline


def _write_state(state_dir: Path, submission_id: str, *, day_0_offset_days: int = 0) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    day_0 = datetime.now(UTC) + timedelta(days=day_0_offset_days)
    tl = build_timeline(submission_id, day_0=day_0)
    payload = {
        "submission_id": submission_id,
        "day_0": day_0.isoformat(),
        "vendor_state": "no_response",
        "milestones": {e.milestone.value: e.scheduled_at.isoformat() for e in tl.entries},
    }
    (state_dir / f"{submission_id}.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )


class TestList:
    def test_empty_state_dir_returns_empty(
        self, client: TestClient, tmp_path: Path
    ) -> None:
        resp = client.get(
            f"/api/chronicle/list?state_dir={tmp_path}"
        )
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_returns_summaries(self, client: TestClient, tmp_path: Path) -> None:
        _write_state(tmp_path, "S-100")
        _write_state(tmp_path, "S-101")
        resp = client.get(f"/api/chronicle/list?state_dir={tmp_path}")
        assert resp.status_code == 200
        body = resp.json()
        ids = sorted(b["submission_id"] for b in body)
        assert ids == ["S-100", "S-101"]


class TestStatus:
    def test_unknown_submission_404(self, client: TestClient, tmp_path: Path) -> None:
        resp = client.get(
            f"/api/chronicle/UNKNOWN/status?state_dir={tmp_path}"
        )
        assert resp.status_code == 404

    def test_status_returns_day_fields(self, client: TestClient, tmp_path: Path) -> None:
        _write_state(tmp_path, "S-200", day_0_offset_days=-5)
        resp = client.get(f"/api/chronicle/S-200/status?state_dir={tmp_path}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["submission_id"] == "S-200"
        assert body["days_elapsed"] == 5
        assert body["vendor_state"] == "no_response"
        assert body["current_milestone"]
        assert body["alert_level"]
