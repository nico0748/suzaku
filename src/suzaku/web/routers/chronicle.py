"""``/api/chronicle/*`` — 90 日タイムライン状態の参照 (read-only)。"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from suzaku.chronicle.escalation import evaluate_alert
from suzaku.chronicle.timeline import (
    build_timeline,
    current_milestone,
    days_elapsed,
)
from suzaku.models import VendorState

router = APIRouter(prefix="/api/chronicle", tags=["chronicle"])

DEFAULT_STATE_DIR = Path("./.suzaku/chronicle")


class ChronicleSummary(BaseModel):
    submission_id: str
    day_0: str
    vendor_state: str
    published_at: str | None = None


class ChronicleStatus(BaseModel):
    submission_id: str
    day_0: str
    days_elapsed: int
    current_milestone: str
    vendor_state: str
    alert_level: str
    action: str


def _resolve_state_dir(raw: str | None) -> Path:
    return Path(raw) if raw else DEFAULT_STATE_DIR


@router.get("/list", response_model=list[ChronicleSummary])
def get_list(
    state_dir: str | None = Query(default=None, description="state ディレクトリ。未指定なら ./.suzaku/chronicle"),
) -> list[ChronicleSummary]:
    """state_dir 内の全 disclosure 一覧 (`chronicle list` 相当)。"""
    sd = _resolve_state_dir(state_dir)
    if not sd.exists():
        return []
    out: list[ChronicleSummary] = []
    for f in sorted(sd.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        out.append(
            ChronicleSummary(
                submission_id=data.get("submission_id", f.stem),
                day_0=data.get("day_0", ""),
                vendor_state=data.get("vendor_state", VendorState.NO_RESPONSE.value),
                published_at=data.get("published_at"),
            )
        )
    return out


@router.get("/{submission_id}/status", response_model=ChronicleStatus)
def get_status(
    submission_id: str,
    state_dir: str | None = Query(default=None),
) -> ChronicleStatus:
    """単一 disclosure の Day 経過 + 推奨アクション (`chronicle status` 相当)。"""
    sd = _resolve_state_dir(state_dir)
    f = sd / f"{submission_id}.json"
    if not f.exists():
        raise HTTPException(status_code=404, detail=f"state not found: {submission_id}")

    data = json.loads(f.read_text(encoding="utf-8"))
    day_0 = datetime.fromisoformat(data["day_0"])
    tl = build_timeline(submission_id, day_0=day_0)
    vendor_state = VendorState(data.get("vendor_state", VendorState.NO_RESPONSE.value))
    now = datetime.now(UTC)

    return ChronicleStatus(
        submission_id=submission_id,
        day_0=day_0.isoformat(),
        days_elapsed=days_elapsed(tl, now=now),
        current_milestone=current_milestone(tl, now=now).value,
        vendor_state=vendor_state.value,
        alert_level=evaluate_alert(tl, vendor_state=vendor_state, now=now).level.value,
        action=evaluate_alert(tl, vendor_state=vendor_state, now=now).template,
    )


__all__ = ["router"]
