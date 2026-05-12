"""Chronicle Timeline — 90 日開示タイムライン管理。

Day 0 (初回連絡) を起点に Day 3 / 14 / 30 / 60 / 90 のマイルストーンを
組み立てる。ベンダの応答状況によりエスカレーション判定を行う。

SPEC.md §Chronicle:
- Day 0: 初回送信 (security@, SECURITY.md, GHSA PVR)
- Day 3-5: リマインド 1 回目
- Day 14: 別チャネル連絡
- Day 30: third reminder + 「90日後に公開予定」
- Day 60: CNA-LR エスカレーション検討
- Day 90: 公開可能
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from suzaku.models import Disclosure, VendorState


class Milestone(StrEnum):
    DAY_0 = "day_0"
    DAY_3 = "day_3"
    DAY_14 = "day_14"
    DAY_30 = "day_30"
    DAY_60 = "day_60"
    DAY_90 = "day_90"


MILESTONE_OFFSETS: dict[Milestone, int] = {
    Milestone.DAY_0: 0,
    Milestone.DAY_3: 3,
    Milestone.DAY_14: 14,
    Milestone.DAY_30: 30,
    Milestone.DAY_60: 60,
    Milestone.DAY_90: 90,
}


@dataclass(frozen=True)
class TimelineEntry:
    milestone: Milestone
    scheduled_at: datetime
    description: str


@dataclass
class Timeline:
    submission_id: str
    day_0: datetime
    entries: list[TimelineEntry] = field(default_factory=list)

    def at(self, milestone: Milestone) -> datetime:
        for e in self.entries:
            if e.milestone == milestone:
                return e.scheduled_at
        raise KeyError(milestone)


_MILESTONE_DESCRIPTIONS: dict[Milestone, str] = {
    Milestone.DAY_0: "Initial notification sent (security@/SECURITY.md/GHSA PVR)",
    Milestone.DAY_3: "First reminder if no acknowledgement yet",
    Milestone.DAY_14: "Second outreach via alternate channel",
    Milestone.DAY_30: "Third reminder; declare planned public disclosure date",
    Milestone.DAY_60: "Consider CNA-LR escalation (MITRE direct)",
    Milestone.DAY_90: "Public disclosure window opens",
}


def build_timeline(submission_id: str, day_0: datetime | None = None) -> Timeline:
    """Day 0 から Day 90 のマイルストーンを生成する。"""
    start = day_0 or datetime.now(UTC)
    if start.tzinfo is None:
        start = start.replace(tzinfo=UTC)
    entries = [
        TimelineEntry(
            milestone=m,
            scheduled_at=start + timedelta(days=offset),
            description=_MILESTONE_DESCRIPTIONS[m],
        )
        for m, offset in MILESTONE_OFFSETS.items()
    ]
    return Timeline(submission_id=submission_id, day_0=start, entries=entries)


def to_disclosure(timeline: Timeline) -> Disclosure:
    """Timeline を :class:`~suzaku.models.Disclosure` に変換する。"""
    return Disclosure(
        submission_id=timeline.submission_id,
        day_0=timeline.day_0,
        vendor_state=VendorState.NO_RESPONSE,
    )


def days_elapsed(timeline: Timeline, now: datetime | None = None) -> int:
    """Day 0 からの経過日数を返す (整数, 負値もあり得る)。"""
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    delta = current - timeline.day_0
    return int(delta.total_seconds() // 86400)


def current_milestone(timeline: Timeline, now: datetime | None = None) -> Milestone:
    """``now`` までに到達した最新マイルストーンを返す。

    Day 0 未満なら DAY_0 (これから送る予定)。
    """
    elapsed = days_elapsed(timeline, now)
    if elapsed < 3:
        return Milestone.DAY_0
    if elapsed < 14:
        return Milestone.DAY_3
    if elapsed < 30:
        return Milestone.DAY_14
    if elapsed < 60:
        return Milestone.DAY_30
    if elapsed < 90:
        return Milestone.DAY_60
    return Milestone.DAY_90
