"""Chronicle timeline のテスト。"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from suzaku.chronicle.timeline import (
    Milestone,
    build_timeline,
    current_milestone,
    days_elapsed,
    to_disclosure,
)
from suzaku.models import VendorState


def _t(year: int, month: int, day: int) -> datetime:
    return datetime(year, month, day, tzinfo=UTC)


class TestBuildTimeline:
    def test_generates_all_six_milestones(self) -> None:
        tl = build_timeline("S-001", day_0=_t(2026, 5, 12))
        kinds = {e.milestone for e in tl.entries}
        assert kinds == set(Milestone)

    def test_offsets_are_correct(self) -> None:
        start = _t(2026, 5, 12)
        tl = build_timeline("S-001", day_0=start)
        assert tl.at(Milestone.DAY_0) == start
        assert tl.at(Milestone.DAY_3) == start + timedelta(days=3)
        assert tl.at(Milestone.DAY_14) == start + timedelta(days=14)
        assert tl.at(Milestone.DAY_30) == start + timedelta(days=30)
        assert tl.at(Milestone.DAY_60) == start + timedelta(days=60)
        assert tl.at(Milestone.DAY_90) == start + timedelta(days=90)

    def test_naive_day_0_normalized_to_utc(self) -> None:
        naive = datetime(2026, 5, 12)
        tl = build_timeline("S-002", day_0=naive)
        assert tl.day_0.tzinfo is not None


class TestDaysElapsed:
    def test_zero_at_day_0(self) -> None:
        start = _t(2026, 5, 12)
        tl = build_timeline("S-001", day_0=start)
        assert days_elapsed(tl, now=start) == 0

    def test_negative_before_day_0(self) -> None:
        start = _t(2026, 5, 12)
        tl = build_timeline("S-001", day_0=start)
        assert days_elapsed(tl, now=start - timedelta(days=2)) < 0

    def test_exact_milestone(self) -> None:
        start = _t(2026, 5, 12)
        tl = build_timeline("S-001", day_0=start)
        assert days_elapsed(tl, now=start + timedelta(days=30)) == 30


class TestCurrentMilestone:
    def test_buckets(self) -> None:
        start = _t(2026, 5, 12)
        tl = build_timeline("S-001", day_0=start)
        cases = {
            0: Milestone.DAY_0,
            2: Milestone.DAY_0,
            3: Milestone.DAY_3,
            13: Milestone.DAY_3,
            14: Milestone.DAY_14,
            29: Milestone.DAY_14,
            30: Milestone.DAY_30,
            59: Milestone.DAY_30,
            60: Milestone.DAY_60,
            89: Milestone.DAY_60,
            90: Milestone.DAY_90,
            120: Milestone.DAY_90,
        }
        for offset, expected in cases.items():
            got = current_milestone(tl, now=start + timedelta(days=offset))
            assert got == expected, f"offset {offset}: got {got}, expected {expected}"


class TestDisclosureBridge:
    def test_to_disclosure_default_state(self) -> None:
        tl = build_timeline("S-001", day_0=_t(2026, 5, 12))
        d = to_disclosure(tl)
        assert d.submission_id == "S-001"
        assert d.day_0 == tl.day_0
        assert d.vendor_state == VendorState.NO_RESPONSE
