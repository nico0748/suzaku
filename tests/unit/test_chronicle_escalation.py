"""Chronicle escalation + ACCS ガードのテスト。"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from suzaku.chronicle.escalation import (
    ACCSViolationError,
    AlertLevel,
    check_publication_allowed,
    evaluate_alert,
)
from suzaku.chronicle.timeline import build_timeline
from suzaku.models import VendorState


def _t(year: int, month: int, day: int) -> datetime:
    return datetime(year, month, day, tzinfo=UTC)


class TestEvaluateAlert:
    @pytest.mark.parametrize(
        "offset_days,expected_level",
        [
            (0, AlertLevel.NONE),
            (2, AlertLevel.NONE),
            (3, AlertLevel.REMINDER),
            (13, AlertLevel.REMINDER),
            (14, AlertLevel.ALT_CHANNEL),
            (29, AlertLevel.ALT_CHANNEL),
            (30, AlertLevel.PUBLIC_NOTICE),
            (59, AlertLevel.PUBLIC_NOTICE),
            (60, AlertLevel.CNA_LR),
            (89, AlertLevel.CNA_LR),
            (90, AlertLevel.READY_TO_PUBLISH),
            (120, AlertLevel.READY_TO_PUBLISH),
        ],
    )
    def test_no_response_thresholds(
        self, offset_days: int, expected_level: AlertLevel
    ) -> None:
        start = _t(2026, 5, 12)
        tl = build_timeline("S-001", day_0=start)
        alert = evaluate_alert(
            tl,
            vendor_state=VendorState.NO_RESPONSE,
            now=start + timedelta(days=offset_days),
        )
        assert alert.level == expected_level

    def test_vendor_acknowledged_keeps_quiet(self) -> None:
        start = _t(2026, 5, 12)
        tl = build_timeline("S-001", day_0=start)
        alert = evaluate_alert(
            tl,
            vendor_state=VendorState.ACKNOWLEDGED,
            now=start + timedelta(days=30),
        )
        assert alert.level == AlertLevel.NONE
        assert "acknowledged" in alert.template.lower()

    def test_vendor_fixed_jumps_to_ready(self) -> None:
        start = _t(2026, 5, 12)
        tl = build_timeline("S-001", day_0=start)
        alert = evaluate_alert(
            tl,
            vendor_state=VendorState.FIXED,
            now=start + timedelta(days=10),
        )
        assert alert.level == AlertLevel.READY_TO_PUBLISH


class TestACCSGuard:
    def test_pre_day0_publication_rejected(self) -> None:
        start = _t(2026, 5, 12)
        tl = build_timeline("S-001", day_0=start)
        with pytest.raises(ACCSViolationError) as exc:
            check_publication_allowed(tl, now=start - timedelta(days=1))
        assert "before day 0" in str(exc.value).lower()

    def test_day_30_publication_rejected_when_no_response(self) -> None:
        start = _t(2026, 5, 12)
        tl = build_timeline("S-001", day_0=start)
        with pytest.raises(ACCSViolationError):
            check_publication_allowed(tl, now=start + timedelta(days=30))

    def test_day_90_publication_allowed(self) -> None:
        start = _t(2026, 5, 12)
        tl = build_timeline("S-001", day_0=start)
        check_publication_allowed(tl, now=start + timedelta(days=91))

    def test_vendor_rejected_allows_early_publication(self) -> None:
        start = _t(2026, 5, 12)
        tl = build_timeline("S-001", day_0=start)
        check_publication_allowed(
            tl,
            vendor_state=VendorState.REJECTED,
            now=start + timedelta(days=20),
        )

    def test_fix_release_within_30_days_rejected(self) -> None:
        start = _t(2026, 5, 12)
        tl = build_timeline("S-001", day_0=start)
        fix = start + timedelta(days=40)
        with pytest.raises(ACCSViolationError) as exc:
            check_publication_allowed(
                tl,
                fixed_released_at=fix,
                now=fix + timedelta(days=10),
            )
        assert "+30 days" in str(exc.value)

    def test_fix_release_plus_30_days_allowed(self) -> None:
        start = _t(2026, 5, 12)
        tl = build_timeline("S-001", day_0=start)
        fix = start + timedelta(days=40)
        check_publication_allowed(
            tl,
            fixed_released_at=fix,
            now=fix + timedelta(days=31),
        )

    def test_custom_fix_grace_days(self) -> None:
        start = _t(2026, 5, 12)
        tl = build_timeline("S-001", day_0=start)
        fix = start + timedelta(days=10)
        # grace=7 を指定すれば +7 経過で公開可能
        check_publication_allowed(
            tl,
            fixed_released_at=fix,
            fix_grace_days=7,
            now=fix + timedelta(days=8),
        )
