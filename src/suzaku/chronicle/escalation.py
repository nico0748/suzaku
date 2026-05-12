"""Chronicle Escalation — エスカレーション判定 + ACCS ガード。

SPEC.md §Chronicle:
- Day 3 + 無応答 -> リマインド送信用テンプレ
- Day 14 + 無応答 -> 別チャネル提案 (GitHub Issue / distros@)
- Day 30 + 無応答 -> 公開予定明記の文面
- Day 60 + 無応答 -> CNA-LR ルート推奨
- Day 90 達成 -> 公開可能ステータス

ACCS事件ガード:
- Day 0 経過前に「公開」アクションを取ろうとすると拒否
- chronicle publish 実行時は修正リリース後 +30 日経過を必須化
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from suzaku.chronicle.timeline import Timeline, days_elapsed
from suzaku.models import VendorState


class AlertLevel(StrEnum):
    NONE = "none"
    REMINDER = "reminder"
    ALT_CHANNEL = "alt_channel"
    PUBLIC_NOTICE = "public_notice"
    CNA_LR = "cna_lr"
    READY_TO_PUBLISH = "ready_to_publish"


@dataclass(frozen=True)
class Alert:
    level: AlertLevel
    days_elapsed: int
    title: str
    template: str


class ACCSViolationError(RuntimeError):
    """ACCS事件 3 手順 (通知 → 修正期間 → 公表) からの逸脱を検知。

    Suzaku は通知前公開 / 修正後 30 日未満の公表 を機械的に拒否する。
    """


def evaluate_alert(
    timeline: Timeline,
    vendor_state: VendorState = VendorState.NO_RESPONSE,
    now: datetime | None = None,
) -> Alert:
    """現在の経過日数 + ベンダ応答状態から取るべきアクションを返す。"""
    elapsed = days_elapsed(timeline, now)

    if vendor_state == VendorState.FIXED:
        # ベンダ修正済みなら、Day 90 を待たずに公開準備に進める扱い
        return Alert(
            level=AlertLevel.READY_TO_PUBLISH,
            days_elapsed=elapsed,
            title="Vendor reported fix",
            template=(
                "Vendor has marked the issue as fixed. Confirm release, "
                "then schedule public disclosure for +30 days after the "
                "fix release."
            ),
        )

    if elapsed >= 90:
        return Alert(
            level=AlertLevel.READY_TO_PUBLISH,
            days_elapsed=elapsed,
            title="Day 90 reached",
            template=(
                "90-day disclosure window has elapsed without a vendor fix. "
                "Suzaku permits public disclosure from now on, with notice."
            ),
        )

    if vendor_state != VendorState.NO_RESPONSE:
        # 応答はあるが未修正: マイルストーンに沿ったソフトな進捗管理に留める
        return Alert(
            level=AlertLevel.NONE,
            days_elapsed=elapsed,
            title="Vendor engaged",
            template=(
                f"Vendor has acknowledged ({vendor_state.value}); continue "
                "coordinated track."
            ),
        )

    if elapsed >= 60:
        return Alert(
            level=AlertLevel.CNA_LR,
            days_elapsed=elapsed,
            title="Day 60+ — escalate to CNA-LR",
            template=(
                "No vendor response for 60+ days. Consider escalating "
                "to MITRE CNA-LR for a CVE assignment, then proceed "
                "with public disclosure preparation."
            ),
        )

    if elapsed >= 30:
        return Alert(
            level=AlertLevel.PUBLIC_NOTICE,
            days_elapsed=elapsed,
            title="Day 30+ — declare public disclosure date",
            template=(
                "Send a third notice that explicitly states a planned "
                "public disclosure at Day 90. Provide a draft advisory."
            ),
        )

    if elapsed >= 14:
        return Alert(
            level=AlertLevel.ALT_CHANNEL,
            days_elapsed=elapsed,
            title="Day 14+ — try alternate channel",
            template=(
                "Vendor has not responded for 14+ days. Reach out via "
                "GitHub Issue, distros@vs.openwall.org, or Twitter DM."
            ),
        )

    if elapsed >= 3:
        return Alert(
            level=AlertLevel.REMINDER,
            days_elapsed=elapsed,
            title="Day 3+ — send first reminder",
            template=(
                "Send a polite reminder asking whether the initial report "
                "was received. Offer to re-send via an alternate channel."
            ),
        )

    return Alert(
        level=AlertLevel.NONE,
        days_elapsed=elapsed,
        title="Within initial response window",
        template="Wait for vendor's initial acknowledgement (Day 0-2).",
    )


def check_publication_allowed(
    timeline: Timeline,
    vendor_state: VendorState = VendorState.NO_RESPONSE,
    fixed_released_at: datetime | None = None,
    fix_grace_days: int = 30,
    now: datetime | None = None,
) -> None:
    """公開アクションが許可されるかをチェックする。

    Raises:
        ACCSViolationError: 通知前 / 90 日未満かつベンダ応答無し ですらない /
            修正リリース後 fix_grace_days 経過していない場合。
    """
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)

    if current < timeline.day_0:
        raise ACCSViolationError(
            "Cannot publish before Day 0 (initial vendor notification). "
            "ACCS 3-step rule: notify → fix window → publicize."
        )

    elapsed = days_elapsed(timeline, current)

    # 公開の条件: (a) 修正がリリースされてから fix_grace_days 経過, または
    # (b) Day 90 経過 + 無応答, または (c) ベンダが reject/fixed
    if fixed_released_at is not None:
        if fixed_released_at.tzinfo is None:
            fixed_released_at = fixed_released_at.replace(tzinfo=UTC)
        if current < fixed_released_at + timedelta(days=fix_grace_days):
            raise ACCSViolationError(
                f"Fix released at {fixed_released_at.isoformat()} — publication "
                f"is allowed only after +{fix_grace_days} days."
            )
        return

    # 修正未リリース: Day 90 達成が必要
    if elapsed < 90 and vendor_state != VendorState.REJECTED:
        raise ACCSViolationError(
            f"Day {elapsed} of disclosure window — cannot publish before "
            "Day 90 unless the vendor has explicitly rejected the report "
            "or released a fix (+30d)."
        )
