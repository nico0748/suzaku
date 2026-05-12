"""脆弱性報告メールの本文生成。

ISO/IEC 29147 / CVD ベストプラクティスに沿った穏当な文面のみを生成する。
脅迫的表現 (報酬要求・最後通牒など) はテンプレート定数で禁止する。
レンダリング結果に禁止語が含まれていれば :class:`ExtortionLanguageError` を投げる。
"""

from __future__ import annotations

from suzaku.herald.checklist import ChecklistError
from suzaku.herald.ghsa import EMAIL_TEMPLATE, Advisory, _build_context, _env

# 報告メールに含めてはならないフレーズ (extortion / threat)。
# 大文字小文字を無視してマッチする。
FORBIDDEN_PHRASES: tuple[str, ...] = (
    "pay first",
    "payment required",
    "bounty payment",
    "wire transfer",
    "ransom",
    "if you do not pay",
    "or else",
    "last warning",
    "24 hours to respond",
    "final warning",
    "or i will release",
    "release details unless",
)


class ExtortionLanguageError(ValueError):
    """生成文面に脅迫表現が混入した場合に発生。"""


def render_email(advisory: Advisory) -> str:
    """vendor 向け coordinated disclosure メールを生成する。

    Args:
        advisory: 5 点セットを満たし、reporter_contact 等を埋めた Advisory

    Raises:
        ChecklistError: 必須フィールドが欠ける場合
        ExtortionLanguageError: 生成文面に禁止語が含まれていた場合
    """
    if not advisory.reporter_contact.strip():
        raise ChecklistError("advisory.reporter_contact is required for email")
    if advisory.disclosure_window_days <= 0:
        raise ChecklistError("advisory.disclosure_window_days must be positive")

    context = _build_context(advisory)
    body = _env().get_template(EMAIL_TEMPLATE).render(**context)

    lowered = body.lower()
    for phrase in FORBIDDEN_PHRASES:
        if phrase in lowered:
            raise ExtortionLanguageError(
                f"Generated email contains forbidden phrase: {phrase!r}. "
                "Suzaku refuses to send extortion-style disclosure messages."
            )
    return body
