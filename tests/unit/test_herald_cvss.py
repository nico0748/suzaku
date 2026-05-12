"""Herald CVSS v3.1 計算機のテスト。

参照: https://www.first.org/cvss/v3.1/specification-document
全ベクタは FIRST.org 公式計算機で事前検証済み。
"""

from __future__ import annotations

import pytest

from suzaku.herald.cvss import (
    CVSSError,
    parse_vector,
    score_severity,
    score_vector,
)


class TestKnownVectors:
    """公式計算機との一致を主要パターンで検証。"""

    @pytest.mark.parametrize(
        "vector,expected_score,expected_severity",
        [
            # 典型的な未認証 RCE
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
            # Scope Changed RCE -> ceiling 10.0
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Critical"),
            # XSS 系 (UI:R)
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8, "High"),
            # ローカル権限昇格 (低権限必要)
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "High"),
            # 低権限が必要、影響中程度
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 5.4, "Medium"),
            # ネットワーク DoS
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "High"),
            # 高条件 + ユーザ操作必要 (Low)
            ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N", 3.1, "Low"),
            # 機密情報漏洩のみ
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "High"),
            # Scope Changed Integrity 損失
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N", 8.6, "High"),
            # I+A 完全損失 (no C)
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", 9.1, "Critical"),
            # 影響なし
            ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0, "None"),
        ],
    )
    def test_official_vectors(
        self, vector: str, expected_score: float, expected_severity: str
    ) -> None:
        score = score_vector(vector)
        assert score == pytest.approx(expected_score, abs=0.05)
        assert score_severity(score) == expected_severity


class TestParseVector:
    def test_returns_dict(self) -> None:
        m = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert m["AV"] == "N"
        assert m["S"] == "U"

    def test_missing_metric_raises(self) -> None:
        with pytest.raises(CVSSError):
            parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")

    def test_invalid_prefix_raises(self) -> None:
        with pytest.raises(CVSSError):
            parse_vector("CVSS:2.0/AV:N/AC:L")

    def test_invalid_metric_value_raises(self) -> None:
        with pytest.raises(CVSSError):
            parse_vector("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_extra_unknown_metric_raises(self) -> None:
        with pytest.raises(CVSSError):
            parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/XX:Y")


class TestSeverityBoundaries:
    @pytest.mark.parametrize(
        "score,label",
        [
            (0.0, "None"),
            (0.1, "Low"),
            (3.9, "Low"),
            (4.0, "Medium"),
            (6.9, "Medium"),
            (7.0, "High"),
            (8.9, "High"),
            (9.0, "Critical"),
            (10.0, "Critical"),
        ],
    )
    def test_thresholds(self, score: float, label: str) -> None:
        assert score_severity(score) == label
