"""CVSS v3.1 Base Score 計算機。

公式: https://www.first.org/cvss/v3.1/specification-document

ベクタ例: ``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``

定数表 (Specification §7):

- AV (Attack Vector):    N=0.85, A=0.62, L=0.55, P=0.20
- AC (Attack Complexity): L=0.77, H=0.44
- PR (Privileges Required) — Scope Unchanged / Changed で値が変わる:
  - Unchanged: N=0.85, L=0.62, H=0.27
  - Changed:   N=0.85, L=0.68, H=0.50
- UI (User Interaction): N=0.85, R=0.62
- S (Scope):  U / C
- C/I/A (Conf/Integ/Avail): H=0.56, L=0.22, N=0.00
"""

from __future__ import annotations

PREFIX = "CVSS:3.1"

METRIC_ORDER: tuple[str, ...] = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
ALLOWED_METRIC_VALUES: dict[str, frozenset[str]] = {
    "AV": frozenset({"N", "A", "L", "P"}),
    "AC": frozenset({"L", "H"}),
    "PR": frozenset({"N", "L", "H"}),
    "UI": frozenset({"N", "R"}),
    "S": frozenset({"U", "C"}),
    "C": frozenset({"H", "L", "N"}),
    "I": frozenset({"H", "L", "N"}),
    "A": frozenset({"H", "L", "N"}),
}

AV_VALUES: dict[str, float] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_VALUES: dict[str, float] = {"L": 0.77, "H": 0.44}
PR_VALUES_UNCHANGED: dict[str, float] = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_VALUES_CHANGED: dict[str, float] = {"N": 0.85, "L": 0.68, "H": 0.50}
UI_VALUES: dict[str, float] = {"N": 0.85, "R": 0.62}
CIA_VALUES: dict[str, float] = {"H": 0.56, "L": 0.22, "N": 0.00}


class CVSSError(ValueError):
    """ベクタの形式が不正な場合に発生する。"""


def parse_vector(vector: str) -> dict[str, str]:
    """``CVSS:3.1/AV:N/...`` をメトリクス辞書に分解する。

    必須メトリクスが揃わない / 未知の値 / 余分なメトリクスは ``CVSSError``。
    """
    parts = vector.split("/")
    if not parts or parts[0] != PREFIX:
        raise CVSSError(f"Vector must start with '{PREFIX}', got: {vector!r}")

    metrics: dict[str, str] = {}
    for entry in parts[1:]:
        if ":" not in entry:
            raise CVSSError(f"Malformed metric entry: {entry!r}")
        key, value = entry.split(":", 1)
        if key not in ALLOWED_METRIC_VALUES:
            raise CVSSError(f"Unknown metric: {key!r}")
        if value not in ALLOWED_METRIC_VALUES[key]:
            raise CVSSError(f"Invalid value for {key}: {value!r}")
        if key in metrics:
            raise CVSSError(f"Duplicate metric: {key!r}")
        metrics[key] = value

    missing = [m for m in METRIC_ORDER if m not in metrics]
    if missing:
        raise CVSSError(f"Missing required metrics: {missing}")

    return metrics


def _roundup(x: float) -> float:
    """CVSS v3.1 Roundup: 0.1 単位で切り上げ。浮動小数誤差を避ける整数演算版。"""
    n = round(x * 100000)
    if n % 10000 == 0:
        return n / 100000
    return (n // 10000 + 1) / 10


def score_vector(vector: str) -> float:
    """ベクタから Base Score を計算する。"""
    m = parse_vector(vector)

    av = AV_VALUES[m["AV"]]
    ac = AC_VALUES[m["AC"]]
    ui = UI_VALUES[m["UI"]]
    pr = PR_VALUES_CHANGED[m["PR"]] if m["S"] == "C" else PR_VALUES_UNCHANGED[m["PR"]]
    c = CIA_VALUES[m["C"]]
    i = CIA_VALUES[m["I"]]
    a = CIA_VALUES[m["A"]]

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = (
        7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        if m["S"] == "C"
        else 6.42 * iss
    )
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    raw = (impact + exploitability) if m["S"] == "U" else 1.08 * (impact + exploitability)
    return _roundup(min(raw, 10.0))


def score_severity(score: float) -> str:
    """CVSS v3.1 §5: スコアから定性ラベルへ。"""
    if score <= 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"
