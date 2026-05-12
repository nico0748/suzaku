"""Sentinel — 8 シグナル評価ロジック。

入力は :class:`RepoSignals` (search.py で GitHub API から組み立てる)。
出力は ``{signal_name: 0.0-1.0}`` の dict と、weights をかけた最終スコア
(0.0-10.0) のタプル。

8 シグナル (SPEC.md §Sentinel):
1. maintenance_inactivity    — 直近 Issue 応答日数 > 30 日 で高
2. thin_auth_layer            — routes 数に対する認証 middleware 比率の薄さ
3. recent_complex_features    — 直近30日に importer/uploader/SSO 系コミット
4. fresh_release              — 直近7日内のリリース
5. multi_tier                 — docker-compose のサービス数
6. many_deps                  — 依存ライブラリ数 (50 超で 1.0)
7. roll_your_own              — 自前 crypto/parser/tokenizer の存在比率
8. monetary                   — payment / subscription / coupon キーワード
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_SIGNALS_PATH = Path(__file__).parent / "signals.yaml"

SIGNAL_NAMES: tuple[str, ...] = (
    "maintenance_inactivity",
    "thin_auth_layer",
    "recent_complex_features",
    "fresh_release",
    "multi_tier",
    "many_deps",
    "roll_your_own",
    "monetary",
)


class ScoringError(ValueError):
    """signals.yaml の形式が不正な場合に発生。"""


@dataclass
class ScoringConfig:
    """weights / keywords / thresholds の正規化済み設定。"""

    weights: dict[str, float]
    keywords: dict[str, list[str]]
    thresholds: dict[str, float]

    @classmethod
    def load(cls, path: Path | None = None) -> ScoringConfig:
        target = path or DEFAULT_SIGNALS_PATH
        with target.open("r", encoding="utf-8") as f:
            data: Any = yaml.safe_load(f)
        if not isinstance(data, dict):
            raise ScoringError(f"signals.yaml must be a mapping at top level: {target}")
        for required in ("weights", "keywords", "thresholds"):
            if required not in data:
                raise ScoringError(f"signals.yaml missing '{required}' section")

        weights = {str(k): float(v) for k, v in data["weights"].items()}
        missing = set(SIGNAL_NAMES) - weights.keys()
        if missing:
            raise ScoringError(f"weights missing for signals: {sorted(missing)}")

        keywords = {str(k): [str(x).lower() for x in v] for k, v in data["keywords"].items()}
        thresholds = {str(k): float(v) for k, v in data["thresholds"].items()}
        return cls(weights=weights, keywords=keywords, thresholds=thresholds)


@dataclass
class RepoSignals:
    """1 リポジトリ分の生の観測値。score_signals() で 0-1 に正規化される。"""

    issue_response_days: float = 0.0
    """直近 Issue への最新応答からの経過日数。応答が無い場合は十分大きな値。"""

    routes_count: int = 0
    auth_middleware_count: int = 0
    """thin_auth_layer = 1 - (auth / routes). routes=0 の時は 0.0 とする。"""

    recent_complex_feature_commits: int = 0
    days_since_last_release: float = 365.0
    docker_compose_services: int = 0
    dependency_count: int = 0

    self_implemented_dirs: list[str] = field(default_factory=list)
    """自前実装の crypto/parser/tokenizer 等のディレクトリ名リスト。"""

    text_corpus: str = ""
    """package.json / composer.json / README の連結 (monetary 検出用)。"""


def _clip01(value: float) -> float:
    if value < 0:
        return 0.0
    if value > 1:
        return 1.0
    return value


def _count_keyword_hits(text: str, keywords: list[str]) -> int:
    text_l = text.lower()
    return sum(text_l.count(kw) for kw in keywords)


def evaluate_signals(signals: RepoSignals, config: ScoringConfig) -> dict[str, float]:
    """各シグナルを 0.0-1.0 で評価する。"""
    th = config.thresholds
    kw = config.keywords

    s_maint = _clip01(signals.issue_response_days / th["issue_response_days_max"])

    if signals.routes_count <= 0:
        s_thin_auth = 0.0
    else:
        ratio = signals.auth_middleware_count / signals.routes_count
        s_thin_auth = _clip01(1.0 - ratio)

    s_recent = _clip01(
        signals.recent_complex_feature_commits / th["recent_complex_feature_commits_max"]
    )

    window = th["fresh_release_window_days"]
    s_fresh = _clip01(1.0 - (signals.days_since_last_release / window))

    s_multi = _clip01(signals.docker_compose_services / th["docker_compose_services_max"])
    s_deps = _clip01(signals.dependency_count / th["dependency_count_max"])
    s_roll = _clip01(len(signals.self_implemented_dirs) / th["roll_your_own_dirs_max"])

    monetary_hits = _count_keyword_hits(signals.text_corpus, kw.get("monetary", []))
    s_monetary = _clip01(monetary_hits / th["monetary_hits_max"])

    return {
        "maintenance_inactivity": s_maint,
        "thin_auth_layer": s_thin_auth,
        "recent_complex_features": s_recent,
        "fresh_release": s_fresh,
        "multi_tier": s_multi,
        "many_deps": s_deps,
        "roll_your_own": s_roll,
        "monetary": s_monetary,
    }


def aggregate_score(per_signal: dict[str, float], config: ScoringConfig) -> float:
    """各シグナルを weights で加重平均し、0.0-10.0 にスケールする。"""
    total_weight = sum(config.weights.get(name, 0.0) for name in SIGNAL_NAMES)
    if total_weight <= 0:
        return 0.0
    weighted = sum(per_signal.get(name, 0.0) * config.weights.get(name, 0.0) for name in SIGNAL_NAMES)
    normalized = weighted / total_weight  # 0.0-1.0
    return round(normalized * 10.0, 2)


def score_repo(
    signals: RepoSignals, config: ScoringConfig | None = None
) -> tuple[dict[str, float], float]:
    """``RepoSignals`` → (per-signal dict, aggregate score) を返す。"""
    cfg = config or ScoringConfig.load()
    per_signal = evaluate_signals(signals, cfg)
    score = aggregate_score(per_signal, cfg)
    return per_signal, score
