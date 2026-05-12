"""Sentinel scoring のテスト。"""

from __future__ import annotations

from pathlib import Path

import pytest

from suzaku.sentinel.scoring import (
    SIGNAL_NAMES,
    RepoSignals,
    ScoringConfig,
    ScoringError,
    aggregate_score,
    evaluate_signals,
    score_repo,
)


@pytest.fixture
def config() -> ScoringConfig:
    return ScoringConfig.load()


class TestScoringConfig:
    def test_load_default(self) -> None:
        cfg = ScoringConfig.load()
        for name in SIGNAL_NAMES:
            assert name in cfg.weights

    def test_missing_section_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "signals.yaml"
        bad.write_text("weights: {}\n")
        with pytest.raises(ScoringError):
            ScoringConfig.load(bad)

    def test_missing_signal_in_weights_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "signals.yaml"
        bad.write_text(
            "weights:\n  maintenance_inactivity: 1.0\n"
            "keywords:\n  monetary: []\n"
            "thresholds:\n  issue_response_days_max: 30\n"
            "  recent_complex_feature_commits_max: 5\n"
            "  docker_compose_services_max: 3\n"
            "  dependency_count_max: 50\n"
            "  roll_your_own_dirs_max: 3\n"
            "  monetary_hits_max: 3\n"
            "  fresh_release_window_days: 7\n"
        )
        with pytest.raises(ScoringError):
            ScoringConfig.load(bad)


class TestEvaluateSignals:
    def test_zero_signals_produces_zero_scores(self, config: ScoringConfig) -> None:
        signals = RepoSignals()
        per = evaluate_signals(signals, config)
        # 何も活動が無いリポジトリ: maintenance は 0, fresh も 0 (古いのでクリップ)
        assert per["recent_complex_features"] == 0.0
        assert per["multi_tier"] == 0.0
        assert per["many_deps"] == 0.0
        assert per["roll_your_own"] == 0.0
        assert per["monetary"] == 0.0

    def test_maintenance_inactivity_saturates(self, config: ScoringConfig) -> None:
        signals = RepoSignals(issue_response_days=100)
        per = evaluate_signals(signals, config)
        assert per["maintenance_inactivity"] == 1.0

    def test_maintenance_inactivity_linear(self, config: ScoringConfig) -> None:
        signals = RepoSignals(issue_response_days=15)
        per = evaluate_signals(signals, config)
        assert 0.4 < per["maintenance_inactivity"] < 0.6

    def test_fresh_release_within_window(self, config: ScoringConfig) -> None:
        signals = RepoSignals(days_since_last_release=0)
        per = evaluate_signals(signals, config)
        assert per["fresh_release"] == 1.0

    def test_fresh_release_outside_window(self, config: ScoringConfig) -> None:
        signals = RepoSignals(days_since_last_release=30)
        per = evaluate_signals(signals, config)
        assert per["fresh_release"] == 0.0

    def test_thin_auth_layer_no_routes(self, config: ScoringConfig) -> None:
        signals = RepoSignals(routes_count=0, auth_middleware_count=0)
        per = evaluate_signals(signals, config)
        assert per["thin_auth_layer"] == 0.0

    def test_thin_auth_layer_thin(self, config: ScoringConfig) -> None:
        signals = RepoSignals(routes_count=100, auth_middleware_count=5)
        per = evaluate_signals(signals, config)
        assert per["thin_auth_layer"] == pytest.approx(0.95, abs=0.01)

    def test_thin_auth_layer_thick(self, config: ScoringConfig) -> None:
        signals = RepoSignals(routes_count=10, auth_middleware_count=10)
        per = evaluate_signals(signals, config)
        assert per["thin_auth_layer"] == 0.0

    def test_many_deps_saturates_at_threshold(self, config: ScoringConfig) -> None:
        signals = RepoSignals(dependency_count=200)
        per = evaluate_signals(signals, config)
        assert per["many_deps"] == 1.0

    def test_monetary_keyword_hits(self, config: ScoringConfig) -> None:
        signals = RepoSignals(
            text_corpus="A platform for Stripe Stripe billing and subscription management"
        )
        per = evaluate_signals(signals, config)
        assert per["monetary"] > 0.5

    def test_roll_your_own_dirs(self, config: ScoringConfig) -> None:
        signals = RepoSignals(self_implemented_dirs=["crypto", "parser", "tokenizer"])
        per = evaluate_signals(signals, config)
        assert per["roll_your_own"] == 1.0


class TestAggregateScore:
    def test_zero_signals_zero_score(self, config: ScoringConfig) -> None:
        per = {name: 0.0 for name in SIGNAL_NAMES}
        assert aggregate_score(per, config) == 0.0

    def test_full_signals_ten(self, config: ScoringConfig) -> None:
        per = {name: 1.0 for name in SIGNAL_NAMES}
        assert aggregate_score(per, config) == 10.0

    def test_score_in_zero_to_ten(self, config: ScoringConfig) -> None:
        signals = RepoSignals(
            issue_response_days=45,
            routes_count=50,
            auth_middleware_count=2,
            recent_complex_feature_commits=3,
            days_since_last_release=2,
            docker_compose_services=2,
            dependency_count=30,
            self_implemented_dirs=["crypto"],
            text_corpus="payment subscription",
        )
        _per, score = score_repo(signals, config)
        assert 0.0 <= score <= 10.0


class TestWeightsAffectRanking:
    """signals.yaml の重みを変えると順位が変わることを保証する。"""

    def test_rebalancing_weights_changes_ordering(self, tmp_path: Path) -> None:
        # 2 リポを準備: A は monetary 強、B は roll_your_own 強
        a = RepoSignals(text_corpus="payment subscription billing")
        b = RepoSignals(self_implemented_dirs=["crypto", "parser", "tokenizer"])

        # 重み A: monetary 重視
        cfg_money = _config_with_weights(
            tmp_path / "money.yaml",
            {**_zero_weights(), "monetary": 5.0, "roll_your_own": 0.1},
        )
        score_a_money = score_repo(a, cfg_money)[1]
        score_b_money = score_repo(b, cfg_money)[1]
        assert score_a_money > score_b_money

        # 重み B: roll_your_own 重視
        cfg_crypto = _config_with_weights(
            tmp_path / "crypto.yaml",
            {**_zero_weights(), "monetary": 0.1, "roll_your_own": 5.0},
        )
        score_a_crypto = score_repo(a, cfg_crypto)[1]
        score_b_crypto = score_repo(b, cfg_crypto)[1]
        assert score_b_crypto > score_a_crypto


def _zero_weights() -> dict[str, float]:
    return {name: 0.0 for name in SIGNAL_NAMES}


def _config_with_weights(path: Path, weights: dict[str, float]) -> ScoringConfig:
    lines = ["weights:"]
    for k, v in weights.items():
        lines.append(f"  {k}: {v}")
    lines.append("keywords:")
    lines.append("  monetary: [payment, subscription, billing]")
    lines.append("  complex_features: []")
    lines.append("  roll_your_own: []")
    lines.append("thresholds:")
    lines.append("  issue_response_days_max: 30")
    lines.append("  recent_complex_feature_commits_max: 5")
    lines.append("  docker_compose_services_max: 3")
    lines.append("  dependency_count_max: 50")
    lines.append("  roll_your_own_dirs_max: 3")
    lines.append("  monetary_hits_max: 3")
    lines.append("  fresh_release_window_days: 7")
    path.write_text("\n".join(lines) + "\n")
    return ScoringConfig.load(path)
