"""Stage 4 statistics: bootstrap, paired tests, calibration, costs, drift, agreement."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import numpy as np
import pytest

from fraud_ai.evaluation.calibration import (
    CalibrationError,
    Calibrator,
    brier,
    calibration_metrics,
    compare_calibrations,
    expected_calibration_error,
    fit_calibrator,
    log_loss,
    reliability,
)
from fraud_ai.evaluation.comparison import agreement, ensemble_research, pairwise_tests
from fraud_ai.evaluation.costs import CostConfig, band_analysis, cost_curve
from fraud_ai.evaluation.drift import js_distance, psi, status
from fraud_ai.evaluation.stats import (
    METRIC_NAMES,
    Interval,
    all_metrics,
    bootstrap_metrics,
    mcnemar,
    paired_difference,
    resample_indices,
    threshold_metrics,
    wilson_interval,
)


def _data(n: int = 400, fraud: int = 40, seed: int = 0, signal: float = 2.0) -> tuple[Any, Any]:
    rng = np.random.default_rng(seed)
    y = np.zeros(n, dtype=int)
    y[:fraud] = 1
    rng.shuffle(y)
    z = rng.normal(size=n) + signal * y
    return y, 1 / (1 + np.exp(-(z - 3)))


# ------------------------------------------------------------------ bootstrap
def test_bootstrap_intervals_cover_point_estimates() -> None:
    y, p = _data()
    cis = bootstrap_metrics(y, p, 0.5, iterations=300, seed=1)
    assert set(cis) == set(METRIC_NAMES)
    point = all_metrics(y, p, 0.5)
    for name, ci in cis.items():
        assert ci.estimate == point[name]
        assert ci.lower is not None and ci.upper is not None
        assert 0.0 <= ci.lower <= ci.upper <= 1.0
        assert ci.level == 0.95 and ci.iterations == 300 and ci.valid_resamples > 0
    assert cis["pr_auc"].lower < cis["pr_auc"].estimate < cis["pr_auc"].upper  # type: ignore[operator]
    wider = bootstrap_metrics(y, p, 0.5, iterations=300, seed=1, level=0.99)["pr_auc"]
    assert wider.lower <= cis["pr_auc"].lower and wider.upper >= cis["pr_auc"].upper  # type: ignore[operator]


def test_bootstrap_is_deterministic_and_seed_dependent() -> None:
    y, p = _data()
    a = bootstrap_metrics(y, p, 0.5, iterations=200, seed=7)
    b = bootstrap_metrics(y, p, 0.5, iterations=200, seed=7)
    c = bootstrap_metrics(y, p, 0.5, iterations=200, seed=8)
    assert {k: v.to_dict() for k, v in a.items()} == {k: v.to_dict() for k, v in b.items()}
    assert a["pr_auc"].to_dict() != c["pr_auc"].to_dict()


def test_stratified_resampling_keeps_class_counts() -> None:
    y, _ = _data(n=100, fraud=7)
    for idx in resample_indices(y, 50, seed=3):
        assert len(idx) == 100 and int(y[idx].sum()) == 7
    unstratified = [int(y[idx].sum()) for idx in resample_indices(y, 50, 3, stratified=False)]
    assert len(set(unstratified)) > 1


def test_bootstrap_with_a_single_class_reports_no_ranking_interval() -> None:
    y = np.zeros(50, dtype=int)
    cis = bootstrap_metrics(y, np.linspace(0, 1, 50), 0.5, iterations=20)
    assert cis["pr_auc"].estimate is None and cis["pr_auc"].lower is None
    assert cis["pr_auc"].valid_resamples == 0
    assert cis["fpr"].estimate == pytest.approx(0.5, abs=0.02)
    assert cis["recall"].estimate is None


def test_threshold_metrics_and_interval_overlap() -> None:
    y = np.array([1, 1, 0, 0, 0])
    p = np.array([0.9, 0.2, 0.8, 0.1, 0.1])
    m = threshold_metrics(y, p, 0.5)
    assert m == {
        "precision": 0.5,
        "recall": 0.5,
        "f1": 0.5,
        "fpr": pytest.approx(1 / 3),
        "fnr": 0.5,
    }
    assert threshold_metrics(y, np.zeros(5), 0.5)["f1"] is None
    a = Interval(0.5, 0.4, 0.6, 0.95, 10, 10)
    assert a.overlaps(Interval(0.7, 0.55, 0.8, 0.95, 10, 10))
    assert not a.overlaps(Interval(0.8, 0.7, 0.9, 0.95, 10, 10))
    assert a.overlaps(Interval(None, None, None, 0.95, 10, 0))  # unknown = cannot separate


def test_paired_difference() -> None:
    y, good = _data(signal=3.0)
    _, weak = _data(signal=0.3, seed=0)
    same = paired_difference(y, good, good, iterations=100)
    assert same["difference"]["estimate"] == 0 and not same["interval_excludes_zero"]
    diff = paired_difference(y, good, weak, iterations=200, seed=2)
    assert diff["a"] > diff["b"] and diff["interval_excludes_zero"]
    assert diff["difference"]["lower"] > 0 and diff["p_value"] < 0.05
    assert paired_difference(y, good, weak, iterations=200, seed=2) == diff  # deterministic
    single = paired_difference(np.zeros(10, dtype=int), good[:10], weak[:10], iterations=10)
    assert single["p_value"] is None and not single["interval_excludes_zero"]


def test_mcnemar() -> None:
    y = np.array([1] * 20 + [0] * 80)
    perfect = y.astype(float)
    assert mcnemar(y, perfect, perfect, 0.5, 0.5) == {
        "a_correct_b_wrong": 0,
        "a_wrong_b_correct": 0,
        "discordant": 0,
        "p_value": 1.0,
    }
    worse = perfect.copy()
    worse[:12] = 0.0  # B misses 12 frauds A catches
    result = mcnemar(y, perfect, worse, 0.5, 0.5)
    assert result["a_correct_b_wrong"] == 12 and result["a_wrong_b_correct"] == 0
    assert result["p_value"] < 0.001
    swapped = mcnemar(y, worse, perfect, 0.5, 0.5)
    assert swapped["p_value"] == result["p_value"]


def test_wilson_interval() -> None:
    assert wilson_interval(0, 0) is None
    low, high = wilson_interval(0, 100)  # type: ignore[misc]
    assert low == 0.0 and 0.0 < high < 0.05
    low, high = wilson_interval(50, 100)  # type: ignore[misc]
    assert low < 0.5 < high and high - low == pytest.approx(0.19, abs=0.01)
    narrow = wilson_interval(50, 100, 0.90)
    assert narrow is not None and narrow[1] - narrow[0] < high - low


# ------------------------------------------------------------------ calibration
def test_brier_log_loss_and_reliability_buckets() -> None:
    y = np.array([0, 0, 1, 1])
    assert brier(y, y.astype(float)) == 0.0
    assert brier(y, np.array([1.0, 1.0, 0.0, 0.0])) == 1.0
    assert brier(y, np.full(4, 0.5)) == 0.25
    assert log_loss(y, np.full(4, 0.5)) == pytest.approx(np.log(2))
    assert np.isfinite(log_loss(y, np.array([1.0, 1.0, 0.0, 0.0])))  # clipped, not infinite
    p = np.array([0.0, 0.05, 0.15, 0.95, 1.0, 0.1])
    buckets = reliability(np.array([0, 0, 1, 1, 1, 0]), p)
    assert len(buckets) == 10
    assert [b["lower"] for b in buckets] == pytest.approx([i / 10 for i in range(10)])
    assert buckets[0]["count"] == 2 and buckets[0]["fraud_rate"] == 0.0
    assert buckets[1]["count"] == 2 and buckets[1]["fraud_rate"] == 0.5  # 0.1 and 0.15
    assert buckets[9]["count"] == 2 and buckets[9]["mean_predicted"] == pytest.approx(0.975)
    assert buckets[5]["count"] == 0 and buckets[5]["fraud_rate"] is None
    assert sum(b["count"] for b in buckets) == 6
    assert expected_calibration_error([]) is None
    ece = expected_calibration_error(buckets)
    assert ece == pytest.approx((2 * 0.025 + 2 * abs(0.125 - 0.5) + 2 * 0.025) / 6)


def test_calibration_fitting_improves_miscalibrated_scores() -> None:
    rng = np.random.default_rng(0)
    true_p = rng.uniform(0, 0.3, 4000)
    y = (rng.uniform(size=4000) < true_p).astype(int)
    overconfident = np.clip(true_p * 3, 0, 1)
    for method in ("sigmoid", "isotonic"):
        cal = fit_calibrator(method, overconfident[:2000], y[:2000])
        before = brier(y[2000:], overconfident[2000:])
        after = brier(y[2000:], cal.transform(overconfident[2000:]))
        assert after < before
        restored = Calibrator.from_dict(cal.to_dict())
        assert np.allclose(restored.transform(overconfident), cal.transform(overconfident))
    sigmoid = fit_calibrator("sigmoid", overconfident, y)
    order = np.argsort(overconfident)
    assert np.all(np.diff(sigmoid.transform(overconfident)[order]) >= 0)  # ranking kept
    assert fit_calibrator("uncalibrated", overconfident, y).transform(overconfident) is not None


def test_calibration_errors() -> None:
    with pytest.raises(CalibrationError, match="both classes"):
        fit_calibrator("sigmoid", np.array([0.1, 0.2]), np.array([0, 0]))
    with pytest.raises(CalibrationError, match="unknown"):
        fit_calibrator("beta", np.array([0.1, 0.2]), np.array([0, 1]))
    with pytest.raises(CalibrationError, match="unknown"):
        Calibrator.from_dict({"method": "beta", "parameters": {}})
    with pytest.raises(CalibrationError, match="unknown"):
        Calibrator("beta", {}).transform(np.array([0.5]))


def test_calibrators_are_fitted_on_validation_only() -> None:
    """Changing the test labels can change the reported test metrics, but never a fitted
    calibrator: the test split is reporting-only."""
    y_val, p_val = _data(seed=1)
    y_test, p_test = _data(seed=2)
    first = compare_calibrations(p_val, y_val, p_test, y_test)
    flipped = compare_calibrations(p_val, y_val, p_test, 1 - y_test)
    for method in ("sigmoid", "isotonic"):
        assert first["methods"][method]["fitted_on"] == "validation"
        assert first["methods"][method]["calibrator"] == flipped["methods"][method]["calibrator"]
        test_brier = first["methods"][method]["test"]["brier"]
        assert test_brier != flipped["methods"][method]["test"]["brier"]
    assert first["lowest_test_brier"] in ("uncalibrated", "sigmoid", "isotonic")
    one_class = compare_calibrations(p_val, np.zeros_like(y_val), p_test, y_test)
    assert "error" in one_class["methods"]["sigmoid"]
    assert one_class["lowest_test_brier"] == "uncalibrated"
    m = calibration_metrics(y_test, p_test)
    assert {"brier", "log_loss", "ece", "reliability", "pr_auc"} <= set(m)


# ------------------------------------------------------------------ costs
def test_cost_curve_arithmetic() -> None:
    y = np.array([1, 1, 0, 0, 0, 0])
    p = np.array([0.9, 0.4, 0.6, 0.2, 0.1, 0.05])
    config = CostConfig()
    curve = cost_curve(y, p, config, thresholds=(0.5,))
    everything, at_half, nothing = curve["rows"]
    assert everything["label"] == "flag everything" and nothing["label"] == "flag nothing"
    # flag everything: 6 reviews at 5 + 4 FPs at 10
    assert everything["total_cost"] == 6 * 5 + 4 * 10 and everything["fraud_missed"] == 0
    # threshold 0.5: flags 0.9 (TP) and 0.6 (FP); misses one fraud (500)
    assert at_half["fraud_caught"] == 1 and at_half["false_positives"] == 1
    assert at_half["missed_fraud_cost"] == 500 and at_half["handling_cost"] == 10
    assert at_half["friction_cost"] == 10 and at_half["total_cost"] == 520
    assert nothing["total_cost"] == 1000 and nothing["flagged"] == 0
    assert curve["lowest_cost_threshold"] == 0.5 and "NOT applied" in curve["note"]
    step_up = cost_curve(y, p, config, thresholds=(0.5,), action="step_up")
    assert step_up["rows"][1]["handling_cost"] == 2
    amounts = np.array([100.0, 30.0, 0, 0, 0, 0])
    by_amount = cost_curve(
        y, p, CostConfig(fraud_loss_mode="amount"), amounts=amounts, thresholds=(0.5,)
    )
    assert by_amount["rows"][1]["missed_fraud_cost"] == 30.0


def test_cost_config_validation() -> None:
    with pytest.raises(ValueError, match="fraud_loss_mode"):
        CostConfig(fraud_loss_mode="guess")
    with pytest.raises(ValueError, match="negative"):
        CostConfig(manual_review_cost=-1)
    with pytest.raises(ValueError, match="amounts"):
        cost_curve(np.array([1]), np.array([0.5]), CostConfig(fraud_loss_mode="amount"))


def test_band_analysis() -> None:
    y = np.array([0, 0, 0, 1, 0, 1, 1, 0, 0, 0])
    p = np.array([0.1, 0.2, 0.25, 0.28, 0.4, 0.5, 0.9, 0.8, 0.05, 0.0])
    result = band_analysis(y, p, CostConfig())
    low, review, high = result["bands"]
    assert (low["events"], review["events"], high["events"]) == (6, 2, 2)
    assert low["fraud"] == 1 and low["conceptual_cost"] == 500
    assert review["manual_review_load"] == 2 and review["conceptual_cost"] == 2 * 5 + 1 * 10
    assert high["fraud_rate"] == 0.5 and high["conceptual_cost"] == 2 * 1 + 1 * 10
    assert sum(b["population_share"] for b in result["bands"]) == pytest.approx(1.0)
    assert sum(b["share_of_all_fraud"] for b in result["bands"]) == pytest.approx(1.0)
    assert "not rules" in result["note"]
    with pytest.raises(ValueError, match="bands"):
        band_analysis(y, p, CostConfig(), bands=(0.7, 0.3))


# ------------------------------------------------------------------ drift
def test_psi_and_js_distance() -> None:
    ref = {"a": 0.5, "b": 0.5}
    assert psi(ref, ref) == 0.0 and js_distance(ref, ref) == 0.0
    shifted = {"a": 0.9, "b": 0.1}
    expected_psi = (0.9 - 0.5) * np.log(0.9 / 0.5) + (0.1 - 0.5) * np.log(0.1 / 0.5)
    assert psi(ref, shifted) == pytest.approx(expected_psi)
    assert 0 < js_distance(ref, shifted) < 1
    assert js_distance(ref, shifted) == pytest.approx(js_distance(shifted, ref))
    assert np.isfinite(psi(ref, {"a": 1.0}))  # empty bucket floored, not infinite
    assert js_distance({"a": 1.0, "b": 0.0}, {"a": 0.0, "b": 1.0}) == pytest.approx(1, abs=1e-3)
    assert [status(v) for v in (0.05, 0.1, 0.25, 0.3)] == [
        "stable",
        "moderate",
        "moderate",
        "significant",
    ]


# ------------------------------------------------------------------ agreement / ensembles
def _fake_ctx(y: Any, models: dict[str, tuple[Any, Any, float]]) -> Any:
    """Duck-typed context: labels per split and models with scores and thresholds."""
    labels = {"validation": y, "test": y}
    ms = [
        SimpleNamespace(model_id=name, threshold=t, scores={"validation": v, "test": s})
        for name, (v, s, t) in models.items()
    ]
    return cast(Any, SimpleNamespace(labels=lambda split: labels[split], models=ms))


def test_agreement_groups() -> None:
    y = np.array([1, 1, 0, 0, 0, 1])
    a = np.array([0.9, 0.9, 0.9, 0.1, 0.1, 0.1])
    b = np.array([0.9, 0.1, 0.1, 0.1, 0.9, 0.1])
    ctx = _fake_ctx(y, {"a": (a, a, 0.5), "b": (b, b, 0.5)})
    groups = {g["group"]: g for g in agreement(ctx)["groups"]}
    assert groups["all_high"]["events"] == 1 and groups["all_high"]["fraud_rate"] == 1.0
    assert groups["only_a_high"]["events"] == 2 and groups["only_a_high"]["fraud"] == 1
    assert groups["only_b_high"]["events"] == 1 and groups["only_b_high"]["fraud"] == 0
    assert groups["all_low"]["events"] == 2 and groups["all_low"]["share_of_all_fraud"] == 1 / 3
    c = np.array([0.9, 0.9, 0.1, 0.1, 0.1, 0.1])
    three = _fake_ctx(y, {"a": (a, a, 0.5), "b": (b, b, 0.5), "c": (c, c, 0.5)})
    assert {g["group"] for g in agreement(three)["groups"]} >= {"mixed", "all_high"}


def test_ensemble_research_and_pairwise_are_experimental() -> None:
    y, good = _data(signal=3.0)
    _, weak = _data(signal=0.5, seed=5)
    ctx = _fake_ctx(y, {"good": (good, good, 0.5), "weak": (weak, weak, 0.5)})
    result = ensemble_research(ctx, iterations=100, seed=0)
    assert result["reference_model"] == "good"
    assert set(result["ensembles"]) == {
        "average_probability",
        "weighted_probability",
        "majority_vote_fraction",
    }
    assert (
        result["weights_from_validation_pr_auc"]["good"]
        > result["weights_from_validation_pr_auc"]["weak"]
    )
    assert all(not e["appears_useful"] for e in result["ensembles"].values())
    assert "no ensemble is persisted or activated" in result["note"]
    assert (
        "needs at least two"
        in ensemble_research(_fake_ctx(y, {"good": (good, good, 0.5)}), iterations=10, seed=0)[
            "note"
        ]
    )
    pairs = pairwise_tests(ctx, iterations=100, seed=0)
    assert len(pairs) == 1 and pairs[0]["difference_interval_excludes_zero"]
    assert "winner" not in pairs[0]["conclusion"] and "best" not in pairs[0]["conclusion"]
    same = pairwise_tests(
        _fake_ctx(y, {"a": (good, good, 0.5), "b": (good, good, 0.5)}), iterations=50, seed=0
    )
    assert same[0]["conclusion"].startswith("no reliable difference")
