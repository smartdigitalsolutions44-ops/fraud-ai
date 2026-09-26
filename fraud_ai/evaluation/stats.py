"""Uncertainty: bootstrap confidence intervals, paired comparisons, proportion intervals.

With tens of fraud examples a point estimate alone is misleading, so every headline metric
carries an interval.

* **Stratified bootstrap**: each resample draws positives and negatives separately with
  replacement, keeping the class counts fixed. Every resample therefore contains both
  classes and PR-AUC/ROC-AUC are always defined; the interval reflects sampling variation
  *given* the observed number of fraud cases.
* **Paired bootstrap** reuses the same resampled rows for both models, so the interval of
  the *difference* accounts for their correlation.
* **McNemar's exact test** compares classification errors of two models at a fixed
  threshold on the same examples.
* **Wilson score intervals** for simple rates such as a cohort's false positive rate.

All randomness comes from ``numpy.random.default_rng(seed)``: the same inputs, iterations
and seed give identical intervals.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

import numpy as np
import numpy.typing as npt
from scipy.stats import binomtest
from sklearn.metrics import average_precision_score, roc_auc_score

Array = npt.NDArray[np.float64]
IntArray = npt.NDArray[np.int_]
DEFAULT_ITERATIONS = 1000
DEFAULT_LEVEL = 0.95


@dataclass(frozen=True)
class Interval:
    estimate: float | None
    lower: float | None
    upper: float | None
    level: float
    iterations: int
    valid_resamples: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def overlaps(self, other: Interval) -> bool:
        if None in (self.lower, self.upper, other.lower, other.upper):
            return True
        assert self.lower is not None and self.upper is not None
        assert other.lower is not None and other.upper is not None
        return self.lower <= other.upper and other.lower <= self.upper


def _confusion(y: IntArray, pred: npt.NDArray[np.bool_]) -> tuple[int, int, int, int]:
    pos = y == 1
    return (
        int(np.sum(pred & pos)),
        int(np.sum(pred & ~pos)),
        int(np.sum(~pred & ~pos)),
        int(np.sum(~pred & pos)),
    )


def _ratio(a: int, b: int) -> float | None:
    return a / b if b else None


def threshold_metrics(y: IntArray, p: Array, threshold: float) -> dict[str, float | None]:
    tp, fp, tn, fn = _confusion(y, p >= threshold)
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall > 0
        else None
    )
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": _ratio(fp, fp + tn),
        "fnr": _ratio(fn, fn + tp),
    }


def ranking_metrics(y: IntArray, p: Array) -> dict[str, float | None]:
    if 0 < int(y.sum()) < len(y):
        return {
            "pr_auc": float(average_precision_score(y, p)),
            "roc_auc": float(roc_auc_score(y, p)),
        }
    return {"pr_auc": None, "roc_auc": None}


def all_metrics(y: IntArray, p: Array, threshold: float) -> dict[str, float | None]:
    return {**ranking_metrics(y, p), **threshold_metrics(y, p, threshold)}


METRIC_NAMES = ("pr_auc", "roc_auc", "precision", "recall", "f1", "fpr", "fnr")


def resample_indices(
    y: IntArray, iterations: int, seed: int, stratified: bool = True
) -> list[IntArray]:
    rng = np.random.default_rng(seed)
    if not stratified:
        return [rng.integers(0, len(y), len(y)) for _ in range(iterations)]
    pos, neg = np.flatnonzero(y == 1), np.flatnonzero(y == 0)
    out = []
    for _ in range(iterations):
        parts = [
            rng.choice(group, size=len(group), replace=True) for group in (pos, neg) if len(group)
        ]
        out.append(np.concatenate(parts))
    return out


def _interval(
    estimate: float | None, samples: list[float], level: float, iterations: int
) -> Interval:
    if not samples:
        return Interval(estimate, None, None, level, iterations, 0)
    alpha = (1 - level) / 2
    lower, upper = np.quantile(samples, [alpha, 1 - alpha])
    return Interval(estimate, float(lower), float(upper), level, iterations, len(samples))


def bootstrap_metrics(
    y: IntArray,
    p: Array,
    threshold: float,
    *,
    iterations: int = DEFAULT_ITERATIONS,
    level: float = DEFAULT_LEVEL,
    seed: int = 0,
    stratified: bool = True,
) -> dict[str, Interval]:
    """Percentile intervals for PR-AUC, ROC-AUC, precision, recall, F1, FPR and FNR."""
    y = np.asarray(y, dtype=int)
    point = all_metrics(y, p, threshold)
    samples: dict[str, list[float]] = {m: [] for m in METRIC_NAMES}
    for idx in resample_indices(y, iterations, seed, stratified):
        for name, value in all_metrics(y[idx], p[idx], threshold).items():
            if value is not None:
                samples[name].append(value)
    return {m: _interval(point[m], samples[m], level, iterations) for m in METRIC_NAMES}


def paired_difference(
    y: IntArray,
    p_a: Array,
    p_b: Array,
    metric: Callable[[IntArray, Array], float | None] | None = None,
    *,
    iterations: int = DEFAULT_ITERATIONS,
    level: float = DEFAULT_LEVEL,
    seed: int = 0,
) -> dict[str, Any]:
    """Bootstrap interval of metric(A) - metric(B) on the *same* resampled rows.

    ``p_value`` is the two-sided bootstrap estimate of P(difference has the other sign)."""
    y = np.asarray(y, dtype=int)

    def pr_auc(yy: IntArray, pp: Array) -> float | None:
        return ranking_metrics(yy, pp)["pr_auc"]

    fn = metric or pr_auc
    a, b = fn(y, p_a), fn(y, p_b)
    point = None if a is None or b is None else a - b
    diffs: list[float] = []
    for idx in resample_indices(y, iterations, seed):
        ra, rb = fn(y[idx], p_a[idx]), fn(y[idx], p_b[idx])
        if ra is not None and rb is not None:
            diffs.append(ra - rb)
    interval = _interval(point, diffs, level, iterations)
    if diffs:
        arr = np.asarray(diffs)
        p_value = min(1.0, 2 * min(float(np.mean(arr <= 0)), float(np.mean(arr >= 0))))
    else:
        p_value = None
    excludes_zero = (
        interval.lower is not None
        and interval.upper is not None
        and (interval.lower > 0 or interval.upper < 0)
    )
    return {
        "a": a,
        "b": b,
        "difference": interval.to_dict(),
        "p_value": p_value,
        "interval_excludes_zero": excludes_zero,
    }


def mcnemar(
    y: IntArray, p_a: Array, p_b: Array, threshold_a: float, threshold_b: float
) -> dict[str, Any]:
    """Exact McNemar test on the discordant classification errors at fixed thresholds."""
    y = np.asarray(y, dtype=int)
    correct_a = (p_a >= threshold_a).astype(int) == y
    correct_b = (p_b >= threshold_b).astype(int) == y
    only_a = int(np.sum(correct_a & ~correct_b))  # A right, B wrong
    only_b = int(np.sum(~correct_a & correct_b))
    discordant = only_a + only_b
    p_value = float(binomtest(only_a, discordant, 0.5).pvalue) if discordant else 1.0
    return {
        "a_correct_b_wrong": only_a,
        "a_wrong_b_correct": only_b,
        "discordant": discordant,
        "p_value": p_value,
    }


def wilson_interval(
    successes: int, n: int, level: float = DEFAULT_LEVEL
) -> tuple[float, float] | None:
    if n == 0:
        return None
    z = {0.90: 1.6448536, 0.95: 1.9599640, 0.99: 2.5758293}.get(round(level, 2), 1.9599640)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)
