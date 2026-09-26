"""Probability calibration and reliability analysis.

Class-weighted models rank well but their scores are not event probabilities. Two
post-hoc calibrators are compared with the uncalibrated scores:

* **sigmoid (Platt)**: a logistic fit ``p' = 1 / (1 + exp(-(a * logit(p) + b)))``;
* **isotonic**: a monotone step function (more flexible; needs more data, can overfit).

Calibrators are fitted on the **validation split only** - :func:`fit_calibrator` never sees
the test split, which is used exclusively for reporting. A test proves that changing test
labels cannot change a fitted calibrator.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.evaluation.stats import Array, IntArray, ranking_metrics

METHODS = ("uncalibrated", "sigmoid", "isotonic")
EPS = 1e-6
DEFAULT_BINS = 10


class CalibrationError(FraudAIError):
    pass


def _logit(p: Array) -> Array:
    clipped = np.clip(p, EPS, 1 - EPS)
    return np.asarray(np.log(clipped / (1 - clipped)), dtype=np.float64)


@dataclass
class Calibrator:
    method: str
    parameters: dict[str, Any]

    def transform(self, p: Array) -> Array:
        p = np.asarray(p, dtype=np.float64)
        if self.method == "uncalibrated":
            return p
        if self.method == "sigmoid":
            z = self.parameters["a"] * _logit(p) + self.parameters["b"]
            return np.asarray(1 / (1 + np.exp(-z)), dtype=np.float64)
        if self.method == "isotonic":
            x = np.asarray(self.parameters["x"], dtype=np.float64)
            y = np.asarray(self.parameters["y"], dtype=np.float64)
            return np.asarray(np.interp(p, x, y), dtype=np.float64)
        raise CalibrationError(f"unknown calibration method {self.method!r}")

    def to_dict(self) -> dict[str, Any]:
        return {"method": self.method, "parameters": self.parameters}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Calibrator:
        if data["method"] not in METHODS:
            raise CalibrationError(f"unknown calibration method {data['method']!r}")
        return cls(data["method"], dict(data["parameters"]))


def fit_calibrator(method: str, p_calibration: Array, y_calibration: IntArray) -> Calibrator:
    """Fit on calibration (validation) data only. The test split must never be passed."""
    y = np.asarray(y_calibration, dtype=int)
    if method == "uncalibrated":
        return Calibrator(method, {})
    if len(np.unique(y)) < 2:
        raise CalibrationError("calibration data must contain both classes")
    if method == "sigmoid":
        lr = LogisticRegression(C=1e6, solver="lbfgs", max_iter=1000)
        lr.fit(_logit(p_calibration).reshape(-1, 1), y)
        return Calibrator(method, {"a": float(lr.coef_[0][0]), "b": float(lr.intercept_[0])})
    if method == "isotonic":
        iso = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip")
        iso.fit(np.asarray(p_calibration, dtype=np.float64), y)
        return Calibrator(
            method,
            {
                "x": [float(v) for v in iso.X_thresholds_],
                "y": [float(v) for v in iso.y_thresholds_],
            },
        )
    raise CalibrationError(f"unknown calibration method {method!r}")


def brier(y: IntArray, p: Array) -> float:
    return float(np.mean((np.asarray(p) - np.asarray(y)) ** 2))


def log_loss(y: IntArray, p: Array) -> float:
    q = np.clip(np.asarray(p, dtype=np.float64), EPS, 1 - EPS)
    ya = np.asarray(y, dtype=np.float64)
    return float(-np.mean(ya * np.log(q) + (1 - ya) * np.log(1 - q)))


def reliability(y: IntArray, p: Array, bins: int = DEFAULT_BINS) -> list[dict[str, Any]]:
    """Equal-width probability buckets: count, mean prediction, observed fraud rate."""
    y = np.asarray(y, dtype=int)
    p = np.asarray(p, dtype=np.float64)
    edges = np.linspace(0.0, 1.0, bins + 1)
    idx = np.clip(np.digitize(p, edges[1:-1], right=False), 0, bins - 1)
    out = []
    for b in range(bins):
        mask = idx == b
        n = int(mask.sum())
        out.append(
            {
                "lower": float(edges[b]),
                "upper": float(edges[b + 1]),
                "count": n,
                "mean_predicted": float(p[mask].mean()) if n else None,
                "fraud_rate": float(y[mask].mean()) if n else None,
                "fraud_count": int(y[mask].sum()),
            }
        )
    return out


def expected_calibration_error(buckets: list[dict[str, Any]]) -> float | None:
    total = sum(b["count"] for b in buckets)
    if not total:
        return None
    return float(
        sum(
            b["count"] / total * abs(b["mean_predicted"] - b["fraud_rate"])
            for b in buckets
            if b["count"]
        )
    )


def calibration_metrics(y: IntArray, p: Array, bins: int = DEFAULT_BINS) -> dict[str, Any]:
    buckets = reliability(y, p, bins)
    return {
        "brier": brier(y, p),
        "log_loss": log_loss(y, p),
        "ece": expected_calibration_error(buckets),
        "mean_predicted": float(np.mean(p)),
        "observed_rate": float(np.mean(y)),
        **ranking_metrics(np.asarray(y, dtype=int), p),
        "reliability": buckets,
    }


def compare_calibrations(
    p_val: Array, y_val: IntArray, p_test: Array, y_test: IntArray, bins: int = DEFAULT_BINS
) -> dict[str, Any]:
    """Fit each method on validation, report on test (and validation, for reference)."""
    results: dict[str, Any] = {}
    for method in METHODS:
        try:
            calibrator = fit_calibrator(method, p_val, y_val)
        except CalibrationError as exc:
            results[method] = {"error": str(exc)}
            continue
        results[method] = {
            "calibrator": calibrator.to_dict(),
            "fitted_on": "validation",
            "validation": calibration_metrics(y_val, calibrator.transform(p_val), bins),
            "test": calibration_metrics(y_test, calibrator.transform(p_test), bins),
        }
    fitted = {m: r for m, r in results.items() if "test" in r}
    best = min(fitted, key=lambda m: (fitted[m]["test"]["brier"], m)) if fitted else None
    return {
        "methods": results,
        "lowest_test_brier": best,
        "note": "Calibrators are fitted on validation only; test is reporting-only. "
        "Sigmoid preserves ranking; isotonic can create ties and may overfit "
        "small validation sets.",
    }
