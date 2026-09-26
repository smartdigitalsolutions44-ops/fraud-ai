"""Drift baseline: reference feature distributions from the training split.

No live drift service exists yet. This module creates the reference and the comparison
maths so later data (a new month, a new region) can be compared against what the model was
trained on:

* numeric features: decile bins from the *observed* training values (edges are recorded),
  plus one bucket per missing reason, so a rise in "unknown" intel shows up as drift;
* boolean/categorical features: token frequencies including missing reasons.

**PSI** (population stability index) = sum((a - e) * ln(a / e)); common reading: < 0.10
stable, 0.10-0.25 moderate shift, > 0.25 significant shift. **Jensen-Shannon distance**
(base 2, in [0, 1]) is symmetric and bounded. Proportions are floored at 1e-6 so empty
buckets do not produce infinities.

Limitations: univariate only (joint shifts are invisible), bin edges from one training
window, thresholds are conventions not guarantees, and drift is not the same as
performance loss - it is a prompt to re-evaluate.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import numpy as np
from scipy.spatial.distance import jensenshannon

from fraud_ai.features.definitions import FeatureType, get_feature_set
from fraud_ai.features.vector import MissingReason
from fraud_ai.models.matrix import ModelMatrix

TRACKED_FEATURES: tuple[str, ...] = (
    "transaction_amount_minor_units",
    "address_age_days",
    "device_age_days",
    "logins_last_1h",
    "network_type",
    "vpn_detected",
    "new_device",
    "new_address",
)
FLOOR = 1e-6
REASONS = tuple(r.value for r in MissingReason)


def _tokens(matrix: ModelMatrix, name: str) -> list[str | float]:
    j = matrix.feature_names.index(name)
    out: list[str | float] = []
    for values, missing in zip(matrix.values, matrix.missing, strict=True):
        if values[j] is None:
            reason = missing[j]
            out.append(f"missing:{reason.value if reason else 'unknown'}")
        elif isinstance(values[j], bool):
            out.append("true" if values[j] else "false")
        elif isinstance(values[j], str):
            out.append(str(values[j]))
        else:
            out.append(float(values[j]))  # type: ignore[arg-type]
    return out


def _distribution(tokens: list[str | float], spec: dict[str, Any]) -> dict[str, float]:
    counts = dict.fromkeys(spec["buckets"], 0)
    for token in tokens:
        if isinstance(token, float):
            key = f"bin:{int(np.searchsorted(spec['edges'], token, side='right'))}"
        else:
            key = token if token in counts else "__other__"
        counts[key] = counts.get(key, 0) + 1
    n = max(1, len(tokens))
    return {k: v / n for k, v in counts.items()}


def build_baseline(
    matrix: ModelMatrix, features: Sequence[str] = TRACKED_FEATURES, bins: int = 10
) -> dict[str, Any]:
    fs = get_feature_set(matrix.feature_version)
    specs: dict[str, Any] = {}
    for name in features:
        d = fs.get(name)
        tokens = _tokens(matrix, name)
        missing_buckets = [f"missing:{r}" for r in REASONS]
        if d.dtype in (FeatureType.FLOAT, FeatureType.INTEGER):
            observed = np.asarray([t for t in tokens if isinstance(t, float)])
            edges = (
                sorted({float(v) for v in np.quantile(observed, np.linspace(0, 1, bins + 1)[1:-1])})
                if len(observed)
                else []
            )
            buckets = [f"bin:{i}" for i in range(len(edges) + 1)] + missing_buckets
            spec: dict[str, Any] = {"kind": "numeric", "edges": edges, "buckets": buckets}
        else:
            if d.dtype is FeatureType.BOOLEAN:
                cats = ["true", "false"]
            else:
                cats = list(
                    d.allowed_values
                    or sorted(
                        {t for t in tokens if isinstance(t, str) and not t.startswith("missing:")}
                    )
                )
            spec = {
                "kind": "categorical",
                "edges": [],
                "buckets": [*cats, "__other__", *missing_buckets],
            }
        spec["reference"] = _distribution(tokens, spec)
        specs[name] = spec
    return {
        "feature_version": matrix.feature_version,
        "rows": len(matrix),
        "bins": bins,
        "features": specs,
        "interpretation": {"psi_stable_below": 0.10, "psi_significant_above": 0.25},
    }


def psi(expected: dict[str, float], actual: dict[str, float]) -> float:
    total = 0.0
    for key in expected:
        e, a = max(expected[key], FLOOR), max(actual.get(key, 0.0), FLOOR)
        total += (a - e) * float(np.log(a / e))
    return total


def js_distance(expected: dict[str, float], actual: dict[str, float]) -> float:
    keys = list(expected)
    e = np.asarray([max(expected[k], FLOOR) for k in keys])
    a = np.asarray([max(actual.get(k, 0.0), FLOOR) for k in keys])
    return float(jensenshannon(e, a, base=2))


def status(value: float) -> str:
    return "stable" if value < 0.10 else ("moderate" if value <= 0.25 else "significant")


def compare_to_baseline(baseline: dict[str, Any], matrix: ModelMatrix) -> dict[str, Any]:
    if matrix.feature_version != baseline["feature_version"]:
        raise ValueError("feature version differs from the baseline")
    out = {}
    for name, spec in baseline["features"].items():
        current = _distribution(_tokens(matrix, name), spec)
        value = psi(spec["reference"], current)
        out[name] = {
            "psi": value,
            "js_distance": js_distance(spec["reference"], current),
            "status": status(value),
            "current": current,
        }
    return {"rows": len(matrix), "features": out}
