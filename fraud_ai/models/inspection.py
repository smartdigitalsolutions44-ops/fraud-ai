"""Model-agnostic inspection: grouped permutation importance.

Every transformed column that belongs to one base feature (its value, its missing-reason
indicators, its one-hot categories) is permuted *together*, so a feature's importance is
not split across its encoding. Importance is the mean drop in PR-AUC (average precision)
over seeded repeats. Inspection only: it never feeds a decision, and it describes what a
model relies on in this dataset, not causal effects.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

import numpy as np
import numpy.typing as npt
from sklearn.metrics import average_precision_score

Array = npt.NDArray[np.float64]


def grouped_permutation_importance(
    predict: Callable[[Array], Array],
    X: Array,
    y: Sequence[int] | npt.NDArray[np.int_],
    columns: Sequence[str],
    base_feature: Callable[[str], str],
    *,
    n_repeats: int = 3,
    seed: int = 0,
    top_k: int = 12,
) -> dict[str, Any]:
    labels = np.asarray(y, dtype=int)
    if len(np.unique(labels)) < 2:
        return {
            "method": "grouped permutation importance",
            "note": "needs labelled data with both classes",
            "top_features": [],
        }
    groups: dict[str, list[int]] = {}
    for j, column in enumerate(columns):
        groups.setdefault(base_feature(column), []).append(j)
    baseline = float(average_precision_score(labels, predict(X)))
    rng = np.random.default_rng(seed)
    scores: dict[str, float] = {}
    for feature in sorted(groups):
        idx = groups[feature]
        drops = []
        for _ in range(n_repeats):
            permuted = X.copy()
            order = rng.permutation(len(X))
            permuted[:, idx] = X[order][:, idx]
            drops.append(baseline - float(average_precision_score(labels, predict(permuted))))
        scores[feature] = float(np.mean(drops))
    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))[:top_k]
    return {
        "method": f"grouped permutation importance (drop in PR-AUC, {n_repeats} seeded "
        "repeats; all encoded columns of a feature permuted together)",
        "baseline_pr_auc": baseline,
        "top_features": [{"feature": f, "importance": s} for f, s in ranked],
    }
