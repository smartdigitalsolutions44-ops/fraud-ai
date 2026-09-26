"""Single-feature shortcut detection.

If one feature alone separates fraud from legitimate examples almost perfectly, a model
trained on that data learns a shortcut rather than behaviour - typically an artefact of
how the (synthetic) data was generated. This computes, for every numeric and boolean
feature, the univariate ROC-AUC of the feature *value* (missing values are placed below
all observed values, i.e. treated as their own lowest bucket), folded so that 0.5 means
no signal and 1.0 means perfect separation in either direction.
"""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.metrics import roc_auc_score

from fraud_ai.evaluation.stats import IntArray
from fraud_ai.features.definitions import FeatureType, get_feature_set
from fraud_ai.models.matrix import ModelMatrix


def univariate_separability(matrix: ModelMatrix, y: IntArray) -> list[dict[str, Any]]:
    y = np.asarray(y, dtype=int)
    if len(np.unique(y)) < 2:
        return []
    fs = get_feature_set(matrix.feature_version)
    out = []
    for j, d in enumerate(fs.definitions):
        if d.dtype not in (FeatureType.FLOAT, FeatureType.INTEGER, FeatureType.BOOLEAN):
            continue
        raw = [row[j] for row in matrix.values]
        observed = [float(v) for v in raw if v is not None]
        if not observed:
            continue
        floor = min(observed) - 1.0
        x = np.asarray([float(v) if v is not None else floor for v in raw])
        if np.all(x == x[0]):
            continue
        auc = float(roc_auc_score(y, x))
        out.append(
            {
                "feature": d.name,
                "auc": max(auc, 1 - auc),
                "direction": "higher = more fraud" if auc >= 0.5 else "lower = more fraud",
                "missing_share": 1 - len(observed) / len(raw),
            }
        )
    return sorted(out, key=lambda r: (-r["auc"], r["feature"]))
