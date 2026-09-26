"""Evaluation metrics and threshold analysis.

Accuracy is deliberately absent: with rare fraud a model that never flags anything is
"99% accurate". The headline metrics are PR-AUC (average precision), precision and recall
at a stated threshold, and the false positive rate. Ratios with an empty denominator are
``None`` (undefined), never a made-up 0.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any

import numpy as np
import numpy.typing as npt
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score

DEFAULT_THRESHOLDS: tuple[float, ...] = (0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90)
SELECTION_GRID: tuple[float, ...] = tuple(round(0.05 * i, 2) for i in range(1, 20))


def _ratio(num: int, den: int) -> float | None:
    return num / den if den else None


@dataclass(frozen=True)
class ThresholdRow:
    threshold: float
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float | None
    recall: float | None
    f1: float | None
    fpr: float | None
    fnr: float | None
    tpr: float | None
    tnr: float | None
    flagged_rate: float | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def confusion_at(
    y: npt.NDArray[np.int_], p: npt.NDArray[np.float64], threshold: float
) -> ThresholdRow:
    pred = p >= threshold
    pos = y == 1
    tp = int(np.sum(pred & pos))
    fp = int(np.sum(pred & ~pos))
    fn = int(np.sum(~pred & pos))
    tn = int(np.sum(~pred & ~pos))
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall > 0
        else None
    )
    return ThresholdRow(
        threshold,
        tp,
        fp,
        tn,
        fn,
        precision,
        recall,
        f1,
        fpr=_ratio(fp, fp + tn),
        fnr=_ratio(fn, fn + tp),
        tpr=recall,
        tnr=_ratio(tn, tn + fp),
        flagged_rate=_ratio(tp + fp, len(y)),
    )


@dataclass(frozen=True)
class ThresholdAnalysis:
    """Model outputs at several operating points. An analysis - never a decision."""

    rows: tuple[ThresholdRow, ...]

    def at(self, threshold: float) -> ThresholdRow:
        for row in self.rows:
            if abs(row.threshold - threshold) < 1e-9:
                return row
        raise KeyError(threshold)

    def to_list(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self.rows]


def threshold_analysis(
    y: Sequence[int] | npt.NDArray[np.int_],
    p: npt.NDArray[np.float64],
    thresholds: Sequence[float] = DEFAULT_THRESHOLDS,
) -> ThresholdAnalysis:
    ya = np.asarray(y, dtype=int)
    return ThresholdAnalysis(tuple(confusion_at(ya, p, t) for t in thresholds))


def select_threshold(
    y: Sequence[int] | npt.NDArray[np.int_], p: npt.NDArray[np.float64]
) -> float | None:
    """Threshold maximising F1 on the given (validation) data; ties -> higher threshold
    (fewer customers flagged). ``None`` when F1 is undefined everywhere."""
    ya = np.asarray(y, dtype=int)
    best: tuple[float, float] | None = None
    for t in SELECTION_GRID:
        f1 = confusion_at(ya, p, t).f1
        if f1 is not None and (best is None or f1 >= best[0]):
            best = (f1, t)
    return best[1] if best else None


def evaluate_scores(
    y: Sequence[int] | npt.NDArray[np.int_], p: npt.NDArray[np.float64], threshold: float
) -> dict[str, Any]:
    ya = np.asarray(y, dtype=int)
    positives = int(ya.sum())
    both_classes = 0 < positives < len(ya)
    row = confusion_at(ya, p, threshold)
    return {
        "n": len(ya),
        "positives": positives,
        "prevalence": positives / len(ya) if len(ya) else None,
        "pr_auc": float(average_precision_score(ya, p)) if both_classes else None,
        "roc_auc": float(roc_auc_score(ya, p)) if both_classes else None,
        "brier": float(brier_score_loss(ya, p)) if len(ya) else None,
        "threshold": threshold,
        **{k: v for k, v in row.to_dict().items() if k != "threshold"},
        "confusion_matrix": [[row.tn, row.fp], [row.fn, row.tp]],
    }
