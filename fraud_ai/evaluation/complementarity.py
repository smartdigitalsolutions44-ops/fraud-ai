"""Does a second model add signal where the first one fails? (Research only.)

The question is not whether model B beats model A by a point estimate. It is:

* **Disagreement groups.** Events are sorted into four groups, each model at its own
  recorded threshold:
  * A high / B low;
  * A low / B high;
  * both high;
  * both low.

  For each group the report gives the fraud prevalence, the fraud types, the scenarios and
  a few behavioural traits, to show whether disagreements are genuinely different
  behaviour.
* **A's misses and false alarms.** Among A's false negatives, how many does B catch? Among
  A's false positives, how many does B clear?
* **B inside A's blind spot.** How well does B rank fraud among the events A scores low
  (PR-AUC only if there are enough examples)?
* **Combinations** (experimental, never persisted):
  * the average probability of A and B;
  * a rank average of A, B and, optionally, an anomaly score.

  Ranks come from each model's *validation* score distribution, so the test labels are
  never used to build the combination. Each combination gets a PR-AUC interval and a paired
  difference against A.

Anomaly scores are treated as a separate signal. They are never read as fraud
probabilities.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

import numpy as np

from fraud_ai.evaluation.context import EvaluationContext, ScoredModel
from fraud_ai.evaluation.segments import MIN_CLASS
from fraud_ai.evaluation.stats import (
    Array,
    IntArray,
    bootstrap_metrics,
    paired_difference,
    ranking_metrics,
)
from fraud_ai.models.base import FRAUD_PROBABILITY

TRAITS = (
    "new_device",
    "new_address",
    "recent_password_reset",
    "vpn_detected",
    "device_seen_before",
)


def _cdf(reference: Array, values: Array) -> Array:
    """Empirical CDF of ``values`` against a reference distribution (validation scores)."""
    ref = np.sort(reference)
    return np.asarray(
        np.searchsorted(ref, values, side="right") / max(1, len(ref)), dtype=np.float64
    )


def _group_profile(ctx: EvaluationContext, split: str, mask: np.ndarray) -> dict[str, Any]:
    idx = ctx.indices(split)
    y = ctx.labels(split)
    vectors = ctx.vectors(split)
    n, fraud = int(mask.sum()), int(y[mask].sum())
    fraud_rows = [i for i in range(len(y)) if mask[i] and y[i] == 1]
    traits = {}
    for trait in TRAITS:
        with_trait = [i for i in range(len(y)) if mask[i] and vectors[i].values.get(trait) is True]
        traits[trait] = len(with_trait) / n if n else None
    return {
        "events": n,
        "fraud": fraud,
        "fraud_rate": fraud / n if n else None,
        "fraud_types": dict(Counter(str(ctx.fraud_types[idx[i]]) for i in fraud_rows)),
        "scenarios": dict(Counter(ctx.scenarios[idx[i]] for i in range(len(y)) if mask[i])),
        "trait_share": traits,
    }


def disagreement(
    ctx: EvaluationContext, a: ScoredModel, b: ScoredModel, split: str = "test"
) -> dict[str, Any]:
    high_a = a.scores[split] >= a.threshold
    high_b = b.scores[split] >= b.threshold
    groups = {
        f"{a.model_id}_high_{b.model_id}_low": high_a & ~high_b,
        f"{a.model_id}_low_{b.model_id}_high": ~high_a & high_b,
        "both_high": high_a & high_b,
        "both_low": ~high_a & ~high_b,
    }
    return {
        "split": split,
        "thresholds": {a.model_id: a.threshold, b.model_id: b.threshold},
        "groups": {name: _group_profile(ctx, split, mask) for name, mask in groups.items()},
    }


def _combination(
    y: IntArray, p: Array, reference: Array, iterations: int, seed: int
) -> dict[str, Any]:
    ci = bootstrap_metrics(np.asarray(y, dtype=int), p, 0.5, iterations=iterations, seed=seed)
    diff = paired_difference(
        np.asarray(y, dtype=int), p, reference, iterations=iterations, seed=seed
    )
    return {
        "pr_auc": ci["pr_auc"].to_dict(),
        "roc_auc": ci["roc_auc"].to_dict(),
        "vs_base_pr_auc_difference": diff["difference"],
        "adds_signal": bool(
            diff["interval_excludes_zero"] and (diff["difference"]["estimate"] or 0) > 0
        ),
    }


def complementarity(
    ctx: EvaluationContext,
    base: ScoredModel,
    other: ScoredModel,
    *,
    anomaly: ScoredModel | None = None,
    iterations: int = 1000,
    seed: int = 0,
    split: str = "test",
) -> dict[str, Any]:
    y = ctx.labels(split)
    pa, pb = base.scores[split], other.scores[split]
    high_a, high_b = pa >= base.threshold, pb >= other.threshold
    fn_a = (y == 1) & ~high_a
    fp_a = (y == 0) & high_a
    low_a = ~high_a
    blind: dict[str, Any] = {
        "events_base_scores_low": int(low_a.sum()),
        "fraud_among_them": int(y[low_a].sum()),
    }
    sub = ranking_metrics(y[low_a], pb[low_a])
    enough = int(y[low_a].sum()) >= MIN_CLASS
    blind[f"{other.model_id}_pr_auc_within"] = sub["pr_auc"] if enough else None
    if anomaly is not None:
        blind[f"{anomaly.model_id}_pr_auc_within"] = (
            ranking_metrics(y[low_a], anomaly.scores[split][low_a])["pr_auc"] if enough else None
        )
    if not enough:
        blind["note"] = (
            f"only {int(y[low_a].sum())} fraud events are below the base "
            f"threshold: PR-AUC within that group needs >= {MIN_CLASS}"
        )
    misses = {
        "base_false_negatives": int(fn_a.sum()),
        "caught_by_other": int((fn_a & high_b).sum()),
        "base_false_positives": int(fp_a.sum()),
        "cleared_by_other": int((fp_a & ~high_b).sum()),
        "other_new_false_positives": int(((y == 0) & ~high_a & high_b).sum()),
    }
    if anomaly is not None:
        top = anomaly.scores[split] >= 0.95
        misses["base_false_negatives_with_anomaly_score_>=_0.95"] = int((fn_a & top).sum())
    va, vb = base.scores["validation"], other.scores["validation"]
    combos: dict[str, Array] = {"rank_average": (_cdf(va, pa) + _cdf(vb, pb)) / 2}
    if other.model.score_kind == FRAUD_PROBABILITY:  # never average a probability with an
        combos["average_probability"] = (pa + pb) / 2  # anomaly score

    if anomaly is not None:
        vn = anomaly.scores["validation"]
        combos["rank_average_with_anomaly"] = (
            _cdf(va, pa) + _cdf(vb, pb) + _cdf(vn, anomaly.scores[split])
        ) / 3
    return {
        "base": base.model_id,
        "other": other.model_id,
        "anomaly": anomaly.model_id if anomaly else None,
        "split": split,
        "disagreement": disagreement(ctx, base, other, split),
        "base_misses_and_false_alarms": misses,
        "fraud_detection_overlap": detection_overlap(ctx, base, other, split),
        "within_base_blind_spot": blind,
        "combinations": {
            name: _combination(y, p, pa, iterations, seed) for name, p in combos.items()
        },
        "note": "Research only: no combination is persisted or activated. 'adds_signal' "
        "requires the paired PR-AUC difference interval to lie above zero. Rank "
        "transforms use validation score distributions. Data is SYNTHETIC.",
    }


def detection_overlap(
    ctx: EvaluationContext, base: ScoredModel, other: ScoredModel, split: str = "test"
) -> dict[str, Any]:
    """Which fraud each model catches at its own threshold: both, only one, or neither."""
    y = ctx.labels(split)
    idx = ctx.indices(split)
    a = base.scores[split] >= base.threshold
    b = other.scores[split] >= other.threshold
    fraud = y == 1
    groups = {
        "caught_by_both": fraud & a & b,
        f"caught_only_by_{base.model_id}": fraud & a & ~b,
        f"caught_only_by_{other.model_id}": fraud & ~a & b,
        "missed_by_both": fraud & ~a & ~b,
    }
    out: dict[str, Any] = {"fraud_events": int(fraud.sum())}
    for name, mask in groups.items():
        rows = np.flatnonzero(mask)
        out[name] = {
            "count": len(rows),
            "fraud_types": dict(Counter(str(ctx.fraud_types[idx[i]]) for i in rows)),
            "scenarios": dict(Counter(ctx.scenarios[idx[i]] for i in rows)),
        }
    out["legitimate_flagged_only_by_other"] = int((~fraud & ~a & b).sum())
    return out
