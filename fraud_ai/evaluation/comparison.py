"""Model comparison on identical examples: paired tests, agreement, ensemble research.

Nothing here selects or activates a model. Ensembles are evaluated experimentally and never
persisted. The ensemble weights and the "reference" single model are chosen on the
*validation* split, so the test split stays untouched by any selection.
"""

from __future__ import annotations

import itertools
from typing import Any

import numpy as np

from fraud_ai.evaluation.context import EvaluationContext, ScoredModel
from fraud_ai.evaluation.stats import (
    Array,
    IntArray,
    bootstrap_metrics,
    mcnemar,
    paired_difference,
    ranking_metrics,
)


def pairwise_tests(
    ctx: EvaluationContext, *, iterations: int, seed: int, split: str = "test"
) -> list[dict[str, Any]]:
    y = ctx.labels(split)
    out = []
    for a, b in itertools.combinations(ctx.models, 2):
        diff = paired_difference(
            y, a.scores[split], b.scores[split], iterations=iterations, seed=seed
        )
        test = mcnemar(y, a.scores[split], b.scores[split], a.threshold, b.threshold)
        out.append(
            {
                "a": a.model_id,
                "b": b.model_id,
                "pr_auc_a": diff["a"],
                "pr_auc_b": diff["b"],
                "pr_auc_difference": diff["difference"],
                "bootstrap_p_value": diff["p_value"],
                "difference_interval_excludes_zero": diff["interval_excludes_zero"],
                "mcnemar": {**test, "thresholds": [a.threshold, b.threshold]},
                "conclusion": (
                    "the PR-AUC difference interval excludes zero on this split"
                    if diff["interval_excludes_zero"]
                    else "no reliable difference: the PR-AUC difference interval includes zero"
                ),
            }
        )
    return out


def agreement(ctx: EvaluationContext, split: str = "test") -> dict[str, Any]:
    """Group events by which models flag them (each at its own threshold)."""
    y = ctx.labels(split)
    high = {m.model_id: m.scores[split] >= m.threshold for m in ctx.models}
    names = list(high)
    groups: dict[str, list[int]] = {}
    for i in range(len(y)):
        flagged = [n for n in names if high[n][i]]
        if not flagged:
            key = "all_low"
        elif len(flagged) == len(names):
            key = "all_high"
        elif len(flagged) == 1:
            key = f"only_{flagged[0]}_high"
        else:
            key = "mixed"
        groups.setdefault(key, []).append(i)
    total_fraud = int(y.sum())
    rows = []
    for key in sorted(groups, key=lambda k: (-len(groups[k]), k)):
        idx = groups[key]
        fraud = int(y[idx].sum())
        rows.append(
            {
                "group": key,
                "events": len(idx),
                "fraud": fraud,
                "fraud_rate": fraud / len(idx),
                "share_of_all_fraud": fraud / total_fraud if total_fraud else None,
            }
        )
    return {
        "split": split,
        "models": names,
        "thresholds": {m.model_id: m.threshold for m in ctx.models},
        "groups": rows,
    }


def _ensembles(ctx: EvaluationContext, split: str, weights: dict[str, float]) -> dict[str, Array]:
    probs = np.vstack([m.scores[split] for m in ctx.models])
    votes = np.vstack([m.scores[split] >= m.threshold for m in ctx.models]).astype(float)
    w = np.asarray([weights[m.model_id] for m in ctx.models])
    return {
        "average_probability": probs.mean(axis=0),
        "weighted_probability": (w[:, None] * probs).sum(axis=0) / w.sum(),
        "majority_vote_fraction": votes.mean(axis=0),
    }


def ensemble_research(ctx: EvaluationContext, *, iterations: int, seed: int) -> dict[str, Any]:
    if len(ctx.models) < 2:
        return {"note": "needs at least two models"}
    y_val, y_test = ctx.labels("validation"), ctx.labels("test")
    val_pr = {
        m.model_id: ranking_metrics(y_val, m.scores["validation"])["pr_auc"] or 0.0
        for m in ctx.models
    }
    weights = {k: max(v, 1e-6) for k, v in val_pr.items()}
    reference = max(ctx.models, key=lambda m: (val_pr[m.model_id], m.model_id))
    test_scores = _ensembles(ctx, "test", weights)
    results = {}
    for name, p in test_scores.items():
        threshold = 0.5
        ci = bootstrap_metrics(y_test, p, threshold, iterations=iterations, seed=seed)
        vs = paired_difference(
            y_test, p, reference.scores["test"], iterations=iterations, seed=seed
        )
        results[name] = {
            "pr_auc": ci["pr_auc"].to_dict(),
            "roc_auc": ci["roc_auc"].to_dict(),
            "recall_at_0_5": ci["recall"].to_dict(),
            "fpr_at_0_5": ci["fpr"].to_dict(),
            "vs_reference_pr_auc_difference": vs["difference"],
            "appears_useful": bool(
                vs["interval_excludes_zero"] and (vs["difference"]["estimate"] or 0) > 0
            ),
        }
    return {
        "reference_model": reference.model_id,
        "reference_chosen_by": "highest validation PR-AUC (test not used for selection)",
        "weights_from_validation_pr_auc": weights,
        "ensembles": results,
        "note": "Experimental only - no ensemble is persisted or activated. 'appears_useful' "
        "requires the paired PR-AUC difference interval to lie above zero.",
    }


def bootstrap_all(
    ctx: EvaluationContext,
    model: ScoredModel,
    *,
    iterations: int,
    level: float,
    seed: int,
    threshold: float | None = None,
) -> dict[str, Any]:
    t = model.threshold if threshold is None else threshold
    out = {}
    for split in ("validation", "test"):
        y: IntArray = ctx.labels(split)
        cis = bootstrap_metrics(
            y, model.scores[split], t, iterations=iterations, level=level, seed=seed
        )
        out[split] = {
            "fraud": int(y.sum()),
            "n": len(y),
            "metrics": {k: v.to_dict() for k, v in cis.items()},
        }
    return {
        "threshold": t,
        "iterations": iterations,
        "level": level,
        "seed": seed,
        "method": "stratified percentile bootstrap (class counts fixed per resample)",
        **out,
    }
