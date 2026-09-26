"""Evaluation of an anomaly-score model (``fraud-ai anomaly evaluate``).

The question is **whether unusual behaviour lines up with fraud** on this dataset. It is
not whether the autoencoder "detects fraud": it detects unusual behaviour, and legitimate
customers can be unusual too. The report covers:

* **Score distributions** of fraud and legitimate test events.
* **Ranking quality** (PR-AUC, ROC-AUC) of the anomaly score, with bootstrap intervals.
* **Flagging behaviour** at anomaly thresholds of 0.90, 0.95 and 0.99: the share of events
  flagged, fraud recall, FPR and precision.
* **Scenarios:** fraud recall per fraud scenario (including stealthy takeovers), and how
  often legitimate scenarios look unusual.
* **Distribution shift:** the monthly share of legitimate events above 0.95 across the
  whole window. A rise means later behaviour differs from the training reference.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import numpy as np

from fraud_ai.evaluation.context import EvaluationContext, ScoredModel
from fraud_ai.evaluation.segments import scenario_report
from fraud_ai.evaluation.stats import bootstrap_metrics, threshold_metrics

THRESHOLDS = (0.90, 0.95, 0.99)
QUANTILES = (0.10, 0.25, 0.50, 0.75, 0.90, 0.99)


def _distribution(values: np.ndarray) -> dict[str, Any]:
    if len(values) == 0:
        return {"n": 0}
    return {
        "n": len(values),
        "mean": float(values.mean()),
        **{f"p{int(q * 100)}": float(np.quantile(values, q)) for q in QUANTILES},
    }


def anomaly_evaluation(
    ctx: EvaluationContext,
    model: ScoredModel,
    *,
    iterations: int = 1000,
    seed: int = 0,
    split: str = "test",
) -> dict[str, Any]:
    y = ctx.labels(split)
    score = model.scores[split]
    flagging = []
    for t in THRESHOLDS:
        m = threshold_metrics(y, score, t)
        flagging.append(
            {
                "threshold": t,
                "flagged_share": float(np.mean(score >= t)),
                "recall": m["recall"],
                "fpr": m["fpr"],
                "precision": m["precision"],
            }
        )
    ci = bootstrap_metrics(y, score, 0.95, iterations=iterations, seed=seed)
    monthly: dict[str, list[float]] = defaultdict(list)
    examples = ctx.prepared.dataset.examples
    for part in ("train", "validation", "test"):
        for i, s in zip(ctx.indices(part), model.scores[part], strict=True):
            if ctx.prepared.y[i] == 0:
                monthly[examples[i].event_time.strftime("%Y-%m")].append(float(s))
    shift = [
        {
            "month": month,
            "legitimate_events": len(v),
            "mean_anomaly_score": float(np.mean(v)),
            "share_above_0_95": float(np.mean(np.asarray(v) >= 0.95)),
        }
        for month, v in sorted(monthly.items())
    ]
    return {
        "split": split,
        "score_kind": "anomaly_score (fraction of training legitimate events that reconstruct "
        "better) - NOT a fraud probability",
        "distributions": {
            "fraud": _distribution(score[y == 1]),
            "legitimate": _distribution(score[y == 0]),
        },
        "ranking": {
            "pr_auc": ci["pr_auc"].to_dict(),
            "roc_auc": ci["roc_auc"].to_dict(),
            "prevalence": float(y.mean()) if len(y) else None,
        },
        "flagging": flagging,
        "scenarios": scenario_report(ctx, model, split, threshold=0.95),
        "legitimate_shift_by_month": shift,
        "note": "An anomaly score measures unusual behaviour, not fraud. By construction "
        "about 5% of legitimate TRAINING events score >= 0.95. Data is SYNTHETIC.",
    }
