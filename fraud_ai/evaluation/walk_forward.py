"""Walk-forward (rolling-origin, expanding-window) evaluation.

    fold k:  train  [t0, t0 + (n+k)P)   validate [.., +P)   test [.., +P)

The most recent ``max_folds`` folds whose validation period is complete are evaluated (the
last test period may be partial).

For every fold a *fresh* model of the same kind, hyperparameters, seed and imbalance
strategy is trained. Leakage rules:

* features are point-in-time (Stage 2) and preprocessing is re-fitted on each fold's
  training rows only;
* **training labels are those known at the fold's training cutoff**: an example is used for
  training only if it has matured by then (``event + maturity <= cutoff``), and it is fraud
  only if a fraud label had been recorded by the cutoff - a chargeback arriving later can
  never inform an earlier fold;
* validation labels are as known at the validation cutoff; the validation-selected
  threshold is chosen there;
* test metrics use the eventual labels (the ground truth being measured).

Fold models are experiments: they are not registered and cannot be scored.
"""

from __future__ import annotations

import statistics
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any

import numpy as np

from fraud_ai.core.enums import LabelValue
from fraud_ai.datasets.labels import LabelDecision
from fraud_ai.evaluation.context import EvaluationContext, ScoredModel
from fraud_ai.evaluation.stats import bootstrap_metrics
from fraud_ai.models.estimators import KIND_BY_NAME, SPECS, BaselineModel, ModelError
from fraud_ai.models.metrics import evaluate_scores, select_threshold
from fraud_ai.utils.time import ensure_utc


@dataclass(frozen=True)
class WalkForwardConfig:
    period_days: int = 30
    initial_train_periods: int = 3
    max_folds: int = 12
    bootstrap_iterations: int = 200

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def label_as_of(
    decision: LabelDecision, event_time: datetime, cutoff: datetime, maturity: timedelta
) -> int | None:
    """The label a model trained at ``cutoff`` could have used (None = not usable)."""
    if ensure_utc(event_time) + maturity > cutoff:
        return None
    fraud_known = any(
        p.label is LabelValue.FRAUD and ensure_utc(p.labelled_at) <= cutoff
        for p in decision.provenance
    )
    return 1 if fraud_known else 0


def walk_forward(
    ctx: EvaluationContext, model: ScoredModel, config: WalkForwardConfig
) -> dict[str, Any]:
    prepared = ctx.prepared
    examples = prepared.dataset.examples
    decisions = prepared.dataset.labels
    times = [ensure_utc(e.event_time) for e in examples]
    manifest = model.record.training_manifest or {}
    maturity = timedelta(
        days=manifest.get("dataset", {}).get("label_policy", {}).get("maturity_days", 30)
    )
    period = timedelta(days=config.period_days)
    origin = min(times).replace(hour=0, minute=0, second=0, microsecond=0)
    last = max(times)
    kind = KIND_BY_NAME[model.record.model_name]
    # Folds need a full validation period; the most recent ``max_folds`` are evaluated, so
    # sparse early history cannot use up the fold budget.
    last_fold = int((last - origin) / period) - config.initial_train_periods - 1
    folds: list[dict[str, Any]] = []
    for k in range(max(0, last_fold - config.max_folds + 1), last_fold + 1):
        train_end = origin + period * (config.initial_train_periods + k)
        val_end, test_end = train_end + period, train_end + 2 * period
        train_idx, train_y, val_idx, val_y = [], [], [], []
        test_idx = []
        for i, t in enumerate(times):
            if t < train_end:
                label = label_as_of(decisions[i], t, train_end, maturity)
                if label is not None:
                    train_idx.append(i)
                    train_y.append(label)
            elif t < val_end:
                label = label_as_of(decisions[i], t, val_end, maturity)
                if label is not None:
                    val_idx.append(i)
                    val_y.append(label)
            elif t < test_end:
                test_idx.append(i)
        fold: dict[str, Any] = {
            "fold": k + 1,
            "train": {
                "start": origin.isoformat(),
                "end": train_end.isoformat(),
                "rows": len(train_idx),
                "fraud": int(sum(train_y)),
            },
            "validation": {
                "start": train_end.isoformat(),
                "end": val_end.isoformat(),
                "rows": len(val_idx),
                "fraud": int(sum(val_y)),
            },
            "test": {
                "start": val_end.isoformat(),
                "end": test_end.isoformat(),
                "rows": len(test_idx),
                "fraud": int(prepared.y[test_idx].sum()) if test_idx else 0,
            },
        }
        for part in ("train", "validation", "test"):
            rows, fraud = fold[part]["rows"], fold[part]["fraud"]
            fold[part]["prevalence"] = fraud / rows if rows else None
        if not test_idx or len(set(train_y)) < 2:
            fold["skipped"] = "training rows lack both classes or the test period is empty"
            folds.append(fold)
            continue
        fold_model = BaselineModel(
            SPECS[kind],
            f"{model.record.model_version}+fold{k + 1}",
            seed=model.model.seed,
            imbalance=model.model.imbalance,
            hyperparameters=model.model.hyperparameters,
            feature_version=model.model.feature_version,
        )
        try:
            fold_model.train(prepared.matrix.take(train_idx), train_y)
        except ModelError as exc:  # pragma: no cover - guarded above
            fold["skipped"] = str(exc)
            folds.append(fold)
            continue
        y_test = prepared.y[test_idx]
        p_test = fold_model.predict_proba(prepared.matrix.take(test_idx))
        selected = None
        if val_idx and len(set(val_y)) == 2:
            p_val = fold_model.predict_proba(prepared.matrix.take(val_idx))
            selected = select_threshold(np.asarray(val_y), p_val)
        metrics = evaluate_scores(y_test, p_test, model.threshold)
        metrics.pop("confusion_matrix", None)
        fold["model"] = {
            "base": model.model_id,
            "retrained_as": fold_model.model_id,
            "kind": kind,
            "seed": fold_model.seed,
            "hyperparameters": fold_model.hyperparameters,
            "registered": False,
        }
        fold["threshold"] = model.threshold
        fold["test_metrics"] = metrics
        if 0 < int(y_test.sum()) < len(y_test):
            ci = bootstrap_metrics(
                y_test, p_test, model.threshold, iterations=config.bootstrap_iterations, seed=k
            )
            fold["test_pr_auc_interval"] = ci["pr_auc"].to_dict()
        fold["validation_selected_threshold"] = selected
        if selected is not None:
            at = evaluate_scores(y_test, p_test, selected)
            fold["test_at_validation_threshold"] = {
                key: at[key] for key in ("precision", "recall", "fpr", "tp", "fp", "fn")
            }
        folds.append(fold)
    evaluated = [f for f in folds if "test_metrics" in f]

    def spread(key: str) -> dict[str, Any]:
        values = [f["test_metrics"][key] for f in evaluated if f["test_metrics"][key] is not None]
        if not values:
            return {"folds": 0}
        return {
            "folds": len(values),
            "mean": statistics.fmean(values),
            "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
            "min": min(values),
            "max": max(values),
        }

    return {
        "config": config.to_dict(),
        "maturity_days": maturity.total_seconds() / 86400,
        "base_model": model.model_id,
        "folds": folds,
        "stability": {k: spread(k) for k in ("pr_auc", "roc_auc", "recall", "precision", "fpr")},
        "note": "Fold models are fresh retrains (not registered). Training labels are as "
        "known at each fold's cutoff; test labels are the eventual ground truth.",
    }
