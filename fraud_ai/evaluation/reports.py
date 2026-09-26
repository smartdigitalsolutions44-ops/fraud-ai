"""Evaluation reports and their persistence.

Artefacts are written as sorted, indented JSON under ``<EVALUATION_DIRECTORY>/<model-id>/``
(or ``comparisons/<dataset>/`` for multi-model reports). Every file starts with a header
naming the report, the evaluation version, the model(s), the dataset fingerprint, the
feature version and the configuration used (including the random seed).

Reports are reproducible: apart from ``generated_at`` the same database, model and settings
produce byte-identical files (tested).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.models import ModelCalibration
from fraud_ai.evaluation.calibration import compare_calibrations
from fraud_ai.evaluation.comparison import (
    agreement,
    bootstrap_all,
    ensemble_research,
    pairwise_tests,
)
from fraud_ai.evaluation.context import EvaluationContext, ScoredModel
from fraud_ai.evaluation.costs import CostConfig, band_analysis, cost_curve
from fraud_ai.evaluation.drift import TRACKED_FEATURES, build_baseline, compare_to_baseline
from fraud_ai.evaluation.segments import cohort_report, error_report, scenario_report
from fraud_ai.evaluation.walk_forward import WalkForwardConfig, walk_forward
from fraud_ai.models.metrics import threshold_analysis
from fraud_ai.utils.time import utcnow


class CalibrationConflictError(FraudAIError):
    pass


@dataclass(frozen=True)
class EvaluationSettings:
    iterations: int = 1000
    level: float = 0.95
    seed: int = 0
    threshold: float | None = None
    costs: CostConfig = field(default_factory=CostConfig)
    bands: tuple[float, float] = (0.30, 0.70)
    walk_forward: WalkForwardConfig = field(default_factory=WalkForwardConfig)
    error_limit: int = 50

    def to_dict(self) -> dict[str, Any]:
        return {
            "iterations": self.iterations,
            "level": self.level,
            "seed": self.seed,
            "threshold": self.threshold,
            "costs": self.costs.to_dict(),
            "bands": list(self.bands),
            "walk_forward": self.walk_forward.to_dict(),
            "error_limit": self.error_limit,
        }


def _with_header(
    ctx: EvaluationContext,
    name: str,
    settings: EvaluationSettings,
    body: dict[str, Any],
    model: ScoredModel | None = None,
) -> dict[str, Any]:
    extra = {"model": model.model_id} if model else {}
    return {**ctx.header(name, settings=settings.to_dict(), **extra), **body}


def confidence(ctx: EvaluationContext, model: ScoredModel, s: EvaluationSettings) -> dict[str, Any]:
    return _with_header(
        ctx,
        "confidence",
        s,
        bootstrap_all(
            ctx, model, iterations=s.iterations, level=s.level, seed=s.seed, threshold=s.threshold
        ),
        model,
    )


def thresholds(ctx: EvaluationContext, model: ScoredModel, s: EvaluationSettings) -> dict[str, Any]:
    y, p = ctx.labels("test"), model.scores["test"]
    return _with_header(
        ctx,
        "thresholds",
        s,
        {
            "threshold_analysis": threshold_analysis(y, p).to_list(),
            "bands": band_analysis(y, p, s.costs, s.bands, amounts=ctx.amounts("test")),
        },
        model,
    )


def calibration(
    ctx: EvaluationContext, model: ScoredModel, s: EvaluationSettings
) -> dict[str, Any]:
    body = compare_calibrations(
        model.scores["validation"],
        ctx.labels("validation"),
        model.scores["test"],
        ctx.labels("test"),
    )
    return _with_header(ctx, "calibration", s, body, model)


def persist_calibrations(
    session: Session, ctx: EvaluationContext, model: ScoredModel, report: dict[str, Any]
) -> list[ModelCalibration]:
    """Store fitted calibrators with the model version (idempotent; conflicts refused)."""
    rows = []
    for method, result in report["methods"].items():
        if method == "uncalibrated" or "calibrator" not in result:
            continue
        params = result["calibrator"]["parameters"]
        existing = session.scalar(
            select(ModelCalibration).where(
                ModelCalibration.model_version_id == model.record.model_version_id,
                ModelCalibration.method == method,
                ModelCalibration.dataset_fingerprint == ctx.fingerprint,
            )
        )
        if existing is not None:
            if existing.parameters != params:
                raise CalibrationConflictError(
                    f"{model.model_id} already has a different {method} calibration for this "
                    "dataset"
                )
            rows.append(existing)
            continue
        row = ModelCalibration(
            model_version_id=model.record.model_version_id,
            method=method,
            fitted_on=result["fitted_on"],
            dataset_fingerprint=ctx.fingerprint,
            parameters=params,
            metrics={k: v for k, v in result["test"].items() if k != "reliability"},
        )
        session.add(row)
        rows.append(row)
    session.flush()
    return rows


def scenarios(ctx: EvaluationContext, model: ScoredModel, s: EvaluationSettings) -> dict[str, Any]:
    return _with_header(
        ctx,
        "scenarios",
        s,
        {
            "scenarios": scenario_report(ctx, model, threshold=s.threshold),
            "cohorts": cohort_report(ctx, model, threshold=s.threshold),
        },
        model,
    )


def errors(ctx: EvaluationContext, model: ScoredModel, s: EvaluationSettings) -> dict[str, Any]:
    return _with_header(
        ctx,
        "errors",
        s,
        error_report(ctx, model, threshold=s.threshold, limit=s.error_limit),
        model,
    )


def costs(ctx: EvaluationContext, model: ScoredModel, s: EvaluationSettings) -> dict[str, Any]:
    y, p = ctx.labels("test"), model.scores["test"]
    amounts = ctx.amounts("test")
    return _with_header(
        ctx,
        "costs",
        s,
        {
            "manual_review": cost_curve(y, p, s.costs, amounts=amounts, action="review"),
            "step_up": cost_curve(y, p, s.costs, amounts=amounts, action="step_up"),
        },
        model,
    )


def walk_forward_report(
    ctx: EvaluationContext, model: ScoredModel, s: EvaluationSettings
) -> dict[str, Any]:
    return _with_header(ctx, "walk_forward", s, walk_forward(ctx, model, s.walk_forward), model)


def drift_baseline(
    ctx: EvaluationContext, s: EvaluationSettings, model: ScoredModel | None = None
) -> dict[str, Any]:
    train_matrix = ctx.prepared.part("train")[0]
    baseline = build_baseline(train_matrix, TRACKED_FEATURES)
    # Demonstration of the comparison: the later test period against the training reference.
    test_comparison = compare_to_baseline(baseline, ctx.prepared.part("test")[0])
    return _with_header(
        ctx,
        "drift_baseline",
        s,
        {
            "reference": "training split",
            "baseline": baseline,
            "test_period_vs_baseline": test_comparison,
            "limitations": "univariate only; bins from one training window; PSI thresholds are "
            "conventions; drift signals a need to re-evaluate, not a failure",
        },
        model,
    )


def compare(ctx: EvaluationContext, s: EvaluationSettings) -> dict[str, Any]:
    return _with_header(
        ctx,
        "compare",
        s,
        {
            "pairwise": pairwise_tests(ctx, iterations=s.iterations, seed=s.seed),
            "agreement": agreement(ctx),
            "ensembles": ensemble_research(ctx, iterations=s.iterations, seed=s.seed),
            "confidence": {
                m.model_id: bootstrap_all(
                    ctx, m, iterations=s.iterations, level=s.level, seed=s.seed
                )["test"]
                for m in ctx.models
            },
        },
    )


def summary(
    ctx: EvaluationContext,
    model: ScoredModel,
    reports: dict[str, dict[str, Any]],
    s: EvaluationSettings,
) -> dict[str, Any]:
    test = reports["confidence"]["test"]["metrics"] if "confidence" in reports else {}
    body: dict[str, Any] = {
        "test_fraud_examples": int(ctx.labels("test").sum()),
        "headline_with_intervals": test,
        "reports": sorted(reports),
    }
    if "calibration" in reports:
        body["lowest_test_brier_calibration"] = reports["calibration"]["lowest_test_brier"]
    if "scenarios" in reports:
        body["flagged_cohorts"] = [
            c["cohort"]
            for c in reports["scenarios"]["cohorts"]["cohorts"]
            if c["flagged_higher_fpr"]
        ]
    if "walk_forward" in reports:
        body["walk_forward_pr_auc"] = reports["walk_forward"]["stability"]["pr_auc"]
    return _with_header(ctx, "summary", s, body, model)


def write_report(directory: Path, name: str, report: dict[str, Any]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.json"
    stamped = {**report, "generated_at": utcnow().isoformat()}
    path.write_text(json.dumps(stamped, indent=2, sort_keys=True, default=str) + "\n")
    return path


MODEL_REPORTS = {
    "confidence": confidence,
    "thresholds": thresholds,
    "calibration": calibration,
    "scenarios": scenarios,
    "errors": errors,
    "costs": costs,
    "walk_forward": walk_forward_report,
}


def full_model_report(
    ctx: EvaluationContext,
    model: ScoredModel,
    s: EvaluationSettings,
    directory: Path,
    session: Session | None = None,
) -> dict[str, Path]:
    reports = {name: fn(ctx, model, s) for name, fn in MODEL_REPORTS.items()}
    reports["drift_baseline"] = drift_baseline(ctx, s, model)
    if session is not None:
        persist_calibrations(session, ctx, model, reports["calibration"])
    reports["summary"] = summary(ctx, model, reports, s)
    return {name: write_report(directory, name, r) for name, r in reports.items()}
