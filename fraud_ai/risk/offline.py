"""Offline policy work on historical labelled events (Stage 4 infrastructure).

* :func:`propose_policy` derives **experimental** decision bands from Stage 4 cost and
  threshold analysis, on the **validation split only**. It marks them as synthetic-derived
  and records the drift baselines that monitoring compares live traffic with.
* :func:`simulate` runs a policy over the **test split** through the same :func:`decide`
  as the live service. It changes no stored decision.
* :func:`compare_policies` runs two policies over exactly the same events and reports the
  paired differences, with a bootstrap interval for the cost difference.

Nothing here activates a policy. A cheaper result in one synthetic run is a finding, not a
reason to deploy.

**How the bands are derived** (on calibrated validation scores, grid 0.01-0.99):

* ``manual review`` lower bound: the lowest-cost threshold from ``cost_curve`` with the
  manual-review action cost;
* ``step-up`` lower bound: the lowest-cost threshold with the (cheaper) step-up action,
  capped at the review bound;
* ``monitoring`` lower bound: the highest threshold at or below step-up that still keeps
  ``monitor_recall`` (default 95%) of validation fraud at or above it;
* ``temporary block`` lower bound: the lowest threshold at or above review whose
  validation precision is at least ``block_precision`` (default 0.95) with at least
  ``min_block_support`` flagged events. If none qualifies, there is no block band.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any

import numpy as np
import numpy.typing as npt

from fraud_ai.core.enums import Decision
from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.models import ModelCalibration
from fraud_ai.evaluation.calibration import Calibrator
from fraud_ai.evaluation.context import EvaluationContext, build_context, pseudonym
from fraud_ai.evaluation.costs import CostConfig, cost_curve
from fraud_ai.evaluation.drift import TRACKED_FEATURES, build_baseline
from fraud_ai.evaluation.reports import EvaluationSettings, calibration, persist_calibrations
from fraud_ai.evaluation.stats import Array, IntArray, resample_indices
from fraud_ai.models.factory import is_anomaly_model
from fraud_ai.risk.engine import PolicyDecision, PolicyInputs, decide
from fraud_ai.risk.policy import (
    Band,
    CalibrationSpec,
    ModelSlot,
    RiskPolicyDefinition,
)
from fraud_ai.rules.ruleset import RULES_VERSION, get_rule_set

BoolArray = npt.NDArray[np.bool_]
GRID = tuple(round(0.01 * i, 2) for i in range(1, 100))
SCORE_BINS = tuple(round(0.1 * i, 1) for i in range(1, 10))
SYNTHETIC_NOTE = (
    "SYNTHETIC: derived from the bundled synthetic generator. These are experimental "
    "defaults, not validated operating points, and imply nothing about real fraud, losses "
    "or savings."
)


class OfflinePolicyError(FraudAIError):
    pass


@dataclass(frozen=True)
class PolicyCostConfig:
    """Experiment parameters for simulated cost (not facts).

    ``step_up_fraud_stop_rate`` is an explicit *assumption*: the share of fraud that a
    step-up challenge would stop. The synthetic data cannot measure it.
    """

    fraud_loss: float = 500.0
    manual_review_cost: float = 5.0
    step_up_cost: float = 1.0
    monitoring_cost: float = 0.1
    false_positive_friction: float = 10.0
    temporary_block_friction: float = 30.0
    step_up_fraud_stop_rate: float = 0.5

    def __post_init__(self) -> None:
        if not 0.0 <= self.step_up_fraud_stop_rate <= 1.0:
            raise ValueError("step_up_fraud_stop_rate must be in [0, 1]")
        if min(asdict(self).values()) < 0:
            raise ValueError("costs must not be negative")

    def event_cost(self, decision: Decision, fraud: bool) -> float:
        if decision is Decision.ALLOW:
            return self.fraud_loss if fraud else 0.0
        if decision is Decision.ALLOW_WITH_MONITORING:
            return self.monitoring_cost + (self.fraud_loss if fraud else 0.0)
        if decision is Decision.STEP_UP_AUTHENTICATION:
            missed = self.fraud_loss * (1 - self.step_up_fraud_stop_rate)
            return self.step_up_cost + (missed if fraud else self.false_positive_friction)
        if decision is Decision.MANUAL_REVIEW:
            return self.manual_review_cost + (0.0 if fraud else self.false_positive_friction)
        return self.manual_review_cost + (0.0 if fraud else self.temporary_block_friction)


# ---------------------------------------------------------------------- shared scoring
def _calibrate(slot: ModelSlot, raw: Array) -> Array:
    if slot.calibration is None:
        return raw
    return Calibrator.from_dict(
        {"method": slot.calibration.method, "parameters": slot.calibration.parameters}
    ).transform(raw)


def policy_refs(*definitions: RiskPolicyDefinition) -> list[str]:
    refs: list[str] = []
    for d in definitions:
        for slot in d.slots().values():
            if slot.ref not in refs:
                refs.append(slot.ref)
    return refs


def _context(session: Any, refs: list[str]) -> EvaluationContext:
    try:
        return build_context(session, refs, allow_anomaly=any(is_anomaly_model(r) for r in refs))
    except FraudAIError as exc:
        raise OfflinePolicyError(
            f"cannot evaluate {refs} on one dataset: {exc}. All models of the compared "
            "policies must be trained on the same recorded dataset."
        ) from None


@dataclass
class OfflineRun:
    decisions: list[PolicyDecision]
    labels: IntArray
    event_refs: list[str]
    primary_scores: Array


def run_policy(ctx: EvaluationContext, policy: RiskPolicyDefinition, split: str) -> OfflineRun:
    """Apply ``policy`` to every decision-point event of ``split`` (the same :func:`decide`
    as the live service)."""
    vectors = ctx.vectors(split)
    labels = ctx.labels(split)
    keep = [i for i, v in enumerate(vectors) if v.event_kind.value in policy.decision_event_kinds]
    if not keep:
        raise OfflinePolicyError(f"no {policy.decision_event_kinds} events in the {split} split")
    primary = _calibrate(policy.primary, ctx.model(policy.primary.ref).scores[split])
    flags: dict[str, Array] = {}
    for role in ("secondary", "sequence"):
        slot = getattr(policy, role)
        if slot is not None:
            flags[role] = ctx.model(slot.ref).scores[split] >= slot.threshold
    anomaly = None
    if policy.anomaly is not None:
        anomaly = ctx.model(policy.anomaly.ref).scores[split] >= policy.anomaly.threshold
    rules = get_rule_set(policy.rules_version)
    ids = ctx.indices(split)
    examples = ctx.prepared.dataset.examples
    decisions = []
    for i in keep:
        v = vectors[i]
        inputs = PolicyInputs(
            primary_score=float(primary[i]),
            rule_results=rules.evaluate(v.values, v.event_kind.value),
            secondary_flags={role: bool(f[i]) for role, f in flags.items()},
            anomaly_flag=None if anomaly is None else bool(anomaly[i]),
        )
        decisions.append(decide(policy, inputs))
    return OfflineRun(
        decisions,
        np.asarray(labels[keep], dtype=int),
        [pseudonym(examples[ids[i]].vector.event_id) for i in keep],
        np.asarray(primary[keep], dtype=np.float64),
    )


def _summary(run: OfflineRun, costs: PolicyCostConfig) -> dict[str, Any]:
    y = run.labels
    decisions = [d.decision for d in run.decisions]
    counts = Counter(d.value for d in decisions)
    fraud = y == 1
    by = {
        d.value: {
            "events": int(sum(1 for x in decisions if x is d)),
            "fraud": int(sum(1 for x, f in zip(decisions, fraud, strict=True) if x is d and f)),
        }
        for d in Decision
    }
    intervened = np.asarray(
        [d.severity >= Decision.MANUAL_REVIEW.severity for d in decisions], dtype=bool
    )
    challenged = np.asarray([d is Decision.STEP_UP_AUTHENTICATION for d in decisions])
    friction = np.asarray(
        [d.severity >= Decision.STEP_UP_AUTHENTICATION.severity for d in decisions]
    )
    cost = float(sum(costs.event_cost(d, bool(f)) for d, f in zip(decisions, fraud, strict=True)))
    reasons = Counter(code for d in run.decisions for code in d.reason_codes)
    n = len(y)
    return {
        "events": n,
        "fraud_events": int(fraud.sum()),
        "decision_distribution": {d.value: counts.get(d.value, 0) for d in Decision},
        "decision_rates": {d.value: counts.get(d.value, 0) / n for d in Decision},
        "by_decision": by,
        "fraud_caught": int((intervened & fraud).sum()),
        "fraud_challenged_step_up": int((challenged & fraud).sum()),
        "fraud_missed": int((~intervened & ~challenged & fraud).sum()),
        "step_up_volume": int(challenged.sum()),
        "manual_review_volume": counts.get(Decision.MANUAL_REVIEW.value, 0),
        "temporary_block_volume": counts.get(Decision.TEMPORARY_BLOCK.value, 0),
        "monitoring_volume": counts.get(Decision.ALLOW_WITH_MONITORING.value, 0),
        "false_positive_volume": int((friction & ~fraud).sum()),
        "false_positive_rate": float((friction & ~fraud).sum() / max(1, int((~fraud).sum()))),
        "estimated_cost": cost,
        "estimated_cost_per_1000_events": 1000 * cost / n if n else None,
        "reason_code_counts": dict(sorted(reasons.items())),
    }


def _header(ctx: EvaluationContext, split: str, costs: PolicyCostConfig) -> dict[str, Any]:
    return {
        "dataset_fingerprint": ctx.fingerprint,
        "split": split,
        "cost_config": asdict(costs),
        "cost_note": "costs and the step-up stop rate are experiment parameters "
        "(assumptions), not facts",
        "data_note": SYNTHETIC_NOTE,
        "stored_decisions_changed": False,
    }


def simulate(
    session: Any,
    policy: RiskPolicyDefinition,
    *,
    split: str = "test",
    costs: PolicyCostConfig | None = None,
) -> dict[str, Any]:
    costs = costs or PolicyCostConfig()
    ctx = _context(session, policy_refs(policy))
    run = run_policy(ctx, policy, split)
    return {
        "report": "policy_simulation",
        "policy_version": policy.policy_version,
        "policy_sha256": policy.sha256(),
        **_header(ctx, split, costs),
        **_summary(run, costs),
    }


def compare_policies(
    session: Any,
    a: RiskPolicyDefinition,
    b: RiskPolicyDefinition,
    *,
    split: str = "test",
    costs: PolicyCostConfig | None = None,
    iterations: int = 1000,
    seed: int = 0,
) -> dict[str, Any]:
    costs = costs or PolicyCostConfig()
    ctx = _context(session, policy_refs(a, b))
    run_a, run_b = run_policy(ctx, a, split), run_policy(ctx, b, split)
    if run_a.event_refs != run_b.event_refs:
        raise OfflinePolicyError(
            "the policies decide on different event sets (their decision_event_kinds "
            "differ); they cannot be compared on exactly the same events"
        )
    y = run_a.labels
    da = [d.decision for d in run_a.decisions]
    db = [d.decision for d in run_b.decisions]
    cross = Counter(f"{x.value}->{z.value}" for x, z in zip(da, db, strict=True))
    fraud = y == 1

    def caught(ds: list[Decision]) -> BoolArray:
        return np.asarray([d.severity >= Decision.MANUAL_REVIEW.severity for d in ds], dtype=bool)

    def friction(ds: list[Decision]) -> BoolArray:
        return np.asarray(
            [d.severity >= Decision.STEP_UP_AUTHENTICATION.severity for d in ds], dtype=bool
        )

    cost_a = np.asarray([costs.event_cost(d, bool(f)) for d, f in zip(da, fraud, strict=True)])
    cost_b = np.asarray([costs.event_cost(d, bool(f)) for d, f in zip(db, fraud, strict=True)])
    diffs = [
        float(cost_a[idx].sum() - cost_b[idx].sum())
        for idx in resample_indices(y, iterations, seed)
    ]
    lower, upper = np.quantile(diffs, [0.025, 0.975]) if diffs else (None, None)
    return {
        "report": "policy_comparison",
        "policy_a": a.policy_version,
        "policy_b": b.policy_version,
        **_header(ctx, split, costs),
        "a": _summary(run_a, costs),
        "b": _summary(run_b, costs),
        "same_events": len(y),
        "decisions_differ": int(sum(1 for x, z in zip(da, db, strict=True) if x is not z)),
        "decision_crosstab": dict(sorted(cross.items())),
        "fraud_caught_only_by_a": int((caught(da) & ~caught(db) & fraud).sum()),
        "fraud_caught_only_by_b": int((caught(db) & ~caught(da) & fraud).sum()),
        "false_positives_only_a": int((friction(da) & ~friction(db) & ~fraud).sum()),
        "false_positives_only_b": int((friction(db) & ~friction(da) & ~fraud).sum()),
        "cost_difference_a_minus_b": {
            "estimate": float(cost_a.sum() - cost_b.sum()),
            "lower_95": None if lower is None else float(lower),
            "upper_95": None if upper is None else float(upper),
            "bootstrap_iterations": iterations,
        },
        "note": "A cheaper policy in one synthetic run is a finding to investigate, never a "
        "reason to activate it. Activation is always an explicit, separate step.",
    }


# ---------------------------------------------------------------------- proposal
def _slot(ctx: EvaluationContext, ref: str, spec: CalibrationSpec | None = None) -> ModelSlot:
    record = ctx.model(ref).record
    if record.artifact_sha256 is None:
        raise OfflinePolicyError(f"{ref} has no artefact digest")
    threshold = record.default_threshold if record.default_threshold is not None else 0.5
    return ModelSlot(
        ref=ref, artifact_sha256=record.artifact_sha256, threshold=threshold, calibration=spec
    )


def _primary_calibration(session: Any, ctx: EvaluationContext, ref: str) -> CalibrationSpec:
    model = ctx.model(ref)
    report = calibration(ctx, model, EvaluationSettings())
    rows: list[ModelCalibration] = persist_calibrations(session, ctx, model, report)
    sigmoid = [r for r in rows if r.method == "sigmoid"]
    if not sigmoid:  # pragma: no cover - sigmoid always fits with both classes present
        raise OfflinePolicyError(f"no sigmoid calibration could be fitted for {ref}")
    row = sigmoid[0]
    return CalibrationSpec(
        calibration_id=str(row.calibration_id), method="sigmoid", parameters=row.parameters
    )


def derive_bands(
    y: IntArray,
    p: Array,
    costs: CostConfig,
    *,
    monitor_recall: float = 0.95,
    block_precision: float = 0.95,
    min_block_support: int = 5,
    min_fraud: int = 10,
) -> tuple[tuple[Band, ...], dict[str, Any]]:
    y = np.asarray(y, dtype=int)
    if int(y.sum()) < min_fraud or int((y == 0).sum()) < min_fraud:
        raise OfflinePolicyError(
            f"band derivation needs at least {min_fraud} fraud and {min_fraud} legitimate "
            f"validation events; found {int(y.sum())} fraud of {len(y)}. Bands derived from "
            "so few examples would be meaningless - use more (synthetic) data or a longer "
            "validation window"
        )
    review = float(
        cost_curve(y, p, costs, action="review", thresholds=GRID)["lowest_cost_threshold"]
    )
    step = float(
        cost_curve(y, p, costs, action="step_up", thresholds=GRID)["lowest_cost_threshold"]
    )
    step = min(step, review)
    total_fraud = int(y.sum())
    monitor = GRID[0]
    for t in GRID:
        if t <= step and int(((p >= t) & (y == 1)).sum()) >= monitor_recall * total_fraud:
            monitor = t
    monitor = min(monitor, step)
    block: float | None = None
    for t in GRID:
        if t <= review:  # strictly above review, so the review band always exists
            continue
        flagged = p >= t
        if int(flagged.sum()) >= min_block_support and (
            float((flagged & (y == 1)).sum()) / int(flagged.sum()) >= block_precision
        ):
            block = t
            break
    candidates = [
        (0.0, "very_low", Decision.ALLOW),
        (monitor, "moderate", Decision.ALLOW_WITH_MONITORING),
        (step, "elevated", Decision.STEP_UP_AUTHENTICATION),
        (review, "high", Decision.MANUAL_REVIEW),
    ]
    if block is not None:
        candidates.append((block, "extreme", Decision.TEMPORARY_BLOCK))
    bands: list[Band] = []
    for lower, level, decision in candidates:
        if bands and lower <= bands[-1].lower:
            # Coinciding bounds leave the earlier band empty: the stricter one replaces it.
            bands.pop()
            lower = max(lower, bands[-1].lower + 0.01) if bands else lower
        bands.append(Band(lower=lower, risk_level=level, decision=decision))
    rows = []
    for i, band in enumerate(bands):
        upper = bands[i + 1].lower if i + 1 < len(bands) else 1.0000001
        mask = (p >= band.lower) & (p < upper)
        rows.append(
            {
                "risk_level": band.risk_level,
                "decision": band.decision.value,
                "range": [band.lower, min(upper, 1.0)],
                "validation_events": int(mask.sum()),
                "validation_fraud": int((mask & (y == 1)).sum()),
            }
        )
    derivation = {
        "method": "stage4 cost_curve lowest-cost thresholds (review, step-up) + recall/"
        "precision targets (monitoring, temporary block) on calibrated VALIDATION scores",
        "grid": [GRID[0], GRID[-1], 0.01],
        "thresholds": {
            "monitoring": monitor,
            "step_up": step,
            "manual_review": review,
            "temporary_block": block,
        },
        "targets": {
            "monitor_recall": monitor_recall,
            "block_precision": block_precision,
            "min_block_support": min_block_support,
            "min_validation_fraud": min_fraud,
        },
        "cost_config": costs.to_dict(),
        "validation_bands": rows,
        "note": SYNTHETIC_NOTE,
    }
    return tuple(bands), derivation


def _histogram(values: Array, edges: tuple[float, ...] = SCORE_BINS) -> dict[str, float]:
    idx = np.searchsorted(np.asarray(edges), values, side="right")
    counts = Counter(int(i) for i in idx)
    n = max(1, len(values))
    return {f"bin:{i}": counts.get(i, 0) / n for i in range(len(edges) + 1)}


@dataclass(frozen=True)
class Proposal:
    definition: RiskPolicyDefinition
    derivation: dict[str, Any]


def propose_policy(
    session: Any,
    version: str,
    *,
    primary: str,
    secondary: str | None = None,
    sequence: str | None = None,
    anomaly: str | None = None,
    costs: CostConfig | None = None,
    monitor_recall: float = 0.95,
    block_precision: float = 0.95,
    description: str = "",
) -> Proposal:
    """Derive an experimental, synthetic-derived policy. Nothing is stored or activated."""
    costs = costs or CostConfig()
    refs = [r for r in (primary, secondary, sequence, anomaly) if r]
    if len(set(refs)) != len(refs):
        raise OfflinePolicyError("a model can fill only one role in a policy")
    ctx = _context(session, refs)
    spec = _primary_calibration(session, ctx, primary)
    primary_slot = _slot(ctx, primary, spec)
    y_val = ctx.labels("validation")
    p_val = _calibrate(primary_slot, ctx.model(primary).scores["validation"])
    bands, derivation = derive_bands(
        y_val, p_val, costs, monitor_recall=monitor_recall, block_precision=block_precision
    )
    kinds = sorted(
        {"transaction", "login"}
        & set(
            (ctx.model(primary).record.training_manifest or {}).get("dataset", {}).get("kinds", [])
        )
    ) or ["transaction"]
    anomaly_slot = None
    if anomaly:
        anomaly_slot = _slot(ctx, anomaly)
        if ctx.model(anomaly).record.default_threshold is None:
            anomaly_slot = anomaly_slot.model_copy(update={"threshold": 0.95})
    definition = RiskPolicyDefinition(
        policy_version=version,
        description=description or "experimental, synthetic-derived policy",
        primary=primary_slot,
        secondary=_slot(ctx, secondary) if secondary else None,
        sequence=_slot(ctx, sequence) if sequence else None,
        anomaly=anomaly_slot,
        bands=bands,
        rules_version=RULES_VERSION,
        rules_fingerprint=get_rule_set(RULES_VERSION).fingerprint(),
        decision_event_kinds=tuple(kinds),
        synthetic_derived=True,
    )
    validation_run = run_policy(ctx, definition, "validation")
    decisions = Counter(d.decision.value for d in validation_run.decisions)
    n = len(validation_run.decisions)
    baselines: dict[str, Any] = {
        "features": build_baseline(ctx.prepared.part("train")[0], TRACKED_FEATURES),
        "prediction": {"edges": list(SCORE_BINS), "reference": _histogram(p_val)},
        "decision_rates": {d.value: decisions.get(d.value, 0) / n for d in Decision},
        "fraud_prevalence": float(y_val.mean()),
        "validation_events": len(y_val),
    }
    if anomaly:
        baselines["anomaly_score"] = {
            "edges": list(SCORE_BINS),
            "reference": _histogram(ctx.model(anomaly).scores["validation"]),
        }
    derivation.update(
        {
            "dataset_fingerprint": ctx.fingerprint,
            "derived_on_split": "validation",
            "models": refs,
            "baselines": baselines,
        }
    )
    return Proposal(definition, derivation)
