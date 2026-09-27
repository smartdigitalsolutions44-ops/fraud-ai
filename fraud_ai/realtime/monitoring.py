"""Monitoring over stored assessments: operational metrics, drift warnings and shadow
evaluation.

Everything is computed from the database (the assessments are the record). The results
are reports and **warnings only**: nothing here retrains a model, changes a policy or
alters a decision.

**Drift** compares the assessments with the baselines the active policy recorded when it
was proposed (Stage 4 drift maths: PSI and Jensen-Shannon):

* feature drift on the tracked features, from the stored point-in-time snapshots;
* prediction drift on the calibrated primary score;
* decision-rate drift;
* fraud-prevalence drift, using the labels known *now* (these lag, so recent periods
  look cleaner than they are);
* anomaly-score drift, if the policy has an anomaly model.

PSI below 0.10 reads as stable, 0.10-0.25 as moderate and above 0.25 as significant. These
are conventions, not guarantees. With fewer than ``MIN_SAMPLE`` assessments no drift
status is reported at all.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

import numpy as np
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from fraud_ai.core.enums import Decision, LabelValue
from fraud_ai.database.models import (
    EventRecord,
    FeatureSnapshot,
    FraudLabel,
    ModelPrediction,
    RiskAssessment,
)
from fraud_ai.evaluation.drift import compare_to_baseline, js_distance, psi, status
from fraud_ai.features.snapshot import load_vector
from fraud_ai.models.matrix import ModelMatrix
from fraud_ai.realtime.review import queue_size
from fraud_ai.realtime.telemetry import percentiles
from fraud_ai.risk.registry import active_deployment, get_policy_record
from fraud_ai.utils.time import ensure_utc

MIN_SAMPLE = 30
PREVALENCE_WARNING_RATIO = 2.0


def _assessments(
    session: Session, since: datetime | None, policy_version: str | None = None
) -> list[RiskAssessment]:
    stmt = select(RiskAssessment)
    if since is not None:
        stmt = stmt.where(RiskAssessment.assessed_at >= since)
    if policy_version is not None:
        stmt = stmt.where(RiskAssessment.policy_version == policy_version)
    return list(session.scalars(stmt.order_by(RiskAssessment.assessed_at)))


def _fraud_events(session: Session, rows: list[RiskAssessment]) -> set[Any]:
    """Assessed events with a fraud label known now (event or transaction level)."""
    event_ids = [r.event_id for r in rows]
    txn_ids = [r.transaction_id for r in rows if r.transaction_id is not None]
    found: set[Any] = set()
    for i in range(0, max(len(event_ids), 1), 500):
        chunk_e = event_ids[i : i + 500]
        chunk_t = txn_ids[i : i + 500]
        if not chunk_e and not chunk_t:
            continue
        conditions = []
        if chunk_e:
            conditions.append(FraudLabel.event_id.in_(chunk_e))
        if chunk_t:
            conditions.append(FraudLabel.transaction_id.in_(chunk_t))
        for event_id, txn_id in session.execute(
            select(FraudLabel.event_id, FraudLabel.transaction_id).where(
                FraudLabel.label == LabelValue.FRAUD, or_(*conditions)
            )
        ):
            found.add(event_id)
            found.add(txn_id)
    return {r.event_id for r in rows if r.event_id in found or r.transaction_id in found}


def summary(session: Session, *, since: datetime | None = None) -> dict[str, Any]:
    rows = _assessments(session, since)
    decisions = Counter(r.decision.value for r in rows)
    fallbacks: Counter[str] = Counter()
    for r in rows:
        for failure in r.failures:
            fallbacks[failure.get("category", "unknown")] += 1
    stages: dict[str, list[float]] = defaultdict(list)
    for r in rows:
        for stage, ms in (r.latency_ms or {}).items():
            stages[stage].append(float(ms))
    compared = disagreed = 0
    for r in rows:
        for group in ("models", "policies"):
            for item in (r.shadow or {}).get(group, []):
                if "agrees" in item:
                    compared += 1
                    disagreed += 0 if item["agrees"] else 1
    events_stmt = select(func.count()).select_from(EventRecord)
    if since is not None:
        events_stmt = events_stmt.where(EventRecord.ingested_at >= since)
    n = len(rows)
    return {
        "since": since.isoformat() if since else None,
        "events_ingested": int(session.scalar(events_stmt) or 0),
        "assessments": n,
        "assessments_with_fallback": sum(1 for r in rows if r.fallback_used),
        "assessments_with_failures": sum(1 for r in rows if r.failures),
        "late_events": sum(1 for r in rows if "LATE_EVENT" in (r.reason_codes or [])),
        "decisions": {d.value: decisions.get(d.value, 0) for d in Decision},
        "decision_rates": {d.value: decisions.get(d.value, 0) / n if n else None for d in Decision},
        "fallbacks_by_category": dict(sorted(fallbacks.items())),
        "latency_ms": {stage: percentiles(v) for stage, v in sorted(stages.items())},
        "review_queue": queue_size(session),
        "shadow_comparisons": compared,
        "shadow_disagreement_rate": disagreed / compared if compared else None,
        "policies_seen": sorted({r.policy_version for r in rows}),
        "note": "latency excludes the final commit; computed from stored assessments",
    }


def _histogram(values: list[float], edges: list[float]) -> dict[str, float]:
    idx = np.searchsorted(np.asarray(edges), np.asarray(values), side="right")
    counts = Counter(int(i) for i in idx)
    n = max(1, len(values))
    return {f"bin:{i}": counts.get(i, 0) / n for i in range(len(edges) + 1)}


def _signal(reference: dict[str, float], current: dict[str, float], n: int) -> dict[str, Any]:
    if n < MIN_SAMPLE:
        return {"status": "insufficient_data", "rows": n, "min_rows": MIN_SAMPLE}
    value = psi(reference, current)
    return {
        "psi": round(value, 4),
        "js_distance": round(js_distance(reference, current), 4),
        "status": status(value),
        "rows": n,
    }


def _prevalence_status(rows: int, ratio: float | None) -> str:
    if rows < MIN_SAMPLE or ratio is None:
        return "insufficient_data"
    if ratio > PREVALENCE_WARNING_RATIO:
        return "shifted"
    if ratio < 1 / PREVALENCE_WARNING_RATIO:
        return "labels_pending_or_lower"  # expected while labels lag; not a warning
    return "stable"


def drift(session: Session, *, since: datetime | None = None) -> dict[str, Any]:
    deployment = active_deployment(session)
    if deployment is None:
        return {"status": "no_active_policy", "warnings": []}
    version = deployment.policy.policy_version
    baselines = (get_policy_record(session, version).derivation or {}).get("baselines")
    if not baselines:
        return {"status": "no_baseline", "policy_version": version, "warnings": []}
    rows = [r for r in _assessments(session, since, version) if r.mode == "live"]
    scored = [r for r in rows if r.calibrated_score is not None]
    out: dict[str, Any] = {"policy_version": version, "assessments": len(rows), "signals": {}}
    edges = baselines["prediction"]["edges"]
    out["signals"]["prediction"] = _signal(
        baselines["prediction"]["reference"],
        _histogram([float(r.calibrated_score or 0.0) for r in scored], edges),
        len(scored),
    )
    decisions = Counter(r.decision.value for r in rows)
    out["signals"]["decision_rates"] = _signal(
        baselines["decision_rates"],
        {d.value: decisions.get(d.value, 0) / max(1, len(rows)) for d in Decision},
        len(rows),
    )
    fraud = _fraud_events(session, rows)
    prevalence = len(fraud) / len(rows) if rows else None
    reference = baselines.get("fraud_prevalence")
    ratio = prevalence / reference if prevalence is not None and reference else None
    out["signals"]["fraud_prevalence"] = {
        "current_known_now": prevalence,
        "baseline": reference,
        "ratio": ratio,
        "status": _prevalence_status(len(rows), ratio),
        "note": "labels arrive late: recent prevalence is understated",
    }
    if "anomaly_score" in baselines:
        values = [
            float(r.model_scores["anomaly"]["raw"])
            for r in rows
            if "raw" in (r.model_scores or {}).get("anomaly", {})
        ]
        out["signals"]["anomaly_score"] = _signal(
            baselines["anomaly_score"]["reference"],
            _histogram(values, baselines["anomaly_score"]["edges"]),
            len(values),
        )
    vectors = []
    snapshot_ids = [r.prediction_id for r in rows if r.prediction_id is not None]
    for i in range(0, len(snapshot_ids), 500):
        for snapshot, event_time in session.execute(
            select(FeatureSnapshot, EventRecord.occurred_at)
            .join(
                ModelPrediction, ModelPrediction.feature_snapshot_id == FeatureSnapshot.snapshot_id
            )
            .join(EventRecord, EventRecord.event_id == FeatureSnapshot.event_id)
            .where(ModelPrediction.prediction_id.in_(snapshot_ids[i : i + 500]))
        ):
            vectors.append(load_vector(snapshot, ensure_utc(event_time)))
    feature_baseline = baselines["features"]
    if len(vectors) >= MIN_SAMPLE:
        comparison = compare_to_baseline(
            feature_baseline, ModelMatrix.from_vectors(vectors, feature_baseline["feature_version"])
        )
        out["signals"]["features"] = {
            name: {k: v for k, v in result.items() if k != "current"}
            for name, result in comparison["features"].items()
        }
    else:
        out["signals"]["features"] = {
            "status": "insufficient_data",
            "rows": len(vectors),
            "min_rows": MIN_SAMPLE,
        }
    warnings = []
    for name, signal in out["signals"].items():
        if name == "features" and "status" not in signal:
            for feature, result in signal.items():
                if result["status"] != "stable":
                    warnings.append(f"feature drift ({result['status']}): {feature}")
        elif signal.get("status") in ("moderate", "significant", "shifted"):
            warnings.append(f"{name} drift: {signal['status']}")
    out["warnings"] = warnings
    out["action"] = "warnings only: re-evaluate the model and policy offline; nothing is retrained"
    return out


def shadow_report(session: Session, *, since: datetime | None = None) -> dict[str, Any]:
    rows = [r for r in _assessments(session, since) if r.shadow]
    fraud = _fraud_events(session, rows)
    models: dict[str, dict[str, Any]] = {}
    policies: dict[str, dict[str, Any]] = {}
    for r in rows:
        is_fraud = r.event_id in fraud
        active_flag = r.decision.severity >= Decision.STEP_UP_AUTHENTICATION.severity
        active_caught = r.decision.severity >= Decision.MANUAL_REVIEW.severity
        for item in r.shadow.get("models", []):
            m = models.setdefault(
                item["model"],
                {"compared": 0, "agree": 0, "errors": 0, "fraud_only_shadow": 0,
                 "false_positives_only_shadow": 0, "fraud_only_active": 0, "latency": []},
            )  # fmt: skip
            if "error" in item:
                m["errors"] += 1
                continue
            m["compared"] += 1
            m["agree"] += int(item["agrees"])
            m["latency"].append(float(item.get("latency_ms", 0.0)))
            if item["flagged"] and not active_flag:
                if is_fraud:
                    m["fraud_only_shadow"] += 1
                else:
                    m["false_positives_only_shadow"] += 1
            if active_flag and not item["flagged"] and is_fraud:
                m["fraud_only_active"] += 1
        for item in r.shadow.get("policies", []):
            p = policies.setdefault(
                item["policy_version"],
                {"compared": 0, "agree": 0, "errors": 0, "fraud_caught_only_shadow": 0,
                 "false_positives_only_shadow": 0, "fraud_caught_only_active": 0,
                 "crosstab": Counter(), "latency": []},
            )  # fmt: skip
            if "error" in item:
                p["errors"] += 1
                continue
            shadow_decision = Decision(item["decision"])
            p["compared"] += 1
            p["agree"] += int(item["agrees"])
            p["crosstab"][f"{r.decision.value}->{shadow_decision.value}"] += 1
            p["latency"].append(float(item.get("latency_ms", 0.0)))
            shadow_caught = shadow_decision.severity >= Decision.MANUAL_REVIEW.severity
            shadow_flag = shadow_decision.severity >= Decision.STEP_UP_AUTHENTICATION.severity
            if shadow_caught and not active_caught and is_fraud:
                p["fraud_caught_only_shadow"] += 1
            if active_caught and not shadow_caught and is_fraud:
                p["fraud_caught_only_active"] += 1
            if shadow_flag and not active_flag and not is_fraud:
                p["false_positives_only_shadow"] += 1

    def finish(entry: dict[str, Any]) -> dict[str, Any]:
        compared = entry["compared"]
        latency = entry.pop("latency")
        entry["agreement_rate"] = entry["agree"] / compared if compared else None
        entry["disagreements"] = compared - entry["agree"]
        entry["latency_ms"] = percentiles(latency)
        if "crosstab" in entry:
            entry["crosstab"] = dict(sorted(entry["crosstab"].items()))
        return entry

    return {
        "assessments_with_shadow": len(rows),
        "labelled_fraud_among_them": len(fraud),
        "models": {k: finish(v) for k, v in sorted(models.items())},
        "policies": {k: finish(v) for k, v in sorted(policies.items())},
        "note": "labels known now only; 'false positives' are shadow-only flags without a "
        "fraud label, which may still become fraud later",
    }
