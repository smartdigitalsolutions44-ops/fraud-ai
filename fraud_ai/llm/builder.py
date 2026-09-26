"""Build the evidence packet for one event from TRUSTED, already-computed system outputs.

Sources, and nothing else:

* **Feature snapshot.** The event's point-in-time snapshot from Stage 2. A curated,
  non-identifying subset of feature values is included.
* **Model predictions.** The *stored* rows in ``model_predictions``. The event is **not
  rescored** here: an investigation needs predictions that already exist
  (``fraud-ai score``).
* **Calibrations.** The stored ``model_calibrations`` (sigmoid, fitted on validation) turn a
  stored probability into a calibrated one.
* **Model metadata.** Model thresholds, and gradient boosting's recorded permutation
  importance, which decides which features are "important".
* **Sequence.** The Stage 6 point-in-time sequence and its summary: change counts, cadence
  and a short timeline.
* **Labels.** Labels known *now* for the event. They are marked as such, so a claim of
  "confirmed fraud" can only rest on a real confirmation.
* **Cohorts.** Operational cohort and behavioural segment flags, computed from the
  snapshot. The synthetic ground-truth scenario is **never** included: it is a label.

Identifiers never enter the packet. The event is referred to by a one-way pseudonym;
there are no ids, IPs, addresses, devices, tokens or free text.
"""

from __future__ import annotations

import hashlib
import itertools
import statistics
import uuid
from collections.abc import Sequence
from typing import Any

import numpy as np
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from fraud_ai.core.enums import LabelValue
from fraud_ai.database.models import (
    EventRecord,
    FraudLabel,
    ModelCalibration,
    ModelPrediction,
    ModelVersion,
    Transaction,
    User,
)
from fraud_ai.evaluation.calibration import Calibrator
from fraud_ai.evaluation.segments import COHORTS, high_velocity, large_purchase
from fraud_ai.evaluation.stealth import sequence_summary
from fraud_ai.features.vector import FraudFeatureVector
from fraud_ai.llm.evidence import EvidenceError, EvidencePacket, EvidenceValue, assemble
from fraud_ai.models.factory import is_anomaly_model
from fraud_ai.models.registry import get_model_version
from fraud_ai.models.scoring import point_in_time_snapshot
from fraud_ai.sequences.definition import SequenceDefinition
from fraud_ai.sequences.extraction import build_sequence

UNCERTAIN = (0.3, 0.7)
TIMELINE_EVENTS = 6
TOP_FEATURES = 6
BASE_MODEL = "gradient-boosting"

FEATURE_SECTIONS: dict[str, tuple[str, ...]] = {
    "security_summary": (
        "recent_password_reset",
        "minutes_since_password_reset",
        "recent_email_change",
        "recent_phone_change",
        "recent_mfa_removed",
        "mfa_enabled",
        "rapid_multi_change_count",
    ),
    "transaction_summary": (
        "transaction_currency",
        "transaction_vs_median_ratio",
        "unusually_high_transaction",
        "transactions_last_1h",
        "transactions_last_24h",
        "time_since_previous_transaction_minutes",
        "new_payment_method",
        "payment_method_age_days",
        "payment_method_seen_before",
    ),
    "network_summary": (
        "network_type",
        "vpn_detected",
        "proxy_detected",
        "tor_detected",
        "datacenter_detected",
        "mobile_network",
        "network_seen_before",
        "country_changed",
        "asn_changed",
        "shared_network_flag",
        "accounts_per_network",
    ),
    "device_summary": (
        "new_device",
        "device_seen_before",
        "device_age_days",
        "device_trusted",
        "time_since_device_last_seen_hours",
        "devices_per_account",
        "device_changed_recently",
    ),
    "address_summary": (
        "new_address",
        "address_seen_before",
        "address_age_days",
        "address_verified",
        "address_changed_recently",
        "orders_to_address",
    ),
}
LIMITATIONS: dict[str, str] = {
    "synthetic_training_data": "Models were trained and evaluated on synthetic data only; "
    "their scores are not validated against real fraud.",
    "probabilities_not_certainty": "Model probabilities are model outputs, not certainty "
    "and not confirmation of fraud.",
    "friendly_fraud_unobservable": "Friendly fraud (a customer disputing their own genuine "
    "purchase) is not observable from these signals.",
    "vpn_not_proof": "VPN, proxy or datacenter use is a risk signal, not proof of fraud.",
    "shared_network_legitimate": "Shared networks such as offices and mobile carriers are "
    "commonly legitimate.",
    "new_account_false_positives": "New accounts had a higher false-positive rate in evaluation.",
    "sequence_models_limited": "Sequence models added little signal over gradient boosting "
    "in evaluation.",
    "raw_scores_overconfident": "Raw scores of class-weighted models are over-confident; "
    "calibrated values are shown where a calibrator exists.",
}


def event_ref(event_id: uuid.UUID) -> str:
    return "ev-" + hashlib.sha256(f"fraud-ai-investigation:{event_id}".encode()).hexdigest()[:16]


def _token(value: Any) -> str:
    return str(value).strip().lower().replace(" ", "_")[:64]


def _feature(vector: FraudFeatureVector, name: str) -> EvidenceValue:
    if name in vector.values:
        value = vector.values[name]
        if isinstance(value, bool | int | float) or value is None:
            return value
        return _token(value)
    reason = vector.missing.get(name)
    return f"missing:{reason.value}" if reason is not None else None


def _model_ref(p: ModelPrediction) -> str:
    return f"{p.model_name}-{p.model_version}"


def _calibrated(session: Session, record: ModelVersion, p: float) -> float | None:
    row = session.scalar(
        select(ModelCalibration).where(
            ModelCalibration.model_version_id == record.model_version_id,
            ModelCalibration.method == "sigmoid",
            ModelCalibration.dataset_fingerprint == record.dataset_fingerprint,
        )
    )
    if row is None:
        return None
    calibrator = Calibrator.from_dict({"method": row.method, "parameters": row.parameters})
    return float(calibrator.transform(np.asarray([p]))[0])


def build_evidence(
    session: Session, event_id: uuid.UUID, model_refs: Sequence[str] | None = None
) -> EvidencePacket:
    event = session.get(EventRecord, event_id)
    if event is None:
        raise EvidenceError(f"unknown event {event_id}")
    predictions = [
        p
        for p in session.scalars(
            select(ModelPrediction).where(ModelPrediction.event_id == event_id)
        )
        if not is_anomaly_model(p.model_name)
    ]
    if model_refs:
        wanted = set(model_refs)
        predictions = [p for p in predictions if _model_ref(p) in wanted]
        if missing := wanted - {_model_ref(p) for p in predictions}:
            raise EvidenceError(
                f"no stored prediction for {sorted(missing)}; score the event "
                "first (`fraud-ai score`) - investigations never rescore"
            )
    if not predictions:
        raise EvidenceError(
            "the event has no stored model predictions; score it first "
            "(`fraud-ai score`) - investigations never rescore"
        )
    predictions.sort(key=lambda p: (p.model_name != BASE_MODEL, _model_ref(p)))
    records = {}
    for p in predictions:
        record = get_model_version(session, p.model_name, p.model_version)
        if record is None:
            raise EvidenceError(f"{_model_ref(p)} is not registered")
        records[_model_ref(p)] = record
    feature_version = predictions[0].feature_version
    _, vector = point_in_time_snapshot(session, event_id, feature_version)

    entries: list[tuple[str, str, EvidenceValue, str]] = []

    def add(section: str, name: str, value: EvidenceValue, source: str) -> None:
        entries.append((section, name, value, source))

    # --- event
    user = session.get(User, event.user_id) if event.user_id else None
    synthetic = bool(user is not None and user.synthetic_scenario is not None)
    add("event_summary", "event_type", _token(event.event_type.value), "event_store")
    add(
        "event_summary",
        "event_time_utc",
        vector.event_timestamp.strftime("%Y-%m-%dt%H:%Mz"),
        "event_store",
    )
    add("event_summary", "data_origin", "synthetic" if synthetic else "unspecified", "event_store")
    add(
        "event_summary",
        "account_age_days",
        _feature(vector, "account_age_days"),
        "feature_snapshot",
    )

    # --- model scores (stored predictions; never rescored)
    flagged: dict[str, bool] = {}
    for p in predictions:
        ref = _model_ref(p)
        source = f"model_prediction:{ref}"
        flagged[ref] = p.fraud_probability >= p.threshold
        add("model_scores", f"{ref}.probability", float(p.fraud_probability), source)
        add("model_scores", f"{ref}.threshold", float(p.threshold), source)
        add("model_scores", f"{ref}.flagged", flagged[ref], source)
        calibrated = _calibrated(session, records[ref], p.fraud_probability)
        if calibrated is not None:
            add(
                "model_scores",
                f"{ref}.calibrated_probability",
                calibrated,
                f"model_calibration:{ref}",
            )

    # --- agreement
    n_flag = sum(flagged.values())
    pattern = "all_high" if n_flag == len(flagged) else ("all_low" if n_flag == 0 else "mixed")
    uncertain = sum(UNCERTAIN[0] <= p.fraud_probability <= UNCERTAIN[1] for p in predictions)
    add("model_agreement", "pattern", pattern, "model_predictions")
    add("model_agreement", "models_flagging", n_flag, "model_predictions")
    add("model_agreement", "models_total", len(flagged), "model_predictions")
    add("model_agreement", "models_uncertain", uncertain, "model_predictions")
    add("model_agreement", "uncertain_band_low", UNCERTAIN[0], "investigation_policy")
    add("model_agreement", "uncertain_band_high", UNCERTAIN[1], "investigation_policy")
    base = next((r for r in flagged if r.startswith(BASE_MODEL)), None)
    if base is not None:
        for ref, is_high in flagged.items():
            if ref != base:
                value = (
                    ("both_high" if is_high else "base_high_other_low")
                    if flagged[base]
                    else ("base_low_other_high" if is_high else "both_low")
                )
                add("model_agreement", f"{base}.vs.{ref}", value, "model_predictions")

    # --- important features (gradient boosting's recorded permutation importance)
    ranked = []
    if base is not None:
        explanation = (records[base].metrics or {}).get("explanation", {})
        ranked = [f["feature"] for f in explanation.get("top_features", [])][:TOP_FEATURES]
    for name in ranked:
        if name in vector.values or name in vector.missing:
            add(
                "important_features",
                name,
                _feature(vector, name),
                f"feature_snapshot:{feature_version}",
            )

    # --- curated feature sections
    for section, names in FEATURE_SECTIONS.items():
        for name in names:
            if name in ranked or not (name in vector.values or name in vector.missing):
                continue
            add(section, name, _feature(vector, name), f"feature_snapshot:{feature_version}")
    txn = session.scalar(select(Transaction).where(Transaction.event_id == event_id))
    if txn is not None:
        add(
            "transaction_summary",
            "amount_major_units",
            round(txn.amount_minor / 100, 2),
            "event_store",
        )

    # --- temporal summary (Stage 6 sequence)
    definition = SequenceDefinition()
    for record in records.values():
        seq = ((record.training_manifest or {}).get("dataset") or {}).get("sequence")
        if seq:
            definition = SequenceDefinition.from_dict(seq)
            break
    batch = build_sequence(session, event_id, definition)
    summary = sequence_summary(batch, 0)
    src = f"sequence:{definition.version}"
    for key in (
        "history_events",
        "device_changes",
        "asn_changes",
        "country_changes",
        "failed_logins",
        "security_changes",
        "address_changes",
        "payment_methods_added",
        "transactions_in_window",
    ):
        add("temporal_summary", key, int(summary[key]), src)
    target = summary["target"]
    add(
        "temporal_summary",
        "minutes_since_previous_event",
        float(target["minutes_since_previous_event"]),
        src,
    )
    hours = [e["hours_before"] for e in summary["last_events"]]
    if len(hours) >= 2:
        gaps = [a - b for a, b in itertools.pairwise(hours)]
        add("temporal_summary", "median_gap_hours", round(statistics.median(gaps), 2), src)
    # timeline.1 is the most recent previous event.
    for n, e in enumerate(reversed(summary["last_events"][-TIMELINE_EVENTS:]), 1):
        add("temporal_summary", f"timeline.{n}.event", _token(e["event"]), src)
        add("temporal_summary", f"timeline.{n}.hours_before", float(e["hours_before"]), src)
        add("temporal_summary", f"timeline.{n}.device_known", bool(e["device_known"]), src)
        add("temporal_summary", f"timeline.{n}.network_known", bool(e["network_known"]), src)

    # --- behavioural segments + operational cohorts (never the synthetic scenario label)
    add("scenario_context", "large_purchase_pattern", large_purchase(vector), "segment_rule")
    add("scenario_context", "high_velocity_pattern", high_velocity(vector), "segment_rule")
    for cohort in COHORTS:
        add(
            "operational_cohorts",
            cohort.name,
            bool(cohort.predicate(vector, "unknown", None, 0)),
            "cohort_rule",
        )

    # --- labels known now (at investigation time)
    conditions = [FraudLabel.event_id == event_id]
    if txn is not None:
        conditions.append(FraudLabel.transaction_id == txn.transaction_id)
    labels = list(session.scalars(select(FraudLabel).where(or_(*conditions))))
    fraud = [lab for lab in labels if lab.label is LabelValue.FRAUD]
    status = "fraud_confirmed" if fraud else ("confirmed_legitimate" if labels else "none")
    add("label_context", "label_status_now", status, "label_store")
    if fraud:
        add("label_context", "label_source", _token(fraud[0].label_source.value), "label_store")

    # --- controlled limitations
    lims = [
        "probabilities_not_certainty",
        "friendly_fraud_unobservable",
        "raw_scores_overconfident",
    ]
    if synthetic:
        lims.insert(0, "synthetic_training_data")
    if any(
        vector.values.get(k) is True
        for k in ("vpn_detected", "proxy_detected", "datacenter_detected")
    ):
        lims.append("vpn_not_proof")
    if vector.values.get("shared_network_flag") is True:
        lims.append("shared_network_legitimate")
    age = vector.values.get("account_age_days")
    if isinstance(age, int | float) and age < 30:
        lims.append("new_account_false_positives")
    if any(r.split("-")[0] in ("gru", "transformer", "hybrid") for r in flagged):
        lims.append("sequence_models_limited")
    return assemble(
        event_ref(event_id),
        _token(event.event_type.value),
        entries,
        [(code, LIMITATIONS[code]) for code in lims],
    )
