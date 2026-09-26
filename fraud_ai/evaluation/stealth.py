"""Stealthy account-takeover report (Stage 6).

**Cases.** The fraud events in the split that are either:
* takeovers with no password reset in the 24 hours before; or
* from the temporal ``slow_account_takeover`` scenario.

These are the frauds that per-event features struggle with.

**For every case:**

* **Model outputs:** each model's probability, and whether it would flag the event at its
  own threshold.
* **Behaviour before the event**, read from the point-in-time sequence (only when a
  sequence model is part of the evaluation, so the sequences are available):
  * the last few events: type, hours before the target, device and network known, network
    type;
  * counts of device changes, network (ASN) changes and country changes;
  * address changes, security changes and failed logins;
  * the timing of the transaction.

**Recall per model** over these cases, and the cases only a sequence model catches.

**Privacy.** Identifiers are one-way pseudonyms; no id, IP, address or payment detail
appears. The sequences themselves only hold types, flags and time gaps.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from fraud_ai.evaluation.context import EvaluationContext, ScoredModel, pseudonym
from fraud_ai.sequences.extraction import SequenceBatch
from fraud_ai.sequences.inputs import SequenceMatrix

LAST_EVENTS = 8


def _is_case(ctx: EvaluationContext, i: int) -> bool:
    if int(ctx.prepared.y[i]) != 1:
        return False
    vector = ctx.prepared.dataset.examples[i].vector
    stealthy_ato = (
        ctx.fraud_types[i] == "account_takeover"
        and vector.values.get("recent_password_reset") is not True
    )
    return stealthy_ato or ctx.scenarios[i] == "slow_account_takeover"


def _summary(batch: SequenceBatch, row: int) -> dict[str, Any]:
    positions = batch.decode(row)
    history, target = positions[:-1], positions[-1]

    def hours(p: dict[str, Any]) -> float:
        return round(float(np.expm1(p["log_hours_before_target"])), 1)

    return {
        "history_events": len(history),
        "last_events": [
            {
                "event": p["event_type"],
                "hours_before": hours(p),
                "device_known": bool(p["device_known"]),
                "network_known": bool(p["network_known"]),
                "network_type": p["network_type"],
            }
            for p in history[-LAST_EVENTS:]
        ],
        "device_changes": int(sum(p["device_changed"] for p in history)),
        "asn_changes": int(sum(p["asn_changed"] for p in history)),
        "country_changes": int(sum(p["country_changed"] for p in history)),
        "address_changes": sum(
            p["event_type"] in ("ADDRESS_ADDED", "ADDRESS_CHANGED") for p in history
        ),
        "payment_methods_added": sum(p["event_type"] == "PAYMENT_METHOD_ADDED" for p in history),
        "security_changes": int(sum(p["is_security_event"] for p in history)),
        "failed_logins": sum(p["event_type"] == "LOGIN_FAILURE" for p in history),
        "transactions_in_window": sum(p["event_type"] == "TRANSACTION_CREATED" for p in history),
        "target": {
            "minutes_since_previous_event": round(
                float(np.expm1(target["log_minutes_since_previous"])), 1
            ),
            "device_known": bool(target["device_known"]),
            "network_known": bool(target["network_known"]),
            "address_known": bool(target["address_known"]) if target["has_address"] else None,
            "payment_method_known": (
                bool(target["payment_method_known"]) if target["has_payment_method"] else None
            ),
        },
    }


def stealth_report(
    ctx: EvaluationContext, models: list[ScoredModel] | None = None, split: str = "test"
) -> dict[str, Any]:
    models = models or ctx.models
    idx = ctx.indices(split)
    rows = [k for k, i in enumerate(idx) if _is_case(ctx, i)]
    sequences = (
        ctx.prepared.matrix.sequences if isinstance(ctx.prepared.matrix, SequenceMatrix) else None
    )
    sequence_models = {m.model_id for m in models if m.model.input_kind == "sequence"}
    cases = []
    for k in rows:
        i = idx[k]
        probs = {m.model_id: round(float(m.scores[split][k]), 4) for m in models}
        flagged = {m.model_id: bool(m.scores[split][k] >= m.threshold) for m in models}
        caught_by = sorted(name for name, f in flagged.items() if f)
        entry: dict[str, Any] = {
            "ref": pseudonym(ctx.prepared.dataset.examples[i].event_id),
            "scenario": ctx.scenarios[i],
            "fraud_type": ctx.fraud_types[i],
            "probabilities": probs,
            "caught_by": caught_by,
            "caught_only_by_sequence_models": bool(caught_by) and set(caught_by) <= sequence_models,
        }
        if sequences is not None:
            entry["behaviour"] = _summary(sequences, i)
        cases.append(entry)
    recall = {
        m.model_id: (
            sum(c["probabilities"][m.model_id] >= m.threshold for c in cases) / len(cases)
            if cases
            else None
        )
        for m in models
    }
    return {
        "split": split,
        "definition": "fraud that is account_takeover with no password reset in the "
        "previous 24h, or from the slow_account_takeover scenario",
        "cases": len(cases),
        "recall_by_model": recall,
        "thresholds": {m.model_id: m.threshold for m in models},
        "caught_only_by_sequence_models": sum(c["caught_only_by_sequence_models"] for c in cases),
        "missed_by_all": sum(not c["caught_by"] for c in cases),
        "by_scenario": {
            s: sum(c["scenario"] == s for c in cases)
            for s in sorted({c["scenario"] for c in cases})
        },
        "details": cases,
        "note": "Small samples: recall over a handful of cases is indicative only. Data is "
        "SYNTHETIC. Refs are one-way pseudonyms.",
    }
