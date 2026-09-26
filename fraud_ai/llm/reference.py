"""A deterministic *template* analyst: the offline reference runtime (**not an LLM**).

It reads the evidence packet from the prompt's data block and builds an explanation from
fixed templates. Every statement cites the evidence it states, and numbers are copied from
the cited values. It exists:

* to run the full investigation pipeline offline, with no model installed;
* as a baseline that the local-model benchmark compares real LLMs against. It is faithful
  by construction, so any model that does worse is worse than a template.

It never decides anything. Its questions are questions.
"""

from __future__ import annotations

import json
import time
from typing import Any

from fraud_ai.llm.evidence import EvidenceItem, EvidencePacket
from fraud_ai.llm.prompt import DATA_END, DATA_START
from fraud_ai.llm.runtime import GenerationRequest, GenerationResult, ModelInfo, RuntimeHealth

REFERENCE_MODEL = "reference-template-1.0.0"
RISK_FLAGS = {
    "new_device": "The event came from a device new to this account",
    "new_address": "The shipping address is new to this account",
    "new_payment_method": "The payment method is new to this account",
    "recent_password_reset": "A password reset happened shortly before",
    "recent_email_change": "The account email was changed recently",
    "recent_phone_change": "The account phone number was changed recently",
    "recent_mfa_removed": "Multi-factor authentication was removed recently",
    "vpn_detected": "The network was flagged as a VPN",
    "proxy_detected": "The network was flagged as a proxy",
    "datacenter_detected": "The network is a datacenter network",
    "country_changed": "The network country differs from the previous one",
    "unusually_high_transaction": "The amount is unusually high for this customer",
    "high_velocity_pattern": "Activity in the previous hour was dense",
    "large_purchase_pattern": "The purchase is large relative to the customer's history",
}
PROTECTIVE_FLAGS = {
    "device_seen_before": "The device has been seen on this account before",
    "address_seen_before": "The address has been used by this account before",
    "network_seen_before": "The network has been seen on this account before",
    "device_trusted": "The device is marked as trusted",
}
QUESTIONS = {
    "new_device": "Was this device previously verified by the customer?",
    "new_address": "Was the address change expected by the customer?",
    "address_changed_recently": "Was the address change expected by the customer?",
    "recent_password_reset": "Was the password reset initiated by the customer?",
    "recent_email_change": "Did the customer request the email change?",
    "vpn_detected": "Is VPN use usual for this customer?",
    "transaction_vs_median_ratio": "Does the transaction amount fit the customer's prior "
    "purchase history?",
    "device_changes": "Were the recent device changes made by the customer?",
}


def _num(value: Any) -> str:
    return f"{value:.2f}" if isinstance(value, float) else str(value)


def _packet(user: str) -> EvidencePacket:
    start = user.index(DATA_START) + len(DATA_START)
    end = user.index(DATA_END)
    return EvidencePacket.from_prompt_data(json.loads(user[start:end]))


class ReferenceAnalyst:
    runtime = "reference"
    model = REFERENCE_MODEL

    def health(self) -> RuntimeHealth:
        return RuntimeHealth(
            self.runtime, True, "built-in deterministic template (not an LLM)", REFERENCE_MODEL
        )

    def list_models(self) -> list[str]:
        return [REFERENCE_MODEL]

    def model_info(self) -> ModelInfo:
        return ModelInfo(
            self.runtime,
            REFERENCE_MODEL,
            "1.0.0",
            {"kind": "deterministic template, not a language model"},
        )

    def generate(self, request: GenerationRequest) -> GenerationResult:
        started = time.perf_counter()
        packet = _packet(request.user)
        text = json.dumps(explain(packet), sort_keys=True)
        return GenerationResult(
            text, self.runtime, REFERENCE_MODEL, time.perf_counter() - started, None, None
        )


def _find(packet: EvidencePacket, name: str) -> EvidenceItem | None:
    for item in packet.items:
        if item.name == name:
            return item
    return None


def explain(packet: EvidencePacket) -> dict[str, Any]:
    def finding(statement: str, *items: EvidenceItem | None) -> dict[str, Any]:
        return {"statement": statement, "evidence_ids": [i.id for i in items if i is not None]}

    pattern = packet.get("model_agreement", "pattern")
    flagging = packet.get("model_agreement", "models_flagging")
    total = packet.get("model_agreement", "models_total")
    assert pattern is not None and flagging is not None and total is not None
    probabilities = [
        i
        for i in packet.section("model_scores")
        if i.name.endswith(".probability") and not i.name.endswith(".calibrated_probability")
    ][:8]  # a finding cites at most 12 ids
    scored = ", ".join(f"{i.name.rsplit('.', 1)[0]} {_num(i.value)}" for i in probabilities)
    summary = finding(
        f"{_num(flagging.value)} of {_num(total.value)} models scored this event at or above "
        f"their thresholds (agreement pattern: {pattern.value}); stored scores: {scored}.",
        flagging,
        total,
        pattern,
        *probabilities,
    )
    risk: list[dict[str, Any]] = []
    protective: list[dict[str, Any]] = []
    questions: list[dict[str, Any]] = []
    asked: set[str] = set()
    for name, text in RISK_FLAGS.items():
        item = _find(packet, name)
        if item is not None and item.value is True:
            risk.append(finding(f"{text}.", item))
            if name in QUESTIONS and QUESTIONS[name] not in asked:
                questions.append({"question": QUESTIONS[name], "evidence_ids": [item.id]})
                asked.add(QUESTIONS[name])
    ratio = _find(packet, "transaction_vs_median_ratio")
    if (
        ratio is not None
        and isinstance(ratio.value, int | float)
        and not isinstance(ratio.value, bool)
    ):
        if ratio.value >= 2:
            risk.append(
                finding(
                    f"The amount is {_num(ratio.value)} times the customer's median "
                    "previous transaction.",
                    ratio,
                )
            )
            questions.append(
                {"question": QUESTIONS["transaction_vs_median_ratio"], "evidence_ids": [ratio.id]}
            )
        elif ratio.value <= 1.5:
            protective.append(
                finding(
                    f"The amount is {_num(ratio.value)} times the customer's "
                    "median previous transaction.",
                    ratio,
                )
            )
    for name, text in PROTECTIVE_FLAGS.items():
        item = _find(packet, name)
        if item is not None and item.value is True:
            protective.append(finding(f"{text}.", item))
    age = packet.get("event_summary", "account_age_days")
    if age is not None and isinstance(age.value, int | float) and age.value >= 365:
        protective.append(finding(f"The account is {_num(age.value)} days old.", age))

    disagreement: list[dict[str, Any]] = []
    scores = {
        i.name.rsplit(".", 1)[0]: i
        for i in packet.section("model_scores")
        if i.name.endswith(".probability") and not i.name.endswith(".calibrated_probability")
    }
    for item in packet.section("model_agreement"):
        if ".vs." not in item.name or str(item.value).startswith("both"):
            continue
        base, other = item.name.split(".vs.")
        high, low = (base, other) if item.value == "base_high_other_low" else (other, base)
        disagreement.append(
            finding(
                f"{high} scored {_num(scores[high].value)} (at or above its threshold) while {low} "
                f"scored {_num(scores[low].value)} (below its threshold).",
                scores[high],
                scores[low],
                item,
            )
        )
    if not disagreement and pattern.value in ("all_high", "all_low"):
        disagreement.append(finding(f"All models agree ({pattern.value}).", pattern))
    uncertain = packet.get("model_agreement", "models_uncertain")
    band_low = packet.get("model_agreement", "uncertain_band_low")
    band_high = packet.get("model_agreement", "uncertain_band_high")
    uncertainties: list[dict[str, Any]] = []
    if (
        uncertain is not None
        and band_low is not None
        and band_high is not None
        and isinstance(uncertain.value, int)
        and uncertain.value > 0
    ):
        uncertainties.append(
            finding(
                f"{uncertain.value} model(s) scored between {_num(band_low.value)} and "
                f"{_num(band_high.value)}, so their view is uncertain.",
                uncertain,
                band_low,
                band_high,
            )
        )
    for lim in packet.limitations:
        uncertainties.append({"statement": lim.text, "evidence_ids": [lim.id]})

    temporal: list[dict[str, Any]] = []
    counts = {
        n: packet.get("temporal_summary", n)
        for n in (
            "history_events",
            "device_changes",
            "asn_changes",
            "failed_logins",
            "security_changes",
            "minutes_since_previous_event",
        )
    }
    if all(
        counts[n] is not None
        for n in ("history_events", "device_changes", "asn_changes", "failed_logins")
    ):
        h, d, a, f = (
            counts[n] for n in ("history_events", "device_changes", "asn_changes", "failed_logins")
        )
        assert h is not None and d is not None and a is not None and f is not None
        temporal.append(
            finding(
                f"In the previous {_num(h.value)} events there were {_num(d.value)} device "
                f"changes, {_num(a.value)} network (ASN) changes and {_num(f.value)} failed "
                "logins.",
                h,
                d,
                a,
                f,
            )
        )
        if isinstance(d.value, int) and d.value >= 3 and QUESTIONS["device_changes"] not in asked:
            questions.append({"question": QUESTIONS["device_changes"], "evidence_ids": [d.id]})
    gap = counts["minutes_since_previous_event"]
    if gap is not None:
        temporal.append(
            finding(f"The event came {_num(gap.value)} minutes after the previous event.", gap)
        )
    for n in range(1, 4):
        event = packet.get("temporal_summary", f"timeline.{n}.event")
        hours = packet.get("temporal_summary", f"timeline.{n}.hours_before")
        known = packet.get("temporal_summary", f"timeline.{n}.device_known")
        if event is None or hours is None or known is None:
            break
        temporal.append(
            finding(
                f"{_num(hours.value)} hours before: {event.value} "
                f"({'known' if known.value else 'unknown'} device).",
                event,
                hours,
                known,
            )
        )
    label = packet.get("label_context", "label_status_now")
    if label is not None and label.value == "fraud_confirmed":
        risk.insert(
            0,
            finding(
                "A fraud label is already recorded for this event, so fraud "
                "is confirmed by the label store.",
                label,
            ),
        )
    result: dict[str, Any] = {
        "summary": summary,
        "risk_factors": risk[:10],
        "protective_factors": protective[:10],
        "model_disagreement": disagreement[:6],
        "temporal_findings": temporal[:6],
        "uncertainties": uncertainties[:6],
        "recommended_review_questions": questions[:8],
    }
    cited = sorted(
        {
            i
            for key in (
                "risk_factors",
                "protective_factors",
                "model_disagreement",
                "temporal_findings",
                "uncertainties",
            )
            for f in result[key]
            for i in f["evidence_ids"]
        }
        | set(summary["evidence_ids"])
        | {i for q in result["recommended_review_questions"] for i in q["evidence_ids"]},
        key=lambda x: (x[0], int(x[1:])),
    )
    result["evidence_ids_used"] = cited
    return result
