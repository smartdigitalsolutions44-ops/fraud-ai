"""Hand-built evidence packets and fake local runtimes for the Stage 7 tests (no model,
no network)."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from fraud_ai.llm.evidence import EvidencePacket, EvidenceValue, assemble
from fraud_ai.llm.reference import explain
from fraud_ai.llm.runtime import (
    GenerationRequest,
    GenerationResult,
    LLMRuntimeError,
    ModelInfo,
    RuntimeHealth,
)

GB, GRU = "gradient-boosting-1.0.0", "gru-1.0.0"
REF = "ev-0123456789abcdef"


def entries(
    *,
    gb: float = 0.91,
    gru: float = 0.12,
    label: str = "none",
    extra: list[tuple[str, str, EvidenceValue, str]] | None = None,
) -> list[tuple[str, str, EvidenceValue, str]]:
    flag_gb, flag_gru = gb >= 0.5, gru >= 0.5
    flagging = int(flag_gb) + int(flag_gru)
    pattern = "all_high" if flagging == 2 else ("all_low" if flagging == 0 else "mixed")
    vs = {
        (True, True): "both_high",
        (True, False): "base_high_other_low",
        (False, True): "base_low_other_high",
        (False, False): "both_low",
    }[(flag_gb, flag_gru)]
    uncertain = sum(0.3 <= p <= 0.7 for p in (gb, gru))
    rows: list[tuple[str, str, EvidenceValue, str]] = [
        ("event_summary", "event_type", "transaction_created", "event_store"),
        ("event_summary", "account_age_days", 420.5, "feature_snapshot"),
        ("model_scores", f"{GB}.probability", gb, f"model_prediction:{GB}"),
        ("model_scores", f"{GB}.threshold", 0.5, f"model_prediction:{GB}"),
        ("model_scores", f"{GB}.flagged", flag_gb, f"model_prediction:{GB}"),
        ("model_scores", f"{GRU}.probability", gru, f"model_prediction:{GRU}"),
        ("model_scores", f"{GRU}.threshold", 0.5, f"model_prediction:{GRU}"),
        ("model_scores", f"{GRU}.flagged", flag_gru, f"model_prediction:{GRU}"),
        ("model_agreement", "pattern", pattern, "model_predictions"),
        ("model_agreement", "models_flagging", flagging, "model_predictions"),
        ("model_agreement", "models_total", 2, "model_predictions"),
        ("model_agreement", "models_uncertain", uncertain, "model_predictions"),
        ("model_agreement", "uncertain_band_low", 0.3, "investigation_policy"),
        ("model_agreement", "uncertain_band_high", 0.7, "investigation_policy"),
        ("model_agreement", f"{GB}.vs.{GRU}", vs, "model_predictions"),
        ("temporal_summary", "history_events", 16, "sequence"),
        ("temporal_summary", "device_changes", 4, "sequence"),
        ("temporal_summary", "asn_changes", 3, "sequence"),
        ("temporal_summary", "failed_logins", 2, "sequence"),
        ("temporal_summary", "minutes_since_previous_event", 3.0, "sequence"),
        ("temporal_summary", "timeline.1.event", "login_success", "sequence"),
        ("temporal_summary", "timeline.1.hours_before", 0.1, "sequence"),
        ("temporal_summary", "timeline.1.device_known", False, "sequence"),
        ("security_summary", "recent_password_reset", True, "feature_snapshot"),
        ("transaction_summary", "transaction_vs_median_ratio", 6.25, "feature_snapshot"),
        ("network_summary", "vpn_detected", True, "feature_snapshot"),
        ("device_summary", "new_device", True, "feature_snapshot"),
        ("device_summary", "device_seen_before", False, "feature_snapshot"),
        ("address_summary", "address_seen_before", True, "feature_snapshot"),
        ("label_context", "label_status_now", label, "label_store"),
    ]
    return rows + (extra or [])


def packet(**kwargs: Any) -> EvidencePacket:
    return assemble(
        REF,
        "transaction_created",
        entries(**kwargs),
        [
            ("synthetic_training_data", "Models were trained on synthetic data only."),
            ("vpn_not_proof", "VPN use is a risk signal, not proof of fraud."),
        ],
    )


def valid_output(p: EvidencePacket) -> dict[str, Any]:
    return explain(p)


class FakeClient:
    """A scripted local runtime: ``respond(request)`` returns the model's raw text."""

    runtime = "fake"

    def __init__(
        self,
        respond: Callable[[GenerationRequest], str] | None = None,
        *,
        model: str = "fake-model",
        available: bool = True,
        error: LLMRuntimeError | None = None,
        info_error: LLMRuntimeError | None = None,
    ) -> None:
        self.model = model
        self.respond = respond or reference_response
        self.available = available
        self.error = error
        self.info_error = info_error
        self.requests: list[GenerationRequest] = []

    def health(self) -> RuntimeHealth:
        return RuntimeHealth(self.runtime, self.available, "fake runtime", "0.0")

    def list_models(self) -> list[str]:
        return [self.model]

    def model_info(self) -> ModelInfo:
        if self.info_error is not None:
            raise self.info_error
        return ModelInfo(self.runtime, self.model, "fake-1", {})

    def generate(self, request: GenerationRequest) -> GenerationResult:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return GenerationResult(self.respond(request), self.runtime, self.model, 0.25, 900, 300)


def packet_from_request(request: GenerationRequest) -> EvidencePacket:
    from fraud_ai.llm.reference import _packet

    return _packet(request.user)


def reference_response(request: GenerationRequest) -> str:
    return json.dumps(explain(packet_from_request(request)))


def mutated(change: Callable[[dict[str, Any], EvidencePacket], None]) -> Callable[..., str]:
    """A fake model that answers faithfully, then applies ``change`` to its own answer."""

    def respond(request: GenerationRequest) -> str:
        p = packet_from_request(request)
        data = explain(p)
        change(data, p)
        return json.dumps(data)

    return respond
