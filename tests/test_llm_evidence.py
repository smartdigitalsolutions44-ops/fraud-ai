import pytest

from fraud_ai.core.enums import Decision
from fraud_ai.llm import EvidencePacket, EvidencePrivacyError, Explanation, ExplanationProvider


def _packet(**kw: object) -> EvidencePacket:
    base: dict[str, object] = dict(
        risk_score=0.91,
        ml_probability=0.78,
        decision=Decision.STEP_UP_AUTHENTICATION,
        policy_version="p1",
        signals={
            "new_device": True,
            "new_address": True,
            "transaction_ratio": 7.4,
            "vpn_probability": 0.93,
            "password_reset_minutes_ago": 12,
        },
        historical={"device_seen_days": 0, "address_seen_days": 0, "account_age_days": 934},
    )
    base.update(kw)
    return EvidencePacket(**base)  # type: ignore[arg-type]


def test_render_is_deterministic_structured_evidence() -> None:
    text = _packet().render()
    assert text.startswith("Risk score: 0.91")
    assert "  new_device = true" in text
    assert "  transaction_ratio = 7.40" in text
    assert "  account_age_days = 934" in text
    assert text.endswith("Decision: STEP_UP_AUTHENTICATION")
    assert _packet().render() == text


@pytest.mark.parametrize(
    ("section", "data"),
    [
        ("signals", {"ip_address": "x"}),
        ("signals", {"email": "x"}),
        ("signals", {"cvv": "1"}),
        ("historical", {"note": "10.1.2.3"}),
        ("historical", {"note": "a@example.com"}),
        ("signals", {"note": "4111 1111 1111 1111"}),
        ("signals", {"password": "x"}),
    ],
)
def test_privacy_guard_rejects_identifying_data(section: str, data: dict[str, str]) -> None:
    with pytest.raises(EvidencePrivacyError):
        _packet(**{section: data})


def test_provider_protocol_is_structural() -> None:
    class Dummy:
        def explain(self, evidence: EvidencePacket) -> Explanation:
            return Explanation("because", "local-test", evidence.risk_score)

    assert isinstance(Dummy(), ExplanationProvider)
    assert Dummy().explain(_packet()).risk_score == 0.91
