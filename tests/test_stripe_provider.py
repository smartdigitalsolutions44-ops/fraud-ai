"""The Stripe TEST-MODE adapter, without Stripe: API calls go to a stub client; webhook
signatures are produced and verified by the official SDK's ``WebhookSignature``.

These tests prove the adapter's own logic and the callback security. They do NOT prove
the adapter works against Stripe's servers (no test-mode credentials are available)."""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Iterator
from datetime import timedelta
from types import SimpleNamespace
from typing import Any

import pytest
import stripe
from pydantic import ValidationError
from sqlalchemy import select

from fraud_ai.config.settings import Settings
from fraud_ai.database.models import PaymentAuthRequest
from fraud_ai.stepup.stripe_provider import StripeConfigurationError, StripePaymentAuthProvider
from tests.conftest import T0
from tests.service_helpers import Clock, Harness, make_harness
from tests.test_service_backends import _seed_step_up

WHSEC = "whsec_" + "t3stW3bh00kS3cr3tForUnitTestsOnly0123"
API_KEY = "sk_test_" + "unitTestsOnlyNotARealKey0123456789"


class StubIntents:
    def __init__(self) -> None:
        self.created: list[dict[str, Any]] = []
        self.mode = "requires_action"
        self.statuses: dict[str, str] = {}

    def create(self, params: dict[str, Any], options: dict[str, Any]) -> Any:
        self.created.append({"params": params, "options": options})
        if self.mode == "timeout":
            time.sleep(2)
        if self.mode == "outage":
            raise stripe.APIConnectionError("network down")
        if self.mode == "declined":
            raise stripe.CardError("Your card was declined.", None, "card_declined")
        pi = f"pi_{uuid.uuid4().hex[:20]}"
        self.statuses[pi] = self.mode
        return SimpleNamespace(id=pi, status=self.mode, client_secret=f"{pi}_secret_abc123")

    def retrieve(self, intent: str) -> Any:
        return SimpleNamespace(id=intent, status=self.statuses.get(intent, "requires_action"))


@pytest.fixture
def stub() -> StubIntents:
    return StubIntents()


@pytest.fixture
def h(any_engine: Any, backend_url: str, stub: StubIntents) -> Iterator[Harness]:
    provider = StripePaymentAuthProvider(
        API_KEY,
        WHSEC,
        return_url="https://merchant.example/return",
        client=SimpleNamespace(payment_intents=stub),
    )
    harness = make_harness(
        backend_url,
        engine=any_engine,
        clock=Clock(T0 + timedelta(minutes=2)),
        payment_provider=provider,
        payment_auth_timeout=0.3,
    )
    yield harness
    harness.container.close()


def _start(h: Harness, token: str = "pm_card_visa_test") -> tuple[str, dict[str, Any]]:
    [(aid, _, _)] = _seed_step_up(h.container.factory)
    cred = h.key()
    r = h.post(
        f"/v1/step-up/{aid}/payment",
        cred,
        {"token_reference": token, "amount_minor": 4250, "currency": "GBP"},
    )
    assert r.status_code == 200, r.text
    return aid, r.json()


def _event(kind: str, pi: str, event_id: str | None = None) -> bytes:
    return json.dumps(
        {
            "id": event_id or f"evt_{uuid.uuid4().hex[:16]}",
            "object": "event",
            "type": kind,
            "data": {"object": {"id": pi, "object": "payment_intent"}},
        }
    ).encode()


def _deliver(h: Harness, body: bytes, *, timestamp: int | None = None, secret: str = WHSEC) -> Any:
    header = stripe.WebhookSignature.generate_signature_header(
        body.decode(), secret, timestamp=timestamp or int(time.time())
    )
    return h.client.post(
        "/v1/callbacks/payment/stripe",
        content=body,
        headers={"Stripe-Signature": header, "Content-Type": "application/json"},
    ), header


def test_requires_action_then_signed_webhook_authenticates(h: Harness, stub: StubIntents) -> None:
    aid, started = _start(h)
    assert started["status"] == "pending" and started["provider"] == "stripe"
    pi = started["next_action"]["payment_intent"]
    assert started["next_action"]["client_secret"].startswith(pi)
    sent = stub.created[0]
    assert sent["params"]["capture_method"] == "manual"  # authorise only
    assert sent["params"]["payment_method_options"]["card"]["request_three_d_secure"] == "any"
    assert sent["params"]["payment_method"] == "pm_card_visa_test"
    assert len(sent["options"]["idempotency_key"]) == 64
    with h.container.factory() as s:
        row = s.scalar(select(PaymentAuthRequest))
        assert row is not None and row.provider_reference == pi
        assert "secret" not in json.dumps([row.provider_reference, row.token_ref_hash])
        assert "pm_card" not in row.token_ref_hash
    body = _event("payment_intent.amount_capturable_updated", pi)
    ok, header = _deliver(h, body)
    assert ok.status_code == 200 and ok.json()["result"] == "SUCCESS", ok.text
    replay = h.client.post(
        "/v1/callbacks/payment/stripe",
        content=body,
        headers={"Stripe-Signature": header, "Content-Type": "application/json"},
    )
    assert replay.status_code == 401 and replay.json()["error"]["code"] == "REPLAYED_SIGNATURE"
    duplicate, _ = _deliver(h, body, timestamp=int(time.time()) + 1)
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "DUPLICATE_CALLBACK"
    view = h.get(f"/v1/assessments/{aid}", h.key()).json()
    assert view["authentication"]["latest_result"] == "SUCCESS"


def test_webhook_rejections(h: Harness) -> None:
    _, started = _start(h)
    pi = started["next_action"]["payment_intent"]
    body = _event("payment_intent.succeeded", pi)
    forged, _ = _deliver(h, body, secret="whsec_" + "x" * 32)
    assert forged.status_code == 401 and forged.json()["error"]["code"] == "INVALID_SIGNATURE"
    stale, _ = _deliver(h, body, timestamp=int(time.time()) - 3600)
    assert stale.status_code == 401 and stale.json()["error"]["code"] == "EXPIRED_SIGNATURE"
    missing = h.client.post("/v1/callbacks/payment/stripe", content=body)
    assert missing.json()["error"]["code"] == "MISSING_SIGNATURE"
    garbled = h.client.post(
        "/v1/callbacks/payment/stripe", content=body, headers={"Stripe-Signature": "t=abc,v1="}
    )
    assert garbled.status_code == 401
    unknown, _ = _deliver(h, _event("payment_intent.succeeded", "pi_unknown000"))
    assert unknown.status_code == 404
    malformed, _ = _deliver(h, b'{"type": "payment_intent.succeeded"}')
    assert malformed.json()["error"]["code"] == "INVALID_CALLBACK"
    ignored, _ = _deliver(h, _event("payment_intent.created", pi))
    assert ignored.status_code == 200 and ignored.json()["accepted"] is False
    failed, _ = _deliver(h, _event("payment_intent.payment_failed", pi))
    assert failed.json()["result"] == "FAILED"


@pytest.mark.parametrize(
    ("mode", "status", "result"),
    [
        ("timeout", "unavailable", "UNAVAILABLE"),
        ("outage", "unavailable", "UNAVAILABLE"),
        ("declined", "failed", "FAILED"),
    ],
)
def test_provider_failures_are_never_an_allow(
    h: Harness, stub: StubIntents, mode: str, status: str, result: str
) -> None:
    stub.mode = mode
    aid, started = _start(h)
    assert started["status"] == status and started["result"] == result
    if mode != "declined":
        assert started["next_action"]["type"] == "authentication_unavailable"
    view = h.get(f"/v1/assessments/{aid}", h.key()).json()
    assert view["decision"] == "STEP_UP_AUTHENTICATION"  # still open; never allowed
    assert view["authentication"]["latest_result"] == result


def test_bad_requests_to_stripe_fail_closed(h: Harness) -> None:
    _, started = _start(h, token="tok_legacy_token_123")
    assert started["status"] == "unavailable"


def test_status_polling_maps_stripe_states(h: Harness, stub: StubIntents) -> None:
    _, started = _start(h)
    pi = started["next_action"]["payment_intent"]
    polled = h.get(f"/v1/step-up/payment/{started['request_id']}", h.key()).json()
    assert polled["status"] == "pending"
    stub.statuses[pi] = "requires_capture"
    polled = h.get(f"/v1/step-up/payment/{started['request_id']}", h.key()).json()
    assert polled["status"] == "authenticated"  # read-only: only the webhook changes state
    with h.container.factory() as s:
        row = s.scalar(select(PaymentAuthRequest))
        assert row is not None and row.status.value == "pending"


def test_only_test_mode_keys_are_accepted() -> None:
    with pytest.raises(StripeConfigurationError, match="TEST-mode"):
        StripePaymentAuthProvider("sk_live_" + "x" * 24, WHSEC)
    with pytest.raises(ValidationError, match="TEST-mode"):
        Settings(
            payment_auth_provider="stripe",
            stripe_api_key="sk_live_" + "x" * 24,
            payment_auth_webhook_secret=WHSEC,
        )
    ok = Settings(
        payment_auth_provider="stripe", stripe_api_key=API_KEY, payment_auth_webhook_secret=WHSEC
    )
    from fraud_ai.service.app import default_payment_provider

    provider = default_payment_provider(ok)
    assert provider is not None and provider.name == "stripe"
