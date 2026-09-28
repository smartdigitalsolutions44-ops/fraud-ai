"""Stripe (TEST MODE ONLY) payment-authentication adapter (Stage 10).

**Status: implemented against the official ``stripe`` Python SDK and Stripe's documented
PaymentIntents and webhook APIs, but NOT exercised against Stripe itself** — this repository
has no Stripe test-mode credentials. Unit tests use a stub client for API calls and the
SDK's own ``WebhookSignature`` for callback signatures. Do not assume it works end to end
until it has been run against a Stripe test account (see AUTHENTICATION.md §3).

How it maps onto the adapter contract:

* ``request_authentication``: creates a PaymentIntent with the merchant's **PaymentMethod
  id** (``pm_...``, a processor token reference; card data never touches this platform),
  ``confirm=True``, ``capture_method="manual"`` (authorise only, nothing is captured) and
  ``payment_method_options.card.request_three_d_secure="any"`` so Stripe runs 3-D Secure.
  The request carries an idempotency key derived from the step-up reference.
  3-D Secure is Stripe's and the issuer's; fraud-ai only asks for it and reads the result.
* ``requires_action`` → pending, and ``next_action`` hands the merchant the PaymentIntent
  id and client secret for Stripe.js (``handleNextAction``). The client secret is returned
  once and never stored or logged.
* A decline (``CardError``) is a terminal ``failed`` result; network/API errors, rate
  limits and timeouts are *provider unavailable* (never an allow).
* ``verify_callback``: ``Stripe-Signature`` is verified with the SDK
  (``stripe.WebhookSignature.verify_header``: HMAC-SHA256 over ``t.payload``, tolerance =
  ``SIGNATURE_MAX_AGE``). The SDK checks freshness against the wall clock. Terminal
  events:

  * ``payment_intent.amount_capturable_updated`` / ``payment_intent.succeeded`` →
    authenticated;
  * ``payment_intent.payment_failed`` → failed;
  * ``payment_intent.canceled`` → cancelled.

  Other event types are acknowledged and ignored.

Live keys are refused: only ``sk_test_`` / ``rk_test_`` keys are accepted.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from fraud_ai.core.enums import PaymentAuthStatus
from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.service.signatures import SignatureError
from fraud_ai.stepup.payment import (
    CallbackEvent,
    CallbackIgnoredError,
    ProviderResponse,
    ProviderUnavailableError,
)

TEST_KEY_PREFIXES = ("sk_test_", "rk_test_")
TERMINAL_EVENTS = {
    "payment_intent.amount_capturable_updated": PaymentAuthStatus.AUTHENTICATED,
    "payment_intent.succeeded": PaymentAuthStatus.AUTHENTICATED,
    "payment_intent.payment_failed": PaymentAuthStatus.FAILED,
    "payment_intent.canceled": PaymentAuthStatus.CANCELLED,
}
STATUS = {
    "requires_capture": PaymentAuthStatus.AUTHENTICATED,
    "succeeded": PaymentAuthStatus.AUTHENTICATED,
    "canceled": PaymentAuthStatus.CANCELLED,
    "requires_payment_method": PaymentAuthStatus.FAILED,
}
SIGNATURE_HEADER = "stripe-signature"


class StripeConfigurationError(FraudAIError):
    pass


class StripePaymentAuthProvider:
    name = "stripe"

    def __init__(
        self,
        api_key: str,
        webhook_secret: str,
        *,
        return_url: str | None = None,
        client: Any = None,
    ) -> None:
        if not api_key.startswith(TEST_KEY_PREFIXES):
            raise StripeConfigurationError(
                "only Stripe TEST-mode keys (sk_test_/rk_test_) are accepted at this stage"
            )
        import stripe

        self._stripe = stripe
        self._client: Any = client or stripe.StripeClient(api_key, max_network_retries=0)
        self._webhook_secret = webhook_secret
        self._return_url = return_url

    def request_authentication(
        self,
        *,
        reference: str,
        token_reference: str,
        amount_minor: int | None,
        currency: str | None,
    ) -> ProviderResponse:
        if amount_minor is None or currency is None:
            raise ProviderUnavailableError("stripe needs amount_minor and currency")
        if not token_reference.startswith("pm_"):
            raise ProviderUnavailableError("stripe needs a PaymentMethod id (pm_...)")
        params: dict[str, Any] = {
            "amount": amount_minor,
            "currency": currency.lower(),
            "payment_method": token_reference,
            "confirm": True,
            "capture_method": "manual",
            "payment_method_types": ["card"],
            "payment_method_options": {"card": {"request_three_d_secure": "any"}},
            "metadata": {"fraud_ai_reference": reference},
        }
        if self._return_url:
            params["return_url"] = self._return_url
        idempotency = hashlib.sha256(f"fraud-ai:{reference}".encode()).hexdigest()
        s = self._stripe
        try:
            intent = self._client.payment_intents.create(
                params=params, options={"idempotency_key": idempotency}
            )
        except s.CardError as exc:
            pi = getattr(getattr(exc, "error", None), "payment_intent", None)
            ref = getattr(pi, "id", None) or f"stripe_declined_{idempotency[:24]}"
            return ProviderResponse(str(ref), PaymentAuthStatus.FAILED, {"type": "declined"})
        except (s.APIConnectionError, s.RateLimitError, s.APIError) as exc:
            raise ProviderUnavailableError(f"stripe unavailable: {type(exc).__name__}") from None
        except s.StripeError as exc:
            raise ProviderUnavailableError(f"stripe error: {type(exc).__name__}") from None
        status = str(intent.status)
        if status == "requires_action":
            return ProviderResponse(
                str(intent.id),
                PaymentAuthStatus.PENDING,
                {
                    "type": "stripe_authentication",
                    "payment_intent": str(intent.id),
                    "client_secret": str(intent.client_secret),
                    "note": "complete with Stripe.js handleNextAction; TEST MODE",
                },
            )
        mapped = STATUS.get(status)
        if mapped is None:  # processing / requires_confirmation: wait for the webhook
            return ProviderResponse(str(intent.id), PaymentAuthStatus.PENDING, {"type": "wait"})
        # Frictionless (authorised without a challenge) or immediately failed: still only
        # the signed webhook changes state, so report pending with what Stripe said.
        return ProviderResponse(
            str(intent.id), PaymentAuthStatus.PENDING, {"type": "wait", "stripe_status": status}
        )

    def get_status(self, provider_reference: str) -> PaymentAuthStatus:
        s = self._stripe
        try:
            intent = self._client.payment_intents.retrieve(provider_reference)
        except s.StripeError as exc:
            raise ProviderUnavailableError(f"stripe unavailable: {type(exc).__name__}") from None
        return STATUS.get(str(intent.status), PaymentAuthStatus.PENDING)

    def verify_callback(
        self, headers: dict[str, str], body: bytes, *, now: datetime, max_age: int
    ) -> CallbackEvent:
        header = headers.get(SIGNATURE_HEADER)
        if not header:
            raise SignatureError("MISSING_SIGNATURE", "Stripe-Signature header missing")
        s = self._stripe
        try:
            s.WebhookSignature.verify_header(
                body.decode("utf-8"), header, self._webhook_secret, tolerance=max_age
            )
        except s.SignatureVerificationError as exc:
            code = "EXPIRED_SIGNATURE" if "tolerance" in str(exc).lower() else "INVALID_SIGNATURE"
            raise SignatureError(code, "Stripe signature verification failed") from None
        except (ValueError, IndexError):
            raise SignatureError("INVALID_SIGNATURE", "malformed Stripe-Signature") from None
        try:
            event = json.loads(body)
            kind = str(event["type"])
            obj = event["data"]["object"]
            reference = str(obj["id"])
        except (ValueError, KeyError, TypeError):
            raise SignatureError("INVALID_CALLBACK", "malformed Stripe event") from None
        status = TERMINAL_EVENTS.get(kind)
        if status is None:
            raise CallbackIgnoredError(f"stripe event {kind} does not change state")
        parts = [p.strip().split("=", 1) for p in header.split(",") if "=" in p]
        timestamp = int(next(v for k, v in parts if k == "t"))
        signature = next(v for k, v in parts if k == "v1")
        return CallbackEvent(
            reference, status, f"v1={signature}", datetime.fromtimestamp(timestamp, UTC)
        )
