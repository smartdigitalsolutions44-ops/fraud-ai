"""Payment-authentication step-up through an EXTERNAL provider (Stage 9).

The fraud system **requests** payment authentication and consumes the result. It never
authenticates cardholders itself:

* it is not an issuer;
* it does not implement 3-D Secure;
* it never sees or stores a PAN, CVV, PIN or track data.

The integrator passes the processor's *token reference*, and the platform stores only a
keyed hash of it.

:class:`PaymentAuthenticationProvider` is the adapter contract a real processor
integration would implement. :class:`FakePaymentAuthProvider` is a deterministic
**development fake**: it is not 3-D Secure and not a payment network. It exists for tests
and local demos. The outcome is chosen by the token reference's suffix:

| token reference ends with | outcome |
|---|---|
| `-authenticated` (or anything else) | authenticated |
| `-failed` | failed |
| `-cancelled` | cancelled |
| `-timeout` | the provider hangs (the adapter timeout fires) |
| `-unavailable` | the provider errors |

**Safety.**

* Provider calls run with a hard timeout. A timeout or error is recorded as
  ``UNAVAILABLE`` and never allows: the original step-up stays in force until the
  attempts run out, and then the case goes to manual review.
* Callbacks are verified before any state change:
  * the provider id;
  * the HMAC signature and the timestamp window;
  * replay (the signature is stored);
  * the reference exists;
  * the state transition is ``pending`` → terminal. A duplicate callback is refused.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from fraud_ai.core.enums import AuthenticationMethod, AuthenticationResult, PaymentAuthStatus
from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.models import PaymentAuthRequest, RiskAssessment
from fraud_ai.security.hashing import HashNamespace, Pseudonymiser
from fraud_ai.service.signatures import SignatureError, check_signature, remember, sign
from fraud_ai.stepup.outcomes import (
    StepUpError,
    ensure_attempts_left,
    record_attempt,
    step_up_target,
)

RESULTS: dict[PaymentAuthStatus, AuthenticationResult] = {
    PaymentAuthStatus.AUTHENTICATED: AuthenticationResult.SUCCESS,
    PaymentAuthStatus.FAILED: AuthenticationResult.FAILED,
    PaymentAuthStatus.CANCELLED: AuthenticationResult.CANCELLED,
    PaymentAuthStatus.TIMEOUT: AuthenticationResult.EXPIRED,
    PaymentAuthStatus.UNAVAILABLE: AuthenticationResult.UNAVAILABLE,
}
TERMINAL = frozenset(RESULTS)
_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="payment-auth")


class ProviderUnavailableError(FraudAIError):
    pass


@dataclass(frozen=True)
class ProviderResponse:
    provider_reference: str
    status: PaymentAuthStatus
    next_action: dict[str, Any]


@dataclass(frozen=True)
class CallbackEvent:
    provider_reference: str
    status: PaymentAuthStatus
    signature: str
    signed_at: datetime


class PaymentAuthenticationProvider(Protocol):
    name: str

    def request_authentication(
        self,
        *,
        reference: str,
        token_reference: str,
        amount_minor: int | None,
        currency: str | None,
    ) -> ProviderResponse: ...

    def get_status(self, provider_reference: str) -> PaymentAuthStatus: ...

    def verify_callback(
        self, headers: dict[str, str], body: bytes, *, now: datetime, max_age: int
    ) -> CallbackEvent: ...


class FakePaymentAuthProvider:
    """DEVELOPMENT FAKE. Not 3-D Secure, not a payment network, not an issuer."""

    name = "fake"

    def __init__(self, webhook_secret: str, *, hang_seconds: float = 30.0) -> None:
        self._secret = webhook_secret
        self._hang = hang_seconds
        self._outcomes: dict[str, PaymentAuthStatus] = {}

    @staticmethod
    def _outcome(token_reference: str) -> PaymentAuthStatus:
        for suffix, status in (
            ("-failed", PaymentAuthStatus.FAILED),
            ("-cancelled", PaymentAuthStatus.CANCELLED),
            ("-timeout", PaymentAuthStatus.TIMEOUT),
            ("-unavailable", PaymentAuthStatus.UNAVAILABLE),
        ):
            if token_reference.endswith(suffix):
                return status
        return PaymentAuthStatus.AUTHENTICATED

    def request_authentication(
        self,
        *,
        reference: str,
        token_reference: str,
        amount_minor: int | None,
        currency: str | None,
    ) -> ProviderResponse:
        outcome = self._outcome(token_reference)
        if outcome is PaymentAuthStatus.TIMEOUT:
            time.sleep(self._hang)  # simulates a hung provider; the adapter timeout fires
        if outcome is PaymentAuthStatus.UNAVAILABLE:
            raise ProviderUnavailableError("fake provider: simulated outage")
        provider_reference = "fake_" + hashlib.sha256(reference.encode()).hexdigest()[:24]
        self._outcomes[provider_reference] = outcome
        return ProviderResponse(
            provider_reference,
            PaymentAuthStatus.PENDING,
            {"type": "fake_challenge", "note": "DEVELOPMENT FAKE - not 3-D Secure"},
        )

    def get_status(self, provider_reference: str) -> PaymentAuthStatus:
        return self._outcomes.get(provider_reference, PaymentAuthStatus.PENDING)

    def simulate_callback(
        self, provider_reference: str, *, timestamp: int | None = None
    ) -> tuple[dict[str, str], bytes]:
        """What the fake provider would POST once the 'customer' finished (tests/demo)."""
        status = self._outcomes.get(provider_reference, PaymentAuthStatus.AUTHENTICATED)
        body = json.dumps(
            {"provider_reference": provider_reference, "status": status.value}, sort_keys=True
        ).encode()
        ts = int(time.time()) if timestamp is None else timestamp
        return {
            "x-provider-id": self.name,
            "x-provider-timestamp": str(ts),
            "x-provider-signature": sign(self._secret, ts, body),
        }, body

    def verify_callback(
        self, headers: dict[str, str], body: bytes, *, now: datetime, max_age: int
    ) -> CallbackEvent:
        if headers.get("x-provider-id") != self.name:
            raise SignatureError("UNKNOWN_PROVIDER", "callback is not from this provider")
        signed_at = check_signature(
            self._secret,
            headers.get("x-provider-timestamp"),
            headers.get("x-provider-signature"),
            body,
            now=now,
            max_age=max_age,
        )
        try:
            data = json.loads(body)
            status = PaymentAuthStatus(data["status"])
            reference = str(data["provider_reference"])
        except (ValueError, KeyError, TypeError):
            raise SignatureError("INVALID_CALLBACK", "malformed callback body") from None
        if status not in TERMINAL:
            raise SignatureError("INVALID_CALLBACK", "callback status must be terminal")
        return CallbackEvent(reference, status, headers["x-provider-signature"], signed_at)


def _call_with_timeout(fn: Any, timeout: float) -> Any:
    future = _POOL.submit(fn)
    try:
        return future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        raise ProviderUnavailableError(f"provider did not answer within {timeout}s") from None


@dataclass(frozen=True)
class PaymentStepUp:
    request: PaymentAuthRequest | None
    status: PaymentAuthStatus
    next_action: dict[str, Any]
    result: AuthenticationResult | None
    followup: RiskAssessment | None


def request_payment_authentication(
    session: Session,
    provider: PaymentAuthenticationProvider,
    pseudonymiser: Pseudonymiser,
    assessment_id: uuid.UUID,
    token_reference: str,
    *,
    timeout: float,
    max_attempts: int,
    amount_minor: int | None = None,
    currency: str | None = None,
) -> PaymentStepUp:
    assessment = step_up_target(session, assessment_id)
    number = ensure_attempts_left(session, assessment.assessment_id, max_attempts)
    reference = f"{assessment.assessment_id}:{number}"
    try:
        response: ProviderResponse = _call_with_timeout(
            lambda: provider.request_authentication(
                reference=reference,
                token_reference=token_reference,
                amount_minor=amount_minor,
                currency=currency,
            ),
            timeout,
        )
    except ProviderUnavailableError as exc:
        _, followup = record_attempt(
            session,
            assessment,
            AuthenticationMethod.PAYMENT_AUTHENTICATION,
            AuthenticationResult.UNAVAILABLE,
            max_attempts=max_attempts,
            failure_reason="provider_unavailable",
        )
        return PaymentStepUp(
            None,
            PaymentAuthStatus.UNAVAILABLE,
            {"type": "authentication_unavailable", "detail": str(exc)[:120]},
            AuthenticationResult.UNAVAILABLE,
            followup,
        )
    row = PaymentAuthRequest(
        assessment_id=assessment.assessment_id,
        provider=provider.name,
        provider_reference=response.provider_reference,
        token_ref_hash=pseudonymiser.hash(HashNamespace.PAYMENT_TOKEN_REF, token_reference),
        status=PaymentAuthStatus.PENDING,
        attempt_number=number,
    )
    session.add(row)
    session.flush()
    return PaymentStepUp(row, PaymentAuthStatus.PENDING, response.next_action, None, None)


def handle_callback(
    session: Session,
    provider: PaymentAuthenticationProvider,
    headers: dict[str, str],
    body: bytes,
    *,
    now: datetime,
    max_age: int,
    max_attempts: int,
) -> PaymentStepUp:
    event = provider.verify_callback(headers, body, now=now, max_age=max_age)
    remember(
        session,
        f"provider:{provider.name}",
        event.signature,
        event.signed_at,
        max_age=max_age,
        now=now,
    )
    row = session.scalar(
        select(PaymentAuthRequest).where(
            PaymentAuthRequest.provider == provider.name,
            PaymentAuthRequest.provider_reference == event.provider_reference,
        )
    )
    if row is None:
        raise StepUpError("NOT_FOUND", "unknown provider reference", 404)
    if row.status is not PaymentAuthStatus.PENDING:
        raise StepUpError(
            "DUPLICATE_CALLBACK", f"payment authentication already {row.status.value}", 409
        )
    assessment = step_up_target(session, row.assessment_id)
    row.status = event.status
    row.completed_at = now
    result = RESULTS[event.status]
    _, followup = record_attempt(
        session,
        assessment,
        AuthenticationMethod.PAYMENT_AUTHENTICATION,
        result,
        max_attempts=max_attempts,
        failure_reason=None if result is AuthenticationResult.SUCCESS else event.status.value,
        credential_ref=row.provider_reference,
        payment_request_id=row.request_id,
    )
    return PaymentStepUp(row, event.status, {}, result, followup)


def payment_status(
    session: Session,
    provider: PaymentAuthenticationProvider,
    request_id: uuid.UUID,
    *,
    timeout: float,
) -> PaymentAuthStatus:
    """The stored status; for a pending request, the provider is polled (read-only: only a
    signed callback changes state)."""
    row = session.get(PaymentAuthRequest, request_id)
    if row is None:
        raise StepUpError("NOT_FOUND", "unknown payment authentication request", 404)
    if row.status is not PaymentAuthStatus.PENDING:
        return row.status
    try:
        status: PaymentAuthStatus = _call_with_timeout(
            lambda: provider.get_status(row.provider_reference), timeout
        )
    except ProviderUnavailableError:
        return PaymentAuthStatus.UNAVAILABLE
    return PaymentAuthStatus.PENDING if status is PaymentAuthStatus.PENDING else status
