"""Stage 9 persistence on every backend (SQLite and PostgreSQL). Covers:

* key storage;
* replay-token and idempotency races;
* single-use challenges;
* follow-up immutability;
* the payment callback transitions.
"""

from __future__ import annotations

import hashlib
import threading
import uuid
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from fraud_ai.core.enums import Decision, EventType
from fraud_ai.database.engine import make_session_factory, session_scope
from fraud_ai.database.models import (
    AuthenticationAttempt,
    PaymentAuthRequest,
    RequestIdempotency,
    RiskAssessment,
)
from fraud_ai.ingestion.processor import EventProcessor
from fraud_ai.service import idempotency
from fraud_ai.service.errors import ApiError
from fraud_ai.service.keys import create_key, revoke_key, verify_key
from fraud_ai.service.signatures import SignatureError, remember
from fraud_ai.stepup.outcomes import StepUpError, record_attempt
from fraud_ai.stepup.payment import FakePaymentAuthProvider
from tests.conftest import T0, create_user, make_event
from tests.realtime_world import PSEUDO
from tests.service_helpers import Clock, Harness, SoftAuthenticator, make_harness


@pytest.fixture
def factory(any_engine: Engine) -> sessionmaker[Session]:
    return make_session_factory(any_engine)


def _seed_step_up(factory: sessionmaker[Session], n: int = 1) -> list[tuple[str, str, str]]:
    """Users with a STEP_UP assessment each (as Stage 8 would have stored it)."""
    out = []
    with session_scope(factory) as s:
        processor = EventProcessor(s, PSEUDO)
        for i in range(n):
            uid = create_user(processor, device_id=f"device-{i}")
            event = make_event(
                EventType.LOGIN_SUCCESS,
                uid,
                {"auth_method": "password"},
                ts=T0 + timedelta(minutes=1),
                device_id=f"device-{i}",
                session_id=f"sess-{i}",
            )
            processor.process(event)
            row = RiskAssessment(
                event_id=event.event_id,
                assessment_version=1,
                idempotency_key=hashlib.sha256(f"{event.event_id}:t:1".encode()).hexdigest(),
                mode="live",
                user_id=uid,
                event_time=event.timestamp,
                arrival_time=event.timestamp,
                policy_version="test-policy-1.0.0",
                primary_model="gradient-boosting-1.0.0",
                ml_probability=0.41,
                calibrated_score=0.37,
                final_risk_score=0.37,
                risk_level="elevated",
                decision=Decision.STEP_UP_AUTHENTICATION,
                reason_codes=["SCORE_BAND_ELEVATED"],
                model_scores={"primary": {"raw": 0.41, "calibrated": 0.37}},
                action={"type": "STEP_UP_AUTHENTICATION"},
            )
            s.add(row)
            s.flush()
            out.append((str(row.assessment_id), str(uid), f"sess-{i}"))
    return out


@pytest.fixture
def h(backend_url: str, any_engine: Engine) -> Iterator[Harness]:
    harness = make_harness(backend_url, engine=any_engine, clock=Clock(T0 + timedelta(minutes=2)))
    yield harness
    harness.container.close()


def _parallel(n: int, fn: Any) -> list[Any]:
    results: list[Any] = []
    lock = threading.Lock()
    barrier = threading.Barrier(n)

    def run() -> None:
        barrier.wait()
        try:
            value = fn()
        except Exception as exc:
            value = exc
        with lock:
            results.append(value)

    threads = [threading.Thread(target=run) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def test_keys(factory: sessionmaker[Session]) -> None:
    with session_scope(factory) as s:
        issued = create_key(s, "svc", ["score:write"])
    with session_scope(factory) as s:
        assert verify_key(s, issued.credential) is not None
        revoke_key(s, issued.key_id)
    with session_scope(factory) as s:
        assert verify_key(s, issued.credential) is None


def test_concurrent_replays_accept_one_signature(factory: sessionmaker[Session]) -> None:
    signed_at = T0

    def attempt() -> bool:
        with session_scope(factory) as s:
            remember(s, "key:x", "v1=abc", signed_at, max_age=300, now=T0)
        return True

    results = _parallel(6, attempt)
    accepted = [r for r in results if r is True]
    refused = [r for r in results if isinstance(r, SignatureError)]
    assert len(accepted) == 1 and len(refused) == 5, results
    assert all(r.code == "REPLAYED_SIGNATURE" for r in refused)


def test_idempotency_race_and_lifecycle(factory: sessionmaker[Session]) -> None:
    digest = "a" * 64

    def begin() -> Any:
        return idempotency.begin(factory, "fak_1", "POST /v1/score", "key-000001", digest)

    results = _parallel(6, begin)
    winners = [r for r in results if isinstance(r, tuple) and r[0] is not None]
    losers = [r for r in results if isinstance(r, ApiError)]
    assert len(winners) == 1 and len(losers) == 5, results
    assert {e.code for e in losers} == {"IDEMPOTENCY_IN_PROGRESS"}
    record_id = winners[0][0]
    idempotency.complete(factory, record_id, 200, {"decision": "ALLOW"}, "p-1")
    assert begin() == (None, idempotency.Stored(200, {"decision": "ALLOW"}))
    with pytest.raises(ApiError) as err:
        idempotency.begin(factory, "fak_1", "POST /v1/score", "key-000001", "b" * 64)
    assert err.value.code == "IDEMPOTENCY_KEY_REUSED"
    other, _ = idempotency.begin(factory, "fak_1", "POST /v1/score", "key-000002", digest)
    assert other is not None
    idempotency.abandon(factory, other)
    again, _ = idempotency.begin(factory, "fak_1", "POST /v1/score", "key-000002", digest)
    assert again is not None
    with factory() as s:
        assert s.scalar(select(func.count()).select_from(RequestIdempotency)) == 2


def test_webauthn_step_up_on_backend(h: Harness) -> None:
    (aid, user_id, session_id), (aid2, user2, session2) = _seed_step_up(h.container.factory, 2)
    cred = h.key()
    authenticator = SoftAuthenticator()
    ch = h.post("/v1/webauthn/registrations/challenge", cred, {"user_id": user_id}).json()
    reg = h.post(
        "/v1/webauthn/registrations",
        cred,
        {
            "challenge_id": ch["challenge_id"],
            "credential": authenticator.register(ch["public_key"]),
        },
    )
    assert reg.status_code == 201, reg.text
    ch = h.post(f"/v1/step-up/{aid}/webauthn/challenge", cred, {"session_id": session_id}).json()
    assertion = authenticator.assertion(ch["public_key"])
    payload = {
        "challenge_id": ch["challenge_id"],
        "session_id": session_id,
        "credential": assertion,
    }
    codes = _parallel(5, lambda: h.post("/v1/step-up/webauthn/verify", cred, payload).status_code)
    assert sorted(codes) == [200, 409, 409, 409, 409]
    with h.container.factory() as s:
        original = s.get(RiskAssessment, uuid.UUID(aid))
        assert original is not None and original.decision is Decision.STEP_UP_AUTHENTICATION
        followup = s.scalar(
            select(RiskAssessment).where(
                RiskAssessment.supersedes_assessment_id == original.assessment_id
            )
        )
        assert followup is not None
        assert followup.decision is Decision.ALLOW_WITH_MONITORING
        assert (followup.ml_probability, followup.calibrated_score) == (0.41, 0.37)
        assert followup.model_scores == original.model_scores
        assert s.scalar(select(func.count()).select_from(AuthenticationAttempt)) == 1
    # Recording an attempt on a completed step-up is refused by the domain layer too.
    with session_scope(h.container.factory) as s:
        row = s.get(RiskAssessment, uuid.UUID(aid2))
        assert row is not None
        from fraud_ai.core.enums import AuthenticationMethod, AuthenticationResult

        _, first = record_attempt(
            s,
            row,
            AuthenticationMethod.WEBAUTHN,
            AuthenticationResult.CANCELLED,
            max_attempts=3,
        )
        assert first is not None and first.decision is Decision.MANUAL_REVIEW
    r = h.post(f"/v1/step-up/{aid2}/webauthn/challenge", cred, {"session_id": session2})
    assert r.json()["error"]["code"] == "STEP_UP_ALREADY_COMPLETED"
    assert user2


def test_payment_callbacks_on_backend(h: Harness) -> None:
    [(aid, _, _)] = _seed_step_up(h.container.factory)
    cred = h.key()
    started = h.post(
        f"/v1/step-up/{aid}/payment", cred, {"token_reference": "tok_backend_1"}
    ).json()
    provider = h.container.payment
    assert isinstance(provider, FakePaymentAuthProvider)
    with h.container.factory() as s:
        row = s.get(PaymentAuthRequest, uuid.UUID(started["request_id"]))
        assert row is not None
        reference = row.provider_reference
    headers, body = provider.simulate_callback(reference, timestamp=int(h.clock().timestamp()))

    def deliver() -> int:
        return int(
            h.client.post(
                "/v1/callbacks/payment/fake",
                content=body,
                headers={**headers, "Content-Type": "application/json"},
            ).status_code
        )

    assert sorted(_parallel(4, deliver)) == [200, 401, 401, 401]  # one accepted, replays refused
    with h.container.factory() as s:
        row = s.get(PaymentAuthRequest, uuid.UUID(started["request_id"]))
        assert row is not None and row.status.value == "authenticated"
        assert s.scalar(select(func.count()).select_from(AuthenticationAttempt)) == 1


def test_step_up_error_carries_status() -> None:
    err = StepUpError("X", "y")
    assert err.status == 409 and err.code == "X"
