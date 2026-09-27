"""Stage 9 functional flows over HTTP on the Stage 8 world.

Covers:

* signed score → STEP_UP → passkey → verified assertion → immutable follow-up;
* WebAuthn failure, expiry, cancellation and replay;
* fake payment authentication, including callback replay, timeout and outage;
* the MANUAL_REVIEW and ALLOW flows;
* idempotency and concurrency;
* the LLM's independence from scoring.
"""

from __future__ import annotations

import json
import threading
import uuid
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select

from fraud_ai.core.enums import Decision
from fraud_ai.database.models import (
    AuthenticationAttempt,
    AuthenticationChallenge,
    EventRecord,
    PaymentAuthRequest,
    ReviewItem,
    RiskAssessment,
    WebAuthnCredential,
)
from fraud_ai.stepup.payment import FakePaymentAuthProvider
from tests.realtime_world import World, open_world
from tests.service_helpers import WEBHOOK_SECRET, Harness, SoftAuthenticator, make_harness

STEP_UP = "STEP_UP_AUTHENTICATION"
FORBIDDEN_KEYS = {
    "ml_probability",
    "calibrated_score",
    "final_risk_score",
    "model_scores",
    "triggered_rules",
    "shadow",
    "features",
    "latency_ms",
    "failures",
}


@pytest.fixture
def w(realtime_world_dir: Path, tmp_path: Path) -> Iterator[World]:
    yield from open_world(realtime_world_dir, tmp_path)


def _harness(w: World, **kwargs: Any) -> Iterator[Harness]:
    h = make_harness(w.url, engine=w.engine, **kwargs)
    try:
        yield h
    finally:
        h.container.close()


@pytest.fixture
def h(w: World) -> Iterator[Harness]:
    yield from _harness(w)


def _keys(body: Any) -> set[str]:
    if isinstance(body, dict):
        return set(body) | {k for v in body.values() for k in _keys(v)}
    if isinstance(body, list):
        return {k for v in body for k in _keys(v)}
    return set()


def _context(w: World, assessment_id: str) -> tuple[str, str]:
    with w.session() as s:
        row = s.get(RiskAssessment, uuid.UUID(assessment_id))
        assert row is not None
        record = s.get(EventRecord, row.event_id)
        assert record is not None and record.session_id
        return str(row.user_id), record.session_id


def _snapshot(w: World, assessment_id: str) -> dict[str, Any]:
    with w.session() as s:
        row = s.get(RiskAssessment, uuid.UUID(assessment_id))
        assert row is not None
        return {
            c.name: getattr(row, c.key)
            for c in RiskAssessment.__table__.columns
            if hasattr(row, c.key)
        }


def _register(h: Harness, cred: str, user_id: str, counter: int = 0) -> SoftAuthenticator:
    authenticator = SoftAuthenticator(counter=counter)
    challenge = h.post("/v1/webauthn/registrations/challenge", cred, {"user_id": user_id})
    assert challenge.status_code == 200, challenge.text
    ch = challenge.json()
    done = h.post(
        "/v1/webauthn/registrations",
        cred,
        {
            "challenge_id": ch["challenge_id"],
            "credential": authenticator.register(ch["public_key"]),
        },
    )
    assert done.status_code == 201, done.text
    return authenticator


def _challenge(h: Harness, cred: str, aid: str, session_id: str) -> dict[str, Any]:
    r = h.post(f"/v1/step-up/{aid}/webauthn/challenge", cred, {"session_id": session_id})
    assert r.status_code == 200, r.text
    return dict(r.json())


def _verify(
    h: Harness, cred: str, ch: dict[str, Any], session_id: str, credential: dict[str, Any]
) -> Any:
    return h.post(
        "/v1/step-up/webauthn/verify",
        cred,
        {"challenge_id": ch["challenge_id"], "session_id": session_id, "credential": credential},
    )


def _step_up(h: Harness, w: World, cred: str) -> tuple[dict[str, Any], str, str]:
    body, _ = h.drive(cred, w.events, STEP_UP)
    user_id, session_id = _context(w, body["assessment_id"])
    return body, user_id, session_id


# ------------------------------------------------------------------ the main STEP_UP flow
def test_signed_score_step_up_webauthn_success_creates_an_immutable_followup(
    w: World, h: Harness
) -> None:
    cred = h.key()
    for event in w.events:
        h.clock.now = datetime.fromisoformat(event["arrival_time"])
        r = h.post("/v1/score", cred, event, sign_it=True)
        assert r.status_code in (200, 202), r.text
        body = r.json()
        if body["decision"] == STEP_UP:
            break
    else:  # pragma: no cover
        pytest.fail("no STEP_UP decision")
    assert _keys(body).isdisjoint(FORBIDDEN_KEYS)
    assert body["step_up_required"] and not body["review_required"]
    assert body["policy_version"] == "risk-policy-1.0.0"
    assert body["model_version"] == "gradient-boosting-1.0.0"
    aid = body["assessment_id"]
    before = _snapshot(w, aid)
    user_id, session_id = _context(w, aid)

    authenticator = _register(h, cred, user_id)
    ch = _challenge(h, cred, aid, session_id)
    assert ch["public_key"]["userVerification"] == "required"
    result = _verify(h, cred, ch, session_id, authenticator.assertion(ch["public_key"]))
    assert result.status_code == 200, result.text
    outcome = result.json()
    assert outcome["result"] == "SUCCESS" and outcome["attempt_number"] == 1
    assert "never proof" in outcome["note"]
    followup = outcome["followup"]
    assert followup["decision"] == "ALLOW_WITH_MONITORING"
    assert followup["supersedes_assessment_id"] == aid
    assert followup["assessment_version"] == 2
    assert followup["followup_policy_version"] == "step-up-followup-1.0.0"

    assert _snapshot(w, aid) == before  # the original is never modified
    after = _snapshot(w, followup["assessment_id"])
    for column in ("ml_probability", "calibrated_score", "final_risk_score", "risk_level"):
        assert after[column] == before[column]  # scores copied verbatim
    assert after["model_scores"] == before["model_scores"]
    assert after["mode"] == "step_up_followup"

    view = h.get(f"/v1/assessments/{aid}", cred).json()
    assert _keys(view).isdisjoint(FORBIDDEN_KEYS)
    assert view["decision"] == STEP_UP and not view["step_up_required"]
    assert view["latest_assessment_id"] == followup["assessment_id"]
    assert view["authentication"] == {
        "attempts": 1,
        "latest_result": "SUCCESS",
        "method": "webauthn",
        "completed": True,
        "followup_assessment_id": followup["assessment_id"],
    }
    # The same challenge cannot be used twice; a new step-up is refused.
    replay = _verify(h, cred, ch, session_id, authenticator.assertion(ch["public_key"]))
    assert replay.status_code == 409 and replay.json()["error"]["code"] == "CHALLENGE_INVALID"
    again = h.post(f"/v1/step-up/{aid}/webauthn/challenge", cred, {"session_id": session_id})
    assert again.json()["error"]["code"] == "STEP_UP_ALREADY_COMPLETED"
    # Redelivering the event returns the latest (follow-up) assessment, never a new decision.
    h.clock.now += timedelta(seconds=1)  # a fresh signature (the old one is spent)
    redelivered = h.post("/v1/score", cred, event, sign_it=True).json()
    assert redelivered["status"] == "duplicate"
    assert redelivered["assessment_id"] == followup["assessment_id"]
    with w.session() as s:
        stored = s.scalar(select(WebAuthnCredential))
        assert stored is not None and stored.sign_count == 1 and stored.last_used_at
        assert b"PRIVATE" not in stored.public_key


def test_webauthn_failures_exhaust_attempts_into_manual_review(w: World, h: Harness) -> None:
    cred = h.key()
    body, user_id, session_id = _step_up(h, w, cred)
    aid = body["assessment_id"]
    authenticator = _register(h, cred, user_id)
    reasons = []
    makers: list[Callable[[dict[str, Any]], dict[str, Any]]] = [
        lambda o: authenticator.assertion(o, tamper=True),
        lambda o: authenticator.assertion(o, origin="https://evil.example"),
        lambda o: authenticator.assertion(o, flags=0x01),  # user not verified
    ]
    for make in makers:
        ch = _challenge(h, cred, aid, session_id)
        r = _verify(h, cred, ch, session_id, make(ch["public_key"]))
        assert r.status_code == 200 and r.json()["result"] == "FAILED"
        reasons.append(r.json()["failure_reason"])
    assert reasons == ["verification_failed"] * 3
    final = r.json()
    assert final["attempts_remaining"] == 0
    assert final["followup"]["decision"] == "MANUAL_REVIEW"
    assert final["followup"]["review_required"]
    with w.session() as s:
        review = s.scalar(
            select(ReviewItem).where(
                ReviewItem.assessment_id == uuid.UUID(final["followup"]["assessment_id"])
            )
        )
        assert review is not None and review.reason_codes == ["STEP_UP_FAILED"]
    assert h.post(f"/v1/step-up/{aid}/webauthn/challenge", cred, {"session_id": session_id}).json()[
        "error"
    ]["code"] in {"STEP_UP_ALREADY_COMPLETED", "ATTEMPTS_EXHAUSTED"}


def test_webauthn_edge_cases(w: World, h: Harness) -> None:
    cred = h.key()
    body, user_id, session_id = _step_up(h, w, cred)
    aid = body["assessment_id"]
    no_passkey = h.post(f"/v1/step-up/{aid}/webauthn/challenge", cred, {"session_id": session_id})
    assert no_passkey.json()["error"]["code"] == "NO_CREDENTIALS"
    mismatch = h.post(f"/v1/step-up/{aid}/webauthn/challenge", cred, {"session_id": "other"})
    assert mismatch.json()["error"]["code"] == "SESSION_MISMATCH"
    unknown = h.post("/v1/webauthn/registrations/challenge", cred, {"user_id": str(uuid.uuid4())})
    assert unknown.status_code == 404
    authenticator = _register(h, cred, user_id)
    # A second registration of the same authenticator is refused.
    ch = h.post("/v1/webauthn/registrations/challenge", cred, {"user_id": user_id}).json()
    dup = h.post(
        "/v1/webauthn/registrations",
        cred,
        {
            "challenge_id": ch["challenge_id"],
            "credential": authenticator.register(ch["public_key"]),
        },
    )
    assert dup.json()["error"]["code"] == "CREDENTIAL_EXISTS"
    # Registration with a forged challenge fails; a used registration challenge is spent.
    ch = h.post("/v1/webauthn/registrations/challenge", cred, {"user_id": user_id}).json()
    forged = SoftAuthenticator().register({"challenge": "AAAA"})
    bad = h.post(
        "/v1/webauthn/registrations",
        cred,
        {"challenge_id": ch["challenge_id"], "credential": forged},
    )
    assert bad.json()["error"]["code"] == "VERIFICATION_FAILED"
    spent = h.post(
        "/v1/webauthn/registrations",
        cred,
        {
            "challenge_id": ch["challenge_id"],
            "credential": SoftAuthenticator().register(ch["public_key"]),
        },
    )
    assert spent.json()["error"]["code"] == "CHALLENGE_INVALID"
    # Another API key cannot consume this key's challenge.
    other = h.key("stepup:write")
    ch = _challenge(h, cred, aid, session_id)
    stolen = _verify(h, other, ch, session_id, authenticator.assertion(ch["public_key"]))
    assert stolen.json()["error"]["code"] == "CHALLENGE_INVALID"
    # A challenge answered for the wrong session / with a foreign challenge fails.
    wrong_session = _verify(h, cred, ch, "sess-x", authenticator.assertion(ch["public_key"]))
    assert wrong_session.json()["failure_reason"] == "session_mismatch"
    ch = _challenge(h, cred, aid, session_id)
    foreign = authenticator.assertion(ch["public_key"], challenge="Zm9yZWlnbg")
    assert _verify(h, cred, ch, session_id, foreign).json()["failure_reason"] == (
        "challenge_mismatch"
    )
    # The attempts are used up; the case went to review, never to ALLOW.
    with w.session() as s:
        results = [a.result.value for a in s.scalars(select(AuthenticationAttempt))]
    assert results == ["FAILED", "FAILED"]
    view = h.get(f"/v1/assessments/{aid}", cred).json()
    assert view["authentication"]["attempts"] == 2 and not view["authentication"]["completed"]


def test_webauthn_expiry_counter_and_malformed(w: World, h: Harness) -> None:
    cred = h.key()
    body, user_id, session_id = _step_up(h, w, cred)
    aid = body["assessment_id"]
    authenticator = _register(h, cred, user_id, counter=5)
    ch = _challenge(h, cred, aid, session_id)
    h.clock.now += timedelta(seconds=h.settings.webauthn_challenge_ttl + 1)
    expired = _verify(h, cred, ch, session_id, authenticator.assertion(ch["public_key"]))
    assert expired.json()["result"] == "EXPIRED"
    ch = _challenge(h, cred, aid, session_id)
    garbage = _verify(h, cred, ch, session_id, {"id": "x"})
    assert garbage.json()["failure_reason"] == "malformed_credential"
    ch = _challenge(h, cred, aid, session_id)
    cloned = _verify(h, cred, ch, session_id, authenticator.assertion(ch["public_key"], counter=3))
    final = cloned.json()
    assert final["result"] == "FAILED"
    assert final["failure_reason"] == "sign_count_regression"  # a cloned authenticator
    assert final["followup"]["decision"] == "MANUAL_REVIEW"


def test_webauthn_cancel_is_terminal_and_goes_to_review(w: World, h: Harness) -> None:
    cred = h.key()
    body, user_id, session_id = _step_up(h, w, cred)
    _register(h, cred, user_id)
    ch = _challenge(h, cred, body["assessment_id"], session_id)
    r = h.post("/v1/step-up/webauthn/cancel", cred, {"challenge_id": ch["challenge_id"]})
    assert r.status_code == 200
    assert r.json()["result"] == "CANCELLED"
    assert r.json()["followup"]["decision"] == "MANUAL_REVIEW"
    again = h.post("/v1/step-up/webauthn/cancel", cred, {"challenge_id": ch["challenge_id"]})
    assert again.json()["error"]["code"] == "CHALLENGE_INVALID"


def test_concurrent_verification_of_one_challenge_succeeds_once(w: World, h: Harness) -> None:
    cred = h.key()
    body, user_id, session_id = _step_up(h, w, cred)
    authenticator = _register(h, cred, user_id)
    ch = _challenge(h, cred, body["assessment_id"], session_id)
    assertion = authenticator.assertion(ch["public_key"])
    results: list[int] = []
    barrier = threading.Barrier(6)

    def worker() -> None:
        barrier.wait()
        results.append(_verify(h, cred, ch, session_id, assertion).status_code)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == [200] + [409] * 5
    with w.session() as s:
        count = s.scalar(select(func.count()).select_from(AuthenticationAttempt))
        followups = s.scalar(
            select(func.count())
            .select_from(RiskAssessment)
            .where(RiskAssessment.mode == "step_up_followup")
        )
    assert count == 1 and followups == 1


# ------------------------------------------------------------------ payment authentication
def _pay(h: Harness, cred: str, aid: str, token: str) -> Any:
    return h.post(
        f"/v1/step-up/{aid}/payment",
        cred,
        {"token_reference": token, "amount_minor": 1999, "currency": "GBP"},
    )


def _callback(h: Harness, headers: dict[str, str], body: bytes, provider: str = "fake") -> Any:
    return h.client.post(
        f"/v1/callbacks/payment/{provider}",
        content=body,
        headers={**headers, "Content-Type": "application/json"},
    )


def test_fake_payment_authentication_success_and_callback_replay(w: World, h: Harness) -> None:
    cred = h.key()
    body, _, _ = _step_up(h, w, cred)
    aid = body["assessment_id"]
    r = _pay(h, cred, aid, "tok_test_0001-authenticated")
    assert r.status_code == 200, r.text
    started = r.json()
    assert started["status"] == "pending" and started["provider"] == "fake"
    assert "not 3-D Secure" in started["next_action"]["note"]
    status = h.get(f"/v1/step-up/payment/{started['request_id']}", cred).json()
    assert status["status"] == "authenticated"  # polled; state changes only by callback
    provider = h.container.payment
    assert isinstance(provider, FakePaymentAuthProvider)
    with w.session() as s:
        row = s.get(PaymentAuthRequest, uuid.UUID(started["request_id"]))
        assert row is not None and row.status.value == "pending"
        assert "tok_test" not in row.token_ref_hash
        reference = row.provider_reference
    ts = int(h.clock().timestamp())
    headers, payload = provider.simulate_callback(reference, timestamp=ts)
    forged = {**headers, "x-provider-signature": "v1=" + "0" * 64}
    assert _callback(h, forged, payload).json()["error"]["code"] == "INVALID_SIGNATURE"
    wrong_id = {**headers, "x-provider-id": "acme"}
    assert _callback(h, wrong_id, payload).json()["error"]["code"] == "UNKNOWN_PROVIDER"
    assert _callback(h, headers, payload, provider="acme").status_code == 404
    stale_headers, stale = provider.simulate_callback(reference, timestamp=ts - 3600)
    assert _callback(h, stale_headers, stale).json()["error"]["code"] == "EXPIRED_SIGNATURE"
    ok = _callback(h, headers, payload)
    assert ok.status_code == 200 and ok.json() == {
        "api_version": "fraud-api-1.0.0",
        "accepted": True,
        "status": "authenticated",
        "result": "SUCCESS",
    }
    replay = _callback(h, headers, payload)
    assert replay.status_code == 401 and replay.json()["error"]["code"] == "REPLAYED_SIGNATURE"
    fresh_headers, fresh = provider.simulate_callback(reference, timestamp=ts + 1)
    duplicate = _callback(h, fresh_headers, fresh)
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "DUPLICATE_CALLBACK"
    unknown_headers, unknown = provider.simulate_callback("fake_nope", timestamp=ts + 2)
    assert _callback(h, unknown_headers, unknown).status_code == 404
    view = h.get(f"/v1/assessments/{aid}", cred).json()
    assert view["authentication"]["method"] == "payment_authentication"
    assert view["authentication"]["latest_result"] == "SUCCESS"
    followup = h.get(f"/v1/assessments/{view['latest_assessment_id']}", cred).json()
    assert followup["decision"] == "ALLOW_WITH_MONITORING"
    assert h.get(f"/v1/step-up/payment/{uuid.uuid4()}", cred).status_code == 404


@pytest.mark.parametrize(("suffix", "result"), [("failed", "FAILED"), ("cancelled", "CANCELLED")])
def test_fake_payment_failure_outcomes(w: World, h: Harness, suffix: str, result: str) -> None:
    cred = h.key()
    body, _, _ = _step_up(h, w, cred)
    started = _pay(h, cred, body["assessment_id"], f"tok_test_0002-{suffix}").json()
    provider = h.container.payment
    assert isinstance(provider, FakePaymentAuthProvider)
    with w.session() as s:
        row = s.get(PaymentAuthRequest, uuid.UUID(started["request_id"]))
        assert row is not None
        reference = row.provider_reference
    headers, payload = provider.simulate_callback(reference, timestamp=int(h.clock().timestamp()))
    ack = _callback(h, headers, payload).json()
    assert ack["result"] == result
    status = h.get(f"/v1/step-up/payment/{started['request_id']}", h.key()).json()
    assert status["status"] == suffix
    if result == "CANCELLED":
        view = h.get(f"/v1/assessments/{body['assessment_id']}", cred).json()
        latest = h.get(f"/v1/assessments/{view['latest_assessment_id']}", cred).json()
        assert latest["decision"] == "MANUAL_REVIEW" and latest["review_required"]


def test_payment_provider_outage_and_timeout_are_never_an_allow(w: World) -> None:
    provider = FakePaymentAuthProvider(WEBHOOK_SECRET, hang_seconds=2.0)
    for h in _harness(w, payment_provider=provider, payment_auth_timeout=0.2):
        cred = h.key()
        body, _, _ = _step_up(h, w, cred)
        aid = body["assessment_id"]
        outcomes = []
        for token in (
            "tok_test_0003-unavailable",
            "tok_test_0004-timeout",
            "tok_test_0005-timeout",
        ):
            r = _pay(h, cred, aid, token)
            assert r.status_code == 200, r.text
            outcomes.append(r.json())
        assert [o["status"] for o in outcomes] == ["unavailable"] * 3
        assert all(o["next_action"]["type"] == "authentication_unavailable" for o in outcomes)
        assert outcomes[0]["followup"] is None and outcomes[1]["followup"] is None
        assert outcomes[2]["followup"]["decision"] == "MANUAL_REVIEW"
        exhausted = _pay(h, cred, aid, "tok_test_0006")
        assert exhausted.json()["error"]["code"] in {
            "STEP_UP_ALREADY_COMPLETED",
            "ATTEMPTS_EXHAUSTED",
        }


def test_payment_step_up_without_a_provider(w: World) -> None:
    for h in _harness(w, payment_provider=None):
        cred = h.key()
        body, _, _ = _step_up(h, w, cred)
        r = _pay(h, cred, body["assessment_id"], "tok_test_0007")
        assert r.status_code == 503
        assert r.json()["error"]["code"] == "PAYMENT_AUTH_NOT_CONFIGURED"
        assert h.get(f"/v1/step-up/payment/{uuid.uuid4()}", cred).status_code == 503
        assert _callback(h, {}, b"{}").status_code == 404


def test_payment_callback_rate_limit(w: World) -> None:
    for h in _harness(w, rate_limit="1/minute", rate_limit_burst=1):
        assert _callback(h, {}, b"{}").status_code == 401
        assert _callback(h, {}, b"{}").status_code == 429


# ------------------------------------------------------------------ review and allow flows
def test_manual_review_flow(w: World, h: Harness) -> None:
    cred = h.key()
    body, _ = h.drive(cred, w.events, "MANUAL_REVIEW")
    assert body["review_required"] and not body["step_up_required"]
    aid = body["assessment_id"]
    listing = h.get("/v1/reviews", cred).json()["items"]
    item = next(i for i in listing if i["assessment_id"] == aid)
    assert _keys(listing).isdisjoint(FORBIDDEN_KEYS)
    detail = h.get(f"/v1/reviews/{item['review_id']}", cred).json()
    assert detail["assessment"]["decision"] == "MANUAL_REVIEW"
    assert _keys(detail).isdisjoint(FORBIDDEN_KEYS)
    pii = h.post(
        f"/v1/reviews/{item['review_id']}/resolve",
        cred,
        {"resolution": "legitimate", "note": "called jane.doe@example.com"},
    )
    assert pii.status_code == 422 and "jane.doe" not in pii.text
    resolved = h.post(
        f"/v1/reviews/{item['review_id']}/resolve",
        cred,
        {"resolution": "legitimate", "note": "customer confirmed by phone"},
    )
    assert resolved.status_code == 200
    out = resolved.json()
    assert (
        out["review"]["status"] == "resolved" and out["outcomes"][0]["resolution"] == "legitimate"
    )
    assert out["assessment"]["decision"] == "MANUAL_REVIEW"  # the decision is never rewritten
    again = h.post(f"/v1/reviews/{item['review_id']}/resolve", cred, {"resolution": "fraud"})
    assert again.status_code == 409
    assert h.get("/v1/reviews?status=all&limit=5", cred).status_code == 200
    assert h.get("/v1/reviews?status=bogus", cred).status_code == 422
    _, session_id = _context(w, aid)
    step = h.post(f"/v1/step-up/{aid}/webauthn/challenge", cred, {"session_id": session_id})
    assert step.json()["error"]["code"] == "STEP_UP_NOT_REQUIRED"


def test_allow_flow_and_policy(w: World, h: Harness) -> None:
    cred = h.key()
    body, _ = h.drive(cred, w.events, "ALLOW")
    assert not body["step_up_required"] and not body["review_required"]
    assert body["action_type"] == "NONE"
    view = h.get(f"/v1/assessments/{body['assessment_id']}", cred).json()
    assert view["review"] is None and view["authentication"]["attempts"] == 0
    policy = h.get("/v1/policy", cred).json()
    assert policy["policy_version"] == "risk-policy-1.0.0"
    assert policy["followup_policy_version"] == "step-up-followup-1.0.0"
    assert set(policy) == {
        "api_version",
        "policy_version",
        "rules_version",
        "primary_model",
        "decision_event_kinds",
        "activated_at",
        "followup_policy_version",
    }
    assert h.get("/v1/ready", None).json()["status"] == "ready"


def test_live_scoring_uses_the_service_clock(w: World, h: Harness) -> None:
    cred = h.key("score:write", "signals:trusted")
    first = w.events[0]
    h.clock.now = datetime.fromisoformat(first["arrival_time"])
    live = {k: v for k, v in first.items() if k != "arrival_time"}
    r = h.post("/v1/score", cred, live)
    assert r.status_code == 202 and r.json()["status"] == "ingested"
    with w.session() as s:
        record = s.get(EventRecord, uuid.UUID(first["event_id"]))
        assert record is not None and record.arrival_time is not None


# ------------------------------------------------------------------ idempotency and concurrency
def test_idempotency_same_and_different_body(w: World, h: Harness) -> None:
    cred = h.key()
    _, nxt = h.drive(cred, w.events, "ALLOW")
    decided_before = _decisions(w)
    event = next(e for e in w.events[nxt:] if e["event_type"] == "TRANSACTION_CREATED")
    h.clock.now = datetime.fromisoformat(event["arrival_time"])
    headers = {"Idempotency-Key": "order-4711-attempt"}
    raw = json.dumps(event).encode()
    first = h.post("/v1/score", cred, raw=raw, headers=headers)
    assert first.status_code == 200 and "idempotent-replayed" not in first.headers
    second = h.post("/v1/score", cred, raw=raw, headers=headers)
    assert second.status_code == 200 and second.headers["idempotent-replayed"] == "true"
    assert second.json() == first.json()
    other_event = next(
        e
        for e in w.events[nxt:]
        if e["event_type"] == "TRANSACTION_CREATED" and e["event_id"] != event["event_id"]
    )
    conflict = h.post("/v1/score", cred, other_event, headers=headers)
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "IDEMPOTENCY_KEY_REUSED"
    with w.session() as s:
        assert s.get(EventRecord, uuid.UUID(other_event["event_id"])) is None  # not processed
    assert _decisions(w) == decided_before + 1
    # The key is scoped to the API key: another key may reuse the same string.
    fresh = h.post("/v1/score", h.key(), raw=raw, headers=headers)
    assert fresh.status_code == 200 and fresh.json()["status"] == "duplicate"


def _decisions(w: World) -> int:
    with w.session() as s:
        return int(s.scalar(select(func.count()).select_from(RiskAssessment)) or 0)


def test_concurrent_idempotent_requests_decide_once(w: World, h: Harness) -> None:
    cred = h.key()
    _, nxt = h.drive(cred, w.events, "MANUAL_REVIEW")
    event = next(e for e in w.events[nxt:] if e["event_type"] == "TRANSACTION_CREATED")
    h.clock.now = datetime.fromisoformat(event["arrival_time"])
    raw = json.dumps(event).encode()
    responses: list[Any] = []
    barrier = threading.Barrier(8)

    def worker(n: int) -> None:
        headers = {"Idempotency-Key": "same-key-123"} if n % 2 == 0 else {}
        barrier.wait()
        responses.append(h.post("/v1/score", cred, raw=raw, headers=headers))

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ok = [r for r in responses if r.status_code == 200]
    assert ok and all(r.status_code in (200, 409) for r in responses)
    assert len({r.json()["assessment_id"] for r in ok}) == 1
    assert all(
        r.json()["error"]["code"] == "IDEMPOTENCY_IN_PROGRESS"
        for r in responses
        if r.status_code == 409
    )
    with w.session() as s:
        n = s.scalar(
            select(func.count())
            .select_from(RiskAssessment)
            .where(RiskAssessment.event_id == uuid.UUID(event["event_id"]))
        )
        reviews = s.scalar(
            select(func.count())
            .select_from(ReviewItem)
            .where(ReviewItem.event_id == uuid.UUID(event["event_id"]))
        )
    assert n == 1
    assert reviews == (1 if ok[0].json()["review_required"] else 0)


def test_concurrent_distinct_events(w: World, h: Harness) -> None:
    cred = h.key()
    _, nxt = h.drive(cred, w.events, STEP_UP)
    batch = w.events[nxt : nxt + 40]
    # Events of one user depend on each other; users are independent, so each thread
    # takes whole users and keeps their events in order.
    users = sorted({str(e.get("user_id")) for e in batch})
    chunks = [[e for e in batch if users.index(str(e.get("user_id"))) % 4 == i] for i in range(4)]
    responses: list[Any] = []
    lock = threading.Lock()

    def worker(chunk: list[dict[str, Any]]) -> None:
        for event in chunk:
            r = h.post("/v1/score", cred, event)
            with lock:
                responses.append(r)

    threads = [threading.Thread(target=worker, args=(chunk,)) for chunk in chunks]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(responses) == len(batch)
    bad = [r.text for r in responses if r.status_code not in (200, 202)]
    assert not bad, bad


# ------------------------------------------------------------------ the LLM stays out of scoring
def test_scoring_works_with_every_llm_runtime_unavailable(w: World) -> None:
    calls: list[int] = []

    def no_llm() -> Any:
        calls.append(1)
        return None

    for h in _harness(w, llm_client=no_llm, local_llm_runtime=None):
        cred = h.key()
        body, _ = h.drive(cred, w.events, STEP_UP)
        assert body["decision"] == STEP_UP and calls == []  # scoring never asks for the LLM
        r = h.post(f"/v1/assessments/{body['assessment_id']}/investigate", cred, {})
        assert r.status_code == 503 and r.json()["error"]["code"] == "LLM_UNAVAILABLE"
        assert "unaffected" in r.json()["error"]["message"]
    for h in _harness(
        w,
        local_llm_runtime="ollama",
        local_llm_model="none",
        local_llm_endpoint="http://127.0.0.1:9",
    ):
        cred = h.key()
        body, _ = h.drive(cred, w.events, "ALLOW")
        assert body["status"] == "decided"
        r = h.post(f"/v1/assessments/{body['assessment_id']}/investigate", cred, {})
        assert r.status_code in (502, 503) and "error" in r.json()


def test_investigation_with_the_reference_runtime(w: World) -> None:
    for h in _harness(w, local_llm_runtime="reference"):
        cred = h.key()
        body, _ = h.drive(cred, w.events, STEP_UP)
        r = h.post(f"/v1/assessments/{body['assessment_id']}/investigate", cred, {})
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["runtime"] == "reference" and out["explanation"]
        assert "nothing was rescored" in out["note"]
        assert h.post(f"/v1/assessments/{uuid.uuid4()}/investigate", cred, {}).status_code == 404
        # Investigating never changes the decision.
        view = h.get(f"/v1/assessments/{body['assessment_id']}", cred).json()
        assert view["decision"] == STEP_UP and view["latest_assessment_id"] == body["assessment_id"]


def test_step_up_on_unknown_assessment(h: Harness) -> None:
    cred = h.key()
    r = h.post(f"/v1/step-up/{uuid.uuid4()}/webauthn/challenge", cred, {"session_id": "s"})
    assert r.status_code == 404
    r = h.post(
        "/v1/step-up/webauthn/verify",
        cred,
        {
            "challenge_id": str(uuid.uuid4()),
            "session_id": "s",
            "credential": {},
        },
    )
    assert r.json()["error"]["code"] == "CHALLENGE_INVALID"
    with h.container.factory() as s:
        assert s.scalar(select(AuthenticationChallenge)) is None
    assert Decision.ALLOW.value == "ALLOW"
