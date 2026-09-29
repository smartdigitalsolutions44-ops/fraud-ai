"""Stage 9 service security tests, on an empty migrated database.

Covers keys, scopes, rate limits, request limits, signatures, strict validation, network
signal integrity, CORS and OpenAPI defaults, sanitised errors, secret redaction and
metrics hygiene.
"""

from __future__ import annotations

import hmac
import json
import logging
import re
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from fraud_ai.config.settings import Environment, Settings, parse_rate
from fraud_ai.database.engine import session_scope
from fraud_ai.database.models import RequestIdempotency, RequestReplayToken, ServiceApiKey
from fraud_ai.realtime.service import ScoringOutcome
from fraud_ai.service import keys as keys_module
from fraud_ai.service.app import ServiceConfigurationError, build_container
from fraud_ai.service.keys import (
    ServiceKeyError,
    create_key,
    list_keys,
    parse_credential,
    revoke_key,
    verify_key,
)
from fraud_ai.service.network import claimed_intel, client_address, headers_of
from fraud_ai.service.rate_limit import InMemoryRateLimiter
from fraud_ai.service.signatures import SignatureError, check_signature, sign
from tests.service_helpers import MASTER_KEY, Clock, Harness, make_harness

UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
NOW = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)


def _event(**overrides: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "event_type": "TRANSACTION_CREATED",
        "timestamp": (NOW - timedelta(seconds=5)).isoformat(),
        "user_id": str(uuid.uuid4()),
        "session_id": "sess-1",
        "device_id": "device-A",
        "source": "api",
        "schema_version": 1,
        "metadata": {
            "transaction_id": str(uuid.uuid4()),
            "amount": "12.34",
            "currency": "GBP",
            "merchant_category": "5411",
            "channel": "web",
            "payment_method_id": str(uuid.uuid4()),
        },
    }
    event.update(overrides)
    return event


def _harness(url: str, **kwargs: Any) -> Iterator[Harness]:
    h = make_harness(url, clock=Clock(NOW), **kwargs)
    try:
        yield h
    finally:
        h.container.close()
        h.container.engine.dispose()


@pytest.fixture
def h(sqlite_url: str) -> Iterator[Harness]:
    yield from _harness(sqlite_url)


def _error(response: Any) -> dict[str, Any]:
    body = response.json()
    assert set(body) == {"error"}, body
    error = body["error"]
    assert {"code", "message", "correlation_id"} <= set(error)
    assert error["correlation_id"] == response.headers["x-correlation-id"]
    return dict(error)


# ------------------------------------------------------------------ health / headers
def test_health_is_public_and_carries_security_headers(h: Harness) -> None:
    r = h.get("/v1/health", None)
    assert r.status_code == 200 and r.json() == {"status": "ok", "api_version": "fraud-api-1.0.0"}
    for name, value in {
        "x-content-type-options": "nosniff",
        "cache-control": "no-store",
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
        "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    }.items():
        assert r.headers[name] == value
    assert "server" not in r.headers
    assert "strict-transport-security" not in r.headers  # only with SERVICE_HSTS behind TLS


def test_correlation_ids_are_reused_only_when_safe(h: Harness) -> None:
    good = h.get("/v1/health", None, headers={"X-Correlation-ID": "req-12345678"})
    assert good.headers["x-correlation-id"] == "req-12345678"
    for bad in ("<script>alert(1)</script>", "short", "x" * 200, "a b c d e f g h"):
        r = h.get("/v1/health", None, headers={"X-Correlation-ID": bad})
        assert r.headers["x-correlation-id"] != bad
        assert re.fullmatch(r"[0-9a-f]{32}", r.headers["x-correlation-id"])


def test_hsts_only_when_enabled(sqlite_url: str) -> None:
    for h in _harness(sqlite_url, service_hsts=True):
        assert "max-age" in h.get("/v1/health", None).headers["strict-transport-security"]


def test_readiness_without_policy_is_not_ready_and_never_needs_the_llm(h: Harness) -> None:
    r = h.get("/v1/ready", None)
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "not_ready"
    assert body["checks"] == {
        "database": "ok",
        "migrations": "ok",
        "active_policy": "missing",
        "primary_model": "missing",
        "shared_state": "not_required",
        "signing_key": "not_required",
        "llm": "not_required",
    }


def test_readiness_reports_database_failure_without_details(h: Harness) -> None:
    h.container.engine.dispose()
    original = h.container.engine.connect

    def broken() -> Any:
        raise RuntimeError("could not connect to /secret/path password=hunter2")

    h.container.engine.connect = broken  # type: ignore[method-assign]
    try:
        r = h.get("/v1/ready", None)
    finally:
        h.container.engine.connect = original  # type: ignore[method-assign]
    assert r.status_code == 503 and r.json()["checks"]["database"] == "failed"
    assert "hunter2" not in r.text and "/secret" not in r.text


# ------------------------------------------------------------------ API keys
def test_missing_malformed_unknown_wrong_and_revoked_keys_get_the_same_401(h: Harness) -> None:
    credential = h.key("assessment:read")
    key_id, secret = credential.split(".", 1)
    with session_scope(h.container.factory) as s:
        revoked = create_key(s, "old", ["assessment:read"])
        revoke_key(s, revoked.key_id)
    path = f"/v1/assessments/{uuid.uuid4()}"
    cases = {
        "missing": {},
        "not bearer": {"Authorization": f"Basic {credential}"},
        "malformed": {"Authorization": "Bearer not-a-key"},
        "unknown": {"Authorization": f"Bearer fak_{'0' * 16}.{secret}"},
        "wrong secret": {"Authorization": f"Bearer {key_id}.{'A' * 43}"},
        "revoked": {"Authorization": f"Bearer {revoked.credential}"},
    }
    bodies = set()
    for headers in cases.values():
        r = h.client.get(path, headers=headers)
        assert r.status_code == 401
        assert r.headers["www-authenticate"].startswith("Bearer")
        error = _error(r)
        bodies.add((error["code"], error["message"]))
    assert bodies == {("UNAUTHENTICATED", "missing or invalid API credentials")}
    assert h.get(path, credential).status_code == 404  # the valid key passes auth


def test_wrong_scope_is_forbidden(h: Harness) -> None:
    credential = h.key("review:read")
    r = h.post("/v1/score", credential, _event())
    assert r.status_code == 403 and _error(r)["code"] == "INSUFFICIENT_SCOPE"
    assert h.get("/v1/metrics", credential).status_code == 403


class _CountingHmac:
    def __init__(self, compare: Any) -> None:
        self.compare_digest = compare


def test_secrets_are_stored_hashed_and_compared_in_constant_time(
    h: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    with session_scope(h.container.factory) as s:
        issued = create_key(s, "svc", ["score:write", "score:write"])
    assert issued.scopes == ("score:write",)
    with h.container.factory() as s:
        row = s.scalar(select(ServiceApiKey).where(ServiceApiKey.key_id == issued.key_id))
        assert row is not None
        stored = json.dumps([row.key_id, row.name, row.secret_salt, row.secret_sha256, row.scopes])
        assert issued.secret not in stored and len(row.secret_sha256) == 64
        calls: list[int] = []
        real = hmac.compare_digest

        def counting(a: Any, b: Any) -> bool:
            calls.append(1)
            return real(a, b)

        monkeypatch.setattr(keys_module, "hmac", _CountingHmac(counting))
        assert verify_key(s, issued.credential) is not None
        assert verify_key(s, f"fak_{'1' * 16}.{issued.secret}") is None  # unknown id
        assert verify_key(s, "garbage") is None
        assert verify_key(s, None) is None
        assert len(calls) == 4  # a comparison happens on every path
        assert [k.key_id for k in list_keys(s)] == [issued.key_id]


def test_key_validation_errors(h: Harness) -> None:
    with session_scope(h.container.factory) as s:
        with pytest.raises(ServiceKeyError, match="unknown scope"):
            create_key(s, "x", ["admin:everything"])
        with pytest.raises(ServiceKeyError, match="at least one"):
            create_key(s, "x", [])
        with pytest.raises(ServiceKeyError, match="name"):
            create_key(s, "", ["score:write"])
        with pytest.raises(ServiceKeyError, match="unknown key"):
            revoke_key(s, "fak_0000000000000000")
        issued = create_key(s, "x", ["score:write"])
        first = revoke_key(s, issued.key_id).revoked_at
        assert revoke_key(s, issued.key_id).revoked_at == first  # idempotent
    assert parse_credential("fak_0123456789abcdef.short") is None
    assert parse_credential("fak_XYZ.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") is None


# ------------------------------------------------------------------ rate limiting
def test_rate_limit_is_per_key_and_route(sqlite_url: str) -> None:
    for h in _harness(sqlite_url, rate_limit="2/minute", rate_limit_burst=2):
        a, b = h.key("assessment:read", "review:read"), h.key("assessment:read")
        path = f"/v1/assessments/{uuid.uuid4()}"
        assert [h.get(path, a).status_code for _ in range(2)] == [404, 404]
        limited = h.get(path, a)
        assert limited.status_code == 429 and _error(limited)["code"] == "RATE_LIMITED"
        assert int(limited.headers["retry-after"]) >= 1
        # The client address is not the identity: spoofed forwarding headers do not help.
        spoofed = h.get(path, a, headers={"X-Forwarded-For": "203.0.113.9"})
        assert spoofed.status_code == 429
        assert h.get(path, b).status_code == 404  # another key has its own bucket
        assert h.get("/v1/reviews", a).status_code == 200  # another route too


def test_repeated_auth_failures_are_throttled(sqlite_url: str) -> None:
    for h in _harness(sqlite_url, rate_limit="2/minute", rate_limit_burst=2):
        codes = [
            h.client.get(
                "/v1/reviews",
                headers={"Authorization": "Bearer nope", "X-Forwarded-For": f"198.51.100.{i}"},
            ).status_code
            for i in range(3)
        ]
        assert codes == [401, 401, 429]


def test_token_bucket_refills() -> None:
    now = [0.0]
    limiter = InMemoryRateLimiter(60, 60.0, 2, clock=lambda: now[0])
    assert [limiter.hit("k").allowed for _ in range(3)] == [True, True, False]
    assert limiter.hit("k").retry_after == 1
    now[0] += 1.0
    assert limiter.hit("k").allowed
    assert limiter.hit("other").allowed
    small = InMemoryRateLimiter(1, 1.0, 1, clock=lambda: now[0])
    small.MAX_BUCKETS = 3
    for i in range(10):
        small.hit(f"b{i}")
    assert len(small._buckets) <= 3


def test_parse_rate() -> None:
    assert parse_rate("120/minute") == (120, 60.0)
    assert parse_rate("5/second") == (5, 1.0)
    for bad in ("120", "x/minute", "10/week", "0/minute"):
        with pytest.raises(ValueError):
            parse_rate(bad)


# ------------------------------------------------------------------ request limits / validation
def test_oversize_requests_are_refused(sqlite_url: str) -> None:
    for h in _harness(sqlite_url, request_size_limit=1024):
        credential = h.key()
        big = json.dumps(_event(padding="x" * 2000)).encode()
        r = h.post("/v1/score", credential, raw=big)
        assert r.status_code == 413 and _error(r)["code"] == "REQUEST_TOO_LARGE"

        def chunks() -> Iterator[bytes]:  # no Content-Length: counted while streaming
            for _ in range(4):
                yield b"x" * 600

        streamed = h.client.post(
            "/v1/score",
            content=chunks(),
            headers={"Content-Type": "application/json", **h.auth(credential)},
        )
        assert streamed.status_code == 413
        bad_length = h.client.post(
            "/v1/score", content=b"{}", headers={"Content-Length": "abc", **h.auth(credential)}
        )
        assert bad_length.status_code == 400


@pytest.mark.parametrize(
    ("change", "fragment"),
    [
        ({"event_type": "TELEPORT"}, "event_type"),
        ({"schema_version": 99}, "schema_version"),
        ({"event_id": "not-a-uuid"}, "event_id"),
        ({"user_id": "123"}, "user_id"),
        ({"timestamp": "yesterday"}, "timestamp"),
        ({"timestamp": "2026-07-01T12:00:00"}, "timestamp"),  # naive
        ({"timestamp": (NOW + timedelta(hours=2)).isoformat()}, "future"),
        ({"unexpected": "not-a-key-SECRETVALUE"}, "unexpected"),
        ({"session_id": None}, "session_id"),
    ],
)
def test_malformed_events_are_rejected_without_echoing_values(
    h: Harness, change: dict[str, Any], fragment: str
) -> None:
    credential = h.key()
    r = h.post("/v1/score", credential, _event(**change))
    assert r.status_code == 422, r.text
    error = _error(r)
    assert error["code"] == "INVALID_EVENT" and fragment in error["message"]
    assert "SECRETVALUE" not in r.text and "TELEPORT" not in r.text


def test_missing_fields_and_bad_bodies(h: Harness) -> None:
    credential = h.key()
    missing = _event()
    del missing["event_id"]
    r = h.post("/v1/score", credential, missing)
    assert r.status_code == 422 and "event_id" in _error(r)["message"]
    assert h.post("/v1/score", credential, [1, 2]).status_code == 422
    assert _error(h.post("/v1/score", credential, raw=b"{not json"))["code"] == "INVALID_JSON"
    wrong_type = h.client.post(
        "/v1/score", content=b"{}", headers={"Content-Type": "text/plain", **h.auth(credential)}
    )
    assert wrong_type.status_code == 415
    forbidden = _event()
    forbidden["metadata"]["card_number"] = "4111111111111111"
    r = h.post("/v1/score", credential, forbidden)
    assert r.status_code == 422 and "4111" not in r.text


def test_unknown_user_is_rejected_with_ids_redacted(h: Harness) -> None:
    event = _event()
    r = h.post("/v1/score", h.key(), event)
    assert r.status_code == 422 and _error(r)["code"] == "INVALID_EVENT"
    assert event["user_id"] not in r.text


def test_client_supplied_network_intelligence_needs_the_trusted_scope(h: Harness) -> None:
    merchant = h.key("score:write")
    event = _event()
    event["metadata"]["network"] = {"ip": "203.0.113.5", "is_known_vpn": False}
    r = h.post("/v1/score", merchant, event)
    assert r.status_code == 422
    error = _error(r)
    assert error["code"] == "UNTRUSTED_SIGNAL"
    assert "metadata.network.is_known_vpn" in error["message"]
    # The plain address is an application-visible fact, not intelligence: it passes this
    # check (and then fails later only because the user is unknown).
    event["metadata"]["network"] = {"ip": "203.0.113.5", "network_type": "unknown"}
    assert _error(h.post("/v1/score", merchant, event))["code"] == "INVALID_EVENT"
    trusted = h.key("score:write", "signals:trusted")
    event["metadata"]["network"] = {"ip": "203.0.113.5", "is_known_vpn": False}
    assert _error(h.post("/v1/score", trusted, event))["code"] == "INVALID_EVENT"


def test_claimed_intel_paths() -> None:
    assert claimed_intel([]) == []
    assert claimed_intel({"metadata": "x"}) == []
    assert claimed_intel({"metadata": {"network": "x"}}) == []
    net = {"network_type": "datacenter", "is_tor": None, "proxy_confidence": 0.1}
    assert claimed_intel({"metadata": {"network": net}}) == [
        "metadata.network.network_type",
        "metadata.network.proxy_confidence",
    ]


def test_arrival_time_requires_the_replay_scope(h: Harness) -> None:
    event = _event(arrival_time=NOW.isoformat())
    r = h.post("/v1/score", h.key("score:write"), event)
    assert r.status_code == 403 and "score:replay" in _error(r)["message"]
    bad = _event(arrival_time="soon")
    assert _error(h.post("/v1/score", h.key(), bad))["code"] == "INVALID_EVENT"


def test_invalid_idempotency_keys(h: Harness) -> None:
    r = h.post("/v1/score", h.key(), _event(), headers={"Idempotency-Key": "bad key!"})
    assert r.status_code == 400 and _error(r)["code"] == "INVALID_IDEMPOTENCY_KEY"


def test_failed_requests_release_their_idempotency_key(h: Harness) -> None:
    credential = h.key()
    headers = {"Idempotency-Key": "retry-me-0001"}
    assert h.post("/v1/score", credential, _event(), headers=headers).status_code == 422
    with h.container.factory() as s:
        assert s.scalar(select(RequestIdempotency)) is None


# ------------------------------------------------------------------ signatures
@pytest.fixture
def signed_h(sqlite_url: str) -> Iterator[Harness]:
    yield from _harness(sqlite_url, service_require_signatures=True)


def test_signed_requests(signed_h: Harness) -> None:
    h = signed_h
    credential = h.key()
    other = h.key()
    body = json.dumps(_event()).encode()
    base = {"Content-Type": "application/json", **h.auth(credential)}

    def send(extra: dict[str, str], content: bytes = body) -> Any:
        return h.client.post("/v1/score", content=content, headers={**base, **extra})

    assert _error(send({}))["code"] == "MISSING_SIGNATURE"
    ts = int(NOW.timestamp())
    assert _error(send({"X-Fraud-Timestamp": str(ts)}))["code"] == "MISSING_SIGNATURE"
    good = h.signed(credential, body)
    first = send(good)
    assert first.status_code == 422  # authenticated; the event itself fails validation
    replay = send(good)
    assert replay.status_code == 401 and _error(replay)["code"] == "REPLAYED_SIGNATURE"
    tampered = send(h.signed(credential, body), content=body.replace(b"12.34", b"99.99"))
    assert _error(tampered)["code"] == "INVALID_SIGNATURE"
    wrong_key = send(h.signed(other, body))
    assert _error(wrong_key)["code"] == "INVALID_SIGNATURE"
    for skew in (-400, 400):
        stale = send(h.signed(credential, body, timestamp=ts + skew))
        assert _error(stale)["code"] == "EXPIRED_SIGNATURE"
    for weird in ("abc", "9" * 30):
        headers = {**h.signed(credential, body), "X-Fraud-Timestamp": weird}
        assert _error(send(headers))["code"] == "INVALID_SIGNATURE"
    with h.container.factory() as s:
        assert len(list(s.scalars(select(RequestReplayToken)))) == 1
    # A GET is signed over the empty body.
    get_headers = {**h.auth(credential), **h.signed(credential, b"")}
    assert h.client.get("/v1/reviews", headers=get_headers).status_code == 200


def test_replay_tokens_expire(signed_h: Harness) -> None:
    h = signed_h
    credential = h.key()
    body = b"{}"
    h.post("/v1/score", credential, raw=body, sign_it=True)
    h.clock.now = NOW + timedelta(seconds=h.settings.signature_max_age + 5)
    h.post("/v1/score", credential, raw=body, sign_it=True)
    with h.container.factory() as s:
        tokens = list(s.scalars(select(RequestReplayToken)))
    assert len(tokens) == 1  # the expired one was pruned


def test_optional_signatures_are_still_verified_when_present(h: Harness) -> None:
    credential = h.key("review:read")
    assert h.get("/v1/reviews", credential).status_code == 200  # unsigned is allowed
    bad = {**h.auth(credential), "X-Fraud-Timestamp": str(int(NOW.timestamp()))}
    bad["X-Fraud-Signature"] = "v1=" + "0" * 64
    assert _error(h.client.get("/v1/reviews", headers=bad))["code"] == "INVALID_SIGNATURE"


def test_signature_headers_without_signing_configured(sqlite_url: str) -> None:
    for h in _harness(sqlite_url, service_signing_master_key=None):
        credential = h.key("review:read")
        headers = {**h.auth(credential), "X-Fraud-Signature": "v1=00"}
        r = h.client.get("/v1/reviews", headers=headers)
        assert r.status_code == 400 and _error(r)["code"] == "SIGNING_NOT_CONFIGURED"


def test_check_signature_unit() -> None:
    body = b'{"a":1}'
    ts = int(NOW.timestamp())
    signature = sign("s" * 32, ts, body)
    assert check_signature("s" * 32, str(ts), signature, body, now=NOW, max_age=60) == NOW
    with pytest.raises(SignatureError) as err:
        check_signature("t" * 32, str(ts), signature, body, now=NOW, max_age=60)
    assert err.value.code == "INVALID_SIGNATURE"


# ------------------------------------------------------------------ proxies
def test_forwarding_headers_are_ignored_unless_the_peer_is_a_trusted_proxy() -> None:
    xff = {"x-forwarded-for": "203.0.113.50, 10.0.0.2"}
    assert client_address("198.51.100.1", xff, []) == "198.51.100.1"
    trusted = Settings(trusted_proxies="10.0.0.0/8").trusted_proxy_networks
    assert client_address("198.51.100.1", xff, trusted) == "198.51.100.1"  # untrusted peer
    assert client_address("10.0.0.1", xff, trusted) == "203.0.113.50"
    assert client_address("10.0.0.1", {"x-forwarded-for": "10.0.0.3"}, trusted) == "10.0.0.1"
    assert client_address("10.0.0.1", {"x-forwarded-for": "junk"}, trusted) == "10.0.0.1"
    forwarded = {"forwarded": 'for="[2001:db8::1]:443";proto=https, for=10.0.0.9'}
    assert client_address("10.0.0.1", forwarded, trusted) == "2001:db8::1"
    assert client_address("10.0.0.1", {"forwarded": "for=192.0.2.4:8080"}, trusted) == ("192.0.2.4")
    assert client_address("testclient", xff, trusted) is None
    assert client_address(None, xff, trusted) is None
    assert headers_of([(b"X-A", b"1"), (b"x-a", b"2")]) == {"x-a": "1,2"}


# ------------------------------------------------------------------ CORS / OpenAPI
def test_cors_is_disabled_by_default(h: Harness) -> None:
    preflight = h.client.options(
        "/v1/score",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert "access-control-allow-origin" not in preflight.headers
    r = h.get("/v1/health", None, headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers


def test_cors_only_for_configured_origins(sqlite_url: str) -> None:
    for h in _harness(sqlite_url, service_cors_origins="https://ops.example"):
        ok = h.get("/v1/health", None, headers={"Origin": "https://ops.example"})
        assert ok.headers["access-control-allow-origin"] == "https://ops.example"
        other = h.get("/v1/health", None, headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in other.headers


def test_openapi_is_hidden_by_default(h: Harness) -> None:
    for path in ("/v1/openapi.json", "/v1/docs", "/docs", "/openapi.json", "/redoc"):
        assert h.get(path, None).status_code == 404


def test_openapi_when_exposed_has_no_model_internals(sqlite_url: str) -> None:
    for h in _harness(sqlite_url, service_expose_openapi=True):
        r = h.get("/v1/openapi.json", None)
        assert r.status_code == 200
        text = r.text
        assert "/v1/score" in text and "/v1/step-up/webauthn/verify" in text
        for internal in ("ml_probability", "calibrated_score", "model_scores", "model_path"):
            assert internal not in text
        assert h.get("/v1/docs", None).status_code == 200


# ------------------------------------------------------------------ errors
def test_errors_are_structured_and_sanitised(h: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _error(h.get("/v1/nope", None))["code"] == "NOT_FOUND"
    assert _error(h.client.delete("/v1/health"))["code"] == "METHOD_NOT_ALLOWED"
    credential = h.key()

    def explode(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("psycopg OperationalError at /srv/app/db.py: password=hunter2")

    monkeypatch.setattr(h.container.scoring, "score_event", explode)
    r = h.post("/v1/score", credential, _event())
    assert r.status_code == 500
    assert _error(r) | {"correlation_id": None} == {
        "code": "INTERNAL_ERROR",
        "message": "internal error",
        "correlation_id": None,
    }
    for leak in ("hunter2", "/srv", "psycopg", "Traceback", "RuntimeError"):
        assert leak not in r.text
    invalid = h.post(f"/v1/reviews/{uuid.uuid4()}/resolve", credential, {"resolution": 5})
    assert invalid.status_code == 422 and _error(invalid)["code"] == "VALIDATION_ERROR"
    extra = h.post(
        f"/v1/reviews/{uuid.uuid4()}/resolve",
        credential,
        {"resolution": "fraud", "sneaky": "sneaky-zzz-value"},
    )
    assert extra.status_code == 422 and "sneaky-zzz-value" not in extra.text
    bad_id = h.get("/v1/assessments/not-a-uuid", credential)
    assert bad_id.status_code == 422 and "not-a-uuid" not in bad_id.text


def test_scoring_timeout_and_database_failure_never_allow(
    sqlite_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    for h in _harness(sqlite_url, service_request_timeout=0.2):
        credential = h.key()
        monkeypatch.setattr(h.container.scoring, "score_event", lambda *a, **k: time.sleep(1))
        slow = h.post("/v1/score", credential, _event())
        assert slow.status_code == 503
        assert _error(slow)["code"] == "SCORING_TIMEOUT"
        assert slow.json()["error"]["fallback_decision"] == "MANUAL_REVIEW"
        failed = ScoringOutcome("not_persisted", uuid.uuid4(), error="OperationalError")
        monkeypatch.setattr(
            h.container.scoring, "score_event", lambda *a, _failed=failed, **k: _failed
        )
        down = h.post("/v1/score", credential, _event())
        assert down.status_code == 503 and _error(down)["code"] == "SCORING_UNAVAILABLE"
        assert down.json()["error"]["fallback_decision"] == "MANUAL_REVIEW"
        assert "OperationalError" not in down.text


def test_policy_unavailable_and_unknown_resources(h: Harness) -> None:
    credential = h.key()
    assert _error(h.get("/v1/policy", credential))["code"] == "POLICY_UNAVAILABLE"
    assert h.get(f"/v1/reviews/{uuid.uuid4()}", credential).status_code == 404
    r = h.post(f"/v1/reviews/{uuid.uuid4()}/resolve", credential, {"resolution": "fraud"})
    assert r.status_code == 404
    assert h.get(f"/v1/assessments/{uuid.uuid4()}", credential).status_code == 404
    r = h.post(f"/v1/assessments/{uuid.uuid4()}/investigate", credential, {})
    assert _error(r)["code"] == "LLM_UNAVAILABLE"


# ------------------------------------------------------------------ secrets / metrics
def test_secrets_never_reach_logs_or_responses(
    signed_h: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    h = signed_h
    caplog.set_level(logging.DEBUG)
    with session_scope(h.container.factory) as s:
        issued = create_key(s, "svc", ["score:write", "metrics:read"])
    body = json.dumps(_event()).encode()
    headers = h.signed(issued.credential, body)
    responses = [
        h.post("/v1/score", issued.credential, raw=body, headers=headers),
        h.post("/v1/score", issued.credential, raw=body, headers=headers),  # replay
        h.post("/v1/score", f"{issued.key_id}.{'B' * 43}", raw=body),
        h.get("/v1/metrics", issued.credential, headers=h.signed(issued.credential, b"")),
    ]
    haystack = caplog.text + "".join(r.text for r in responses)
    for secret in (issued.secret, MASTER_KEY, headers["X-Fraud-Signature"].split("=", 1)[1]):
        assert secret not in haystack


def test_metrics_never_label_ids(h: Harness) -> None:
    credential = h.key()
    h.get(f"/v1/assessments/{uuid.uuid4()}", credential)
    h.post("/v1/score", credential, _event())
    h.client.get("/v1/reviews", headers={"Authorization": "Bearer nope"})
    r = h.get("/v1/metrics", credential)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    text = r.text
    assert 'route="/v1/assessments/{assessment_id}"' in text
    assert "fraud_api_auth_failures_total" in text and "fraud_api_review_queue" in text
    assert not UUID_RE.search(text)
    assert credential.split(".")[0] not in text and "testclient" not in text


def test_metrics_render_when_the_database_is_down(
    h: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    credential = h.key("metrics:read")
    from fraud_ai.realtime import review

    def down(session: Any) -> Any:
        raise RuntimeError("down")

    monkeypatch.setattr(review, "queue_size", down)
    assert h.get("/v1/metrics", credential).status_code == 200


# ------------------------------------------------------------------ settings
@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"service_signing_master_key": "short"}, "at least 32"),
        ({"payment_auth_webhook_secret": "short"}, "at least 32"),
        ({"service_require_signatures": True}, "SERVICE_SIGNING_MASTER_KEY"),
        ({"payment_auth_provider": "fake"}, "PAYMENT_AUTH_WEBHOOK_SECRET"),
        ({"payment_auth_provider": "acme"}, "fake"),
        ({"trusted_proxies": "10.0.0.0/8, not-an-ip"}, "TRUSTED_PROXIES"),
        ({"rate_limit": "lots"}, "RATE_LIMIT"),
    ],
)
def test_service_settings_validation(values: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Settings(**values)


def test_production_refuses_development_service_settings() -> None:
    import secrets as pysecrets

    strong = pysecrets.token_urlsafe(32)
    base: dict[str, Any] = {
        "environment": Environment.PRODUCTION,
        "database_url": f"postgresql+psycopg://u:{pysecrets.token_urlsafe(16)}@db/x",
        "pseudonymisation_key": strong,
    }
    http_origin = Settings(**base)  # batch/CLI jobs need no service configuration
    assert "production requires an https WEBAUTHN_ORIGIN" in http_origin.service_problems()
    with pytest.raises(ServiceConfigurationError, match="https WEBAUTHN_ORIGIN"):
        build_container(http_origin)
    with pytest.raises(ValidationError, match="fake payment-auth"):
        Settings(
            **base,
            webauthn_origin="https://pay.example",
            payment_auth_provider="fake",
            payment_auth_webhook_secret=pysecrets.token_urlsafe(32),
        )
    from fraud_ai.trust.keys import encode_public, generate

    ok = Settings(
        **base,
        webauthn_origin="https://pay.example",
        service_signing_master_key=pysecrets.token_urlsafe(32),
        service_require_signatures=True,
        # Stage 11: production requires signed models, hence a trusted model key.
        model_signing_public_keys=encode_public(generate().public),
    )
    assert ok.service_problems() == []
    assert ok.requires_model_signatures and ok.effective_signature_min_version == "v2"
    assert ok.effective_policy_approvals == 2
    unsigned = Settings(**{**ok.model_dump(), "model_signing_public_keys": None})
    assert any("MODEL_SIGNING_PUBLIC_KEYS" in p for p in unsigned.service_problems())
    assert ok.cors_origins == [] and ok.trusted_proxy_networks == []
    assert ok.service_host == "127.0.0.1"
    assert ok.requires_promotion and ok.effective_log_format == "json"


@pytest.mark.parametrize(
    ("overrides", "fragment"),
    [
        ({"pseudonymisation_key": "change_me_" + "x9" * 12}, "PSEUDONYMISATION_KEY looks like"),
        ({"pseudonymisation_key": "a" * 40}, "PSEUDONYMISATION_KEY looks like"),
        ({"database_url": "postgresql+psycopg://fraud_ai:fraud_ai_dev@db/x"}, "DATABASE_URL"),
        ({"service_cors_origins": "*"}, "CORS"),
        ({"service_cors_origins": "http://ops.example"}, "CORS"),
        ({"local_llm_runtime": "reference"}, "reference LLM"),
        ({"service_require_signatures": False}, "SERVICE_REQUIRE_SIGNATURES"),
        ({"redis_url": "redis://:password123@r:6379/0", "state_backend": "redis"}, "REDIS_URL"),
    ],
)
def test_production_profile_rejections(overrides: dict[str, Any], fragment: str) -> None:
    import secrets as pysecrets

    values: dict[str, Any] = {
        "environment": Environment.PRODUCTION,
        "database_url": f"postgresql+psycopg://u:{pysecrets.token_urlsafe(16)}@db/x",
        "pseudonymisation_key": pysecrets.token_urlsafe(32),
        "webauthn_origin": "https://pay.example",
        "service_signing_master_key": pysecrets.token_urlsafe(32),
        "service_require_signatures": True,
    }
    values.update(overrides)
    problems = Settings(**values).service_problems()
    assert any(fragment in p for p in problems), problems


def test_staging_may_opt_into_the_fake_provider_but_production_never() -> None:
    import secrets as pysecrets

    base: dict[str, Any] = {
        "database_url": f"postgresql+psycopg://u:{pysecrets.token_urlsafe(16)}@db/x",
        "pseudonymisation_key": pysecrets.token_urlsafe(32),
        "payment_auth_provider": "fake",
        "payment_auth_webhook_secret": pysecrets.token_urlsafe(32),
        "payment_auth_allow_fake_in_staging": True,
    }
    assert Settings(environment=Environment.STAGING, **base).payment_auth_provider == "fake"
    with pytest.raises(ValidationError, match="production never"):
        Settings(environment=Environment.PRODUCTION, **base)
    with pytest.raises(ValidationError, match="STRIPE_API_KEY"):
        Settings(payment_auth_provider="stripe", payment_auth_webhook_secret="w" * 40)


def test_fake_provider_callback_validation() -> None:
    from fraud_ai.stepup.payment import FakePaymentAuthProvider

    provider = FakePaymentAuthProvider("w" * 40)
    ts = int(NOW.timestamp())

    def headers(body: bytes) -> dict[str, str]:
        return {
            "x-provider-id": "fake",
            "x-provider-timestamp": str(ts),
            "x-provider-signature": sign("w" * 40, ts, body),
        }

    for body in (
        b"not json",
        json.dumps({"provider_reference": "r", "status": "pending"}).encode(),
    ):
        with pytest.raises(SignatureError) as err:
            provider.verify_callback(headers(body), body, now=NOW, max_age=60)
        assert err.value.code == "INVALID_CALLBACK"
    assert provider.get_status("unknown").value == "pending"
