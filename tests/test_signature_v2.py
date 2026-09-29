"""Stage 11 request-signature v2: binds method, canonical path/query, timestamp and the body
digest; downgrade protection with SIGNATURE_MIN_VERSION; key rotation; replay."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from fraud_ai.config.settings import Environment, Settings
from fraud_ai.service.signatures import (
    RequestTarget,
    SignatureError,
    canonical_target,
    canonical_v2,
    check_signature,
    select_signature,
    sign,
    sign_v2,
)
from tests.service_helpers import MASTER_KEY, Clock, Harness, make_harness

NOW = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)
TS = int(NOW.timestamp())
PREVIOUS = "previous-signing-master-key-0123456789ab"
SECRET = "unit-test-signing-secret-0123456789abcd"


def _h(url: str, **overrides: Any) -> Iterator[Harness]:
    values: dict[str, Any] = {"service_require_signatures": True, "signature_min_version": "v2"}
    values.update(overrides)
    h = make_harness(url, clock=Clock(NOW), **values)
    try:
        yield h
    finally:
        h.container.close()
        h.container.engine.dispose()


@pytest.fixture
def h(sqlite_url: str) -> Iterator[Harness]:
    yield from _h(sqlite_url)


def _code(response: Any) -> str:
    return str(response.json()["error"]["code"])


def _send(
    h: Harness,
    credential: str,
    *,
    method: str,
    path: str,
    signed: dict[str, str],
    body: bytes = b"",
) -> Any:
    headers = {**h.auth(credential), **signed}
    if method == "GET":
        return h.client.get(path, headers=headers)
    return h.client.post(
        path, content=body, headers={**headers, "Content-Type": "application/json"}
    )


# ------------------------------------------------------------------ unit: canonical form
def test_canonical_target_edge_cases() -> None:
    assert canonical_target("") == "/"
    assert canonical_target("/v1/reviews") == "/v1/reviews"
    assert canonical_target("/v1/reviews/") != canonical_target("/v1/reviews")  # distinct
    # Query order, percent-encoding case and '+' vs '%20' do not matter...
    a = canonical_target("/v1/reviews", "status=open&limit=50")
    assert (
        a
        == canonical_target("/v1/reviews", "limit=50&status=open")
        == ("/v1/reviews?limit=50&status=open")
    )
    assert canonical_target("/v1/x", "q=a+b") == canonical_target("/v1/x", "q=a%20b")
    assert canonical_target("/v1/%7euser") == canonical_target("/v1/~user") == "/v1/~user"
    assert canonical_target("/v1/a%2fb") == canonical_target("/v1/a%2Fb")
    # ...but values, repeated keys and blank values do.
    assert canonical_target("/v1/x", "a=1&a=2") == "/v1/x?a=1&a=2"
    assert canonical_target("/v1/x", "a=1") != canonical_target("/v1/x", "a=1&a=1")
    assert canonical_target("/v1/x", "e=") == "/v1/x?e="
    assert canonical_target("/v1/café") == "/v1/caf%C3%A9"
    # Reserved characters in values are always escaped, so '&'/'=' cannot be smuggled.
    assert canonical_target("/v1/x", "a=%26b%3D1") == "/v1/x?a=%26b%3D1"
    assert canonical_target("/v1/x", "a=%26b%3D1") != canonical_target("/v1/x", "a=&b=1")


def test_canonical_message_layout() -> None:
    message = canonical_v2("post", "/v1/score", "", TS, b"{}")
    lines = message.decode().split("\n")
    assert lines[0] == "fraud-ai-v2" and lines[1] == "POST" and lines[2] == "/v1/score"
    assert lines[3] == str(TS)
    assert lines[4] == "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"


def test_v2_binds_method_path_query_body_and_timestamp() -> None:
    body = b'{"amount":"12.34"}'
    target = RequestTarget("POST", "/v1/score")
    good = sign_v2(SECRET, "POST", "/v1/score", TS, body)

    def check(signature: str, **kw: Any) -> datetime:
        return check_signature(
            SECRET,
            str(kw.get("ts", TS)),
            signature,
            kw.get("body", body),
            now=NOW,
            max_age=300,
            target=kw.get("target", target),
            min_version="v2",
        )

    assert check(good) == NOW
    tampered = {
        "path": {"target": RequestTarget("POST", "/v1/step-up/x/payment")},
        "method": {"target": RequestTarget("PUT", "/v1/score")},
        "query": {"target": RequestTarget("POST", "/v1/score", "dry_run=1")},
        "body": {"body": b'{"amount":"99.99"}'},
        "timestamp": {"ts": TS + 1},
    }
    for name, change in tampered.items():
        with pytest.raises(SignatureError) as err:
            check(good, **change)
        assert err.value.code == "INVALID_SIGNATURE", name
    # v1 over the same body does not bind the path: exactly the gap v2 closes.
    v1 = sign(SECRET, TS, body)
    other = RequestTarget("POST", "/v1/elsewhere")
    assert check_signature(
        SECRET, str(TS), v1, body, now=NOW, max_age=300, target=other, min_version="v1"
    )


def test_signature_header_parsing_and_version_selection() -> None:
    v1, v2 = "v1=" + "a" * 64, "v2=" + "b" * 64
    assert select_signature(f"{v1},{v2}", "v1") == ("v2", v2)  # strongest present wins
    assert select_signature(f"{v2}, {v1}", "v2") == ("v2", v2)
    assert select_signature(v1, "v1") == ("v1", v1)
    with pytest.raises(SignatureError) as err:
        select_signature(v1, "v2")
    assert err.value.code == "SIGNATURE_VERSION_REJECTED"
    for bad in ("v3=" + "a" * 64, "v2=zz", f"{v2},{v2}", "v2" + "a" * 64, "", "v2=" + "A" * 64):
        with pytest.raises(SignatureError) as err:
            select_signature(bad, "v1")
        assert err.value.code == "INVALID_SIGNATURE", bad


def test_a_valid_v1_next_to_an_invalid_v2_is_not_a_fallback() -> None:
    body = b"{}"
    header = sign(SECRET, TS, body) + ",v2=" + "0" * 64
    with pytest.raises(SignatureError) as err:
        check_signature(
            SECRET,
            str(TS),
            header,
            body,
            now=NOW,
            max_age=300,
            target=RequestTarget("POST", "/v1/score"),
            min_version="v1",
        )
    assert err.value.code == "INVALID_SIGNATURE"


def test_min_version_defaults() -> None:
    assert Settings(database_url="sqlite:///x.db").effective_signature_min_version == "v1"
    prod = Settings.model_construct(environment=Environment.PRODUCTION, signature_min_version=None)
    assert prod.effective_signature_min_version == "v2"
    explicit = Settings(database_url="sqlite:///x.db", signature_min_version="v2")
    assert explicit.effective_signature_min_version == "v2"


# ------------------------------------------------------------------ service
def test_service_accepts_v2_and_refuses_tampering(h: Harness) -> None:
    credential = h.key()
    body = json.dumps({"not": "an event"}).encode()
    ok = _send(
        h,
        credential,
        method="POST",
        path="/v1/score",
        body=body,
        signed=h.signed(credential, body, version="v2", path="/v1/score"),
    )
    assert ok.status_code == 422  # authenticated; the event itself is invalid

    h.clock.now += timedelta(seconds=1)
    for_score = h.signed(credential, body, version="v2", path="/v1/score")
    moved = _send(h, credential, method="POST", path="/v1/step-up/x/payment", body=body,
                  signed=for_score)  # fmt: skip
    assert moved.status_code == 401 and _code(moved) == "INVALID_SIGNATURE"

    h.clock.now += timedelta(seconds=1)
    as_post = h.signed(credential, b"", version="v2", method="POST", path="/v1/reviews")
    method = _send(h, credential, method="GET", path="/v1/reviews", signed=as_post)
    assert _code(method) == "INVALID_SIGNATURE"

    h.clock.now += timedelta(seconds=1)
    q = "/v1/reviews?status=open"
    signed_q = h.signed(credential, b"", version="v2", method="GET", path=q)
    changed = _send(h, credential, method="GET", path="/v1/reviews?status=resolved",
                    signed=signed_q)  # fmt: skip
    assert _code(changed) == "INVALID_SIGNATURE"
    reordered = h.signed(credential, b"", version="v2", method="GET",
                         path="/v1/reviews?limit=5&status=open")  # fmt: skip
    same = _send(h, credential, method="GET", path="/v1/reviews?status=open&limit=5",
                 signed=reordered)  # fmt: skip
    assert same.status_code == 200  # canonical query order

    h.clock.now += timedelta(seconds=1)
    good = h.signed(credential, body, version="v2", path="/v1/score")
    changed_body = _send(h, credential, method="POST", path="/v1/score",
                         body=body + b" ", signed=good)  # fmt: skip
    assert _code(changed_body) == "INVALID_SIGNATURE"
    shifted = {**good, "X-Fraud-Timestamp": str(int(h.clock().timestamp()) + 1)}
    assert _code(_send(h, credential, method="POST", path="/v1/score", body=body,
                       signed=shifted)) == "INVALID_SIGNATURE"  # fmt: skip


def test_service_replay_of_a_v2_signature(h: Harness) -> None:
    credential = h.key("review:read")
    signed = h.signed(credential, b"", version="v2", method="GET", path="/v1/reviews")
    assert _send(h, credential, method="GET", path="/v1/reviews", signed=signed).status_code == 200
    again = _send(h, credential, method="GET", path="/v1/reviews", signed=signed)
    assert again.status_code == 401 and _code(again) == "REPLAYED_SIGNATURE"


def test_downgrade_to_v1_is_refused_not_ignored(h: Harness) -> None:
    credential = h.key("review:read")
    v1 = h.signed(credential, b"", version="v1", method="GET", path="/v1/reviews")
    r = _send(h, credential, method="GET", path="/v1/reviews", signed=v1)
    assert r.status_code == 401 and _code(r) == "SIGNATURE_VERSION_REJECTED"
    metrics = h.container.metrics.render().decode()
    assert 'fraud_api_signature_failures_total{code="SIGNATURE_VERSION_REJECTED"} 1.0' in metrics


def test_v1_still_accepted_during_migration(sqlite_url: str) -> None:
    for h in _h(sqlite_url, signature_min_version="v1"):
        credential = h.key("review:read")
        v1 = h.signed(credential, b"", version="v1", method="GET", path="/v1/reviews")
        assert _send(h, credential, method="GET", path="/v1/reviews", signed=v1).status_code == 200
        h.clock.now += timedelta(seconds=1)
        v2 = h.signed(credential, b"", version="v2", method="GET", path="/v1/reviews")
        assert _send(h, credential, method="GET", path="/v1/reviews", signed=v2).status_code == 200


def test_v2_with_key_rotation(sqlite_url: str) -> None:
    rotated = {
        "service_signing_key_version": "2",
        "service_signing_previous_key": PREVIOUS,
        "service_signing_previous_key_version": "1",
        "service_signing_previous_key_expires_at": NOW + timedelta(hours=1),
        "service_signing_master_key": MASTER_KEY,
    }
    for h in _h(sqlite_url, **rotated):
        credential = h.key("review:read")

        def get(master: str, h: Harness = h, credential: str = credential) -> Any:
            h.clock.now += timedelta(seconds=1)
            signed = h.signed(
                credential, b"", version="v2", method="GET", path="/v1/reviews", master=master
            )
            return _send(h, credential, method="GET", path="/v1/reviews", signed=signed)

        assert get(MASTER_KEY).status_code == 200  # current key
        assert get(PREVIOUS).status_code == 200  # previous key, inside the grace period
        h.clock.now = NOW + timedelta(hours=2)  # grace over: the old key is dead
        assert _code(get(PREVIOUS)) == "INVALID_SIGNATURE"
        assert _code(get("never-configured-master-key-0123456789")) == "INVALID_SIGNATURE"
        assert get(MASTER_KEY).status_code == 200
