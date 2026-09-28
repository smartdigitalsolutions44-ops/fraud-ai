"""Stage 10 shared state: memory and Redis backends, multi-process races, and the service
using it (distributed rate limits, distributed replay protection, fail-closed on outage,
signing-key rotation)."""

from __future__ import annotations

import json
import multiprocessing
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from fraud_ai.service.app import signing_keys
from fraud_ai.service.keys import signing_secret
from fraud_ai.service.signatures import sign
from fraud_ai.state.base import SharedState, StateUnavailableError
from fraud_ai.state.memory import MemoryState
from fraud_ai.state.redis import RedisState
from tests.service_helpers import MASTER_KEY, Clock, Harness, make_harness, settings_for

NOW = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)
PREVIOUS = "previous-signing-master-key-0123456789ab"


@pytest.fixture(params=["memory", "redis"])
def state(request: pytest.FixtureRequest) -> Iterator[SharedState]:
    if request.param == "memory":
        yield MemoryState()
        return
    url = request.getfixturevalue("flushed_redis")
    backend = RedisState(url, prefix=f"t-{uuid.uuid4().hex[:6]}:")
    yield backend
    backend.close()


def test_token_bucket_is_deterministic(state: SharedState) -> None:
    decisions = [state.token_bucket("k", rate=0.001, capacity=3).allowed for _ in range(5)]
    assert decisions == [True, True, True, False, False]
    refused = state.token_bucket("k", rate=0.001, capacity=3)
    assert refused.retry_after >= 1 and refused.remaining == 0
    assert state.token_bucket("other", rate=0.001, capacity=3).allowed


def test_token_bucket_refills(state: SharedState) -> None:
    assert state.token_bucket("r", rate=20.0, capacity=1).allowed
    assert not state.token_bucket("r", rate=20.0, capacity=1).allowed
    time.sleep(0.12)
    assert state.token_bucket("r", rate=20.0, capacity=1).allowed


def test_claims_are_single_use_and_expire(state: SharedState) -> None:
    assert state.claim("sig", 0.2) is True
    assert state.claim("sig", 0.2) is False
    time.sleep(0.3)
    assert state.claim("sig", 0.2) is True


def test_locks_compare_and_delete(state: SharedState) -> None:
    token = state.acquire_lock("job", 5)
    assert token is not None and state.acquire_lock("job", 5) is None
    assert state.release_lock("job", "not-the-owner") is False
    assert state.release_lock("job", token) is True
    assert state.acquire_lock("job", 5) is not None
    assert state.ping() >= 0.0


def test_redis_bucket_state_expires(flushed_redis: str) -> None:
    import redis

    backend = RedisState(flushed_redis, prefix="exp:")
    backend.token_bucket("idle", rate=10.0, capacity=5)
    client = redis.Redis.from_url(flushed_redis)
    ttl = client.pttl("exp:rl:idle")
    assert 0 < ttl <= 1600  # the refill time plus one second, never unbounded
    assert client.pttl("exp:rl:idle") != -1
    client.close()
    backend.close()


def test_redis_unavailable_raises() -> None:
    backend = RedisState("redis://127.0.0.1:1/0", timeout=0.2)
    for call in (
        lambda: backend.token_bucket("k", rate=1, capacity=1),
        lambda: backend.claim("k", 1),
        backend.ping,
    ):
        with pytest.raises(StateUnavailableError):
            call()


# ------------------------------------------------------------------ multi-process races
def _hammer_bucket(url: str, prefix: str, n: int, out: Any) -> None:
    backend = RedisState(url, prefix=prefix)
    out.put(sum(backend.token_bucket("shared", rate=0.0001, capacity=10).allowed for _ in range(n)))
    backend.close()


def _claim_once(url: str, prefix: str, out: Any) -> None:
    backend = RedisState(url, prefix=prefix)
    out.put(backend.claim("replay:same-signature", 30))
    backend.close()


def test_distributed_rate_limit_across_processes(flushed_redis: str) -> None:
    ctx = multiprocessing.get_context("spawn")
    out = ctx.Queue()
    procs = [
        ctx.Process(target=_hammer_bucket, args=(flushed_redis, "mp:", 20, out)) for _ in range(4)
    ]
    for p in procs:
        p.start()
    allowed = [out.get(timeout=60) for _ in procs]
    for p in procs:
        p.join(timeout=30)
    assert sum(allowed) == 10  # 80 attempts from 4 processes; exactly the capacity passes


def test_distributed_replay_claim_across_processes(flushed_redis: str) -> None:
    ctx = multiprocessing.get_context("spawn")
    out = ctx.Queue()
    procs = [ctx.Process(target=_claim_once, args=(flushed_redis, "mp2:", out)) for _ in range(8)]
    for p in procs:
        p.start()
    results = [out.get(timeout=60) for _ in procs]
    for p in procs:
        p.join(timeout=30)
    assert results.count(True) == 1 and results.count(False) == 7


# ------------------------------------------------------------------ the service on Redis
def _two_workers(url: str, redis_url: str, **kwargs: Any) -> list[Harness]:
    """Two independent containers (as two uvicorn workers would be) on one Redis."""
    workers = []
    for _ in range(2):
        state = RedisState(redis_url, prefix="svc:")
        workers.append(
            make_harness(
                url,
                clock=Clock(NOW),
                shared_state=state,
                state_backend="redis",
                redis_url=redis_url,
                **kwargs,
            )
        )
    return workers


@pytest.fixture
def workers(sqlite_url: str, flushed_redis: str) -> Iterator[list[Harness]]:
    pair = _two_workers(sqlite_url, flushed_redis, service_require_signatures=True)
    yield pair
    for h in pair:
        h.container.close()
        h.container.engine.dispose()


def test_signature_accepted_by_one_worker_is_rejected_by_another(workers: list[Harness]) -> None:
    a, b = workers
    credential = a.key("review:read")
    headers = {**a.auth(credential), **a.signed(credential, b"")}
    assert a.client.get("/v1/reviews", headers=headers).status_code == 200
    replay = b.client.get("/v1/reviews", headers=headers)
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "REPLAYED_SIGNATURE"
    assert a.client.get("/v1/reviews", headers=headers).status_code == 401


def test_rate_limit_is_shared_between_workers(sqlite_url: str, flushed_redis: str) -> None:
    pair = _two_workers(sqlite_url, flushed_redis, rate_limit="2/minute", rate_limit_burst=2)
    try:
        a, b = pair
        credential = a.key("review:read")
        codes = [
            a.get("/v1/reviews", credential).status_code,
            b.get("/v1/reviews", credential).status_code,
            a.get("/v1/reviews", credential).status_code,
            b.get("/v1/reviews", credential).status_code,
        ]
        assert codes == [200, 200, 429, 429]
    finally:
        for h in pair:
            h.container.close()
            h.container.engine.dispose()


def test_redis_outage_fails_closed(sqlite_url: str) -> None:
    down = RedisState("redis://127.0.0.1:1/0", timeout=0.2)
    h = make_harness(
        sqlite_url,
        clock=Clock(NOW),
        shared_state=down,
        state_backend="redis",
        redis_url="redis://127.0.0.1:1/0",
    )
    try:
        credential = h.key("review:read")
        r = h.get("/v1/reviews", credential)
        assert r.status_code == 503 and r.json()["error"]["code"] == "STATE_UNAVAILABLE"
        anonymous = h.client.get("/v1/reviews", headers={"Authorization": "Bearer nope"})
        assert anonymous.status_code == 503
        ready = h.get("/v1/ready", None).json()
        assert ready["checks"]["shared_state"] == "failed" and ready["status"] == "not_ready"
        metrics = h.container.metrics.render().decode()
        assert 'fraud_api_state_unavailable_total{what="rate_limit"}' in metrics
    finally:
        h.container.close()
        h.container.engine.dispose()


# ------------------------------------------------------------------ signing-key rotation
def _rotated(url: str, **overrides: Any) -> Harness:
    values: dict[str, Any] = {
        "service_require_signatures": True,
        "service_signing_key_version": "2",
        "service_signing_previous_key": PREVIOUS,
        "service_signing_previous_key_version": "1",
        "service_signing_previous_key_expires_at": NOW + timedelta(hours=1),
    }
    values.update(overrides)
    return make_harness(url, clock=Clock(NOW), **values)


def _signed_get(
    h: Harness, credential: str, master: str, extra: dict[str, str] | None = None
) -> Any:
    ts = int(h.clock().timestamp())
    key_id = credential.split(".", 1)[0]
    headers = {
        **h.auth(credential),
        "X-Fraud-Timestamp": str(ts),
        "X-Fraud-Signature": sign(signing_secret(master, key_id), ts, b""),
        **(extra or {}),
    }
    return h.client.get("/v1/reviews", headers=headers)


def test_signing_key_rotation_grace_period(sqlite_url: str) -> None:
    h = _rotated(sqlite_url)
    try:
        credential = h.key("review:read")
        assert _signed_get(h, credential, MASTER_KEY).status_code == 200  # current key
        h.clock.now += timedelta(seconds=1)
        assert _signed_get(h, credential, PREVIOUS).status_code == 200  # previous, in grace
        h.clock.now += timedelta(seconds=1)
        pinned = _signed_get(h, credential, PREVIOUS, {"X-Fraud-Key-Version": "2"})
        assert pinned.json()["error"]["code"] == "INVALID_SIGNATURE"  # wrong version pinned
        h.clock.now = NOW + timedelta(hours=1, seconds=5)  # grace over
        expired = _signed_get(h, credential, PREVIOUS)
        assert expired.status_code == 401 and expired.json()["error"]["code"] == "INVALID_SIGNATURE"
        assert _signed_get(h, credential, MASTER_KEY).status_code == 200
        metrics = h.container.metrics.render().decode()
        assert 'fraud_api_signatures_verified_total{key_version="1"} 1.0' in metrics
        assert 'fraud_api_signatures_verified_total{key_version="2"} 2.0' in metrics
    finally:
        h.container.close()
        h.container.engine.dispose()


def test_signing_key_settings_validation() -> None:
    from pydantic import ValidationError

    base = {"database_url": "sqlite:///x.db"}
    with pytest.raises(ValidationError, match="VERSION"):
        settings_for(base["database_url"], service_signing_previous_key=PREVIOUS)
    with pytest.raises(ValidationError, match="different version"):
        settings_for(
            base["database_url"],
            service_signing_previous_key=PREVIOUS,
            service_signing_previous_key_version="1",
            service_signing_previous_key_expires_at=NOW,
        )
    with pytest.raises(ValidationError, match="must differ"):
        settings_for(
            base["database_url"],
            service_signing_key_version="2",
            service_signing_previous_key=MASTER_KEY,
            service_signing_previous_key_version="1",
            service_signing_previous_key_expires_at=NOW,
        )
    with pytest.raises(ValidationError, match="REDIS_URL"):
        settings_for(base["database_url"], state_backend="redis")
    with pytest.raises(ValidationError, match="STATE_BACKEND"):
        settings_for(base["database_url"], state_backend="memcached")
    naive = settings_for(
        base["database_url"],
        service_signing_key_version="2",
        service_signing_previous_key=PREVIOUS,
        service_signing_previous_key_version="1",
        service_signing_previous_key_expires_at=datetime(2026, 7, 1, 13, 0),
    )
    keys = signing_keys(naive)
    assert [k.version for k in keys] == ["2", "1"] and keys[1].not_after == NOW + timedelta(hours=1)
    assert PREVIOUS not in repr(keys)
    assert json.dumps([k.version for k in keys])
