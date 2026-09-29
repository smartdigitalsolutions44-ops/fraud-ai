"""Stage 10 multi-process correctness: the real service with several uvicorn workers on
PostgreSQL + Redis. Requests use fresh connections, so they spread across workers.

Checked: signed-request replay, Idempotency-Key, review creation, WebAuthn challenge
consumption, distributed rate limiting, readiness of every worker (each loads and
verifies its own model cache) and a worker being killed and restarted."""

from __future__ import annotations

import json
import os
import signal
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, ClassVar

import httpx
import pytest
from sqlalchemy import func, select

from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.models import EventRecord, ReviewItem, RiskAssessment
from fraud_ai.service.keys import create_key, signing_secret
from fraud_ai.service.signatures import sign
from tests.service_helpers import ALL_SCOPES, MASTER_KEY, WEBHOOK_SECRET, SoftAuthenticator
from tests.service_process import ServiceProcess, running_service

pytestmark = pytest.mark.postgres
RP_ID, ORIGIN = "localhost", "http://localhost:8080"


class Client:
    """A signing client; every request gets a unique timestamp (hence a unique signature)."""

    _used: ClassVar[dict[bytes, set[int]]] = {}
    _lock = threading.Lock()

    def __init__(self, base_url: str, credential: str) -> None:
        self.base = base_url
        self.credential = credential
        self.secret = signing_secret(MASTER_KEY, credential.split(".", 1)[0])

    def _timestamp(self, body: bytes) -> int:
        """A timestamp within the signature window not yet used for this body."""
        now = int(time.time())
        with self._lock:
            used = self._used.setdefault(body, set())
            for ts in range(now, now - 250, -1):
                if ts not in used:
                    used.add(ts)
                    return ts
        raise AssertionError("no unused timestamp left in the signature window")

    def headers(self, body: bytes, ts: int | None = None) -> dict[str, str]:
        if ts is None:
            ts = self._timestamp(body)
        return {
            "Authorization": f"Bearer {self.credential}",
            "Content-Type": "application/json",
            "X-Fraud-Timestamp": str(ts),
            "X-Fraud-Signature": sign(self.secret, ts, body),
        }

    def post(
        self, path: str, payload: Any, *, extra: dict[str, str] | None = None
    ) -> httpx.Response:
        body = json.dumps(payload).encode()
        return httpx.post(
            self.base + path,
            content=body,
            headers={**self.headers(body), **(extra or {})},
            timeout=60,
        )

    def get(self, path: str) -> httpx.Response:
        return httpx.get(self.base + path, headers=self.headers(b""), timeout=60)


def parallel(n: int, fn: Callable[[int], Any]) -> list[Any]:
    out: list[Any] = [None] * n
    barrier = threading.Barrier(n)

    def run(i: int) -> None:
        barrier.wait()
        out[i] = fn(i)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return out


@pytest.fixture(scope="module")
def world(pg_world: tuple[str, Path]) -> Iterator[dict[str, Any]]:
    url, root = pg_world
    engine = create_db_engine(url)
    events = [json.loads(line) for line in (root / "live.jsonl").read_text().splitlines()]
    yield {"url": url, "root": root, "engine": engine, "events": events}
    engine.dispose()


def _key(world: dict[str, Any], *scopes: str) -> str:
    with session_scope(make_session_factory(world["engine"])) as s:
        return create_key(s, f"mp-{uuid.uuid4().hex[:6]}", list(scopes or ALL_SCOPES)).credential


@pytest.fixture(scope="module")
def service(
    world: dict[str, Any], redis_url: str, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[ServiceProcess]:
    import redis

    client = redis.Redis.from_url(redis_url)
    client.flushdb()
    client.close()
    env = {
        "ENVIRONMENT": "test",
        "DATABASE_URL": world["url"],
        "MODEL_DIRECTORY": str(world["root"] / "models"),
        "STATE_BACKEND": "redis",
        "REDIS_URL": redis_url,
        "SERVICE_SIGNING_MASTER_KEY": MASTER_KEY,
        "SERVICE_REQUIRE_SIGNATURES": "true",
        "RATE_LIMIT": "120/minute",
        "RATE_LIMIT_BURST": "100",
        "SERVICE_REQUEST_TIMEOUT": "60",
        "WEBAUTHN_RP_ID": RP_ID,
        "WEBAUTHN_ORIGIN": ORIGIN,
        "PAYMENT_AUTH_PROVIDER": "fake",
        "PAYMENT_AUTH_WEBHOOK_SECRET": WEBHOOK_SECRET,
        "LOG_FORMAT": "json",
        "DB_POOL_SIZE": "5",
        "DB_MAX_OVERFLOW": "5",
    }
    with running_service(env, workers=3, log_dir=tmp_path_factory.mktemp("mp")) as svc:
        yield svc


def _count(world: dict[str, Any], model: Any, **where: Any) -> int:
    with make_session_factory(world["engine"])() as s:
        stmt = select(func.count()).select_from(model)
        for column, value in where.items():
            stmt = stmt.where(getattr(model, column) == value)
        return int(s.scalar(stmt) or 0)


def _drive(
    c: Client, events: list[dict[str, Any]], decision: str, start: int
) -> tuple[dict[str, Any], int]:
    for i in range(start, len(events)):
        r = c.post("/v1/score", events[i])
        assert r.status_code in (200, 202), r.text
        body = r.json()
        if body.get("decision") == decision and body["status"] == "decided":
            return body, i + 1
    raise AssertionError(f"no {decision}")


def test_multiprocess_invariants(service: ServiceProcess, world: dict[str, Any]) -> None:
    events = world["events"]
    assert len(service.worker_pids()) == 3
    c = Client(service.base_url, _key(world))

    # Every worker reports ready: each verified and loaded its own model cache.
    assert all(
        httpx.get(service.base_url + "/v1/ready", timeout=10).status_code == 200 for _ in range(12)
    )

    step_up, nxt = _drive(c, events, "STEP_UP_AUTHENTICATION", 0)

    # 1. A signed request accepted once is refused by every worker afterwards.
    body = b""
    headers = c.headers(body)
    replay = parallel(
        10,
        lambda _: (
            httpx.get(service.base_url + "/v1/policy", headers=headers, timeout=30).status_code
        ),
    )
    assert sorted(replay) == [200] + [401] * 9

    # 2. Idempotency-Key across workers: one decision.
    target = next(e for e in events[nxt:] if e["event_type"] == "TRANSACTION_CREATED")
    raw = json.dumps(target).encode()
    now = int(time.time())

    def idem(i: int) -> httpx.Response:
        h = {**c.headers(raw, ts=now - 260 - i), "Idempotency-Key": "mp-order-0001"}
        return httpx.post(service.base_url + "/v1/score", content=raw, headers=h, timeout=60)

    responses = parallel(8, idem)
    ok = [r for r in responses if r.status_code == 200]
    assert ok and all(r.status_code in (200, 409) for r in responses), [r.text for r in responses]
    assert len({r.json()["assessment_id"] for r in ok}) == 1
    assert _count(world, RiskAssessment, event_id=uuid.UUID(target["event_id"])) == 1

    # 3. Concurrent redelivery of a MANUAL_REVIEW event: one assessment, one review item.
    review, _ = _drive(c, events, "MANUAL_REVIEW", events.index(target) + 1)
    with make_session_factory(world["engine"])() as s:
        event_id = s.scalar(
            select(RiskAssessment.event_id).where(
                RiskAssessment.assessment_id == uuid.UUID(review["assessment_id"])
            )
        )
    redeliver = next(e for e in events if e["event_id"] == str(event_id))
    c2 = Client(service.base_url, _key(world))  # its own rate-limit bucket
    again = parallel(8, lambda _: c2.post("/v1/score", redeliver))
    assert {r.json().get("status") for r in again} == {"duplicate"}, [r.text for r in again]
    assert _count(world, ReviewItem, event_id=event_id) == 1

    # 4. A WebAuthn challenge is consumed exactly once across workers.
    aid = step_up["assessment_id"]
    with make_session_factory(world["engine"])() as s:
        row = s.get(RiskAssessment, uuid.UUID(aid))
        assert row is not None
        record = s.get(EventRecord, row.event_id)
        assert record is not None
        user_id, session_id = str(row.user_id), record.session_id
    authenticator = SoftAuthenticator(rp_id=RP_ID, origin=ORIGIN)
    ch = c.post("/v1/webauthn/registrations/challenge", {"user_id": user_id}).json()
    reg = c.post(
        "/v1/webauthn/registrations",
        {
            "challenge_id": ch["challenge_id"],
            "credential": authenticator.register(ch["public_key"]),
        },
    )
    assert reg.status_code == 201, reg.text
    ch = c.post(f"/v1/step-up/{aid}/webauthn/challenge", {"session_id": session_id}).json()
    payload = {
        "challenge_id": ch["challenge_id"],
        "session_id": session_id,
        "credential": authenticator.assertion(ch["public_key"]),
    }
    verify = parallel(6, lambda _: c.post("/v1/step-up/webauthn/verify", payload).status_code)
    assert sorted(verify) == [200] + [409] * 5
    assert _count(world, RiskAssessment, supersedes_assessment_id=uuid.UUID(aid)) == 1

    # 5. The rate limit is global: 150 requests from one key share one bucket of 100.
    limited = Client(service.base_url, _key(world, "policy:read"))
    started = time.monotonic()
    codes = parallel(150, lambda _: limited.get("/v1/policy").status_code)
    elapsed = time.monotonic() - started
    allowed = codes.count(200)
    # Exactly the burst, plus whatever the bucket refilled (2 tokens/s) while the burst ran:
    # the bound follows the measured duration, not an assumed one (a loaded machine is slower).
    ceiling = 100 + int(2 * elapsed) + 1
    assert 100 <= allowed <= ceiling, (allowed, round(elapsed, 1))
    assert codes.count(429) == 150 - allowed

    # 6. Kill a worker: uvicorn replaces it; shared state and idempotency survive.
    victims = service.worker_pids()
    os.kill(victims[0], signal.SIGKILL)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        pids = service.worker_pids()
        if len(pids) == 3 and victims[0] not in pids:
            break
        time.sleep(0.5)
    assert len(service.worker_pids()) == 3 and victims[0] not in service.worker_pids()
    ready = 0
    deadline = time.monotonic() + 90
    while ready < 6 and time.monotonic() < deadline:
        try:
            ready += httpx.get(service.base_url + "/v1/ready", timeout=10).status_code == 200
        except httpx.HTTPError:
            time.sleep(0.5)
    assert ready >= 6
    after = parallel(6, lambda _: c2.post("/v1/score", redeliver).json()["assessment_id"])
    assert set(after) == {review["assessment_id"]}
    stale = httpx.get(service.base_url + "/v1/policy", headers=headers, timeout=30)
    assert stale.status_code == 401  # the replay claim lives in Redis, not in a worker
    log = service.log()
    assert '"level": "ERROR"' not in log.replace("startup refused", "")
