"""Stage 10 chaos / failure injection: every failure is conservative (503, fallback to
MANUAL_REVIEW, or not ready) and never an ALLOW.

Covered elsewhere: Redis unavailable (test_state), payment provider down/timeout
(test_service_flows, test_stripe_provider), worker restart (test_multiprocess), artefact
changed on disk while running (test_hardening_world)."""

from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, event, text

from fraud_ai.config.settings import Settings
from fraud_ai.service.health import readiness
from tests.realtime_world import World, open_world
from tests.service_helpers import Harness, make_harness


@pytest.fixture
def w(realtime_world_dir: Path, tmp_path: Path) -> Iterator[World]:
    yield from open_world(realtime_world_dir, tmp_path)


def _first_transaction(h: Harness, w: World, cred: str) -> dict[str, Any]:
    """Score the stream up to the first decided transaction."""
    for event_ in w.events:
        r = h.score(cred, event_)
        body = r.json()
        if event_["event_type"] == "TRANSACTION_CREATED":
            return {**body, "http": r.status_code}
    raise AssertionError("no transaction")


def test_database_unavailable(tmp_path: Path) -> None:
    url = "postgresql+psycopg://fraud_ai:x@127.0.0.1:1/none?connect_timeout=1"
    h = make_harness(url)
    try:
        assert h.get("/v1/health", None).status_code == 200  # liveness stays up
        ready = h.get("/v1/ready", None)
        assert ready.status_code == 503 and ready.json()["checks"]["database"] == "failed"
        r = h.client.get(
            "/v1/reviews", headers={"Authorization": "Bearer fak_0123456789abcdef." + "a" * 43}
        )
        assert r.status_code == 503
        assert r.json()["error"]["code"] == "DATABASE_UNAVAILABLE"
        assert "127.0.0.1" not in r.text and "psycopg" not in r.text
    finally:
        h.container.close()
        h.container.engine.dispose()


def test_corrupted_artifact_in_a_fresh_process_falls_back(w: World) -> None:
    with w.session() as s:
        path = Path(
            str(
                s.scalar(
                    text("SELECT model_path FROM model_versions WHERE model_name = :n"),
                    {"n": "gradient-boosting"},
                )
            )
        )
    for f in path.iterdir():
        if f.suffix != ".json":
            f.write_bytes(f.read_bytes() + b"corrupt")
    h = make_harness(w.url, engine=w.engine)  # a fresh process: empty model cache
    try:
        assert h.get("/v1/ready", None).json()["checks"]["primary_model"] == "failed"
        cred = h.key()
        decided = _first_transaction(h, w, cred)
        assert decided["http"] == 200 and decided["decision"] == "MANUAL_REVIEW"
        assert decided["fallback_used"] is True
    finally:
        h.container.close()


def test_deleted_artifact_in_a_fresh_process_falls_back(w: World) -> None:
    import shutil

    shutil.rmtree(w.root / "models")
    h = make_harness(w.url, engine=w.engine)
    try:
        decided = _first_transaction(h, w, h.key())
        assert decided["decision"] == "MANUAL_REVIEW" and decided["fallback_used"]
        metrics = h.get("/v1/metrics", h.key()).text
        assert "fraud_api_fallbacks_total" in metrics
    finally:
        h.container.close()


def test_signing_key_missing_fails_closed(sqlite_url: str) -> None:
    with pytest.raises(ValidationError, match="SERVICE_SIGNING_MASTER_KEY"):
        Settings(service_require_signatures=True)
    h = make_harness(sqlite_url, service_require_signatures=True)
    try:
        h.container.signing_keys = ()  # e.g. a secret that failed to mount
        assert readiness(h.container)["signing_key"] == "missing"
        cred = h.key("review:read")
        r = h.get("/v1/reviews", cred)
        # With no key to verify against, a required signature cannot be accepted.
        assert r.status_code == 503 and r.json()["error"]["code"] == "SIGNING_UNAVAILABLE"
    finally:
        h.container.close()
        h.container.engine.dispose()


def test_slow_database_times_out_to_review(w: World) -> None:
    h = make_harness(w.url, engine=w.engine, service_request_timeout=1.0)

    def slow(*_: Any) -> None:
        time.sleep(0.05)

    try:
        cred = h.key()
        event.listen(w.engine, "before_cursor_execute", slow)
        decided = _first_transaction(h, w, cred)
        assert decided["http"] == 503
        assert decided["error"]["code"] == "SCORING_TIMEOUT"
        assert decided["error"]["fallback_decision"] == "MANUAL_REVIEW"
    finally:
        if event.contains(w.engine, "before_cursor_execute", slow):
            event.remove(w.engine, "before_cursor_execute", slow)
        h.container.close()


def test_connection_pool_exhaustion(sqlite_url: str) -> None:
    engine = create_engine(sqlite_url, pool_size=1, max_overflow=0, pool_timeout=0.3)
    h = make_harness(sqlite_url, engine=engine)
    try:
        cred = h.key("review:read")
        held = engine.connect()  # the only connection is busy
        try:
            r = h.get("/v1/reviews", cred)
            assert r.status_code == 503
            assert r.json()["error"]["code"] == "DATABASE_UNAVAILABLE"
            assert h.get("/v1/ready", None).status_code == 503
        finally:
            held.close()
        assert h.get("/v1/reviews", cred).status_code == 200  # recovers once released
    finally:
        h.container.close()
        engine.dispose()
