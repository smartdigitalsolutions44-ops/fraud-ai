"""Stage 8 units without a database: the event contract, the model cache, structured
logging and in-process metrics."""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from fraud_ai.realtime.cache import ModelCache
from fraud_ai.realtime.contract import (
    CONTRACT_VERSION,
    EventContractError,
    check_clock,
    parse_incoming,
)
from fraud_ai.realtime.telemetry import Metrics, event_ref, log_decision, percentiles

T = datetime(2026, 7, 1, 12, tzinfo=UTC)


def event(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "event_type": "LOGIN_SUCCESS",
        "timestamp": T.isoformat(),
        "user_id": str(uuid.uuid4()),
        "session_id": "s-1",
        "device_id": "d-1",
        "source": "web",
        "metadata": {"auth_method": "password"},
        "schema_version": 1,
    }
    data.update(overrides)
    return {k: v for k, v in data.items() if v is not ...}


# ------------------------------------------------------------------ contract
def test_valid_event_parses() -> None:
    incoming = parse_incoming(event())
    assert incoming.decision_kind == "login" and incoming.arrival_time is None
    assert CONTRACT_VERSION == "realtime-event-1"
    txn = parse_incoming(
        event(
            event_type="TRANSACTION_CREATED",
            metadata={"transaction_id": str(uuid.uuid4()), "amount": "10.00", "currency": "GBP"},
        )
    )
    assert txn.decision_kind == "transaction"
    reset = parse_incoming(event(event_type="PASSWORD_RESET", metadata={}, session_id=...))
    assert reset.decision_kind is None


@pytest.mark.parametrize(
    "field", ["event_id", "event_type", "timestamp", "schema_version", "source"]
)
def test_required_fields(field: str) -> None:
    with pytest.raises(EventContractError, match=field):
        parse_incoming(event(**{field: ...}))


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"session_id": ...}, "requires session_id"),
        ({"schema_version": 9}, "schema_version"),
        ({"event_type": "NOT_A_TYPE"}, "event_type"),
        ({"timestamp": "2026-07-01T12:00:00"}, "timestamp"),
        ({"user_id": ..., "event_type": "LOGIN_SUCCESS"}, "requires user_id"),
        ({"metadata": {"auth_method": "password", "unexpected": 1}}, "unexpected"),
        ({"metadata": {"card_number": "4111111111111111"}}, "forbidden"),
    ],
)
def test_malformed_events_are_rejected(overrides: dict[str, Any], match: str) -> None:
    with pytest.raises(EventContractError, match=match):
        parse_incoming(event(**overrides))


def test_rejections_never_echo_values() -> None:
    with pytest.raises(EventContractError) as exc:
        parse_incoming(event(metadata={"password": "hunter2secret"}))
    assert "hunter2secret" not in str(exc.value)


def test_non_object_is_rejected() -> None:
    with pytest.raises(EventContractError):
        parse_incoming(["not", "an", "object"])


def test_arrival_time_is_replay_only() -> None:
    data = event(arrival_time=(T + timedelta(hours=2)).isoformat())
    with pytest.raises(EventContractError, match="arrival_time"):
        parse_incoming(data)
    incoming = parse_incoming(data, allow_arrival_time=True)
    assert incoming.arrival_time == T + timedelta(hours=2)
    with pytest.raises(EventContractError, match="ISO-8601"):
        parse_incoming(event(arrival_time="yesterday"), allow_arrival_time=True)


def test_future_events_are_refused() -> None:
    incoming = parse_incoming(event())
    check_clock(incoming.event, T + timedelta(minutes=1))
    check_clock(incoming.event, T - timedelta(minutes=4))  # within the skew
    with pytest.raises(EventContractError, match="future"):
        check_clock(incoming.event, T - timedelta(hours=1))


# ------------------------------------------------------------------ model cache
def _record(name: str = "gradient-boosting", version: str = "1.0.0", sha: str = "a") -> Any:
    return SimpleNamespace(model_name=name, model_version=version, artifact_sha256=sha)


def test_cache_hits_and_keys() -> None:
    loads: list[str] = []

    def loader(record: Any) -> Any:
        loads.append(record.model_name)
        return object()

    cache = ModelCache(loader)
    cache.bind("deployment-1")
    first, cached = cache.get(_record())
    assert not cached
    again, cached = cache.get(_record())
    assert cached and again is first and loads == ["gradient-boosting"]
    other, _ = cache.get(_record(sha="b"))  # a new artefact digest is a different entry
    assert other is not first and len(loads) == 2
    assert cache.keys() == [
        ("gradient-boosting", "1.0.0", "a"),
        ("gradient-boosting", "1.0.0", "b"),
    ]
    assert cache.stats.to_dict() == {
        "hits": 1,
        "misses": 2,
        "loads": 2,
        "load_failures": 0,
        "invalidations": 0,
    }


def test_cache_invalidates_on_deployment_change() -> None:
    cache = ModelCache(lambda r: object())
    cache.bind("d1")
    cache.get(_record())
    cache.bind("d1")
    assert cache.keys()
    cache.bind("d2")
    assert cache.keys() == [] and cache.stats.invalidations == 1 and cache.generation == "d2"


def test_failed_loads_are_never_cached() -> None:
    calls = {"n": 0}

    def loader(record: Any) -> Any:
        calls["n"] += 1
        raise OSError("corrupt artefact")

    cache = ModelCache(loader)
    for _ in range(2):
        with pytest.raises(OSError):
            cache.get(_record())
    assert calls["n"] == 2 and cache.keys() == [] and cache.stats.load_failures == 2


def test_concurrent_requests_load_once() -> None:
    loads: list[int] = []
    barrier = threading.Barrier(8)

    def loader(record: Any) -> Any:
        time.sleep(0.05)
        loads.append(1)
        return object()

    cache = ModelCache(loader)
    results: list[Any] = []

    def worker() -> None:
        barrier.wait()
        results.append(cache.get(_record())[0])

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(loads) == 1 and len({id(r) for r in results}) == 1


# ------------------------------------------------------------------ logging + metrics
def test_decision_log_is_structured_and_filtered(caplog: pytest.LogCaptureFixture) -> None:
    raw_id = uuid.uuid4()
    with caplog.at_level(logging.INFO, logger="fraud_ai.realtime"):
        line = log_decision(
            event="realtime_decision",
            event_ref=event_ref(raw_id),
            decision="ALLOW",
            policy_version="risk-policy-1.0.0",
            latency_ms={"total": 1.5},
            ip="203.0.113.9",
            card_number="4111111111111111",
            event_id=str(raw_id),
        )
    record = json.loads(line)
    assert record["decision"] == "ALLOW" and record["event_ref"].startswith("rt-")
    assert "ip" not in record and "card_number" not in record and "event_id" not in record
    assert str(raw_id) not in caplog.text and "203.0.113.9" not in caplog.text
    assert event_ref(raw_id) == event_ref(str(raw_id)) != event_ref(uuid.uuid4())


def test_percentiles_and_metrics() -> None:
    assert percentiles([]) == {"p50": None, "p95": None, "p99": None, "count": 0}
    p = percentiles([float(i) for i in range(1, 101)])
    assert (
        p["p50"] == pytest.approx(50.5) and p["p99"] == pytest.approx(99.01) and p["count"] == 100
    )
    m = Metrics()
    m.record(status="decided", decision="ALLOW", failures=[], latency_ms={"total": 2.0})
    m.record(
        status="decided",
        decision="MANUAL_REVIEW",
        failures=["feature_extraction_failed"],
        latency_ms={"total": 4.0},
        shadow_comparisons=2,
        shadow_disagreements=1,
    )
    m.record(status="rejected", decision=None, failures=["event_rejected"], latency_ms={})
    snap = m.snapshot()
    assert snap["counters"]["events_processed"] == 3 and snap["counters"]["events_decided"] == 2
    assert snap["counters"]["events_with_failures"] == 2
    assert snap["decisions"] == {"ALLOW": 1, "MANUAL_REVIEW": 1}
    assert snap["fallbacks"] == {"feature_extraction_failed": 1, "event_rejected": 1}
    assert snap["shadow_disagreement_rate"] == 0.5
    assert snap["latency_ms"]["total"]["count"] == 2
    assert Metrics().snapshot()["shadow_disagreement_rate"] is None
