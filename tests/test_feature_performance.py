"""No N+1: the number of queries per vector is constant, independent of history size."""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from sqlalchemy import Engine, event
from sqlalchemy.orm import Session

from fraud_ai.features.batch import iter_vectors
from fraud_ai.features.extractor import extract_features
from fraud_ai.ingestion.processor import EventProcessor
from tests.feature_helpers import Scenario

T = datetime(2026, 7, 1, tzinfo=UTC)


@contextmanager
def count_queries(engine: Engine) -> Iterator[list[int]]:
    counter = [0]

    def _count(*_: object) -> None:
        counter[0] += 1

    event.listen(engine, "before_cursor_execute", _count)
    try:
        yield counter
    finally:
        event.remove(engine, "before_cursor_execute", _count)


def _account_with_history(sc: Scenario, n: int, device: str) -> object:
    uid = sc.user(T - timedelta(days=400), device=device)
    addr = sc.address(uid, T - timedelta(days=400))
    pm = sc.payment_method(uid, T - timedelta(days=400))
    for i in range(n):
        at = T - timedelta(hours=6 * (n - i))
        sc.login(uid, at, device=device)
        sc.purchase(uid, at + timedelta(minutes=1), "10.00", pm=pm, address=addr, device=device)
    event_, _ = sc.purchase(uid, T, "25.00", pm=pm, address=addr, device=device)
    sc.session.flush()
    return event_


def test_query_count_independent_of_history(
    session: Session, processor: EventProcessor, engine: Engine
) -> None:
    sc = Scenario(session, processor)
    small = _account_with_history(sc, 3, "d-small")
    large = _account_with_history(sc, 150, "d-large")
    counts = []
    for ev in (small, large):
        session.expire_all()
        with count_queries(engine) as n:
            extract_features(session, ev.event_id)  # type: ignore[attr-defined]
        counts.append(n[0])
    assert counts[0] == counts[1]
    assert counts[0] <= 30  # ~27 for a transaction with address + payment method


def test_batch_context_loading_is_bulk(
    session: Session, processor: EventProcessor, engine: Engine
) -> None:
    sc = Scenario(session, processor)
    uid = sc.user(T - timedelta(days=10))
    events = [sc.login(uid, T - timedelta(minutes=m)).event_id for m in range(40, 0, -1)]
    session.flush()
    with count_queries(engine) as n:
        vectors = list(iter_vectors(session, events))
    per_event = n[0] / len(events)
    assert len(vectors) == 40 and per_event < 20  # context loading is amortised


def test_extraction_throughput_smoke(session: Session, processor: EventProcessor) -> None:
    sc = Scenario(session, processor)
    ev = _account_with_history(sc, 60, "d-perf")
    started = time.perf_counter()
    for _ in range(20):
        extract_features(session, ev.event_id)  # type: ignore[attr-defined]
    per_vector = (time.perf_counter() - started) / 20
    assert per_vector < 0.25  # generous bound; real numbers are in scripts/benchmark_features.py
