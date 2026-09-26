#!/usr/bin/env python
"""Benchmark point-in-time feature extraction on synthetic data.

Seeds a fresh database (SQLite in a temporary directory unless --database-url is given),
extracts vectors for every scorable event and reports throughput and queries per vector.

    python scripts/benchmark_features.py --users 100
    python scripts/benchmark_features.py --database-url postgresql+psycopg://... --users 100
"""

from __future__ import annotations

import argparse
import statistics
import tempfile
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import event, select, text

from fraud_ai.data.seed import seed_synthetic_data
from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.migrations import upgrade
from fraud_ai.database.models import EventRecord
from fraud_ai.features.batch import BATCH_SIZE, iter_vectors
from fraud_ai.features.context import SCORABLE_EVENT_TYPES
from fraud_ai.security.hashing import Pseudonymiser


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--users", type=int, default=100)
    parser.add_argument("--days", type=int, default=90)
    parser.add_argument("--database-url", default=None, help="Must point at an EMPTY database.")
    args = parser.parse_args()

    tmp = tempfile.mkdtemp(prefix="fraud-ai-bench-")
    url = args.database_url or f"sqlite:///{Path(tmp) / 'bench.db'}"
    upgrade(url)
    engine = create_db_engine(url)
    started = time.perf_counter()
    with session_scope(make_session_factory(engine)) as s:
        summary = seed_synthetic_data(
            s,
            Pseudonymiser(b"benchmark-key-" * 3),
            n_users=args.users,
            seed=1,
            reference_time=datetime(2026, 9, 1, tzinfo=UTC),
            activity_days=args.days,
        )
    print(
        f"backend={engine.dialect.name} users={summary.users} events={summary.events} "
        f"seed={time.perf_counter() - started:.1f}s"
    )
    if engine.dialect.name == "postgresql":
        with engine.begin() as conn:
            conn.execute(text("ANALYZE"))

    queries = [0]
    event.listen(engine, "before_cursor_execute", lambda *_: queries.__setitem__(0, queries[0] + 1))
    with make_session_factory(engine)() as s:
        ids = list(
            s.scalars(
                select(EventRecord.event_id)
                .where(EventRecord.event_type.in_(SCORABLE_EVENT_TYPES))
                .order_by(EventRecord.occurred_at, EventRecord.event_id)
            )
        )
        queries[0] = 0
        timings: list[float] = []
        kinds: Counter[str] = Counter()
        t0 = time.perf_counter()
        last = t0
        for vector in iter_vectors(s, ids):
            now = time.perf_counter()
            timings.append(now - last)
            last = now
            kinds[vector.event_kind.value] += 1
        total = time.perf_counter() - t0
    timings.sort()
    print(
        f"vectors={len(ids)} ({dict(kinds)}) total={total:.1f}s throughput={len(ids) / total:.0f}/s"
    )
    p50, p99 = timings[len(timings) // 2], timings[int(len(timings) * 0.99)]
    print(
        f"per-vector ms: mean={1000 * statistics.mean(timings):.2f} "
        f"p50={1000 * p50:.2f} p99={1000 * p99:.2f}"
    )
    print(f"queries/vector={queries[0] / len(ids):.1f} (context loaded in chunks of {BATCH_SIZE})")
    engine.dispose()


if __name__ == "__main__":
    main()
