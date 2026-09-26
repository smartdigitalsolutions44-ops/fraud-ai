#!/usr/bin/env python
"""Benchmark the baseline models, keeping model inference separate from database latency.

Reports, per model: training time, model-only single-event latency (preprocessing +
estimator on an in-memory vector), model-only batch throughput. Separately reports the
database-bound parts of scoring - point-in-time feature extraction and the full
``score_event`` path (snapshot + model + prediction row) - on the given database.

    python scripts/benchmark_models.py --database-url sqlite:///data/fraud_ai.db
    python scripts/benchmark_models.py --database-url postgresql+psycopg://... --seed-users 150

With --seed-users the database must be EMPTY; it is migrated and seeded first.
"""

from __future__ import annotations

import argparse
import statistics
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select

from fraud_ai.data.seed import seed_synthetic_data
from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.migrations import upgrade
from fraud_ai.database.models import Transaction
from fraud_ai.features.extractor import extract_features
from fraud_ai.models.registry import resolve_model
from fraud_ai.models.report import comparison_table
from fraud_ai.models.scoring import load_registered_model, score_event
from fraud_ai.models.training import TrainingConfig, run_training
from fraud_ai.security.hashing import Pseudonymiser


def _ms(values: list[float]) -> str:
    values = sorted(values)
    return (
        f"p50={1000 * statistics.median(values):.2f}ms "
        f"p95={1000 * values[int(0.95 * (len(values) - 1))]:.2f}ms"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--seed-users", type=int, default=0)
    parser.add_argument("--days", type=int, default=180)
    parser.add_argument("--events", type=int, default=50, help="Events for DB-bound timing.")
    args = parser.parse_args()

    engine = create_db_engine(args.database_url)
    factory = make_session_factory(engine)
    if args.seed_users:
        upgrade(args.database_url)
        started = time.perf_counter()
        with session_scope(factory) as s:
            seed_synthetic_data(
                s,
                Pseudonymiser(b"benchmark-key-" * 3),
                n_users=args.seed_users,
                seed=7,
                reference_time=datetime(2026, 9, 1, tzinfo=UTC),
                activity_days=args.days,
            )
        print(f"seeded {args.seed_users} users in {time.perf_counter() - started:.1f}s")

    model_dir = Path(tempfile.mkdtemp(prefix="fraud-ai-bench-models-"))
    version = f"0.0.0-bench{int(time.time())}"  # never collides with a real model version
    config = TrainingConfig(version=version)
    with session_scope(factory) as s:
        started = time.perf_counter()
        run = run_training(s, ["logistic", "random-forest", "gradient-boosting"], config, model_dir)
        total = time.perf_counter() - started
        summary = run.prepared.summary()
        print(
            f"backend={engine.dialect.name} examples={summary['examples']} "
            f"fraud={summary['positives']} ({100 * summary['prevalence']:.2f}%) "
            f"pipeline={total:.1f}s (dataset build + 3 models + evaluation)"
        )
        for r in run.results:
            t = r.timings
            print(
                f"  {r.model_id:<34} train={t['train_seconds']:.2f}s  model-only single "
                f"p50={t['single_event_p50_ms']:.2f}ms p95={t['single_event_p95_ms']:.2f}ms  "
                f"batch={t['batch_rows_per_second']:.0f} rows/s"
            )
        print()
        print(comparison_table([r.registered for r in run.results if r.registered]))

    with make_session_factory(engine)() as s:
        events = list(
            s.scalars(
                select(Transaction.event_id)
                .order_by(Transaction.occurred_at.desc())
                .limit(args.events)
            )
        )
        extraction = []
        for event_id in events:
            started = time.perf_counter()
            extract_features(s, event_id)
            extraction.append(time.perf_counter() - started)
        model = resolve_model(s, f"gradient-boosting-{version}")
        loaded = load_registered_model(model)
        scoring = []
        for event_id in events:
            started = time.perf_counter()
            score_event(s, event_id, model, loaded=loaded)
            scoring.append(time.perf_counter() - started)
        s.rollback()
    print(f"\n[{engine.dialect.name}] point-in-time feature extraction: {_ms(extraction)}")
    print(
        f"[{engine.dialect.name}] score_event end-to-end (snapshot + model + prediction row): "
        f"{_ms(scoring)}"
    )
    print("Timings are from synthetic data on this machine; they are not production figures.")
    engine.dispose()


if __name__ == "__main__":
    main()
