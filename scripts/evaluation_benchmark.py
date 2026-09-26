#!/usr/bin/env python
"""Stage 4 benchmark evaluation on a larger synthetic world (scripts only, not unit tests).

Seeds a fresh world (default 1,000 users over 180 days; --fraud-multiplier scales the
fraud scenarios), trains the three baselines on one dataset, then writes every Stage 4
report for each model plus the paired comparison:

    <output>/<model-id>/{summary,confidence,thresholds,calibration,scenarios,errors,costs,
                         walk_forward,drift_baseline}.json
    <output>/comparisons/<dataset>/compare.json
    <output>/benchmark.json              seed, sizes, univariate shortcut check, timings

    python scripts/evaluation_benchmark.py --users 1000 --output evaluation-benchmark
    python scripts/evaluation_benchmark.py --users 1500 --fraud-multiplier 0.5 ...
    python scripts/evaluation_benchmark.py --database-url postgresql+psycopg://... (EMPTY db)

All numbers describe SYNTHETIC data produced by the bundled generator. They are evidence
about the evaluation machinery and the generator, not about real-world fraud performance.
"""

from __future__ import annotations

import argparse
import json
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fraud_ai.data.seed import seed_synthetic_data
from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.migrations import upgrade
from fraud_ai.evaluation import reports
from fraud_ai.evaluation.context import build_context
from fraud_ai.evaluation.reports import EvaluationSettings
from fraud_ai.evaluation.shortcuts import univariate_separability
from fraud_ai.evaluation.walk_forward import WalkForwardConfig
from fraud_ai.models.training import TrainingConfig, run_training
from fraud_ai.security.hashing import Pseudonymiser

KINDS = ["logistic", "random-forest", "gradient-boosting"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--users", type=int, default=1000)
    parser.add_argument("--days", type=int, default=180)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--fraud-multiplier", type=float, default=1.0)
    parser.add_argument("--maturity-days", type=int, default=14)
    parser.add_argument("--bootstrap", type=int, default=1000)
    parser.add_argument("--database-url", default=None, help="Must point at an EMPTY database.")
    parser.add_argument("--output", type=Path, default=Path("evaluation-benchmark"))
    args = parser.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="fraud-ai-eval-bench-"))
    url = args.database_url or f"sqlite:///{tmp / 'bench.db'}"
    upgrade(url)
    engine = create_db_engine(url)
    factory = make_session_factory(engine)
    timings: dict[str, float] = {}

    started = time.perf_counter()
    with session_scope(factory) as s:
        seeded = seed_synthetic_data(
            s,
            Pseudonymiser(b"benchmark-key-" * 3),
            n_users=args.users,
            seed=args.seed,
            reference_time=datetime(2026, 9, 1, tzinfo=UTC),
            activity_days=args.days,
            fraud_multiplier=args.fraud_multiplier,
        )
    timings["seed_seconds"] = time.perf_counter() - started
    print(
        f"seeded {seeded.users} users, {seeded.events} events, {seeded.fraud_labels} fraud "
        f"labels in {timings['seed_seconds']:.0f}s ({engine.dialect.name})"
    )

    started = time.perf_counter()
    config = TrainingConfig(maturity=timedelta(days=args.maturity_days))
    with session_scope(factory) as s:
        run = run_training(s, KINDS, config, tmp / "models")
        refs = [r.model_id for r in run.results]
    timings["train_seconds"] = time.perf_counter() - started

    settings = EvaluationSettings(
        iterations=args.bootstrap,
        walk_forward=WalkForwardConfig(bootstrap_iterations=min(args.bootstrap, 300)),
    )
    out: dict[str, Any] = {
        "users": args.users,
        "days": args.days,
        "seed": args.seed,
        "fraud_multiplier": args.fraud_multiplier,
        "backend": engine.dialect.name,
        "scenario_counts": seeded.scenario_counts,
        "settings": settings.to_dict(),
    }
    with session_scope(factory) as s:
        started = time.perf_counter()
        ctx = build_context(s, refs)
        timings["context_seconds"] = time.perf_counter() - started
        out["dataset_fingerprint"] = ctx.fingerprint
        out["splits"] = {
            split: {"rows": len(ctx.labels(split)), "fraud": int(ctx.labels(split).sum())}
            for split in ("train", "validation", "test")
        }
        matrix, y = ctx.prepared.part("train")
        out["univariate_top5"] = univariate_separability(matrix, y)[:5]
        print(f"dataset {ctx.fingerprint}: {out['splits']}")
        print(f"strongest single feature (train): {out['univariate_top5'][0]}")
        for model in ctx.models:
            started = time.perf_counter()
            reports.full_model_report(ctx, model, settings, args.output / model.model_id, s)
            timings[f"report_{model.model_id}_seconds"] = time.perf_counter() - started
            print(
                f"  wrote {args.output / model.model_id} "
                f"({timings[f'report_{model.model_id}_seconds']:.0f}s)"
            )
        started = time.perf_counter()
        compared = reports.compare(ctx, settings)
        reports.write_report(
            args.output / "comparisons" / ctx.fingerprint[:16], "compare", compared
        )
        timings["compare_seconds"] = time.perf_counter() - started
    out["timings"] = timings
    out["note"] = (
        "SYNTHETIC data: evidence about the evaluation machinery and generator only; "
        "no real-world detection rate, loss or saving is implied."
    )
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "benchmark.json").write_text(
        json.dumps(out, indent=2, sort_keys=True, default=str) + "\n"
    )
    print(f"written {args.output}")
    engine.dispose()


if __name__ == "__main__":
    main()
