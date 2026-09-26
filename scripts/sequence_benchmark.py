#!/usr/bin/env python
"""Stage 6 benchmark: sequence models vs the tabular models on one synthetic world.

1. Seed a world (``--seed-users``; the database must be EMPTY) or use an existing one.
2. Sequence-length experiment: the GRU trained with windows of 16 / 32 / 64 events,
   selected on *validation* PR-AUC (nothing registered, test untouched).
3. Train on ONE dataset and ONE split: logistic regression, random forest, gradient
   boosting, the feed-forward network, GRU, causal Transformer and hybrid GRU.
4. Stage 4 per-model reports (confidence, calibration, scenarios, errors, costs,
   walk-forward, drift) for GB, NN and the three sequence models; the paired comparison;
   sequence-vs-GB complementarity; the stealthy-takeover report.
5. Latency: point-in-time sequence extraction (database) measured separately from
   model-only inference; artefact sizes and parameter counts.

    python scripts/sequence_benchmark.py --seed-users 1000 --output sequence-benchmark

All numbers describe SYNTHETIC data; CPU timings on this machine.
"""

from __future__ import annotations

import argparse
import json
import statistics
import tempfile
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import numpy as np
import torch
from sqlalchemy import select

from fraud_ai.data.seed import seed_synthetic_data
from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.migrations import upgrade
from fraud_ai.database.models import Transaction
from fraud_ai.evaluation import reports
from fraud_ai.evaluation.complementarity import complementarity
from fraud_ai.evaluation.context import build_context
from fraud_ai.evaluation.reports import EvaluationSettings
from fraud_ai.evaluation.stealth import stealth_report
from fraud_ai.evaluation.walk_forward import WalkForwardConfig
from fraud_ai.models.sequence_models import SequenceModel
from fraud_ai.models.training import TrainingConfig, prepare_data, run_training
from fraud_ai.security.hashing import Pseudonymiser
from fraud_ai.sequences.definition import SequenceDefinition
from fraud_ai.sequences.extraction import build_sequence

KINDS = [
    "logistic",
    "random-forest",
    "gradient-boosting",
    "neural-network",
    "gru",
    "transformer",
    "hybrid-gru",
]
NAMES = {"logistic": "logistic-regression"}


def _ms(values: list[float]) -> dict[str, float]:
    values = sorted(values)
    return {
        "p50_ms": 1000 * statistics.median(values),
        "p95_ms": 1000 * values[int(0.95 * (len(values) - 1))],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--seed-users", type=int, default=0)
    parser.add_argument("--days", type=int, default=180)
    parser.add_argument("--world-seed", type=int, default=2026)
    parser.add_argument("--maturity-days", type=int, default=14)
    parser.add_argument("--version", default="1.0.0")
    parser.add_argument("--bootstrap", type=int, default=1000)
    parser.add_argument("--lengths", default="16,32,64")
    parser.add_argument(
        "--tolerance",
        type=float,
        default=0.01,
        help="Validation PR-AUC within which the shortest window is preferred.",
    )
    parser.add_argument("--model-directory", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=Path("sequence-benchmark"))
    args = parser.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="fraud-ai-seq-bench-"))
    url = args.database_url or f"sqlite:///{tmp / 'bench.db'}"
    model_dir = args.model_directory or tmp / "models"
    engine = create_db_engine(url)
    factory = make_session_factory(engine)
    timings: dict[str, float] = {}
    out: dict[str, Any] = {
        "database": engine.dialect.name,
        "torch": torch.__version__,
        "cuda_available": torch.cuda.is_available(),
        "device": "cpu",
    }
    if args.seed_users:
        upgrade(url)
        started = time.perf_counter()
        with session_scope(factory) as s:
            seeded = seed_synthetic_data(
                s,
                Pseudonymiser(b"benchmark-key-" * 3),
                n_users=args.seed_users,
                seed=args.world_seed,
                reference_time=datetime(2026, 9, 1, tzinfo=UTC),
                activity_days=args.days,
            )
        timings["seed_seconds"] = time.perf_counter() - started
        out["world"] = {
            "users": seeded.users,
            "events": seeded.events,
            "fraud_labels": seeded.fraud_labels,
            "scenario_counts": seeded.scenario_counts,
        }
        print(f"seeded {seeded.users} users, {seeded.events} events", flush=True)

    base = TrainingConfig(maturity=timedelta(days=args.maturity_days), version=args.version)

    # ---- 2. sequence-length experiment (validation only)
    lengths = [int(x) for x in args.lengths.split(",") if x]
    experiment = []
    for n in lengths:
        definition = SequenceDefinition(max_events=n)
        with make_session_factory(engine)() as s:
            started = time.perf_counter()
            prepared = prepare_data(s, replace(base, sequence=definition))
            extraction = time.perf_counter() - started
        model = SequenceModel("gru", "experiment", seed=base.seed)
        started = time.perf_counter()
        model.train(*prepared.part("train"), validation=prepared.part("validation"))
        best_row = model.history[model.training_summary["best_epoch"] - 1]
        experiment.append(
            {
                "max_events": n,
                "validation_pr_auc": best_row["validation_pr_auc"],
                "best_epoch": model.training_summary["best_epoch"],
                "train_seconds": time.perf_counter() - started,
                "dataset_build_seconds": extraction,
            }
        )
        experiment[-1]["parameter_count"] = model.parameter_count
        started = time.perf_counter()
        model.predict_proba(prepared.part("test")[0])
        experiment[-1]["batch_inference_seconds_test_split"] = time.perf_counter() - started
        r = experiment[-1]
        print(
            f"length {n}: validation PR-AUC {r['validation_pr_auc']:.4f} dataset build "
            f"{r['dataset_build_seconds']:.0f}s train {r['train_seconds']:.0f}s "
            f"batch inference {r['batch_inference_seconds_test_split']:.2f}s",
            flush=True,
        )
    # Cost-aware choice: the SHORTEST window whose validation PR-AUC is within
    # `tolerance` of the best (differences below that are within seed-to-seed noise, and a
    # longer window costs more extraction, memory and inference time).
    best = max(r["validation_pr_auc"] or -1 for r in experiment)
    eligible = [r for r in experiment if (r["validation_pr_auc"] or -1) >= best - args.tolerance]
    chosen = min(eligible, key=lambda r: r["max_events"])
    out["length_experiment"] = {
        "results": experiment,
        "selected": chosen["max_events"],
        "selection": f"shortest window within {args.tolerance} validation PR-AUC of the best "
        "(the test split is not used)",
    }
    definition = SequenceDefinition(max_events=chosen["max_events"])

    # ---- 3. train every model on one dataset and split
    config = replace(base, sequence=definition, hyperparameters={"transformer": {"layers": 2}})
    with session_scope(factory) as s:
        started = time.perf_counter()
        run = run_training(s, KINDS, config, model_dir)
        timings["training_run_seconds"] = time.perf_counter() - started
        out["models"] = {}
        for r in run.results:
            directory = r.artifact_path
            size = sum(p.stat().st_size for p in directory.iterdir()) if directory else 0
            manifest = r.model.manifest()
            params = manifest.get("parameter_count")
            out["models"][r.model_id] = {
                "timings": r.timings,
                "warnings": r.warnings,
                "parameter_count": params,
                "parameter_bytes_float32": 4 * params if params else None,
                "artifact_bytes": size,
                "training": manifest.get("training"),
                "test": {
                    k: r.metrics["test"].get(k)
                    for k in ("pr_auc", "roc_auc", "precision", "recall", "fpr", "positives")
                },
            }
            print(f"trained {r.model_id} ({r.timings['train_seconds']:.0f}s)", flush=True)
        out["dataset"] = run.prepared.summary()

    # ---- 4. evaluation
    v = args.version
    refs = [f"{NAMES.get(k, k)}-{v}" for k in KINDS]
    settings = EvaluationSettings(
        iterations=args.bootstrap,
        walk_forward=WalkForwardConfig(bootstrap_iterations=min(args.bootstrap, 300)),
    )
    with session_scope(factory) as s:
        started = time.perf_counter()
        ctx = build_context(s, refs)
        timings["context_seconds"] = time.perf_counter() - started
        for ref in (
            f"gradient-boosting-{v}",
            f"neural-network-{v}",
            f"gru-{v}",
            f"transformer-{v}",
            f"hybrid-gru-{v}",
        ):
            started = time.perf_counter()
            reports.full_model_report(ctx, ctx.model(ref), settings, args.output / ref, s)
            timings[f"report_{ref}_seconds"] = time.perf_counter() - started
            print(
                f"wrote {args.output / ref} ({timings[f'report_{ref}_seconds']:.0f}s)", flush=True
            )
        reports.write_report(args.output / "comparisons", "compare", reports.compare(ctx, settings))
        gb = ctx.model(f"gradient-boosting-{v}")
        seq = {}
        for ref in (f"neural-network-{v}", f"gru-{v}", f"transformer-{v}", f"hybrid-gru-{v}"):
            seq[ref] = complementarity(ctx, gb, ctx.model(ref), iterations=args.bootstrap)
        y = ctx.labels("test")
        caught = [(m.scores["test"] >= m.threshold) & (y == 1) for m in ctx.models]
        reports.write_report(
            args.output / "comparisons",
            "sequence_compare",
            ctx.header(
                "sequence_compare",
                base=gb.model_id,
                comparisons=seq,
                missed_by_all_models=int(((y == 1) & ~np.logical_or.reduce(caught)).sum()),
            ),
        )
        reports.write_report(
            args.output / "comparisons",
            "stealth_report",
            ctx.header("stealth_report", **stealth_report(ctx)),
        )

        # ---- 5. extraction latency (database), separate from model inference
        events = list(
            s.scalars(
                select(Transaction.event_id).order_by(Transaction.occurred_at.desc()).limit(100)
            )
        )
        durations = []
        for event_id in events:
            started = time.perf_counter()
            build_sequence(s, event_id, definition)
            durations.append(time.perf_counter() - started)
        out["sequence_extraction_single_event"] = _ms(durations)
        s.rollback()
    out["sequence_definition"] = definition.to_dict()
    out["timings"] = timings
    out["note"] = "SYNTHETIC data; CPU timings on this machine; not production figures."
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "benchmark.json").write_text(
        json.dumps(out, indent=2, sort_keys=True, default=str) + "\n"
    )
    print(f"written {args.output}")
    engine.dispose()


if __name__ == "__main__":
    main()
