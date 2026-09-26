#!/usr/bin/env python
"""Stage 5 benchmark: neural network vs the baselines on one synthetic world (scripts only).

Steps (all on one dataset and one time-ordered split):

1. seed a world (``--seed-users``; the database must be EMPTY) or use an existing one;
2. train the three baselines if they are not registered yet;
3. run the neural hyperparameter grid (selected on validation PR-AUC; test untouched);
4. train ``neural-network-<version>`` with the selected hyperparameters, and the
   experimental ``autoencoder-<version>``;
5. write the Stage 4 per-model reports for all four fraud models, the paired comparison,
   the gradient-boosting vs neural complementarity (with the anomaly score) and the anomaly
   evaluation, plus ``benchmark.json`` (sizes, selection, timings, device).

    python scripts/neural_benchmark.py --seed-users 1000 --output neural-benchmark
    python scripts/neural_benchmark.py --database-url sqlite:///bench.db --output out

All numbers describe SYNTHETIC data. Timings are CPU-only unless CUDA is present.
"""

from __future__ import annotations

import argparse
import json
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import torch

from fraud_ai.data.seed import seed_synthetic_data
from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.migrations import upgrade
from fraud_ai.evaluation import reports
from fraud_ai.evaluation.anomaly_report import anomaly_evaluation
from fraud_ai.evaluation.complementarity import complementarity
from fraud_ai.evaluation.context import EvaluationContext, build_context
from fraud_ai.evaluation.reports import EvaluationSettings
from fraud_ai.evaluation.walk_forward import WalkForwardConfig
from fraud_ai.models.experiments import ExperimentGrid, run_experiments
from fraud_ai.models.registry import get_model_version
from fraud_ai.models.training import TrainingConfig, prepare_data, run_training
from fraud_ai.security.hashing import Pseudonymiser

BASELINES = {
    "logistic": "logistic-regression",
    "random-forest": "random-forest",
    "gradient-boosting": "gradient-boosting",
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--seed-users", type=int, default=0)
    parser.add_argument("--days", type=int, default=180)
    parser.add_argument("--world-seed", type=int, default=2026)
    parser.add_argument("--fraud-multiplier", type=float, default=1.0)
    parser.add_argument("--maturity-days", type=int, default=14)
    parser.add_argument("--version", default="1.0.0")
    parser.add_argument("--bootstrap", type=int, default=1000)
    parser.add_argument("--no-experiments", action="store_true")
    parser.add_argument("--model-directory", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=Path("neural-benchmark"))
    args = parser.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="fraud-ai-neural-bench-"))
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
                fraud_multiplier=args.fraud_multiplier,
            )
        timings["seed_seconds"] = time.perf_counter() - started
        out["world"] = {
            "users": seeded.users,
            "events": seeded.events,
            "scenario_counts": seeded.scenario_counts,
        }
    config = TrainingConfig(maturity=timedelta(days=args.maturity_days), version=args.version)

    with session_scope(factory) as s:
        missing = [
            k for k, name in BASELINES.items() if get_model_version(s, name, args.version) is None
        ]
        if missing:
            started = time.perf_counter()
            run_training(s, missing, config, model_dir)
            timings["baseline_training_seconds"] = time.perf_counter() - started

    selected: dict[str, Any] = {}
    if not args.no_experiments:
        with make_session_factory(engine)() as s:
            prepared = prepare_data(s, config)
            started = time.perf_counter()

            def progress(i: int, n: int, r: dict[str, Any]) -> None:
                print(
                    f"  [{i:>2}/{n}] {r['hyperparameters']['hidden_sizes']} "
                    f"d={r['hyperparameters']['dropout']} "
                    f"lr={r['hyperparameters']['learning_rate']} "
                    f"wd={r['hyperparameters']['weight_decay']} val PR-AUC "
                    f"{r['validation_pr_auc']:.4f} epoch {r['best_epoch']} "
                    f"{r['train_seconds']:.0f}s",
                    flush=True,
                )

            experiments = run_experiments(
                prepared, ExperimentGrid(), seed=config.seed, progress=progress
            )
            timings["experiments_seconds"] = time.perf_counter() - started
        reports.write_report(args.output / "neural_experiments", "experiments", experiments)
        selected = {
            k: v for k, v in experiments["selected"]["hyperparameters"].items() if k != "optimizer"
        }
        out["experiments"] = {
            "selected": experiments["selected"],
            "loss_experiment": {
                k: experiments["loss_experiment"][k]["validation_pr_auc"]
                for k in ("weighted_bce", "focal")
            },
            "configurations": len(experiments["results"]),
        }

    with session_scope(factory) as s:
        started = time.perf_counter()
        nn_config = TrainingConfig(
            maturity=config.maturity,
            version=args.version,
            hyperparameters={"neural-network": selected},
        )
        nn_run = run_training(s, ["neural-network"], nn_config, model_dir)
        timings["neural_training_seconds"] = time.perf_counter() - started
        started = time.perf_counter()
        ae_config = TrainingConfig(maturity=config.maturity, version=args.version, threshold=0.95)
        run_training(s, ["autoencoder"], ae_config, model_dir)
        timings["autoencoder_training_seconds"] = time.perf_counter() - started
        nn_result = nn_run.results[0]
        out["neural"] = {
            "timings": nn_result.timings,
            "warnings": nn_result.warnings,
            "training": nn_result.model.manifest()["training"],
            "parameter_count": nn_result.model.manifest()["parameter_count"],
            "architecture": nn_result.model.manifest()["architecture"],
            "hyperparameters": nn_result.model.hyperparameters,
        }

    v = args.version
    fraud_refs = [f"{name}-{v}" for name in BASELINES.values()] + [f"neural-network-{v}"]
    settings = EvaluationSettings(
        iterations=args.bootstrap,
        walk_forward=WalkForwardConfig(bootstrap_iterations=min(args.bootstrap, 300)),
    )
    with session_scope(factory) as s:
        started = time.perf_counter()
        ctx = build_context(s, [*fraud_refs, f"autoencoder-{v}"], allow_anomaly=True)
        timings["context_seconds"] = time.perf_counter() - started
        out["dataset_fingerprint"] = ctx.fingerprint
        out["splits"] = {
            p: {"rows": len(ctx.labels(p)), "fraud": int(ctx.labels(p).sum())}
            for p in ("train", "validation", "test")
        }
        fraud_ctx = EvaluationContext(
            ctx.prepared, [ctx.model(r) for r in fraud_refs], ctx.scenarios, ctx.fraud_types
        )
        for ref in fraud_refs:
            started = time.perf_counter()
            reports.full_model_report(
                fraud_ctx, fraud_ctx.model(ref), settings, args.output / ref, s
            )
            timings[f"report_{ref}_seconds"] = time.perf_counter() - started
            print(f"wrote {args.output / ref}", flush=True)
        reports.write_report(
            args.output / "comparisons", "compare", reports.compare(fraud_ctx, settings)
        )
        gb, nn, ae = (
            ctx.model(f"gradient-boosting-{v}"),
            ctx.model(f"neural-network-{v}"),
            ctx.model(f"autoencoder-{v}"),
        )
        reports.write_report(
            args.output / "comparisons",
            "complementarity_gb_vs_nn",
            ctx.header(
                "complementarity",
                **complementarity(ctx, gb, nn, anomaly=ae, iterations=args.bootstrap),
            ),
        )
        reports.write_report(
            args.output / f"autoencoder-{v}",
            "anomaly",
            ctx.header(
                "anomaly",
                **anomaly_evaluation(ctx, ae, iterations=args.bootstrap),
                versus_fraud_model=complementarity(ctx, gb, ae, iterations=args.bootstrap),
            ),
        )
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
