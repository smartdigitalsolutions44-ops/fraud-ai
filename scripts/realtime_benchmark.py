#!/usr/bin/env python
"""Stage 8 benchmark: the full real-time scoring path on one synthetic world.

1. Seed synthetic history plus a held-out live stream (``--users``, ``--live-days``).
2. Train gradient boosting (primary), the feed-forward network (secondary), the GRU
   (sequence) and logistic regression (shadow) on the history.
3. Propose two experimental policies from Stage 4 cost analysis (validation split), then
   simulate and compare them on the test split.
4. Activate policy A with LR as a shadow model and policy B as a shadow policy.
5. Replay the live stream through ``FraudScoringService`` in arrival order, reporting
   per-stage p50/p95/p99, the decision distribution, shadow agreement, cache behaviour and
   a concurrent re-delivery run.

    python scripts/realtime_benchmark.py --users 300 --output realtime-benchmark

All numbers are SYNTHETIC, on this machine's CPU and SQLite (unless --database-url points
elsewhere). This is not a production SLA.
"""

from __future__ import annotations

import argparse
import json
import tempfile
import threading
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fraud_ai.data.seed import seed_with_live_holdout
from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.migrations import upgrade
from fraud_ai.models.training import TrainingConfig, run_training
from fraud_ai.realtime import monitoring
from fraud_ai.realtime.service import FraudScoringService
from fraud_ai.realtime.telemetry import percentiles
from fraud_ai.risk.offline import compare_policies, propose_policy, simulate
from fraud_ai.risk.registry import activate, create_policy
from fraud_ai.security.hashing import Pseudonymiser

GB, NN, GRU, LR = (
    "gradient-boosting-1.0.0",
    "neural-network-1.0.0",
    "gru-1.0.0",
    "logistic-regression-1.0.0",
)
STAGES = (
    "validation",
    "ingestion",
    "policy_load",
    "cutoff_check",
    "features",
    "sequence",
    "model_resolution",
    "model_loading",
    "inference_primary",
    "inference_secondary",
    "inference_sequence",
    "calibration",
    "rules",
    "policy",
    "shadow",
    "prediction_persistence",
    "persistence",
    "commit",
    "total",
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--users", type=int, default=300)
    parser.add_argument("--days", type=int, default=180)
    parser.add_argument("--live-days", type=int, default=7)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--fraud-multiplier", type=float, default=2.0)
    parser.add_argument("--reference-time", default="2026-07-01")
    parser.add_argument("--database-url", default=None, help="Default: a new SQLite file")
    parser.add_argument("--output", type=Path, default=Path("realtime-benchmark"))
    parser.add_argument("--threads", type=int, default=4)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix="fraud-ai-realtime-"))
    url = args.database_url or f"sqlite:///{workdir / 'realtime.db'}"
    upgrade(url)
    engine = create_db_engine(url)
    factory = make_session_factory(engine)
    pseudo = Pseudonymiser(b"realtime-benchmark-key-not-a-secret-0123456789")
    report: dict[str, Any] = {
        "data_note": "SYNTHETIC world; CPU timings on this machine; not a production SLA",
        "config": {k: str(v) for k, v in vars(args).items()},
    }
    t = time.perf_counter()
    with session_scope(factory) as s:
        holdout = seed_with_live_holdout(
            s,
            pseudo,
            n_users=args.users,
            seed=args.seed,
            reference_time=datetime.fromisoformat(args.reference_time).replace(tzinfo=UTC),
            activity_days=args.days,
            live_days=args.live_days,
            fraud_multiplier=args.fraud_multiplier,
            late_fraction=0.03,
        )
    report["world"] = {
        "users": args.users,
        "history_events": holdout.history.events,
        "live_events": len(holdout.events),
        "late_live_events": holdout.late_events,
        "cutoff": holdout.cutoff.isoformat(),
        "seconds": round(time.perf_counter() - t, 1),
    }
    print("world", report["world"], flush=True)
    t = time.perf_counter()
    with session_scope(factory) as s:
        run_training(
            s,
            ["gradient-boosting", "neural-network", "gru", "logistic"],
            TrainingConfig(),
            workdir / "models",
        )
    report["training_seconds"] = round(time.perf_counter() - t, 1)
    print("trained", report["training_seconds"], flush=True)
    with session_scope(factory) as s:
        a = propose_policy(s, "risk-policy-1.0.0", primary=GB, secondary=NN, sequence=GRU)
        create_policy(s, a.definition, derivation=a.derivation)
        b = propose_policy(
            s, "risk-policy-1.1.0", primary=GB, monitor_recall=0.8, block_precision=0.9
        )
        create_policy(s, b.definition, derivation=b.derivation)
        report["policies"] = {
            p.definition.policy_version: {
                "bands": [
                    [band.lower, band.risk_level, band.decision.value]
                    for band in p.definition.bands
                ],
                "thresholds": p.derivation["thresholds"],
                "validation_bands": p.derivation["validation_bands"],
            }
            for p in (a, b)
        }
        report["simulation"] = {
            p.definition.policy_version: simulate(s, p.definition) for p in (a, b)
        }
        report["comparison"] = compare_policies(s, a.definition, b.definition, iterations=500)
        activate(
            s,
            a.definition.policy_version,
            shadow_models=[LR],
            shadow_policies=[b.definition.policy_version],
        )
    print("policies", report["policies"], flush=True)

    service = FraudScoringService(factory, pseudo, replay=True)
    outcomes = []
    t = time.perf_counter()
    for event in holdout.events:
        outcomes.append(service.score_event(event))
    wall = time.perf_counter() - t
    decided = [o for o in outcomes if o.status == "decided"]
    report["replay"] = {
        "events": len(outcomes),
        "wall_seconds": round(wall, 2),
        "events_per_second": round(len(outcomes) / wall, 1),
        "statuses": dict(Counter(o.status for o in outcomes)),
        "decisions": dict(Counter(o.decision.value for o in decided if o.decision)),
        "failures": dict(Counter(f["category"] for o in outcomes for f in o.failures)),
        "late_decisions": sum(1 for o in decided if "LATE_EVENT" in o.reason_codes),
        "cache": service.cache.stats.to_dict(),
        "decision_latency_ms": {
            stage: percentiles([o.latency_ms[stage] for o in decided if stage in o.latency_ms])
            for stage in STAGES
        },
        "non_decision_latency_ms": percentiles(
            [o.latency_ms["total"] for o in outcomes if o.status == "ingested"]
        ),
    }
    # Concurrent re-delivery: every decided event again, from several threads.
    threads_out: list[Any] = []
    lock = threading.Lock()
    chunks = [holdout.events[i :: args.threads] for i in range(args.threads)]

    def worker(chunk: list[dict[str, Any]]) -> None:
        for event in chunk:
            outcome = service.score_event(event)
            with lock:
                threads_out.append(outcome)

    workers = [threading.Thread(target=worker, args=(c,)) for c in chunks]
    t = time.perf_counter()
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    report["concurrent_redelivery"] = {
        "threads": args.threads,
        "events": len(threads_out),
        "statuses": dict(Counter(o.status for o in threads_out)),
        "wall_seconds": round(time.perf_counter() - t, 2),
        "latency_ms": percentiles([o.latency_ms["total"] for o in threads_out]),
    }
    with session_scope(factory) as s:
        summary = monitoring.summary(s)
        report["monitoring"] = {k: v for k, v in summary.items() if k != "latency_ms"}
        report["drift"] = monitoring.drift(s)
        report["shadow"] = monitoring.shadow_report(s)
    path = args.output / "realtime_benchmark.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str))
    print(json.dumps(report["replay"], indent=2))
    print("written", path)
    engine.dispose()


if __name__ == "__main__":
    main()
