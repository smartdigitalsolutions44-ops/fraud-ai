#!/usr/bin/env python
"""Stage 10 PostgreSQL load benchmark: the real service (``fraud-ai service run`` with N
uvicorn worker processes) on PostgreSQL + Redis, driven over loopback HTTP.

Each run gets a fresh clone of the synthetic world (``scripts/pg_world.py``) and replays the
live stream with N concurrent clients (workers take whole users, so per-user order holds).

Reported per run:

* requests/sec, latency p50/p95/p99 (all requests and decision points), error rate;
* **database-bound time**: the Stage 8 per-stage timings of the stored assessments
  (ingestion + features + persistence + commit), p50/p95;
* **connections**: peak PostgreSQL backends for the run's database (sampled from
  ``pg_stat_activity``) against the pool ceiling ``workers x (pool_size + max_overflow)``
  (= pool saturation), plus peak connections waiting on a lock;
* **resources**: RSS and CPU seconds per worker, Redis clients;
* **startup**: time until ``/v1/ready`` (each worker loads and verifies its models).

    python scripts/pg_load_benchmark.py --admin-url postgresql+psycopg://u:p@localhost/postgres \
        --root /tmp/world --redis-url redis://127.0.0.1:6379/0 --output pg-benchmark

SYNTHETIC data, this machine, loopback network. Not an SLA; see HARDENING.md.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select, text

from fraud_ai.database.engine import (
    create_db_engine,
    make_session_factory,
    session_scope,
)
from fraud_ai.database.models import RiskAssessment
from fraud_ai.service.keys import create_key
from scripts.pg_world import clone, drop
from tests.conftest import TEST_KEY
from tests.service_process import running_service

DB_STAGES = ("ingestion", "features", "persistence", "commit")


def pct(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"p50": None, "p95": None, "p99": None}
    p50, p95, p99 = np.percentile(np.asarray(values), [50, 95, 99])
    return {"p50": round(float(p50), 2), "p95": round(float(p95), 2), "p99": round(float(p99), 2)}


def partitions(events: list[dict[str, Any]], n: int) -> list[list[dict[str, Any]]]:
    users = sorted({str(e.get("user_id")) for e in events})
    slot = {u: i % n for i, u in enumerate(users)}
    return [[e for e in events if slot[str(e.get("user_id"))] == i] for i in range(n)]


def proc_stats(pid: int) -> dict[str, float]:
    status = Path(f"/proc/{pid}/status").read_text()
    rss_kb = next(int(line.split()[1]) for line in status.splitlines() if line.startswith("VmRSS"))
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    ticks = 100.0
    cpu = (int(fields[11]) + int(fields[12])) / ticks
    return {"rss_mb": rss_kb / 1024, "cpu_s": cpu}


class Sampler(threading.Thread):
    def __init__(self, admin_url: str, db: str) -> None:
        super().__init__(daemon=True)
        self.engine = create_db_engine(admin_url)
        self.db = db
        self.stop = threading.Event()
        self.peak_conns = 0
        self.peak_lock_waits = 0
        self.samples = 0

    def run(self) -> None:
        q = text(
            "SELECT count(*), count(*) FILTER (WHERE wait_event_type = 'Lock') "
            "FROM pg_stat_activity WHERE datname = :db"
        )
        with self.engine.connect() as conn:
            while not self.stop.is_set():
                total, locks = conn.execute(q, {"db": self.db}).one()
                self.peak_conns = max(self.peak_conns, int(total))
                self.peak_lock_waits = max(self.peak_lock_waits, int(locks))
                self.samples += 1
                time.sleep(0.05)
        self.engine.dispose()


def run_once(
    args: argparse.Namespace,
    events: list[dict[str, Any]],
    *,
    workers: int,
    clients: int,
    pool_size: int,
    max_overflow: int,
    pool_timeout: float,
    label: str,
) -> dict[str, Any]:
    name = f"fraud_ai_bench_{label}"
    url = clone(args.admin_url, args.template, name)
    engine = create_db_engine(url)
    with session_scope(make_session_factory(engine)) as s:
        credential = create_key(
            s, "bench", ["score:write", "score:replay", "signals:trusted", "metrics:read"]
        ).credential
    import redis

    rclient = redis.Redis.from_url(args.redis_url)
    rclient.flushdb()
    env = {
        "ENVIRONMENT": "test",
        "DATABASE_URL": url,
        "PSEUDONYMISATION_KEY": TEST_KEY,
        "MODEL_DIRECTORY": str(args.root / "models"),
        "STATE_BACKEND": "redis",
        "REDIS_URL": args.redis_url,
        "RATE_LIMIT": "1000000/minute",
        "RATE_LIMIT_BURST": "10000",
        "SERVICE_REQUEST_TIMEOUT": "30",
        "DB_POOL_SIZE": str(pool_size),
        "DB_MAX_OVERFLOW": str(max_overflow),
        "DB_POOL_TIMEOUT": str(pool_timeout),
        "LOG_LEVEL": "WARNING",
        **dict(kv.split("=", 1) for kv in args.env),
    }
    started = time.perf_counter()
    result: dict[str, Any] = {
        "label": label,
        "server_workers": workers,
        "clients": clients,
        "pool_size": pool_size,
        "max_overflow": max_overflow,
        "pool_timeout": pool_timeout,
        "pool_ceiling": workers * (pool_size + max_overflow),
    }
    with running_service(env, workers=workers, log_dir=args.output, timeout=600) as svc:
        result["startup_seconds"] = round(time.perf_counter() - started, 2)
        # Warm every worker (each has its own model cache) before measuring.
        for _ in range(workers * 4):
            httpx.get(svc.base_url + "/v1/ready", timeout=30)
        pids = svc.worker_pids()
        before = {pid: proc_stats(pid) for pid in pids}
        sampler = Sampler(args.admin_url, name)
        sampler.start()
        samples: list[tuple[float, int, str]] = []
        lock = threading.Lock()

        def worker(chunk: list[dict[str, Any]]) -> None:
            local = []
            # No keep-alive: every request is a new connection, so the kernel spreads load
            # over all workers as a load balancer would (a pinned connection would not).
            limits = httpx.Limits(max_keepalive_connections=0)
            with httpx.Client(base_url=svc.base_url, timeout=60, limits=limits) as client:
                headers = {
                    "Authorization": f"Bearer {credential}",
                    "Content-Type": "application/json",
                }
                for event in chunk:
                    body = json.dumps(event).encode()
                    t0 = time.perf_counter()
                    r = client.post("/v1/score", content=body, headers=headers)
                    ms = (time.perf_counter() - t0) * 1e3
                    status = (
                        r.json().get("status", "error")
                        if r.status_code in (200, 202)
                        else f"http_{r.status_code}"
                    )
                    local.append((ms, r.status_code, status))
            with lock:
                samples.extend(local)

        t0 = time.perf_counter()
        threads = [threading.Thread(target=worker, args=(c,)) for c in partitions(events, clients)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        elapsed = time.perf_counter() - t0
        sampler.stop.set()
        sampler.join()
        after = {pid: proc_stats(pid) for pid in pids if Path(f"/proc/{pid}").exists()}
        info = rclient.info("clients")
    rclient.close()
    all_ms = [ms for ms, _, _ in samples]
    decided = [ms for ms, _, st in samples if st == "decided"]
    errors = [s for s in samples if s[1] not in (200, 202)]
    with make_session_factory(engine)() as s:
        stage = [
            sum(float((latency or {}).get(k, 0.0)) for k in DB_STAGES)
            for latency in s.scalars(select(RiskAssessment.latency_ms))
        ]
    engine.dispose()
    drop(args.admin_url, name)
    result.update(
        {
            "requests": len(samples),
            "seconds": round(elapsed, 2),
            "requests_per_second": round(len(samples) / elapsed, 1),
            "latency_ms_all": pct(all_ms),
            "latency_ms_decisions": pct(decided),
            "error_rate": round(len(errors) / max(1, len(samples)), 4),
            "errors": sorted({e[2] for e in errors}),
            "db_stage_ms_per_decision": pct(stage),
            "peak_db_connections": sampler.peak_conns,
            "pool_saturation": round(sampler.peak_conns / max(1, result["pool_ceiling"]), 2),
            "peak_lock_waits": sampler.peak_lock_waits,
            "redis_connected_clients": int(info.get("connected_clients", 0)),
            "worker_rss_mb": [round(v["rss_mb"], 1) for v in after.values()],
            "worker_cpu_seconds": [
                round(after[p]["cpu_s"] - before[p]["cpu_s"], 2) for p in after if p in before
            ],
        }
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--admin-url", required=True)
    parser.add_argument("--template", default="fraud_ai_world_tpl")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--redis-url", required=True)
    parser.add_argument("--workers", default="1,4,8,16")
    parser.add_argument("--pool-sweep", default="1:0,2:0,5:0,5:10,10:10")
    parser.add_argument("--pool-sweep-workers", type=int, default=8)
    parser.add_argument("--output", type=Path, default=Path("pg-benchmark"))
    parser.add_argument(
        "--env", action="append", default=[], help="extra KEY=VALUE for the service, repeatable"
    )
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    events = [json.loads(line) for line in (args.root / "live.jsonl").read_text().splitlines()]
    report: dict[str, Any] = {
        "kind": "pg_load_benchmark",
        "note": "SYNTHETIC data, local 4-CPU machine, loopback; not an SLA",
        "events_per_run": len(events),
        "scaling": [],
        "pool_sweep": [],
    }
    for w in [int(x) for x in args.workers.split(",") if x]:
        r = run_once(
            args,
            events,
            workers=w,
            clients=w,
            pool_size=5,
            max_overflow=10,
            pool_timeout=30,
            label=f"w{w}",
        )
        report["scaling"].append(r)
        print(
            json.dumps(
                {
                    k: r[k]
                    for k in (
                        "label",
                        "requests_per_second",
                        "latency_ms_all",
                        "error_rate",
                        "peak_db_connections",
                    )
                }
            )
        )
    for spec in [s for s in args.pool_sweep.split(",") if s]:
        size, overflow = (int(x) for x in spec.split(":"))
        r = run_once(
            args,
            events,
            workers=args.pool_sweep_workers,
            clients=16,
            pool_size=size,
            max_overflow=overflow,
            pool_timeout=2,
            label=f"pool{size}_{overflow}",
        )
        report["pool_sweep"].append(r)
        print(
            json.dumps(
                {
                    k: r[k]
                    for k in (
                        "label",
                        "requests_per_second",
                        "latency_ms_all",
                        "error_rate",
                        "pool_saturation",
                    )
                }
            )
        )
    target = args.output / "pg_load_benchmark.json"
    target.write_text(json.dumps(report, indent=2, sort_keys=True))
    print(f"written {target}")


if __name__ == "__main__":
    main()
