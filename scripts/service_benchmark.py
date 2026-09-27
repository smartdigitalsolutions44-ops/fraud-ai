#!/usr/bin/env python
"""Stage 9 benchmark: the HTTP service against direct Stage 8 library scoring.

1. Build (or reuse, with ``--world``) the synthetic Stage 8 test world: history, trained
   models, two policies, an active deployment and a held-out live stream.
2. For each worker count (default 1, 4, 8, 16), replay the live stream on a fresh copy of
   the world three ways:
   * ``direct``: ``FraudScoringService.score_event`` in-process;
   * ``http``: ``POST /v1/score`` over a real loopback socket to uvicorn, with keep-alive
     and one client per worker;
   * ``http_signed``: the same with HMAC request signatures (replay tokens persisted).

   Workers take whole users, so per-user event order is preserved, as in production
   partitioning.
3. Report requests/sec and p50/p95/p99 latency, for all requests and for decision points
   only, plus the HTTP overhead over direct scoring.

    python scripts/service_benchmark.py --output service-benchmark

Numbers are SYNTHETIC, on this machine's CPU and SQLite (single writer: scoring
serialises there, so more workers mostly add queueing). This is not a production SLA.
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import numpy as np
import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fraud_ai.config.settings import Settings
from fraud_ai.database.engine import session_scope
from fraud_ai.database.migrations import upgrade
from fraud_ai.service.app import build_container, create_app
from fraud_ai.service.keys import create_key, signing_secret
from fraud_ai.service.signatures import sign
from tests.conftest import TEST_KEY
from tests.realtime_world import build_world, copy_world

MASTER = "benchmark-signing-master-key-0123456789"  # synthetic, benchmark only
DECIDED = {"decided"}


def _pct(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"p50": None, "p95": None, "p99": None}
    p50, p95, p99 = np.percentile(np.asarray(values), [50, 95, 99])
    return {"p50": round(float(p50), 2), "p95": round(float(p95), 2), "p99": round(float(p99), 2)}


def _partitions(events: list[dict[str, Any]], workers: int) -> list[list[dict[str, Any]]]:
    users = sorted({str(e.get("user_id")) for e in events})
    slot = {u: i % workers for i, u in enumerate(users)}
    return [[e for e in events if slot[str(e.get("user_id"))] == i] for i in range(workers)]


def _run(
    workers: int, events: list[dict[str, Any]], call: Any
) -> tuple[float, list[tuple[float, str]]]:
    parts = _partitions(events, workers)
    samples: list[tuple[float, str]] = []
    lock = threading.Lock()
    errors: list[str] = []

    def worker(index: int, chunk: list[dict[str, Any]]) -> None:
        state = call.setup(index)
        local = []
        for event in chunk:
            started = time.perf_counter()
            status = call.score(state, event)
            local.append(((time.perf_counter() - started) * 1e3, status))
            if status.startswith("error"):
                errors.append(status)
        with lock:
            samples.extend(local)

    threads = [threading.Thread(target=worker, args=(i, c)) for i, c in enumerate(parts)]
    started = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if errors:
        raise SystemExit(f"{len(errors)} requests failed, e.g. {errors[0]}")
    return time.perf_counter() - started, samples


class Direct:
    def __init__(self, service: Any) -> None:
        self.service = service

    def setup(self, index: int) -> None:
        return None

    def score(self, state: None, event: dict[str, Any]) -> str:
        return str(self.service.score_event(event).status)


class Http:
    def __init__(self, base: str, credential: str, signed: bool) -> None:
        self.base, self.credential, self.signed = base, credential, signed
        self.secret = signing_secret(MASTER, credential.split(".", 1)[0])

    def setup(self, index: int) -> httpx.Client:
        return httpx.Client(base_url=self.base, timeout=30.0)

    def score(self, client: httpx.Client, event: dict[str, Any]) -> str:
        body = json.dumps(event).encode()
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.credential}"}
        if self.signed:
            ts = int(time.time())
            headers["X-Fraud-Timestamp"] = str(ts)
            # A unique signature per request: the body differs per event.
            headers["X-Fraud-Signature"] = sign(self.secret, ts, body)
        r = client.post("/v1/score", content=body, headers=headers)
        if r.status_code not in (200, 202):
            return f"error {r.status_code}: {r.text[:200]}"
        return str(r.json()["status"])


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _serve(settings: Settings) -> tuple[uvicorn.Server, threading.Thread, Any]:
    container = build_container(settings)
    app = create_app(settings, container=container)
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
            proxy_headers=False,
            server_header=False,
            access_log=False,
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    return server, thread, container


def _summary(elapsed: float, samples: list[tuple[float, str]]) -> dict[str, Any]:
    all_ms = [ms for ms, _ in samples]
    decided = [ms for ms, status in samples if status in DECIDED]
    return {
        "requests": len(samples),
        "decisions": len(decided),
        "seconds": round(elapsed, 2),
        "requests_per_second": round(len(samples) / elapsed, 1),
        "latency_ms_all": _pct(all_ms),
        "latency_ms_decisions": _pct(decided),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--world", type=Path, default=None, help="Reuse a built world dir.")
    parser.add_argument("--workers", default="1,4,8,16")
    parser.add_argument("--output", type=Path, default=Path("service-benchmark"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="fraud-ai-service-bench-"))
    try:
        world = args.world
        if world is None:
            template = scratch / "template.db"
            upgrade(f"sqlite:///{template}")
            (scratch / "world").mkdir()
            started = time.perf_counter()
            world = build_world(scratch / "world", template)
            print(f"built the synthetic world in {time.perf_counter() - started:.0f}s")
        results: dict[str, Any] = {}
        for workers in [int(x) for x in args.workers.split(",")]:
            row: dict[str, Any] = {}
            for mode in ("direct", "http", "http_signed"):
                dest = scratch / f"run-{workers}-{mode}"
                dest.mkdir()
                w = copy_world(world, dest)
                if mode == "direct":
                    elapsed, samples = _run(workers, w.events, Direct(w.service()))
                else:
                    settings = Settings(
                        database_url=w.url,
                        pseudonymisation_key=TEST_KEY,
                        service_signing_master_key=MASTER,
                        rate_limit="1000000/minute",
                        rate_limit_burst=10_000,
                    )
                    keys = build_container(settings, engine=w.engine)
                    with session_scope(keys.factory) as s:
                        credential = create_key(
                            s, "bench", ["score:write", "score:replay", "signals:trusted"]
                        ).credential
                    keys.close()
                    server, thread, container = _serve(settings)
                    try:
                        base = f"http://127.0.0.1:{server.config.port}"
                        elapsed, samples = _run(
                            workers, w.events, Http(base, credential, mode == "http_signed")
                        )
                    finally:
                        server.should_exit = True
                        thread.join(timeout=10)
                        container.close()
                w.engine.dispose()
                row[mode] = _summary(elapsed, samples)
                shutil.rmtree(dest, ignore_errors=True)
            direct_p50 = row["direct"]["latency_ms_all"]["p50"]
            row["http_overhead_ms_p50"] = round(
                row["http"]["latency_ms_all"]["p50"] - direct_p50, 2
            )
            row["signing_overhead_ms_p50"] = round(
                row["http_signed"]["latency_ms_all"]["p50"] - row["http"]["latency_ms_all"]["p50"],
                2,
            )
            results[str(workers)] = row
            print(f"workers={workers}")
            for mode in ("direct", "http", "http_signed"):
                r = row[mode]
                a, d = r["latency_ms_all"], r["latency_ms_decisions"]
                print(
                    f"  {mode:<12} {r['requests_per_second']:>7.1f} req/s  all p50/p95/p99 "
                    f"{a['p50']}/{a['p95']}/{a['p99']} ms  decisions p50/p95/p99 "
                    f"{d['p50']}/{d['p95']}/{d['p99']} ms"
                )
            print(
                f"  http overhead p50 {row['http_overhead_ms_p50']} ms, "
                f"signing overhead p50 {row['signing_overhead_ms_p50']} ms"
            )
        report = {
            "kind": "service_benchmark",
            "note": "synthetic data, local CPU, SQLite single writer; not a production SLA",
            "events_per_run": len((world / "live.jsonl").read_text().splitlines()),
            "results": results,
        }
        target = args.output / "service_benchmark.json"
        target.write_text(json.dumps(report, indent=2, sort_keys=True))
        print(f"written {target}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    main()
