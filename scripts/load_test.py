#!/usr/bin/env python
"""Stage 12 staging load test: the real stack over TLS (Caddy -> fraud-ai workers ->
PostgreSQL + Redis, each in its own container), driven from a separate load-generator
process. SYNTHETIC data. Not part of CI.

Everything runs on ONE host: containers on Docker networks, real TCP and TLS between them,
but shared CPUs. It is a single-host networked test, not a multi-machine one.

Shapes (``--shapes``):

* ``steady``: C clients replay the live stream (users partitioned, so per-user order
  holds) at a target aggregate rate;
* ``burst``: 3xC clients, unthrottled, for a short window;
* ``replay``: already-accepted signed requests re-sent verbatim, which must be refused
  (REPLAYED_SIGNATURE) without being stored;
* ``reviews``: high review volume. Lists and details, then every open review resolved,
  each with the reviewer's own single-use operator assertion;
* ``stepups``: high step-up volume. Payment step-ups for the STEP_UP decisions, then
  their signed provider callbacks;
* ``failures``: moderate steady load while one service worker is killed, Redis is
  restarted and every service database connection is terminated. It records a per-second
  timeline to show fail-closed behaviour and recovery.

Measured: throughput, latency p50/p95/p99, error rate by code, container CPU and memory
(``docker stats``), PostgreSQL connections (``pg_stat_activity``) and Redis latency
(``redis-cli --latency``).

    python scripts/load_test.py --base-url https://staging.fraud-ai.test:8443 \\
        --ca-bundle deploy/staging/out/caddy-root.crt --credential ... --signing-secret ... \\
        --webhook-secret-file deploy/staging/secrets/payment_webhook_secret \\
        --events deploy/staging/models/live.jsonl \\
        --reviewer-key deploy/staging/operators/rita.pem \\
        --compose deploy/staging/docker-compose.staging.yml --output load-test/run.json
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import shutil
import subprocess  # nosec B404 - docker CLI with fixed arguments
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fraud_ai.service.signatures import sign_v2
from fraud_ai.stepup.payment import FakePaymentAuthProvider

DOCKER = shutil.which("docker") or "docker"
SERVICE_CONNECTIONS = "select count(*) from pg_stat_activity where usename = 'fraud_service'"
TERMINATE_SERVICE_CONNECTIONS = (
    "select count(pg_terminate_backend(pid)) from pg_stat_activity where usename = 'fraud_service'"
)
LIST_PROCESSES = (
    "import os\n"
    "for p in os.listdir('/proc'):\n"
    " if p.isdigit():\n"
    "  s = open(f'/proc/{p}/stat').read().rsplit(')', 1)[1].split()\n"
    "  print(p, s[1])"
)


def pct(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"p50": None, "p95": None, "p99": None}
    p50, p95, p99 = np.percentile(np.asarray(values), [50, 95, 99])
    return {"p50": round(float(p50), 1), "p95": round(float(p95), 1), "p99": round(float(p99), 1)}


@dataclass
class Result:
    ok: int = 0
    codes: Counter[str] = field(default_factory=Counter)
    latencies: list[float] = field(default_factory=list)
    timeline: dict[int, Counter[str]] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add(self, started: float, status: int, code: str | None, t0: float) -> None:
        elapsed = (time.perf_counter() - started) * 1000
        key = "ok" if 200 <= status < 300 else f"{status}:{code or '-'}"
        second = int(time.time() - t0)
        with self.lock:
            self.latencies.append(elapsed)
            self.codes[key] += 1
            self.timeline.setdefault(second, Counter())[key] += 1
            if key == "ok":
                self.ok += 1

    def summary(self, seconds: float) -> dict[str, Any]:
        total = sum(self.codes.values())
        return {
            "requests": total,
            "seconds": round(seconds, 2),
            "requests_per_second": round(total / seconds, 1) if seconds else None,
            "latency_ms": pct(self.latencies),
            "error_rate": round(1 - self.ok / total, 4) if total else None,
            "codes": dict(self.codes),
        }


_USED: dict[tuple[str, str, bytes], set[int]] = {}
_USED_LOCK = threading.Lock()


def _timestamp(method: str, path: str, body: bytes) -> int:
    """A timestamp not yet used for this exact request: identical requests in the same
    second would carry identical signatures, which the service refuses as replays."""
    now = int(time.time())
    with _USED_LOCK:
        used = _USED.setdefault((method, path, body), set())
        ts = next(t for t in range(now, now - 250, -1) if t not in used)
        used.add(ts)
        return ts


class Client:
    """Keep-alive HTTPS client with v2 request signatures (one per load thread)."""

    def __init__(self, base: str, credential: str, secret: str, verify: Any) -> None:
        self.http = httpx.Client(base_url=base, verify=verify, timeout=60)
        self.credential, self.secret = credential, secret

    def headers(self, method: str, path: str, body: bytes) -> dict[str, str]:
        ts = _timestamp(method, path, body)
        bare, _, query = path.partition("?")
        return {
            "Authorization": f"Bearer {self.credential}",
            "Content-Type": "application/json",
            "X-Fraud-Timestamp": str(ts),
            "X-Fraud-Signature": sign_v2(self.secret, method, bare, ts, body, query=query),
        }

    def send(
        self, method: str, path: str, payload: Any = None, extra: dict[str, str] | None = None
    ) -> tuple[httpx.Response, bytes, dict[str, str]]:
        body = b"" if payload is None else json.dumps(payload).encode()
        headers = {**self.headers(method, path, body), **(extra or {})}
        return self.http.request(method, path, content=body or None, headers=headers), body, headers


def _code(response: httpx.Response) -> str | None:
    try:
        return str(response.json().get("error", {}).get("code"))
    except ValueError:
        return None


class Sampler(threading.Thread):
    """Container CPU/memory, PostgreSQL connections and Redis latency, every ``interval``."""

    def __init__(self, compose: Path, redis_password: str | None, interval: float = 3.0) -> None:
        super().__init__(daemon=True)
        self.compose, self.redis_password, self.interval = compose, redis_password, interval
        self.samples: list[dict[str, Any]] = []
        self.stop_event = threading.Event()

    def _run(self, *args: str, timeout: float = 20) -> str:
        return subprocess.run(  # nosec B603 # noqa: S603 - docker CLI, argument list
            [DOCKER, "compose", "-f", str(self.compose), *args],
            capture_output=True, text=True, timeout=timeout, check=False,
        ).stdout  # fmt: skip

    def sample(self) -> dict[str, Any]:
        out: dict[str, Any] = {"t": time.time()}
        stats = subprocess.run(  # noqa: S603  # nosec B603 - docker CLI, argument list
            [DOCKER, "stats", "--no-stream", "--format", "{{json .}}"],
            capture_output=True, text=True, timeout=30, check=False,
        ).stdout  # fmt: skip
        for line in stats.splitlines():
            row = json.loads(line)
            name = row["Name"]
            for svc in ("fraud-ai-1", "postgres-1", "redis-1", "proxy-1"):
                if name.endswith(svc):
                    out[svc.removesuffix("-1")] = {
                        "cpu_pct": float(row["CPUPerc"].rstrip("%") or 0),
                        "mem": row["MemUsage"].split("/")[0].strip(),
                    }
        conns = self._run("exec", "-T", "postgres", "psql", "-U", "postgres", "-Atc",
                          SERVICE_CONNECTIONS)  # fmt: skip
        out["db_connections"] = int(conns.strip() or 0) if conns.strip().isdigit() else None
        if self.redis_password:
            lat = self._run("exec", "-T", "redis", "sh", "-c",
                            f"timeout 2 redis-cli -a '{self.redis_password}' --no-auth-warning "
                            "--latency --raw", timeout=10)  # fmt: skip
            parts = lat.strip().split()
            out["redis_latency_ms"] = float(parts[2]) if len(parts) >= 3 else None
        return out

    def run(self) -> None:
        while not self.stop_event.is_set():
            with contextlib.suppress(subprocess.TimeoutExpired, ValueError, OSError):
                self.samples.append(self.sample())
            self.stop_event.wait(self.interval)

    def summary(self) -> dict[str, Any]:
        def peak(key: str, sub: str) -> float | None:
            vals = [s[key][sub] for s in self.samples if key in s]
            return max(vals) if vals else None

        def mems(key: str) -> list[str]:
            return [s[key]["mem"] for s in self.samples if key in s][-1:]

        conns = [s["db_connections"] for s in self.samples if s.get("db_connections") is not None]
        redis = [s["redis_latency_ms"] for s in self.samples if s.get("redis_latency_ms")]
        return {
            "samples": len(self.samples),
            "peak_cpu_pct": {
                k: peak(k, "cpu_pct") for k in ("fraud-ai", "postgres", "redis", "proxy")
            },
            "last_mem": {k: mems(k) for k in ("fraud-ai", "postgres", "redis", "proxy")},
            "db_connections": {
                "peak": max(conns, default=None),
                "mean": round(float(np.mean(conns)), 1) if conns else None,
            },
            "redis_latency_ms_avg": {
                "mean": round(float(np.mean(redis)), 2) if redis else None,
                "max": max(redis, default=None),
            },
        }


def partitions(events: list[dict[str, Any]], n: int) -> list[list[dict[str, Any]]]:
    users = sorted({str(e.get("user_id")) for e in events})
    slot = {u: i % n for i, u in enumerate(users)}
    out: list[list[dict[str, Any]]] = [[] for _ in range(n)]
    for e in events:
        out[slot[str(e.get("user_id"))]].append(e)
    return out


def replay_stream(args: argparse.Namespace, events: list[dict[str, Any]], clients: int,
                  seconds: float, rate: float | None, collect: dict[str, list[Any]],
                  t0: float | None = None) -> tuple[Result, float]:  # fmt: skip
    """Score events for ``seconds`` with ``clients`` threads at ``rate`` req/s in total."""
    result = Result()
    t0 = t0 or time.time()
    deadline = time.perf_counter() + seconds
    parts = partitions(events, clients)
    interval = clients / rate if rate else 0.0

    def worker(part: list[dict[str, Any]]) -> None:
        client = Client(args.base_url, args.credential, args.signing_secret, args.verify)
        next_at = time.perf_counter()
        for event in part:
            if time.perf_counter() > deadline:
                break
            if interval:
                next_at += interval
                delay = next_at - time.perf_counter()
                if delay > 0:
                    time.sleep(delay)
            started = time.perf_counter()
            try:
                r, body, headers = client.send("POST", "/v1/score", event)
            except httpx.HTTPError as exc:
                result.add(started, 0, type(exc).__name__, t0)
                continue
            result.add(started, r.status_code, _code(r), t0)
            if r.status_code == 200:
                data = r.json()
                with result.lock:
                    if len(collect["signed"]) < 500:
                        collect["signed"].append((body, headers))
                    if (
                        data.get("decision") == "STEP_UP_AUTHENTICATION"
                        and data.get("status") == "decided"
                    ):
                        collect["stepups"].append(data["assessment_id"])
        client.http.close()

    start = time.perf_counter()
    threads = [threading.Thread(target=worker, args=(p,)) for p in parts]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return result, time.perf_counter() - start


def replay_attack(
    args: argparse.Namespace, signed: list[tuple[bytes, dict[str, str]]]
) -> dict[str, Any]:
    result = Result()
    t0 = time.time()
    client = Client(args.base_url, args.credential, args.signing_secret, args.verify)
    start = time.perf_counter()
    for body, headers in signed[:300]:
        s = time.perf_counter()
        r = client.http.post("/v1/score", content=body, headers=headers)
        result.add(s, r.status_code, _code(r), t0)
    client.http.close()
    out = result.summary(time.perf_counter() - start)
    out["accepted_replays"] = result.ok  # must be 0
    return out


def reviews(args: argparse.Namespace) -> dict[str, Any]:
    from fraud_ai.trust.keys import load_private_key
    from fraud_ai.trust.operators import create_assertion

    pair = load_private_key(args.reviewer_key)
    result = Result()
    t0 = time.time()
    client = Client(args.base_url, args.credential, args.signing_secret, args.verify)
    start = time.perf_counter()
    listed = client.send("GET", "/v1/reviews?status=open&limit=200")[0].json().get("items", [])

    def work(items: list[dict[str, Any]]) -> None:
        c = Client(args.base_url, args.credential, args.signing_secret, args.verify)
        for item in items:
            for _ in range(3):
                s = time.perf_counter()
                r = c.send("GET", "/v1/reviews?status=open&limit=50")[0]
                result.add(s, r.status_code, _code(r), t0)
            s = time.perf_counter()
            r = c.send("GET", f"/v1/reviews/{item['review_id']}")[0]
            result.add(s, r.status_code, _code(r), t0)
            token = create_assertion(pair, args.reviewer_id, action="review.resolve",
                                     target=item["review_id"], binding={"resolution": "legitimate"},
                                     audience=args.operator_audience)  # fmt: skip
            s = time.perf_counter()
            r = c.send("POST", f"/v1/reviews/{item['review_id']}/resolve",
                       {"resolution": "legitimate", "note": "load test (synthetic)"},
                       extra={"X-Fraud-Operator-Assertion": token})[0]  # fmt: skip
            result.add(s, r.status_code, _code(r), t0)
        c.http.close()

    chunks = [listed[i :: args.clients] for i in range(args.clients)]
    threads = [threading.Thread(target=work, args=(c,)) for c in chunks if c]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    client.http.close()
    out = result.summary(time.perf_counter() - start)
    out["open_reviews_resolved"] = len(listed)
    return out


def stepups(args: argparse.Namespace, assessments: list[str]) -> dict[str, Any]:
    result = Result()
    t0 = time.time()
    fake = FakePaymentAuthProvider(args.webhook_secret)
    start = time.perf_counter()

    def work(ids: list[str]) -> None:
        c = Client(args.base_url, args.credential, args.signing_secret, args.verify)
        for aid in ids:
            s = time.perf_counter()
            r = c.send("POST", f"/v1/step-up/{aid}/payment",
                       {"token_reference": "tok_load_synthetic_0001", "amount_minor": 4250,
                        "currency": "GBP"})[0]  # fmt: skip
            result.add(s, r.status_code, _code(r), t0)
            if r.status_code != 200:
                continue
            attempt = r.json().get("attempt_number", 1)
            reference = "fake_" + hashlib.sha256(f"{aid}:{attempt}".encode()).hexdigest()[:24]
            headers, payload = fake.simulate_callback(reference)
            s = time.perf_counter()
            cb = c.http.post("/v1/callbacks/payment/fake", content=payload,
                             headers={**headers, "Content-Type": "application/json"})  # fmt: skip
            result.add(s, cb.status_code, _code(cb), t0)
        c.http.close()

    unique = list(dict.fromkeys(assessments))
    chunks = [unique[i :: args.clients] for i in range(args.clients)]
    threads = [threading.Thread(target=work, args=(c,)) for c in chunks if c]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    out = result.summary(time.perf_counter() - start)
    out["step_ups"] = len(unique)
    return out


def failures(args: argparse.Namespace, events: list[dict[str, Any]]) -> dict[str, Any]:
    """Moderate load for ~100 s with three injected failures; a per-second timeline."""
    compose = [DOCKER, "compose", "-f", str(args.compose)]
    injected: list[dict[str, Any]] = []
    t0 = time.time()

    def inject() -> None:
        time.sleep(20)
        pids = subprocess.run(  # nosec B603 # noqa: S603
            [*compose, "exec", "-T", "fraud-ai", "python", "-c",
             LIST_PROCESSES],
            capture_output=True, text=True, check=False,
        ).stdout.split()  # fmt: skip
        pairs = list(zip(pids[::2], pids[1::2], strict=False))
        master = min(int(p) for p, ppid in pairs if ppid == "0") if pairs else 1
        children = sorted(int(p) for p, ppid in pairs if int(ppid) == master)
        victim = children[-1] if children else None
        # The slim image has no `kill` binary (a shell builtin): signal from Python, then
        # confirm the process is really gone before recording the injection.
        killed = False
        if victim:
            done = subprocess.run(  # noqa: S603  # nosec B603
                [*compose, "exec", "-T", "fraud-ai", "python", "-c",
                 f"import os, signal, time; os.kill({victim}, signal.SIGKILL); time.sleep(1); "
                 f"print(os.path.exists('/proc/{victim}/status') and "
                 f"'State:\\tZ' not in open('/proc/{victim}/status').read())"],
                capture_output=True, text=True, check=False,
            )  # fmt: skip
            killed = done.returncode == 0 and done.stdout.strip() == "False"
        injected.append(
            {"t": round(time.time() - t0, 1), "event": f"SIGKILL worker pid {victim}",
             "confirmed_dead": killed}
        )  # fmt: skip
        time.sleep(25)
        injected.append({"t": round(time.time() - t0, 1), "event": "redis restart begins"})
        subprocess.run([*compose, "restart", "redis"], capture_output=True, check=False)  # noqa: S603  # nosec B603
        injected.append({"t": round(time.time() - t0, 1), "event": "redis restarted"})
        time.sleep(25)
        subprocess.run(  # noqa: S603  # nosec B603
            [*compose, "exec", "-T", "postgres", "psql", "-U", "postgres", "-Atc",
             TERMINATE_SERVICE_CONNECTIONS],
            capture_output=True, check=False,
        )  # fmt: skip
        injected.append(
            {
                "t": round(time.time() - t0, 1),
                "event": "terminated every fraud_service DB connection",
            }
        )

    threading.Thread(target=inject, daemon=True).start()
    collect: dict[str, list[Any]] = {"signed": [], "stepups": []}
    result, seconds = replay_stream(args, events, args.clients, 100, args.rate / 2, collect, t0=t0)
    timeline = {str(sec): dict(counts) for sec, counts in sorted(result.timeline.items())}
    return {"summary": result.summary(seconds), "injected": injected, "timeline": timeline}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--credential", required=True)
    parser.add_argument("--signing-secret", required=True)
    parser.add_argument("--webhook-secret-file", type=Path, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--ca-bundle", default=None)
    parser.add_argument("--reviewer-key", type=Path, required=True)
    parser.add_argument("--reviewer-id", default="rita")
    parser.add_argument("--operator-audience", default="fraud-ai-admin")
    parser.add_argument("--compose", type=Path, required=True)
    parser.add_argument("--redis-password-file", type=Path, default=None)
    parser.add_argument("--clients", type=int, default=16)
    parser.add_argument("--rate", type=float, default=80.0, help="steady aggregate req/s")
    parser.add_argument("--steady-seconds", type=float, default=90.0)
    parser.add_argument("--burst-seconds", type=float, default=15.0)
    parser.add_argument("--shapes", default="steady,burst,replay,reviews,stepups,failures")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.verify = args.ca_bundle or True
    args.webhook_secret = args.webhook_secret_file.read_text().strip()
    events = [json.loads(line) for line in args.events.read_text().splitlines() if line.strip()]
    shapes = set(args.shapes.split(","))
    redis_pw = args.redis_password_file.read_text().strip() if args.redis_password_file else None
    report: dict[str, Any] = {
        "kind": "stage12_load_test",
        "note": "SYNTHETIC data; ONE host (separate containers, real TCP/TLS, shared CPUs)",
        "live_events_available": len(events),
        "users_in_stream": len({e.get("user_id") for e in events}),
        "clients": args.clients,
    }
    collect: dict[str, list[Any]] = {"signed": [], "stepups": []}
    cursor = 0

    def take(n: int) -> list[dict[str, Any]]:
        nonlocal cursor
        chunk = events[cursor : cursor + n]
        cursor += n
        return chunk

    if "steady" in shapes:
        sampler = Sampler(args.compose, redis_pw)
        sampler.start()
        batch = take(int(args.rate * args.steady_seconds * 1.2))
        r, secs = replay_stream(args, batch, args.clients,
                                args.steady_seconds, args.rate, collect)  # fmt: skip
        sampler.stop_event.set()
        sampler.join()
        report["steady"] = {
            **r.summary(secs),
            "target_rps": args.rate,
            "resources": sampler.summary(),
        }
        print("steady", json.dumps(report["steady"])[:400], flush=True)
    if "burst" in shapes:
        sampler = Sampler(args.compose, redis_pw, interval=2)
        sampler.start()
        # Sized from the throughput a burst can reach (generously), so the later shapes
        # still get fresh, never-scored events.
        burst_events = int(args.clients * 3 * args.burst_seconds * 12)
        r, secs = replay_stream(
            args, take(burst_events), args.clients * 3, args.burst_seconds, None, collect
        )
        sampler.stop_event.set()
        sampler.join()
        report["burst"] = {
            **r.summary(secs),
            "clients": args.clients * 3,
            "resources": sampler.summary(),
        }
        print("burst", json.dumps(report["burst"])[:400], flush=True)
    if "replay" in shapes:
        report["replay"] = replay_attack(args, collect["signed"])
        print("replay", json.dumps(report["replay"])[:300], flush=True)
    if "stepups" in shapes:
        report["stepups"] = stepups(args, collect["stepups"])
        print("stepups", json.dumps(report["stepups"])[:300], flush=True)
    if "reviews" in shapes:
        report["reviews"] = reviews(args)
        print("reviews", json.dumps(report["reviews"])[:300], flush=True)
    if "failures" in shapes:
        report["failures"] = failures(args, take(int(args.rate / 2 * 100 * 1.5)))
        print("failures", json.dumps(report["failures"]["summary"])[:300], flush=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"written {args.output}")


if __name__ == "__main__":
    main()
