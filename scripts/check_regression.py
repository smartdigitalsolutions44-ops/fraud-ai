#!/usr/bin/env python
"""Compare a benchmark result against the stored baseline (Stage 10).

Flags only *large* regressions, so timing noise does not fail anything:

* latency (p50/p95/p99): worse by more than ``--latency-tolerance`` (default 35 %) **and**
  by more than ``--latency-floor-ms`` (default 5 ms);
* throughput: lower by more than ``--throughput-tolerance`` (default 25 %);
* memory: higher by more than ``--memory-tolerance`` (default 30 %) and 50 MB.

    python scripts/check_regression.py benchmarks/baseline.json new-results.json

The files use the flat ``metrics`` format written by ``--extract``:

    python scripts/check_regression.py --extract pg_load_benchmark.json > new-results.json

Exit status 1 when a regression is flagged (0 otherwise). CI runs it as an informational
step: benchmarks need a quiet, comparable machine to be meaningful.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def extract(report: dict[str, Any]) -> dict[str, float]:
    """Flatten a pg_load_benchmark / service_benchmark / model_cache report."""
    flat: dict[str, float] = {}
    kind = report.get("kind")
    if kind == "pg_load_benchmark":
        for run in report.get("scaling", []):
            prefix = f"pg.{run['label']}"
            flat[f"{prefix}.rps"] = run["requests_per_second"]
            for q in ("p50", "p95", "p99"):
                flat[f"{prefix}.latency_{q}_ms"] = run["latency_ms_all"][q]
            if run.get("worker_rss_mb"):
                flat[f"{prefix}.rss_mb_max"] = max(run["worker_rss_mb"])
    elif kind == "service_benchmark":
        for workers, row in report.get("results", {}).items():
            for mode in ("direct", "http", "http_signed"):
                prefix = f"sqlite.w{workers}.{mode}"
                flat[f"{prefix}.rps"] = row[mode]["requests_per_second"]
                for q in ("p50", "p95", "p99"):
                    flat[f"{prefix}.latency_{q}_ms"] = row[mode]["latency_ms_all"][q]
    elif kind == "model_cache_benchmark":
        flat["model_cache.rss_mb"] = report["cache_rss_mb_mean"]
    return {k: float(v) for k, v in flat.items() if v is not None}


def compare(
    baseline: dict[str, float], current: dict[str, float], args: argparse.Namespace
) -> list[str]:
    problems = []
    for key, old in sorted(baseline.items()):
        new = current.get(key)
        if new is None:
            continue
        if "latency" in key:
            if new > old * (1 + args.latency_tolerance) and new - old > args.latency_floor_ms:
                problems.append(f"{key}: {old:.1f} -> {new:.1f} ms")
        elif key.endswith(".rps"):
            if new < old * (1 - args.throughput_tolerance):
                problems.append(f"{key}: {old:.1f} -> {new:.1f} req/s")
        elif "rss" in key and new > old * (1 + args.memory_tolerance) and new - old > 50:
            problems.append(f"{key}: {old:.0f} -> {new:.0f} MB")
    return problems


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("baseline", type=Path, nargs="?")
    parser.add_argument("current", type=Path, nargs="?")
    parser.add_argument("--extract", type=Path, nargs="+", default=None)
    parser.add_argument("--latency-tolerance", type=float, default=0.35)
    parser.add_argument("--latency-floor-ms", type=float, default=5.0)
    parser.add_argument("--throughput-tolerance", type=float, default=0.25)
    parser.add_argument("--memory-tolerance", type=float, default=0.30)
    args = parser.parse_args()
    if args.extract:
        merged: dict[str, float] = {}
        for path in args.extract:
            merged.update(extract(json.loads(path.read_text())))
        print(json.dumps({"metrics": merged}, indent=2, sort_keys=True))
        return
    if args.baseline is None or args.current is None:
        parser.error("baseline and current are required")
    baseline = json.loads(args.baseline.read_text())["metrics"]
    current = json.loads(args.current.read_text())["metrics"]
    problems = compare(baseline, current, args)
    for problem in problems:
        print(f"REGRESSION {problem}")
    print(f"{len(problems)} regression(s) across {len(baseline)} baseline metrics")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
