#!/usr/bin/env python
"""Per-process model cache cost (Stage 10).

Every uvicorn worker is its own process with its own model cache; model objects are never
shared between processes (sharing unpickled objects across processes would be unsafe and
is not attempted). This measures, in a fresh process per model set:

* artefact verification cost: SHA-256 over the artefact files only;
* verified load time: ``load_registered_model`` (verify, then deserialise);
* resident memory before and after loading the active policy's models (and the shadow
  models), i.e. the per-worker memory the cache adds.

    python scripts/model_cache_benchmark.py --database-url postgresql+psycopg://... \
        --output model-cache.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _rss_mb() -> float:
    status = Path("/proc/self/status").read_text()
    return (
        next(int(line.split()[1]) for line in status.splitlines() if line.startswith("VmRSS"))
        / 1024
    )


def measure(database_url: str) -> dict[str, Any]:
    from fraud_ai.database.engine import create_db_engine, make_session_factory
    from fraud_ai.models.registry import resolve_model
    from fraud_ai.models.scoring import load_registered_model
    from fraud_ai.risk.registry import active_deployment

    engine = create_db_engine(database_url)
    started_rss = _rss_mb()
    out: dict[str, Any] = {"baseline_rss_mb": round(started_rss, 1), "models": []}
    with make_session_factory(engine)() as s:
        deployment = active_deployment(s)
        assert deployment is not None, "no active deployment"
        refs = [slot.ref for slot in deployment.policy.slots().values()]
        refs += list(deployment.shadow_models)
        records = [resolve_model(s, ref) for ref in refs]
    for record in records:
        path = Path(record.model_path)
        t0 = time.perf_counter()
        size = 0
        for f in sorted(path.iterdir()):
            data = f.read_bytes()
            size += len(data)
            hashlib.sha256(data).hexdigest()
        hash_ms = (time.perf_counter() - t0) * 1e3
        before = _rss_mb()
        t1 = time.perf_counter()
        load_registered_model(record)
        load_ms = (time.perf_counter() - t1) * 1e3
        out["models"].append(
            {
                "model": f"{record.model_name}-{record.model_version}",
                "artifact_bytes": size,
                "sha256_ms": round(hash_ms, 2),
                "verified_load_ms": round(load_ms, 2),
                "rss_delta_mb": round(_rss_mb() - before, 1),
            }
        )
    out["loaded_rss_mb"] = round(_rss_mb(), 1)
    out["cache_rss_mb"] = round(out["loaded_rss_mb"] - started_rss, 1)
    engine.dispose()
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--runs", type=int, default=3, help="fresh processes to average over")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child:
        print(json.dumps(measure(args.database_url)))
        return
    runs = []
    for _ in range(args.runs):
        proc = subprocess.run(  # noqa: S603 - this script, fixed arguments
            [sys.executable, __file__, "--database-url", args.database_url, "--child"],
            capture_output=True,
            text=True,
            check=True,
        )
        runs.append(json.loads(proc.stdout.strip().splitlines()[-1]))
    report = {
        "kind": "model_cache_benchmark",
        "note": "fresh process per run; SYNTHETIC models; this machine",
        "runs": runs,
        "cache_rss_mb_mean": round(sum(r["cache_rss_mb"] for r in runs) / len(runs), 1),
    }
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(text)
    print(text)


if __name__ == "__main__":
    main()
