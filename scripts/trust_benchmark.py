#!/usr/bin/env python
"""Stage 11 overhead measurements (SYNTHETIC; this machine; not an SLA).

* request signing: v1 vs v2 sign + verify (per request, microseconds)
* model loading: verified load with and without the Ed25519 signature check (startup /
  first load only; the cache means scoring requests never pay it)
* audit anchoring: creating an anchor and verifying anchors over N events
* two-person approval: approving and checking the activation gate

    python scripts/trust_benchmark.py --out benchmarks/stage11_trust_overhead.json
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select

from fraud_ai import audit
from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.migrations import upgrade
from fraud_ai.database.models import ModelVersion
from fraud_ai.models.scoring import load_registered_model
from fraud_ai.models.signing import ModelTrust, sign_model
from fraud_ai.service.signatures import RequestTarget, check_signature, sign, sign_v2
from fraud_ai.trust import keys as tk
from fraud_ai.trust.anchors import FileAnchorStore, create_anchor, verify_anchors

NOW = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)


def _stats(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    return {
        "median": round(statistics.median(ordered), 3),
        "p95": round(ordered[int(0.95 * (len(ordered) - 1))], 3),
        "n": len(ordered),
    }


def signing(n: int = 20000) -> dict[str, Any]:
    secret = "benchmark-signing-secret-0123456789abcdef"
    body = json.dumps({"event": "x" * 1500}).encode()  # a typical ~1.5 KB scoring body
    ts = int(NOW.timestamp())
    target = RequestTarget("POST", "/v1/score", "")
    out: dict[str, Any] = {}
    for version in ("v1", "v2"):
        samples = []
        for _ in range(n):
            started = time.perf_counter()
            header = (
                sign(secret, ts, body)
                if version == "v1"
                else sign_v2(secret, "POST", "/v1/score", ts, body)
            )
            check_signature(
                secret, str(ts), header, body, now=NOW, max_age=300, target=target,
                min_version="v1",
            )  # fmt: skip
            samples.append((time.perf_counter() - started) * 1e6)
        out[version] = _stats(samples)
    out["unit"] = "microseconds per request (sign + verify, 1.5 KB body)"
    return out


def model_loads(world: Path, url: str, pair: tk.KeyPair, repeats: int = 7) -> dict[str, Any]:
    """Per-model components: one safe read of the directory, the digest over those bytes,
    the Ed25519 signature check over them, and the full verified load."""
    from fraud_ai.models.artifact_io import ArtifactBytes
    from fraud_ai.models.factory import digest_names, kind_for_name
    from fraud_ai.models.signing import verify_loaded

    engine = create_db_engine(url)
    factory = make_session_factory(engine)
    trusted = ModelTrust(required=True, keys={pair.key_id: pair.public})
    out: dict[str, Any] = {}
    with factory() as s:
        for m in s.scalars(select(ModelVersion)):
            read, digest, signature, full = [], [], [], []
            for _ in range(repeats):
                t0 = time.perf_counter()
                blob = ArtifactBytes.read(Path(m.model_path))
                t1 = time.perf_counter()
                blob.digest(digest_names(kind_for_name(m.model_name), blob))
                t2 = time.perf_counter()
                verify_loaded(m, blob, trusted)
                t3 = time.perf_counter()
                load_registered_model(m, trust=trusted)
                t4 = time.perf_counter()
                read.append((t1 - t0) * 1000)
                digest.append((t2 - t1) * 1000)
                signature.append((t3 - t2) * 1000)
                full.append((t4 - t3) * 1000)
            out[f"{m.model_name}-{m.model_version}"] = {
                "artifact_bytes": sum(len(v) for v in blob.files.values()),
                "read_once_ms": _stats(read),
                "digest_ms": _stats(digest),
                "signature_check_ms": _stats(signature),
                "full_verified_load_ms": _stats(full),
            }
    out["unit"] = "milliseconds (startup / cache miss only; never per request)"
    engine.dispose()
    return out


def anchoring(tmp: Path, events: int) -> dict[str, Any]:
    db = tmp / "anchor.db"
    url = f"sqlite:///{db}"
    upgrade(url)
    factory = make_session_factory(create_db_engine(url))
    with session_scope(factory) as s:
        for i in range(events):
            audit.record(s, "service_key.created", actor="cli:bench", target_type="k",
                         target_id=str(i), now=NOW + timedelta(seconds=i))  # fmt: skip
    pair = tk.generate()
    store = FileAnchorStore(tmp / "anchors")
    started = time.perf_counter()
    with factory() as s:
        create_anchor(s, store, pair, actor="cli:bench", now=NOW + timedelta(days=1))
    create_ms = (time.perf_counter() - started) * 1000
    started = time.perf_counter()
    with factory() as s:
        report = verify_anchors(s, store, {pair.key_id: pair.public})
    verify_ms = (time.perf_counter() - started) * 1000
    assert report.ok
    return {
        "events": events,
        "create_anchor_ms": round(create_ms, 1),
        "verify_chain_and_anchors_ms": round(verify_ms, 1),
    }


def approvals(url: str) -> dict[str, Any]:
    from fraud_ai.risk.approvals import approve, ensure_approved
    from fraud_ai.risk.promotion import promote

    factory = make_session_factory(create_db_engine(url))
    policy = "risk-policy-1.1.0"
    with session_scope(factory) as s:
        promote(s, policy, "shadow", actor="cli:a", note="bench")
        promote(s, policy, "evaluation", actor="cli:a", note="bench",
                evidence={"simulation": {"events": 1}})  # fmt: skip
        promote(s, policy, "candidate", actor="cli:a", note="bench", approved=True)
    timings = []
    for operator in ("alice", "bob"):
        started = time.perf_counter()
        with session_scope(factory) as s:
            approve(s, policy, operator=operator, note="bench", ttl_hours=72, now=NOW)
        timings.append((time.perf_counter() - started) * 1000)
    started = time.perf_counter()
    with factory() as s:
        ensure_approved(s, policy, required=2, now=NOW)
    gate_ms = (time.perf_counter() - started) * 1000
    return {
        "approve_ms": [round(t, 1) for t in timings],
        "activation_gate_ms": round(gate_ms, 2),
        "note": "operator actions, never on the request path",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--events", type=int, default=2000)
    args = parser.parse_args()
    from tests.realtime_world import build_world, copy_world

    report: dict[str, Any] = {
        "kind": "stage11_trust_overhead",
        "note": "SYNTHETIC; local 4-vCPU container; not an SLA",
    }
    report["request_signing"] = signing()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        template = root / "template.db"
        upgrade(f"sqlite:///{template}")
        (root / "world").mkdir()
        (root / "copy").mkdir()
        world_dir = build_world(root / "world", template)
        world = copy_world(world_dir, root / "copy")
        pair = tk.generate()
        with world.session() as s:
            for model in s.scalars(select(ModelVersion)):
                sign_model(s, model, pair, actor="cli:bench")
            s.commit()
        report["model_loading"] = model_loads(world.root, world.url, pair)
        report["audit_anchoring"] = anchoring(root, args.events)
        report["two_person_approval"] = approvals(world.url)
        world.engine.dispose()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
