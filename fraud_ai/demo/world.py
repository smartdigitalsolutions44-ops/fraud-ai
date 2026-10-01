"""Build the deterministic portfolio demo world (Stage 12).

``build_world`` (``fraud-ai demo reset``):

1. creates a fresh SQLite demo database (the guard has already checked the target) whose
   first audit event is the ``demo.world_created`` marker;
2. seeds a SYNTHETIC world with fixed seeds: users of every synthetic scenario, 60 days of
   history and an 8-day live stream;
3. trains gradient boosting (primary) and logistic regression (shadow) with fixed seeds,
   signs both with a demo model key, and activates a policy with a shadow model and a
   shadow policy;
4. scores the first part of the live stream as background;
5. picks the ten demo cases (:data:`CASES`) from what the rest of the stream produces,
   then re-scores exactly the walkthrough's order on a scratch copy. The catalogue's
   *expected* decisions are therefore measured, not hoped for. A case the seed cannot
   produce is reported as missing, never faked;
6. writes the demo configuration: keys, operator registry, an API key and ``demo.env``.

Everything is SYNTHETIC. Nothing here is evidence of real-world fraud performance.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import numpy as np
from sqlalchemy import select

from fraud_ai import audit
from fraud_ai.core.enums import Decision
from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.migrations import upgrade
from fraud_ai.database.models import ModelVersion, User
from fraud_ai.demo.guard import MARKER
from fraud_ai.risk.policy import Band
from fraud_ai.security.hashing import Pseudonymiser

SEED = 20260701
USERS = 360
REFERENCE = datetime(2026, 7, 1, tzinfo=UTC)
PRIMARY, SHADOW = "gradient-boosting-1.0.0", "logistic-regression-1.0.0"
POLICY, SHADOW_POLICY = "risk-policy-1.0.0", "risk-policy-1.1.0"
LEGITIMATE = {"normal", "legitimate_vpn", "shared_network", "new_home_address",
              "new_customer", "legitimate_lookalike", "suspicious_velocity"}  # fmt: skip
RESTRICTIVE = {
    Decision.STEP_UP_AUTHENTICATION.value,
    Decision.MANUAL_REVIEW.value,
    Decision.TEMPORARY_BLOCK.value,
}
# (lower bound of the calibrated score, risk level, decision): DEMO ONLY, see build_world.
DEMO_BANDS = (
    (0.0, "very_low", Decision.ALLOW),
    (0.02, "moderate", Decision.ALLOW_WITH_MONITORING),
    (0.04, "elevated", Decision.STEP_UP_AUTHENTICATION),
    (0.15, "high", Decision.MANUAL_REVIEW),
    (0.7, "extreme", Decision.TEMPORARY_BLOCK),
)
SCOPES = [
    "score:write",
    "score:replay",
    "signals:trusted",
    "assessment:read",
    "review:read",
    "review:write",
    "policy:read",
    "stepup:write",
    "webauthn:write",
    "investigation:write",
    "metrics:read",
    "analyst:read",
]


@dataclass(frozen=True)
class Case:
    label: str
    title: str
    story: str
    match: Callable[[dict[str, Any]], bool]
    # Used only when nothing matches strictly; the catalogue then says so ("relaxed").
    fallback: Callable[[dict[str, Any]], bool] | None = None


def _txn(row: dict[str, Any]) -> bool:
    return bool(row["event_type"] == "TRANSACTION_CREATED")


CASES: tuple[Case, ...] = (
    Case("normal_purchase", "Normal purchase",
         "A long-standing customer buys as usual: known device, home network.",
         lambda r: r["scenario"] == "normal" and _txn(r) and r["decision"] == "ALLOW"),
    Case("legitimate_vpn", "Legitimate VPN customer",
         "A genuine customer who always shops through a VPN. A VPN is a signal, not proof.",
         lambda r: r["scenario"] == "legitimate_vpn" and _txn(r)
         and r["decision"] not in RESTRICTIVE),
    Case("house_mover", "House mover",
         "A genuine customer ships to a new home address after moving.",
         lambda r: r["scenario"] == "new_home_address" and _txn(r)
         and r["decision"] != "TEMPORARY_BLOCK"),
    Case("large_legitimate", "Large legitimate purchase",
         "An unusually large basket (top 10%) from a genuine customer; any friction it gets "
         "is a false positive, shown as it is.",
         lambda r: r["scenario"] in LEGITIMATE and _txn(r) and r["large"]),
    Case("high_velocity_fraud", "High-velocity fraud",
         "A fraudster buying repeatedly within a day on a new or taken-over account.",
         lambda r: r["scenario"] in {"new_account_fraud", "account_takeover"} and _txn(r)
         and r["decision"] in RESTRICTIVE and r["recent_purchases"] >= 1,
         lambda r: r["scenario"] in {"new_account_fraud", "account_takeover"} and _txn(r)
         and r["recent_purchases"] >= 1),
    Case("account_takeover", "Account takeover",
         "A stolen login from a new device and network, then a purchase.",
         lambda r: r["scenario"] == "account_takeover" and r["decision"] in RESTRICTIVE),
    Case("stealth_takeover", "Stealth (slow) takeover",
         "An attacker who changes little at a time. Shown as scored, even if it is missed.",
         lambda r: r["scenario"] == "slow_account_takeover" and _txn(r)),
    Case("manual_review", "Manual review",
         "Uncertain risk: the policy routes the event to an analyst.",
         lambda r: r["decision"] == "MANUAL_REVIEW"),
    Case("step_up_success", "Step-up, then success",
         "Moderate risk: authentication is requested and passes. (If the scenario is a "
         "fraud one, this shows what happens when an attacker can pass step-up too.)",
         lambda r: r["decision"] == "STEP_UP_AUTHENTICATION" and r["scenario"] in LEGITIMATE,
         lambda r: r["decision"] == "STEP_UP_AUTHENTICATION"),
    Case("step_up_failure", "Step-up, then failure",
         "Moderate risk: authentication is requested and fails.",
         lambda r: r["decision"] == "STEP_UP_AUTHENTICATION"),
)  # fmt: skip


def _users_by_scenario(factory: Any) -> dict[str, str]:
    with factory() as s:
        return {str(u.user_id): u.synthetic_scenario or "" for u in s.scalars(select(User))}


def _score(service: Any, events: list[dict[str, Any]]) -> list[Any]:
    return [service.score_event(e) for e in events]


def _rows(
    events: list[dict[str, Any]], outcomes: list[Any], scenarios: dict[str, str]
) -> list[dict[str, Any]]:
    amounts = [
        float((e.get("metadata") or {}).get("amount") or 0)
        for e in events
        if e["event_type"] == "TRANSACTION_CREATED"
    ]
    large = float(np.percentile(amounts, 90)) if amounts else float("inf")
    rows = []
    purchases: dict[str, list[datetime]] = {}
    for i, (event, outcome) in enumerate(zip(events, outcomes, strict=True)):
        reasons = list(outcome.reason_codes or [])
        user = str(event.get("user_id"))
        at = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
        recent = [t for t in purchases.get(user, []) if at - t <= timedelta(hours=24)]
        if event["event_type"] == "TRANSACTION_CREATED":
            purchases.setdefault(user, []).append(at)
        rows.append(
            {
                "index": i,
                "event": event,
                "user": str(event.get("user_id")),
                "scenario": scenarios.get(str(event.get("user_id")), ""),
                "event_type": event["event_type"],
                "decision": outcome.decision.value if outcome.decision else None,
                "reasons": reasons,
                "large": float((event.get("metadata") or {}).get("amount") or 0) >= large,
                "recent_purchases": len(recent),
            }
        )
    return rows


def _copy(root: Path, name: str) -> tuple[Any, Any]:
    target = root / f"{name}.db"
    shutil.copy(root / "fraud_ai_demo.db", target)
    engine = create_db_engine(f"sqlite:///{target}")
    return engine, make_session_factory(engine)


def build_world(
    root: Path, *, users: int = USERS, echo: Callable[[str], None] = print
) -> dict[str, Any]:
    """(Re)create the demo world under ``root``. The caller has run the demo guard."""
    import logging

    from fraud_ai.data.seed import seed_with_live_holdout
    from fraud_ai.models.signing import sign_model
    from fraud_ai.models.training import TrainingConfig, run_training
    from fraud_ai.realtime.service import FraudScoringService
    from fraud_ai.risk.offline import propose_policy
    from fraud_ai.risk.registry import activate, create_policy
    from fraud_ai.service.keys import create_key, signing_secret
    from fraud_ai.trust import keys as tk

    logging.getLogger("fraud_ai.realtime").setLevel(logging.WARNING)  # thousands of events
    root.mkdir(parents=True, exist_ok=True)
    for stale in ("fraud_ai_demo.db", "scratch.db", "verify.db"):
        (root / stale).unlink(missing_ok=True)
    for directory in ("models", "anchors"):
        shutil.rmtree(root / directory, ignore_errors=True)
    config = _demo_config(root)
    url = f"sqlite:///{root / 'fraud_ai_demo.db'}"
    upgrade(url)
    engine = create_db_engine(url)
    factory = make_session_factory(engine)
    pseudo = Pseudonymiser(config["PSEUDONYMISATION_KEY"].encode())
    with session_scope(factory) as s:
        audit.record(s, MARKER, actor="cli:demo", target_type="demo",
                     details={"seed": SEED, "users": users, "synthetic": True})  # fmt: skip
    echo(f"seeding {users} synthetic users (seed {SEED}) ...")
    with session_scope(factory) as s:
        holdout = seed_with_live_holdout(
            s, pseudo, n_users=users, seed=SEED, reference_time=REFERENCE,
            activity_days=60, live_days=8, fraud_multiplier=2.5, late_fraction=0.0,
        )  # fmt: skip
    echo("training gradient boosting and logistic regression (fixed seeds) ...")
    training = TrainingConfig(
        maturity=timedelta(days=14),
        seed=SEED,
        hyperparameters={"gradient-boosting": {"max_iter": 120}},
    )  # fmt: skip
    with session_scope(factory) as s:
        run_training(s, ["gradient-boosting", "logistic"], training, root / "models")
    model_key = tk.load_private_key(root / "keys" / "model.pem")
    with session_scope(factory) as s:
        for model in s.scalars(select(ModelVersion)):
            sign_model(s, model, model_key, actor="cli:demo")
    with session_scope(factory) as s:
        first = propose_policy(s, POLICY, primary=PRIMARY)
        # DEMO ONLY: hand-set bands so that every decision type can be shown. Staging and
        # the evaluation use bands DERIVED from validation data (propose_policy).
        definition = first.definition.model_copy(
            update={
                "bands": tuple(
                    Band(lower=lower, risk_level=level, decision=decision)
                    for lower, level, decision in DEMO_BANDS
                ),
                "description": "DEMO policy: hand-set bands for illustration (synthetic)",
            }
        )
        derivation = {**first.derivation, "demo_bands": "hand-set for the demo, not derived"}
        create_policy(s, definition, derivation=derivation)
        second = propose_policy(s, SHADOW_POLICY, primary=PRIMARY, monitor_recall=0.8)
        create_policy(s, second.definition, derivation=second.derivation)
        activate(s, POLICY, shadow_models=[SHADOW], shadow_policies=[SHADOW_POLICY],
                 note="demo world (synthetic)", activated_by="cli:demo")  # fmt: skip
    live = list(holdout.events)
    cut = int(len(live) * 0.5)
    background, rest = live[:cut], live[cut:]
    echo(f"scoring {len(background)} background live events ...")
    service = FraudScoringService(factory, pseudo, replay=True)
    _score(service, background)
    scenarios = _users_by_scenario(factory)

    # Selection pass (scratch copy): what the remaining stream would produce.
    scratch_engine, scratch_factory = _copy(root, "scratch")
    rows = _rows(
        rest, _score(FraudScoringService(scratch_factory, pseudo, replay=True), rest), scenarios
    )
    scratch_engine.dispose()
    chosen: list[tuple[Case, dict[str, Any]]] = []
    used_users: set[str] = set()
    relaxed: set[str] = set()
    for case in CASES:
        row = next((r for r in rows if r["user"] not in used_users and case.match(r)), None)
        if row is None and case.fallback is not None:
            row = next((r for r in rows if r["user"] not in used_users and case.fallback(r)), None)
            if row is not None:
                relaxed.add(case.label)
        if row is not None:
            used_users.add(row["user"])
            chosen.append((case, row))
    # Verification pass: exactly the walkthrough order (each case's earlier same-user events
    # first), on a fresh copy. These measured decisions are the catalogue's expectations.
    verify_engine, verify_factory = _copy(root, "verify")
    verifier = FraudScoringService(verify_factory, pseudo, replay=True)
    catalogue = []
    for case, row in chosen:
        prelude = [r["event"] for r in rows[: row["index"]] if r["user"] == row["user"]]
        _score(verifier, prelude)
        outcome = verifier.score_event(row["event"])
        catalogue.append(
            {
                "label": case.label,
                "title": case.title,
                "story": case.story,
                "scenario": row["scenario"],
                "prelude": prelude,
                "event": row["event"],
                "expected_decision": outcome.decision.value if outcome.decision else outcome.status,
                "expected_reasons": list(outcome.reason_codes or []),
                "relaxed_match": case.label in relaxed,
            }
        )
    verify_engine.dispose()
    for leftover in ("scratch.db", "verify.db"):
        (root / leftover).unlink(missing_ok=True)
    missing = [c.label for c in CASES if c.label not in {x["label"] for x in catalogue}]
    stats: dict[str, dict[str, int]] = {}
    for r in rows:
        if r["decision"]:
            per = stats.setdefault(r["scenario"], {})
            per[r["decision"]] = per.get(r["decision"], 0) + 1

    # Demo API key and its request-signing secret (demo only; printed by `demo start`).
    with session_scope(factory) as s:
        issued = create_key(s, "demo-walkthrough", SCOPES)
    credentials = {
        "credential": issued.credential,
        "signing_secret": signing_secret(config["SERVICE_SIGNING_MASTER_KEY"], issued.key_id),
    }
    _write_private(root / "demo-credentials.json", json.dumps(credentials, indent=2))
    engine.dispose()
    document = {
        "synthetic": True,
        "seed": SEED,
        "users": users,
        "reference_time": REFERENCE.isoformat(),
        "cases": catalogue,
        "missing_cases": missing,
        "selection_pass_decisions": stats,
        "note": "SYNTHETIC demo data. Expected decisions were measured by re-scoring in the "
        "walkthrough's order; they are not claims about real-world fraud performance.",
    }
    (root / "catalogue.json").write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    echo(f"demo world ready: {len(catalogue)}/{len(CASES)} cases"
         + (f" (missing: {', '.join(missing)})" if missing else ""))  # fmt: skip
    return document


def _write_private(path: Path, text: str) -> None:
    path.unlink(missing_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(text + "\n")


def _demo_config(root: Path) -> dict[str, str]:
    """Demo keys, operator registry and ``demo.env`` (created once, reused by resets)."""
    from fraud_ai.trust import keys as tk

    keys = root / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    os.chmod(keys, 0o700)
    public: dict[str, str] = {}
    for purpose in ("model", "audit", "release"):
        path = keys / f"{purpose}.pem"
        if not path.exists():
            tk.write_private_key(tk.generate(), path)
        public[purpose] = tk.encode_public(tk.load_private_key(path).public)
    roles = {"alice": "policy_approver", "bob": "policy_approver", "carol": "policy_activator",
             "rita": "reviewer", "sec": "security_admin"}  # fmt: skip
    entries = []
    for operator, role in roles.items():
        path = keys / f"operator-{operator}.pem"
        if not path.exists():
            tk.write_private_key(tk.generate(), path)
        key = tk.encode_public(tk.load_private_key(path).public)
        entries.append({"id": operator, "roles": [role], "public_keys": [key]})
    (root / "operators.json").write_text(json.dumps({"version": 1, "operators": entries}, indent=2))
    env_file = root / "demo.env"
    existing: dict[str, str] = {}
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                existing[k] = v
    config = {
        "DEMO_MODE": "true",
        "ENVIRONMENT": "development",
        "DATABASE_URL": f"sqlite:///{(root / 'fraud_ai_demo.db').resolve()}",
        "MODEL_DIRECTORY": str((root / "models").resolve()),
        "PSEUDONYMISATION_KEY": existing.get("PSEUDONYMISATION_KEY") or secrets.token_urlsafe(32),
        "SERVICE_SIGNING_MASTER_KEY": existing.get("SERVICE_SIGNING_MASTER_KEY")
        or secrets.token_urlsafe(32),
        "PAYMENT_AUTH_WEBHOOK_SECRET": existing.get("PAYMENT_AUTH_WEBHOOK_SECRET")
        or secrets.token_urlsafe(32),
        "PAYMENT_AUTH_PROVIDER": "fake",
        "SERVICE_REQUIRE_SIGNATURES": "true",
        "SIGNATURE_MIN_VERSION": "v2",
        "MODEL_SIGNATURES_REQUIRED": "true",
        "MODEL_SIGNING_PUBLIC_KEYS": public["model"],
        "AUDIT_ANCHOR_PUBLIC_KEYS": public["audit"],
        "AUDIT_ANCHOR_PRIVATE_KEY_FILE": str((keys / "audit.pem").resolve()),
        "AUDIT_ANCHOR_DIRECTORY": str((root / "anchors").resolve()),
        "RELEASE_SIGNING_PUBLIC_KEYS": public["release"],
        "MODEL_SIGNING_PRIVATE_KEY_FILE": str((keys / "model.pem").resolve()),
        "RELEASE_SIGNING_PRIVATE_KEY_FILE": str((keys / "release.pem").resolve()),
        "OPERATOR_AUTH_REQUIRED": "true",
        "OPERATOR_REGISTRY_FILE": str((root / "operators.json").resolve()),
        "POLICY_APPROVALS_REQUIRED": "2",
        "LOCAL_LLM_RUNTIME": existing.get("LOCAL_LLM_RUNTIME", "reference"),
        "RATE_LIMIT": "6000/minute",
        "RATE_LIMIT_BURST": "1000",
        "WEBAUTHN_RP_ID": "localhost",
        "WEBAUTHN_ORIGIN": "http://localhost:8080",
    }
    for key in ("LOCAL_LLM_MODEL", "LOCAL_LLM_ENDPOINT"):
        if existing.get(key):
            config[key] = existing[key]
    lines = ["# fraud-ai DEMO configuration (synthetic data only; demo secrets only)"]
    lines += [f"{k}={v}" for k, v in config.items()]
    _write_private(env_file, "\n".join(lines))
    return config


def load_env(root: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in (root / "demo.env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            env[k] = v
    return env
