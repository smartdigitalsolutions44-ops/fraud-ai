#!/usr/bin/env python
"""Bootstrap a SYNTHETIC deployment world (staging stack, container smoke test).

Seeds synthetic history plus a held-out live stream, trains the requested models (fast
settings), creates two policies and makes the **first** deployment. The first deployment
has nothing to shadow, so it is the documented bootstrap exception to promotion and
approval. Later policies go through ``fraud-ai policy promote`` and ``policy approve``.

    python scripts/bootstrap_world.py --models /models --kinds gradient-boosting,gru,logistic

Uses DATABASE_URL, PSEUDONYMISATION_KEY and MODEL_DIRECTORY from the environment (settings).
Writes ``<models>/live.jsonl`` (the synthetic live stream).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fraud_ai.config.settings import get_settings
from fraud_ai.data.seed import seed_with_live_holdout
from fraud_ai.database.engine import engine_from_settings, make_session_factory, session_scope
from fraud_ai.models.training import TrainingConfig, run_training
from fraud_ai.risk.offline import propose_policy
from fraud_ai.risk.registry import activate, create_policy
from fraud_ai.security.hashing import Pseudonymiser

FAST = {
    "gradient-boosting": {"max_iter": 80},
    "gru": {"hidden_size": 16, "max_epochs": 6, "patience": 3},
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--models", type=Path, required=True)
    parser.add_argument("--kinds", default="gradient-boosting,logistic")
    parser.add_argument("--users", type=int, default=80)
    parser.add_argument("--activity-days", type=int, default=120)
    parser.add_argument("--live-days", type=int, default=7)
    parser.add_argument(
        "--sign-key",
        type=Path,
        default=None,
        help="Ed25519 model key: sign every trained model before the policies are proposed "
        "(needed where MODEL_SIGNATURES_REQUIRED is on)",
    )
    parser.add_argument(
        "--sign-with-provider",
        action="store_true",
        help="Stage 12: sign with the configured key provider (e.g. Vault transit) instead",
    )
    args = parser.parse_args()
    kinds = [k.strip() for k in args.kinds.split(",") if k.strip()]
    settings = get_settings()
    factory = make_session_factory(engine_from_settings(settings))
    assert settings.pseudonymisation_key is not None
    pseudo = Pseudonymiser(settings.pseudonymisation_key.get_secret_value().encode())
    with session_scope(factory) as s:
        holdout = seed_with_live_holdout(
            s,
            pseudo,
            n_users=args.users,
            seed=13,
            reference_time=datetime(2026, 7, 1, tzinfo=UTC),
            activity_days=args.activity_days,
            live_days=args.live_days,
            fraud_multiplier=2.0,
            late_fraction=0.05,
        )
    args.models.mkdir(parents=True, exist_ok=True)
    (args.models / "live.jsonl").write_text("".join(json.dumps(e) + "\n" for e in holdout.events))
    config = TrainingConfig(maturity=timedelta(days=14), hyperparameters=FAST)
    with session_scope(factory) as s:
        run_training(s, kinds, config, args.models)
    if args.sign_key is not None or args.sign_with_provider:
        from sqlalchemy import select

        from fraud_ai.database.models import ModelVersion
        from fraud_ai.models.signing import sign_model
        from fraud_ai.trust.kms import signer_for

        pair = signer_for(settings, "model", key_file=args.sign_key)
        with session_scope(factory) as s:
            for model in s.scalars(select(ModelVersion)):
                sign_model(s, model, pair, actor="cli:bootstrap")
    sequence = "gru-1.0.0" if "gru" in kinds else None
    shadow = ["logistic-regression-1.0.0"] if "logistic" in kinds else []
    with session_scope(factory) as s:
        first = propose_policy(s, "risk-policy-1.0.0", primary="gradient-boosting-1.0.0",
                               sequence=sequence)  # fmt: skip
        create_policy(s, first.definition, derivation=first.derivation)
        second = propose_policy(
            s, "risk-policy-1.1.0", primary="gradient-boosting-1.0.0", monitor_recall=0.8
        )
        create_policy(s, second.definition, derivation=second.derivation)
        activate(
            s,
            "risk-policy-1.0.0",
            shadow_models=shadow,
            shadow_policies=["risk-policy-1.1.0"],
            note="bootstrap (synthetic)",
            activated_by="cli:bootstrap",
        )
    print(f"bootstrapped: models {kinds}, policies risk-policy-1.0.0 (active) / 1.1.0 (shadow)")


if __name__ == "__main__":
    main()
