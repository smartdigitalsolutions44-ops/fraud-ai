"""A shared Stage 8 test world.

It contains synthetic history, a held-out live stream, trained models, two policies and an
active deployment. Each test gets its own copy of it."""

from __future__ import annotations

import json
import shutil
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from fraud_ai.data.seed import seed_with_live_holdout
from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.models.training import run_training
from fraud_ai.realtime.service import FraudScoringService, ScoringOutcome
from fraud_ai.risk.offline import propose_policy
from fraud_ai.risk.registry import activate, create_policy
from fraud_ai.security.hashing import Pseudonymiser
from tests.conftest import TEST_KEY, fast_training_config

REF = datetime(2026, 7, 1, tzinfo=UTC)
GB, GRU, LR = "gradient-boosting-1.0.0", "gru-1.0.0", "logistic-regression-1.0.0"
P1, P2 = "risk-policy-1.0.0", "risk-policy-1.1.0"
PSEUDO = Pseudonymiser(TEST_KEY.encode())


def build_world(root: Path, template: Path) -> Path:
    shutil.copy(template, root / "w.db")
    engine = create_db_engine(f"sqlite:///{root / 'w.db'}")
    factory = make_session_factory(engine)
    with session_scope(factory) as s:
        holdout = seed_with_live_holdout(
            s,
            PSEUDO,
            n_users=80,
            seed=13,
            reference_time=REF,
            activity_days=120,
            live_days=7,
            fraud_multiplier=2.0,
            late_fraction=0.05,
        )
    (root / "live.jsonl").write_text("".join(json.dumps(e) + "\n" for e in holdout.events))
    with session_scope(factory) as s:
        run_training(
            s, ["gradient-boosting", "gru", "logistic"], fast_training_config(), root / "models"
        )
    with session_scope(factory) as s:
        first = propose_policy(s, P1, primary=GB, sequence=GRU)
        create_policy(s, first.definition, derivation=first.derivation)
        second = propose_policy(s, P2, primary=GB, monitor_recall=0.8)
        create_policy(s, second.definition, derivation=second.derivation)
        activate(s, P1, shadow_models=[LR], shadow_policies=[P2], note="test world")
    engine.dispose()
    return root


@dataclass
class World:
    root: Path
    engine: Engine
    factory: sessionmaker[Session]
    events: list[dict[str, Any]]
    services: list[FraudScoringService] = field(default_factory=list)

    @property
    def url(self) -> str:
        return f"sqlite:///{self.root / 'w.db'}"

    def service(self, **kwargs: Any) -> FraudScoringService:
        kwargs.setdefault("replay", True)
        svc = FraudScoringService(self.factory, PSEUDO, **kwargs)
        self.services.append(svc)
        return svc

    def session(self) -> Session:
        return self.factory()

    def sql(self, statement: str, **params: Any) -> Any:
        with self.engine.begin() as conn:
            return conn.execute(text(statement), params)

    def transactions(self) -> list[dict[str, Any]]:
        return [e for e in self.events if e["event_type"] == "TRANSACTION_CREATED"]

    def replay_until(
        self, service: FraudScoringService, decisions: int = 1
    ) -> tuple[list[ScoringOutcome], int]:
        """Replay live events in arrival order until ``decisions`` assessments exist.
        Returns the outcomes and the index of the next unprocessed event."""
        outcomes: list[ScoringOutcome] = []
        decided = 0
        for i, e in enumerate(self.events):
            outcome = service.score_event(e)
            outcomes.append(outcome)
            if outcome.status == "decided":
                decided += 1
                if decided >= decisions:
                    return outcomes, i + 1
        return outcomes, len(self.events)


def copy_world(world: Path, dest: Path) -> World:
    shutil.copy(world / "w.db", dest / "w.db")
    shutil.copytree(world / "models", dest / "models")
    engine = create_db_engine(f"sqlite:///{dest / 'w.db'}")
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE model_versions SET model_path = replace(model_path, :old, :new)"),
            {"old": str(world / "models"), "new": str(dest / "models")},
        )
    events = [json.loads(line) for line in (world / "live.jsonl").read_text().splitlines()]
    shutil.copy(world / "live.jsonl", dest / "live.jsonl")
    return World(dest, engine, make_session_factory(engine), events)


def open_world(world: Path, dest: Path) -> Iterator[World]:
    w = copy_world(world, dest)
    try:
        yield w
    finally:
        w.engine.dispose()
