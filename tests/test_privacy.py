"""Stage 11 privacy tooling: free-text PII rules, the inventory, the erasure plan (dry run)
and the core retention classes."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from fraud_ai.cli.main import cli
from fraud_ai.config.settings import Settings, get_settings
from fraud_ai.core.enums import EventType, FraudType
from fraud_ai.database.base import Base
from fraud_ai.database.engine import session_scope
from fraud_ai.database.models import (
    EventRecord,
    NetworkEvent,
    NetworkIdentity,
    ReviewItem,
    ReviewOutcome,
    SecurityEvent,
    User,
)
from fraud_ai.ingestion.processor import EventProcessor
from fraud_ai.privacy import freetext
from fraud_ai.privacy.inventory import INVENTORY, check_inventory, erasure_plan
from fraud_ai.retention import RetentionError, plan, run
from fraud_ai.service.keys import ServiceKeyError, create_key
from tests.conftest import T0, create_user, make_event
from tests.realtime_world import REF, World, open_world

SAMPLE = (
    "customer bob.smith@example.com rang from +44 20 7946 0958, IP 203.0.113.9 / 2001:db8::1,"
    " card 4111 1111 1111 1111, key sk_test_abcdefgh12345678, password=hunter2"
)

# Card numbers never reach storage: the event contract refuses them outright (Stage 1).
NO_CARD = SAMPLE.replace(" card 4111 1111 1111 1111,", "")


def test_card_numbers_in_event_text_are_refused_not_sanitised() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="forbidden sensitive data"):
        make_event(
            EventType.FRAUD_CONFIRMED,
            uuid.uuid4(), {"fraud_type": "account_takeover",
                                                     "notes": SAMPLE})  # fmt: skip


# ------------------------------------------------------------------ detection
def test_detect_and_sanitise() -> None:
    assert freetext.detect(SAMPLE) == [
        "IP address",
        "card number",
        "email address",
        "phone number",
        "secret",
    ]
    clean, kinds = freetext.sanitise(SAMPLE)
    for leaked in ("bob.smith", "7946", "203.0.113.9", "2001:db8", "4111", "sk_test", "hunter2"):
        assert leaked not in clean
    assert "[EMAIL]" in clean and "[IP]" in clean and "[CARD]" in clean and "[SECRET]" in clean
    assert len(kinds) == 5


@pytest.mark.parametrize(
    "text",
    [
        "refund approved after call about order 12345",
        "amount 12.34 GBP on 2026-07-01 at 10:15",
        "ref ev-0123456789abcdef",
        "version 1.2.3 of the checkout",
        "seen 3 times in 24h",
    ],
)
def test_ordinary_text_is_not_flagged(text: str) -> None:
    assert freetext.detect(text) == []
    assert freetext.sanitise(text)[0] == text


def test_rules_per_field() -> None:
    with pytest.raises(freetext.FreeTextError) as err:
        freetext.check("policy.approval_note", "approved, call me on +44 20 7946 0958")
    assert err.value.kinds == ["phone number"]
    with pytest.raises(freetext.FreeTextError, match="limited to 500"):
        freetext.check("review.note", "x" * 501)
    # Merchant event text is sanitised rather than refused (the label is not lost).
    assert freetext.check("event.fraud_confirmed.notes", SAMPLE) == freetext.sanitise(SAMPLE)[0]
    assert all(
        f.max_length > 0 and f.rule in ("reject", "sanitise") for f in freetext.FREE_TEXT_FIELDS
    )


def test_ingested_fraud_notes_are_sanitised(processor: EventProcessor, session: Session) -> None:
    uid = create_user(processor, net={"ip": "198.51.100.23", "country": "GB"})
    event = make_event(
        EventType.FRAUD_CONFIRMED,
        uid,
        {"fraud_type": FraudType.ACCOUNT_TAKEOVER.value, "notes": NO_CARD},
        ts=T0 + timedelta(hours=1),
    )
    processor.process(event)
    session.flush()
    stored = session.get(EventRecord, event.event_id)
    assert stored is not None
    notes = stored.metadata_json["notes"]
    assert "bob.smith" not in notes and "[EMAIL]" in notes and "[PHONE]" in notes
    assert "203.0.113.9" not in notes and "hunter2" not in notes
    # The structured network IP of the account-creation event is hashed, not "sanitised".
    created = session.scalar(
        select(EventRecord).where(
            EventRecord.user_id == uid, EventRecord.event_type == EventType.ACCOUNT_CREATED
        )
    )
    assert created is not None and "ip_hash" in created.metadata_json["network"]
    assert "[IP]" not in str(created.metadata_json)


def test_operator_inputs_refuse_pii(session: Session) -> None:
    with pytest.raises(ServiceKeyError, match="email address"):
        create_key(session, "checkout for bob@example.com", ["score:write"])
    assert create_key(session, "checkout-backend", ["score:write"]).credential


# ------------------------------------------------------------------ inventory / erasure
def test_inventory_matches_the_schema() -> None:
    assert check_inventory() == []
    tables = {i.table for i in INVENTORY}
    for personal in ("users", "events", "network_identities", "addresses", "payment_methods",
                     "risk_assessments", "review_outcomes", "webauthn_credentials"):  # fmt: skip
        assert personal in tables
    assert all(i.purpose and i.retention and i.deletion for i in INVENTORY)


@pytest.fixture
def w(realtime_world_dir: Path, tmp_path: Path) -> Iterator[World]:
    yield from open_world(realtime_world_dir, tmp_path)


def _all_counts(s: Session) -> dict[str, int]:
    return {
        name: int(s.scalar(select(func.count()).select_from(table)) or 0)
        for name, table in Base.metadata.tables.items()
    }


def test_erasure_plan_is_a_dry_run(w: World) -> None:
    svc = w.service()
    w.replay_until(svc, decisions=5)
    with w.session() as s:
        user = s.scalar(
            select(User).join(EventRecord, EventRecord.user_id == User.user_id).limit(1)
        )
        assert user is not None
        before = _all_counts(s)
        report = erasure_plan(s, user.external_ref)
        assert _all_counts(s) == before  # nothing changed
    assert report["found"] and report["dry_run"]
    actions = {(step["table"], step["action"]) for step in report["steps"]}
    assert ("users", "pseudonymise") in actions
    assert ("events", "must_remain") in actions
    assert any(t == "risk_assessments" and a == "must_remain" for t, a in actions) or not any(
        t == "risk_assessments" for t, _ in actions
    )
    assert "events.user_id -> users.user_id" in report["dependencies"]
    with w.session() as s:
        assert erasure_plan(s, "no-such-user")["found"] is False
        by_id = erasure_plan(s, str(user.user_id))
        assert by_id["user_id"] == str(user.user_id)


def test_privacy_cli(w: World) -> None:
    def run_cli(*args: str) -> Any:
        get_settings.cache_clear()
        try:
            return CliRunner().invoke(cli, list(args), env={"DATABASE_URL": w.url})
        finally:
            get_settings.cache_clear()

    inv = run_cli("privacy", "inventory")
    assert inv.exit_code == 0 and "network_identities.ip_address" in inv.output
    assert '"deletion"' in run_cli("privacy", "inventory", "--format", "json").output
    with w.session() as s:
        ref = s.scalar(select(User.external_ref).limit(1))
    plan_out = run_cli("privacy", "erasure-plan", str(ref))
    assert plan_out.exit_code == 0 and "DRY RUN" in plan_out.output
    assert "must remain" in plan_out.output
    assert run_cli("privacy", "erasure-plan", "missing").exit_code != 0


# ------------------------------------------------------------------ core retention classes
def test_core_retention_classes(w: World) -> None:
    svc = w.service()
    w.replay_until(svc, decisions=40)
    from fraud_ai.core.enums import ReviewResolution
    from fraud_ai.realtime.review import resolve

    with session_scope(w.factory) as s:
        item = s.scalar(select(ReviewItem).limit(1))
        assert item is not None
        resolve(s, item.review_id, ReviewResolution.LEGITIMATE, note="checked the order history",
                now=REF)  # fmt: skip
    later = REF + timedelta(days=400)
    with pytest.raises(ValueError, match="at least 180"):
        Settings(retention_network_observation_days=30)
    settings = Settings(
        retention_network_observation_days=180,
        retention_request_metadata_days=30,
        retention_review_note_days=30,
        retention_investigation_days=30,
    )
    with w.session() as s:
        planned = {p.name: p for p in plan(s, settings, now=later)}
        network_before = s.scalar(select(func.count()).select_from(NetworkEvent))
        identities = s.scalar(select(func.count()).select_from(NetworkIdentity))
        events_before = s.scalar(select(func.count()).select_from(EventRecord))
    assert planned["network_observations"].rows == network_before and network_before
    assert planned["review_notes"].rows == 1
    with session_scope(w.factory) as s:
        done = run(s, settings, execute=True, confirmed=True, actor="cli:test", now=later)
    assert done["applied"]["network_observations"] == network_before
    assert done["applied"]["review_notes"] == 1
    with w.session() as s:
        assert s.scalar(select(func.count()).select_from(NetworkEvent)) == 0
        assert s.scalar(select(func.count()).select_from(NetworkIdentity)) == identities
        assert s.scalar(select(func.count()).select_from(EventRecord)) == events_before
        outcome = s.scalar(select(ReviewOutcome))
        assert outcome is not None and outcome.note is None and outcome.resolution
        assert all(e.details == {} for e in s.scalars(select(SecurityEvent)))


def test_retention_refuses_protected_tables(monkeypatch: pytest.MonkeyPatch, w: World) -> None:
    import fraud_ai.retention as retention
    from fraud_ai.database.models import RiskAssessment

    rogue = retention.Category(
        "rogue", "x", "delete", lambda s: 1.0, lambda now, d: RiskAssessment.assessed_at < now,
        RiskAssessment,
    )  # fmt: skip
    monkeypatch.setattr(retention, "CATEGORIES", (rogue,))
    w.replay_until(w.service(), decisions=1)
    with pytest.raises(RetentionError, match="protected"), session_scope(w.factory) as s:
        run(s, Settings(), execute=True, confirmed=True, actor="t", now=REF + timedelta(days=9))
