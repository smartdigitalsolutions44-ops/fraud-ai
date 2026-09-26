from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Engine, func, select, update
from sqlalchemy.exc import IntegrityError

from fraud_ai.database.engine import make_session_factory
from fraud_ai.database.models import FeatureSnapshot
from fraud_ai.features.extractor import extract_features
from fraud_ai.features.snapshot import (
    SnapshotDriftError,
    SnapshotIntegrityError,
    load_vector,
    persist_snapshot,
    snapshot_features,
    verify_snapshots,
)
from fraud_ai.ingestion.processor import EventProcessor
from fraud_ai.security.hashing import Pseudonymiser
from tests.conftest import TEST_KEY
from tests.feature_helpers import VPN, Scenario

T = datetime(2026, 5, 1, 9, 30, tzinfo=UTC)


@pytest.fixture
def sc(any_engine: Engine) -> Scenario:
    session = make_session_factory(any_engine)()
    return Scenario(session, EventProcessor(session, Pseudonymiser(TEST_KEY.encode())))


def _setup(sc: Scenario):  # type: ignore[no-untyped-def]
    uid = sc.user(T - timedelta(days=60))
    pm = sc.payment_method(uid, T - timedelta(days=60), fingerprint="fp")
    sc.purchase(uid, T - timedelta(days=3), "12.34", pm=pm)
    sc.login(uid, T - timedelta(minutes=2), network=VPN)
    event, _ = sc.purchase(uid, T, "56.78", pm=pm, network=VPN)
    sc.session.flush()
    return uid, event


def test_snapshot_round_trip_and_idempotence(sc: Scenario) -> None:
    _, event = _setup(sc)
    snap = snapshot_features(sc.session, event.event_id)
    assert snap.feature_version == "fraud-features-1.0.0" and len(snap.feature_hash) == 64
    assert snap.as_of_timestamp == T and snap.transaction_id is not None
    assert snap.source_event_count > 0
    sc.session.commit()
    sc.session.expire_all()
    stored = sc.session.get(FeatureSnapshot, snap.snapshot_id)
    assert stored is not None
    vector = load_vector(stored, T)  # JSON/JSONB round trip preserves the exact hash
    assert vector.feature_hash == stored.feature_hash
    assert vector == extract_features(sc.session, event.event_id)
    again = snapshot_features(sc.session, event.event_id)
    assert again.snapshot_id == snap.snapshot_id  # idempotent
    assert sc.session.scalar(select(func.count()).select_from(FeatureSnapshot)) == 1
    later = snapshot_features(sc.session, event.event_id, T + timedelta(days=1))
    assert later.snapshot_id != snap.snapshot_id  # different as_of = different snapshot
    sc.session.rollback()


def test_unique_constraint_at_database_level(sc: Scenario) -> None:
    _, event = _setup(sc)
    snap = snapshot_features(sc.session, event.event_id)
    sc.session.add(
        FeatureSnapshot(
            event_id=snap.event_id,
            feature_version=snap.feature_version,
            as_of_timestamp=snap.as_of_timestamp,
            features=snap.features,
            feature_hash=snap.feature_hash,
            source_event_count=0,
        )
    )
    with pytest.raises(IntegrityError):
        sc.session.flush()
    sc.session.rollback()


def test_drift_is_detected_never_overwritten(sc: Scenario) -> None:
    uid, event = _setup(sc)
    snap = snapshot_features(sc.session, event.event_id)
    original = snap.feature_hash
    # Late-arriving history *before* the event changes the correct vector: this is drift
    # relative to what was stored (and what a model may already have scored).
    sc.login(uid, T - timedelta(minutes=1), ok=False)
    sc.session.flush()
    with pytest.raises(SnapshotDriftError, match="stored hash"):
        snapshot_features(sc.session, event.event_id)
    assert sc.session.get(FeatureSnapshot, snap.snapshot_id).feature_hash == original  # type: ignore[union-attr]
    [check] = verify_snapshots(sc.session, [snap])
    assert not check.ok and check.problem and "failed_logins" in check.problem
    sc.session.rollback()


def test_tampering_is_detected(sc: Scenario) -> None:
    _, event = _setup(sc)
    snap = snapshot_features(sc.session, event.event_id)
    tampered = dict(snap.features)
    tampered["values"] = {**tampered["values"], "transaction_amount_minor_units": 1}
    sc.session.execute(
        update(FeatureSnapshot)
        .where(FeatureSnapshot.snapshot_id == snap.snapshot_id)
        .values(features=tampered)
    )
    sc.session.expire_all()
    stored = sc.session.get(FeatureSnapshot, snap.snapshot_id)
    assert stored is not None
    with pytest.raises(SnapshotIntegrityError):
        load_vector(stored, T)
    [check] = verify_snapshots(sc.session, [stored])
    assert not check.ok and "does not match" in (check.problem or "")
    sc.session.rollback()


def test_verify_reports_ok(sc: Scenario) -> None:
    _, event = _setup(sc)
    snap = snapshot_features(sc.session, event.event_id)
    [check] = verify_snapshots(sc.session, [snap])
    assert check.ok and check.problem is None
    assert persist_snapshot(sc.session, extract_features(sc.session, event.event_id)) is snap
    sc.session.rollback()


def test_determinism_across_backends(any_engine: Engine, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The same events produce byte-identical vectors on SQLite and PostgreSQL."""
    from fraud_ai.database.engine import create_db_engine
    from fraud_ai.database.migrations import upgrade

    ref_url = f"sqlite:///{tmp_path / 'ref.db'}"
    upgrade(ref_url)
    ref_engine = create_db_engine(ref_url)
    hashes = []
    for engine in (any_engine, ref_engine):
        session = make_session_factory(engine)()
        scenario = Scenario(session, EventProcessor(session, Pseudonymiser(TEST_KEY.encode())))
        from uuid import UUID

        uid = UUID("11111111-1111-4111-8111-111111111111")
        from fraud_ai.core.enums import EventType

        scenario.emit(
            EventType.ACCOUNT_CREATED,
            T - timedelta(days=9),
            uid,
            {"external_ref": "fixed", "network": VPN},
        )
        for i in range(5):
            scenario.purchase(uid, T - timedelta(days=i + 1), f"{i + 1}.33", network=VPN)
        event, _ = scenario.purchase(uid, T, "7.77", network=VPN)
        hashes.append(scenario.features(event).canonical_json())
        session.rollback()
        session.close()
    ref_engine.dispose()
    assert hashes[0] == hashes[1]
