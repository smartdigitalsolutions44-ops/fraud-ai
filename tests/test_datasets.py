from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from fraud_ai.core.enums import FraudType, LabelSource, LabelValue
from fraud_ai.database.repositories import record_label
from fraud_ai.datasets.builder import DatasetBuildError, TrainingDatasetBuilder
from fraud_ai.datasets.labels import LabelAvailabilityPolicy, LabelStatus
from fraud_ai.features.batch import extract_training_features, scorable_event_ids
from fraud_ai.features.definitions import EventKind, get_feature_set
from fraud_ai.ingestion.processor import EventProcessor
from tests.feature_helpers import Scenario

T = datetime(2026, 3, 1, tzinfo=UTC)
DAY = timedelta(days=1)


@pytest.fixture
def sc(session: Session, processor: EventProcessor) -> Scenario:
    return Scenario(session, processor)


def _world(sc: Scenario) -> dict[str, object]:
    uid = sc.user(T - 100 * DAY)
    pm = sc.payment_method(uid, T - 100 * DAY)
    ev = {}
    ev["legit_old"], txn_legit = sc.purchase(uid, T, "10.00", pm=pm)
    record_label(
        sc.session,
        user_id=uid,
        transaction_id=txn_legit,
        event_id=ev["legit_old"].event_id,
        label=LabelValue.LEGITIMATE,
        label_source=LabelSource.ANALYST,
        labelled_at=T + 2 * DAY,
    )
    ev["fraud"], txn_fraud = sc.purchase(uid, T + DAY, "500.00", pm=pm)
    sc.chargeback(uid, txn_fraud, T + 20 * DAY)
    ev["late_fraud"], txn_late = sc.purchase(uid, T + 2 * DAY, "600.00", pm=pm)
    sc.chargeback(uid, txn_late, T + 70 * DAY)  # after the cutoff
    ev["unlabelled_old"], _ = sc.purchase(uid, T + 3 * DAY, "11.00", pm=pm)
    ev["login"] = sc.login(uid, T + 4 * DAY)
    sc.confirm_fraud(uid, T + 5 * DAY, target=ev["login"].event_id)
    ev["recent"], txn_recent = sc.purchase(uid, T + 50 * DAY, "12.00", pm=pm)
    record_label(
        sc.session,
        user_id=uid,
        transaction_id=txn_recent,
        event_id=ev["recent"].event_id,
        label=LabelValue.LEGITIMATE,
        label_source=LabelSource.ANALYST,
        labelled_at=T + 51 * DAY,
    )
    ev["bad_provenance"], txn_bad = sc.purchase(uid, T + 6 * DAY, "13.00", pm=pm)
    record_label(
        sc.session,
        user_id=uid,
        transaction_id=txn_bad,
        label=LabelValue.FRAUD,
        fraud_type=FraudType.OTHER,
        label_source=LabelSource.ANALYST,
        labelled_at=T + 5 * DAY,
    )  # before the event happened
    sc.session.flush()
    return ev


def _policy(**kw: object) -> LabelAvailabilityPolicy:
    return LabelAvailabilityPolicy(label_cutoff=T + 60 * DAY, maturity=30 * DAY, **kw)  # type: ignore[arg-type]


def _status(ds, event) -> LabelStatus:  # type: ignore[no-untyped-def]
    for d in [*ds.labels, *ds.excluded]:
        if d.event_id == event.event_id:
            return d.status  # type: ignore[no-any-return]
    raise AssertionError("not found")


def test_label_policy(sc: Scenario) -> None:
    ev = _world(sc)
    ds = TrainingDatasetBuilder(sc.session, _policy()).build(T, T + 60 * DAY)
    assert _status(ds, ev["legit_old"]) is LabelStatus.NEGATIVE
    assert _status(ds, ev["fraud"]) is LabelStatus.POSITIVE
    assert _status(ds, ev["late_fraud"]) is LabelStatus.LABEL_NOT_YET_KNOWN  # refused
    assert _status(ds, ev["unlabelled_old"]) is LabelStatus.UNLABELLED
    assert _status(ds, ev["login"]) is LabelStatus.POSITIVE  # FRAUD_CONFIRMED on the login
    assert _status(ds, ev["recent"]) is LabelStatus.IMMATURE  # chargebacks may still arrive
    assert _status(ds, ev["bad_provenance"]) is LabelStatus.INVALID_PROVENANCE
    assert ds.y() == [d.label for d in ds.labels]
    assert len(ds.X()) == len(ds.y()) == len(ds.examples)
    positive = next(d for d in ds.labels if d.event_id == ev["fraud"].event_id)
    assert positive.provenance[0].label_source is LabelSource.CHARGEBACK
    assert positive.provenance[0].known_at_cutoff


def test_implicit_negatives_and_sources(sc: Scenario) -> None:
    ev = _world(sc)
    ds = TrainingDatasetBuilder(sc.session, _policy(implicit_negatives=True)).build(T, T + 60 * DAY)
    assert _status(ds, ev["unlabelled_old"]) is LabelStatus.NEGATIVE_IMPLICIT
    only_chargebacks = _policy(allowed_sources=frozenset({LabelSource.CHARGEBACK}))
    ds2 = TrainingDatasetBuilder(sc.session, only_chargebacks).build(T, T + 60 * DAY)
    assert _status(ds2, ev["login"]) is LabelStatus.UNLABELLED  # analyst label not allowed
    assert _status(ds2, ev["fraud"]) is LabelStatus.POSITIVE
    early_cutoff = LabelAvailabilityPolicy(label_cutoff=T + 10 * DAY, maturity=DAY)
    ds3 = TrainingDatasetBuilder(sc.session, early_cutoff).build(T, T + 10 * DAY)
    assert _status(ds3, ev["fraud"]) is LabelStatus.LABEL_NOT_YET_KNOWN  # chargeback on day 20


def test_labels_are_never_inside_feature_vectors(sc: Scenario, tmp_path: Path) -> None:
    ev = _world(sc)
    ds = TrainingDatasetBuilder(sc.session, _policy()).build(T, T + 60 * DAY)
    names = set(get_feature_set().names)
    assert not {n for n in names if n in {"label", "is_fraud", "fraud"}}
    paths = ds.write(tmp_path / "out")
    features = [json.loads(line) for line in paths["features.jsonl"].read_text().splitlines()]
    labels = [json.loads(line) for line in paths["labels.jsonl"].read_text().splitlines()]
    assert all("label" not in row and "status" not in row for row in features)
    assert [f["event_id"] for f in features] == [lbl["event_id"] for lbl in labels]
    manifest = json.loads(paths["manifest.json"].read_text())
    assert manifest["positives"] == 2 and manifest["label_policy"]["maturity_days"] == 30
    assert manifest["feature_set_fingerprint"] == get_feature_set().fingerprint()
    assert manifest["label_status_counts"]["label_not_yet_known"] == 1
    excluded = paths["excluded.jsonl"].read_text()
    assert str(ev["late_fraud"].event_id) in excluded


def test_positive_features_equal_features_without_any_labels(sc: Scenario) -> None:
    ev = _world(sc)
    ds = TrainingDatasetBuilder(sc.session, _policy()).build(T, T + 60 * DAY)
    fraud_vector = next(e.vector for e in ds.examples if e.event_id == ev["fraud"].event_id)
    batch = extract_training_features(sc.session, T + DAY, T + DAY, kinds=[EventKind.TRANSACTION])
    assert [v.feature_hash for v in batch.vectors] == [fraud_vector.feature_hash]


def test_builder_rejects_range_after_cutoff(sc: Scenario) -> None:
    with pytest.raises(DatasetBuildError, match="after the label cutoff"):
        TrainingDatasetBuilder(sc.session, _policy()).build(T, T + 61 * DAY)
    with pytest.raises(ValueError, match="timezone"):
        LabelAvailabilityPolicy(label_cutoff=datetime(2026, 1, 1))
    with pytest.raises(ValueError, match="maturity"):
        LabelAvailabilityPolicy(label_cutoff=T, maturity=-DAY)
    with pytest.raises(ValueError):
        extract_training_features(sc.session, T, T - DAY)


def test_snapshot_reuse_in_builder(sc: Scenario) -> None:
    _world(sc)
    builder = TrainingDatasetBuilder(sc.session, _policy())
    first = builder.build(T, T + 60 * DAY, persist_snapshots=True)
    assert first.snapshots_created == len(first.examples) + len(first.excluded)
    second = builder.build(T, T + 60 * DAY, use_snapshots=True)
    assert second.snapshots_reused == first.snapshots_created and second.snapshots_created == 0
    assert [e.feature_hash for e in second.examples] == [e.feature_hash for e in first.examples]
    assert all(e.snapshot_id is not None for e in second.examples)


def test_batch_ordering_and_kinds(sc: Scenario) -> None:
    _world(sc)
    ids = scorable_event_ids(sc.session, T, T + 60 * DAY)
    logins = scorable_event_ids(sc.session, T, T + 60 * DAY, [EventKind.LOGIN])
    txns = scorable_event_ids(sc.session, T, T + 60 * DAY, [EventKind.TRANSACTION])
    assert len(logins) == 1 and len(txns) == 6 and set(ids) == set(logins) | set(txns)
    batch = extract_training_features(sc.session, T, T + 60 * DAY)
    stamps = [v.event_timestamp for v in batch.vectors]
    assert stamps == sorted(stamps)
    assert all(v.as_of_timestamp == v.event_timestamp for v in batch.vectors)
