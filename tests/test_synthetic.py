import ipaddress
import shutil
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from fraud_ai.core.enums import EventType, FraudType, LabelSource, LabelValue
from fraud_ai.data.seed import SeedError, seed_synthetic_data
from fraud_ai.data.synthetic import SCENARIOS, SyntheticDataGenerator
from fraud_ai.database.engine import create_db_engine, make_session_factory, session_scope
from fraud_ai.database.models import Address, FraudLabel, NetworkIdentity, Transaction, User
from fraud_ai.security.hashing import Pseudonymiser
from fraud_ai.security.redaction import find_forbidden_data
from tests.conftest import TEST_KEY

REF = datetime(2026, 6, 1, tzinfo=UTC)
_SAFE_NETS = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "100.64.0.0/10", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]


def _gen(seed: int = 1) -> SyntheticDataGenerator:
    return SyntheticDataGenerator(seed=seed, reference_time=REF, activity_days=60)


def test_generation_is_deterministic() -> None:
    a = _gen().generate(24)
    b = _gen().generate(24)
    assert [e.model_dump() for e in a.events] == [e.model_dump() for e in b.events]
    c = _gen(seed=2).generate(24)
    assert [e.event_id for e in a.events] != [e.event_id for e in c.events]


def test_allocation_covers_every_scenario() -> None:
    counts = SyntheticDataGenerator.allocate(24)
    assert set(counts) == set(SCENARIOS) and sum(counts.values()) == 24
    assert all(v >= 1 for v in counts.values())
    with pytest.raises(ValueError):
        SyntheticDataGenerator.allocate(3)


def test_events_are_chronological_safe_and_bounded() -> None:
    ds = _gen().generate(24)
    stamps = [e.timestamp for e in ds.events]
    assert stamps == sorted(stamps)
    assert max(stamps) <= REF
    assert {
        EventType.PASSWORD_RESET,
        EventType.ADDRESS_CHANGED,
        EventType.CHARGEBACK,
        EventType.FRAUD_CONFIRMED,
        EventType.LOGIN_FAILURE,
    } <= {e.event_type for e in ds.events}
    for e in ds.events:
        assert find_forbidden_data(e.metadata) == []
        net = e.metadata.get("network")
        if net:
            ip = ipaddress.ip_address(net["ip"])
            assert any(ip in n for n in _SAFE_NETS), ip  # never a real public address
            assert 64512 <= net["asn"] <= 65534  # private-use ASNs only


@pytest.fixture(scope="module")
def seeded_template(migrated_template: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Seed once per module; each test gets its own copy of the resulting database."""
    path = tmp_path_factory.mktemp("seeded") / "seeded.db"
    shutil.copy(migrated_template, path)
    engine = create_db_engine(f"sqlite:///{path}")
    with session_scope(make_session_factory(engine)) as sess:
        seed_synthetic_data(
            sess,
            Pseudonymiser(TEST_KEY.encode()),
            n_users=24,
            seed=3,
            reference_time=REF,
            activity_days=45,
        )
    engine.dispose()
    return path


@pytest.fixture
def seeded(seeded_template: Path, tmp_path: Path) -> Iterator[Session]:
    path = tmp_path / "seeded.db"
    shutil.copy(seeded_template, path)
    engine = create_db_engine(f"sqlite:///{path}")
    with make_session_factory(engine)() as sess:
        yield sess
    engine.dispose()


def _scenario_labels(session: Session, scenario: str) -> list[FraudLabel]:
    return list(
        session.scalars(
            select(FraudLabel)
            .join(User)
            .where(User.synthetic_scenario == scenario, FraudLabel.label == LabelValue.FRAUD)
        )
    )


def test_seed_labels_match_scenarios(seeded: Session) -> None:
    ato = _scenario_labels(seeded, "account_takeover")
    assert ato and {lbl.fraud_type for lbl in ato} == {FraudType.ACCOUNT_TAKEOVER}
    assert any(lbl.transaction_id is not None for lbl in ato)
    stuffing = _scenario_labels(seeded, "suspicious_velocity")
    assert stuffing and {lbl.fraud_type for lbl in stuffing} == {FraudType.CREDENTIAL_STUFFING}
    for legit in ("normal", "legitimate_vpn", "shared_network", "new_home_address"):
        assert _scenario_labels(seeded, legit) == [], legit


def test_every_transaction_has_ground_truth(seeded: Session) -> None:
    txns = seeded.scalar(select(func.count()).select_from(Transaction))
    labelled = seeded.scalar(select(func.count(func.distinct(FraudLabel.transaction_id))))
    assert txns and txns == labelled
    truth = seeded.scalar(
        select(func.count())
        .select_from(FraudLabel)
        .where(FraudLabel.label_source == LabelSource.SYNTHETIC_GROUND_TRUTH)
    )
    assert truth and truth < txns


def test_new_home_address_is_legitimate_move(seeded: Session) -> None:
    movers = seeded.scalars(select(User).where(User.synthetic_scenario == "new_home_address")).all()
    assert movers
    for user in movers:
        homes = seeded.scalars(select(Address).where(Address.user_id == user.user_id)).all()
        assert len(homes) == 2 and sum(a.is_active for a in homes) == 1


def test_shared_network_has_multi_user_ips(seeded: Session) -> None:
    assert (seeded.scalar(select(func.max(NetworkIdentity.distinct_user_count))) or 0) >= 2


def test_seed_refuses_to_run_twice(seeded: Session, pseudonymiser: Pseudonymiser) -> None:
    with pytest.raises(SeedError, match="already contains"):
        seed_synthetic_data(seeded, pseudonymiser, n_users=10, seed=3, reference_time=REF)


@pytest.mark.parametrize("days", [30, 31, 365])
def test_short_and_long_activity_windows(days: int) -> None:
    for seed in range(5):
        ds = SyntheticDataGenerator(seed=seed, reference_time=REF, activity_days=days).generate(12)
        assert max(e.timestamp for e in ds.events) <= REF
    with pytest.raises(ValueError):
        SyntheticDataGenerator(seed=1, reference_time=REF, activity_days=10)


def test_seed_end_to_end_on_each_backend(any_engine: Engine) -> None:
    """The full ingestion path works on SQLite and PostgreSQL alike."""
    with session_scope(make_session_factory(any_engine)) as sess:
        summary = seed_synthetic_data(
            sess,
            Pseudonymiser(TEST_KEY.encode()),
            n_users=8,
            seed=5,
            reference_time=REF,
            activity_days=30,
        )
    assert summary.fraud_labels > 0 and summary.transactions > 0
    with session_scope(make_session_factory(any_engine)) as sess:
        assert sess.scalar(select(func.count()).select_from(User)) == 8
        assert sess.scalar(select(func.count()).select_from(FraudLabel)) == (
            summary.fraud_labels + summary.legitimate_labels
        )
