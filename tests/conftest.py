from __future__ import annotations

import os
import shutil
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from fraud_ai.config.settings import reset_settings_cache
from fraud_ai.core.enums import EventSource, EventType
from fraud_ai.core.events import Event
from fraud_ai.database.engine import create_db_engine, make_session_factory
from fraud_ai.database.migrations import upgrade
from fraud_ai.ingestion.processor import EventProcessor
from fraud_ai.security.hashing import Pseudonymiser

TEST_KEY = "test-pseudonymisation-key-0123456789abcdef"
_ENV_VARS = (
    "DATABASE_URL",
    "ENVIRONMENT",
    "LOG_LEVEL",
    "MODEL_DIRECTORY",
    "DATA_DIRECTORY",
    "PSEUDONYMISATION_KEY",
    "STORE_RAW_IP",
    "LOCAL_LLM_MODEL",
    "LOCAL_LLM_ENDPOINT",
    "DATABASE_ECHO",
)
POSTGRES_URL = os.environ.get("TEST_POSTGRES_URL")


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Path]:
    """Every test runs with a clean environment in its own directory (no stray .env)."""
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("DATA_DIRECTORY", str(tmp_path / "data"))
    monkeypatch.setenv("MODEL_DIRECTORY", str(tmp_path / "models"))
    monkeypatch.setenv("PSEUDONYMISATION_KEY", TEST_KEY)
    reset_settings_cache()
    yield tmp_path
    reset_settings_cache()


@pytest.fixture(scope="session")
def migrated_template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("template") / "template.db"
    upgrade(f"sqlite:///{path}")
    return path


@pytest.fixture
def sqlite_url(tmp_path: Path, migrated_template: Path) -> str:
    path = tmp_path / "test.db"
    shutil.copy(migrated_template, path)
    return f"sqlite:///{path}"


@pytest.fixture
def engine(sqlite_url: str) -> Iterator[Engine]:
    eng = create_db_engine(sqlite_url)
    yield eng
    eng.dispose()


def _reset_postgres(url: str) -> None:
    eng = create_db_engine(url)
    with eng.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    eng.dispose()


@pytest.fixture(params=["sqlite", pytest.param("postgres", marks=pytest.mark.postgres)])
def backend_url(request: pytest.FixtureRequest, tmp_path: Path) -> str:
    """An *empty* database URL on each available backend."""
    if request.param == "sqlite":
        return f"sqlite:///{tmp_path / 'backend.db'}"
    if not POSTGRES_URL:
        pytest.skip("TEST_POSTGRES_URL not set")
    _reset_postgres(POSTGRES_URL)
    return POSTGRES_URL


@pytest.fixture
def any_engine(backend_url: str) -> Iterator[Engine]:
    """A migrated database on each available backend."""
    upgrade(backend_url)
    eng = create_db_engine(backend_url)
    yield eng
    eng.dispose()


@pytest.fixture
def session(engine: Engine) -> Iterator[Session]:
    factory = make_session_factory(engine)
    with factory() as sess:
        yield sess
        sess.rollback()


@pytest.fixture
def pseudonymiser() -> Pseudonymiser:
    return Pseudonymiser(TEST_KEY.encode())


@pytest.fixture
def processor(session: Session, pseudonymiser: Pseudonymiser) -> EventProcessor:
    return EventProcessor(session, pseudonymiser)


T0 = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)

HOME_NET: dict[str, Any] = {
    "ip": "10.1.2.3",
    "asn": 64601,
    "asn_org": "Home ISP",
    "country": "GB",
    "network_type": "residential",
    "is_known_vpn": False,
}
VPN_NET: dict[str, Any] = {
    "ip": "198.51.100.7",
    "asn": 65001,
    "asn_org": "VPN Co",
    "country": "NL",
    "network_type": "datacenter",
    "is_known_vpn": True,
    "is_datacenter": True,
    "proxy_confidence": 0.93,
    "intel_source": "test",
}
DESKTOP = {"os_family": "Windows", "client_family": "Firefox", "device_type": "desktop"}


def make_event(
    event_type: EventType,
    user_id: uuid.UUID | None,
    metadata: dict[str, Any],
    *,
    ts: datetime = T0,
    device_id: str | None = "device-A",
    session_id: str | None = "sess-1",
) -> Event:
    return Event(
        event_type=event_type,
        timestamp=ts,
        user_id=user_id,
        session_id=session_id,
        device_id=device_id,
        source=EventSource.API,
        metadata=metadata,
    )


def create_user(
    processor: EventProcessor,
    *,
    ts: datetime = T0,
    user_id: uuid.UUID | None = None,
    device_id: str | None = "device-A",
    net: dict[str, Any] | None = None,
) -> uuid.UUID:
    uid = user_id or uuid.uuid4()
    processor.process(
        make_event(
            EventType.ACCOUNT_CREATED,
            uid,
            {
                "external_ref": f"REF-{uid.hex[:10]}",
                "home_country": "GB",
                "network": net or HOME_NET,
                "device": DESKTOP,
            },
            ts=ts,
            device_id=device_id,
        )
    )
    return uid
