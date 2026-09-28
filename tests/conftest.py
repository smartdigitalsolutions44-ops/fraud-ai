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
    "LOCAL_LLM_RUNTIME",
    "SERVICE_SIGNING_MASTER_KEY",
    "SERVICE_REQUIRE_SIGNATURES",
    "PAYMENT_AUTH_PROVIDER",
    "PAYMENT_AUTH_WEBHOOK_SECRET",
    "TRUSTED_PROXIES",
    "RATE_LIMIT",
    "SERVICE_CORS_ORIGINS",
    "STATE_BACKEND",
    "REDIS_URL",
    "SERVICE_SIGNING_PREVIOUS_KEY",
    "SERVICE_SIGNING_PREVIOUS_KEY_VERSION",
    "SERVICE_SIGNING_PREVIOUS_KEY_EXPIRES_AT",
    "SERVICE_SIGNING_KEY_VERSION",
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


# --------------------------------------------------------------------------- Stage 3 world
MODEL_REF_TIME = datetime(2026, 7, 1, tzinfo=UTC)


@pytest.fixture(scope="session")
def seeded_model_world(migrated_template: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A synthetic world with fraud spread across time, seeded once per session. Tests copy
    the file before mutating it."""
    from fraud_ai.data.seed import seed_synthetic_data
    from fraud_ai.database.engine import session_scope

    path = tmp_path_factory.mktemp("model_world") / "world.db"
    shutil.copy(migrated_template, path)
    eng = create_db_engine(f"sqlite:///{path}")
    with session_scope(make_session_factory(eng)) as sess:
        seed_synthetic_data(
            sess,
            Pseudonymiser(TEST_KEY.encode()),
            n_users=80,
            seed=13,
            reference_time=MODEL_REF_TIME,
            activity_days=120,
            # Enough fraud in every time-ordered split for calibration and segment tests.
            fraud_multiplier=2.0,
        )
    eng.dispose()
    return path


@pytest.fixture(scope="session")
def pg_world(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[str, Path]]:
    """The Stage 8 world on PostgreSQL in its own schema (survives other tests' resets)."""
    if not POSTGRES_URL:
        pytest.skip("TEST_POSTGRES_URL not set")
    from tests.realtime_world import build_pg_world

    root = tmp_path_factory.mktemp("pg_world")
    url = build_pg_world(POSTGRES_URL, "stage10_world", root)
    yield url, root
    eng = create_db_engine(POSTGRES_URL)
    with eng.begin() as conn:
        conn.execute(text('DROP SCHEMA IF EXISTS "stage10_world" CASCADE'))
    eng.dispose()


@pytest.fixture(scope="session")
def redis_url(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """A throwaway local redis-server (no persistence) for the Stage 10 state tests."""
    import socket
    import subprocess
    import time

    binary = shutil.which("redis-server")
    if binary is None:
        pytest.skip("redis-server is not installed")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    workdir = tmp_path_factory.mktemp("redis")
    proc = subprocess.Popen(  # noqa: S603 - fixed local binary, fixed arguments
        [
            binary,
            "--port",
            str(port),
            "--bind",
            "127.0.0.1",
            "--save",
            "",
            "--appendonly",
            "no",
            "--dir",
            str(workdir),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"redis://127.0.0.1:{port}/0"
    import redis

    client = redis.Redis.from_url(url)
    for _ in range(100):
        try:
            client.ping()
            break
        except redis.RedisError:
            time.sleep(0.05)
    client.close()
    yield url
    proc.terminate()
    proc.wait(timeout=10)


@pytest.fixture
def flushed_redis(redis_url: str) -> str:
    import redis

    client = redis.Redis.from_url(redis_url)
    client.flushdb()
    client.close()
    return redis_url


@pytest.fixture(scope="session")
def realtime_world_dir(migrated_template: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The Stage 8 world (models, policies, live stream), built once per session. Tests
    copy it (``tests.realtime_world.open_world``) before mutating anything."""
    from tests.realtime_world import build_world

    return build_world(tmp_path_factory.mktemp("realtime_world"), migrated_template)


def fast_training_config(**overrides: Any) -> Any:
    from datetime import timedelta

    from fraud_ai.models.training import TrainingConfig

    base: dict[str, Any] = {
        "maturity": timedelta(days=14),
        "hyperparameters": {
            "random-forest": {"n_estimators": 60},
            "gradient-boosting": {"max_iter": 80},
            "neural-network": {"hidden_sizes": [32, 16], "max_epochs": 15, "patience": 4},
            "autoencoder": {"hidden_sizes": [32], "bottleneck": 6, "max_epochs": 15},
            **{
                kind: {
                    "hidden_size": 16,
                    "heads": 2,
                    "ff_size": 32,
                    "max_epochs": 6,
                    "patience": 3,
                    "fusion_hidden": 8,
                    "static_hidden": 16,
                }
                for kind in ("gru", "transformer", "hybrid-gru")
            },
        },
    }
    base.update(overrides)
    return TrainingConfig(**base)
