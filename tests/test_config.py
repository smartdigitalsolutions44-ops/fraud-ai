from pathlib import Path

import pytest
from pydantic import ValidationError

from fraud_ai.config.settings import Environment, Settings, get_settings

PG = "postgresql+psycopg://user:s3cret@db.internal:5432/fraud"
KEY = "k" * 40


def test_defaults_are_development_friendly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ENVIRONMENT")
    monkeypatch.delenv("PSEUDONYMISATION_KEY")
    monkeypatch.delenv("DATA_DIRECTORY")
    s = Settings()
    assert s.environment is Environment.DEVELOPMENT
    assert s.log_level == "INFO"
    assert s.resolved_database_url == "sqlite:///data/fraud_ai.db"
    assert s.is_sqlite
    assert s.store_raw_ip is False
    assert s.local_llm_endpoint is None


def test_reads_environment_variables(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOG_LEVEL", "debug")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///x.db")
    monkeypatch.setenv("MODEL_DIRECTORY", str(tmp_path / "m"))
    s = get_settings()
    assert s.log_level == "DEBUG"
    assert s.resolved_database_url == "sqlite:///x.db"
    assert s.model_directory == tmp_path / "m"
    assert s.environment is Environment.TEST


def test_invalid_log_level_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(log_level="LOUD")


def test_safe_database_url_masks_password() -> None:
    s = Settings(database_url=PG)
    assert "s3cret" not in s.safe_database_url
    assert "***" in s.safe_database_url


@pytest.mark.parametrize("env", ["production", "staging"])
def test_production_requires_postgres_and_key(env: str) -> None:
    with pytest.raises(ValidationError, match="PostgreSQL"):
        Settings(environment=env, database_url="sqlite:///prod.db", pseudonymisation_key=KEY)
    with pytest.raises(ValidationError, match="PSEUDONYMISATION_KEY"):
        Settings(environment=env, database_url=PG, pseudonymisation_key=None)
    with pytest.raises(ValidationError, match="ECHO"):
        Settings(environment=env, database_url=PG, pseudonymisation_key=KEY, database_echo=True)
    ok = Settings(environment=env, database_url=PG, pseudonymisation_key=KEY)
    assert ok.environment == env


def test_short_key_rejected() -> None:
    with pytest.raises(ValidationError, match="at least"):
        Settings(pseudonymisation_key="short")


def test_secret_not_in_repr() -> None:
    s = Settings(pseudonymisation_key=KEY)
    assert KEY not in repr(s)
    assert KEY not in str(s.model_dump())


@pytest.mark.parametrize(
    "endpoint",
    ["http://localhost:11434", "http://127.0.0.1:8080", "http://10.0.0.5:11434", "http://[::1]:1"],
)
def test_local_llm_endpoint_accepts_local(endpoint: str) -> None:
    assert Settings(local_llm_endpoint=endpoint).local_llm_endpoint == endpoint


@pytest.mark.parametrize(
    "endpoint", ["https://api.example.com/v1", "http://8.8.8.8:80", "ftp://localhost", "localhost"]
)
def test_local_llm_endpoint_rejects_remote(endpoint: str) -> None:
    with pytest.raises(ValidationError):
        Settings(local_llm_endpoint=endpoint)


def test_local_llm_defaults_are_offline_and_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("LOCAL_LLM_RUNTIME", "LOCAL_LLM_MODEL", "LOCAL_LLM_TEMPERATURE"):
        monkeypatch.delenv(var, raising=False)
    s = Settings()
    assert s.local_llm_runtime is None and s.local_llm_model is None
    assert s.local_llm_temperature == 0.0 and s.local_llm_seed == 0 and s.local_llm_top_p == 1.0
    assert s.local_llm_timeout > 0 and s.local_llm_context_window >= 1024


def test_local_llm_settings_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCAL_LLM_RUNTIME", "llamacpp-process")
    monkeypatch.setenv("LOCAL_LLM_MODEL_PATH", "/models/m.gguf")
    monkeypatch.setenv("LOCAL_LLM_TIMEOUT", "30")
    s = Settings()
    assert s.local_llm_runtime == "llamacpp-process"
    assert s.local_llm_model_path == Path("/models/m.gguf") and s.local_llm_timeout == 30
    assert Settings(local_llm_runtime="").local_llm_runtime is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"local_llm_runtime": "openai"},
        {"local_llm_timeout": 0},
        {"local_llm_temperature": -1},
        {"local_llm_max_tokens": 10},
    ],
)
def test_invalid_local_llm_settings_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Settings(**overrides)  # type: ignore[arg-type]
