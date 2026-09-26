"""Typed application settings loaded from environment variables (and an optional ``.env``).

No secrets live in source code. Secrets (database passwords, the pseudonymisation key) are
supplied through the environment only.
"""

from __future__ import annotations

import ipaddress
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_MIN_KEY_LENGTH = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    environment: Environment = Environment.DEVELOPMENT
    log_level: str = "INFO"
    database_url: str | None = None
    data_directory: Path = Path("data")
    model_directory: Path = Path("models")
    evaluation_directory: Path = Path("evaluation")

    # HMAC key used to pseudonymise IPs, device identifiers and addresses.
    pseudonymisation_key: SecretStr | None = None
    # Raw IP addresses are personal data; only keep them when explicitly enabled.
    store_raw_ip: bool = False

    # Stage 7: local, offline analyst-assistance LLM (explanations only, never decisions).
    # Runtime: ollama | llamacpp-server | llamacpp-process | reference (template, not an LLM).
    local_llm_runtime: str | None = None
    local_llm_model: str | None = None
    # Defaults per runtime (localhost) when unset; public addresses are refused.
    local_llm_endpoint: str | None = None
    local_llm_timeout: float = Field(default=120.0, gt=0, le=3600)
    # llamacpp-process only: the local binary and GGUF model file.
    local_llm_binary: str = "llama-cli"
    local_llm_model_path: Path | None = None
    local_llm_context_window: int = Field(default=8192, ge=1024, le=262_144)
    local_llm_max_tokens: int = Field(default=1200, ge=64, le=8192)
    # Deterministic by default: temperature 0, fixed seed.
    local_llm_temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    local_llm_top_p: float = Field(default=1.0, gt=0.0, le=1.0)
    local_llm_seed: int = 0

    database_echo: bool = Field(default=False, description="Echo SQL (never in production).")

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        level = value.upper()
        if level not in _LOG_LEVELS:
            raise ValueError(f"LOG_LEVEL must be one of {sorted(_LOG_LEVELS)}")
        return level

    @field_validator("local_llm_runtime")
    @classmethod
    def _validate_llm_runtime(cls, value: str | None) -> str | None:
        runtimes = {"ollama", "llamacpp-server", "llamacpp-process", "reference"}
        if value is None or value == "":
            return None
        if value not in runtimes:
            raise ValueError(f"LOCAL_LLM_RUNTIME must be one of {sorted(runtimes)}")
        return value

    @field_validator("local_llm_endpoint")
    @classmethod
    def _validate_llm_endpoint_is_local(cls, value: str | None) -> str | None:
        """The LLM layer is local/offline by design: refuse public endpoints."""
        if value is None or value == "":
            return None
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("LOCAL_LLM_ENDPOINT must be an http(s) URL")
        host = parsed.hostname
        if host == "localhost":
            return value
        try:
            addr = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError(
                "LOCAL_LLM_ENDPOINT must be localhost or a loopback/private IP address"
            ) from exc
        if not (addr.is_loopback or addr.is_private):
            raise ValueError("LOCAL_LLM_ENDPOINT must not point at a public address")
        return value

    @model_validator(mode="after")
    def _validate_environment_policy(self) -> Settings:
        if self.environment in {Environment.STAGING, Environment.PRODUCTION}:
            if self.database_url is None or not self.database_url.startswith("postgresql"):
                raise ValueError(f"{self.environment} requires a PostgreSQL DATABASE_URL")
            if self.database_echo:
                raise ValueError("DATABASE_ECHO must be disabled outside development/test")
            if self.pseudonymisation_key is None:
                raise ValueError(f"{self.environment} requires PSEUDONYMISATION_KEY")
        if (
            self.pseudonymisation_key is not None
            and len(self.pseudonymisation_key.get_secret_value()) < _MIN_KEY_LENGTH
        ):
            raise ValueError(f"PSEUDONYMISATION_KEY must be at least {_MIN_KEY_LENGTH} characters")
        return self

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{(self.data_directory / 'fraud_ai.db').as_posix()}"

    @property
    def is_sqlite(self) -> bool:
        return self.resolved_database_url.startswith("sqlite")

    @property
    def safe_database_url(self) -> str:
        """Database URL with any password masked - safe to print or log."""
        return make_url(self.resolved_database_url).render_as_string(hide_password=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()
