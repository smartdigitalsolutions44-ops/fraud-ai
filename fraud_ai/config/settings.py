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

    # Stage 7 (local offline LLM). Declared now so configuration is stable.
    local_llm_model: str | None = None
    local_llm_endpoint: str | None = None

    database_echo: bool = Field(default=False, description="Echo SQL (never in production).")

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        level = value.upper()
        if level not in _LOG_LEVELS:
            raise ValueError(f"LOG_LEVEL must be one of {sorted(_LOG_LEVELS)}")
        return level

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
