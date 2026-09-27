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


_RATE_UNITS = {"second": 1.0, "minute": 60.0, "hour": 3600.0}


def _split(value: str) -> list[str]:
    return [p.strip() for p in value.split(",") if p.strip()]


def parse_rate(value: str) -> tuple[int, float]:
    """``"120/minute"`` -> (120, 60.0 seconds)."""
    try:
        count, unit = value.strip().split("/")
        n = int(count)
        period = _RATE_UNITS[unit.strip().lower()]
    except (ValueError, KeyError):
        raise ValueError(
            "RATE_LIMIT must look like '<count>/<second|minute|hour>', e.g. '120/minute'"
        ) from None
    if n < 1:
        raise ValueError("RATE_LIMIT count must be positive")
    return n, period


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

    # Stage 9: the machine-to-machine fraud service. No production secret has a default.
    service_host: str = "127.0.0.1"
    service_port: int = Field(default=8080, ge=1, le=65535)
    # Comma-separated IPs/CIDRs of reverse proxies whose X-Forwarded-For is honoured.
    # Empty (the default) means forwarding headers are NEVER trusted.
    trusted_proxies: str = ""
    request_size_limit: int = Field(default=64 * 1024, ge=1024, le=10 * 1024 * 1024)
    # "<count>/<second|minute|hour>" per API key and route group.
    rate_limit: str = "120/minute"
    rate_limit_burst: int = Field(default=30, ge=1, le=10_000)
    service_request_timeout: float = Field(default=10.0, gt=0, le=120)
    # Signed requests: HMAC-SHA256(timestamp + "." + body) with a per-key signing secret
    # derived from this master key (from the environment / a secret manager).
    service_signing_master_key: SecretStr | None = None
    service_require_signatures: bool = False
    signature_max_age: int = Field(default=300, ge=10, le=3600)
    # Comma-separated allowed CORS origins. Empty (default) disables CORS entirely.
    service_cors_origins: str = ""
    service_expose_openapi: bool = False
    service_hsts: bool = False  # only behind TLS termination
    # WebAuthn relying party (development defaults: localhost).
    webauthn_rp_id: str = "localhost"
    webauthn_rp_name: str = "fraud-ai (development)"
    webauthn_origin: str = "http://localhost:8080"
    webauthn_challenge_ttl: int = Field(default=120, ge=30, le=900)
    step_up_max_attempts: int = Field(default=3, ge=1, le=10)
    # Payment authentication provider: "fake" (development only) or unset.
    payment_auth_provider: str | None = None
    payment_auth_webhook_secret: SecretStr | None = None
    payment_auth_timeout: float = Field(default=5.0, gt=0, le=60)

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

    @field_validator("rate_limit")
    @classmethod
    def _validate_rate_limit(cls, value: str) -> str:
        parse_rate(value)
        return value

    @field_validator("trusted_proxies")
    @classmethod
    def _validate_trusted_proxies(cls, value: str) -> str:
        for part in _split(value):
            try:
                ipaddress.ip_network(part, strict=False)
            except ValueError as exc:
                raise ValueError(f"TRUSTED_PROXIES entry {part!r} is not an IP/CIDR") from exc
        return value

    @field_validator("payment_auth_provider")
    @classmethod
    def _validate_payment_provider(cls, value: str | None) -> str | None:
        if value in (None, ""):
            return None
        if value not in {"fake"}:
            raise ValueError("PAYMENT_AUTH_PROVIDER must be 'fake' or unset (no real adapter yet)")
        return value

    @model_validator(mode="after")
    def _validate_environment_policy(self) -> Settings:
        for secret, name in (
            (self.service_signing_master_key, "SERVICE_SIGNING_MASTER_KEY"),
            (self.payment_auth_webhook_secret, "PAYMENT_AUTH_WEBHOOK_SECRET"),
        ):
            if secret is not None and len(secret.get_secret_value()) < _MIN_KEY_LENGTH:
                raise ValueError(f"{name} must be at least {_MIN_KEY_LENGTH} characters")
        if self.service_require_signatures and self.service_signing_master_key is None:
            raise ValueError("SERVICE_REQUIRE_SIGNATURES needs SERVICE_SIGNING_MASTER_KEY")
        if self.payment_auth_provider is not None and self.payment_auth_webhook_secret is None:
            raise ValueError("PAYMENT_AUTH_PROVIDER needs PAYMENT_AUTH_WEBHOOK_SECRET")
        if self.environment in {Environment.STAGING, Environment.PRODUCTION}:
            if self.payment_auth_provider == "fake":
                raise ValueError("the fake payment-auth provider is refused outside dev/test")
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

    def service_problems(self) -> list[str]:
        """Settings the HTTP service refuses to start with (checked only when serving, so
        batch and CLI jobs need no service configuration)."""
        problems = []
        hosted = self.environment in {Environment.STAGING, Environment.PRODUCTION}
        if hosted and not self.webauthn_origin.startswith("https://"):
            problems.append(f"{self.environment} requires an https WEBAUTHN_ORIGIN")
        return problems

    @property
    def trusted_proxy_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [ipaddress.ip_network(p, strict=False) for p in _split(self.trusted_proxies)]

    @property
    def cors_origins(self) -> list[str]:
        return _split(self.service_cors_origins)

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
