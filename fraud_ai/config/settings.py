"""Typed application settings loaded from environment variables (and an optional ``.env``).

No secrets live in source code. Secrets (database passwords, the pseudonymisation key) are
supplied through the environment only.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict
from sqlalchemy.engine import make_url


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_MIN_KEY_LENGTH = 32
_OPERATOR = re.compile(r"[a-z0-9._@-]{2,64}")


_RATE_UNITS = {"second": 1.0, "minute": 60.0, "hour": 3600.0}


def _split(value: str) -> list[str]:
    return [p.strip() for p in value.split(",") if p.strip()]


_PLACEHOLDER_WORDS = (
    "changeme",
    "change_me",
    "change-me",
    "example",
    "placeholder",
    "default",
    "password",
    "secret",
    "dummy",
    "sample",
    "fraud_ai_dev",
    "insecure",
)


def looks_default(value: str) -> bool:
    """A heuristic for secrets that were never replaced: placeholder words, very low
    variety (e.g. ``aaaa...``) or a trivially short value. It cannot prove a secret is
    strong; it only refuses the obvious mistakes."""
    lowered = value.lower()
    if any(word in lowered for word in _PLACEHOLDER_WORDS):
        return True
    return len(value) < 12 or len(set(value)) < 8


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


class _FileSecretSource(PydanticBaseSettingsSource):
    """``<NAME>_FILE`` secret references (see :mod:`fraud_ai.config.secrets`)."""

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:
        return None, field_name, False

    def __call__(self) -> dict[str, Any]:
        from fraud_ai.config.secrets import resolve_file_secrets

        return dict(resolve_file_secrets())


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # Precedence: explicit arguments, environment, *_FILE secret references, .env.
        return (
            init_settings,
            env_settings,
            _FileSecretSource(settings_cls),
            dotenv_settings,
            file_secret_settings,
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
    service_signing_key_version: str = Field(default="1", pattern=r"^[A-Za-z0-9._-]{1,16}$")
    # Rotation (Stage 10): the previous master key stays valid for verification until
    # SERVICE_SIGNING_PREVIOUS_KEY_EXPIRES_AT; new signatures use the current key.
    service_signing_previous_key: SecretStr | None = None
    service_signing_previous_key_version: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9._-]{1,16}$"
    )
    service_signing_previous_key_expires_at: datetime | None = None
    service_require_signatures: bool = False
    signature_max_age: int = Field(default=300, ge=10, le=3600)
    # Stage 11: the weakest request-signature scheme accepted (v1 = timestamp + body;
    # v2 = method + canonical path/query + timestamp + body digest). Unset: v2 in
    # production, v1 elsewhere (migration). v1 is then refused, never silently accepted.
    signature_min_version: Literal["v1", "v2"] | None = None
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

    # Stage 10: shared coordination state. "memory" is one process only; "redis" shares
    # rate limits and replay claims across every worker and instance.
    state_backend: str = "memory"
    redis_url: SecretStr | None = None
    redis_key_prefix: str = Field(default="fraud-ai:", min_length=1, max_length=64)
    redis_timeout: float = Field(default=0.5, gt=0, le=10)
    # Staging may use the development fake provider only with this explicit opt-in;
    # production never can.
    payment_auth_allow_fake_in_staging: bool = False
    # Stripe test-mode adapter (Stage 10): official SDK, processor token references only.
    stripe_api_key: SecretStr | None = None
    stripe_return_url: str | None = None
    # Policy activation must follow shadow -> evaluation -> candidate. Default: required in
    # staging/production, optional in development/test.
    policy_require_promotion: bool | None = None
    # The reference template "LLM" is refused in production unless explicitly allowed.
    allow_reference_llm: bool = False
    service_key_rotation_grace_hours: float = Field(default=24.0, ge=0, le=24 * 90)
    # "text" or "json"; json is the default in staging/production.
    log_format: str | None = None
    # PostgreSQL connection pool (ignored for SQLite). Benchmark before changing.
    db_pool_size: int = Field(default=5, ge=1, le=200)
    db_max_overflow: int = Field(default=10, ge=0, le=200)
    db_pool_timeout: float = Field(default=30.0, gt=0, le=600)
    db_pool_recycle: int = Field(default=1800, ge=-1, le=86_400)
    # Retention (days; 0 disables the category). Destructive runs also need
    # RETENTION_ALLOW_DELETE=true or an explicit confirmation.
    retention_allow_delete: bool = False
    retention_idempotency_days: float = Field(default=7.0, ge=0)
    retention_challenge_days: float = Field(default=7.0, ge=0)
    retention_payment_request_days: float = Field(default=0.0, ge=0)
    retention_failed_attempt_days: float = Field(default=0.0, ge=0)
    retention_raw_ip_days: float = Field(default=30.0, ge=0)
    # Stage 11 core retention classes (``fraud-ai retention``; 0 disables). Assessments,
    # labels, model/policy history and the audit log have no class: never deleted here.
    retention_network_observation_days: float = Field(default=0.0, ge=0)
    retention_request_metadata_days: float = Field(default=0.0, ge=0)
    retention_investigation_days: float = Field(default=0.0, ge=0)
    retention_review_note_days: float = Field(default=0.0, ge=0)

    # Stage 11 trust chain (TRUST_CHAIN.md). Public keys are base64url raw Ed25519 keys,
    # comma-separated; one set per purpose, and no key may appear in two sets. Private keys
    # live in files and are needed only by the signing commands, never by the service.
    model_signing_public_keys: str | None = None
    model_signing_private_key_file: Path | None = None
    # Unset: required in staging and production. Required means an unsigned model, or one
    # signed by an untrusted key, is never loaded (conservative fallback instead).
    model_signatures_required: bool | None = None
    audit_anchor_public_keys: str | None = None
    audit_anchor_private_key_file: Path | None = None
    audit_anchor_directory: Path | None = None
    release_signing_public_keys: str | None = None
    release_signing_private_key_file: Path | None = None
    # Two-person rule: distinct operator approvals needed before activation (0 = off).
    # Unset: 2 in production, 0 elsewhere. Approvals expire after the TTL (0 = never).
    policy_approvals_required: int | None = Field(default=None, ge=0, le=2)
    policy_approval_ttl_hours: float = Field(default=72.0, ge=0)
    # The operator identity for approvals, from trusted CLI configuration (not a login).
    operator_id: str | None = None
    # Optional allow-list of operator identities that may approve.
    operator_allowlist: str | None = None
    # Readiness re-hashes the primary artefact at least this often (and on any change).
    readiness_reverify_seconds: float = Field(default=300.0, ge=0, le=86_400)

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

    @field_validator("state_backend")
    @classmethod
    def _validate_state_backend(cls, value: str) -> str:
        if value not in {"memory", "redis"}:
            raise ValueError("STATE_BACKEND must be 'memory' or 'redis'")
        return value

    @field_validator("payment_auth_provider")
    @classmethod
    def _validate_payment_provider(cls, value: str | None) -> str | None:
        if value in (None, ""):
            return None
        if value not in {"fake", "stripe"}:
            raise ValueError("PAYMENT_AUTH_PROVIDER must be 'fake', 'stripe' or unset")
        return value

    @model_validator(mode="after")
    def _validate_environment_policy(self) -> Settings:
        for secret, name in (
            (self.service_signing_master_key, "SERVICE_SIGNING_MASTER_KEY"),
            (self.payment_auth_webhook_secret, "PAYMENT_AUTH_WEBHOOK_SECRET"),
            (self.service_signing_previous_key, "SERVICE_SIGNING_PREVIOUS_KEY"),
        ):
            if secret is not None and len(secret.get_secret_value()) < _MIN_KEY_LENGTH:
                raise ValueError(f"{name} must be at least {_MIN_KEY_LENGTH} characters")
        if self.service_require_signatures and self.service_signing_master_key is None:
            raise ValueError("SERVICE_REQUIRE_SIGNATURES needs SERVICE_SIGNING_MASTER_KEY")
        if self.service_signing_previous_key is not None:
            if self.service_signing_master_key is None:
                raise ValueError("SERVICE_SIGNING_PREVIOUS_KEY needs SERVICE_SIGNING_MASTER_KEY")
            if (
                self.service_signing_previous_key_version is None
                or self.service_signing_previous_key_expires_at is None
            ):
                raise ValueError(
                    "SERVICE_SIGNING_PREVIOUS_KEY needs SERVICE_SIGNING_PREVIOUS_KEY_VERSION "
                    "and SERVICE_SIGNING_PREVIOUS_KEY_EXPIRES_AT (the end of the grace period)"
                )
            if self.service_signing_previous_key_version == self.service_signing_key_version:
                raise ValueError("the previous signing key needs a different version")
            if (
                self.service_signing_previous_key.get_secret_value()
                == self.service_signing_master_key.get_secret_value()
            ):
                raise ValueError("the previous signing key must differ from the current one")
        if self.state_backend == "redis" and self.redis_url is None:
            raise ValueError("STATE_BACKEND=redis needs REDIS_URL")
        if self.payment_auth_provider is not None and self.payment_auth_webhook_secret is None:
            raise ValueError("PAYMENT_AUTH_PROVIDER needs PAYMENT_AUTH_WEBHOOK_SECRET")
        self._validate_trust()
        if 0 < self.retention_network_observation_days < 180:
            raise ValueError(
                "RETENTION_NETWORK_OBSERVATION_DAYS must be 0 (off) or at least 180 "
                "(beyond every feature window)"
            )
        if self.log_format not in (None, "text", "json"):
            raise ValueError("LOG_FORMAT must be 'text' or 'json'")
        if self.payment_auth_provider == "stripe":
            if self.stripe_api_key is None:
                raise ValueError("PAYMENT_AUTH_PROVIDER=stripe needs STRIPE_API_KEY")
            if not self.stripe_api_key.get_secret_value().startswith(("sk_test_", "rk_test_")):
                raise ValueError("STRIPE_API_KEY must be a TEST-mode key (sk_test_/rk_test_)")
        if self.environment in {Environment.STAGING, Environment.PRODUCTION}:
            fake_ok = (
                self.environment is Environment.STAGING and self.payment_auth_allow_fake_in_staging
            )
            if self.payment_auth_provider == "fake" and not fake_ok:
                raise ValueError(
                    "the fake payment-auth provider is refused outside dev/test (staging needs "
                    "PAYMENT_AUTH_ALLOW_FAKE_IN_STAGING=true; production never allows it)"
                )
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

    def _validate_trust(self) -> None:
        from fraud_ai.trust.keys import TrustError, check_separation, parse_public_keys

        try:
            check_separation(
                {
                    "model": parse_public_keys(self.model_signing_public_keys),
                    "audit": parse_public_keys(self.audit_anchor_public_keys),
                    "release": parse_public_keys(self.release_signing_public_keys),
                }
            )
        except TrustError as exc:
            raise ValueError(str(exc)) from None
        if self.operator_id is not None and not _OPERATOR.fullmatch(self.operator_id):
            raise ValueError("OPERATOR_ID must be 2-64 characters of [a-z0-9._@-]")

    @property
    def requires_model_signatures(self) -> bool:
        if self.model_signatures_required is not None:
            return self.model_signatures_required
        return self.environment in {Environment.STAGING, Environment.PRODUCTION}

    @property
    def effective_policy_approvals(self) -> int:
        if self.policy_approvals_required is not None:
            return self.policy_approvals_required
        return 2 if self.environment is Environment.PRODUCTION else 0

    @property
    def operators_allowed(self) -> set[str] | None:
        if not self.operator_allowlist:
            return None
        return {o.strip() for o in self.operator_allowlist.split(",") if o.strip()}

    def service_problems(self) -> list[str]:
        """Settings the HTTP service refuses to start with (checked only when serving, so
        batch and CLI jobs need no service configuration)."""
        problems: list[str] = []
        hosted = self.environment in {Environment.STAGING, Environment.PRODUCTION}
        if not hosted:
            return problems
        env = self.environment.value
        if not self.webauthn_origin.startswith("https://"):
            problems.append(f"{env} requires an https WEBAUTHN_ORIGIN")
        for name, secret in self._secret_values().items():
            if looks_default(secret):
                problems.append(f"{name} looks like a default/placeholder secret")
        password = make_url(self.resolved_database_url).password
        if password is not None and looks_default(str(password)):
            problems.append("DATABASE_URL uses a default/placeholder password")
        for origin in self.cors_origins:
            if origin == "*" or not origin.startswith("https://"):
                problems.append(f"{env} refuses the CORS origin {origin!r} (https only, no *)")
        if self.requires_model_signatures and not self.model_signing_public_keys:
            problems.append(
                "model signatures are required but MODEL_SIGNING_PUBLIC_KEYS is not set"
            )
        if self.environment is Environment.PRODUCTION:
            if self.local_llm_runtime == "reference" and not self.allow_reference_llm:
                problems.append(
                    "production refuses the reference LLM template unless ALLOW_REFERENCE_LLM"
                )
            if not self.service_require_signatures:
                problems.append("production requires SERVICE_REQUIRE_SIGNATURES=true")
        return problems

    def _secret_values(self) -> dict[str, str]:
        values = {
            "PSEUDONYMISATION_KEY": self.pseudonymisation_key,
            "SERVICE_SIGNING_MASTER_KEY": self.service_signing_master_key,
            "SERVICE_SIGNING_PREVIOUS_KEY": self.service_signing_previous_key,
            "PAYMENT_AUTH_WEBHOOK_SECRET": self.payment_auth_webhook_secret,
            "STRIPE_API_KEY": self.stripe_api_key,
        }
        out = {k: v.get_secret_value() for k, v in values.items() if v is not None}
        if self.redis_url is not None:
            redis_password = urlparse(self.redis_url.get_secret_value()).password
            if redis_password:
                out["REDIS_URL password"] = redis_password
        return out

    @property
    def requires_promotion(self) -> bool:
        if self.policy_require_promotion is not None:
            return self.policy_require_promotion
        return self.environment in {Environment.STAGING, Environment.PRODUCTION}

    @property
    def effective_signature_min_version(self) -> str:
        if self.signature_min_version is not None:
            return self.signature_min_version
        return "v2" if self.environment is Environment.PRODUCTION else "v1"

    @property
    def effective_log_format(self) -> str:
        if self.log_format:
            return self.log_format
        hosted = self.environment in {Environment.STAGING, Environment.PRODUCTION}
        return "json" if hosted else "text"

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
