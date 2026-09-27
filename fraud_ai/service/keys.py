"""Service-to-service API keys (no FastAPI dependency; used by the CLI and the API).

A presented credential is ``<key_id>.<secret>``, for example ``fak_1a2b3c4d5e6f7a8b.X…``:

* ``key_id``: a public identifier (``fak_`` plus 16 hex characters), stored in clear.
* ``secret``: 32 random bytes from :func:`secrets.token_urlsafe` (256 bits). It is
  **shown once** at creation and stored only as ``SHA-256(salt || secret)`` with a
  per-key random salt.

A fast hash is appropriate here because the secret is a high-entropy random value, not
a human password, so there is nothing to brute-force. Comparison always uses
:func:`hmac.compare_digest` (constant time). An unknown key id still costs one hash and
one comparison, so response timing does not reveal which ids exist.

**Signing secrets** for signed requests are *derived*:
``HMAC-SHA256(SERVICE_SIGNING_MASTER_KEY, "fraud-ai-signing:" + key_id)``. The server
can recompute them from the master key, which lives in the environment or a secret
manager. They are never stored.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.models import ServiceApiKey

KEY_PREFIX = "fak_"
KEY_ID_PATTERN = re.compile(r"^fak_[0-9a-f]{16}$")
SECRET_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,100}$")

SCOPES: dict[str, str] = {
    "score:write": "POST /v1/score",
    "score:replay": "supply a recorded arrival_time when scoring (backfill tooling only)",
    "signals:trusted": "submit network-intelligence flags as trusted infrastructure signals",
    "assessment:read": "GET /v1/assessments/{id}",
    "review:read": "GET /v1/reviews, GET /v1/reviews/{id}",
    "review:write": "POST /v1/reviews/{id}/resolve",
    "policy:read": "GET /v1/policy",
    "stepup:write": "start and complete step-up authentication",
    "webauthn:write": "register passkeys for a user",
    "investigation:write": "POST /v1/assessments/{id}/investigate (analyst-triggered LLM)",
    "metrics:read": "GET /v1/metrics",
}
_DUMMY_SALT = "0" * 32
_DUMMY_HASH = hashlib.sha256(b"fraud-ai-dummy").hexdigest()


class ServiceKeyError(FraudAIError):
    pass


@dataclass(frozen=True)
class IssuedKey:
    key_id: str
    secret: str
    scopes: tuple[str, ...]

    @property
    def credential(self) -> str:
        return f"{self.key_id}.{self.secret}"


@dataclass(frozen=True)
class VerifiedKey:
    key_id: str
    scopes: frozenset[str]


def _hash(salt: str, secret: str) -> str:
    return hashlib.sha256(f"{salt}:{secret}".encode()).hexdigest()


def create_key(session: Session, name: str, scopes: list[str]) -> IssuedKey:
    unknown = sorted(set(scopes) - set(SCOPES))
    if unknown:
        raise ServiceKeyError(f"unknown scope(s) {unknown}; known: {sorted(SCOPES)}")
    if not scopes:
        raise ServiceKeyError("a key needs at least one scope")
    if not 1 <= len(name) <= 100:
        raise ServiceKeyError("name must be 1-100 characters")
    key_id = KEY_PREFIX + secrets.token_hex(8)
    secret = secrets.token_urlsafe(32)
    salt = secrets.token_hex(16)
    session.add(
        ServiceApiKey(
            key_id=key_id,
            name=name,
            secret_salt=salt,
            secret_sha256=_hash(salt, secret),
            scopes=sorted(set(scopes)),
        )
    )
    session.flush()
    return IssuedKey(key_id, secret, tuple(sorted(set(scopes))))


def parse_credential(presented: str) -> tuple[str, str] | None:
    key_id, _, secret = presented.strip().partition(".")
    if not KEY_ID_PATTERN.match(key_id) or not SECRET_PATTERN.match(secret):
        return None
    return key_id, secret


def verify_key(session: Session, presented: str | None) -> VerifiedKey | None:
    """The verified key, or ``None`` for missing, malformed, unknown, wrong or revoked
    credentials. The caller answers all of them the same way."""
    parsed = parse_credential(presented or "")
    if parsed is None:
        hmac.compare_digest(_DUMMY_HASH, _hash(_DUMMY_SALT, "x"))
        return None
    key_id, secret = parsed
    row = session.scalar(select(ServiceApiKey).where(ServiceApiKey.key_id == key_id))
    if row is None:
        hmac.compare_digest(_DUMMY_HASH, _hash(_DUMMY_SALT, secret))
        return None
    matches = hmac.compare_digest(row.secret_sha256, _hash(row.secret_salt, secret))
    if not matches or row.revoked_at is not None:
        return None
    return VerifiedKey(row.key_id, frozenset(row.scopes))


def revoke_key(session: Session, key_id: str) -> ServiceApiKey:
    row = session.scalar(select(ServiceApiKey).where(ServiceApiKey.key_id == key_id))
    if row is None:
        raise ServiceKeyError(f"unknown key {key_id}")
    if row.revoked_at is None:
        row.revoked_at = datetime.now(UTC)
        session.flush()
    return row


def list_keys(session: Session) -> list[ServiceApiKey]:
    return list(session.scalars(select(ServiceApiKey).order_by(ServiceApiKey.created_at)))


def signing_secret(master_key: str, key_id: str) -> str:
    return hmac.new(
        master_key.encode(), f"fraud-ai-signing:{key_id}".encode(), hashlib.sha256
    ).hexdigest()
