"""Request idempotency for ``POST`` endpoints (the ``Idempotency-Key`` header).

The key is scoped to (API key, route, ``Idempotency-Key``). The row stores the SHA-256 of
the raw request body, the policy version that answered, and the response.

| Situation | Result |
|---|---|
| new key | a placeholder row (``in_progress``) is **committed first**, then the request runs |
| same key, same body, completed | the stored response is replayed (``Idempotent-Replayed: true``) |
| same key, **different** body | 409 ``IDEMPOTENCY_KEY_REUSED``; the request is not processed |
| same key while the first request is still running | 409 ``IDEMPOTENCY_IN_PROGRESS`` |
| the request fails (non-2xx or an exception) | the placeholder is deleted; the key can be retried |

Only the unique constraint decides the race. Two concurrent first uses cannot both
proceed. Replays return the original assessment even if the active policy has changed
since. Assessments are immutable, and the stored response carries the policy version that
made the decision. Stage 8 event-id idempotency still applies underneath, so a
redelivered event never gets a second decision.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from fraud_ai.database.engine import write_scope
from fraud_ai.database.models import RequestIdempotency
from fraud_ai.service.errors import ApiError

KEY_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{8,100}$")
IN_PROGRESS, COMPLETED = "in_progress", "completed"


@dataclass(frozen=True)
class Stored:
    status_code: int
    body: dict[str, Any]


def body_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def validate_key(value: str) -> str:
    if not KEY_PATTERN.match(value):
        raise ApiError(
            400,
            "INVALID_IDEMPOTENCY_KEY",
            "Idempotency-Key must be 8-100 characters of [A-Za-z0-9_.:-]",
        )
    return value


def begin(
    factory: sessionmaker[Session], api_key_id: str, route: str, key: str, digest: str
) -> tuple[uuid.UUID | None, Stored | None]:
    """``(placeholder_id, None)`` to proceed, or ``(None, stored)`` to replay."""
    try:
        with write_scope(factory) as session:
            row = RequestIdempotency(
                api_key_id=api_key_id,
                route=route,
                idempotency_key=key,
                request_sha256=digest,
                state=IN_PROGRESS,
            )
            session.add(row)
            session.flush()
            return row.record_id, None
    except IntegrityError:
        pass
    with factory() as session:
        existing = session.scalar(
            select(RequestIdempotency).where(
                RequestIdempotency.api_key_id == api_key_id,
                RequestIdempotency.route == route,
                RequestIdempotency.idempotency_key == key,
            )
        )
        if existing is None:  # the first request failed and was cleaned up meanwhile
            raise ApiError(409, "IDEMPOTENCY_IN_PROGRESS", "retry the request")
        if existing.request_sha256 != digest:
            raise ApiError(
                409,
                "IDEMPOTENCY_KEY_REUSED",
                "this Idempotency-Key was already used with a different request body",
            )
        if existing.state != COMPLETED or existing.status_code is None:
            raise ApiError(
                409,
                "IDEMPOTENCY_IN_PROGRESS",
                "a request with this Idempotency-Key is still being processed",
                headers={"Retry-After": "1"},
            )
        return None, Stored(existing.status_code, dict(existing.response_body or {}))


def complete(
    factory: sessionmaker[Session],
    record_id: uuid.UUID,
    status_code: int,
    body: dict[str, Any],
    policy_version: str | None,
) -> None:
    with write_scope(factory) as session:
        row = session.get(RequestIdempotency, record_id)
        if row is None:  # pragma: no cover - only deleted on failure
            return
        row.state = COMPLETED
        row.status_code = status_code
        row.response_body = body
        row.policy_version = policy_version


def abandon(factory: sessionmaker[Session], record_id: uuid.UUID) -> None:
    with write_scope(factory) as session:
        session.execute(delete(RequestIdempotency).where(RequestIdempotency.record_id == record_id))
