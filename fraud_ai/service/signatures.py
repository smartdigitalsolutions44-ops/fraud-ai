"""Signed requests and callbacks: HMAC-SHA256 with timestamps and persisted replay
protection (no FastAPI dependency).

Scheme (``v1``)::

    X-Fraud-Timestamp: <unix seconds>
    X-Fraud-Signature: v1=<hex HMAC-SHA256(secret, "<timestamp>." + raw_request_body)>

A request is rejected when:

* the headers are missing or malformed;
* the timestamp is more than ``max_age`` seconds away from the server clock, in either
  direction;
* the signature does not match (compared in constant time);
* the same signature was already accepted (a **replay**).

Accepted signatures are stored in ``request_replay_tokens`` until they expire. The unique
constraint means two concurrent replays cannot both pass. A legitimate retry must be
signed again with a fresh timestamp; idempotency (Idempotency-Key and ``event_id``) then
returns the original result.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.models import RequestReplayToken

SIGNATURE_VERSION = "v1"


class SignatureError(FraudAIError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def sign(secret: str, timestamp: int, body: bytes) -> str:
    digest = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
    return f"{SIGNATURE_VERSION}={digest.hexdigest()}"


def check_signature(
    secret: str,
    timestamp_header: str | None,
    signature_header: str | None,
    body: bytes,
    *,
    now: datetime,
    max_age: int,
) -> datetime:
    """Validate format, freshness and the HMAC. Returns the signed time."""
    if not timestamp_header or not signature_header:
        raise SignatureError("MISSING_SIGNATURE", "signature headers are required")
    try:
        timestamp = int(timestamp_header)
        signed_at = datetime.fromtimestamp(timestamp, UTC)
    except (ValueError, OverflowError, OSError):
        raise SignatureError("INVALID_SIGNATURE", "malformed signature timestamp") from None
    if abs((now - signed_at).total_seconds()) > max_age:
        raise SignatureError(
            "EXPIRED_SIGNATURE", f"signature timestamp is outside the {max_age}s window"
        )
    if not hmac.compare_digest(sign(secret, timestamp, body), signature_header.strip()):
        raise SignatureError("INVALID_SIGNATURE", "signature does not match")
    return signed_at


def remember(
    session: Session,
    signer: str,
    signature: str,
    signed_at: datetime,
    *,
    max_age: int,
    now: datetime | None = None,
) -> None:
    """Record an accepted signature; a second use raises ``REPLAYED_SIGNATURE``.

    Runs in the caller's session, which should commit straight away, so the token exists
    before any processing.
    """
    now = now or datetime.now(UTC)
    session.execute(delete(RequestReplayToken).where(RequestReplayToken.expires_at < now))
    token = hashlib.sha256(f"{signer}|{signature}".encode()).hexdigest()
    savepoint = session.begin_nested()
    try:
        session.add(
            RequestReplayToken(
                signer=signer,
                signature_sha256=token,
                signed_at=signed_at,
                expires_at=signed_at + timedelta(seconds=max_age),
            )
        )
        session.flush()
        savepoint.commit()
    except IntegrityError:
        savepoint.rollback()
        raise SignatureError("REPLAYED_SIGNATURE", "this signed request was already used") from None
