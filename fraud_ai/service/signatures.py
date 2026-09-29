"""Signed requests and callbacks: HMAC-SHA256 with timestamps and persisted replay
protection (no FastAPI dependency).

Scheme ``v1`` (Stage 9; kept for migration)::

    X-Fraud-Timestamp: <unix seconds>
    X-Fraud-Signature: v1=<hex HMAC-SHA256(secret, "<timestamp>." + raw_request_body)>

Scheme ``v2`` (Stage 11; preferred) binds the method, the canonical path and query, the
timestamp and the SHA-256 of the body::

    canonical = "fraud-ai-v2" \n METHOD \n CANONICAL_TARGET \n TIMESTAMP \n hex(SHA256(body))
    X-Fraud-Signature: v2=<hex HMAC-SHA256(secret, canonical)>

``CANONICAL_TARGET`` is the path, percent-decoded and re-encoded (RFC 3986 unreserved
characters and ``/`` kept literally, everything else ``%XX`` upper-case), then ``?`` and the
query parameters (blank values kept) sorted by name and value and encoded the same way. It
is omitted with its ``?`` when there is no query. A client may send both schemes
(``v1=…,v2=…``) during a migration: the server then verifies **only** the strongest one
present and never falls back to a weaker one. ``SIGNATURE_MIN_VERSION`` refuses anything
below it (``SIGNATURE_VERSION_REJECTED``) instead of silently accepting it.

A request is rejected when:

* the headers are missing or malformed;
* the timestamp is more than ``max_age`` seconds away from the server clock, in either
  direction;
* the signature does not match (compared in constant time);
* the same signature was already accepted (a **replay**).

Accepted signatures are stored in ``request_replay_tokens`` (or claimed in Redis) until they
expire. A legitimate retry must be signed again with a fresh timestamp; idempotency
(Idempotency-Key and ``event_id``) then returns the original result.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qsl, quote, unquote

from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.database.models import RequestReplayToken
from fraud_ai.state.base import SharedState

SIGNATURE_VERSION = "v1"
VERSIONS = ("v1", "v2")
V2_CONTEXT = "fraud-ai-v2"


class SignatureError(FraudAIError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def sign(secret: str, timestamp: int, body: bytes) -> str:
    """A ``v1`` signature (timestamp + body only)."""
    digest = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
    return f"{SIGNATURE_VERSION}={digest.hexdigest()}"


def _encode(value: str) -> str:
    return quote(value, safe="-._~")


def canonical_target(path: str, query: str = "") -> str:
    """The canonical path and query of a request (see the module docstring)."""
    canonical_path = quote(unquote(path), safe="/-._~") or "/"
    pairs = sorted(parse_qsl(query, keep_blank_values=True))
    if not pairs:
        return canonical_path
    return canonical_path + "?" + "&".join(f"{_encode(k)}={_encode(v)}" for k, v in pairs)


def canonical_v2(method: str, path: str, query: str, timestamp: int, body: bytes) -> bytes:
    return "\n".join(
        (
            V2_CONTEXT,
            method.upper(),
            canonical_target(path, query),
            str(timestamp),
            hashlib.sha256(body).hexdigest(),
        )
    ).encode()


def sign_v2(
    secret: str, method: str, path: str, timestamp: int, body: bytes, *, query: str = ""
) -> str:
    """A ``v2`` signature over method, canonical path/query, timestamp and body digest."""
    message = canonical_v2(method, path, query, timestamp, body)
    return "v2=" + hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class RequestTarget:
    """What a ``v2`` signature binds besides the timestamp and the body."""

    method: str
    path: str
    query: str = ""


def parse_signature_header(header: str) -> dict[str, str]:
    """``"v1=ab…,v2=cd…"`` -> ``{"v1": "ab…", "v2": "cd…"}``; unknown or duplicate
    versions and malformed values are an ``INVALID_SIGNATURE``."""
    found: dict[str, str] = {}
    for part in header.split(","):
        version, sep, value = part.strip().partition("=")
        value = value.strip()
        if (
            not sep
            or version not in VERSIONS
            or version in found
            or len(value) != 64
            or any(ch not in "0123456789abcdef" for ch in value)
        ):
            raise SignatureError("INVALID_SIGNATURE", "malformed signature header")
        found[version] = value
    return found


def select_signature(header: str, min_version: str) -> tuple[str, str]:
    """The strongest signature present, or ``SIGNATURE_VERSION_REJECTED`` when it is below
    ``min_version``. Never a weaker one when a stronger one is present (no downgrade)."""
    found = parse_signature_header(header)
    version = max(found, key=VERSIONS.index)
    if VERSIONS.index(version) < VERSIONS.index(min_version):
        raise SignatureError(
            "SIGNATURE_VERSION_REJECTED",
            f"signature {version} is not accepted; this service requires {min_version} or later",
        )
    return version, f"{version}={found[version]}"


def check_signature(
    secret: str,
    timestamp_header: str | None,
    signature_header: str | None,
    body: bytes,
    *,
    now: datetime,
    max_age: int,
    target: RequestTarget | None = None,
    min_version: str = "v1",
) -> datetime:
    """Validate format, freshness and the HMAC. Returns the signed time.

    With ``target`` (service requests) the header may carry ``v1`` and/or ``v2``; the
    strongest is verified and anything below ``min_version`` is refused. Without it
    (provider callbacks) exactly one ``v1`` signature is expected."""
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
    if target is None:  # provider callbacks: a single v1 signature
        expected = sign(secret, timestamp, body)
        presented = signature_header.strip()
    else:
        version, presented = select_signature(signature_header, min_version)
        expected = (
            sign(secret, timestamp, body)
            if version == "v1"
            else sign_v2(secret, target.method, target.path, timestamp, body, query=target.query)
        )
    if not hmac.compare_digest(expected, presented):
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


def remember_shared(
    state: SharedState,
    signer: str,
    signature: str,
    signed_at: datetime,
    *,
    max_age: int,
    now: datetime,
) -> None:
    """The distributed variant of :func:`remember` (``STATE_BACKEND=redis``).

    One atomic ``SET NX`` per signature, kept until the signature would be rejected as
    expired anyway. A signature accepted by one worker is refused by every other worker.
    Backend errors raise ``StateUnavailableError`` (the caller fails closed).
    """
    token = hashlib.sha256(f"{signer}|{signature}".encode()).hexdigest()
    ttl = (signed_at + timedelta(seconds=max_age) - now).total_seconds() + 1.0
    if not state.claim("replay:" + token, max(ttl, 1.0)):
        raise SignatureError("REPLAYED_SIGNATURE", "this signed request was already used")
