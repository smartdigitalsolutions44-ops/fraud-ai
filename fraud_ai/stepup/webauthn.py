"""WebAuthn / passkey step-up using the maintained ``webauthn`` (py_webauthn) library.

No cryptography is implemented here. The library verifies:

* the attestation;
* the assertion signature over ``authenticatorData || SHA-256(clientDataJSON)``;
* the RP ID hash, the origin, and user presence and verification;
* the signature counter.

This module manages the surrounding state:

* **Credentials.** Only the credential id, the COSE *public* key, the sign counter,
  transports, the user reference, timestamps and status are stored. The private key
  never leaves the user's authenticator.
* **Challenges:**
  * 32 random bytes from ``secrets.token_bytes`` via the library;
  * **single use:** consumed atomically with ``UPDATE … WHERE consumed_at IS NULL``, so a
    replayed or concurrent second use fails;
  * **short lived** (``WEBAUTHN_CHALLENGE_TTL``);
  * **bound** to the user, the session and the assessment.

  Only the challenge's SHA-256 is stored. On completion, the challenge inside the
  client's signed ``clientDataJSON`` is hashed and matched against it before the library
  verifies the signature.
* **User handle.** It is a one-way hash of the user id, not the id itself, and the user
  name shown to authenticators is a pseudonym. No personal data is sent to the client.

Any storage or verification error fails closed. Nothing is authenticated implicitly.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    bytes_to_base64url,
    parse_authentication_credential_json,
    parse_client_data_json,
    parse_registration_credential_json,
)
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from fraud_ai.core.enums import (
    AuthenticationMethod,
    AuthenticationResult,
    ChallengePurpose,
    CredentialStatus,
)
from fraud_ai.database.models import (
    AuthenticationAttempt,
    AuthenticationChallenge,
    RiskAssessment,
    User,
    WebAuthnCredential,
)
from fraud_ai.stepup.outcomes import (
    StepUpError,
    ensure_attempts_left,
    record_attempt,
    step_up_target,
)


@dataclass(frozen=True)
class WebAuthnConfig:
    rp_id: str
    rp_name: str
    origin: str
    challenge_ttl: int = 120
    max_attempts: int = 3


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def user_handle(user_id: uuid.UUID) -> bytes:
    return hashlib.sha256(f"fraud-ai-webauthn-user:{user_id}".encode()).digest()[:32]


def _pseudonym(user_id: uuid.UUID) -> str:
    return "user-" + hashlib.sha256(f"fraud-ai-webauthn-name:{user_id}".encode()).hexdigest()[:12]


def _store_challenge(
    session: Session,
    challenge: bytes,
    purpose: ChallengePurpose,
    user_id: uuid.UUID,
    *,
    ttl: int,
    now: datetime,
    session_id: str | None = None,
    assessment_id: uuid.UUID | None = None,
    api_key_id: str | None = None,
) -> AuthenticationChallenge:
    row = AuthenticationChallenge(
        purpose=purpose,
        challenge_sha256=_sha256(challenge),
        user_id=user_id,
        session_id=session_id,
        assessment_id=assessment_id,
        api_key_id=api_key_id,
        created_at=now,
        expires_at=now + timedelta(seconds=ttl),
    )
    session.add(row)
    session.flush()
    return row


def _consume(
    session: Session, challenge_id: uuid.UUID, purpose: ChallengePurpose, now: datetime
) -> AuthenticationChallenge:
    """Atomically mark the challenge used. Unknown, wrong-purpose or already-used
    challenges fail (replay protection)."""
    result = session.execute(
        update(AuthenticationChallenge)
        .where(
            AuthenticationChallenge.challenge_id == challenge_id,
            AuthenticationChallenge.purpose == purpose,
            AuthenticationChallenge.consumed_at.is_(None),
        )
        .values(consumed_at=now)
        .execution_options(synchronize_session=False)
    )
    if getattr(result, "rowcount", 0) != 1:
        raise StepUpError("CHALLENGE_INVALID", "unknown, used or replayed challenge", 409)
    row = session.get(AuthenticationChallenge, challenge_id)
    assert row is not None
    session.refresh(row)
    return row


def _client_challenge(client_data_b64: bytes) -> bytes:
    return parse_client_data_json(client_data_b64).challenge


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


# ------------------------------------------------------------------ registration
def start_registration(
    session: Session,
    config: WebAuthnConfig,
    user_id: uuid.UUID,
    *,
    now: datetime,
    api_key_id: str | None = None,
) -> tuple[AuthenticationChallenge, dict[str, Any]]:
    if session.get(User, user_id) is None:
        raise StepUpError("NOT_FOUND", "unknown user", 404)
    existing = [
        PublicKeyCredentialDescriptor(id=_b64decode(c.credential_id))
        for c in _credentials(session, user_id)
    ]
    options = generate_registration_options(
        rp_id=config.rp_id,
        rp_name=config.rp_name,
        user_name=_pseudonym(user_id),
        user_id=user_handle(user_id),
        exclude_credentials=existing,
        timeout=config.challenge_ttl * 1000,
    )
    row = _store_challenge(
        session,
        options.challenge,
        ChallengePurpose.REGISTRATION,
        user_id,
        ttl=config.challenge_ttl,
        now=now,
        api_key_id=api_key_id,
    )
    return row, json.loads(options_to_json(options))


def finish_registration(
    session: Session,
    config: WebAuthnConfig,
    challenge_id: uuid.UUID,
    credential: dict[str, Any],
    *,
    now: datetime,
) -> WebAuthnCredential:
    challenge = _consume(session, challenge_id, ChallengePurpose.REGISTRATION, now)
    if _utc(challenge.expires_at) < now:
        raise StepUpError("CHALLENGE_EXPIRED", "the registration challenge has expired", 410)
    try:
        parsed = parse_registration_credential_json(credential)
        client_challenge = _client_challenge(parsed.response.client_data_json)
        if _sha256(client_challenge) != challenge.challenge_sha256:
            raise StepUpError("VERIFICATION_FAILED", "challenge mismatch", 422)
        verified = verify_registration_response(
            credential=parsed,
            expected_challenge=client_challenge,
            expected_rp_id=config.rp_id,
            expected_origin=config.origin,
            require_user_verification=True,
        )
    except StepUpError:
        raise
    except (WebAuthnException, ValueError, KeyError, TypeError) as exc:
        raise StepUpError(
            "VERIFICATION_FAILED", f"registration could not be verified: {type(exc).__name__}", 422
        ) from None
    credential_id = bytes_to_base64url(verified.credential_id)
    if session.scalar(
        select(WebAuthnCredential).where(WebAuthnCredential.credential_id == credential_id)
    ):
        raise StepUpError("CREDENTIAL_EXISTS", "this credential is already registered", 409)
    row = WebAuthnCredential(
        credential_id=credential_id,
        user_id=challenge.user_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        transports=[t for t in credential.get("response", {}).get("transports", []) or []],
        created_at=now,
    )
    session.add(row)
    session.flush()
    return row


def _credentials(session: Session, user_id: uuid.UUID) -> list[WebAuthnCredential]:
    return list(
        session.scalars(
            select(WebAuthnCredential).where(
                WebAuthnCredential.user_id == user_id,
                WebAuthnCredential.status == CredentialStatus.ACTIVE,
            )
        )
    )


def _b64decode(value: str) -> bytes:
    from webauthn.helpers import base64url_to_bytes

    return base64url_to_bytes(value)


# ------------------------------------------------------------------ authentication (step-up)
def start_authentication(
    session: Session,
    config: WebAuthnConfig,
    assessment_id: uuid.UUID,
    *,
    session_id: str,
    now: datetime,
    api_key_id: str | None = None,
) -> tuple[AuthenticationChallenge, dict[str, Any]]:
    assessment = step_up_target(session, assessment_id)
    ensure_attempts_left(session, assessment.assessment_id, config.max_attempts)
    if assessment.user_id is None:
        raise StepUpError("NO_USER", "the assessed event has no user", 409)
    credentials = _credentials(session, assessment.user_id)
    if not credentials:
        raise StepUpError(
            "NO_CREDENTIALS",
            "the user has no registered passkey; use another step-up method or review",
            409,
        )
    options = generate_authentication_options(
        rp_id=config.rp_id,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=_b64decode(c.credential_id)) for c in credentials
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=config.challenge_ttl * 1000,
    )
    row = _store_challenge(
        session,
        options.challenge,
        ChallengePurpose.AUTHENTICATION,
        assessment.user_id,
        ttl=config.challenge_ttl,
        now=now,
        session_id=session_id,
        assessment_id=assessment.assessment_id,
        api_key_id=api_key_id,
    )
    return row, json.loads(options_to_json(options))


@dataclass(frozen=True)
class StepUpCompletion:
    result: AuthenticationResult
    attempt: AuthenticationAttempt
    followup: RiskAssessment | None
    failure_reason: str | None


def finish_authentication(
    session: Session,
    config: WebAuthnConfig,
    challenge_id: uuid.UUID,
    credential: dict[str, Any],
    *,
    session_id: str,
    now: datetime,
) -> StepUpCompletion:
    challenge = _consume(session, challenge_id, ChallengePurpose.AUTHENTICATION, now)
    assert challenge.assessment_id is not None
    assessment = step_up_target(session, challenge.assessment_id)
    result, reason, credential_row = _verify_assertion(
        session, config, challenge, credential, session_id=session_id, now=now
    )
    if result is AuthenticationResult.SUCCESS and credential_row is not None:
        credential_row.last_used_at = now
    attempt, followup = record_attempt(
        session,
        assessment,
        AuthenticationMethod.WEBAUTHN,
        result,
        max_attempts=config.max_attempts,
        failure_reason=reason,
        credential_ref=credential_row.credential_id[:100] if credential_row else None,
        challenge_id=challenge.challenge_id,
    )
    return StepUpCompletion(result, attempt, followup, reason)


def cancel_authentication(
    session: Session, config: WebAuthnConfig, challenge_id: uuid.UUID, *, now: datetime
) -> StepUpCompletion:
    challenge = _consume(session, challenge_id, ChallengePurpose.AUTHENTICATION, now)
    assert challenge.assessment_id is not None
    assessment = step_up_target(session, challenge.assessment_id)
    attempt, followup = record_attempt(
        session,
        assessment,
        AuthenticationMethod.WEBAUTHN,
        AuthenticationResult.CANCELLED,
        max_attempts=config.max_attempts,
        failure_reason="cancelled_by_user",
        challenge_id=challenge.challenge_id,
    )
    return StepUpCompletion(AuthenticationResult.CANCELLED, attempt, followup, "cancelled_by_user")


def _verify_assertion(
    session: Session,
    config: WebAuthnConfig,
    challenge: AuthenticationChallenge,
    credential: dict[str, Any],
    *,
    session_id: str,
    now: datetime,
) -> tuple[AuthenticationResult, str | None, WebAuthnCredential | None]:
    if _utc(challenge.expires_at) < now:
        return AuthenticationResult.EXPIRED, "challenge_expired", None
    if challenge.session_id != session_id:
        return AuthenticationResult.FAILED, "session_mismatch", None
    try:
        parsed = parse_authentication_credential_json(credential)
    except (WebAuthnException, ValueError, KeyError, TypeError):
        return AuthenticationResult.FAILED, "malformed_credential", None
    stored = session.scalar(
        select(WebAuthnCredential).where(
            WebAuthnCredential.credential_id == bytes_to_base64url(parsed.raw_id)
        )
    )
    if (
        stored is None
        or stored.user_id != challenge.user_id
        or stored.status is not CredentialStatus.ACTIVE
    ):
        return AuthenticationResult.FAILED, "unknown_credential", None
    try:
        client_challenge = _client_challenge(parsed.response.client_data_json)
    except (WebAuthnException, ValueError, KeyError, TypeError):
        return AuthenticationResult.FAILED, "malformed_client_data", stored
    if _sha256(client_challenge) != challenge.challenge_sha256:
        return AuthenticationResult.FAILED, "challenge_mismatch", stored
    try:
        verified = verify_authentication_response(
            credential=parsed,
            expected_challenge=client_challenge,
            expected_rp_id=config.rp_id,
            expected_origin=config.origin,
            credential_public_key=stored.public_key,
            credential_current_sign_count=stored.sign_count,
            require_user_verification=True,
        )
    except WebAuthnException as exc:
        reason = "sign_count_regression" if "count" in str(exc).lower() else "verification_failed"
        return AuthenticationResult.FAILED, reason, stored
    stored.sign_count = verified.new_sign_count
    return AuthenticationResult.SUCCESS, None, stored
