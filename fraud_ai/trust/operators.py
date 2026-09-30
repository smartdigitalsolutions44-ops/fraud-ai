"""Operator authentication for administrative actions (Stage 12).

Stage 11's ``OPERATOR_ID`` was configuration, not authentication. Stage 12 authenticates
each administrative action with a **signed assertion** from the operator's own key.

**Standards used.**

* The assertion is a JWT (RFC 7519) signed with EdDSA/Ed25519 (RFC 8037), created and
  checked with PyJWT.
* It is used the way OAuth's ``private_key_jwt`` client assertion (RFC 7523) is: the
  holder of a registered private key proves its identity to a verifier that knows only the
  public key.

Nothing cryptographic is home-made.

**Registry.** ``OPERATOR_REGISTRY_FILE`` is trusted configuration, deployed like the
trusted model keys (reviewed, not writable by the service):

.. code-block:: json

    {"version": 1, "operators": [
      {"id": "alice", "roles": ["policy_approver"], "public_keys": ["<base64url Ed25519>"]},
      {"id": "sec", "roles": ["security_admin"], "public_keys": ["..."], "disabled": false}]}

**Roles** (:data:`ROLES`): ``reviewer``, ``policy_approver``, ``policy_activator`` and
``security_admin``. Authorisation comes from the registry entry of the key that signed the
assertion. It never comes from a string the caller supplies: an assertion carries no roles.

**Assertion claims:**

* ``iss`` = ``sub`` = operator id;
* ``aud`` = ``OPERATOR_AUDIENCE``;
* ``iat``, ``nbf`` and ``exp``: lifetime at most ``OPERATOR_ASSERTION_MAX_SECONDS``, 5 min
  by default;
* ``jti``: single use;
* ``act``: the action, e.g. ``policy.approve``;
* ``tgt``: its target, e.g. the policy version;
* ``bnd``: a binding to the exact content, e.g. the policy definition's SHA-256 and the
  note's SHA-256.

A stolen assertion is therefore good for one action, on one object, with one content, for a
few minutes. A verified assertion is **consumed** (``operator_assertions``, unique ``jti``),
so it cannot be replayed.

**Checks**, all enforced:

* the header ``alg`` must be ``EdDSA``: no ``none``, and no RSA/HMAC confusion;
* ``kid`` must be a registered key of an enabled operator;
* ``iss`` and ``sub`` must name that same operator. One principal cannot sign as another;
* audience, expiry, not-before and maximum lifetime;
* action, target and binding must equal what the command is about to do;
* the operator must hold the action's role (:data:`ACTIONS`);
* the ``jti`` must not have been used before.

**Evidence.** A policy approval keeps its consumed assertion, so activation can
*re-verify* every approval cryptographically. A row inserted directly into
``policy_approvals`` (by a DBA, bypassing the tooling) has no valid assertion and does not
count. Tokens are never written to logs or audit details; the audit records the operator,
key id, action, target and ``jti``.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.trust import keys as tk

ROLES = ("reviewer", "policy_approver", "policy_activator", "security_admin")

#: Which role each administrative action needs.
ACTIONS: dict[str, str] = {
    "review.resolve": "reviewer",
    "policy.approve": "policy_approver",
    "policy.activate": "policy_activator",
    "service_key.manage": "security_admin",  # create, rotate, revoke API keys
    "signing_key.rotate": "security_admin",  # rotate a KMS signing key
    "retention.execute": "security_admin",
    "release.sign": "security_admin",
    "privacy.export": "security_admin",
    "operator.check": "reviewer|policy_approver|policy_activator|security_admin",
}

ALGORITHM = "EdDSA"
_ID = re.compile(r"^[a-z0-9._@-]{2,64}$")
_TARGET_MAX = 200
MAX_REGISTRY_BYTES = 256 * 1024


class OperatorAuthError(FraudAIError):
    """Authentication or authorisation failed. ``code`` is safe to show and to audit."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Operator:
    operator_id: str
    roles: frozenset[str]
    keys: dict[str, Ed25519PublicKey]
    disabled: bool = False

    def may(self, action: str) -> bool:
        needed = ACTIONS.get(action)
        return needed is not None and bool(set(needed.split("|")) & self.roles)


@dataclass(frozen=True)
class OperatorRegistry:
    operators: dict[str, Operator]
    sha256: str
    source: str

    @property
    def by_key(self) -> dict[str, str]:
        return {kid: op.operator_id for op in self.operators.values() for kid in op.keys}

    def public_keys(self) -> dict[str, Ed25519PublicKey]:
        return {kid: key for op in self.operators.values() for kid, key in op.keys.items()}

    @classmethod
    def parse(cls, text: str, source: str = "<registry>") -> OperatorRegistry:
        try:
            data = json.loads(text)
        except ValueError:
            raise OperatorAuthError("REGISTRY_INVALID", f"{source} is not valid JSON") from None
        if not isinstance(data, dict) or data.get("version") != 1:
            raise OperatorAuthError("REGISTRY_INVALID", f"{source}: expected version 1")
        entries = data.get("operators")
        if not isinstance(entries, list) or not entries:
            raise OperatorAuthError("REGISTRY_INVALID", f"{source}: no operators")
        operators: dict[str, Operator] = {}
        owners: dict[str, str] = {}
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) - {
                "id",
                "roles",
                "public_keys",
                "disabled",
                "name",
            }:
                raise OperatorAuthError("REGISTRY_INVALID", f"{source}: malformed operator entry")
            op_id = entry.get("id")
            if not isinstance(op_id, str) or not _ID.match(op_id):
                raise OperatorAuthError("REGISTRY_INVALID", f"{source}: invalid operator id")
            if op_id in operators:
                raise OperatorAuthError("REGISTRY_INVALID", f"{source}: duplicate id {op_id}")
            roles = entry.get("roles")
            if not isinstance(roles, list) or not roles or set(roles) - set(ROLES):
                raise OperatorAuthError(
                    "REGISTRY_INVALID", f"{source}: {op_id} has unknown or no roles"
                )
            public = entry.get("public_keys")
            if not isinstance(public, list) or not public:
                raise OperatorAuthError("REGISTRY_INVALID", f"{source}: {op_id} has no keys")
            keys: dict[str, Ed25519PublicKey] = {}
            for text_key in public:
                key = tk.decode_public(str(text_key))
                kid = tk.key_id(key)
                if kid in owners:
                    raise OperatorAuthError(
                        "REGISTRY_INVALID",
                        f"{source}: key {kid} is registered for both {owners[kid]} and {op_id}",
                    )
                owners[kid] = op_id
                keys[kid] = key
            operators[op_id] = Operator(
                op_id, frozenset(roles), keys, bool(entry.get("disabled", False))
            )
        digest = hashlib.sha256(text.encode()).hexdigest()
        return cls(operators, digest, source)

    @classmethod
    def load(cls, path: Path) -> OperatorRegistry:
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise OperatorAuthError(
                "REGISTRY_MISSING", f"cannot read OPERATOR_REGISTRY_FILE {path}: {exc.strerror}"
            ) from None
        if len(data) > MAX_REGISTRY_BYTES:
            raise OperatorAuthError("REGISTRY_INVALID", f"{path} is too large")
        return cls.parse(data.decode(errors="strict"), str(path))


def registry_from_settings(settings: Any) -> OperatorRegistry:
    path = settings.operator_registry_file
    if path is None:
        raise OperatorAuthError(
            "REGISTRY_MISSING", "operator authentication needs OPERATOR_REGISTRY_FILE"
        )
    registry = OperatorRegistry.load(Path(path))
    check_registry_separation(registry, settings)
    return registry


def check_registry_separation(registry: OperatorRegistry, settings: Any) -> None:
    """Operator keys must not double as model, audit or release keys."""
    try:
        tk.check_separation(
            {
                "model": tk.parse_public_keys(settings.model_signing_public_keys),
                "audit": tk.parse_public_keys(settings.audit_anchor_public_keys),
                "release": tk.parse_public_keys(settings.release_signing_public_keys),
                "operator": registry.public_keys(),
            }
        )
    except tk.TrustError as exc:
        raise OperatorAuthError("REGISTRY_INVALID", str(exc)) from None


@dataclass(frozen=True)
class VerifiedAssertion:
    operator_id: str
    key_id: str
    roles: frozenset[str]
    action: str
    target: str
    binding: dict[str, str]
    jti: str
    issued_at: datetime
    expires_at: datetime
    token_sha256: str

    @property
    def actor(self) -> str:
        return f"operator:{self.operator_id}"


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def create_assertion(
    signer: tk.KeyPair,
    operator_id: str,
    *,
    action: str,
    target: str,
    binding: dict[str, str] | None = None,
    audience: str,
    lifetime_seconds: int = 120,
    now: datetime | None = None,
) -> str:
    """A signed, single-use assertion (what an operator's CLI produces)."""
    if action not in ACTIONS:
        raise OperatorAuthError("UNKNOWN_ACTION", f"unknown administrative action {action!r}")
    now = now or datetime.now(UTC)
    iat = int(now.timestamp())
    claims = {
        "iss": operator_id,
        "sub": operator_id,
        "aud": audience,
        "iat": iat,
        "nbf": iat,
        "exp": iat + lifetime_seconds,
        "jti": uuid.uuid4().hex,
        "act": action,
        "tgt": target[:_TARGET_MAX],
        "bnd": dict(binding or {}),
    }
    return jwt.encode(
        claims,
        signer.private,
        algorithm=ALGORITHM,
        headers={"kid": signer.key_id, "typ": "JWT"},
    )


def _claims(
    token: str,
    registry: OperatorRegistry,
    *,
    audience: str,
    leeway: int,
) -> tuple[Operator, str, dict[str, Any]]:
    if not isinstance(token, str) or len(token) > 4096 or token.count(".") != 2:
        raise OperatorAuthError("MALFORMED_ASSERTION", "the operator assertion is malformed")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise OperatorAuthError(
            "MALFORMED_ASSERTION", "the operator assertion is malformed"
        ) from None
    if header.get("alg") != ALGORITHM:
        raise OperatorAuthError("BAD_ALGORITHM", "operator assertions must be EdDSA-signed")
    kid = header.get("kid")
    owner = registry.by_key.get(str(kid))
    if owner is None:
        raise OperatorAuthError(
            "UNKNOWN_KEY", "the assertion's key is not a registered operator key"
        )
    operator = registry.operators[owner]
    if operator.disabled:
        raise OperatorAuthError("OPERATOR_DISABLED", f"operator {owner} is disabled")
    try:
        claims = jwt.decode(
            token,
            operator.keys[str(kid)],
            algorithms=[ALGORITHM],
            audience=audience,
            leeway=leeway,
            options={
                "require": ["iss", "sub", "aud", "iat", "exp", "jti", "act", "tgt", "bnd"],
                # Times are checked by verify_assertion against the caller's clock (the
                # service clock, or the approval time for stored evidence).
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except jwt.InvalidAudienceError:
        raise OperatorAuthError("WRONG_AUDIENCE", "the assertion is for another audience") from None
    except jwt.PyJWTError:
        raise OperatorAuthError(
            "INVALID_ASSERTION", "the operator assertion does not verify"
        ) from None
    if claims.get("iss") != owner or claims.get("sub") != owner:
        # A registered key signing in another operator's name: impersonation.
        raise OperatorAuthError(
            "IDENTITY_MISMATCH", "the assertion names a different operator than its key"
        )
    return operator, str(kid), claims


def verify_assertion(
    token: str,
    registry: OperatorRegistry,
    *,
    audience: str,
    action: str,
    target: str,
    binding: dict[str, str] | None = None,
    max_lifetime: int = 300,
    leeway: int = 30,
    now: datetime | None = None,
    at: datetime | None = None,
) -> VerifiedAssertion:
    """Verify an assertion for exactly this action, target and binding.

    ``at`` re-verifies stored evidence: the assertion must have been valid *at that time*
    (e.g. when an approval was recorded) instead of now."""
    now = now or datetime.now(UTC)
    operator, kid, claims = _claims(token, registry, audience=audience, leeway=leeway)
    try:
        iat, exp = int(claims["iat"]), int(claims["exp"])
        nbf = int(claims.get("nbf", iat))
    except (TypeError, ValueError):
        raise OperatorAuthError("INVALID_ASSERTION", "malformed assertion times") from None
    if exp - iat > max_lifetime or exp <= iat:
        raise OperatorAuthError(
            "LIFETIME_TOO_LONG", f"operator assertions may live at most {max_lifetime} s"
        )
    when = (at or now).timestamp()
    if max(iat, nbf) > when + leeway:
        raise OperatorAuthError("NOT_YET_VALID", "the assertion is not valid yet")
    if when >= exp + leeway:
        raise OperatorAuthError(
            "EXPIRED_ASSERTION",
            "the assertion has expired" if at is None else "the assertion was not valid then",
        )
    if claims.get("act") != action:
        raise OperatorAuthError("WRONG_ACTION", f"the assertion is not for {action}")
    if claims.get("tgt") != target[:_TARGET_MAX]:
        raise OperatorAuthError("WRONG_TARGET", "the assertion is for a different target")
    bnd = claims.get("bnd")
    if not isinstance(bnd, dict) or bnd != dict(binding or {}):
        raise OperatorAuthError(
            "WRONG_BINDING", "the assertion covers different content than this action"
        )
    if not operator.may(action):
        raise OperatorAuthError(
            "FORBIDDEN", f"operator {operator.operator_id} lacks the role for {action}"
        )
    return VerifiedAssertion(
        operator_id=operator.operator_id,
        key_id=kid,
        roles=operator.roles,
        action=action,
        target=target,
        binding=dict(binding or {}),
        jti=str(claims["jti"])[:64],
        issued_at=datetime.fromtimestamp(iat, UTC),
        expires_at=datetime.fromtimestamp(exp, UTC),
        token_sha256=hashlib.sha256(token.encode()).hexdigest(),
    )


def consume(session: Session, verified: VerifiedAssertion, *, now: datetime | None = None) -> None:
    """Record the ``jti`` (single use) and audit the authentication, in the caller's
    transaction: if the action fails and rolls back, the assertion stays unused."""
    from fraud_ai import audit
    from fraud_ai.database.models import OperatorAssertion

    now = now or datetime.now(UTC)
    row = OperatorAssertion(
        jti=verified.jti,
        operator_id=verified.operator_id,
        key_id=verified.key_id,
        action=verified.action,
        target=verified.target[:_TARGET_MAX],
        issued_at=verified.issued_at,
        expires_at=verified.expires_at,
        used_at=now,
        token_sha256=verified.token_sha256,
    )
    savepoint = session.begin_nested()
    try:
        session.add(row)
        session.flush()
        savepoint.commit()
    except IntegrityError:
        savepoint.rollback()
        raise OperatorAuthError(
            "REPLAYED_ASSERTION", "this operator assertion was already used"
        ) from None
    audit.record(
        session,
        "operator.authenticated",
        actor=verified.actor,
        target_type="operator",
        target_id=verified.operator_id,
        details={
            "action": verified.action,
            "target": verified.target[:_TARGET_MAX],
            "key_id": verified.key_id,
            "jti": verified.jti,
            "expires_at": verified.expires_at.isoformat(),
        },
        now=now,
    )


def authenticate(
    session: Session,
    settings: Any,
    token: str,
    *,
    action: str,
    target: str,
    binding: dict[str, str] | None = None,
    registry: OperatorRegistry | None = None,
    now: datetime | None = None,
) -> VerifiedAssertion:
    """Verify and consume an assertion for one administrative action."""
    registry = registry or registry_from_settings(settings)
    verified = verify_assertion(
        token,
        registry,
        audience=settings.operator_audience,
        action=action,
        target=target,
        binding=binding,
        max_lifetime=settings.operator_assertion_max_seconds,
        leeway=settings.operator_assertion_leeway_seconds,
        now=now,
    )
    consume(session, verified, now=now)
    return verified


def record_failure(
    factory: Any, *, action: str, target: str, error: OperatorAuthError, via: str
) -> None:
    """Audit a refused authentication in its own transaction (the action's own
    transaction is rolled back). Only the error code is recorded, never the token."""
    from fraud_ai import audit
    from fraud_ai.database import session_scope

    try:
        with session_scope(factory) as session:
            audit.record(
                session,
                "operator.authentication_failed",
                actor=f"unauthenticated:{via}",
                target_type="operator",
                details={"action": action, "target": target[:_TARGET_MAX], "code": error.code},
            )
    except Exception:  # noqa: S110  # nosec B110 - auditing a refusal must not mask it
        pass
