"""Data inventory and erasure analysis (Stage 11).

``fraud-ai privacy inventory`` prints :data:`INVENTORY`: every stored field that holds, or
is derived from, personal data. For each: its class, purpose, retention, pseudonymisation,
access path and what deletion is possible. :func:`check_inventory` is run by the tests
against the real schema, so the inventory cannot silently drift from the tables.

``fraud-ai privacy erasure-plan <pseudonym>`` (:func:`erasure_plan`) is a **dry run**. It
never changes anything. For one user (merchant reference or internal user id) it reports:

* **erase:** rows that can be deleted without breaking fraud evidence or integrity;
* **pseudonymise:** fields that can be replaced or nulled while the row stays;
* **must remain:** records that the audit/integrity design keeps (immutable assessments,
  labels, predictions, the event log, the audit chain), with the reason;
* **dependencies:** the foreign keys that force that order.

This is an engineering analysis to support a real erasure process. It is not a legal
assessment, and it does not claim GDPR or any other compliance.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass
from typing import Any

from sqlalchemy import Table, func, select
from sqlalchemy.orm import Session

from fraud_ai.database.base import Base
from fraud_ai.database.models import (
    AuthenticationAttempt,
    PaymentAuthRequest,
    ReviewItem,
    ReviewOutcome,
    RiskAssessment,
    User,
)


@dataclass(frozen=True)
class InventoryItem:
    data_class: str
    table: str
    field: str
    purpose: str
    retention: str
    pseudonymisation: str
    access_path: str
    deletion: str


_API = "service API (scoped key) + fraud_service/fraud_readonly DB roles"
_DB = "fraud_service/fraud_readonly DB roles, CLI"
INVENTORY: tuple[InventoryItem, ...] = (
    InventoryItem(
        "customer reference",
        "users",
        "external_ref",
        "link events to a customer",
        "indefinite",
        "merchant-chosen id (should itself be a pseudonym)",
        _DB,
        "pseudonymise (erasure plan)",
    ),
    InventoryItem(
        "location (coarse)",
        "users",
        "home_country",
        "geo features",
        "indefinite",
        "country code only",
        _DB,
        "nullable",
    ),
    InventoryItem(
        "session identifier",
        "events",
        "session_id",
        "session features, step-up binding",
        "indefinite (event log)",
        "merchant session id",
        _DB,
        "must remain (immutable event log)",
    ),
    InventoryItem(
        "event payload",
        "events",
        "metadata",
        "audit of inputs, features",
        "indefinite (event log)",
        "IP/device/address hashed; free text PII-sanitised; secrets and card data refused",
        _DB,
        "must remain (immutable event log)",
    ),
    InventoryItem(
        "IP address (keyed hash)",
        "network_identities",
        "ip_hash",
        "network velocity features",
        "indefinite",
        "HMAC-SHA256 with PSEUDONYMISATION_KEY",
        _DB,
        "must remain (shared across users)",
    ),
    InventoryItem(
        "IP address (raw)",
        "network_identities",
        "ip_address",
        "investigation (optional)",
        "RETENTION_RAW_IP_DAYS (30)",
        "none: raw, only if STORE_RAW_IP=true",
        _DB,
        "nullify (retention job, erasure plan)",
    ),
    InventoryItem(
        "network observation",
        "network_events",
        "observed_at",
        "network features",
        "RETENTION_NETWORK_OBSERVATION_DAYS (off; >= 180)",
        "linked by user_id",
        _DB,
        "delete (retention job, erasure plan)",
    ),
    InventoryItem(
        "network enrichment",
        "network_identities",
        "asn_org",
        "network features",
        "indefinite",
        "operator name, PII-sanitised",
        _DB,
        "nullable",
    ),
    InventoryItem(
        "device identifier (keyed hash)",
        "devices",
        "device_hash",
        "device features",
        "indefinite",
        "HMAC-SHA256",
        _DB,
        "must remain (shared across users)",
    ),
    InventoryItem(
        "device-user link",
        "user_devices",
        "user_id",
        "device trust features",
        "indefinite",
        "internal ids",
        _DB,
        "delete (erasure plan)",
    ),
    InventoryItem(
        "address (keyed hash)",
        "addresses",
        "address_hash",
        "address features",
        "indefinite",
        "HMAC-SHA256 of the normalised address",
        _DB,
        "pseudonymise (erasure plan)",
    ),
    InventoryItem(
        "location (coarse)",
        "addresses",
        "postal_prefix",
        "geo features",
        "indefinite",
        "prefix only",
        _DB,
        "pseudonymise (null)",
    ),
    InventoryItem(
        "payment token reference",
        "payment_methods",
        "token_reference",
        "payment features, step-up",
        "indefinite",
        "processor token (no PAN)",
        _DB,
        "pseudonymise (erasure plan)",
    ),
    InventoryItem(
        "card attributes",
        "payment_methods",
        "card_last4",
        "payment features",
        "indefinite",
        "last 4 digits only; never PAN/CVV/PIN",
        _DB,
        "pseudonymise (null)",
    ),
    InventoryItem(
        "login record",
        "login_events",
        "session_id",
        "login features",
        "indefinite",
        "merchant session id",
        _DB,
        "must remain (feature evidence)",
    ),
    InventoryItem(
        "security event details",
        "security_events",
        "details",
        "account-security features",
        "RETENTION_REQUEST_METADATA_DAYS (off)",
        "redacted mapping",
        _DB,
        "nullify (retention job)",
    ),
    InventoryItem(
        "transaction",
        "transactions",
        "amount_minor",
        "scoring, labels",
        "indefinite",
        "linked by user_id",
        _DB,
        "must remain (fraud evidence)",
    ),
    InventoryItem(
        "feature vector",
        "feature_snapshots",
        "features",
        "reproducible scoring",
        "indefinite",
        "derived values only",
        _DB,
        "must remain (prediction evidence)",
    ),
    InventoryItem(
        "model prediction",
        "model_predictions",
        "fraud_probability",
        "model history",
        "indefinite",
        "linked by user_id",
        _DB,
        "must remain (model history)",
    ),
    InventoryItem(
        "risk assessment",
        "risk_assessments",
        "decision",
        "decision record",
        "indefinite, immutable",
        "linked by user_id",
        _API,
        "must remain (immutable)",
    ),
    InventoryItem(
        "fraud label",
        "fraud_labels",
        "label",
        "training labels",
        "indefinite",
        "linked by user_id",
        _DB,
        "must remain (labels)",
    ),
    InventoryItem(
        "label note",
        "fraud_labels",
        "notes",
        "label context",
        "indefinite",
        "PII-sanitised at ingestion",
        _DB,
        "pseudonymise (null)",
    ),
    InventoryItem(
        "review note",
        "review_outcomes",
        "note",
        "analyst rationale",
        "RETENTION_REVIEW_NOTE_DAYS (off)",
        "PII refused at input",
        _API,
        "nullify (retention job, erasure plan)",
    ),
    InventoryItem(
        "passkey",
        "webauthn_credentials",
        "public_key",
        "step-up authentication",
        "until revoked",
        "public key only (no biometric data)",
        _API,
        "delete (erasure plan)",
    ),
    InventoryItem(
        "step-up challenge",
        "authentication_challenges",
        "session_id",
        "WebAuthn binding",
        "RETENTION_CHALLENGE_DAYS (7)",
        "challenge hash only",
        _API,
        "delete",
    ),
    InventoryItem(
        "step-up attempt",
        "authentication_attempts",
        "credential_ref",
        "authentication evidence",
        "RETENTION_FAILED_ATTEMPT_DAYS (off)",
        "credential id / provider reference",
        _API,
        "must remain if it produced a follow-up",
    ),
    InventoryItem(
        "payment step-up",
        "payment_auth_requests",
        "token_ref_hash",
        "external step-up",
        "RETENTION_PAYMENT_REQUEST_DAYS (off)",
        "HMAC of the token reference",
        _API,
        "delete when unreferenced",
    ),
    InventoryItem(
        "LLM explanation",
        "investigations",
        "evidence_packet",
        "analyst decision support",
        "RETENTION_INVESTIGATION_DAYS (off)",
        "privacy-gated evidence packet",
        _API,
        "delete (retention job, erasure plan)",
    ),
    InventoryItem(
        "API client",
        "service_api_keys",
        "name",
        "machine credential",
        "indefinite",
        "salted SHA-256 of the secret; name PII-refused",
        _DB,
        "not personal data",
    ),
    InventoryItem(
        "operator identity",
        "audit_events",
        "actor",
        "accountability",
        "indefinite, immutable",
        "OS user / OPERATOR_ID / key id",
        _DB,
        "must remain (audit chain)",
    ),
    InventoryItem(
        "operator identity",
        "policy_approvals",
        "operator",
        "two-person rule",
        "indefinite, append-only",
        "OPERATOR_ID",
        _DB,
        "must remain (approval record)",
    ),
)


def check_inventory() -> list[str]:
    """Inventory entries that no longer match the schema (empty when in sync)."""
    problems = []
    tables = Base.metadata.tables
    for item in INVENTORY:
        table = tables.get(item.table)
        if table is None:
            problems.append(f"{item.table}: no such table")
        elif item.field not in table.c:
            problems.append(f"{item.table}.{item.field}: no such column")
    return problems


# ------------------------------------------------------------------ erasure analysis
@dataclass(frozen=True)
class ErasureStep:
    table: str
    rows: int
    action: str  # erase | pseudonymise | must_remain
    detail: str


_ERASE = {
    "webauthn_credentials": "delete the passkeys (the customer re-registers if they return)",
    "authentication_challenges": "delete (short-lived; unreferenced after expiry)",
    "user_devices": "delete the device links (device hashes stay: shared, pseudonymous)",
    "network_events": "delete raw observations (affects this user's history features only)",
    "investigations": "delete stored LLM explanations for this user's events",
}
_PSEUDONYMISE = {
    "users": "replace external_ref with a random 'erased-…' value; null home_country",
    "addresses": "null region/postal_prefix; the keyed hash cannot be reversed",
    "payment_methods": "replace token_reference; null card_last4/brand",
    "fraud_labels": "null free-text notes (the label itself stays)",
    "review_outcomes": "null the free-text notes (resolutions stay)",
}
_REMAIN = {
    "events": "the immutable event log (inputs to every decision); payload is pseudonymised",
    "risk_assessments": "immutable decision records (Stage 8 invariant)",
    "model_predictions": "model history; predictions are never rewritten",
    "feature_snapshots": "reproducibility of predictions",
    "fraud_labels": "labels are training and evaluation evidence",
    "transactions": "fraud evidence referenced by assessments and labels",
    "login_events": "feature evidence referenced by snapshots",
    "security_events": "account-security evidence (details can be emptied by retention)",
    "fraud_signals": "evidence behind assessments",
    "review_queue": "part of the decision record",
    "authentication_attempts": "authentication evidence behind follow-up assessments",
    "payment_auth_requests": "referenced by attempts",
}


def _count(session: Session, stmt: Any) -> int:
    return int(session.scalar(select(func.count()).select_from(stmt.subquery())) or 0)


def resolve_user(session: Session, pseudonym: str) -> User | None:
    user = session.scalar(select(User).where(User.external_ref == pseudonym))
    if user is None:
        try:
            user = session.get(User, uuid.UUID(pseudonym))
        except ValueError:
            return None
    return user


def erasure_plan(session: Session, pseudonym: str) -> dict[str, Any]:
    user = resolve_user(session, pseudonym)
    if user is None:
        return {"found": False, "pseudonym": pseudonym, "dry_run": True}
    uid = user.user_id
    counts: dict[str, int] = {}
    for name, tbl in Base.metadata.tables.items():
        if "user_id" in tbl.c:
            counts[name] = _count(session, select(tbl.c.user_id).where(tbl.c.user_id == uid))
    assessments = select(RiskAssessment.assessment_id).where(RiskAssessment.user_id == uid)
    counts["review_queue"] = _count(
        session, select(ReviewItem.review_id).where(ReviewItem.assessment_id.in_(assessments))
    )
    counts["review_outcomes"] = _count(
        session,
        select(ReviewOutcome.outcome_id)
        .join(ReviewItem, ReviewItem.review_id == ReviewOutcome.review_id)
        .where(ReviewItem.assessment_id.in_(assessments)),
    )
    counts["authentication_attempts"] = _count(
        session,
        select(AuthenticationAttempt.attempt_id).where(
            AuthenticationAttempt.assessment_id.in_(assessments)
        ),
    )
    counts["payment_auth_requests"] = _count(
        session,
        select(PaymentAuthRequest.request_id).where(
            PaymentAuthRequest.assessment_id.in_(assessments)
        ),
    )
    events = select(Base.metadata.tables["events"].c.event_id).where(
        Base.metadata.tables["events"].c.user_id == uid
    )
    inv = Base.metadata.tables["investigations"]
    counts["investigations"] = _count(
        session, select(inv.c.investigation_id).where(inv.c.event_id.in_(events))
    )

    steps: list[ErasureStep] = []
    for table, rows in sorted(counts.items()):
        if not rows:
            continue
        if table in _ERASE:
            steps.append(ErasureStep(table, rows, "erase", _ERASE[table]))
        if table in _PSEUDONYMISE:
            steps.append(ErasureStep(table, rows, "pseudonymise", _PSEUDONYMISE[table]))
        if table in _REMAIN and table not in _ERASE:
            steps.append(ErasureStep(table, rows, "must_remain", _REMAIN[table]))
        if table not in _ERASE and table not in _PSEUDONYMISE and table not in _REMAIN:
            steps.append(ErasureStep(table, rows, "must_remain", "not classified: review first"))
    return {
        "found": True,
        "dry_run": True,
        "pseudonym": pseudonym,
        "user_id": str(uid),
        "steps": [asdict(s) for s in steps],
        "dependencies": dependencies(),
        "note": "DRY RUN: nothing was changed. Engineering analysis only, not legal advice.",
    }


def dependencies() -> list[str]:
    """Foreign keys that pin a user's rows (why 'must remain' rows block deleting the user)."""
    out = []
    users: Table = Base.metadata.tables["users"]
    for name, table in sorted(Base.metadata.tables.items()):
        for fk in table.foreign_keys:
            if fk.column.table is users:
                out.append(f"{name}.{fk.parent.name} -> users.user_id")
    return out
