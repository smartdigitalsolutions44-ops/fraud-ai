"""Pseudonym-scoped data export (Stage 12): ``fraud-ai privacy export <pseudonym>``.

Everything stored about **one** user (found by merchant reference or user id), as JSON,
for an access request or an investigation. Engineering tooling, not a legal
assessment.

**Scope and safety rules:**

* **One user only.** Every row is selected by that user's id, or through that user's own
  events and assessments. Tables shared between users (network identities, devices) are
  reached only through this user's links, and only non-identifying attributes are
  exported. No other user's id or data can appear.
* **Explicit column allow-list per table** (:data:`EXPORT`). A new column is *not*
  exported until someone adds it here, so it is reviewed first.
* **Never exported:**
  * secrets and credential material: processor token references, WebAuthn public keys and
    counters, challenge hashes, API keys;
  * keyed pseudonyms (HMAC digests), which mean nothing to the person and belong to the
    pseudonymisation key;
  * internal model inputs and outputs (feature vectors, raw model scores, prompts and
    evidence packets);
  * staff identities (which reviewer resolved a case);
  * signing material of any kind.

  :data:`EXCLUDED` states each exclusion and its reason in the export itself.
* **Nested JSON is redacted too.** Allow-listed JSON columns (event metadata, security-event
  details, signal values) can carry keyed hashes, token references or raw addresses. Every
  nested key matching :data:`NESTED_REDACT` is removed, and the count is reported.
* **Audited.** ``privacy.exported`` records who exported which pseudonym and the row counts,
  never the data. Operator authentication (``security_admin``) is required when it is
  enabled.
"""

from __future__ import annotations

import enum
import re
import uuid
from collections.abc import Iterable
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import Table, select
from sqlalchemy.orm import Session

from fraud_ai.database.base import Base
from fraud_ai.privacy.inventory import resolve_user

# table -> (columns exported, how rows are linked to the user)
EXPORT: dict[str, tuple[tuple[str, ...], str]] = {
    "users": (
        ("user_id", "external_ref", "account_created_at", "home_country", "status", "created_at"),
        "user",
    ),
    "addresses": (
        (
            "address_id",
            "address_type",
            "country",
            "region",
            "postal_prefix",
            "added_at",
            "superseded_at",
            "is_active",
            "verified_at",
        ),
        "user",
    ),
    "payment_methods": (
        (
            "payment_method_id",
            "method_type",
            "card_brand",
            "card_last4",
            "funding",
            "issuer_country",
            "added_at",
            "verified_at",
        ),
        "user",
    ),
    "events": (
        ("event_id", "event_type", "occurred_at", "source", "schema_version", "metadata"),
        "user",
    ),
    "transactions": (
        (
            "transaction_id",
            "event_id",
            "amount_minor",
            "currency",
            "merchant_category",
            "channel",
            "status",
            "occurred_at",
            "decided_at",
            "decision_outcome",
            "decision_reason",
        ),
        "user",
    ),
    "login_events": (
        ("login_event_id", "event_id", "occurred_at", "outcome", "auth_method", "mfa_used"),
        "user",
    ),
    "network_events": (
        (
            "event_id",
            "observed_at",
            "asn",
            "country",
            "network_type",
            "is_known_vpn",
            "is_known_proxy",
            "is_tor",
            "is_datacenter",
            "is_mobile_network",
        ),
        "user",
    ),
    "security_events": (("event_id", "security_event_type", "occurred_at", "details"), "user"),
    "user_devices": (
        ("first_seen_at", "last_seen_at", "is_trusted", "successful_logins", "failed_logins"),
        "user",
    ),
    "fraud_labels": (
        (
            "label_id",
            "event_id",
            "label",
            "fraud_type",
            "label_source",
            "confidence",
            "labelled_at",
        ),
        "user",
    ),
    "fraud_signals": (("event_id", "signal_name", "signal_source", "value", "observed_at"), "user"),
    "risk_assessments": (
        (
            "assessment_id",
            "event_id",
            "assessed_at",
            "policy_version",
            "final_risk_score",
            "risk_level",
            "decision",
            "action",
            "reason_codes",
        ),
        "user",
    ),
    "review_queue": (
        (
            "review_id",
            "assessment_id",
            "status",
            "reason_codes",
            "created_at",
            "reviewed_at",
            "outcome",
        ),
        "assessment",
    ),
    "authentication_attempts": (
        (
            "attempt_id",
            "assessment_id",
            "method",
            "attempt_number",
            "result",
            "failure_reason",
            "created_at",
        ),
        "assessment",
    ),
    "payment_auth_requests": (
        (
            "request_id",
            "assessment_id",
            "provider",
            "status",
            "attempt_number",
            "created_at",
            "completed_at",
        ),
        "assessment",
    ),
    "webauthn_credentials": (("status", "transports", "created_at", "last_used_at"), "user"),
    "investigations": (("investigation_id", "event_id", "created_at", "explanation_text"), "event"),
}

# Nested JSON keys never exported (keyed pseudonyms, token/credential material, raw IPs).
NESTED_REDACT = re.compile(
    r"(_hash$|^hash$|token|secret|password|passwd|credential|signature|fingerprint"
    r"|^ip$|^ip_address$|^raw_ip$)",
    re.IGNORECASE,
)

EXCLUDED: dict[str, str] = {
    "<any JSON column>.<nested key matching NESTED_REDACT>": (
        "keyed pseudonyms, token or credential material and raw IPs inside JSON values "
        "(for example events.metadata.network.ip_hash)"
    ),
    "addresses.address_hash": "keyed pseudonym (HMAC); the key is never exported",
    "payment_methods.token_reference": "processor token reference: credential material",
    "payment_methods.fingerprint_hash": "keyed pseudonym",
    "events.session_id/device_id": "internal linking identifiers",
    "network_events.network_identity_id": "shared network identity (other users' data)",
    "user_devices.device_id + devices.*": "shared device records; keyed device hashes",
    "risk_assessments.model_scores/ml_probability/triggered_rules/failures": (
        "internal model outputs; the decision and reason codes are exported"
    ),
    "review_outcomes.*": "staff notes and reviewer identities (the outcome is in review_queue)",
    "authentication_attempts.credential_ref/challenge_id": "credential material",
    "payment_auth_requests.provider_reference/token_ref_hash": "processor references",
    "webauthn_credentials.credential_id/public_key/sign_count": "credential material",
    "authentication_challenges": "short-lived challenge hashes",
    "investigations.evidence_packet/prompt/validation": (
        "internal model inputs; the explanation text is exported"
    ),
    "feature_snapshots / model_predictions": "internal model inputs and raw scores",
    "audit_events, operator_assertions, signatures, api keys": (
        "administrative and signing records: not about the person"
    ),
}


def _plain(value: Any, redacted: list[int] | None = None) -> Any:
    if isinstance(value, uuid.UUID | Decimal):
        return str(value)
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if NESTED_REDACT.search(str(k)):
                if redacted is not None:
                    redacted[0] += 1
                continue
            out[str(k)] = _plain(v, redacted)
        return out
    if isinstance(value, list | tuple):
        return [_plain(v, redacted) for v in value]
    return value


def _rows(
    session: Session, table: Table, columns: Iterable[str], where: Any, redacted: list[int]
) -> list[dict[str, Any]]:
    cols = [table.c[c] for c in columns]
    return [
        {c.name: _plain(v, redacted) for c, v in zip(cols, row, strict=True)}
        for row in session.execute(select(*cols).where(where))
    ]


def export_subject(session: Session, pseudonym: str) -> dict[str, Any]:
    user = resolve_user(session, pseudonym)
    if user is None:
        return {"found": False, "pseudonym": pseudonym}
    uid = user.user_id
    tables = Base.metadata.tables
    assessments = select(tables["risk_assessments"].c.assessment_id).where(
        tables["risk_assessments"].c.user_id == uid
    )
    events = select(tables["events"].c.event_id).where(tables["events"].c.user_id == uid)
    out: dict[str, list[dict[str, Any]]] = {}
    redacted = [0]
    for name, (columns, link) in EXPORT.items():
        table = tables[name]
        if link == "user":
            where = table.c.user_id == uid
        elif link == "assessment":
            where = table.c.assessment_id.in_(assessments)
        else:
            where = table.c.event_id.in_(events)
        rows = _rows(session, table, columns, where, redacted)
        if rows:
            out[name] = rows
    return {
        "found": True,
        "pseudonym": pseudonym,
        "user_id": str(uid),
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "tables": out,
        "row_counts": {k: len(v) for k, v in out.items()},
        "redacted_nested_keys": redacted[0],
        "excluded": EXCLUDED,
        "note": (
            "Data held about one user, from an explicit per-column allow-list. Secrets, "
            "credential material, keyed pseudonyms, internal model data, staff identities "
            "and other users' data are excluded (see 'excluded'). Engineering export, not "
            "legal advice."
        ),
    }
