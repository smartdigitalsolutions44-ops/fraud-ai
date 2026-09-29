"""Free-text boundaries and PII rules (Stage 11).

Every user-controlled free-text input is listed in :data:`FREE_TEXT_FIELDS`, with a
maximum length and a rule:

* ``reject``: operator and analyst text (review notes, approval and promotion notes, key
  names). A person can rephrase, so text that looks like personal data or a secret is
  refused with the kinds found, never stored.
* ``sanitise``: merchant-supplied event text (``FRAUD_CONFIRMED.notes`` and the short
  reason/method strings). Refusing the event would lose a fraud label, so detected values
  are replaced by typed placeholders (``[EMAIL]``, ``[PHONE]``, ``[IP]``, ``[CARD]``,
  ``[SECRET]``) before storage.

Detected: e-mail addresses, phone numbers, IPv4/IPv6 addresses (validated), card-like
numbers (Luhn-checked) and obvious tokens or secrets (``key=value`` secrets, bearer tokens,
``sk_``/``rk_``/``whsec_``/``tok_`` style values, API credentials).

**Structured fields are not touched.** The IP in ``metadata.network.ip``, device ids and
full addresses have their own handling: keyed hashes, and raw IP only with
``STORE_RAW_IP``. Codes such as ``merchant_category``, ``card_last4`` or ``country`` are
typed and pattern-validated. Only fields declared here are treated as free text.

Pattern detection is heuristic: it finds common formats, not every possible form of
personal data (a name, for example). It is a guard rail, not a guarantee.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from fraud_ai.core.exceptions import FraudAIError
from fraud_ai.security.pii import EMAIL, IPV4, IPV6, PHONE, SECRET_ASSIGNMENT, TOKEN
from fraud_ai.security.redaction import _PAN_CANDIDATE, _is_pan

_EXTRA_SECRETS = (
    re.compile(r"\b(fak_[0-9a-f]{16})\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\b(?:sk|rk|whsec|pk)_(?:test_|live_)?[A-Za-z0-9]{8,}"),
    re.compile(r"\b(?:pi|seti)_[A-Za-z0-9]+_secret_[A-Za-z0-9]+"),
    re.compile(r"\bv[12]=[0-9a-f]{64}\b"),
    re.compile(
        r"(?i)\b(?:token|access_token|refresh_token|auth|authorization|pwd|pin|cvv2?|cvc2?)"
        r"\s*[:=]\s*\S+"
    ),
)
PLACEHOLDERS = {
    "secret": "[SECRET]",  # nosec B105 - a placeholder label, not a secret
    "card number": "[CARD]",
    "email address": "[EMAIL]",
    "IP address": "[IP]",
    "phone number": "[PHONE]",
}


class FreeTextError(FraudAIError):
    def __init__(self, field: str, message: str, kinds: list[str] | None = None) -> None:
        super().__init__(message)
        self.field = field
        self.kinds = kinds or []


@dataclass(frozen=True)
class FreeTextField:
    name: str
    where: str
    max_length: int
    rule: str  # "reject" | "sanitise"
    purpose: str


FREE_TEXT_FIELDS: tuple[FreeTextField, ...] = (
    FreeTextField("review.note", "POST /v1/reviews/{id}/resolve, fraud-ai review resolve",
                  500, "reject", "analyst rationale for a review outcome"),
    FreeTextField("policy.approval_note", "fraud-ai policy approve --note", 500, "reject",
                  "why an operator approved a policy"),
    FreeTextField("policy.promotion_note", "fraud-ai policy promote --note", 500, "reject",
                  "why a policy moved a lifecycle stage"),
    FreeTextField("deployment.note", "fraud-ai deployment activate --note", 500, "reject",
                  "why a deployment was made"),
    FreeTextField("service_key.name", "fraud-ai service-key create --name", 100, "reject",
                  "what an API key is for"),
    FreeTextField("event.fraud_confirmed.notes", "FRAUD_CONFIRMED metadata.notes", 1000,
                  "sanitise", "merchant context for a fraud confirmation"),
    FreeTextField("event.login.failure_reason", "LOGIN_* metadata.failure_reason", 64,
                  "sanitise", "merchant login failure code/text"),
    FreeTextField("event.transaction_decision.reason", "TRANSACTION_* metadata.reason", 64,
                  "sanitise", "merchant decision reason"),
    FreeTextField("event.chargeback.reason_code", "CHARGEBACK metadata.reason_code", 32,
                  "sanitise", "scheme reason code"),
    FreeTextField("event.network.asn_org", "metadata.network.asn_org", 255, "sanitise",
                  "network operator name from IP intelligence"),
)  # fmt: skip
FIELDS = {f.name: f for f in FREE_TEXT_FIELDS}
# Event payload keys that are free text, per path inside the stored metadata.
EVENT_FREE_TEXT_KEYS = {
    ("notes",): "event.fraud_confirmed.notes",
    ("failure_reason",): "event.login.failure_reason",
    ("reason",): "event.transaction_decision.reason",
    ("reason_code",): "event.chargeback.reason_code",
    ("network", "asn_org"): "event.network.asn_org",
}


def _valid_ip(candidate: str) -> bool:
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


_DATE_OR_TIME = re.compile(r"\d{4}-\d{2}-\d{2}|\d{1,2}:\d{2}")


def _phone(candidate: str) -> bool:
    """A phone-like run: 9-15 digits, and not a date, time or plain number range."""
    if _DATE_OR_TIME.search(candidate):
        return False
    digits = sum(ch.isdigit() for ch in candidate)
    return 9 <= digits <= 15 and (candidate.startswith("+") or " " in candidate.strip()
                                  or "-" in candidate or digits >= 10)  # fmt: skip


def _spans(text: str) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    for pattern in (*_EXTRA_SECRETS, TOKEN, SECRET_ASSIGNMENT):
        spans += [(m.start(), m.end(), "secret") for m in pattern.finditer(text)]
    spans += [
        (m.start(), m.end(), "card number")
        for m in _PAN_CANDIDATE.finditer(text)
        if _is_pan(m.group(0))
    ]
    spans += [(m.start(), m.end(), "email address") for m in EMAIL.finditer(text)]
    for pattern in (IPV4, IPV6):
        spans += [
            (m.start(), m.end(), "IP address")
            for m in pattern.finditer(text)
            if _valid_ip(m.group(0))
        ]
    spans += [
        (m.start(), m.end(), "phone number") for m in PHONE.finditer(text) if _phone(m.group(0))
    ]
    # Keep the first (highest-priority) finding for overlapping spans.
    chosen: list[tuple[int, int, str]] = []
    for span in spans:
        if all(span[1] <= c[0] or span[0] >= c[1] for c in chosen):
            chosen.append(span)
    return sorted(chosen)


def detect(text: str) -> list[str]:
    """The kinds of personal data or secrets found (empty if none)."""
    return sorted({kind for _, _, kind in _spans(text)})


def sanitise(text: str) -> tuple[str, list[str]]:
    """Replace every detected value with its typed placeholder."""
    out, last, kinds = [], 0, set()
    for start, end, kind in _spans(text):
        out.append(text[last:start])
        out.append(PLACEHOLDERS[kind])
        kinds.add(kind)
        last = end
    out.append(text[last:])
    return "".join(out), sorted(kinds)


def check(field: str, text: str | None) -> str | None:
    """Apply a field's rule: returns the text to store (sanitised where that is the rule),
    or raises :class:`FreeTextError` (too long, or PII under a ``reject`` rule)."""
    if text is None:
        return None
    spec = FIELDS[field]
    value = text.strip()
    if len(value) > spec.max_length:
        raise FreeTextError(field, f"{field} is limited to {spec.max_length} characters")
    if spec.rule == "sanitise":
        return sanitise(value)[0]
    kinds = detect(value)
    if kinds:
        raise FreeTextError(
            field,
            f"{field} looks like it contains {', '.join(kinds)}; it must not hold personal "
            "data or secrets",
            kinds,
        )
    return value


def sanitise_event_metadata(metadata: dict[str, object]) -> dict[str, object]:
    """Sanitise the declared free-text keys of stored event metadata (in place and
    returned). Other keys are left exactly as they are."""
    for path, field in EVENT_FREE_TEXT_KEYS.items():
        parent: object = metadata
        for key in path[:-1]:
            parent = parent.get(key) if isinstance(parent, dict) else None
        if isinstance(parent, dict) and isinstance(parent.get(path[-1]), str):
            parent[path[-1]] = sanitise(str(parent[path[-1]]))[0][: FIELDS[field].max_length]
    return metadata
