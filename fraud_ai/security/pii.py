"""Pattern checks for personal data, secrets and instruction-like text in free text.

Shared by the Stage 7 LLM privacy gate and the Stage 8 review-note check. It is pure
functions over strings: no LLM, database or network code, so importing it pulls in
nothing else.
"""

from __future__ import annotations

import ipaddress
import re

from fraud_ai.security.redaction import REDACTED, contains_card_number, redact_text

EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", re.IGNORECASE)
PHONE = re.compile(r"(?<![\w.])\+?\d[\d ()-]{8,}\d(?![\w.])")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
IPV6 = re.compile(r"(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])", re.IGNORECASE)
UUID = re.compile(
    r"[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}", re.IGNORECASE
)
LONG_HEX = re.compile(r"(?<![0-9a-f])[0-9a-f]{24,}(?![0-9a-f])", re.IGNORECASE)
TOKEN = re.compile(r"\btok_[A-Za-z0-9]+|\bsk-[A-Za-z0-9]{8,}|\bghp_[A-Za-z0-9]{8,}")
SECRET_ASSIGNMENT = re.compile(
    r"\b(password|passwd|secret|api[_-]?key)\s*[:=]\s*\S+", re.IGNORECASE
)
STREET = re.compile(
    r"\b\d{1,5}\s+[A-Za-z][A-Za-z ]{1,40}\s(?:road|street|lane|avenue|drive|close|way|"
    r"court|place|crescent|terrace|rd|st|ave)\b",
    re.IGNORECASE,
)
INSTRUCTION = re.compile(
    r"\b(ignore|disregard|forget)\b.{0,40}\b(instruction|prompt|rule|above|previous)|"
    r"\b(system prompt|you are now|act as|jailbreak)\b|"
    r"\b(approve|block|decline|allow|whitelist)\b.{0,20}\b(transaction|account|payment|order|"
    r"this)\b",
    re.IGNORECASE,
)
# Tokens join words with separators ("ignore_previous_instructions"); read them as words.
SEPARATORS = re.compile(r"[_.:+-]+")
# Pseudonymous references this system itself produces are allowed.
ALLOWED_REF = re.compile(r"^(ev|ex)-[0-9a-f]{16}$")


def _ip(text: str) -> bool:
    for candidate in IPV4.findall(text) + IPV6.findall(text):
        try:
            ipaddress.ip_address(candidate)
            return True
        except ValueError:
            continue
    return False


def text_violations(text: str, *, free_text_allowed: bool) -> list[str]:
    if ALLOWED_REF.match(text):
        return []
    found = []
    if EMAIL.search(text):
        found.append("email address")
    if _ip(text):
        found.append("IP address")
    if contains_card_number(text):
        found.append("card number")
    if TOKEN.search(text) or SECRET_ASSIGNMENT.search(text):
        found.append("token or secret")
    if UUID.search(text):
        found.append("raw identifier (UUID)")
    elif LONG_HEX.search(text):
        found.append("long hex identifier")
    if STREET.search(text):
        found.append("street address")
    if PHONE.search(text) and not contains_card_number(text):
        found.append("phone number")
    if INSTRUCTION.search(text) or INSTRUCTION.search(SEPARATORS.sub(" ", text)):
        found.append("embedded instruction")
    if not free_text_allowed and (" " in text.strip() or len(text) > 64):
        found.append("unexpected free text")
    return found


def redact(text: str) -> str:
    """Mask anything identifier-like before a model output fragment is echoed in an error."""
    for pattern in (EMAIL, UUID, LONG_HEX, TOKEN, SECRET_ASSIGNMENT, STREET, IPV4, IPV6, PHONE):
        text = pattern.sub(REDACTED, text)
    return redact_text(text)
