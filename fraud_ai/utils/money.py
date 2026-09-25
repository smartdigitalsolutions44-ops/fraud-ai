"""Exact money handling.

Amounts are stored as integers in the currency's minor unit (e.g. pence, cents) so that
arithmetic is exact on every database backend. Floating point is never used for money.
"""

from __future__ import annotations

from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation

# ISO 4217 minor-unit exponents for currencies that differ from the default of 2.
_EXPONENT_OVERRIDES: dict[str, int] = {
    "JPY": 0,
    "KRW": 0,
    "ISK": 0,
    "CLP": 0,
    "VND": 0,
    "BHD": 3,
    "KWD": 3,
    "OMR": 3,
    "JOD": 3,
    "TND": 3,
}


class MoneyError(ValueError):
    """Raised for invalid monetary values."""


def currency_exponent(currency: str) -> int:
    code = normalise_currency(currency)
    return _EXPONENT_OVERRIDES.get(code, 2)


def normalise_currency(currency: str) -> str:
    code = currency.strip().upper()
    if len(code) != 3 or not code.isalpha():
        raise MoneyError(f"invalid ISO 4217 currency code: {currency!r}")
    return code


def to_minor_units(amount: Decimal | str | int, currency: str) -> int:
    """Convert a major-unit amount to integer minor units.

    Raises if the amount has more precision than the currency supports - silently rounding
    a transaction amount would corrupt the historical record.
    """
    if isinstance(amount, float):
        raise MoneyError("floats are not accepted for money; use Decimal or str")
    try:
        value = Decimal(str(amount))
    except InvalidOperation as exc:
        raise MoneyError(f"invalid amount: {amount!r}") from exc
    if not value.is_finite():
        raise MoneyError("amount must be finite")
    exponent = currency_exponent(currency)
    scaled = value.scaleb(exponent)
    if scaled != scaled.to_integral_value():
        raise MoneyError(f"{amount} has more precision than {currency} allows")
    return int(scaled)


def from_minor_units(minor: int, currency: str) -> Decimal:
    exponent = currency_exponent(currency)
    quantum = Decimal(1).scaleb(-exponent)
    return (Decimal(minor).scaleb(-exponent)).quantize(quantum, rounding=ROUND_HALF_EVEN)
