from decimal import Decimal

import pytest

from fraud_ai.utils.money import MoneyError, from_minor_units, to_minor_units


@pytest.mark.parametrize(
    ("amount", "currency", "minor"),
    [
        ("0.10", "GBP", 10),
        ("19.99", "usd", 1999),
        ("1000", "JPY", 1000),
        ("1.234", "BHD", 1234),
        (Decimal("0.01"), "EUR", 1),
        (5, "GBP", 500),
        ("92233720368547.75", "GBP", 9223372036854775),
    ],
)
def test_to_minor_units(amount: object, currency: str, minor: int) -> None:
    assert to_minor_units(amount, currency) == minor  # type: ignore[arg-type]


def test_round_trip_is_exact() -> None:
    for text in ["0.01", "0.10", "0.30", "123456789.99"]:
        assert from_minor_units(to_minor_units(text, "GBP"), "GBP") == Decimal(text)
    # The classic float failure mode does not exist for integer minor units.
    total = sum(to_minor_units("0.10", "GBP") for _ in range(3))
    assert from_minor_units(total, "GBP") == Decimal("0.30")


@pytest.mark.parametrize(
    ("amount", "currency"), [("0.001", "GBP"), ("1.5", "JPY"), ("abc", "GBP"), ("NaN", "GBP")]
)
def test_rejects_invalid_precision_or_value(amount: str, currency: str) -> None:
    with pytest.raises(MoneyError):
        to_minor_units(amount, currency)


def test_rejects_float_and_bad_currency() -> None:
    with pytest.raises(MoneyError):
        to_minor_units(0.1, "GBP")  # type: ignore[arg-type]
    with pytest.raises(MoneyError):
        to_minor_units("1.00", "POUNDS")


def test_from_minor_units_quantized() -> None:
    assert str(from_minor_units(5, "GBP")) == "0.05"
    assert str(from_minor_units(5, "JPY")) == "5"
    assert str(from_minor_units(5, "KWD")) == "0.005"
