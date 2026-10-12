import pytest

from app.utils.validation import ValidationError, validate_bytecode

LIMIT = 100


def test_accepts_prefixed_and_normalizes_case():
    assert validate_bytecode("0x60AB", LIMIT) == "60ab"
    assert validate_bytecode("  0X6001  ", LIMIT) == "6001"


@pytest.mark.parametrize(
    "raw,code",
    [
        (None, "not_a_string"),
        (123, "not_a_string"),
        ("", "empty"),
        ("0x", "empty"),
        ("   ", "empty"),
        ("0xzz", "invalid_hex"),
        ("60 01", "invalid_hex"),
        ("600", "odd_length"),
        ("00" * 101, "too_large"),
        ("00" * 5000, "too_large"),
    ],
)
def test_rejects_bad_input(raw, code):
    with pytest.raises(ValidationError) as exc:
        validate_bytecode(raw, LIMIT)
    assert exc.value.code == code


def test_exact_limit_is_allowed():
    assert len(validate_bytecode("00" * LIMIT, LIMIT)) == 2 * LIMIT
