"""Input validation. Runs before anything else touches user-supplied bytecode."""
from __future__ import annotations

import re

_HEX_RE = re.compile(r"[0-9a-fA-F]+")


class ValidationError(ValueError):
    """Raised for invalid user input. `code` is stable and machine-readable."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def validate_bytecode(raw: object, max_bytes: int) -> str:
    """Return canonical bytecode: lowercase hex, no 0x prefix, even length.

    Rejects non-strings, empty input, non-hex characters, odd length, and
    anything larger than `max_bytes` (checked before the regex so huge inputs
    are rejected cheaply).
    """
    if not isinstance(raw, str):
        raise ValidationError("not_a_string", "Bytecode must be a string.")

    text = raw.strip()
    if text[:2] in ("0x", "0X"):
        text = text[2:]

    if not text:
        raise ValidationError("empty", "Bytecode is empty.")
    if len(text) > 2 * max_bytes + 1:
        raise ValidationError(
            "too_large", f"Bytecode exceeds the {max_bytes}-byte limit."
        )
    if not _HEX_RE.fullmatch(text):
        raise ValidationError(
            "invalid_hex",
            "Bytecode may contain only the characters 0-9 and a-f "
            "(an optional 0x prefix is allowed, whitespace inside is not).",
        )
    if len(text) % 2:
        raise ValidationError(
            "odd_length", "Bytecode has an odd number of hex digits; bytes need two each."
        )
    if len(text) // 2 > max_bytes:
        raise ValidationError(
            "too_large", f"Bytecode exceeds the {max_bytes}-byte limit."
        )
    return text.lower()
