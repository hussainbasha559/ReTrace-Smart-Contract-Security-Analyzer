"""Content validation and filename handling for uploaded bytecode."""
from __future__ import annotations

import re
import unicodedata

from app.config import Settings
from app.utils.validation import ValidationError, validate_bytecode

_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def sanitize_filename(raw: str | None, default: str = "bytecode.hex") -> str:
    """Return a safe display name: no directories, no control or markup characters."""
    name = unicodedata.normalize("NFKC", raw or "")
    name = name.replace("\\", "/").split("/")[-1]
    name = re.sub(r"[^A-Za-z0-9._() \-]", "_", name)
    name = re.sub(r"\s+", " ", name).strip(" .")
    name = name[:100]
    return name or default


def detect_and_normalize(data: bytes, settings: Settings) -> tuple[str, str]:
    """Inspect the *content* (not the extension). Returns (canonical_hex, detected_type).

    Accepted: hex text (optional 0x, surrounding whitespace) or raw binary bytecode.
    Anything else (Solidity source, JSON, ...) is rejected. Nothing is ever executed.
    """
    if not data:
        raise ValidationError("empty", "The file is empty.")
    if len(data) > settings.max_upload_bytes:
        raise ValidationError("too_large", "The file is too large.")
    if all(b in _PRINTABLE for b in data):
        text = data.decode("ascii")
        try:
            return validate_bytecode(text, settings.max_bytecode_bytes), "hex_text"
        except ValidationError as exc:
            if exc.code == "invalid_hex":
                raise ValidationError(
                    "unsupported_format",
                    "This file is text but not hex bytecode. Upload deployed (runtime) bytecode as hex, "
                    "or raw binary bytecode. Solidity source files are not supported.",
                ) from exc
            raise
    if len(data) > settings.max_bytecode_bytes:
        raise ValidationError("too_large", f"Bytecode exceeds the {settings.max_bytecode_bytes}-byte limit.")
    return data.hex(), "raw_binary"
