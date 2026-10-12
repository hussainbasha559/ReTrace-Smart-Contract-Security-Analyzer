"""Private file storage. Files live under RETRACE_STORAGE_DIR, which is never served by the
web server, under server-generated keys (32 hex chars). User-supplied names are never used
as paths, so path traversal is impossible by construction; the key check is a second guard."""
from __future__ import annotations

import hashlib
import os
import re
import uuid
from pathlib import Path

from app.config import Settings

_KEY_RE = re.compile(r"[0-9a-f]{32}")


def _root(settings: Settings, area: str) -> Path:
    root = Path(settings.storage_dir).resolve() / area
    root.mkdir(parents=True, exist_ok=True)
    return root


def _path(settings: Settings, area: str, key: str) -> Path:
    if not _KEY_RE.fullmatch(key):
        raise ValueError("invalid storage key")
    root = _root(settings, area)
    p = (root / key[:2] / key).resolve()
    if root not in p.parents:
        raise ValueError("path escapes storage root")
    return p


def new_key() -> str:
    return uuid.uuid4().hex


def write(settings: Settings, area: str, key: str, data: bytes) -> None:
    p = _path(settings, area, key)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, p)


def read(settings: Settings, area: str, key: str) -> bytes:
    return _path(settings, area, key).read_bytes()


def delete(settings: Settings, area: str, key: str) -> None:
    try:
        _path(settings, area, key).unlink(missing_ok=True)
    except (ValueError, OSError):
        pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
