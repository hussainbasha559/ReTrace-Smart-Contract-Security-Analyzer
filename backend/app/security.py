"""Password hashing, session tokens, password policy and a small in-memory rate limiter."""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
from collections import defaultdict, deque

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from email_validator import EmailNotValidError, validate_email

from app.config import get_settings

# Argon2id with the library's current recommended defaults.
_hasher = PasswordHasher()

# A real hash of a random string, verified when the email is unknown so that login takes
# about as long whether or not the account exists (limits user-enumeration by timing).
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

_COMMON = {
    "password", "password1", "password123", "passw0rd", "qwerty", "qwerty123", "letmein",
    "welcome", "welcome1", "admin", "admin123", "iloveyou", "123456", "12345678", "123456789",
    "1234567890", "abc123", "monkey", "dragon", "football", "baseball", "changeme",
}


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    if password_hash is None:
        try:
            _hasher.verify(_DUMMY_HASH, password)
        except Exception:
            pass
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def password_problems(password: str, email: str = "", name: str = "") -> list[str]:
    """Human-readable reasons a password is rejected (empty list = acceptable)."""
    problems = []
    if len(password) < 10:
        problems.append("Use at least 10 characters.")
    if len(password) > 128:
        problems.append("Use at most 128 characters.")
    if not re.search(r"[a-z]", password):
        problems.append("Add a lowercase letter.")
    if not re.search(r"[A-Z]", password):
        problems.append("Add an uppercase letter.")
    if not re.search(r"\d", password):
        problems.append("Add a digit.")
    if password.lower() in _COMMON:
        problems.append("This password is too common.")
    local = email.split("@")[0].lower()
    if len(local) >= 4 and local in password.lower():
        problems.append("Do not include your email name in the password.")
    return problems


def normalize_email(raw: str) -> str:
    """Return the lowercase, validated address or raise ValueError."""
    try:
        info = validate_email(raw.strip(), check_deliverability=False)
    except EmailNotValidError as exc:
        raise ValueError(str(exc)) from exc
    return info.normalized.lower()


def clean_name(raw: str) -> str:
    name = re.sub(r"\s+", " ", raw).strip()
    if not 1 <= len(name) <= 100:
        raise ValueError("Name must be 1 to 100 characters.")
    if re.search(r"[\x00-\x1f\x7f<>]", name):
        raise ValueError("Name contains characters that are not allowed.")
    return name


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    """HMAC-SHA256 of the cookie token, keyed with the server secret."""
    key = get_settings().secret_key.encode()
    return hmac.new(key, token.encode(), hashlib.sha256).hexdigest()


def safe_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


class RateLimiter:
    """Sliding-window limiter. In-memory, so it is per process: fine for one uvicorn worker.
    Behind several workers use a shared store (Redis) or enforce limits at the reverse proxy."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_s: int) -> bool:
        """Record an attempt; return False if the key is over the limit."""
        if not get_settings().rate_limit_enabled:
            return True
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window_s:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()
