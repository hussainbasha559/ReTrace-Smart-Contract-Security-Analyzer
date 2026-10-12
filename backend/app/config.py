"""Central configuration. Every value can be overridden with an environment variable.

No secrets live here. Limits exist so that one request cannot consume unbounded
memory, CPU time or output.
"""
from __future__ import annotations

import os
import secrets
import shlex
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

try:  # .env is a local-development convenience; real deployments set real env vars.
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
except ImportError:  # pragma: no cover
    pass


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _float_or_none(name: str):
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return None


_BACKEND_DIR = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Settings:
    # EIP-170 caps deployed (runtime) contract code at 24,576 bytes.
    max_bytecode_bytes: int = 24_576
    max_request_body_bytes: int = 256 * 1024

    decompile_timeout_s: int = 60
    mythril_timeout_s: int = 90          # symbolic-execution budget passed to Mythril
    mythril_transaction_count: int = 2
    mythril_modules: str = ""            # e.g. "ExternalCalls,StateChangeAfterCall"; empty = all

    max_tool_output_chars: int = 200_000
    max_concurrent_analyses: int = 2

    heimdall_bin: str = "heimdall"
    heimdall_extra_args: tuple[str, ...] = ()
    mythril_bin: str = "myth"

    # How each tool is launched.
    #   heimdall_mode: auto | native | wsl     (wsl = run inside Ubuntu/WSL2 from a Windows backend)
    #   mythril_mode : auto | native | docker  (docker = run the official image, offline and limited)
    # "auto" prefers a tool found on PATH, then falls back to WSL / Docker.
    heimdall_mode: str = "auto"
    mythril_mode: str = "auto"
    wsl_bin: str = "wsl"
    wsl_distro: str = ""                 # empty = the default WSL distro
    wsl_mount_root: str = "/mnt"         # where WSL mounts Windows drives (C: -> /mnt/c)
    docker_bin: str = "docker"
    mythril_image: str = "mythril/myth:latest"
    docker_memory: str = "2g"
    docker_cpus: str = "2"
    docker_pids_limit: int = 256

    cors_origins: tuple[str, ...] = ("http://localhost:5173", "http://127.0.0.1:5173")

    # ---- Platform: database, sessions, storage -------------------------------------
    # Supabase (PostgreSQL): see backend/.env.example. postgres:// URLs are accepted and normalised.
    database_url: str = ""
    db_pool_size: int = 3                # connections kept open per process (Supabase free tier is small)
    db_max_overflow: int = 4             # extra short-lived connections allowed under load
    # Signs/keys session tokens. If unset a random per-process key is used, which is safe
    # but logs everyone out on restart. Set RETRACE_SECRET_KEY (>= 32 chars) for real use.
    secret_key: str = ""
    secret_key_is_ephemeral: bool = False
    session_cookie_name: str = "retrace_session"
    cookie_secure: bool = False          # MUST be true behind HTTPS
    cookie_samesite: str = "lax"
    session_ttl_hours: int = 12          # absolute lifetime
    session_idle_minutes: int = 120      # inactivity timeout
    storage_dir: str = str(_BACKEND_DIR / "storage")   # outside any public web directory
    max_upload_bytes: int = 128 * 1024   # raw upload size cap (a 24 KB contract is ~48 KB of hex)
    max_files_per_user: int = 200
    max_pasted_chars: int = 2 * 24_576 + 16

    # ---- Scan jobs -----------------------------------------------------------------
    jobs_inline: bool = False            # run scan jobs synchronously (tests only)
    scan_max_attempts: int = 2           # retries only for unexpected internal errors
    analyzer_version: str = "retrace-0.2.0"

    # ---- Rate limiting (per process; use Redis or a reverse proxy for multiple workers)
    rate_limit_enabled: bool = True

    # ---- Retention -------------------------------------------------------------------
    audit_retention_days: int = 365

    # ---- AI provider -----------------------------------------------------------------
    ai_provider: str = "none"            # none | openai (any OpenAI-compatible chat API)
    ai_api_key: str = ""
    ai_base_url: str = "https://api.openai.com/v1"
    ai_model: str = "gpt-4o-mini"
    ai_timeout_s: int = 60
    ai_max_tokens: int = 1200
    ai_requests_per_hour: int = 30
    ai_price_input_per_1m: float | None = None    # USD, optional; enables cost estimates
    ai_price_output_per_1m: float | None = None


def _mode(name: str, allowed: tuple[str, ...]) -> str:
    value = os.environ.get(name, "auto").strip().lower()
    return value if value in allowed else "auto"


@lru_cache
def get_settings() -> Settings:
    secret = os.environ.get("RETRACE_SECRET_KEY", "").strip()
    ephemeral = False
    if len(secret) < 32:
        secret, ephemeral = secrets.token_hex(32), True
    return Settings(
        database_url=os.environ.get("DATABASE_URL", "").strip(),
        db_pool_size=max(1, _int("RETRACE_DB_POOL_SIZE", 3)),
        db_max_overflow=max(0, _int("RETRACE_DB_MAX_OVERFLOW", 4)),
        secret_key=secret,
        secret_key_is_ephemeral=ephemeral,
        cookie_secure=_bool("RETRACE_COOKIE_SECURE", False),
        session_ttl_hours=_int("RETRACE_SESSION_TTL_HOURS", 12),
        session_idle_minutes=_int("RETRACE_SESSION_IDLE_MINUTES", 120),
        storage_dir=os.environ.get("RETRACE_STORAGE_DIR", str(_BACKEND_DIR / "storage")),
        max_upload_bytes=_int("RETRACE_MAX_UPLOAD_BYTES", 128 * 1024),
        max_files_per_user=_int("RETRACE_MAX_FILES_PER_USER", 200),
        jobs_inline=_bool("RETRACE_JOBS_INLINE", False),
        scan_max_attempts=_int("RETRACE_SCAN_MAX_ATTEMPTS", 2),
        rate_limit_enabled=_bool("RETRACE_RATE_LIMIT", True),
        audit_retention_days=_int("RETRACE_AUDIT_RETENTION_DAYS", 365),
        ai_provider=os.environ.get("RETRACE_AI_PROVIDER", "none").strip().lower(),
        ai_api_key=os.environ.get("RETRACE_AI_API_KEY", os.environ.get("OPENAI_API_KEY", "")).strip(),
        ai_base_url=os.environ.get("RETRACE_AI_BASE_URL", "https://api.openai.com/v1").rstrip("/"),
        ai_model=os.environ.get("RETRACE_AI_MODEL", "gpt-4o-mini"),
        ai_timeout_s=_int("RETRACE_AI_TIMEOUT_S", 60),
        ai_max_tokens=_int("RETRACE_AI_MAX_TOKENS", 1200),
        ai_requests_per_hour=_int("RETRACE_AI_REQUESTS_PER_HOUR", 30),
        ai_price_input_per_1m=_float_or_none("RETRACE_AI_PRICE_INPUT_PER_1M"),
        ai_price_output_per_1m=_float_or_none("RETRACE_AI_PRICE_OUTPUT_PER_1M"),
        max_bytecode_bytes=_int("RETRACE_MAX_BYTECODE_BYTES", 24_576),
        decompile_timeout_s=_int("RETRACE_DECOMPILE_TIMEOUT_S", 60),
        mythril_timeout_s=_int("RETRACE_MYTHRIL_TIMEOUT_S", 90),
        mythril_transaction_count=_int("RETRACE_MYTHRIL_TX_COUNT", 2),
        mythril_modules=os.environ.get("RETRACE_MYTHRIL_MODULES", ""),
        max_tool_output_chars=_int("RETRACE_MAX_TOOL_OUTPUT_CHARS", 200_000),
        max_concurrent_analyses=_int("RETRACE_MAX_CONCURRENT", 2),
        heimdall_bin=os.environ.get("RETRACE_HEIMDALL_BIN", "heimdall"),
        heimdall_extra_args=tuple(shlex.split(os.environ.get("RETRACE_HEIMDALL_ARGS", ""))),
        mythril_bin=os.environ.get("RETRACE_MYTHRIL_BIN", "myth"),
        heimdall_mode=_mode("RETRACE_HEIMDALL_MODE", ("auto", "native", "wsl")),
        mythril_mode=_mode("RETRACE_MYTHRIL_MODE", ("auto", "native", "docker")),
        wsl_bin=os.environ.get("RETRACE_WSL_BIN", "wsl"),
        wsl_distro=os.environ.get("RETRACE_WSL_DISTRO", "").strip(),
        wsl_mount_root=os.environ.get("RETRACE_WSL_MOUNT_ROOT", "/mnt").rstrip("/") or "/mnt",
        docker_bin=os.environ.get("RETRACE_DOCKER_BIN", "docker"),
        mythril_image=os.environ.get("RETRACE_MYTHRIL_IMAGE", "mythril/myth:latest"),
        docker_memory=os.environ.get("RETRACE_DOCKER_MEMORY", "2g"),
        docker_cpus=os.environ.get("RETRACE_DOCKER_CPUS", "2"),
        docker_pids_limit=_int("RETRACE_DOCKER_PIDS_LIMIT", 256),
        cors_origins=tuple(
            o.strip()
            for o in os.environ.get(
                "RETRACE_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
            ).split(",")
            if o.strip()
        ),
    )
