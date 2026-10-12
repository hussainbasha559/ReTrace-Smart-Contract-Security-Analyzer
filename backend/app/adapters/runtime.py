"""Decides HOW each external tool is launched, and whether it can be launched at all.

Heimdall-rs   native  - `heimdall` is on PATH of the backend process
              wsl     - the backend runs on Windows and Heimdall lives in Ubuntu/WSL2
Mythril       native  - `myth` is on PATH of the backend process
              docker  - run the official image (default: mythril/myth:latest)

`auto` (the default) prefers a native install and falls back to WSL / Docker, so the same
code works whether the backend runs on Windows, inside WSL, or on Linux.

Everything here uses argument lists with shell=False. The only text ever handed to a
shell is the fixed lookup script below, which contains no user input.
"""
from __future__ import annotations

import re
import shutil
import threading
import time
from dataclasses import dataclass

from app.adapters.base import run_command
from app.config import Settings

_PROBE_TIMEOUT_S = 20
_CACHE_TTL_S = 30.0

# A login shell is needed to see ~/.bifrost/bin, which `wsl --exec` alone does not put on PATH.
# The script is a constant (no quotes, no interpolation), so it is safe to pass as one argument.
_WSL_FIND_HEIMDALL = (
    "for p in $(command -v heimdall) $HOME/.bifrost/bin/heimdall "
    "$HOME/.cargo/bin/heimdall /usr/local/bin/heimdall; "
    "do [ -x $p ] && echo $p && break; done"
)

_WIN_PATH = re.compile(r"^([A-Za-z]):[\\/]*(.*)$")


@dataclass(frozen=True)
class Runtime:
    mode: str        # native | wsl | docker | none
    available: bool
    detail: str      # short, human-readable, free of server file paths
    bin: str = ""    # executable to run (the in-WSL absolute path when mode == "wsl")


_cache: dict[tuple, tuple[float, Runtime]] = {}
_lock = threading.Lock()


def reset_cache() -> None:
    with _lock:
        _cache.clear()


def _cached(key: tuple, compute) -> Runtime:
    now = time.monotonic()
    with _lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < _CACHE_TTL_S:
            return hit[1]
    value = compute()
    with _lock:
        _cache[key] = (now, value)
    return value


# --------------------------------------------------------------------------- WSL helpers

def wsl_prefix(settings: Settings) -> list[str]:
    """`wsl [-d distro] --exec` : run a program directly, with no shell in between."""
    args = [settings.wsl_bin]
    if settings.wsl_distro:
        args += ["-d", settings.wsl_distro]
    args.append("--exec")
    return args


def windows_to_wsl_path(path: str, mount_root: str = "/mnt") -> str:
    """C:\\Users\\me\\x  ->  /mnt/c/Users/me/x.  POSIX paths pass through unchanged."""
    text = str(path)
    if text.startswith("\\\\"):
        raise ValueError("Network (UNC) paths cannot be used with WSL; use a local drive for TEMP.")
    m = _WIN_PATH.match(text)
    if m:
        drive, rest = m.group(1).lower(), m.group(2).replace("\\", "/").strip("/")
        return f"{mount_root}/{drive}/{rest}" if rest else f"{mount_root}/{drive}"
    if text.startswith("/"):
        return text
    raise ValueError("Cannot translate a relative path for WSL.")


def _find_heimdall_in_wsl(settings: Settings) -> str | None:
    prefix = wsl_prefix(settings)
    configured = settings.heimdall_bin
    if configured != "heimdall" and configured.startswith("/"):
        res = run_command([*prefix, "test", "-x", configured], _PROBE_TIMEOUT_S)
        return configured if res.returncode == 0 else None
    res = run_command([*prefix, "bash", "-lc", _WSL_FIND_HEIMDALL], _PROBE_TIMEOUT_S)
    if res.returncode != 0:
        return None
    lines = [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]
    # wsl.exe prints its own errors (e.g. unknown distro) as UTF-16 text; only accept a clean path.
    return lines[-1] if lines and lines[-1].startswith("/") else None


def _distro_label(settings: Settings) -> str:
    return settings.wsl_distro or "default distro"


# --------------------------------------------------------------------------- Heimdall

def resolve_heimdall(settings: Settings) -> Runtime:
    key = ("heimdall", settings.heimdall_mode, settings.heimdall_bin, settings.wsl_bin, settings.wsl_distro)
    return _cached(key, lambda: _resolve_heimdall(settings))


def _resolve_heimdall(settings: Settings) -> Runtime:
    mode = settings.heimdall_mode
    native = shutil.which(settings.heimdall_bin)

    if mode in ("auto", "native") and native:
        return Runtime("native", True, "native", settings.heimdall_bin)
    if mode == "native":
        return Runtime("native", False, f"'{settings.heimdall_bin}' was not found on PATH.")

    if shutil.which(settings.wsl_bin) is None:
        return Runtime(
            "none", False,
            f"'{settings.heimdall_bin}' is not on PATH and WSL ('{settings.wsl_bin}') is not available.",
        )
    found = _find_heimdall_in_wsl(settings)
    if found:
        return Runtime("wsl", True, f"WSL ({_distro_label(settings)})", found)
    return Runtime(
        "wsl", False,
        f"Heimdall was not found in WSL ({_distro_label(settings)}). "
        "Check `wsl heimdall --version`, or set RETRACE_HEIMDALL_BIN to its full path inside WSL.",
    )


# --------------------------------------------------------------------------- Mythril

def resolve_mythril(settings: Settings) -> Runtime:
    key = ("mythril", settings.mythril_mode, settings.mythril_bin, settings.docker_bin, settings.mythril_image)
    return _cached(key, lambda: _resolve_mythril(settings))


def _resolve_mythril(settings: Settings) -> Runtime:
    mode = settings.mythril_mode
    native = shutil.which(settings.mythril_bin)

    if mode in ("auto", "native") and native:
        return Runtime("native", True, "native", settings.mythril_bin)
    if mode == "native":
        return Runtime("native", False, f"'{settings.mythril_bin}' was not found on PATH.")

    if shutil.which(settings.docker_bin) is None:
        return Runtime(
            "none", False,
            f"'{settings.mythril_bin}' is not on PATH and Docker ('{settings.docker_bin}') is not available.",
        )
    res = run_command(
        [settings.docker_bin, "image", "inspect", settings.mythril_image], _PROBE_TIMEOUT_S
    )
    if res.returncode == 0:
        return Runtime("docker", True, f"Docker ({settings.mythril_image})", settings.docker_bin)
    err = (res.stderr or "").lower()
    if "no such image" in err or "no such object" in err:
        return Runtime(
            "docker", False,
            f"Docker image {settings.mythril_image} is not downloaded. "
            f"Run: docker pull {settings.mythril_image}",
        )
    return Runtime("docker", False, "Docker is installed but its daemon is not reachable. Start Docker Desktop.")
