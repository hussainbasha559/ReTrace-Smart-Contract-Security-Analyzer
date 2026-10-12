"""Safe subprocess runner shared by the tool adapters.

Rules enforced here:
  * arguments are always a list and shell=False, so user input can never be
    interpreted by a shell;
  * every call has a timeout;
  * captured output is capped before it travels any further.
"""
from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from typing import Optional

from app.utils.normalization import truncate


@dataclass
class AdapterResult:
    """What an adapter hands back to a service."""

    status: str                    # ok | not_installed | timeout | error
    output: Optional[str] = None   # primary output (tool-specific)
    error: Optional[str] = None
    duration_s: float = 0.0
    truncated: bool = False


@dataclass
class CommandResult:
    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool
    not_found: bool
    duration_s: float


def _to_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def run_command(args: list[str], timeout_s: float, cwd: Optional[str] = None) -> CommandResult:
    start = time.monotonic()
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_s,
            shell=False,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return CommandResult(None, "", "", False, True, time.monotonic() - start)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            None, _to_text(exc.stdout), _to_text(exc.stderr), True, False,
            time.monotonic() - start,
        )
    return CommandResult(
        proc.returncode, proc.stdout or "", proc.stderr or "", False, False,
        time.monotonic() - start,
    )


def tail(text: str, limit: int = 1500) -> str:
    """Last `limit` characters, which is where tools usually put the real error."""
    text = text.strip()
    return text if len(text) <= limit else "… " + text[-limit:]


def cap(text: str, limit: int) -> tuple[str, bool]:
    return truncate(text, limit)


def scrub(text: str, *paths: object) -> str:
    """Replace server-side temp paths in tool output so API errors never leak them."""
    for p in paths:
        s = str(p)
        if s:
            text = text.replace(s, "<tmp>").replace(s.replace("\\", "/"), "<tmp>")
    return text
