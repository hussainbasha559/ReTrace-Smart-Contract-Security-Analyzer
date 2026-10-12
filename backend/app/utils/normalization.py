"""Convert tool-specific output into the consistent shapes used by the API."""
from __future__ import annotations

import json
from typing import Any, Optional

from app.schemas import Severity

_SEVERITY = {
    "high": "high",
    "critical": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
    "info": "informational",
}


def normalize_severity(value: Any) -> Severity:
    return _SEVERITY.get(str(value or "").strip().lower(), "informational")  # type: ignore[return-value]


def truncate(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[:limit] + "\n… [truncated]", True


def issue_description(issue: dict) -> str:
    """Mythril has emitted `description` as a string and as {head, tail}."""
    desc = issue.get("description")
    if isinstance(desc, dict):
        parts = [str(desc.get("head", "")).strip(), str(desc.get("tail", "")).strip()]
        return " ".join(p for p in parts if p)
    return str(desc or "").strip()


def issue_pc(issue: dict) -> Optional[int]:
    addr = issue.get("address")
    if isinstance(addr, bool):
        return None
    if isinstance(addr, int):
        return addr
    if isinstance(addr, str) and addr.strip().lstrip("-").isdigit():
        return int(addr)
    return None


def compact_issue_json(issue: dict, limit: int = 2000) -> str:
    text = json.dumps(issue, indent=2, sort_keys=True, default=str)
    return truncate(text, limit)[0]
