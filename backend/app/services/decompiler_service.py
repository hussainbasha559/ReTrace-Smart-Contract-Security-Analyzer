"""Decompilation via Heimdall. Returns a tool report plus the reconstructed code."""
from __future__ import annotations

from typing import Optional

from app.adapters import heimdall_adapter
from app.config import Settings
from app.schemas import ToolReport


def decompile(bytecode_hex: str, settings: Settings) -> tuple[ToolReport, Optional[str]]:
    result = heimdall_adapter.run_heimdall(bytecode_hex, settings)
    report = ToolReport(
        name="heimdall",
        status=result.status,  # type: ignore[arg-type]
        duration_s=round(result.duration_s, 2),
        error=result.error,
        truncated=result.truncated,
    )
    if result.status == "ok" and result.output is not None and not result.output.strip():
        report.status = "error"
        report.error = "Heimdall produced empty output."
        return report, None
    return report, result.output if result.status == "ok" else None
