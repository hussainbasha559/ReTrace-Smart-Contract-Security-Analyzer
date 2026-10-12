"""Security analysis via Mythril. Parses its JSON into normalized findings."""
from __future__ import annotations

import json

from app.adapters import mythril_adapter
from app.config import Settings
from app.schemas import Evidence, Finding, ToolReport
from app.utils.normalization import (
    compact_issue_json,
    issue_description,
    issue_pc,
    normalize_severity,
)

_REENTRANCY_EXPLANATIONS = {
    "state": (
        "Mythril found a path where contract state is read or written after an external call. "
        "If the callee is attacker-controlled it can call back in before the state is updated, "
        "which is the pattern behind re-entrancy attacks."
    ),
    "call": (
        "Mythril reports an external call to another address. A call alone is not a "
        "vulnerability, but it hands control to code the contract does not own; check what "
        "state is touched before and after it."
    ),
}
_REENTRANCY_FIX = (
    "Apply checks-effects-interactions: update balances and other state before the external "
    "call. Add a reentrancy guard, or use a pull-payment pattern so the contract does not "
    "push funds during state-changing logic."
)
_GENERIC_FIX = "Review the flagged instruction and the related SWC entry for remediation guidance."


def _parse_issues(raw: str) -> tuple[list[dict], str | None]:
    """Return (issues, error). Mythril reports its own failures inside the JSON."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return [], "Mythril output was not valid JSON."
    if not isinstance(data, dict):
        return [], "Mythril output had an unexpected structure."
    if data.get("success") is False or data.get("error"):
        return [], f"Mythril reported an error: {str(data.get('error'))[:500]}"
    issues = data.get("issues", [])
    if not isinstance(issues, list):
        return [], "Mythril output had an unexpected 'issues' field."
    return [i for i in issues if isinstance(i, dict)], None


def analyze(bytecode_hex: str, settings: Settings) -> tuple[ToolReport, list[Finding]]:
    result = mythril_adapter.run_mythril(bytecode_hex, settings)
    report = ToolReport(
        name="mythril",
        status=result.status,  # type: ignore[arg-type]
        duration_s=round(result.duration_s, 2),
        error=result.error,
        truncated=result.truncated,
    )
    if result.status != "ok" or result.output is None:
        return report, []

    issues, parse_error = _parse_issues(result.output)
    if parse_error:
        report.status = "error"
        report.error = parse_error
        return report, []

    findings: list[Finding] = []
    for n, issue in enumerate(issues):
        swc_raw = str(issue.get("swc-id") or issue.get("swc_id") or "").strip()
        swc = f"SWC-{swc_raw}" if swc_raw and not swc_raw.upper().startswith("SWC") else (swc_raw or None)
        title = str(issue.get("title") or "Untitled Mythril issue")
        reentrancy = swc == "SWC-107"
        pc = issue_pc(issue)

        if reentrancy:
            kind = "state" if "state" in title.lower() else "call"
            explanation = _REENTRANCY_EXPLANATIONS[kind]
            fix = _REENTRANCY_FIX
        else:
            explanation = "Reported by Mythril's symbolic execution; see the description and evidence."
            fix = _GENERIC_FIX

        findings.append(
            Finding(
                id=f"mythril-{n}-{pc if pc is not None else 'na'}",
                source="mythril",
                title=title,
                swc_id=swc,
                severity=normalize_severity(issue.get("severity")),
                confidence="tool_reported",
                reentrancy_related=reentrancy,
                description=issue_description(issue) or title,
                function=(str(issue["function"]) if issue.get("function") else None),
                evidence=Evidence(
                    pcs=[pc] if pc is not None else [],
                    tool_output=compact_issue_json(issue),
                ),
                explanation=explanation,
                recommendation=fix,
            )
        )
    return report, findings
