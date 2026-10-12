"""Orchestrates one analysis request and correlates the results.

Order of work: validate -> disassemble -> (Heimdall || Mythril) -> heuristic ->
attach instruction evidence -> cross-check tools -> choose a verdict.

The verdict deliberately has three outcomes. "No issues detected" is only
returned when Mythril actually completed; a failure or timeout is reported as
"analysis incomplete", never as a clean result.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from app.config import Settings
from app.schemas import (
    AnalyzeResponse,
    DisassembleResponse,
    Finding,
    ToolReport,
    Verdict,
)
from app.services import decompiler_service, mythril_service, reentrancy_service
from app.services.bytecode_service import Instruction, disassemble
from app.utils.validation import validate_bytecode

CONTEXT_BEFORE = 3
CONTEXT_AFTER = 3


def disassemble_only(raw: str, settings: Settings) -> DisassembleResponse:
    hex_code = validate_bytecode(raw, settings.max_bytecode_bytes)
    instrs, warnings = disassemble(hex_code)
    return DisassembleResponse(
        input_bytes=len(hex_code) // 2,
        instruction_count=len(instrs),
        instructions=[i.to_out() for i in instrs],
        warnings=warnings,
    )


def _attach_context(findings: list[Finding], instrs: list[Instruction], warnings: list[str]) -> None:
    index = {ins.pc: k for k, ins in enumerate(instrs)}
    for f in findings:
        picked: dict[int, Instruction] = {}
        for pc in f.evidence.pcs:
            k = index.get(pc)
            if k is None:
                warnings.append(
                    f"Finding '{f.title}' points at pc {pc}, which is not an instruction "
                    "boundary in the supplied bytecode. Was this the runtime code?"
                )
                continue
            for j in range(max(0, k - CONTEXT_BEFORE), min(len(instrs), k + CONTEXT_AFTER + 1)):
                picked[instrs[j].pc] = instrs[j]
        f.evidence.instructions = [picked[pc].to_out() for pc in sorted(picked)]


def _cross_check(findings: list[Finding], mythril_ok: bool, warnings: list[str]) -> None:
    mythril_re = [f for f in findings if f.source == "mythril" and f.reentrancy_related]
    # Only Mythril's "state access after external call" result is comparable to the
    # heuristic (which looks for a storage write after a call). A plain "external call to a
    # user-supplied address" is informational and appears even in correctly ordered code, so
    # it must not trigger disagreement warnings.
    mythril_state = [f for f in mythril_re if "state" in f.title.lower()]
    heuristic = [f for f in findings if f.source == "heuristic"]

    for h in heuristic:
        h_pcs = set(h.evidence.pcs)
        for m in mythril_re:
            if h_pcs & set(m.evidence.pcs):
                h.corroborated_by.append(m.id)
                m.corroborated_by.append(h.id)

    if mythril_ok and heuristic and not mythril_state:
        warnings.append(
            "Tools disagree: the structural heuristic found a storage write after an external "
            "call, but Mythril reported no re-entrancy issue. Mythril may have proved the path "
            "infeasible, or the heuristic may be over-approximating. Inspect the evidence."
        )
    if mythril_state and not heuristic:
        warnings.append(
            "Mythril reported a re-entrancy-related issue that the structural heuristic did "
            "not reproduce; the path may use jumps the heuristic cannot resolve."
        )


def _verdict(
    findings: list[Finding], tools: list[ToolReport], run_mythril: bool
) -> tuple[Verdict, str]:
    mythril = next((t for t in tools if t.name == "mythril"), None)
    if findings:
        n_m = sum(1 for f in findings if f.source == "mythril")
        n_h = len(findings) - n_m
        parts = []
        if n_m:
            parts.append(f"{n_m} reported by Mythril")
        if n_h:
            parts.append(f"{n_h} by the structural heuristic")
        reason = f"{len(findings)} finding(s): " + " and ".join(parts) + "."
        if n_m == 0:
            reason += " Only the heuristic flagged this, which is a lower-confidence signal."
        if mythril is not None and mythril.status != "ok":
            reason += f" Mythril did not complete ({mythril.status}), so the list may be incomplete."
        return "issues_detected", reason

    if not run_mythril or mythril is None:
        return (
            "analysis_incomplete",
            "Mythril was not run. The structural heuristic alone cannot show that "
            "re-entrancy is absent.",
        )
    if mythril.status != "ok":
        return (
            "analysis_incomplete",
            f"Mythril did not complete ({mythril.status}): {mythril.error or 'no details'} "
            "This is not a clean result.",
        )
    return (
        "no_issues_detected",
        "Mythril completed and the structural heuristic found nothing. This is not a proof "
        "of safety: symbolic execution is bounded by timeouts and transaction depth.",
    )


def analyze(
    raw: str, run_decompiler: bool, run_mythril: bool, settings: Settings
) -> AnalyzeResponse:
    hex_code = validate_bytecode(raw, settings.max_bytecode_bytes)
    instrs, warnings = disassemble(hex_code)

    tools: list[ToolReport] = []
    decompiled: str | None = None
    findings: list[Finding] = []

    with ThreadPoolExecutor(max_workers=2) as pool:
        dec_future = pool.submit(decompiler_service.decompile, hex_code, settings) if run_decompiler else None
        myth_future = pool.submit(mythril_service.analyze, hex_code, settings) if run_mythril else None

        if dec_future is not None:
            report, decompiled = dec_future.result()
            tools.append(report)
        else:
            tools.append(ToolReport(name="heimdall", status="skipped"))

        if myth_future is not None:
            report, myth_findings = myth_future.result()
            tools.append(report)
            findings.extend(myth_findings)
        else:
            tools.append(ToolReport(name="mythril", status="skipped"))

    heuristic_findings, heuristic_warnings = reentrancy_service.find_call_then_write(instrs)
    findings.extend(heuristic_findings)
    warnings.extend(heuristic_warnings)

    _attach_context(findings, instrs, warnings)
    mythril_report = next(t for t in tools if t.name == "mythril")
    _cross_check(findings, mythril_report.status == "ok", warnings)

    for t in tools:
        if t.status in ("not_installed", "timeout", "error"):
            warnings.append(f"{t.name}: {t.status}. {t.error or ''}".strip())
        if t.truncated:
            warnings.append(f"{t.name}: output was truncated at the size limit.")

    verdict, reason = _verdict(findings, tools, run_mythril)
    requested_ok = all(t.status in ("ok", "skipped") for t in tools)

    return AnalyzeResponse(
        status="completed" if requested_ok else "partial",
        verdict=verdict,
        verdict_reason=reason,
        input_bytes=len(hex_code) // 2,
        instructions=[i.to_out() for i in instrs],
        decompiled_code=decompiled,
        tools=tools,
        findings=findings,
        warnings=warnings,
    )
