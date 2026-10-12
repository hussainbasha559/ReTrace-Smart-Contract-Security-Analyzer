"""API request/response shapes. The frontend renders exactly these fields."""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

ToolStatus = Literal["ok", "not_installed", "timeout", "error", "skipped"]
Verdict = Literal["issues_detected", "no_issues_detected", "analysis_incomplete"]
Severity = Literal["high", "medium", "low", "informational"]


class DisassembleRequest(BaseModel):
    bytecode: str


class AnalyzeRequest(BaseModel):
    bytecode: str
    run_decompiler: bool = True
    run_mythril: bool = True


class InstructionOut(BaseModel):
    pc: int
    opcode: str            # "0x60"
    name: str              # "PUSH1"
    operand: Optional[str] = None   # hex without prefix, PUSH only
    truncated: bool = False         # PUSH data runs past the end of the code


class ToolReport(BaseModel):
    name: str
    status: ToolStatus
    duration_s: float = 0.0
    error: Optional[str] = None
    truncated: bool = False


class Evidence(BaseModel):
    pcs: list[int] = Field(default_factory=list)
    instructions: list[InstructionOut] = Field(default_factory=list)  # context window
    tool_output: Optional[str] = None


class Finding(BaseModel):
    id: str
    source: Literal["mythril", "heuristic"]
    title: str
    swc_id: Optional[str] = None
    severity: Severity
    confidence: Literal["tool_reported", "heuristic"]
    reentrancy_related: bool = False
    description: str
    function: Optional[str] = None
    evidence: Evidence = Field(default_factory=Evidence)
    explanation: str
    recommendation: str
    corroborated_by: list[str] = Field(default_factory=list)


class DisassembleResponse(BaseModel):
    input_bytes: int
    instruction_count: int
    instructions: list[InstructionOut]
    warnings: list[str] = Field(default_factory=list)


class AnalyzeResponse(BaseModel):
    status: Literal["completed", "partial"]
    verdict: Verdict
    verdict_reason: str
    input_bytes: int
    instructions: list[InstructionOut]
    decompiled_code: Optional[str] = None
    tools: list[ToolReport] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class HealthResponse(BaseModel):
    status: Literal["ok"]
    tools: dict[str, bool]
    # How each tool runs ("native", "WSL (Ubuntu)", "Docker (mythril/myth:latest)") or why it
    # is unavailable. Contains no server file paths.
    details: dict[str, str] = Field(default_factory=dict)
