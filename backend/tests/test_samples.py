"""Regression test on real solc output (solc 0.8.26, optimizer off, evm paris)."""
from pathlib import Path

import pytest

from app.services.bytecode_service import disassemble
from app.services.reentrancy_service import find_call_then_write
from app.utils.validation import validate_bytecode

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def load(rel):
    return disassemble(validate_bytecode((SAMPLES / rel).read_text(), 24_576))[0]


def test_vulnerable_bank_is_flagged():
    findings, _ = find_call_then_write(load("vulnerable/VulnerableBank.runtime.hex"))
    assert len(findings) == 1
    call_pc, write_pc = findings[0].evidence.pcs[:2]
    ins = {i.pc: i.name for i in load("vulnerable/VulnerableBank.runtime.hex")}
    assert ins[call_pc] == "CALL" and ins[write_pc] == "SSTORE"


def test_corrected_bank_is_not_flagged():
    findings, _ = find_call_then_write(load("corrected/SafeBank.runtime.hex"))
    assert findings == []
