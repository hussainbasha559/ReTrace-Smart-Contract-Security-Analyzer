from app.services.bytecode_service import disassemble
from app.services.reentrancy_service import find_call_then_write

PUSH5 = "6000" * 5


def run(hex_code):
    instrs, _ = disassemble(hex_code)
    return find_call_then_write(instrs)


def test_call_then_sstore_is_flagged_with_pcs():
    code = PUSH5 + "33" + "5a" + "f1" + "50" + "6001" + "6000" + "55" + "00"
    findings, _ = run(code)
    assert len(findings) == 1
    f = findings[0]
    assert f.swc_id == "SWC-107" and f.confidence == "heuristic"
    assert f.evidence.pcs == [12, 18]  # CALL at 12, SSTORE at 18


def test_sstore_before_call_is_not_flagged():
    code = "6001" + "6000" + "55" + PUSH5 + "33" + "5a" + "f1" + "50" + "00"
    findings, _ = run(code)
    assert findings == []


def test_write_reachable_through_static_jump():
    # CALL; PUSH1 5; JUMPI; STOP; JUMPDEST; PUSH1 1; PUSH1 0; SSTORE; STOP
    findings, _ = run("f1600557005b600160005500")
    assert len(findings) == 1
    assert findings[0].evidence.pcs == [0, 10]


def test_unreachable_write_is_not_flagged():
    # CALL; STOP; JUMPDEST; ... SSTORE  (nothing jumps to the JUMPDEST)
    findings, _ = run("f1005b600160005500")
    assert findings == []


def test_no_call_no_finding():
    findings, _ = run("600160005500")
    assert findings == []


def test_unresolved_jump_is_reported_when_nothing_found():
    # CALL; PUSH1 0; CALLDATALOAD; JUMP (dynamic target) -> cannot follow
    findings, warnings = run("f1" + "6000" + "35" + "56")
    assert findings == []
    assert any("unresolved" in w for w in warnings)
