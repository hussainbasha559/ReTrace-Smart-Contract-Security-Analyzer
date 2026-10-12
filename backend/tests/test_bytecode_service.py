from app.services.bytecode_service import disassemble


def test_basic_listing_and_pcs():
    instrs, warnings = disassemble("6001600055")  # PUSH1 1, PUSH1 0, SSTORE
    assert [(i.pc, i.name) for i in instrs] == [(0, "PUSH1"), (2, "PUSH1"), (4, "SSTORE")]
    assert instrs[0].operand == b"\x01"
    assert warnings == []


def test_push_data_is_not_decoded_as_opcodes():
    # PUSH2 0x5b5b: the 0x5b bytes are data, not JUMPDESTs.
    instrs, _ = disassemble("615b5b00")
    assert [i.name for i in instrs] == ["PUSH2", "STOP"]


def test_push0_and_wide_push():
    instrs, _ = disassemble("5f" + "7f" + "ff" * 32)
    assert [i.name for i in instrs] == ["PUSH0", "PUSH32"]
    assert instrs[1].pc == 1 and instrs[1].size == 33


def test_truncated_push_is_flagged():
    instrs, warnings = disassemble("6100")  # PUSH2 with one data byte
    assert instrs[0].truncated
    assert any("cut off" in w for w in warnings)


def test_unknown_opcode_warns():
    instrs, warnings = disassemble("0c")
    assert instrs[0].name == "UNKNOWN_0x0c"
    assert warnings


def test_call_family_names():
    instrs, _ = disassemble("f1f2f4fa")
    assert [i.name for i in instrs] == ["CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"]
