"""EVM bytecode -> instruction list (program counter, opcode, operand)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.schemas import InstructionOut

_BASE: dict[int, str] = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV", 0x05: "SDIV",
    0x06: "MOD", 0x07: "SMOD", 0x08: "ADDMOD", 0x09: "MULMOD", 0x0A: "EXP", 0x0B: "SIGNEXTEND",
    0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ", 0x15: "ISZERO",
    0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT", 0x1A: "BYTE", 0x1B: "SHL",
    0x1C: "SHR", 0x1D: "SAR",
    0x20: "KECCAK256",
    0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER", 0x34: "CALLVALUE",
    0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY", 0x38: "CODESIZE",
    0x39: "CODECOPY", 0x3A: "GASPRICE", 0x3B: "EXTCODESIZE", 0x3C: "EXTCODECOPY",
    0x3D: "RETURNDATASIZE", 0x3E: "RETURNDATACOPY", 0x3F: "EXTCODEHASH",
    0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP", 0x43: "NUMBER",
    0x44: "PREVRANDAO", 0x45: "GASLIMIT", 0x46: "CHAINID", 0x47: "SELFBALANCE",
    0x48: "BASEFEE", 0x49: "BLOBHASH", 0x4A: "BLOBBASEFEE",
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8", 0x54: "SLOAD",
    0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI", 0x58: "PC", 0x59: "MSIZE", 0x5A: "GAS",
    0x5B: "JUMPDEST", 0x5C: "TLOAD", 0x5D: "TSTORE", 0x5E: "MCOPY", 0x5F: "PUSH0",
    0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE", 0xF3: "RETURN", 0xF4: "DELEGATECALL",
    0xF5: "CREATE2", 0xFA: "STATICCALL", 0xFD: "REVERT", 0xFE: "INVALID", 0xFF: "SELFDESTRUCT",
}
OPCODES: dict[int, str] = dict(_BASE)
for _i in range(1, 33):
    OPCODES[0x5F + _i] = f"PUSH{_i}"
for _i in range(1, 17):
    OPCODES[0x7F + _i] = f"DUP{_i}"
    OPCODES[0x8F + _i] = f"SWAP{_i}"
for _i in range(5):
    OPCODES[0xA0 + _i] = f"LOG{_i}"

# Opcodes after which execution cannot continue to the next instruction.
TERMINATORS = {"STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT"}


@dataclass(frozen=True)
class Instruction:
    pc: int
    opcode: int
    name: str
    operand: Optional[bytes] = None
    truncated: bool = False

    @property
    def size(self) -> int:
        return 1 + (len(self.operand) if self.operand is not None else 0)

    @property
    def is_unknown(self) -> bool:
        return self.opcode not in OPCODES

    def to_out(self) -> InstructionOut:
        return InstructionOut(
            pc=self.pc,
            opcode=f"0x{self.opcode:02x}",
            name=self.name,
            operand=self.operand.hex() if self.operand else None,
            truncated=self.truncated,
        )


def disassemble(bytecode_hex: str) -> tuple[list[Instruction], list[str]]:
    """Decode validated, prefix-free hex bytecode.

    PUSH data is consumed as an operand, never decoded as opcodes, so a 0x5b byte
    inside PUSH data is correctly *not* a JUMPDEST.
    """
    code = bytes.fromhex(bytecode_hex)
    instructions: list[Instruction] = []
    warnings: list[str] = []
    pc, n = 0, len(code)

    while pc < n:
        op = code[pc]
        name = OPCODES.get(op, f"UNKNOWN_0x{op:02x}")
        operand = None
        truncated = False
        if name.startswith("PUSH") and name != "PUSH0":
            width = int(name[4:])
            operand = code[pc + 1 : pc + 1 + width]
            truncated = len(operand) < width
        elif name == "PUSH0":
            operand = None
        instr = Instruction(pc, op, name, operand, truncated)
        instructions.append(instr)
        pc += instr.size

    unknown = sum(1 for i in instructions if i.is_unknown)
    if unknown:
        warnings.append(
            f"{unknown} byte(s) decode to undefined opcodes. This is normal at the end of "
            "Solidity runtime code, where compiler metadata is stored as data, but it can "
            "also mean the input is not EVM runtime bytecode."
        )
    if instructions and instructions[-1].truncated:
        warnings.append("The final PUSH instruction is cut off by the end of the code.")
    return instructions, warnings
