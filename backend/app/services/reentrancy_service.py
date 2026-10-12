"""Structural re-entrancy heuristic: external call -> reachable storage write.

This is deliberately NOT a proof. It builds a coarse control-flow graph and asks:
"after an external call, can execution reach an SSTORE?". That is the shape of the
classic checks-effects-interactions violation. Limits, stated plainly:

  * Only jumps whose target is a PUSH immediately before JUMP/JUMPI are resolved.
    Dynamic jumps (for example, returns from internal functions) are not followed,
    so a write that happens only after such a jump can be missed.
  * It cannot tell whether the storage slot written is the one the call depended on,
    whether a guard such as a mutex is in place, or how much gas the call forwards.
  * Reachable does not mean exploitable.

Mythril's symbolic execution is the stronger signal; this heuristic exists to give
instruction-level evidence and to be cross-checked against Mythril.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.schemas import Evidence, Finding
from app.services.bytecode_service import TERMINATORS, Instruction

EXTERNAL_CALLS = {"CALL", "CALLCODE", "DELEGATECALL"}
MAX_WRITES_PER_CALL = 5


@dataclass
class Block:
    start: int                       # index into the instruction list
    end: int                         # exclusive
    successors: list[int] = field(default_factory=list)   # block ids
    has_unresolved_jump: bool = False


def build_blocks(instrs: list[Instruction]) -> list[Block]:
    if not instrs:
        return []
    pc_to_idx = {i.pc: k for k, i in enumerate(instrs)}
    jumpdests = {i.pc for i in instrs if i.name == "JUMPDEST"}

    leaders = {0}
    for k, ins in enumerate(instrs):
        if ins.name == "JUMPDEST":
            leaders.add(k)
        if (ins.name in ("JUMP", "JUMPI") or ins.name in TERMINATORS) and k + 1 < len(instrs):
            leaders.add(k + 1)
    starts = sorted(leaders)
    blocks = [
        Block(s, starts[n + 1] if n + 1 < len(starts) else len(instrs))
        for n, s in enumerate(starts)
    ]
    idx_to_block = {}
    for b_id, b in enumerate(blocks):
        for k in range(b.start, b.end):
            idx_to_block[k] = b_id

    for b_id, b in enumerate(blocks):
        last = instrs[b.end - 1]
        prev = instrs[b.end - 2] if b.end - 2 >= b.start else None

        def static_target():
            if prev is not None and prev.name.startswith("PUSH") and prev.operand and not prev.truncated:
                target_pc = int.from_bytes(prev.operand, "big")
                if target_pc in jumpdests:
                    return idx_to_block[pc_to_idx[target_pc]]
            return None

        if last.name == "JUMP":
            t = static_target()
            if t is None:
                b.has_unresolved_jump = True
            else:
                b.successors.append(t)
        elif last.name == "JUMPI":
            t = static_target()
            if t is None:
                b.has_unresolved_jump = True
            else:
                b.successors.append(t)
            if b_id + 1 < len(blocks):
                b.successors.append(b_id + 1)
        elif last.name in TERMINATORS:
            pass
        elif b_id + 1 < len(blocks):
            b.successors.append(b_id + 1)
    return blocks


def _writes_after_call(
    instrs: list[Instruction], blocks: list[Block], call_idx: int
) -> tuple[list[Instruction], bool]:
    """SSTOREs reachable after instruction `call_idx`, and whether an unresolved jump was hit."""
    block_of = {}
    for b_id, b in enumerate(blocks):
        for k in range(b.start, b.end):
            block_of[k] = b_id
    start_block = block_of[call_idx]

    writes: list[Instruction] = []
    unresolved = False
    # Rest of the call's own block.
    for k in range(call_idx + 1, blocks[start_block].end):
        if instrs[k].name == "SSTORE":
            writes.append(instrs[k])
    unresolved |= blocks[start_block].has_unresolved_jump

    seen = {start_block}
    stack = list(blocks[start_block].successors)
    while stack:
        b_id = stack.pop()
        if b_id in seen:
            continue
        seen.add(b_id)
        b = blocks[b_id]
        for k in range(b.start, b.end):
            if instrs[k].name == "SSTORE":
                writes.append(instrs[k])
        unresolved |= b.has_unresolved_jump
        stack.extend(b.successors)

    writes.sort(key=lambda i: i.pc)
    return writes, unresolved


def find_call_then_write(instrs: list[Instruction]) -> tuple[list[Finding], list[str]]:
    blocks = build_blocks(instrs)
    findings: list[Finding] = []
    warnings: list[str] = []
    any_unresolved = any(b.has_unresolved_jump for b in blocks)

    for k, ins in enumerate(instrs):
        if ins.name not in EXTERNAL_CALLS:
            continue
        writes, unresolved = _writes_after_call(instrs, blocks, k)
        if not writes:
            continue
        shown = writes[:MAX_WRITES_PER_CALL]
        pcs = [ins.pc] + [w.pc for w in shown]
        more = len(writes) - len(shown)
        findings.append(
            Finding(
                id=f"heuristic-call-{ins.pc}",
                source="heuristic",
                title="Storage write reachable after external call",
                swc_id="SWC-107",
                severity="medium",
                confidence="heuristic",
                reentrancy_related=True,
                description=(
                    f"The {ins.name} at pc {ins.pc} can reach an SSTORE at "
                    f"pc {', '.join(str(w.pc) for w in shown)}"
                    f"{f' (and {more} more)' if more else ''}."
                ),
                evidence=Evidence(pcs=pcs),   # instruction context is attached by report_service
                explanation=(
                    "If a contract updates its own storage after it has handed control to "
                    "another address, that address may call back into the contract while the "
                    "old state is still in place. This check only shows the ordering exists "
                    "in the control-flow graph; it does not prove the write is the one the "
                    "call depends on, or that the path is exploitable."
                ),
                recommendation=(
                    "Review the function: update balances and other state before the external "
                    "call (checks-effects-interactions), and consider a reentrancy guard."
                ),
            )
        )
        if unresolved:
            warnings.append(
                f"Heuristic path search from the call at pc {ins.pc} reached a jump whose "
                "target could not be resolved statically; some paths were not followed."
            )

    if any_unresolved and not findings:
        warnings.append(
            "The structural heuristic found nothing, but the code contains jumps with "
            "unresolved targets, so some paths were not examined."
        )
    return findings, sorted(set(warnings))
