"""Static, reviewed security guidance. Used as (a) the rule-based fallback when no LLM is
configured and (b) reference material the LLM is told to stay consistent with."""
from __future__ import annotations

REENTRANCY = {
    "what": ("Re-entrancy happens when a contract makes an external call (for example sending ETH) before it has "
             "finished updating its own state. The callee can call back into the contract while the old state is "
             "still in place."),
    "impact": ("If the contract pays out based on a stored balance, a malicious callee may be able to trigger repeated "
               "withdrawals before the balance is reduced. The size of any loss depends on funds held, which this tool "
               "does not know."),
    "conditions": [
        "The external call forwards enough gas for the callee to execute code.",
        "The callee address can be a contract an attacker controls.",
        "Contract state that the call depends on is still unchanged when control returns.",
        "The vulnerable function can be reached again (re-entered) during the call.",
    ],
    "fixes": [
        "Checks-effects-interactions: validate inputs, update storage (for example set the balance to zero), and only then make the external call.",
        "Add a re-entrancy guard (a mutex such as OpenZeppelin's ReentrancyGuard `nonReentrant` modifier) on functions that make external calls and change state.",
        "Prefer pull payments: record what each user is owed and let them withdraw, instead of pushing ETH during other logic.",
        "Limit forwarded gas only as defense in depth; it is not a substitute for correct ordering.",
    ],
    "tests": [
        "Write a test with an attacker contract whose receive()/fallback() calls the vulnerable function again; assert the balance cannot be drained.",
        "Assert state variables are updated before the external call (check storage inside the callback).",
        "Run the same test against the fixed version to confirm the callback now reverts or does nothing.",
    ],
    "example": ("// Illustrative only (not recovered from bytecode)\n"
                "function withdraw() external {\n"
                "    uint256 amount = balances[msg.sender];\n"
                "    balances[msg.sender] = 0;                       // effect first\n"
                "    (bool ok, ) = msg.sender.call{value: amount}(\"\"); // interaction last\n"
                "    require(ok, \"transfer failed\");\n"
                "}"),
}

EXTERNAL_CALL = {
    "what": "The contract performs a call to an address that can be chosen by the caller or by stored data.",
    "impact": "On its own this is informational: it becomes a re-entrancy or logic problem only if state is inconsistent when the call happens.",
    "conditions": ["The target address is attacker-controlled.", "State changes or checks are ordered after the call."],
    "fixes": ["Apply checks-effects-interactions around the call.", "Validate or restrict the target address when it does not need to be arbitrary.",
              "Check the call's success and handle failure explicitly."],
    "tests": ["Test with a malicious receiver contract that reverts, consumes gas, or calls back."],
    "example": None,
}

GENERIC = {
    "what": "The analyzer flagged a pattern that may indicate a vulnerability or a risky construct.",
    "impact": "Impact depends on the contract's purpose and the funds or permissions it controls, which are not known from bytecode alone.",
    "conditions": ["See the evidence instructions and the tool's own description for the exact condition."],
    "fixes": ["Review the flagged instructions against the original source and apply the tool's recommendation."],
    "tests": ["Write a regression test that reproduces the flagged condition before fixing it, then confirm it passes after."],
    "example": None,
}


def guidance_for(finding: dict) -> dict:
    if (finding.get("reentrancy_related") and "state" in finding["title"].lower()) or finding.get("source") == "heuristic":
        return REENTRANCY
    if finding.get("reentrancy_related"):
        return EXTERNAL_CALL
    return GENERIC
