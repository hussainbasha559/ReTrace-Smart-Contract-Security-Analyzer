# Samples

| Contract | Expectation |
|---|---|
| `vulnerable/VulnerableBank.sol` | External call, then `balances[msg.sender] = 0` — should be flagged. |
| `corrected/SafeBank.sol` | Same logic with the state cleared first — should not be flagged. |

The `*.runtime.hex` files are real runtime bytecode compiled with **solc 0.8.26, optimizer off,
EVM `paris`**, so they are reproducible. With Foundry installed you can regenerate them from this folder:

```bash
forge inspect VulnerableBank deployedBytecode --root . > vulnerable/VulnerableBank.runtime.hex
```

(Foundry's output may differ slightly from solc-js depending on compiler settings; the program counters
in the tests refer to the files committed here.)

Verified so far (structural heuristic only): vulnerable → CALL at pc 360 reaches SSTORE at pc 548;
corrected → no finding. **Mythril and Heimdall results have not been recorded yet** — that is the first
job of the evaluation step.
