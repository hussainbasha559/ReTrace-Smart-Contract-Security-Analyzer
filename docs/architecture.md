# Architecture

```
browser (React) ──POST /api/analyze──▶ FastAPI routes
                                          │ validate (utils/validation.py)
                                          ▼
                                    report_service.analyze
                          ┌───────────────┼────────────────────┐
                          ▼               ▼                    ▼
                 bytecode_service   decompiler_service   mythril_service
                 (opcode listing)   └ heimdall_adapter   └ mythril_adapter
                          │               │                    │
                          ▼               ▼                    ▼
                 reentrancy_service   decompiled code     Mythril issues
                 (CFG heuristic)                          (normalized)
                          └───────────────┬────────────────────┘
                                          ▼
                     attach instruction evidence → cross-check → verdict
```

## Verdicts

| Verdict | Meaning |
|---|---|
| `issues_detected` | At least one finding (Mythril and/or the structural heuristic). |
| `no_issues_detected` | Mythril **completed** and nothing was found. Not a proof of safety. |
| `analysis_incomplete` | Mythril was skipped, missing, timed out or failed. Never shown as clean. |

## Endpoints

- `GET  /api/health` — which external tools are installed.
- `POST /api/disassemble` — validation + opcode listing only (no external tools).
- `POST /api/analyze` — the full pipeline. Body: `{ "bytecode": "0x…", "run_decompiler": true, "run_mythril": true }`.

Errors for bad input are HTTP 422 with `{"detail": {"code", "message"}}`. Codes: `empty`,
`invalid_hex`, `odd_length`, `too_large`, `not_a_string`. HTTP 429 `busy` means the concurrency cap is reached.

## Structural heuristic (reentrancy_service.py)

Builds basic blocks, resolves jumps of the form `PUSH <dest>; JUMP/JUMPI`, then asks whether an
`SSTORE` is reachable after each `CALL`/`CALLCODE`/`DELEGATECALL`. Dynamic jumps are not followed
(reported as warnings). Reachable ≠ exploitable; it supplies instruction evidence and a second
opinion to compare against Mythril. Disagreements between the two are surfaced as warnings.

## Security controls

- Bytecode is validated (hex only, ≤ 24,576 bytes) before use.
- External tools run via `subprocess.run(list, shell=False)` with timeouts; input goes through a temp file, never a command string.
- Tool output is capped; request bodies over 256 KB are rejected; concurrent analyses are capped.
- Docker image runs unprivileged with dropped capabilities (see docker-compose.yml).
