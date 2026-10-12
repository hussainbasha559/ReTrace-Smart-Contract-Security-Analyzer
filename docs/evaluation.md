# Evaluation: live Heimdall + Mythril runs

Recorded 2026-10-10 by running the full backend (`POST /api/analyze`) against the two committed samples
with both real tools on PATH.

## Environment

| Item | Value |
|---|---|
| Mythril | v0.24.8 (`pip install mythril` in a venv) |
| Heimdall-rs | 0.9.3 release binary (it prints `heimdall 0.9.2` for `--version`; the output header says the same) |
| Python | 3.12 |
| Adapter flags | unchanged: `heimdall decompile <file> --include-sol --skip-resolving --output <dir>`; `myth analyze -f <file> --bin-runtime -o json -t 2 --execution-timeout 60` |

## Results

| Sample | Verdict | Mythril (time) | Heimdall (time) | Findings |
|---|---|---|---|---|
| `vulnerable/VulnerableBank` | `issues_detected` | ok (~38-40 s) | ok (~0.2 s) | Mythril: External Call To User-Supplied Address (SWC-107, low, pc 360); Transaction Order Dependence (SWC-114, medium, pc 360); **State access after external call (SWC-107, medium, pc 548)**. Heuristic: storage write reachable after call (pc 360 -> 548). Both tools corroborate each other. |
| `corrected/SafeBank` | `issues_detected` | ok (~30-32 s) | ok (~0.2 s) | Mythril: External Call To User-Supplied Address (SWC-107, low, pc 428); Transaction Order Dependence (SWC-114, medium, pc 428). **No "state access after external call"**; heuristic finds nothing. |

Heimdall's decompiled `withdraw()` shows the difference directly: in the vulnerable sample the transfer comes
before `storage_map_a[var_a] = 0`; in the corrected sample the write comes first.

## Observations

- **The discriminating signal is Mythril's "State access after external call".** Present only in the vulnerable
  sample, and it lines up with the heuristic's SSTORE at pc 548.
- **The corrected sample still gets an `issues_detected` verdict.** Mythril reports the low-severity external call
  and SWC-114 even for correctly ordered code, because `withdraw()` does call `msg.sender`. These are true
  statements about the code, not reentrancy proof. Decide whether informational call-only findings should
  count toward the verdict; today every finding does.
- **Fixed during this run:** the call-only finding used to trigger a misleading "Mythril reported a re-entrancy
  issue the heuristic did not reproduce" warning on the corrected sample. Cross-tool warnings now key on
  Mythril's state-access finding only (see `report_service._cross_check`, regression test in `test_api.py`).
- Mythril exits with code 1 when it finds issues; the adapter correctly keys off stdout, not the return code.
- Mythril JSON for these samples is 7-11 KB, far below the 200,000-character cap (the full `tx_sequence`
  includes the bytecode, so larger contracts will be bigger).

## Setup gotchas

- Mythril on Python 3.12 may fail with `No module named 'pkg_resources'`; fix with `pip install "setuptools<81"`.
- `bifrost` requires `cargo` even with `-B`. Without Rust, download the release binary directly:
  `https://github.com/Jon-Becker/heimdall-rs/releases/download/<version>/heimdall-linux-amd64`.
- On WSL, run everything inside the Linux shell, not PowerShell.

## Still not evaluated

False-positive/negative rates beyond these two samples, Mythril timing on large contracts, the Docker image
build, and visual review of the frontend.
