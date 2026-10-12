"""Check the real Heimdall + Mythril integration end to end, without starting the web server.

    python verify_tools.py                 # analyse the vulnerable sample with both tools
    python verify_tools.py --no-mythril    # quick check of Heimdall only

Prints how each tool is launched, whether it worked, and what it found.
Exit code 0 only if every tool that was run completed.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app.adapters import heimdall_adapter, mythril_adapter
from app.config import get_settings
from app.services import report_service

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "vulnerable" / "VulnerableBank.runtime.hex"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--no-mythril", action="store_true", help="skip Mythril (it takes ~30-90 s)")
    ap.add_argument("--no-heimdall", action="store_true", help="skip Heimdall")
    ap.add_argument("--file", type=Path, default=SAMPLE, help="hex file to analyse")
    args = ap.parse_args()

    s = get_settings()
    print("How the tools will run")
    print(f"  heimdall : {'OK ' if heimdall_adapter.is_available(s) else 'MISSING'} {heimdall_adapter.describe(s)}")
    print(f"  mythril  : {'OK ' if mythril_adapter.is_available(s) else 'MISSING'} {mythril_adapter.describe(s)}")

    code = args.file.read_text().strip()
    print(f"\nAnalysing {args.file.name} ({len(code) // 2:,} bytes) ... Mythril can take a minute.")
    result = report_service.analyze(code, not args.no_heimdall, not args.no_mythril, s)

    print("\nTool results")
    ok = True
    for t in result.tools:
        print(f"  {t.name:<8} {t.status:<14} {t.duration_s:>6.1f}s  {t.error or ''}")
        ok = ok and t.status in ("ok", "skipped")

    print(f"\nVerdict : {result.verdict}\n  {result.verdict_reason}")
    for f in result.findings:
        pcs = ",".join(map(str, f.evidence.pcs)) or "-"
        print(f"  [{f.severity:<13}] {f.source:<9} {f.title} (pc {pcs})")
    if result.decompiled_code:
        print("\nDecompiled output (first 8 lines):")
        print("\n".join("  " + ln for ln in result.decompiled_code.splitlines()[:8]))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
