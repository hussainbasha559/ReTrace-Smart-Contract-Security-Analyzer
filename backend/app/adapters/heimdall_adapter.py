"""Controlled interface to Heimdall-rs (decompiler).

Heimdall can run natively, or inside Ubuntu/WSL2 when the backend runs on Windows
(see adapters/runtime.py). In WSL mode the temp files live on the Windows drive and are
handed to Heimdall through /mnt/<drive>/..., so no copying is needed.

Heimdall's CLI flags change between releases. Verify them with
`heimdall decompile --help`; extra flags can be supplied without code changes
through the RETRACE_HEIMDALL_ARGS environment variable.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from app.adapters import runtime
from app.adapters.base import AdapterResult, cap, run_command, scrub, tail
from app.config import Settings


def is_available(settings: Settings) -> bool:
    return runtime.resolve_heimdall(settings).available


def describe(settings: Settings) -> str:
    return runtime.resolve_heimdall(settings).detail


def build_args(rt: runtime.Runtime, settings: Settings, code_file: Path, out_dir: Path) -> list[str]:
    """Build the command line. Raises ValueError if a path cannot be translated for WSL."""
    if rt.mode == "wsl":
        target = runtime.windows_to_wsl_path(str(code_file), settings.wsl_mount_root)
        out = runtime.windows_to_wsl_path(str(out_dir), settings.wsl_mount_root)
        head = [*runtime.wsl_prefix(settings), rt.bin]
    else:
        target, out, head = str(code_file), str(out_dir), [rt.bin]
    return [
        *head,
        "decompile",
        target,
        "--include-sol",
        "--skip-resolving",   # no network lookups for function signatures
        "--output",
        out,
        *settings.heimdall_extra_args,
    ]


def run_heimdall(bytecode_hex: str, settings: Settings) -> AdapterResult:
    """Decompile validated, prefix-free hex bytecode. Returns Solidity-like text."""
    rt = runtime.resolve_heimdall(settings)
    if not rt.available:
        return AdapterResult("not_installed", error=rt.detail)

    with tempfile.TemporaryDirectory(prefix="retrace-heimdall-") as tmp:
        tmp_path = Path(tmp).resolve()      # resolve() expands Windows 8.3 short names
        code_file = tmp_path / "runtime.hex"
        code_file.write_text("0x" + bytecode_hex)
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        try:
            args = build_args(rt, settings, code_file, out_dir)
        except ValueError as exc:
            return AdapterResult("error", error=str(exc))
        res = run_command(args, timeout_s=settings.decompile_timeout_s)

        if res.not_found:
            runtime.reset_cache()
            return AdapterResult("not_installed", error=f"Could not start Heimdall ({rt.detail}).")
        if res.timed_out:
            return AdapterResult(
                "timeout",
                error=f"Decompilation exceeded {settings.decompile_timeout_s}s.",
                duration_s=res.duration_s,
            )
        if res.returncode != 0:
            message = scrub(tail(res.stderr or res.stdout), tmp_path)
            return AdapterResult(
                "error",
                error=message or f"Heimdall exited with code {res.returncode}.",
                duration_s=res.duration_s,
            )

        # Heimdall nests its output directory differently across versions.
        candidates = sorted(out_dir.rglob("decompiled.sol")) or sorted(
            out_dir.rglob("decompiled.*")
        )
        if not candidates:
            return AdapterResult(
                "error",
                error="Heimdall finished but produced no decompiled output file.",
                duration_s=res.duration_s,
            )
        text = candidates[0].read_text(errors="replace")
        text, truncated = cap(text, settings.max_tool_output_chars)
        return AdapterResult("ok", output=text, duration_s=res.duration_s, truncated=truncated)
