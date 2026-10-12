"""Controlled interface to Mythril (symbolic-execution security analysis).

Mythril can run natively or from the official Docker image. In Docker mode the container is
started with no network, a read-only bind mount holding only the bytecode file, dropped
capabilities, and memory / CPU / process limits, and it is force-removed if it times out.
"""
from __future__ import annotations

import os
import tempfile
import uuid
from pathlib import Path

from app.adapters import runtime
from app.adapters.base import AdapterResult, cap, run_command, scrub, tail
from app.config import Settings

# Added on top of Mythril's own execution timeout, to cover start-up and solver overhead.
_GRACE_S = 30
_CONTAINER_PATH = "/work/runtime.hex"


def is_available(settings: Settings) -> bool:
    return runtime.resolve_mythril(settings).available


def describe(settings: Settings) -> str:
    return runtime.resolve_mythril(settings).detail


def _myth_args(settings: Settings, code_path: str) -> list[str]:
    args = [
        "analyze",
        "-f", code_path,
        "--bin-runtime",
        "-o", "json",
        "-t", str(settings.mythril_transaction_count),
        "--execution-timeout", str(settings.mythril_timeout_s),
    ]
    if settings.mythril_modules:
        args += ["-m", settings.mythril_modules]
    return args


def build_args(
    rt: runtime.Runtime, settings: Settings, code_file: Path, container_name: str
) -> list[str]:
    if rt.mode == "docker":
        return [
            rt.bin, "run", "--rm",
            "--name", container_name,
            "--network", "none",                      # bytecode analysis needs no network
            "--memory", settings.docker_memory,
            "--cpus", settings.docker_cpus,
            "--pids-limit", str(settings.docker_pids_limit),
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--tmpfs", "/tmp",
            "--mount", f"type=bind,source={code_file.parent},target=/work,readonly",
            settings.mythril_image,
            *_myth_args(settings, _CONTAINER_PATH),
        ]
    return [rt.bin, *_myth_args(settings, str(code_file))]


def _kill_container(settings: Settings, name: str) -> None:
    """Stopping the docker CLI does not stop the container, so remove it explicitly."""
    run_command([settings.docker_bin, "rm", "-f", name], timeout_s=20)


def run_mythril(bytecode_hex: str, settings: Settings) -> AdapterResult:
    """Analyse validated runtime bytecode. `output` is Mythril's raw JSON text."""
    rt = runtime.resolve_mythril(settings)
    if not rt.available:
        return AdapterResult("not_installed", error=rt.detail)

    with tempfile.TemporaryDirectory(prefix="retrace-mythril-") as tmp:
        tmp_path = Path(tmp).resolve()
        # A file avoids command-line length limits (Windows caps a command at ~32k chars,
        # while 24 KB of bytecode is 49k hex characters).
        code_file = tmp_path / "runtime.hex"
        code_file.write_text(bytecode_hex)
        if rt.mode == "docker" and os.name != "nt":
            # The container's root has no capabilities, so it needs world-readable permissions.
            # The file holds only public bytecode, so this exposes nothing sensitive.
            os.chmod(tmp_path, 0o755)
            os.chmod(code_file, 0o644)

        if rt.mode == "docker" and "," in str(tmp_path):
            return AdapterResult("error", error="TEMP path contains a comma, which Docker --mount cannot accept.")

        name = "retrace-myth-" + uuid.uuid4().hex[:12]
        args = build_args(rt, settings, code_file, name)
        res = run_command(args, timeout_s=settings.mythril_timeout_s + _GRACE_S)

        if res.not_found:
            runtime.reset_cache()
            return AdapterResult("not_installed", error=f"Could not start Mythril ({rt.detail}).")
        if res.timed_out:
            if rt.mode == "docker":
                _kill_container(settings, name)
            return AdapterResult(
                "timeout",
                error=f"Mythril exceeded {settings.mythril_timeout_s + _GRACE_S}s and was stopped.",
                duration_s=res.duration_s,
            )
        if not res.stdout.strip():
            message = scrub(tail(res.stderr), tmp_path)
            return AdapterResult(
                "error",
                error=message or f"Mythril exited with code {res.returncode} and no output.",
                duration_s=res.duration_s,
            )
        text, truncated = cap(res.stdout, settings.max_tool_output_chars)
        if truncated:
            # Truncated JSON cannot be parsed reliably; report it rather than guess.
            return AdapterResult(
                "error",
                error="Mythril output exceeded the size limit and was discarded.",
                duration_s=res.duration_s,
                truncated=True,
            )
        return AdapterResult("ok", output=text, duration_s=res.duration_s)
