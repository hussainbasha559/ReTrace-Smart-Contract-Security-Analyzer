"""Execution-mode tests: native / WSL (Heimdall) and native / Docker (Mythril).

Most tests drive the real subprocess path using small fake `wsl`, `docker` and `heimdall`
executables placed on PATH, so argument building, path handling and cleanup are exercised
without needing the real tools. They are shell scripts, so they are skipped on Windows.

What this does NOT prove: that the real Heimdall / Mythril image accept these flags. That is
checked by running the app against the real tools (see README, "Verify the integration").
"""
import json
import stat
import sys
from pathlib import Path

import pytest

from app.adapters import heimdall_adapter, mythril_adapter, runtime
from app.config import Settings

CODE = "6001600055"
needs_posix = pytest.mark.skipif(sys.platform == "win32", reason="fake tools are bash scripts")


@pytest.fixture(autouse=True)
def _fresh_cache():
    runtime.reset_cache()
    yield
    runtime.reset_cache()


# ------------------------------------------------------------------ path translation

@pytest.mark.parametrize(
    "win,expected",
    [
        ("C:\\Users\\me\\AppData\\Local\\Temp\\x", "/mnt/c/Users/me/AppData/Local/Temp/x"),
        ("d:/data/out", "/mnt/d/data/out"),
        ("C:\\", "/mnt/c"),
        ("/already/posix", "/already/posix"),
    ],
)
def test_windows_to_wsl_path(win, expected):
    assert runtime.windows_to_wsl_path(win) == expected


def test_windows_to_wsl_path_custom_mount_root():
    assert runtime.windows_to_wsl_path("C:\\a", "/windir") == "/windir/c/a"


@pytest.mark.parametrize("bad", ["\\\\server\\share\\x", "relative\\path"])
def test_windows_to_wsl_path_rejects_unsupported(bad):
    with pytest.raises(ValueError):
        runtime.windows_to_wsl_path(bad)


# ------------------------------------------------------------------ config

def test_invalid_mode_env_falls_back_to_auto(monkeypatch):
    from app import config

    monkeypatch.setenv("RETRACE_HEIMDALL_MODE", "rm -rf /")
    monkeypatch.setenv("RETRACE_MYTHRIL_MODE", "bogus")
    config.get_settings.cache_clear()
    try:
        s = config.get_settings()
        assert (s.heimdall_mode, s.mythril_mode) == ("auto", "auto")
    finally:
        config.get_settings.cache_clear()


# ------------------------------------------------------------------ resolution without tools

def test_nothing_installed_reports_not_installed(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))          # empty dir: no tools at all
    s = Settings()
    assert not heimdall_adapter.is_available(s)
    assert not mythril_adapter.is_available(s)
    assert heimdall_adapter.run_heimdall(CODE, s).status == "not_installed"
    assert mythril_adapter.run_mythril(CODE, s).status == "not_installed"
    assert "Docker" in mythril_adapter.describe(s)


def test_forced_native_does_not_fall_back(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))
    s = Settings(heimdall_mode="native", mythril_mode="native")
    assert heimdall_adapter.describe(s).startswith("'heimdall' was not found")
    assert mythril_adapter.describe(s).startswith("'myth' was not found")


# ------------------------------------------------------------------ fake executables

def _script(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/env bash\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


@pytest.fixture
def fakes(tmp_path, monkeypatch):
    """A PATH holding fake `wsl`, `docker` and (inside "WSL" only) `heimdall`."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    wsl_only = tmp_path / "wslbin"      # heimdall lives here: visible to fake WSL, not to Windows
    wsl_only.mkdir()
    log = tmp_path / "calls.log"
    log.write_text("")

    # wsl [-d NAME] --exec CMD ARGS...   ->  run CMD with the WSL-only dir on PATH.
    _script(bin_dir / "wsl", f"""
echo "wsl $*" >> {log}
if [ "$1" = "-d" ]; then shift 2; fi
[ "$1" = "--exec" ] && shift
PATH="{wsl_only}:$PATH" exec "$@"
""")

    _script(wsl_only / "heimdall", f"""
echo "heimdall $*" >> {log}
out=""
while [ $# -gt 0 ]; do [ "$1" = "--output" ] && out="$2"; shift; done
mkdir -p "$out/sub"
echo "contract Decompiled {{ function withdraw() {{}} }}" > "$out/sub/decompiled.sol"
""")

    # docker image inspect IMG | docker run ... | docker rm -f NAME
    _script(bin_dir / "docker", f"""
echo "docker $*" >> {log}
case "$1" in
  image) [ -n "$FAKE_NO_IMAGE" ] && {{ echo "Error: No such image: x" >&2; exit 1; }}; exit 0 ;;
  rm) exit 0 ;;
  run)
    [ -n "$FAKE_SLEEP" ] && sleep "$FAKE_SLEEP"
    src=""
    while [ $# -gt 0 ]; do
      if [ "$1" = "--mount" ]; then src="$(echo "$2" | sed -E 's/.*source=([^,]*),.*/\\1/')"; fi
      shift
    done
    cat "$src/runtime.hex" > /dev/null || exit 2
    echo '{{"success": true, "error": null, "issues": []}}'
    exit 0 ;;
esac
""")

    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")   # no native heimdall / myth
    return log


def lines(log: Path) -> list[str]:
    return [ln for ln in log.read_text().splitlines() if ln]


@needs_posix
def test_heimdall_runs_through_wsl(fakes):
    s = Settings(wsl_distro="Ubuntu")
    assert heimdall_adapter.is_available(s)
    assert heimdall_adapter.describe(s) == "WSL (Ubuntu)"

    res = heimdall_adapter.run_heimdall(CODE, s)
    assert res.status == "ok", res.error
    assert "function withdraw" in res.output

    wsl_calls = [ln for ln in lines(fakes) if ln.startswith("wsl ")]
    assert all(ln.startswith("wsl -d Ubuntu --exec") for ln in wsl_calls)
    heimdall_call = next(ln for ln in lines(fakes) if ln.startswith("heimdall "))
    assert "decompile" in heimdall_call and "--include-sol" in heimdall_call
    assert "--skip-resolving" in heimdall_call


@needs_posix
def test_heimdall_auto_prefers_native_when_present(fakes, tmp_path, monkeypatch):
    native = tmp_path / "native"
    native.mkdir()
    _script(native / "heimdall", 'out=""; while [ $# -gt 0 ]; do [ "$1" = "--output" ] && out="$2"; shift; done; echo native > "$out/decompiled.sol"')
    monkeypatch.setenv("PATH", f"{native}:{tmp_path / 'bin'}:/usr/bin:/bin")
    runtime.reset_cache()
    s = Settings()
    assert heimdall_adapter.describe(s) == "native"
    assert heimdall_adapter.run_heimdall(CODE, s).output.strip() == "native"
    assert not any(ln.startswith("wsl ") for ln in lines(fakes))


@needs_posix
def test_heimdall_wsl_bin_override_must_exist(fakes):
    s = Settings(heimdall_mode="wsl", heimdall_bin="/no/such/heimdall")
    assert not heimdall_adapter.is_available(s)
    assert "not found in WSL" in heimdall_adapter.describe(s)


@needs_posix
def test_mythril_runs_in_docker_with_isolation_flags(fakes):
    s = Settings()
    assert mythril_adapter.is_available(s)
    res = mythril_adapter.run_mythril(CODE, s)
    assert res.status == "ok", res.error
    assert json.loads(res.output)["success"] is True

    run = next(ln for ln in lines(fakes) if ln.startswith("docker run"))
    for flag in ("--rm", "--network none", "--cap-drop ALL", "--security-opt no-new-privileges",
                 "--memory 2g", "--pids-limit 256", ",readonly"):
        assert flag in run, flag
    # image comes after all docker options, then the myth sub-command and its flags
    tail = run.split("mythril/myth:latest", 1)[1]
    assert tail.split()[0] == "analyze"
    assert "/work/runtime.hex" in tail and "--bin-runtime" in tail and "-o json" in tail
    # no shell involved, so nothing from the bytecode can reach a command line
    assert CODE not in run


@needs_posix
def test_mythril_missing_image_gives_actionable_message(fakes, monkeypatch):
    monkeypatch.setenv("FAKE_NO_IMAGE", "1")
    s = Settings()
    assert not mythril_adapter.is_available(s)
    res = mythril_adapter.run_mythril(CODE, s)
    assert res.status == "not_installed"
    assert "docker pull mythril/myth:latest" in res.error


@needs_posix
def test_mythril_docker_timeout_removes_the_container(fakes, monkeypatch):
    monkeypatch.setenv("FAKE_SLEEP", "5")
    monkeypatch.setattr(mythril_adapter, "_GRACE_S", 0)
    s = Settings(mythril_timeout_s=1)
    res = mythril_adapter.run_mythril(CODE, s)
    assert res.status == "timeout"
    ls = lines(fakes)
    name = next(ln for ln in ls if ln.startswith("docker run")).split("--name ")[1].split()[0]
    assert f"docker rm -f {name}" in ls


@needs_posix
def test_health_reports_how_tools_run(fakes):
    from fastapi.testclient import TestClient
    from app.main import app

    body = TestClient(app).get("/api/health").json()
    assert body["tools"] == {"heimdall": True, "mythril": True}
    assert body["details"]["heimdall"].startswith("WSL")
    assert body["details"]["mythril"].startswith("Docker")
    assert "/tmp" not in json.dumps(body)       # no server paths in the response
