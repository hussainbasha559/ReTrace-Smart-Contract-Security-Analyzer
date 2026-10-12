# ReTrace

> **v0.2: multi-user platform.** Accounts, PostgreSQL (Supabase) persistence, file management, scan history, usage analytics and
> AI-assisted explanations now wrap the original analyzer. See **Platform** below; Supabase setup is in
> [`docs/supabase-setup.md`](docs/supabase-setup.md).

Evidence-driven EVM decompilation and re-entrancy analysis. Paste runtime bytecode; get an opcode listing,
a decompiled approximation (Heimdall-rs), Mythril's security findings, and a structural re-entrancy check —
each warning linked to the instructions behind it.

ReTrace integrates established tools. It is not a new decompiler or symbolic executor; its contribution is the
workflow, evidence-linked presentation, and honest handling of uncertainty (tool failure ≠ "no issues").

## Run it

**Backend** (Python 3.10+; works on Windows, inside WSL2, or on Linux. See "Heimdall and Mythril" below)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate      # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m pytest                                        # 116 tests, no external tools needed
uvicorn app.main:app --reload                           # http://127.0.0.1:8000/docs
```

**Frontend** (Node 18+)

```bash
cd frontend
npm install
npm run dev                                             # http://localhost:5173 (proxies /api to :8000)
```

## Heimdall and Mythril

ReTrace launches each tool in whichever way is available. The default `auto` mode prefers a native install
on `PATH`, then falls back to WSL (Heimdall) or Docker (Mythril), so the same code runs on Windows, in WSL2,
or on Linux.

| Tool | `native` | fallback | How the fallback runs |
|---|---|---|---|
| Heimdall-rs | `heimdall` on PATH | `wsl` (Windows backend, Heimdall installed in Ubuntu) | `wsl -d <distro> --exec <heimdall> decompile ...`; temp files stay on the Windows drive and are passed as `/mnt/c/...` |
| Mythril | `myth` on PATH | `docker` (`mythril/myth:latest`) | `docker run --rm --network none --cap-drop ALL --memory 2g --cpus 2 --pids-limit 256`, bytecode mounted read-only; the container is force-removed on timeout |

**Windows backend + Ubuntu/WSL Heimdall + Docker Mythril** (the setup this project was built for):

```powershell
docker pull mythril/myth:latest           # once; the adapter does not pull for you
cd backend
.\start-backend.ps1                       # or -Distro Ubuntu-22.04; sets the env vars below, then runs uvicorn
```

**Backend inside WSL** needs nothing special: Heimdall is on PATH and Docker Desktop's WSL integration provides `docker`.

### Verify the integration (run this first)

```bash
cd backend
python verify_tools.py --no-mythril     # Heimdall only, a few seconds
python verify_tools.py                  # full run on the vulnerable sample, ~30-90 s
```

It prints how each tool will run, each tool's status, the verdict, and the findings. `GET /api/health` returns the
same availability (`tools`) plus how each runs or why it is unavailable (`details`); the dashboard sidebar shows both.

### Configuration (environment variables, all optional)

| Variable | Default | Meaning |
|---|---|---|
| `RETRACE_HEIMDALL_MODE` | `auto` | `auto`, `native` or `wsl` |
| `RETRACE_MYTHRIL_MODE` | `auto` | `auto`, `native` or `docker` |
| `RETRACE_WSL_DISTRO` | *(default distro)* | WSL distribution name, e.g. `Ubuntu` |
| `RETRACE_HEIMDALL_BIN` | `heimdall` | In WSL mode, set a full in-WSL path if auto-detection fails (e.g. `/home/you/.bifrost/bin/heimdall`) |
| `RETRACE_HEIMDALL_ARGS` | *(none)* | Extra Heimdall flags |
| `RETRACE_WSL_MOUNT_ROOT` | `/mnt` | Where WSL mounts Windows drives, if you changed `automount.root` |
| `RETRACE_MYTHRIL_IMAGE` | `mythril/myth:latest` | Docker image |
| `RETRACE_DOCKER_MEMORY` / `_CPUS` / `_PIDS_LIMIT` | `2g` / `2` / `256` | Container limits |
| `RETRACE_MYTHRIL_TIMEOUT_S` | `90` | Symbolic-execution budget; a further 30 s grace covers start-up |
| `RETRACE_MYTHRIL_TX_COUNT` | `2` | Transaction depth |

### Troubleshooting

- **Heimdall "not found in WSL"**: `wsl heimdall --version` can fail even when Heimdall works in your Ubuntu shell, because
  `~/.bifrost/bin` is added to PATH by your interactive shell profile. The adapter also checks `~/.bifrost/bin`,
  `~/.cargo/bin` and `/usr/local/bin`; otherwise set `RETRACE_HEIMDALL_BIN` to the full path (`which heimdall` in Ubuntu).
- **Mythril "image is not downloaded"**: run `docker pull mythril/myth:latest`.
- **"Docker daemon is not reachable"**: start Docker Desktop.
- **Heimdall flag errors**: flags vary by version. The adapter calls
  `heimdall decompile <file> --include-sol --skip-resolving --output <dir>`. Check `wsl heimdall decompile --help`
  and adjust `adapters/heimdall_adapter.py` or set `RETRACE_HEIMDALL_ARGS`.
- **Mythril on a native Python 3.12 install** may fail with `No module named 'pkg_resources'`: `pip install "setuptools<81"`.
  Using the Docker image avoids this.

Without the tools the app still works: you get the opcode listing and the structural heuristic, and the verdict
is **Analysis incomplete**, never "clean".

## Themes

The dashboard has a light and a dark theme. Use the sun/moon switch in the top bar; the choice is remembered in the
browser (light is the default). All colours are tokens in `frontend/src/styles.css`: edit the `:root` block for light
and `:root[data-theme="dark"]` for dark.

## Status: what is and isn't verified

| Verified (automated) | Not yet verified |
|---|---|
| Input validation, opcode decoding (incl. PUSH data, truncation) | Docker image build |
| CFG heuristic on hand-built cases and on real solc output (vulnerable flagged, corrected not) | Visual review in a browser |
| API behavior with mocked tools: failure → incomplete, corroboration, disagreement warnings | Mythril false-positive/timing evaluation beyond the two samples |
| Live runs with real Heimdall 0.9.3 + Mythril v0.24.8 on both samples (`docs/evaluation.md`); frontend production build | |
| WSL and Docker launch paths: argument building, Windows→`/mnt/c` path translation, isolation flags, timeout cleanup, health `details` (tested with fake `wsl`/`docker`/`heimdall` executables) | The same paths against your real Ubuntu/WSL and Docker Desktop. Run `python verify_tools.py` to confirm |
| Light and dark theme rendering and switch persistence (headless browser, desktop and phone width) | Real-browser review on your machine |

## Layout

See `docs/architecture.md`. Two small additions to the planned tree: `adapters/base.py` (shared safe
subprocess runner) and `samples/README.md`.

## Next steps

1. ~~Install Mythril + Heimdall, run both samples~~ done; see `docs/evaluation.md`. Decide whether call-only Mythril findings should count toward the verdict.
2. Fix-and-retest view (compare two runs side by side).
3. Control-flow graph view (block structure already exists in `reentrancy_service.build_blocks`).


## Platform (v0.2)

**Quick start**

```bash
# 1. Supabase connection string in backend/.env  -> docs/supabase-setup.md
cd backend && pip install -r requirements.txt
alembic upgrade head
python -m app.cli create-admin --email you@example.com --name "You"   # optional administrator
uvicorn app.main:app --reload
# 2. frontend
cd ../frontend && npm install && npm run dev     # http://localhost:5173 -> register -> Analyze
```

| Area | What it does |
|---|---|
| Auth | Register/login/logout, Argon2id hashes, server-side sessions in an HttpOnly SameSite cookie (12 h absolute, 2 h idle), CSRF token header, Origin check, rate limits, generic login errors, password change signs out other devices, profile, delete data/account |
| Files | Upload hex or raw-binary bytecode (content-validated), paste, rename, download, delete, projects, SHA-256, server-generated storage keys outside the web root, ownership checks on every call |
| Scans | `QUEUED -> RUNNING -> COMPLETED / FAILED / CANCELLED` in a background worker; COMPLETED only after results are saved; retry on internal errors; interrupted scans marked FAILED at startup; filters, pagination, re-run, cancel, compare, JSON/Markdown export, integrity-checked reports |
| Usage | Per-user dashboard; admin dashboard with aggregates only (admins cannot read others' files or scans) |
| AI | Provider abstraction (any OpenAI-compatible API). Deterministic risk model; explanation, remediation, reports and chat grounded in stored findings; works without an LLM in rule-based mode (labelled); chat needs an LLM |

**Finding labels.** `corroborated` = Mythril and the structural check agree on the same instruction; `symbolically_feasible` = reported by
Mythril's symbolic execution; `heuristic` = structural pattern only. Scan verdict `analysis_incomplete` is the "inconclusive" state.
Nothing is labelled "confirmed exploitable"; the tool does not generate exploits.

**Tests**: `cd backend && python -m pytest` (116 tests, SQLite, no external tools). Against Postgres/Supabase:
`RETRACE_TEST_DATABASE_URL=postgresql://...@localhost/retrace_test python -m pytest` (use a throwaway database, NEVER your real Supabase project: tests drop and recreate tables).

**Known limits**
- Email verification and password reset by email are not implemented (they need an SMTP service).
- Rate limiting and the job queue are in-process: fine for one uvicorn worker. Use Redis/Celery or a reverse proxy for several.
- Cancelling a *running* scan marks it CANCELLED and discards its result, but the external tool runs to its own timeout.
- Set `RETRACE_COOKIE_SECURE=true`, serve over HTTPS, and put a reverse proxy with a hard body-size limit in front for real use.
- Risk-score weights are judgement calls, not validated against incident data; the UI says so. Business impact is "not assessed".
- AI features were tested against a mocked provider; no live LLM call was made in development.
- Chat history is not stored (only metadata and token counts).
- Retention: `python -m app.cli purge` removes expired sessions and audit rows older than `RETRACE_AUDIT_RETENTION_DAYS` (365); users can delete their data from Profile.
