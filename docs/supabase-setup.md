# Supabase (PostgreSQL) setup

ReTrace's backend (FastAPI + SQLAlchemy) connects to Supabase's Postgres database directly.
It does **not** use the Supabase REST API, Auth or the anon key.

## 1. Get the connection string

Supabase Dashboard → your project → **Connect** → **Session pooler**.

| Mode | Host | Port | Use for |
|---|---|---|---|
| **Session pooler** (recommended) | `aws-0-<region>.pooler.supabase.com` | 5432 | Render, Railway, Docker, home PCs, migrations |
| Transaction pooler | same host | 6543 | many short-lived / serverless instances (API only) |
| Direct connection | `db.<ref>.supabase.co` | 5432 | only if your host has IPv6 |

The username for pooler URLs is `postgres.<project-ref>`, not `postgres`.

## 2. Configure `backend/.env`

```
DATABASE_URL=postgresql://postgres.<ref>:<URL_ENCODED_PASSWORD>@aws-0-<region>.pooler.supabase.com:5432/postgres
RETRACE_SECRET_KEY=<python -c "import secrets; print(secrets.token_hex(32))">
```

`postgres://…` and `postgresql://…` are fine; the app switches to the psycopg 3 driver and adds
`sslmode=require` itself. Special characters in the password must be URL-encoded
(`@`→`%40`, `#`→`%23`, `/`→`%2F`, `:`→`%3A`, `?`→`%3F`, `%`→`%25`).

## 3. Create the tables (pick ONE)

**A. Alembic**
```
cd backend
pip install -r requirements.txt
alembic upgrade head
```
**B. SQL editor** – paste `backend/sql/schema.postgres.sql` into Supabase → SQL Editor → Run.
(It records Alembic revision `0002`, so running Alembic afterwards does nothing.)

Both create the 10 tables **and enable Row Level Security** with no policies, so the public
Supabase API (anon key) cannot read your users/sessions. The backend is unaffected because it
connects as the `postgres` role.

## 4. Check it

```
python verify_db.py          # explains what is wrong, in plain words
uvicorn app.main:app --port 8000
curl http://localhost:8000/health/db
python -m app.cli create-admin --email you@example.com --name "You"
```

## Common errors

| Error | Cause / fix |
|---|---|
| `No module named 'pymysql'` / `psycopg2` | old MySQL URL or driver; use the URL above and `pip install -r requirements.txt` |
| `Network is unreachable` / `could not translate host name "db.xxx.supabase.co"` | direct host is IPv6-only → use the **Session pooler** string |
| `password authentication failed` | wrong password, or username is `postgres` instead of `postgres.<ref>` |
| `Tenant or user not found` | wrong region/host in the pooler URL; copy it again from **Connect** |
| `DuplicatePreparedStatement` / `prepared statement "_pg3_0" already exists` | transaction pooler (6543) with an old build; fixed here (prepared statements are disabled on 6543) |
| `QueuePool limit … reached` | old pool size of 1; now `RETRACE_DB_POOL_SIZE=3` + overflow 4 |
| `relation "users" does not exist` | step 3 not done on *this* database |
| SQL editor fails on `ENGINE=InnoDB` / backticks | you ran the old `schema.mysql.sql`; use `schema.postgres.sql` |
| `still contains the dashboard placeholder` | `[YOUR-PASSWORD]` was left in `DATABASE_URL` |

## Deploying (Render etc.)

Set `DATABASE_URL`, `RETRACE_SECRET_KEY`, `RETRACE_COOKIE_SECURE=true` as environment variables.
**Uploads and reports are stored on local disk** (`RETRACE_STORAGE_DIR`); on hosts with an ephemeral
filesystem they disappear on every deploy, so attach a persistent disk (or move storage to
Supabase Storage).
