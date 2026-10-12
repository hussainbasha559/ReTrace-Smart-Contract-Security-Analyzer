"""Diagnose the database connection.   python verify_db.py

Prints what is wrong in plain words (placeholder password, wrong driver, IPv6-only host,
missing tables ...) instead of a long SQLAlchemy traceback.
"""
from __future__ import annotations

import sys

from sqlalchemy import inspect, text

from app.config import get_settings
from app.db import is_transaction_pooler, make_engine, normalize_database_url

EXPECTED = {"users", "user_sessions", "projects", "uploaded_files", "scans",
            "vulnerabilities", "scan_reports", "usage_events", "ai_analysis", "audit_logs"}


def main() -> int:
    raw = get_settings().database_url
    if not raw:
        print("FAIL  DATABASE_URL is not set. Copy backend/.env.example to backend/.env and fill it in.")
        return 1
    try:
        url = normalize_database_url(raw)
    except Exception as exc:
        print(f"FAIL  {exc}")
        return 1

    safe = url.render_as_string(hide_password=True)
    print(f"URL   {safe}")
    host = url.host or ""
    if host.startswith("db.") and host.endswith(".supabase.co"):
        print("NOTE  Direct connection hosts (db.<ref>.supabase.co) are IPv6-only. If this fails with "
              "'could not translate host name' or 'Network is unreachable', use the Session pooler "
              "string (…pooler.supabase.com:5432) from Dashboard -> Connect.")
    if is_transaction_pooler(url):
        print("NOTE  Port 6543 = transaction pooler: fine for the API; use port 5432 for `alembic upgrade`.")
    if "@" in (url.password or ""):
        print("WARN  Password contains '@' - it must be URL-encoded as %40.")

    try:
        engine = make_engine(raw)
        with engine.connect() as conn:
            print("OK    connected:", conn.execute(text("select version()")).scalar().split(",")[0])
            tables = set(inspect(conn).get_table_names())
    except ModuleNotFoundError as exc:
        print(f"FAIL  Missing Python driver ({exc}). Run: pip install -r requirements.txt")
        return 1
    except Exception as exc:
        msg = str(exc).splitlines()[0] if str(exc) else repr(exc)
        print(f"FAIL  {type(exc).__name__}: {msg}")
        if "password authentication failed" in msg:
            print("HINT  Wrong password, or wrong username. Pooler usernames look like postgres.<project-ref>.")
        elif "Tenant or user not found" in msg:
            print("HINT  Wrong region host or project ref in the pooler URL - copy it again from Dashboard -> Connect.")
        elif "translate host name" in msg or "unreachable" in msg:
            print("HINT  Use the Session pooler connection string (IPv4 compatible).")
        return 1

    missing = EXPECTED - tables
    if missing:
        print("FAIL  Missing tables:", ", ".join(sorted(missing)))
        print("HINT  Run `alembic upgrade head` or paste sql/schema.postgres.sql into the Supabase SQL editor.")
        return 1
    print("OK    all", len(EXPECTED), "tables present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
