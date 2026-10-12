"""lock down tables for Supabase (row level security)

Revision ID: 0002
Revises: 0001

Supabase exposes every table in the ``public`` schema through its REST API using the public
``anon`` key. This app never uses that API: only the FastAPI backend talks to the database,
through the ``postgres`` role, which bypasses RLS. Enabling RLS with no policies therefore
blocks all access from ``anon`` / ``authenticated`` and leaves the backend unaffected.
No-op on SQLite and non-Supabase servers.
"""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

TABLES = (
    "users", "user_sessions", "projects", "uploaded_files", "scans",
    "vulnerabilities", "scan_reports", "usage_events", "ai_analysis", "audit_logs",
    "alembic_version",
)


def _is_postgres() -> bool:
    return op.get_context().dialect.name == "postgresql"


def upgrade() -> None:
    if not _is_postgres():
        return
    for t in TABLES:
        op.execute(f'ALTER TABLE public."{t}" ENABLE ROW LEVEL SECURITY')
    # Belt and braces: also remove direct grants from the Supabase API roles (if they exist).
    op.execute("""
DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['anon','authenticated'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA public FROM %I', r);
      EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM %I', r);
    END IF;
  END LOOP;
END $$;
""")


def downgrade() -> None:
    if not _is_postgres():
        return
    for t in TABLES:
        op.execute(f'ALTER TABLE public."{t}" DISABLE ROW LEVEL SECURITY')
