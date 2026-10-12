"""Database engine and session handling (SQLAlchemy 2.x).

Targets PostgreSQL (Supabase). SQLite is still supported for the test-suite.

Supabase notes handled here:
  * ``postgres://`` / ``postgresql://`` URLs are rewritten to ``postgresql+psycopg://`` (psycopg 3).
  * ``sslmode=require`` is added for Supabase hosts (they refuse plain connections).
  * Port 6543 is Supavisor *transaction* mode, which does not support server-side prepared
    statements, so they are switched off for that port.
  * The pool is small (Supabase free tier allows only a handful of connections) but never 1:
    a request thread and a background scan thread each need their own connection.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine, URL, make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    """Naive UTC timestamp. All DATETIME columns store UTC."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


_PG_ALIASES = {"postgres", "postgresql", "postgresql+psycopg2", "postgres+psycopg2", "postgresql+psycopg"}


def normalize_database_url(raw: str) -> URL:
    """Turn whatever the user pasted from the Supabase dashboard into a working SQLAlchemy URL."""
    raw = (raw or "").strip().strip('"').strip("'")
    if raw.startswith("[") or "YOUR-PASSWORD" in raw or "[YOUR" in raw:
        raise RuntimeError(
            "DATABASE_URL still contains the dashboard placeholder [YOUR-PASSWORD]. "
            "Replace it with your real database password (URL-encoded)."
        )
    url = make_url(raw)
    if url.drivername in _PG_ALIASES:
        url = url.set(drivername="postgresql+psycopg")
        host = url.host or ""
        if "supabase" in host and "sslmode" not in url.query:
            url = url.update_query_dict({"sslmode": "require"})
    return url


def is_transaction_pooler(url: URL) -> bool:
    """Supavisor transaction mode listens on 6543 (pgbouncer-style)."""
    return bool(url.drivername.startswith("postgresql") and url.port == 6543)


def make_engine(url_str: str, *, for_migrations: bool = False) -> Engine:
    url = normalize_database_url(url_str)
    s = get_settings()
    kwargs: dict = {"pool_pre_ping": True, "future": True}

    if url.get_backend_name() == "sqlite":
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        connect_args: dict = {"connect_timeout": 10}
        if url.drivername == "postgresql+psycopg":
            connect_args.update({"keepalives": 1, "keepalives_idle": 30, "keepalives_interval": 10, "keepalives_count": 5})
            if is_transaction_pooler(url):
                connect_args["prepare_threshold"] = None   # no prepared statements via the pooler
        kwargs["connect_args"] = connect_args
        if for_migrations:
            from sqlalchemy.pool import NullPool
            kwargs["poolclass"] = NullPool
        else:
            kwargs.update({
                "pool_size": s.db_pool_size,
                "max_overflow": s.db_max_overflow,
                "pool_timeout": 30,
                "pool_recycle": 900,   # recycle before the pooler/proxy drops idle connections
            })

    engine = create_engine(url, **kwargs)

    if url.get_backend_name() == "sqlite":
        @event.listens_for(engine, "connect")
        def _fk_on(dbapi_conn, _):
            dbapi_conn.execute("PRAGMA foreign_keys=ON")

    return engine


_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    global _engine, _SessionLocal

    if _engine is None:
        url = get_settings().database_url
        if not url:
            raise RuntimeError("DATABASE_URL is not set. Configure it in the environment.")
        _engine = make_engine(url)
        _SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)

    return _engine


def session_factory() -> sessionmaker[Session]:
    get_engine()
    assert _SessionLocal is not None
    return _SessionLocal


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one session per request, always closed."""
    db = session_factory()()
    try:
        yield db
    finally:
        db.close()


def reset_engine() -> None:
    """Used by tests to point the app at a fresh database."""
    global _engine, _SessionLocal

    if _engine is not None:
        _engine.dispose()

    _engine = None
    _SessionLocal = None
