import os
from logging.config import fileConfig

from alembic import context

import app.models  # noqa: F401  (registers the tables)
from app.db import Base, make_engine, normalize_database_url

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)

url = os.environ.get("DATABASE_URL", "")
if not url:
    from app.config import get_settings  # loads backend/.env
    url = get_settings().database_url
if not url:
    raise SystemExit("DATABASE_URL is not set (see backend/.env.example).")


def run_migrations_online() -> None:
    # NullPool engine: migrations are short-lived and must not hold pooler connections open.
    engine = make_engine(url, for_migrations=True)
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=Base.metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


def run_migrations_offline() -> None:
    context.configure(
        url=normalize_database_url(url).render_as_string(hide_password=False),
        target_metadata=Base.metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


run_migrations_offline() if context.is_offline_mode() else run_migrations_online()
