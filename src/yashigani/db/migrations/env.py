"""Alembic environment — uses YASHIGANI_DB_DSN for sync migrations."""
from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = None


def get_url() -> str:
    dsn = os.environ.get("YASHIGANI_DB_DSN", config.get_main_option("sqlalchemy.url", ""))
    # asyncpg DSN → sync psycopg2 DSN for Alembic
    return dsn.replace("postgresql://", "postgresql+psycopg2://").replace(
        "postgresql+asyncpg://", "postgresql+psycopg2://"
    )


def run_migrations_offline() -> None:
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = create_engine(get_url(), poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
