from yashigani.db.postgres import create_pool, close_pool, tenant_transaction, get_pool

__all__ = ["create_pool", "close_pool", "tenant_transaction", "get_pool", "run_migrations"]


def run_migrations() -> None:
    """Run Alembic migrations to head (sync, safe to call from startup)."""
    import logging
    import os
    from alembic.config import Config
    from alembic import command

    logger = logging.getLogger(__name__)
    migrations_dir = os.path.join(os.path.dirname(__file__), "migrations")
    alembic_cfg = Config()
    alembic_cfg.set_main_option("script_location", migrations_dir)
    dsn = os.environ.get("YASHIGANI_DB_DSN", "")
    sync_dsn = dsn.replace("postgresql://", "postgresql+psycopg2://").replace(
        "postgresql+asyncpg://", "postgresql+psycopg2://"
    )
    alembic_cfg.set_main_option("sqlalchemy.url", sync_dsn)
    try:
        command.upgrade(alembic_cfg, "head")
        logger.info("Database migrations applied successfully")
    except Exception as exc:
        logger.warning("Database migration failed: %s", exc)
