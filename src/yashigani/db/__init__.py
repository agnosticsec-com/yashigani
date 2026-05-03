# Last updated: 2026-05-02T00:00:00+01:00 (RETRO-R4-2: expose connect_with_retry_sync)
from yashigani.db.postgres import create_pool, close_pool, tenant_transaction, get_pool, connect_with_retry_sync

__all__ = ["create_pool", "close_pool", "tenant_transaction", "get_pool", "run_migrations", "connect_with_retry_sync"]


# Stable 64-bit advisory-lock key for Yashigani schema/bootstrap operations.
# Generated from `python -c "import zlib; print(hex(zlib.crc32(b'yashigani.bootstrap')))"`
# and biased into the int64 range. Any value works as long as it's stable across
# all replicas. Documented so future migration code uses the same key for
# bootstrap-class operations rather than inventing new ones.
_BOOTSTRAP_ADVISORY_LOCK_KEY = 0x7959470062535F31


def run_migrations() -> None:
    """Run Alembic migrations to head (sync, safe to call from startup).

    Multi-replica safety: when multiple backoffice/gateway replicas come up
    concurrently in K8s, only ONE replica should run the migrations to avoid
    alembic_version row contention and partial-DDL races. We acquire a
    PostgreSQL session-scoped advisory lock BEFORE alembic upgrades, hold it
    for the whole upgrade, then release. Other replicas block on the same key
    until the holder releases, then run alembic which detects "already at
    head" and is a no-op. Captain #58c #3bv evidence (2026-04-29) — found
    by static audit between Round 7 and Round 8.
    """
    import logging
    import os
    from alembic.config import Config
    from alembic import command
    from urllib.parse import urlparse, unquote

    logger = logging.getLogger(__name__)
    migrations_dir = os.path.join(os.path.dirname(__file__), "migrations")
    alembic_cfg = Config()
    alembic_cfg.set_main_option("script_location", migrations_dir)
    dsn = os.environ.get("YASHIGANI_DB_DSN", "")
    sync_dsn = dsn.replace("postgresql://", "postgresql+psycopg2://").replace(
        "postgresql+asyncpg://", "postgresql+psycopg2://"
    )
    # v2.23.1 fix: alembic.Config backs onto ConfigParser, which treats '%' as
    # an interpolation sigil. URL-encoded passwords (e.g. ',' -> '%2C',
    # '!' -> '%21') therefore raise "invalid interpolation syntax" on
    # set_main_option. Double '%' to escape, then libpq / SQLAlchemy decode it
    # back to the encoded form, and psycopg2 URL-unquotes it to the real
    # password before sending to pgbouncer.
    sync_dsn_alembic = sync_dsn.replace("%", "%%")
    alembic_cfg.set_main_option("sqlalchemy.url", sync_dsn_alembic)

    # Multi-replica advisory lock: hold this for the duration of the upgrade.
    # Use a dedicated psycopg2 connection (not the alembic-internal one) so the
    # lock outlives any of alembic's per-revision transactions.
    #
    # CRITICAL (Captain #58c #3bw, 2026-04-29): the lock connection MUST go
    # direct to postgres, NOT through pgbouncer. pgbouncer in transaction-pool
    # mode routes each new connection to a different postgres backend, and
    # postgres advisory locks are session-scoped (per-backend). If both
    # replicas connect through pgbouncer they land on different backends and
    # both successfully "acquire" the same lock key independently — no
    # serialisation. We use YASHIGANI_DB_DSN_DIRECT (set in K8s helm chart
    # pointing at yashigani-postgres:5432, bypassing yashigani-pgbouncer:5432)
    # for the lock connection when it's set; compose runs single-replica so
    # falls back to YASHIGANI_DB_DSN where contention doesn't matter.
    lock_dsn = os.environ.get("YASHIGANI_DB_DSN_DIRECT") or dsn
    # RETRO-R4-2: use connect_with_retry_sync instead of bare psycopg2.connect()
    # so a postgres restart mid-startup fails fast (connect_timeout=15s) and
    # retries rather than hanging the process indefinitely.
    lock_conn = connect_with_retry_sync(lock_dsn, max_attempts=5, backoff_s=3.0)
    try:
        lock_conn.autocommit = True
        with lock_conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(%s)", (_BOOTSTRAP_ADVISORY_LOCK_KEY,))
        logger.info("Acquired migration advisory lock %s", hex(_BOOTSTRAP_ADVISORY_LOCK_KEY))
        try:
            command.upgrade(alembic_cfg, "head")
            logger.info("Database migrations applied successfully (replica-safe)")
        except Exception as exc:
            logger.warning("Database migration failed: %s", exc)
        finally:
            with lock_conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_unlock(%s)", (_BOOTSTRAP_ADVISORY_LOCK_KEY,))
            logger.info("Released migration advisory lock")
    finally:
        lock_conn.close()
