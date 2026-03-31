"""
Postgres connection pool via asyncpg + PgBouncer.

Design:
- Single asyncpg pool per process, shared across all coroutines.
- PgBouncer is the actual Postgres connection manager (transaction mode).
  asyncpg connects to PgBouncer (port 5432), not Postgres directly.
- app.tenant_id and app.aes_key are SET at the start of every transaction.
  This is safe in PgBouncer transaction mode because the SET is within the
  transaction boundary.
- All queries use asyncpg's $1/$2 parameterized syntax. No f-strings in SQL.
"""
from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

import asyncpg
from asyncpg import Pool, Connection

logger = logging.getLogger(__name__)

_pool: Pool | None = None
_AES_KEY_ENV = "YASHIGANI_DB_AES_KEY"


async def create_pool() -> Pool:
    dsn = os.environ["YASHIGANI_DB_DSN"]
    global _pool
    _pool = await asyncpg.create_pool(
        dsn=dsn,
        min_size=2,
        max_size=10,
        max_inactive_connection_lifetime=300,
        command_timeout=10,
        init=_init_connection,
    )
    logger.info("Postgres pool created (PgBouncer DSN)")
    return _pool


async def _init_connection(conn: Connection) -> None:
    await conn.execute("SET application_name = 'yashigani-gateway'")


async def close_pool() -> None:
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


@asynccontextmanager
async def tenant_transaction(tenant_id: str) -> AsyncIterator[Connection]:
    """
    Acquire a connection, open a transaction, and SET the tenant context.
    RLS policies evaluate current_setting('app.tenant_id') on every row access.
    The AES key is also injected here so pgcrypto functions can reference it.
    """
    if _pool is None:
        raise RuntimeError("DB pool not initialized — call create_pool() at startup")
    aes_key = os.environ.get(_AES_KEY_ENV, "")
    async with _pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "SELECT set_config('app.tenant_id', $1, true),"
                "       set_config('app.aes_key', $2, true)",
                tenant_id,
                aes_key,
            )
            yield conn


def get_pool() -> Pool:
    if _pool is None:
        raise RuntimeError("DB pool not initialized — call create_pool() at startup")
    return _pool
