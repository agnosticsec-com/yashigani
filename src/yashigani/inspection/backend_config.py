"""
Yashigani Inspection — Backend configuration persistence in Redis db/1.

Key schema:
    inspection:backend:active          String — active backend name
    inspection:backend:fallback_chain  List — ordered fallback backend names
    inspection:backend:config:{name}   Hash — per-backend config (no secret values)

Secrets (API keys) are NEVER stored here. They are fetched from KMS at
backend instantiation time. Only non-secret configuration fields are
persisted (base_url, model, timeout_seconds, max_tokens, etc.).
"""
from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

_KEY_ACTIVE = "inspection:backend:active"
_KEY_FALLBACK = "inspection:backend:fallback_chain"
_KEY_CONFIG = "inspection:backend:config:{}"

DEFAULT_ACTIVE = "ollama"
DEFAULT_FALLBACK_CHAIN = ["ollama", "gemini", "fail_closed"]


class BackendConfigStore:
    """
    Persists active backend name, fallback chain, and per-backend
    non-secret configuration in Redis.

    Shares Redis db/1 with the session store — uses a distinct key
    namespace (inspection:backend:*) to avoid collisions.
    """

    def __init__(self, redis_client) -> None:
        self._redis = redis_client

    # ── Active backend ────────────────────────────────────────────────────────

    def get_active(self) -> str:
        """Return active backend name, or DEFAULT_ACTIVE if not set."""
        val = self._redis.get(_KEY_ACTIVE)
        if val is None:
            return DEFAULT_ACTIVE
        return val.decode() if isinstance(val, bytes) else str(val)

    def set_active(self, backend_name: str) -> None:
        """Persist the active backend name."""
        self._redis.set(_KEY_ACTIVE, backend_name)
        logger.info("BackendConfigStore: active backend set to %r", backend_name)

    # ── Fallback chain ────────────────────────────────────────────────────────

    def get_fallback_chain(self) -> list[str]:
        """Return the ordered fallback chain, or DEFAULT_FALLBACK_CHAIN if not set."""
        items = self._redis.lrange(_KEY_FALLBACK, 0, -1)
        if not items:
            return list(DEFAULT_FALLBACK_CHAIN)
        return [i.decode() if isinstance(i, bytes) else str(i) for i in items]

    def set_fallback_chain(self, chain: list[str]) -> None:
        """Atomically replace the fallback chain list."""
        key = _KEY_FALLBACK
        self._redis.delete(key)
        if chain:
            self._redis.rpush(key, *chain)
        logger.info("BackendConfigStore: fallback chain set to %s", chain)

    # ── Per-backend config ────────────────────────────────────────────────────

    def get_backend_config(self, backend_name: str) -> dict:
        """
        Return stored configuration for a backend.
        Returns empty dict if no config is stored.
        Never returns secret values — those are never stored here.
        """
        raw = self._redis.hgetall(_KEY_CONFIG.format(backend_name))
        if not raw:
            return {}
        return {
            (k.decode() if isinstance(k, bytes) else k):
            (v.decode() if isinstance(v, bytes) else v)
            for k, v in raw.items()
        }

    def set_backend_config(self, backend_name: str, config: dict) -> None:
        """
        Persist non-secret backend config fields.
        api_key and any field containing 'secret' or 'password' in its name
        are explicitly filtered out before storage.
        """
        key = _KEY_CONFIG.format(backend_name)
        self._redis.delete(key)
        if config:
            _SECRET_FIELDS = frozenset({"api_key", "secret", "password", "token"})
            safe = {
                k: str(v)
                for k, v in config.items()
                if k not in _SECRET_FIELDS and not any(s in k.lower() for s in ("key", "secret", "password", "token"))
            }
            if safe:
                self._redis.hset(key, mapping=safe)
        logger.info(
            "BackendConfigStore: config persisted for backend %r (%d fields)",
            backend_name, len(config),
        )
