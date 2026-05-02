"""
Yashigani CHS — Credential Handle Service.
Issues opaque handles for raw credentials. Raw values never leave CHS.
All inter-process communication via Unix domain socket only.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from yashigani.chs.resource_monitor import ResourceMonitor, TTL_FLOOR_SECONDS

logger = logging.getLogger(__name__)


@dataclass
class Handle:
    handle_id: str              # UUID v4 — opaque to consumers
    secret_key: str             # KSM key this handle maps to
    issued_at: float            # unix timestamp
    expires_at: float           # unix timestamp
    resolved_count: int = 0     # number of times this handle has been resolved
    revoked: bool = False


class CredentialHandleService:
    """
    In-memory, thread-safe registry of opaque credential handles.
    Raw credential values are fetched from KSM at resolution time only.
    Handles are short-lived (TTL set by ResourceMonitor).

    Security invariants:
    - Raw credential values are NEVER stored in this registry.
    - Handles are UUID v4 strings with no semantic meaning.
    - The registry is never persisted to disk.
    - Resolution is logged (not the value) via the audit callback.
    """

    def __init__(
        self,
        kms_provider,                   # KSMProvider instance
        resource_monitor: ResourceMonitor,
        on_audit: Optional[Callable[..., Any]] = None,
        max_ttl_seconds: int = 14400,   # 4-hour admin-configured ceiling
    ) -> None:
        self._kms = kms_provider
        self._monitor = resource_monitor
        self._on_audit = on_audit or (lambda event, data: None)
        self._max_ttl = max_ttl_seconds
        self._registry: dict[str, Handle] = {}
        self._lock = threading.RLock()
        # Start background expiry reaper
        self._reaper = threading.Thread(
            target=self._reap_expired, daemon=True, name="chs-reaper"
        )
        self._reaper.start()

    # -- Public API ----------------------------------------------------------

    def issue(self, secret_key: str) -> str:
        """
        Issue an opaque handle for the given KSM secret key.
        Returns the handle_id string. Raises ProviderError if KSM is
        unreachable (fail closed).
        """
        # Validate key exists in KSM before issuing (fail fast)
        self._kms.get_secret(secret_key)  # raises if not found

        ttl = min(self._monitor.current_ttl_seconds, self._max_ttl)
        now = time.monotonic()
        handle = Handle(
            handle_id=secrets.token_hex(16),   # 32 hex chars, opaque
            secret_key=secret_key,
            issued_at=now,
            expires_at=now + ttl,
        )

        with self._lock:
            self._registry[handle.handle_id] = handle

        logger.debug("Handle issued (ttl=%ds, key_hash=%s)", ttl, _key_hash(secret_key))
        self._on_audit("HANDLE_ISSUED", {
            "handle_id": handle.handle_id,
            "key_hash": _key_hash(secret_key),
            "ttl_seconds": ttl,
        })
        return handle.handle_id

    def resolve(self, handle_id: str, requester_id: str) -> str:
        """
        Resolve a handle to its raw secret value.
        Only called at the final consumption point (e.g. outbound HTTP client).
        Resolution is audit-logged. The raw value is never logged.
        Raises ValueError if handle is unknown, expired, or revoked.
        """
        with self._lock:
            handle = self._registry.get(handle_id)
            if handle is None:
                raise ValueError(f"Unknown handle: {handle_id}")
            if handle.revoked:
                raise ValueError(f"Handle has been revoked: {handle_id}")
            if time.monotonic() > handle.expires_at:
                del self._registry[handle_id]
                raise ValueError(f"Handle has expired: {handle_id}")
            handle.resolved_count += 1

        self._on_audit("HANDLE_RESOLVED", {
            "handle_id": handle_id,
            "requester_id": requester_id,
            "resolved_count": handle.resolved_count,
        })

        return self._kms.get_secret(handle.secret_key)

    def revoke(self, handle_id: str) -> None:
        """Immediately revoke a handle. Future resolve() calls will fail."""
        with self._lock:
            handle = self._registry.get(handle_id)
            if handle:
                handle.revoked = True
        self._on_audit("HANDLE_REVOKED", {"handle_id": handle_id})

    def active_count(self) -> int:
        with self._lock:
            now = time.monotonic()
            return sum(
                1 for h in self._registry.values()
                if not h.revoked and h.expires_at > now
            )

    def current_ttl_seconds(self) -> int:
        return min(self._monitor.current_ttl_seconds, self._max_ttl)

    # -- Internal ------------------------------------------------------------

    def _reap_expired(self) -> None:
        """Background thread — removes expired handles every 60 seconds."""
        while True:
            time.sleep(60)
            now = time.monotonic()
            with self._lock:
                expired = [
                    hid for hid, h in self._registry.items()
                    if h.expires_at <= now or h.revoked
                ]
                for hid in expired:
                    del self._registry[hid]
            if expired:
                logger.debug("CHS reaper removed %d expired/revoked handles", len(expired))


def _key_hash(key: str) -> str:
    """Return a short hash of the key name for safe logging (not the value)."""
    return hashlib.sha256(key.encode()).hexdigest()[:12]
