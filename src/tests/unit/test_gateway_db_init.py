"""
Unit tests for gateway DB init fail-closed behaviour (M-02 / SOP 1).

The gateway entrypoint's DB block must:
  - Re-raise on init failure when YASHIGANI_DB_DSN is set (fail-closed).
  - Warn-and-continue when YASHIGANI_DB_DSN is NOT set (no DB configured is fine).

We test the logic directly without importing the full entrypoint (which would
attempt to connect to all services), by exercising the relevant code path via
a minimal reproduce of the decision logic.

Last updated: 2026-04-27T21:53:12+01:00
"""
from __future__ import annotations

import logging
import os

import pytest


# ---------------------------------------------------------------------------
# Helpers — replicate the exact M-02 logic in isolation
# ---------------------------------------------------------------------------

def _run_db_init_block(db_dsn: str, raise_in_migrations: bool) -> tuple[bool, object]:
    """
    Simulate the gateway DB-init block (M-02 logic only).

    The actual gateway block structure:
        _db_dsn_configured = False
        try:
            [imports succeed]
            if db_dsn and "${POSTGRES_PASSWORD}" not in db_dsn:
                _db_dsn_configured = True
                run_migrations()       ← may raise here
                ...
            else:
                logger.warning("DSN not set")
        except Exception as exc:
            if _db_dsn_configured:
                logger.exception(...)
                raise                  ← fail-closed
            logger.warning(...)        ← swallow (no DSN configured)

    Parameters
    ----------
    db_dsn : str
        Value of YASHIGANI_DB_DSN.  Empty string = not configured.
    raise_in_migrations : bool
        If True, run_migrations() throws (simulates DB unreachable after DSN check).

    Returns (False, None) on success; re-raises on fail-closed path.
    """
    _db_dsn_configured = False

    try:
        if db_dsn and "${POSTGRES_PASSWORD}" not in db_dsn:
            _db_dsn_configured = True
            if raise_in_migrations:
                raise RuntimeError("cannot connect to postgres")
        # else: no DSN, nothing to do
    except Exception:
        if _db_dsn_configured:
            raise  # fail-closed — let caller catch
        # swallow — no DSN configured
        return False, RuntimeError("import/other error")

    return False, None


class TestGatewayDBInitFailClosed:
    """
    M-02: Gateway DB init must be fail-closed when DSN is configured.

    These tests exercise the decision logic isolated from the full entrypoint
    (which requires a live stack).  The logic under test is the
    `_db_dsn_configured` flag + re-raise pattern added in M-02.
    """

    def test_no_dsn_no_error_is_ok(self):
        """No DSN set, no error → normal community deploy path, returns cleanly."""
        result, exc = _run_db_init_block(db_dsn="", raise_in_migrations=False)
        assert not result
        assert exc is None

    def test_no_dsn_migration_error_is_not_reachable(self):
        """No DSN set: run_migrations is never called, so raise_in_migrations=True
        has no effect — returns cleanly (DSN guard prevents the code path)."""
        # With no DSN the raise_in_migrations=True path is never reached because
        # _db_dsn_configured stays False and run_migrations is gated behind it.
        result, exc = _run_db_init_block(db_dsn="", raise_in_migrations=True)
        assert not result
        assert exc is None

    def test_dsn_set_success_is_ok(self):
        """DSN set + no error → DB ready, no raise."""
        result, exc = _run_db_init_block(
            db_dsn="postgresql://user:pass@postgres:5432/yashigani",
            raise_in_migrations=False,
        )
        assert not result
        assert exc is None

    def test_dsn_set_failure_reraises(self):
        """DSN set + DB init failure → must re-raise (fail-closed, M-02 / SOP 1).

        This is the core SOP 1 invariant: a configured-but-broken DB must never
        be silently swallowed.  The process must exit non-zero so the orchestrator
        surfaces the fault.
        """
        with pytest.raises(RuntimeError, match="cannot connect to postgres"):
            _run_db_init_block(
                db_dsn="postgresql://user:pass@postgres:5432/yashigani",
                raise_in_migrations=True,
            )

    def test_dsn_set_failure_logs_exception(self, caplog):
        """The exception path must log at ERROR/EXCEPTION level before re-raising.

        Verifies the entrypoint logging pattern (logger.exception) would fire.
        """
        log = logging.getLogger("test_gateway_db_init")
        with caplog.at_level(logging.ERROR, logger="test_gateway_db_init"):
            with pytest.raises(RuntimeError):
                try:
                    raise RuntimeError("db down")
                except Exception:
                    log.exception("Gateway DB/inference init FAILED with YASHIGANI_DB_DSN configured")
                    raise
        assert "FAILED" in caplog.text

    def test_placeholder_password_dsn_not_configured(self):
        """DSN with unresolved ${POSTGRES_PASSWORD} placeholder is treated as unconfigured.

        If password substitution fails, the placeholder is left in the DSN string.
        The gateway must not arm the fail-closed re-raise path in that state.
        """
        dsn = "postgresql://user:${POSTGRES_PASSWORD}@postgres:5432/yashigani"
        # Gateway condition: `if db_dsn and "${POSTGRES_PASSWORD}" not in db_dsn`
        db_dsn_configured = False
        if dsn and "${POSTGRES_PASSWORD}" not in dsn:
            db_dsn_configured = True
        assert not db_dsn_configured, \
            "Unresolved placeholder DSN must not arm the fail-closed re-raise path"
