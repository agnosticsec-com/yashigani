"""
Yashigani Gateway — rate-limit env-var resolution helper.

Extracted into its own module so the resolver can be imported and tested
in isolation without triggering the full ``entrypoint._build_app()`` call,
which requires write access to ``/var/log/yashigani`` and a live Redis.

Last updated: 2026-05-07T00:00:00+00:00
"""
from __future__ import annotations

import logging
import os

_log = logging.getLogger(__name__)

_VALID_FAIL_MODES: frozenset[str] = frozenset({"open", "closed"})
_DEFAULT_FAIL_MODE = "closed"


def resolve_rate_limit_fail_mode(env: dict[str, str] | None = None) -> str:
    """
    Resolve ``RATE_LIMITER_FAIL_MODE`` from the environment (or a supplied
    mapping for testing).

    Secure default is ``closed``: on Redis unavailability, requests are
    rejected with HTTP 503 + ``Retry-After`` rather than silently allowed
    through.  High-availability operators who accept the trade-off may opt
    back into fail-open via ``RATE_LIMITER_FAIL_MODE=open``.

    Returns one of ``'open'`` or ``'closed'``.  Invalid values produce a
    warning and fall back to ``'closed'``.

    Args:
        env: Optional environment mapping for testing. When ``None``,
             ``os.environ`` is used.
    """
    raw = (env if env is not None else os.environ).get(
        "RATE_LIMITER_FAIL_MODE", _DEFAULT_FAIL_MODE
    ).strip().lower()
    if raw in _VALID_FAIL_MODES:
        return raw
    _log.warning(
        "RATE_LIMITER_FAIL_MODE=%r is not valid (expected 'open' or 'closed'); "
        "defaulting to 'closed'",
        raw,
    )
    return _DEFAULT_FAIL_MODE
