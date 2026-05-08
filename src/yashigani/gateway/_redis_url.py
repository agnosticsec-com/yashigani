"""Redis URL construction helper.

# Last updated: 2026-05-03T00:00:00+01:00

Centralises the rediss:// / redis:// URL pattern used by gateway, backoffice,
and ratelimit consumers.  Previously each call site rebuilt the URL inline,
with a copy-paste risk of cert-path divergence.

Design notes
------------
* The DB index MUST appear BEFORE the query-string: `{base}/{db}{query}`.
  redis-py parses the URL left-to-right; a `?` before `/{db}` corrupts the
  path component and routes all clients to DB 0 regardless of the supplied
  index.  This was the v2.23.1 gateway-DSN-DIRECT bug (gate #58b evidence).
* TLS cert paths use the secrets_dir prefix so that tests can override via
  the YASHIGANI_SECRETS_DIR env var without touching the code.
* `client_cert_name` is the stem of the client cert pair, e.g. "gateway_client"
  → /run/secrets/gateway_client.crt + gateway_client.key.
* The ca_root.crt trust anchor is always used (not ca_intermediate.crt) because
  redis-py uses Python ssl which does not set X509_V_FLAG_PARTIAL_CHAIN on
  Python 3.12 / OpenSSL 3.0 / Ubuntu 24.04 — intermediate-only anchors fail.
  Gate #58a evidence (2026-04-28).
"""
from __future__ import annotations

import os
from urllib.parse import quote


def build_redis_url(
    db: int,
    *,
    host: str | None = None,
    port: str | None = None,
    password: str | None = None,
    use_tls: bool | None = None,
    secrets_dir: str | None = None,
    client_cert_name: str = "gateway_client",
) -> str:
    """Return a fully-formed redis(s):// URL for the given DB index.

    Parameters
    ----------
    db:
        Redis logical database index (0–15).
    host:
        Redis hostname.  Defaults to REDIS_HOST env var, falling back to
        ``"redis"``.
    port:
        Redis port as a string.  Defaults to REDIS_PORT env var, falling back
        to ``"6380"`` (TLS port).
    password:
        Redis auth password.  If *None*, the helper reads the password from
        ``<secrets_dir>/redis_password`` (preferred) or the ``REDIS_PASSWORD``
        env var (fallback).
    use_tls:
        Force TLS on/off.  If *None*, derived from ``REDIS_USE_TLS`` env var
        (default: ``true``).
    secrets_dir:
        Directory containing TLS cert/key files and the redis_password file.
        Defaults to ``YASHIGANI_SECRETS_DIR`` env var, falling back to
        ``"/run/secrets"``.
    client_cert_name:
        Stem of the client certificate pair under ``secrets_dir``.  For the
        gateway use ``"gateway_client"``; for the backoffice use
        ``"backoffice_client"``.

    Returns
    -------
    str
        A redis:// or rediss:// URL suitable for ``redis.from_url()``.
    """
    _secrets_dir: str = secrets_dir or os.getenv("YASHIGANI_SECRETS_DIR") or "/run/secrets"
    _host = host or os.getenv("REDIS_HOST", "redis")
    _port = port or os.getenv("REDIS_PORT", "6380")

    if use_tls is None:
        use_tls = os.getenv("REDIS_USE_TLS", "true").lower() == "true"

    if password is None:
        pwd_file = os.path.join(_secrets_dir, "redis_password")
        try:
            with open(pwd_file) as _f:
                password = _f.read().strip()
        except OSError:
            password = os.getenv("REDIS_PASSWORD", "")

    _q = quote(password or "", safe="")

    if use_tls:
        _ca = f"{_secrets_dir}/ca_root.crt"
        _crt = f"{_secrets_dir}/{client_cert_name}.crt"
        _key = f"{_secrets_dir}/{client_cert_name}.key"
        base = f"rediss://:{_q}@{_host}:{_port}"
        query = (
            f"?ssl_cert_reqs=required&ssl_ca_certs={_ca}"
            f"&ssl_certfile={_crt}&ssl_keyfile={_key}"
        )
        return f"{base}/{db}{query}"
    else:
        return f"redis://:{_q}@{_host}:{_port}/{db}"
