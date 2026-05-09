<!-- last-updated: 2026-05-09T00:00:00+01:00 -->

# SSRF Defences in Yashigani

**Applies to:** Yashigani v2.23.3+  
**Threat:** Server-Side Request Forgery (SSRF) — OWASP API Security Top 10: API7

---

## Overview

Yashigani makes outbound HTTP requests on behalf of the gateway operator: HIBP
password-breach checks, OIDC/SSO token exchange, Open WebUI model pushes, OPA
policy evaluation, SIEM event forwarding, and alert sinks (Slack, Teams,
PagerDuty).

Every outbound call is routed through the centralised `HttpClient`
(`yashigani.net.HttpClient`), which enforces:

- HTTPS-only by default (HTTP opt-in via `YASHIGANI_OUTBOUND_ALLOW_HTTP=1`)
- Scheme allowlist (`https://`, `http://` opt-in only — never `file://`, `gopher://`, etc.)
- Hard-blocked destination ranges:
  - `127.0.0.0/8` — loopback
  - `::1/128` — IPv6 loopback
  - `169.254.0.0/16` — link-local IPv4 (covers AWS/Azure/GCP IMDS at `169.254.169.254`)
  - `fe80::/10` — link-local IPv6
  - `169.254.169.254` — AWS/Azure/GCP IMDS (explicit hostname block)
  - `metadata.google.internal` — GCP metadata
  - `100.100.100.200` — Alibaba Cloud metadata
- Operator-configured `YASHIGANI_OUTBOUND_ALLOWLIST` — hostname, suffix, or CIDR entries
- Operator-configured `YASHIGANI_OUTBOUND_BLOCKLIST` — additional deny list
- No automatic redirect following (follow-redirects defaults to `False`)
- 30-second timeout ceiling

---

## DNS-Rebinding Defence (v2.23.3)

### The attack

Standard pre-flight allowlist checks run at URL-parse time, before the TCP
connection is opened. An attacker who controls DNS for the target hostname can
serve a **different IP on the actual connection** than the one that passed the
pre-flight check:

1. Attacker registers `api.attacker.example` in an allowlisted zone.
2. Gateway performs the allowlist check: DNS returns `203.0.113.1` (public) — pass.
3. Attacker changes the DNS record TTL to 0 and swaps it to `10.0.0.1` (internal).
4. Gateway opens the TCP connection: OS resolver returns `10.0.0.1` — internal host reached.

This is the classic DNS-rebinding SSRF bypass.

### The defence — `pinned_resolver`

Yashigani v2.23.3 introduces `yashigani.net.pinned_resolver`, an async context
manager that closes the race window:

1. **Resolve once at context entry** — `socket.getaddrinfo` is called
   synchronously when the context manager is entered.
2. **Verify the resolved IP** — the result is checked against the same
   hard-block ranges and operator allowlist/blocklist before being cached.
3. **Pin the transport** — a bespoke `httpx.AsyncHTTPTransport` subclass
   (`_PinnedTransport`) monkey-patches `socket.getaddrinfo` for the duration
   of each request, returning the cached IP instead of performing a fresh
   lookup. The original resolver is restored immediately after the request
   completes (in a `finally` block, so exception paths are also covered).
4. **Audit event** — every successful pin emits `SSRF_PINNED_RESOLVER_USED`
   at `DEBUG` log level, including the hostname and pinned IP, so operators
   can confirm the path is active.

The patch scope is intentionally narrow:

- Only the hostname matching the current request URL is intercepted.
- All other hosts pass through to the real OS resolver.
- `follow_redirects` is always `False` on the yielded client — redirect chains
  to a different hostname cannot bypass the pin.

### Usage

```python
from yashigani.net import pinned_resolver, BlockedByPolicy

try:
    async with pinned_resolver(
        "api.pwnedpasswords.com",
        port=443,
        allowlist=["api.pwnedpasswords.com"],
    ) as session:
        resp = await session.get("https://api.pwnedpasswords.com/range/ABCDE")
except BlockedByPolicy as exc:
    logger.warning("SSRF policy blocked outbound request: %s", exc)
```

### Environment variables

The `pinned_resolver` uses the same allowlist/blocklist infrastructure as
`HttpClient`. No additional configuration is required. The pinned-resolver path
is opt-in at each call site.

| Variable | Default | Effect |
|---|---|---|
| `YASHIGANI_OUTBOUND_ALLOWLIST` | (empty — allow all public) | Comma-separated hostname/suffix/CIDR entries |
| `YASHIGANI_OUTBOUND_BLOCKLIST` | (empty) | Additional deny entries beyond hard-coded ranges |

### Observability

Enable `DEBUG` logging on the `yashigani.net.pinned_resolver` logger to see
per-request pin events:

```
DEBUG yashigani.net.pinned_resolver SSRF_PINNED_RESOLVER_USED host=api.pwnedpasswords.com pinned_ip=104.21.44.102 port=443
```

To promote this to `INFO` for production visibility, add:

```python
logging.getLogger("yashigani.net.pinned_resolver").setLevel(logging.INFO)
```

or set `YASHIGANI_LOG_LEVEL_NET=INFO` if your deployment uses the structured
log-level override map.

---

## Remaining Attack Surface

| Call site | Current guard | Pinned resolver? |
|---|---|---|
| HIBP (password breach) | `HttpClient`, allowlist `api.pwnedpasswords.com` | No — hardcoded URL; risk is theoretical |
| Open WebUI model push | `HttpClient`, `YASHIGANI_OWUI_HOSTNAMES` | No — admin-configured at deploy time |
| OIDC token exchange | `HttpClient`, OIDC discovery URL validation | No — operator-configured, validated at startup |
| OPA policy push | `HttpClient`, OPA URL schema check | No — internal sidecar; no public DNS |
| SIEM forwarding | `validate_siem_url()` allowlist | No — operator-configured at deploy time |
| Alert sinks (Slack/Teams/PagerDuty) | `HttpClient` | No — webhook URLs are operator-configured |
| Gateway upstream proxy | Admin-configured allowlist, `_assert_safe_upstream_url` | No — admin-controlled |

Sites marked "No" carry low DNS-rebinding risk because either:
- the URL is fully hardcoded (no attacker-controlled hostname component), or
- the hostname is operator-configured at deploy time and validated once at
  startup (not per-request).

`pinned_resolver` is available for any call site where the URL target is
computed at request time and the hostname could theoretically be influenced by
external data.

---

## References

- [OWASP API Security Top 10: API7 — Server Side Request Forgery](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- Yashigani issue #91 — pinned-resolver implementation
- `src/yashigani/net/pinned_resolver.py` — implementation
- `src/tests/security/test_dns_rebinding.py` — test suite
