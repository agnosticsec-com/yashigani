# Yashigani Security Gateway — OWASP Compliance Mapping

**Document Version:** 1.2
**Date:** 2026-03-30
**Codebase version:** v0.8.4
**Audience:** Security Architects, Compliance Engineers, Procurement Teams
**Classification:** Public

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Section 1: OWASP ASVS v5 Mapping](#section-1-owasp-asvs-v5-mapping)
3. [Section 2: OWASP API Security Top 10 (2023) Mapping](#section-2-owasp-api-security-top-10-2023-mapping)
4. [Section 3: OWASP Agentic AI and LLM Top 10 Mapping](#section-3-owasp-agentic-ai-and-llm-top-10-mapping)
5. [Section 4: Compliance Summary Table](#section-4-compliance-summary-table)
6. [Section 5: Gap Analysis and Residual Risk](#section-5-gap-analysis-and-residual-risk)
7. [Appendix: Terminology and References](#appendix-terminology-and-references)

---

## Executive Summary

Yashigani is a security enforcement gateway purpose-built for MCP (Model Context Protocol) servers and agentic AI systems. It operates as a reverse proxy between AI agents and MCP tool servers, providing defense-in-depth through a multi-layer inspection pipeline, OPA-enforced access control, credential isolation, and comprehensive audit infrastructure.

This document maps Yashigani's security controls against three authoritative OWASP frameworks:

- **OWASP Application Security Verification Standard (ASVS) v5** — 13 control chapters
- **OWASP API Security Top 10 (2023)** — 10 API-specific risk categories
- **OWASP LLM Top 10 and Agentic AI Security** — 10 LLM risk categories plus agent-specific controls

The mapping is intended to serve security architects performing due diligence, procurement teams evaluating vendor risk, and compliance engineers preparing evidence packages for audits (SOC 2, ISO 27001, etc.).

### Summary Coverage

| Framework | Full Coverage | Partial Coverage | Not Applicable | Not Covered |
|---|---|---|---|---|
| OWASP ASVS v5 (L2) | 67% | 24% | 6% | 3% |
| OWASP API Security Top 10 | 80% | 20% | 0% | 0% |
| OWASP LLM Top 10 | 70% | 20% | 10% | 0% |

Controls marked PARTIAL reflect areas where Yashigani provides meaningful mitigations but cannot achieve full coverage due to architectural scope boundaries (e.g., client-side controls, training-time concerns). These are documented in detail in Section 5.

---

## Section 1: OWASP ASVS v5 Mapping

The OWASP Application Security Verification Standard (ASVS) v5 defines a framework of security requirements organized into 14 chapters. This section maps Yashigani controls to ASVS Level 2 requirements — the standard baseline for most enterprise applications handling sensitive data.

ASVS levels are defined as:
- **L1** — Minimum security baseline
- **L2** — Standard for most applications
- **L3** — High-assurance / highly sensitive applications

Coverage ratings:
- **FULL** — Yashigani directly implements or enforces this control
- **PARTIAL** — Control is present but may depend on operator configuration or has scope boundaries
- **N/A** — Requirement does not apply to a gateway/proxy architecture
- **GAP** — Control is not currently implemented

---

### V1 — Encoding and Sanitization

| ASVS Requirement | Level | Yashigani Control | Coverage |
|---|---|---|---|
| V1.1.1 — Verify that all request data is validated and sanitized on a trusted server | L1 | FastText ML first-pass + OPA policy engine inspect and validate all inbound requests at the gateway data plane before forwarding | FULL |
| V1.1.2 — Verify that all input fields, including hidden fields, cookies, and HTTP headers, are validated | L1 | OPA input object includes the full request context: all headers, path, method, query parameters, and body metadata | FULL |
| V1.1.3 — Verify that all output is encoded appropriately for the context | L2 | Response inspection pipeline validates upstream responses when YASHIGANI_INSPECT_RESPONSES is enabled; backoffice renders with strict CSP | PARTIAL |
| V1.1.4 — Verify that all untrusted HTML data is sanitized before being sent to the browser | L2 | Backoffice admin panel serves strict Content-Security-Policy headers, X-Frame-Options: DENY, and encodes dynamic content | FULL |
| V1.1.5 — Verify that body size limits are enforced | L2 | Hard limit of 4 MB enforced by FastAPI middleware on all inbound request bodies; requests exceeding this limit are rejected before inspection | FULL |
| V1.1.6 — Verify that UTF-8 safe decoding is enforced | L2 | UTF-8 safe decode applied during inspection pipeline ingestion; malformed byte sequences trigger rejection before forwarding | FULL |

**Chapter Notes:** The gateway's position as a reverse proxy provides a centralized enforcement point for input validation that is consistent across all upstream MCP tool servers, regardless of each server's own validation posture. This is a significant architectural advantage — a misconfigured upstream cannot introduce encoding vulnerabilities through Yashigani.

---

### V2 — Authentication

| ASVS Requirement | Level | Yashigani Control | Coverage |
|---|---|---|---|
| V2.1.1 — Verify that passwords are stored using an approved adaptive one-way function | L1 | Argon2id is the default password hashing algorithm for all user accounts; bcrypt is supported as a legacy compatibility option | FULL |
| V2.1.2 — Verify that passwords at least 12 characters in length are permitted | L1 | Minimum password length is configurable with a system-enforced floor; argon2 parameters (memory, iterations, parallelism) are operator-configurable | FULL |
| V2.2.1 — Verify that TOTP authentication is available | L2 | TOTP 2FA is mandatory for backoffice admin accounts; enforced at session creation, not opt-in | FULL |
| V2.2.2 — Verify that multi-factor authentication (MFA) is enforced for privileged users | L2 | Admin sessions require TOTP verification before any privileged operation is permitted; TOTP enforcement is not bypassable via configuration | FULL |
| V2.3.1 — Verify that credential reset uses a secure out-of-band mechanism | L2 | Operator-managed; Yashigani provides secure session invalidation but credential reset flow is delegated to the operator's identity infrastructure | PARTIAL |
| V2.4.1 — Verify that SAML assertions are validated | L2 | SAML v2 integration validates assertions, enforces NotBefore/NotOnOrAfter time bounds, and verifies signature against configured IdP metadata | FULL |
| V2.4.2 — Verify that OIDC tokens are validated | L2 | OIDC ID token validation enforces signature verification, issuer, audience, and expiry checks against the configured JWKS endpoint | FULL |
| V2.5.1 — Verify that JWT tokens use only permitted algorithms | L2 | JWT introspection rejects alg:none unconditionally; only RS256, RS384, RS512, ES256, ES384, ES512 are permitted; HS* (HMAC-based) algorithms are rejected | FULL |
| V2.5.2 — Verify that JWKS key material is validated | L2 | JWKS waterfall: primary JWKS endpoint, fallback to secondary, then static key file; key rotation is handled automatically on 401 from upstream | FULL |
| V2.6.1 — Verify that agent/API token credentials meet minimum entropy requirements | L2 | Agent bearer tokens must meet a minimum length of 64 characters; tokens below this threshold are rejected at registration time | FULL |

**Chapter Notes:** The combination of Argon2id hashing, mandatory TOTP, and strict JWT algorithm enforcement provides strong authentication coverage. The SAML and OIDC integrations allow Yashigani to participate in enterprise SSO ecosystems without weakening its own authentication posture.

---

### V3 — Session Management

| ASVS Requirement | Level | Yashigani Control | Coverage |
|---|---|---|---|
| V3.1.1 — Verify that the application never reveals session tokens in URLs | L1 | Session identifiers are transmitted exclusively via HttpOnly cookies; no URL-based session token patterns are supported | FULL |
| V3.2.1 — Verify that session cookies use HttpOnly, Secure, and SameSite attributes | L1 | All session cookies are set with HttpOnly=true, Secure=true, SameSite=Strict; backoffice enforces SameSite=Strict | FULL |
| V3.2.2 — Verify that session tokens are invalidated on logout | L1 | Redis session store invalidates tokens synchronously on logout; server-side session records are deleted, not merely expired | FULL |
| V3.3.1 — Verify that session expiry is enforced | L2 | Session TTL is configurable per deployment; idle timeout and absolute expiry are both enforced independently at the Redis session store | FULL |
| V3.4.1 — Verify that concurrent session limits are enforced | L2 | Configurable maximum concurrent sessions per user; exceeding the limit invalidates the oldest session (configurable to reject new sessions instead) | FULL |
| V3.5.1 — Verify that session identifiers have sufficient entropy | L2 | Session tokens generated via cryptographically secure PRNG; minimum 128-bit entropy enforced by generation policy | FULL |

---

### V4 — Access Control

| ASVS Requirement | Level | Yashigani Control | Coverage |
|---|---|---|---|
| V4.1.1 — Verify that access control decisions are made server-side | L1 | OPA policy engine executes locally on the server; no access control decisions are delegated to clients or cloud services | FULL |
| V4.1.2 — Verify that access control fails securely (fail-closed) | L1 | OPA evaluation errors result in deny; there is no fail-open code path in the policy evaluation loop | FULL |
| V4.1.3 — Verify that the principle of least privilege is enforced | L2 | RBAC groups define the minimum permission set for each role; OPA policy enforces method+path+identity checks on every request | FULL |
| V4.2.1 — Verify that object-level authorization is enforced | L2 | Tenant row-level security (RLS) in PostgreSQL ensures data isolation; OPA input includes tenant context for every policy evaluation | FULL |
| V4.3.1 — Verify that administrative interfaces are secured | L1 | Backoffice control plane is isolated on port 8443 with local authentication only; no gateway (data plane) path can reach backoffice routes | FULL |
| V4.3.2 — Verify that administrative functionality is separated from regular usage | L2 | Backoffice and gateway are architecturally separated processes; admin routes are protected by require_admin_session middleware, which is not present on gateway routes | FULL |
| V4.3.3 — Verify that a minimum number of administrative accounts are enforced | L2 | Admin minimum count enforcement prevents deletion of the last admin account; system will reject operations that would leave zero active admins | FULL |
| V4.4.1 — Verify that RBAC groups control access to sensitive functions | L2 | OPA policy evaluates RBAC group membership for every request; group-level rate limit overrides allow security teams to apply stricter controls per group | FULL |

---

### V5 — Validation, Sanitization, and Encoding

| ASVS Requirement | Level | Yashigani Control | Coverage |
|---|---|---|---|
| V5.1.1 — Verify that input validation rejects untrusted input | L1 | FastText ML classification (<5ms) performs first-pass content analysis on all request bodies; suspicious content is routed for deeper inspection before forwarding | FULL |
| V5.1.2 — Verify that body size limits are enforced before processing | L1 | 4 MB hard limit is enforced by the ingestion middleware before inspection pipeline is invoked; prevents resource exhaustion from oversized payloads | FULL |
| V5.2.1 — Verify that all user-supplied input is sanitized before rendering | L2 | Backoffice templates apply context-aware output encoding; API responses from upstream are inspected and sanitized before forwarding when response inspection is enabled | PARTIAL |
| V5.3.1 — Verify that prompt injection mitigations are applied for AI inputs | L2 | Multi-stage inspection: FastText first-pass → Ollama LLM second-pass → multi-backend fallback (Anthropic, Gemini, Azure OpenAI); payloads classified INJECTED are discarded, caller receives alert | FULL |
| V5.4.1 — Verify that credentials are stripped before AI processing | L2 | Credential Handle Service (CHS) strips all credential-pattern tokens from payloads before ANY AI inspection call; CHS operates on configurable regex+entropy patterns | FULL |
| V5.5.1 — Verify that injection attacks are mitigated in database queries | L1 | PostgreSQL access uses parameterized queries throughout; ORM-level query construction prevents SQL injection; RLS enforces tenant boundaries at the database layer | FULL |

---

### V6 — Stored Cryptography

| ASVS Requirement | Level | Yashigani Control | Coverage |
|---|---|---|---|
| V6.1.1 — Verify that sensitive data at rest is encrypted | L2 | AES-256-GCM column encryption via pgcrypto on all sensitive PostgreSQL columns; encryption keys managed via integrated secrets backends | FULL |
| V6.2.1 — Verify that strong, current algorithms are used | L2 | AES-256-GCM for symmetric encryption; ECDSA P-256 for license signing; Argon2id for password hashing; no deprecated algorithms (MD5, SHA1, DES, 3DES) permitted | FULL |
| V6.2.2 — Verify that random number generation is cryptographically secure | L2 | All security-sensitive random values (session tokens, API keys, nonces) use the OS CSPRNG (os.urandom / secrets module) | FULL |
| V6.3.1 — Verify that cryptographic keys are protected | L2 | Keys are managed via external secrets backends: Docker Secrets, Keeper, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, HashiCorp Vault; no keys stored in environment variables in production mode | FULL |
| V6.4.1 — Verify that key rotation is supported | L2 | Secrets backend integrations support key versioning and rotation; JWKS key rotation is automatic on upstream 401 response | PARTIAL |
| V6.5.1 — Verify that passwords are hashed using Argon2id or equivalent | L1 | Argon2id is the required default; Argon2 parameters (memory cost 65536 KB, time cost 3, parallelism 4 by default) are operator-configurable within secure bounds | FULL |

---

### V7 — Error Handling and Logging

| ASVS Requirement | Level | Yashigani Control | Coverage |
|---|---|---|---|
| V7.1.1 — Verify that all logging events contain required data | L1 | Structured JSON audit log records: timestamp, request_id, agent_id, session_id, method, path, policy decision, inspection result, upstream response code, SHA-256 content hash | FULL |
| V7.1.2 — Verify that security events are logged | L1 | Authentication attempts (success/failure), policy denials, inspection results (CLEAN/INJECTED/UNCERTAIN), rate limit triggers, and anomaly detections all generate audit events | FULL |
| V7.2.1 — Verify that error responses do not contain stack traces | L1 | All unhandled exceptions return a generic HTTP 500 with no internal detail; stack traces are written to the internal log only; error messages are sanitized before transmission | FULL |
| V7.3.1 — Verify that audit logs are written to a separate system | L2 | MultiSinkAuditWriter writes to: local file (rotation-managed), PostgreSQL audit table, and SIEM (Splunk, Elasticsearch, Wazuh); loss of one sink does not halt operation | FULL |
| V7.4.1 — Verify that log injection attacks are prevented | L2 | All log values are escaped before formatting; structured JSON logging eliminates newline injection; log fields use typed serialization | FULL |
| V7.4.2 — Verify that logs do not contain sensitive data | L2 | CHS applies masking to audit log payload records; configurable PII masking hooks allow operators to define additional field-level masking patterns | FULL |

---

### V8 — Data Protection

| ASVS Requirement | Level | Yashigani Control | Coverage |
|---|---|---|---|
| V8.1.1 — Verify that sensitive data is identified and classified | L2 | CHS maintains a configurable credential pattern registry; PII detection hooks allow classification of additional sensitive field types | PARTIAL |
| V8.2.1 — Verify that sensitive data is not cached where inappropriate | L2 | Response cache stores CLEAN responses only; BLOCKED, INJECTED, or SANITIZED responses are never cached; cache keys exclude credential-bearing headers | FULL |
| V8.3.1 — Verify that client-side storage of sensitive data is minimized | L2 | Backoffice admin panel does not store sensitive values in localStorage or sessionStorage; session token is in HttpOnly cookie inaccessible to JavaScript | FULL |
| V8.4.1 — Verify that multi-tenant data isolation is enforced | L2 | PostgreSQL RLS policies enforce per-tenant row isolation; separate Redis database indices are used per tenant for rate limiting and session state | FULL |
| V8.5.1 — Verify that credentials are not exposed to AI backends | L2 | CHS strips credential-matching tokens from all payloads before invoking any AI inspection backend (Ollama, Anthropic, Gemini, Azure OpenAI); CHS operates regardless of inspection backend type | FULL |

---

### V9 — Communication Security

| ASVS Requirement | Level | Yashigani Control | Coverage |
|---|---|---|---|
| V9.1.1 — Verify that TLS is required for all external communications | L1 | Caddy handles TLS termination; TLS 1.2 is the minimum version; TLS 1.0 and 1.1 are disabled; plain HTTP is redirected to HTTPS | FULL |
| V9.1.2 — Verify that HSTS is enabled | L2 | HSTS header (Strict-Transport-Security: max-age=31536000; includeSubDomains) is served by Caddy and enforced by backoffice security middleware | FULL |
| V9.1.3 — Verify that certificate management is automated | L2 | Three certificate modes supported: ACME (automatic Let's Encrypt), CA-signed (operator-provided), and self-signed (development); ACME renewal is fully automated via Caddy | FULL |
| V9.2.1 — Verify that internal service communications are protected | L2 | Internal service-to-service communication (gateway to OPA, gateway to PostgreSQL, gateway to Redis) uses network isolation; container network policies restrict cross-service reachability | PARTIAL |
| V9.3.1 — Verify that weak cipher suites are disabled | L2 | Caddy cipher suite configuration excludes RC4, NULL, EXPORT, DES, 3DES, and MD5-MAC suites; only AEAD cipher suites are permitted | FULL |

---

### V10 — Malicious Code

| ASVS Requirement | Level | Yashigani Control | Coverage |
|---|---|---|---|
| V10.1.1 — Verify that source code and build artifacts are scanned | L2 | Trivy container scanning is integrated into CI/CD pipeline; pyproject.toml dependencies are locked; GitHub Actions CODEOWNERS enforces review requirements on security-sensitive paths | FULL |
| V10.2.1 — Verify that the application runs with minimum OS privileges | L2 | Container runs as UID 1001 (non-root); no privilege escalation (allowPrivilegeEscalation: false); no new privileges flag set | FULL |
| V10.2.2 — Verify that system call filtering is applied | L3 | seccomp allowlist restricts container syscalls to required operations only; AppArmor profile provides mandatory access control at the kernel level | FULL |
| V10.3.1 — Verify that the filesystem is read-only where possible | L2 | readOnlyRootFilesystem: true in container security context; tmpfs mounts provide writable temporary storage for paths that require it (e.g., /tmp, runtime sockets) | FULL |
| V10.4.1 — Verify that container images are built from trusted base images | L2 | Base images are digest-pinned in Dockerfile; image digests are verified in CI before deployment; no mutable tags (e.g., :latest) used in production configurations | FULL |

---

### V11 — Business Logic Security

| ASVS Requirement | Level | Yashigani Control | Coverage |
|---|---|---|---|
| V11.1.1 — Verify that business logic limits are enforced | L1 | Per-IP, per-session, per-agent, and per-endpoint rate limits are independently enforced via Redis fixed-window counters; all limits are configurable per deployment | FULL |
| V11.1.2 — Verify that unusual activity patterns are detected | L2 | Repeated-small-calls anomaly detection uses a Redis ZSET sliding window to identify agents making unusually high-frequency low-cost requests; triggers audit event and optional block | FULL |
| V11.2.1 — Verify that the policy engine fails closed on error | L2 | OPA evaluation errors result in an explicit deny decision; there is no fallback to allow on policy evaluation failure; this is enforced in the policy evaluation wrapper | FULL |
| V11.3.1 — Verify that agent authentication meets minimum standards | L2 | Agent bearer tokens must be at minimum 64 characters; tokens below this threshold are rejected at registration; token entropy is validated at admission time | FULL |
| V11.4.1 — Verify that administrative minimums are enforced | L2 | System enforces a minimum active admin account count; operations that would drop the count below this floor are rejected | FULL |

---

### V12 — Files and Resources

| ASVS Requirement | Level | Yashigani Control | Coverage |
|---|---|---|---|
| V12.1.1 — Verify that file upload size limits are enforced | L1 | 4 MB body size limit applies to all inbound content including file uploads; limit is enforced at the middleware layer before storage | FULL |
| V12.2.1 — Verify that audit log retention policies are enforced | L2 | Audit log file rotation is configured with maximum file size and retention period; PostgreSQL audit table uses pg_partman partitioning for time-based partition expiry | FULL |
| V12.3.1 — Verify that temporary data is stored securely | L2 | tmpfs mounts are used for all transient sensitive data paths; tmpfs data does not persist to container restart; no sensitive data written to container overlay filesystem | FULL |
| V12.4.1 — Verify that log files are protected from unauthorized access | L2 | Audit log files written with restrictive permissions (0600); PostgreSQL audit table access is controlled by RLS and role-based grants; SIEM forwarding uses TLS | FULL |

---

### V13 — API and Web Service

| ASVS Requirement | Level | Yashigani Control | Coverage |
|---|---|---|---|
| V13.1.1 — Verify that every API request is authenticated and authorized | L1 | OPA policy check is executed on every request to the gateway; unauthenticated requests to protected endpoints are rejected before reaching the upstream | FULL |
| V13.2.1 — Verify that HTTP methods are validated | L1 | OPA policy input includes the HTTP method; policies can enforce method-level restrictions per path and identity; unexpected methods return 405 | FULL |
| V13.2.2 — Verify that hop-by-hop headers are stripped | L2 | Connection, Keep-Alive, Transfer-Encoding, Upgrade, Proxy-Authorization, and TE headers are stripped from proxied requests; prevents header injection to upstreams | FULL |
| V13.2.3 — Verify that X-Forwarded-For handling is correct | L2 | X-Forwarded-For is validated and sanitized; spoofed headers from untrusted clients are overridden with the actual connection IP; trusted proxy chains are configurable | FULL |
| V13.3.1 — Verify that internal metrics and debug endpoints are protected | L2 | OpenTelemetry metrics endpoint is on an internal-only port; no metrics or debug routes are exposed on the public gateway port; Jaeger UI is network-isolated | FULL |
| V13.4.1 — Verify that API versioning is managed | L2 | Agent registry and API routes include version metadata; deprecated routes return appropriate warnings; SCIM provisioning endpoints follow RFC 7644 versioning | PARTIAL |

---

## Section 2: OWASP API Security Top 10 (2023) Mapping

The OWASP API Security Top 10 (2023) identifies the most critical security risks facing modern APIs. This section maps each risk to Yashigani's controls, including residual risk notes for areas where operator configuration or deployment decisions affect the coverage level.

---

### API1 — Broken Object Level Authorization (BOLA)

**Risk Description:** APIs fail to properly validate that the requesting user has authorization to access or modify a specific object. Attackers substitute their own object IDs to access other users' data.

**Yashigani Controls:**

Every request to the gateway passes through OPA policy evaluation before being forwarded to any upstream. OPA receives the full request context — identity, group membership, requested path, HTTP method, and query parameters — and evaluates authorization against the current policy bundle. Policy decisions are synchronous and blocking; no request is forwarded until OPA returns an explicit allow.

At the data layer, PostgreSQL row-level security (RLS) policies enforce per-tenant isolation. Even if a policy misconfiguration allowed an unauthorized path, the database would refuse to return rows belonging to a different tenant. RLS operates at the PostgreSQL level and cannot be bypassed by application-layer code.

RBAC group definitions control which object paths each identity is permitted to access. Group assignments are managed through the backoffice control plane and are reflected in OPA policy evaluations on the next policy bundle refresh (configurable interval, default 30 seconds).

**Residual Risk:** OPA policy logic is operator-authored. Yashigani provides the enforcement mechanism and a default policy bundle, but operators who write overly permissive policies may undermine BOLA protection. Policy review should be part of the deployment security review process.

**Coverage: FULL** (with operator policy quality caveat)

---

### API2 — Broken Authentication

**Risk Description:** Weak authentication mechanisms allow attackers to compromise authentication tokens, impersonate users, or bypass authentication entirely.

**Yashigani Controls:**

Yashigani implements layered authentication defenses. User account passwords are hashed using Argon2id with configurable memory and iteration parameters. TOTP second factor is mandatory for all admin accounts; it is not an opt-in feature and cannot be disabled for privileged sessions.

JWT tokens are validated with strict algorithm enforcement: alg:none is rejected unconditionally at the token parsing layer, before any claim evaluation occurs. HMAC-based algorithms (HS256, HS384, HS512) are rejected because they require sharing the signing key with verifiers. Only asymmetric algorithms (RS*, ES*) are accepted. The JWKS waterfall provides automatic key rotation handling.

Session cookies are configured with HttpOnly, Secure, and SameSite=Strict attributes. Session identifiers have a minimum of 128 bits of entropy. Server-side session invalidation at logout prevents token reuse attacks. Idle timeout and absolute session expiry are independently enforced.

Agent bearer tokens must meet a minimum length of 64 characters, enforced at registration time. Token lookup is performed against the agent registry, which includes active/inactive lifecycle status.

**Residual Risk:** Brute-force protection on the login endpoint depends on rate limiting being correctly configured. Operators should verify that per-IP rate limits are applied to the authentication endpoint. Credential reset flows are delegated to the operator's identity infrastructure.

**Coverage: FULL**

---

### API3 — Broken Object Property Level Authorization

**Risk Description:** APIs expose object properties that should not be accessible to the caller, or allow modification of properties that should be read-only for the caller's role.

**Yashigani Controls:**

OPA policy input includes the complete request context: all headers, path parameters, query string, and body metadata. Policies can enforce field-level restrictions on both request inputs and response outputs.

The Credential Handle Service (CHS) provides a complementary control: it strips credential-pattern fields from payloads before AI inspection, ensuring that sensitive properties are not inadvertently disclosed to inspection backends. CHS patterns are configurable and can be extended to cover domain-specific sensitive fields.

The architectural separation of the backoffice (control plane, port 8443, local auth) from the gateway (data plane) ensures that administrative object properties — policy bundles, agent registrations, audit records — are never accessible through the gateway data path.

**Residual Risk:** Response filtering (ensuring upstream responses do not return excess object properties to the caller) depends on the upstream MCP server's implementation. Yashigani can inspect and block responses containing sensitive patterns when response inspection is enabled, but this is a configuration-dependent control.

**Coverage: PARTIAL** (full for gateway-managed objects; partial for upstream response properties without response inspection enabled)

---

### API4 — Unrestricted Resource Consumption

**Risk Description:** APIs do not enforce limits on the size or number of requests, allowing attackers to cause denial of service through resource exhaustion.

**Yashigani Controls:**

Yashigani implements four independent rate limiting dimensions, all backed by Redis:

- **Per-IP rate limiting:** Limits the number of requests from any single source IP within a fixed window
- **Per-session rate limiting:** Limits requests from any single authenticated session
- **Per-agent rate limiting:** Limits requests from any single registered agent identity
- **Per-endpoint rate limiting:** Limits requests to any specific path, regardless of caller identity

All four dimensions are enforced independently. Breaching any single limit results in a 429 response. Rate limit thresholds are configurable per deployment; RBAC group-level overrides allow different limits for different user categories.

The anomaly detection subsystem provides a complementary control: the repeated-small-calls detector uses a Redis ZSET sliding window to identify agents that are making many low-cost requests — a pattern that might evade fixed-window rate limits by staying just below thresholds. Detected anomalies trigger audit events and can optionally trigger automatic blocking.

Body size limits (4 MB) prevent resource exhaustion from oversized payloads. The response cache reduces load on both the inspection pipeline and upstream MCP servers for repeated identical requests.

**Residual Risk:** Redis availability is a dependency for rate limiting. A Redis outage could cause rate limiting to fail; operators should configure Redis in a high-availability configuration and define behavior-on-cache-failure policy.

**Coverage: FULL**

---

### API5 — Broken Function Level Authorization

**Risk Description:** Complex API designs with multiple roles allow attackers to access administrative or privileged functions by calling endpoints intended for other user types.

**Yashigani Controls:**

OPA policy evaluation enforces function-level authorization by evaluating the combination of HTTP method, request path, and caller identity on every request. No request is forwarded until OPA explicitly allows it. Policy deny-on-error ensures that policy evaluation failures do not create permission gaps.

The backoffice control plane is architecturally isolated on port 8443 and requires local authentication. There is no code path through the gateway data plane that can reach backoffice routes. Admin functions — policy management, agent registration, audit log access, user management — are exclusively accessible through the backoffice.

Admin routes within the backoffice are protected by require_admin_session middleware. Session validation includes both the session token check and the TOTP-verified admin flag.

**Residual Risk:** Operators who deploy Yashigani without network-level port isolation between gateway (80/443) and backoffice (8443) may allow network-adjacent attackers to reach the backoffice port. Network segmentation of port 8443 to management networks is a deployment requirement.

**Coverage: FULL**

---

### API6 — Unrestricted Access to Sensitive Business Flows

**Risk Description:** APIs expose business flows (purchase, registration, content creation) without controls that prevent automated abuse of the flow at scale.

**Yashigani Controls:**

The agentic AI context makes this risk particularly relevant: AI agents can programmatically invoke MCP tool calls at machine speed. Yashigani addresses this through multiple controls.

The repeated-small-calls anomaly detection system specifically targets the pattern where an agent makes many small, individually-permitted calls that collectively abuse a business flow. The Redis ZSET sliding window tracks call frequency per agent over configurable time windows, and triggers when the frequency exceeds the configured threshold.

Per-endpoint rate limits can be configured independently for sensitive business function endpoints, allowing tighter restrictions on high-value operations (e.g., credential-bearing tool calls, data exfiltration-adjacent operations).

Agent token authentication with minimum-length enforcement ensures that programmatic access to sensitive flows requires proper registration in the agent registry. Unregistered agents cannot access the gateway.

**Residual Risk:** The semantics of "sensitive business flow" depend on the upstream MCP server's design. Yashigani can enforce rate and volume controls but cannot identify business logic abuse patterns without operator-defined policy rules.

**Coverage: FULL** (with operator policy configuration for domain-specific flows)

---

### API7 — Server Side Request Forgery (SSRF)

**Risk Description:** APIs fetch remote resources based on user-supplied URLs, allowing attackers to use the server as a proxy to reach internal services, cloud metadata endpoints, or other restricted targets.

**Yashigani Controls:**

The upstream MCP server URL is configured exclusively through server-side environment variables at deployment time. There is no user-controlled URL input that determines where the gateway forwards requests. Callers control the path and method within the upstream, but not the hostname or scheme.

OPA policy controls which paths are permitted to be forwarded to the upstream. Path-based policy rules can block requests to paths that would trigger SSRF-relevant behavior in the upstream MCP server.

Because Yashigani is itself a proxy, it does not make outbound requests based on user input. The only outbound connections are: to the configured upstream (fixed), to OPA (local), to the configured inspection backends (fixed), to the configured secrets backend (fixed), and to the audit SIEM sinks (fixed).

**Residual Risk:** If the upstream MCP server itself is vulnerable to SSRF and Yashigani forwards a crafted request to it, the SSRF would be in the upstream. Yashigani's inspection pipeline can identify known SSRF payload patterns if the ML/LLM inspection models are trained on such patterns.

**Coverage: FULL** (for SSRF in Yashigani itself; partial for SSRF in upstream MCP servers)

---

### API8 — Security Misconfiguration

**Risk Description:** Missing security hardening, unnecessary features enabled, default credentials, verbose error messages, and unpatched vulnerabilities constitute security misconfiguration.

**Yashigani Controls:**

All credential and secret values are managed through the secrets backend integrations (Docker Secrets, Keeper, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, HashiCorp Vault). There are no default passwords in the system; all credentials are auto-generated at installation time with a minimum of 36 characters of entropy and printed once at install time.

Container hardening is applied by default: seccomp allowlist, AppArmor profile, UID 1001 non-root, readOnlyRootFilesystem, no privilege escalation. These settings are configured in the provided container manifests and are not optional in supported deployment configurations.

Caddy handles TLS with HTTPS-only enforcement; plain HTTP is redirected. Security headers (HSTS, X-Frame-Options: DENY, Content-Security-Policy, X-Content-Type-Options) are applied by security middleware on all backoffice responses.

Error responses from the gateway return generic messages with no internal implementation detail. Stack traces and framework-specific error information are suppressed in all non-development deployment modes.

Trivy container scanning in CI identifies known CVEs in base images and Python dependencies before images are pushed to the registry.

**Residual Risk:** Operators who override default hardening configurations (e.g., running as root, disabling seccomp, using environment variables for secrets) reduce the security posture below the documented baseline.

**Coverage: FULL**

---

### API9 — Improper Inventory Management

**Risk Description:** Outdated, undocumented, or shadow API endpoints allow attackers to exploit functionality that operators believe is inaccessible.

**Yashigani Controls:**

The agent registry provides a complete inventory of all registered agents with active/inactive lifecycle status. Agents that are deactivated cannot authenticate against the gateway. The registry is managed through the backoffice admin UI, providing full operator visibility into the agent inventory.

Every agent registration event generates an audit log entry. Operators can review the audit trail to identify unauthorized registration attempts or unexpected agents.

SCIM v2 provisioning integration allows enterprise identity providers to manage the agent inventory programmatically, ensuring that agent lifecycle events (provisioning, deprovisioning) are driven by the authoritative identity system.

All active API routes are enumerated in the OPA policy bundle. Routes not present in the policy bundle are denied by default, preventing shadow endpoint access even if a route exists in the application code.

**Residual Risk:** Upstream MCP servers may expose endpoints that are not reflected in Yashigani's policy bundle. Operators should ensure that the OPA policy bundle accurately represents the full set of intended upstream paths.

**Coverage: FULL**

---

### API10 — Unsafe Consumption of External APIs

**Risk Description:** Applications that consume third-party APIs blindly trust the responses, inherit vulnerabilities from upstream systems, and expose users to injected content from compromised upstreams.

**Yashigani Controls:**

When YASHIGANI_INSPECT_RESPONSES is enabled, the inspection pipeline processes all upstream responses through the same FastText + LLM pipeline used for inbound requests. Upstream responses containing injection patterns, credential-like content, or other suspicious material are flagged, logged, and optionally blocked before being forwarded to the caller.

Hop-by-hop headers are stripped from upstream responses before they are forwarded, preventing upstreams from injecting proxy-control headers into the response stream.

The response cache stores only CLEAN-classified responses. Responses that have been blocked, flagged, or sanitized are never cached, ensuring that cached content has passed inspection.

The inspection backend chain (Ollama local → Anthropic → Gemini → Azure OpenAI) is itself consumed with security controls: API keys are stored in the secrets backend, CHS strips credentials before sending payloads, and all responses from inspection backends are treated as untrusted input.

**Residual Risk:** Response inspection adds latency and is a configuration-dependent control. Deployments that disable response inspection for performance reasons lose the upstream response validation layer.

**Coverage: FULL** (with response inspection enabled; partial without)

---

## Section 3: OWASP Agentic AI and LLM Top 10 Mapping

The OWASP LLM Top 10 and emerging Agentic AI security guidance address risks specific to AI-integrated systems. Yashigani's design is purpose-built for this context, as it sits at the trust boundary between AI agents and the MCP tool servers they interact with.

---

### LLM01 — Prompt Injection

**Risk Description:** Attackers craft malicious inputs that manipulate AI systems into ignoring previous instructions, exfiltrating data, executing unintended actions, or bypassing safety controls.

**Yashigani Controls:**

Yashigani implements a multi-stage, multi-backend prompt injection detection pipeline:

1. **FastText ML (< 5ms):** A lightweight fastText binary classification model performs the first-pass analysis on all request content. This model is bundled in the container image and requires no network call. Its low latency makes it suitable for inline inspection of every request without meaningful performance impact.

2. **Ollama LLM (local, second pass):** Requests classified as UNCERTAIN by fastText, or where confidence falls below the configured threshold, are routed to a locally-running Ollama model for deeper semantic analysis. Ollama runs within the deployment environment; no content is sent to a cloud service at this stage.

3. **Multi-backend fallback chain:** If Ollama is unavailable or returns UNCERTAIN, the system falls back to configured cloud backends in priority order: Anthropic Claude, Google Gemini, Azure OpenAI. The fallback chain is configurable and each backend is optional.

4. **Fail-closed on INJECTED:** Payloads classified as INJECTED are discarded and never forwarded to the upstream MCP server. The caller receives a policy alert response. The inspection result and payload hash are logged to the audit trail.

5. **Confidence thresholds:** Each classification stage has a configurable confidence threshold. Results below the threshold are escalated to the next stage rather than making a low-confidence allow decision.

**Residual Risk:** Novel prompt injection patterns not represented in the fastText training data may evade the first-pass filter. The LLM second-pass provides a semantic fallback, but LLMs can themselves be manipulated in adversarial prompting scenarios. Defense in depth at the model level, combined with OPA policy enforcement, limits the blast radius of a missed detection.

**Coverage: FULL**

---

### LLM02 — Insecure Output Handling

**Risk Description:** AI-generated outputs are not validated or sanitized before being rendered or acted upon, allowing XSS, SSRF, code injection, or other attacks through model outputs.

**Yashigani Controls:**

When YASHIGANI_INSPECT_RESPONSES is enabled, all upstream responses pass through the inspection pipeline before being returned to the caller. Suspicious response content is flagged, logged to the SIEM, and optionally sanitized or blocked.

Backoffice UI output rendering uses strict CSP headers that block inline script execution, limiting the impact of any unsanitized output that reaches the admin interface.

Audit log entries for flagged outputs include the full payload hash, classification result, and backend used for classification, enabling post-incident forensic analysis.

**Residual Risk:** Response inspection is an operator-configurable control. Applications that render gateway responses in contexts susceptible to injection (e.g., HTML rendering of MCP tool output) must ensure response inspection is enabled and that output encoding is applied at the rendering layer.

**Coverage: PARTIAL** (depends on response inspection configuration)

---

### LLM03 — Training Data Poisoning

**Risk Description:** Adversaries corrupt the training data or fine-tuning datasets used to build AI models, causing the model to exhibit malicious behavior in production.

**Yashigani Controls:**

Training data poisoning is a training-time concern that occurs before deployment of the model. Yashigani is a runtime proxy and cannot directly prevent poisoning of the models it interacts with. However, the following mitigations apply:

- The fastText classification model's training scripts are provided to operators, allowing them to audit and validate the training data and model behavior.
- The model binary is bundled in the container image, which is digest-pinned. Tampered images would not match the recorded digest.
- The multi-backend fallback chain provides redundancy: if one model's behavior has been altered, another backend provides a cross-check.

**Residual Risk:** This is fundamentally a training-time and supply chain concern that is out of scope for a runtime gateway. Operators using custom-trained fastText models should apply appropriate controls to their model training pipelines. This gap is acknowledged in Section 5.

**Coverage: PARTIAL** (integrity controls on model artifacts; training process is out of scope)

---

### LLM04 — Model Denial of Service

**Risk Description:** Attackers consume excessive AI inference resources through crafted inputs that trigger expensive model operations, causing service degradation or complete unavailability.

**Yashigani Controls:**

Per-endpoint and per-agent rate limits constrain the number of requests that can be directed at the inspection pipeline within any time window. Requests exceeding rate limits are rejected before inspection, preventing resource exhaustion through the inspection chain.

Anomaly detection identifies unusual call patterns — including the repeated-small-calls pattern that can be used to run many inexpensive inference operations that collectively exhaust resources.

Ollama request queuing limits concurrent inference requests to the local LLM. Requests beyond the queue capacity are routed to the next fallback backend rather than blocking.

Container resource limits (cgroup v2) constrain the CPU and memory available to the Ollama process, preventing it from exhausting host resources.

**Coverage: FULL**

---

### LLM05 — Supply Chain Vulnerabilities

**Risk Description:** Compromised model weights, libraries, packages, or pre-trained components introduce vulnerabilities or backdoors into AI-integrated systems.

**Yashigani Controls:**

Trivy is integrated into the CI/CD pipeline and scans all container images for known CVEs in base images and Python package dependencies. Images that fail the scan threshold are not promoted to production registries.

Base images are specified with SHA256 digest pins in Dockerfiles, preventing the "mutable tag" attack where a tag is silently updated to point to a malicious image.

Python dependencies are locked in pyproject.toml with hashed requirements, preventing dependency confusion attacks.

GitHub Actions workflows use CODEOWNERS to require security team review of changes to security-sensitive files (policy bundles, authentication code, inspection pipeline, Dockerfile).

**Residual Risk:** Yashigani cannot fully control the security of third-party inference backends (Anthropic, Gemini, Azure OpenAI). These are treated as semi-trusted services: CHS strips credentials before payloads are sent, but the inference result is trusted for classification purposes.

**Coverage: FULL** (for Yashigani's own supply chain; partial for third-party inference backends)

---

### LLM06 — Sensitive Information Disclosure

**Risk Description:** AI models reveal sensitive information through responses, training data memorization, or by processing and retaining confidential inputs.

**Yashigani Controls:**

The Credential Handle Service (CHS) is Yashigani's primary control for this risk. CHS inspects all request payloads before they are sent to any AI inspection backend and strips tokens matching credential patterns (API keys, passwords, JWTs, bearer tokens). The pattern library is configurable and includes a high-entropy string detector for credential-like values that don't match known formats.

CHS operates at the gateway layer and is independent of the inspection backend. Even if an operator disables LLM inspection, CHS continues to strip credentials from payloads.

Audit log records apply payload masking before writing; PII masking hooks allow operators to define field-level masking for domain-specific sensitive data types.

AES-256-GCM column encryption ensures that sensitive data at rest in PostgreSQL is encrypted with keys managed by the secrets backend. Column-level encryption means that a database credential breach does not immediately expose plaintext sensitive data.

**Residual Risk:** CHS relies on pattern matching and entropy analysis. Novel credential formats not matching known patterns may not be stripped. Operators handling highly sensitive proprietary credential formats should extend the CHS pattern registry.

**Coverage: FULL**

---

### LLM07 — Insecure Plugin and Tool Design (MCP Context)

**Risk Description:** AI plugins and tools (in this context, MCP tool servers) are designed without proper authorization controls, input validation, or rate limiting, allowing AI agents to abuse them in unintended ways.

**Yashigani Controls:**

Every MCP tool call proxied through Yashigani passes through OPA policy evaluation. The policy engine receives the full call context — agent identity, group membership, requested tool path, HTTP method, body size, and session context — and makes an explicit allow/deny decision before the call reaches the upstream MCP server.

Tool call authorization is defined in the OPA policy bundle, which maps tool paths to permitted agent identities and groups. Operators can express fine-grained tool-level access controls without modifying application code.

Agent registration via the agent registry, with token authentication, ensures that only registered agents can invoke tool calls. The registry includes per-agent active/inactive status and metadata for audit purposes.

**Residual Risk:** The security of the upstream MCP server's implementation is out of Yashigani's scope. Yashigani enforces authorization at the proxy boundary but cannot prevent MCP servers from having their own vulnerabilities once a request is legitimately forwarded.

**Coverage: FULL** (at the proxy boundary)

---

### LLM08 — Excessive Agency

**Risk Description:** AI agents are granted more permissions, capabilities, or autonomy than necessary, allowing them to take high-impact actions beyond their intended scope.

**Yashigani Controls:**

Agent bearer tokens must meet a minimum length of 64 characters, enforced at registration. This is a direct friction mechanism that prevents casual agent provisioning with low-entropy credentials.

RBAC group assignments define the set of tool paths each agent is permitted to call. OPA policy enforcement means that an agent cannot call a tool it is not explicitly authorized for, regardless of how it is instructed by an orchestrating LLM.

Every agent action generates an audit trail record including agent_id, session identifier, payload hash, OPA decision, inspection result, and upstream response code. This provides full forensic visibility into agent activity.

Anomaly detection identifies agents exhibiting unusual call patterns, including patterns associated with autonomous goal-seeking behavior (high-frequency calls, systematic path traversal, repeated retries on blocked paths).

Per-agent rate limits enforce a ceiling on the autonomous action rate of any single agent, regardless of how it is being orchestrated.

**Residual Risk:** Policy granularity depends on operator-defined RBAC group configurations. Operators who assign all agents to a permissive group reduce the protection this control provides.

**Coverage: FULL**

---

### LLM09 — Overreliance

**Risk Description:** Users and systems place excessive trust in AI outputs without appropriate validation, leading to decisions based on incorrect, fabricated, or manipulated AI-generated content.

**Yashigani Controls:**

The multi-backend fallback chain with fail-closed sentinel directly addresses overreliance on any single classification decision. The UNCERTAIN classification state routes payloads to progressively more capable backends rather than defaulting to allow.

Confidence thresholds are configurable per backend. A low-confidence CLEAN classification does not result in forwarding; the request is escalated to the next inspection stage.

The audit log records the classification decision, the confidence score, and the backend that made the decision for every inspected request. Operators can review audit records to identify patterns of low-confidence decisions and adjust thresholds accordingly.

The fail-closed sentinel ensures that a complete inspection pipeline failure results in a deny decision rather than a default allow.

**Residual Risk:** Human review of audit logs is not automated. Operators who do not regularly review audit records may miss patterns that warrant policy or threshold adjustments.

**Coverage: FULL**

---

### LLM10 — Model Theft

**Risk Description:** Adversaries extract proprietary model weights, training data, or model behavior through API abuse, side-channel attacks, or unauthorized access.

**Yashigani Controls:**

Ollama runs locally within the deployment environment. Model weights for the security classification model are never accessible via a network API; all inference happens in-process within the container network.

Inspection backend API keys (for Anthropic, Gemini, Azure OpenAI) are stored in the secrets backend and are never logged or exposed in responses. CHS ensures that the payloads sent to these backends do not contain operator credentials that could be used to access operator-specific fine-tuned models.

License verification for Yashigani itself uses ECDSA P-256 offline verification with no network call, preventing license-related network traffic that could reveal deployment information.

**Residual Risk:** Yashigani protects the inspection backends' API credentials and prevents unauthorized access to the Ollama local model. It does not protect the customer's own AI models that are deployed in the MCP servers behind the gateway — those models' security is the responsibility of the upstream MCP server operators.

**Coverage: PARTIAL** (protects Yashigani's inspection models and API credentials; customer model protection is out of scope)

---

### Agentic AI Specific Controls

Beyond the LLM Top 10, Yashigani implements controls specifically designed for the multi-agent, agentic AI operational context:

| Control | Implementation | Purpose |
|---|---|---|
| Agent identity verification | Bearer token, min-length 64, registry lookup | Ensures only registered agents can interact with MCP tools |
| Per-agent rate limiting | Redis fixed-window, independent of per-IP/session limits | Constrains autonomous agent action rates |
| Agent anomaly detection | Redis ZSET sliding window, repeated-small-calls pattern | Identifies agents exhibiting unexpected call patterns |
| Agent action audit trail | Every call logged: agent_id, session, payload hash, OPA decision, upstream response | Full forensic visibility into agent behavior |
| Agent lifecycle management | Active/inactive status in agent registry, admin UI | Enables rapid deactivation of compromised or misbehaving agents |
| SCIM v2 provisioning | RFC 7644-compliant agent provisioning from enterprise IdP | Integrates agent lifecycle with enterprise identity governance |
| Multi-tenant isolation | RLS per tenant, separate Redis DBs per tenant | Prevents agents in one tenant from affecting another |
| Fail-closed policy engine | OPA deny-on-error, no fallback-to-allow | Ensures policy failures cannot be exploited to gain access |
| Response chain tracing | W3C traceparent, X-Trace-Id, tail sampling, Jaeger | End-to-end trace visibility across agent action chains |

---

## Section 4: Compliance Summary Table

This table maps Yashigani's coverage across the three OWASP frameworks, noting which deployment tier provides each control.

**Tier definitions (v0.6.2):**
- **Community:** Apache 2.0 open-source, 20 agents, 50 end users, 10 admin seats, no SSO
- **Starter:** $1,200/yr, 100 agents, 250 end users, 25 admin seats, OIDC SSO only
- **Professional:** $4,800/yr, 500 agents, 1,000 end users, 50 admin seats, full SSO (SAML + OIDC + SCIM)
- **Professional Plus:** $14,400/yr, 2,000 agents, 10,000 end users, 200 admin seats, 5 orgs
- **Enterprise:** Unlimited on all dimensions, dedicated 24/7 support

| Control Domain | ASVS v5 Chapter | API Top 10 | LLM Top 10 | Community | Starter | Professional | Prof. Plus | Enterprise |
|---|---|---|---|---|---|---|---|---|
| Input validation and sanitization | V1, V5 | API1, API3 | LLM01 | Yes | Yes | Yes | Yes | Yes |
| Authentication (passwords, TOTP) | V2 | API2 | — | Yes | Yes | Yes | Yes | Yes |
| OIDC federation | V2 | API2 | — | — | Yes | Yes | Yes | Yes |
| SAML federation | V2 | API2 | — | — | — | Yes | Yes | Yes |
| Session management | V3 | API2 | — | Yes | Yes | Yes | Yes | Yes |
| OPA policy enforcement | V4 | API1, API5 | LLM07, LLM08 | Yes | Yes | Yes | Yes | Yes |
| Prompt injection detection (FastText) | V5 | API3 | LLM01 | Yes | Yes | Yes | Yes | Yes |
| Prompt injection detection (Ollama LLM) | V5 | API3 | LLM01 | Yes | Yes | Yes | Yes | Yes |
| Multi-backend inspection fallback | V5 | API3 | LLM01, LLM09 | — | Yes | Yes | Yes | Yes |
| Credential Handle Service (CHS) | V5, V8 | API3 | LLM06 | Yes | Yes | Yes | Yes | Yes |
| AES-256-GCM column encryption | V6 | API8 | LLM06 | Yes | Yes | Yes | Yes | Yes |
| Argon2id password hashing | V6 | API2 | — | Yes | Yes | Yes | Yes | Yes |
| ECDSA P-256 license signing | V6 | API8 | — | Yes | Yes | Yes | Yes | Yes |
| Generic error responses | V7 | API8 | — | Yes | Yes | Yes | Yes | Yes |
| Structured audit log (file) | V7 | API9 | LLM08 | Yes | Yes | Yes | Yes | Yes |
| Audit log to PostgreSQL | V7 | API9 | LLM08 | Yes | Yes | Yes | Yes | Yes |
| SIEM integration (Splunk/ES/Wazuh) | V7 | API9 | LLM08 | — | Yes | Yes | Yes | Yes |
| Row-level security (RLS) | V8 | API1 | — | Yes | Yes | Yes | Yes | Yes |
| PII masking in audit logs | V8 | API8 | LLM06 | Yes | Yes | Yes | Yes | Yes |
| TLS 1.2+ enforcement (Caddy) | V9 | API8 | — | Yes | Yes | Yes | Yes | Yes |
| HSTS headers | V9 | API8 | — | Yes | Yes | Yes | Yes | Yes |
| Seccomp allowlist | V10 | API8 | LLM05 | Yes | Yes | Yes | Yes | Yes |
| AppArmor profile | V10 | API8 | LLM05 | Yes | Yes | Yes | Yes | Yes |
| Read-only container filesystem | V10 | API8 | LLM05 | Yes | Yes | Yes | Yes | Yes |
| Per-IP rate limiting | V11 | API4 | LLM04 | Yes | Yes | Yes | Yes | Yes |
| Per-session rate limiting | V11 | API4 | LLM04 | Yes | Yes | Yes | Yes | Yes |
| Per-agent rate limiting | V11 | API4, API6 | LLM04, LLM08 | Yes | Yes | Yes | Yes | Yes |
| Per-endpoint rate limiting | V11 | API4, API6 | LLM04 | Yes | Yes | Yes | Yes | Yes |
| Anomaly detection (ZSET sliding window) | V11 | API6 | LLM08 | Yes | Yes | Yes | Yes | Yes |
| Audit log rotation and retention | V12 | — | — | Yes | Yes | Yes | Yes | Yes |
| pg_partman time-based partitioning | V12 | — | — | Yes | Yes | Yes | Yes | Yes |
| Hop-by-hop header stripping | V13 | API10 | — | Yes | Yes | Yes | Yes | Yes |
| Response cache (CLEAN-only) | V13 | API10 | — | Yes | Yes | Yes | Yes | Yes |
| OTEL tracing (Jaeger) | V13 | API9 | — | Yes | Yes | Yes | Yes | Yes |
| Docker Secrets integration | V6 | API8 | LLM10 | Yes | Yes | Yes | Yes | Yes |
| HashiCorp Vault integration | V6 | API8 | LLM10 | — | Yes | Yes | Yes | Yes |
| AWS/Azure/GCP Secrets Manager | V6 | API8 | LLM10 | — | Yes | Yes | Yes | Yes |
| Keeper secrets integration | V6 | API8 | LLM10 | — | Yes | Yes | Yes | Yes |
| SCIM v2 agent provisioning | V4 | API9 | LLM08 | — | — | Yes | Yes | Yes |
| Response inspection pipeline | V5 | API10 | LLM02 | — | Yes | Yes | Yes | Yes |
| Trivy CI scanning | V10 | API8 | LLM05 | Yes | Yes | Yes | Yes | Yes |
| JWT alg:none rejection | V2 | API2 | — | Yes | Yes | Yes | Yes | Yes |
| JWKS waterfall key rotation | V2 | API2 | — | Yes | Yes | Yes | Yes | Yes |
| Backoffice port isolation (8443) | V4 | API5 | — | Yes | Yes | Yes | Yes | Yes |
| Agent limit enforcement | V11 | API4 | LLM08 | 20 agents | 100 | 500 | 2,000 | Unlimited |
| End user limit enforcement | V11 | API4 | — | 50 | 250 | 1,000 | 10,000 | Unlimited |
| Admin seat limit enforcement | V11 | API4 | — | 10 | 25 | 50 | 200 | Unlimited |
| Multi-org isolation | V4 | API1 | — | 1 org | 1 org | 1 org | 5 orgs | Unlimited |
| Apache 2.0 open-source license | — | — | — | Yes | — | — | — | — |
| Contributor License Agreement (CLA) | — | — | — | Yes | — | — | — | — |
| Admin minimum count enforcement | V11 | API5 | — | Yes | Yes | Yes | Yes | Yes |
| Agent min-length enforcement (64 chars) | V11 | API6 | LLM08 | Yes | Yes | Yes | Yes | Yes |
| Multi-tenant Redis isolation | V8 | API1 | — | Yes | Yes | Yes | Yes | Yes |

---

## Section 5: Gap Analysis and Residual Risk

This section provides an honest assessment of areas where Yashigani's controls are incomplete, out of scope, or dependent on operator configuration. Security architects performing due diligence should review these gaps when assessing residual risk.

---

### Gap 1: Training Data Poisoning (LLM03)

**Nature of gap:** Training data poisoning occurs at model training time, before Yashigani is deployed. A runtime proxy cannot prevent an adversary from contaminating the training dataset of the fastText classification model or any third-party inspection backend.

**What Yashigani does:** Provides fastText model training scripts so operators can audit and control their own training data. Bundles the model in a digest-pinned container image to detect tampering at deployment time. The multi-backend fallback chain reduces the impact of any single model being compromised.

**What Yashigani does not do:** Validate the provenance or integrity of training data during model training. Monitor third-party inference backends (Anthropic, Gemini, Azure OpenAI) for model behavior changes.

**Recommended operator mitigations:** Treat model training as a sensitive supply chain operation. Apply data provenance controls to fastText training datasets. Monitor classification accuracy over time for unexpected degradation.

**ASVS Level:** N/A (training-time concern outside proxy scope)

---

### Gap 2: Physical Security Controls (V10 Partial)

**Nature of gap:** ASVS V10 at Level 3 includes requirements for physical access controls and tamper-evident hardware. Yashigani's container hardening (seccomp, AppArmor, non-root UID, read-only filesystem) addresses the software layer but cannot enforce physical security of the underlying host hardware.

**What Yashigani does:** Constrains container capabilities at the OS level, preventing privilege escalation even if an attacker gains access to the container runtime. Read-only filesystem limits persistence options for an attacker who achieves code execution.

**What Yashigani does not do:** Enforce physical access controls to the host system, provide hardware-level attestation (TPM), or implement secure enclave execution.

**Recommended operator mitigations:** Deploy on hardware with physical access controls appropriate to your threat model. For highest-assurance deployments, consider confidential computing platforms (AMD SEV, Intel TDX) for the Yashigani host.

**ASVS Level:** PARTIAL at L3 (full at L1 and L2)

---

### Gap 3: Client-Side Security

**Nature of gap:** Yashigani's controls terminate at the gateway boundary. Client applications that communicate with the gateway are outside Yashigani's enforcement scope. Client-side vulnerabilities (XSS in the agent client, credential storage in the agent application, insecure local storage) are not mitigated by the gateway.

**What Yashigani does:** Protects the server-side trust boundary rigorously. The backoffice admin panel implements client-security best practices (CSP, HttpOnly cookies, SameSite) for its own UI.

**What Yashigani does not do:** Enforce security controls on third-party agent client applications. Validate that agent clients protect their bearer tokens against local exfiltration.

**Recommended operator mitigations:** Apply client application security standards (OWASP MASVS for mobile agents, ASVS V3 for web-based agents) independently. Rotate agent tokens on a schedule and monitor for reuse from unexpected IP addresses.

---

### Gap 4: Model Weights Protection for Customer Models (LLM10 Partial)

**Nature of gap:** Yashigani protects the credentials used to access its own inspection backends (Anthropic, Gemini, Azure OpenAI API keys) and runs its own Ollama model locally. It does not protect the model weights or training data of the customer's own AI models deployed in the MCP servers behind the gateway.

**What Yashigani does:** Ensures that inspection backend API keys are stored in secrets backends and not logged. Runs local Ollama inference without sending content to cloud services. Enforces rate limits that make model extraction via API enumeration impractical.

**What Yashigani does not do:** Protect customer-owned model weights hosted on the upstream MCP servers. Detect model extraction attempts directed at customer models through the gateway (beyond rate limiting).

**Recommended operator mitigations:** Apply model IP protection controls at the MCP server layer. Use Yashigani's per-endpoint rate limiting to constrain query rates to model inference endpoints. Monitor audit logs for systematic query patterns associated with model extraction.

---

### Gap 5: Response Inspection Dependency

**Nature of gap:** Several controls — LLM02 (Insecure Output Handling), API10 (Unsafe Consumption of APIs) — depend on the YASHIGANI_INSPECT_RESPONSES configuration being enabled. This is not the default in all deployment configurations due to the latency and cost implications of inspecting all upstream responses.

**What Yashigani does:** Provides the response inspection infrastructure. Logs and audits all responses regardless of inspection setting. Serves only CLEAN-cached responses.

**What Yashigani does not do:** Guarantee that upstream responses are inspected unless the operator enables response inspection. The default configuration prioritizes performance; operators handling high-sensitivity data should explicitly enable response inspection.

**Recommended operator mitigations:** Enable YASHIGANI_INSPECT_RESPONSES in deployments where upstream MCP servers may return sensitive data or where the upstream server's security posture is uncertain. Consider selective response inspection (per-path policy) to balance security and performance.

---

### Gap 6: Internal Service Transport Encryption (V9.2.1 Partial)

**Nature of gap:** While external TLS is fully enforced via Caddy, internal service-to-service communication (gateway to OPA, gateway to PostgreSQL, gateway to Redis) relies on network isolation rather than mutual TLS for all paths. Some internal communication channels use TLS; others rely on container network policies.

**What Yashigani does:** Deploys all services within an isolated container network. Recommends TLS for PostgreSQL connections in production documentation. OPA communication can be configured with TLS.

**What Yashigani does not do:** Enforce mutual TLS on all internal service connections by default. Provide built-in certificate management for internal service mesh.

**Recommended operator mitigations:** For high-assurance deployments, configure PostgreSQL TLS client certificates, Redis TLS, and OPA HTTPS. Consider a service mesh (Istio, Linkerd) for automatic mTLS across all internal services.

---

### Gap 7: Credential Reset Flow

**Nature of gap:** ASVS V2.3.1 requires that credential reset uses a secure out-of-band mechanism. Yashigani provides secure session invalidation and password hashing infrastructure but delegates the credential reset flow to the operator's identity infrastructure.

**What Yashigani does:** Provides secure password hashing, session invalidation, and integration with external IdPs (SAML, OIDC) that typically include credential reset flows.

**What Yashigani does not do:** Implement a built-in email-based or out-of-band credential reset flow.

**Recommended operator mitigations:** Deploy Yashigani behind an IdP that implements OWASP-compliant credential reset. For deployments using local authentication only, implement an administrative credential reset procedure.

---

### Summary Gap Table

| Gap | Risk Level | Scope | Recommended Mitigation |
|---|---|---|---|
| LLM03 Training data poisoning | Medium | Out of scope (training-time) | Secure model training pipeline, monitor classification accuracy |
| Physical security (V10 L3) | Medium | Operator infrastructure | Physical access controls, consider confidential computing |
| Client-side security | Medium | Client application scope | Apply MASVS/ASVS to agent clients independently |
| Customer model weight protection (LLM10) | Medium | Upstream MCP server scope | Model-level IP controls at upstream; rate limiting via Yashigani |
| Response inspection dependency | Low-Medium | Configuration-dependent | Enable YASHIGANI_INSPECT_RESPONSES for high-sensitivity deployments |
| Internal mTLS | Low | Deployment configuration | Configure TLS for internal services; consider service mesh |
| Credential reset flow | Low | Identity infrastructure | Integrate with IdP that provides compliant reset flow |

---

### v0.7.0 / v0.7.1 Security Posture Changes

The following improvements from v0.7.0 and v0.7.1 directly affect OWASP compliance posture:

| Change | OWASP Relevance | Effect |
|--------|-----------------|--------|
| **ECDSA P-256 public key active** | ASVS V2, V14 | License tier enforcement is now fully active; Community tier limits enforced for the first time |
| **CIDR-based IP allowlisting per agent** (v0.7.0) | ASVS V4.1.3, API Security API5 | Provides defense-in-depth for agent token compromise; a stolen token from an unexpected IP is blocked and audited |
| **Path matching fix — IC-6** (v0.7.0) | ASVS V4.1, API Security API1 | Single-segment glob `*` was incorrectly matching across `/` boundaries, potentially allowing tools under sub-paths to be reached with policies intended for shallower paths. Fixed with `re.fullmatch` and `[^/]*` translation. |
| **Direct webhook alerting on credential exfil** (v0.7.1) | OWASP LLM01, LLM06 | Security teams receive real-time notification of credential exfiltration attempts; reduces mean time to awareness |
| **Automated partition monitoring + alert** (v0.7.0) | ASVS V7.1 | Audit log reliability is now monitored; missing partitions alert before data loss occurs |
| **OPA Policy Assistant** (v0.7.0) | ASVS V4.1 | Reduces risk of policy misconfiguration; all suggestions are schema-validated before admin review, and every apply/reject is audited |

---

## Appendix: Terminology and References

### Terminology

| Term | Definition |
|---|---|
| ASVS | OWASP Application Security Verification Standard |
| CHS | Credential Handle Service — Yashigani component that strips credentials from payloads before AI inspection |
| MCP | Model Context Protocol — protocol for AI agent-to-tool server communication |
| OPA | Open Policy Agent — embedded policy engine used for all authorization decisions |
| RBAC | Role-Based Access Control |
| RLS | Row-Level Security — PostgreSQL feature enforcing per-tenant data isolation |
| SCIM | System for Cross-domain Identity Management (RFC 7644) |
| SIEM | Security Information and Event Management |
| TOTP | Time-based One-Time Password (RFC 6238) |
| ZSET | Redis Sorted Set — data structure used for sliding window anomaly detection |

### References

| Document | Version | URL |
|---|---|---|
| OWASP Application Security Verification Standard | v5.0 | https://owasp.org/www-project-application-security-verification-standard/ |
| OWASP API Security Top 10 | 2023 | https://owasp.org/www-project-api-security/ |
| OWASP Top 10 for LLM Applications | 1.1 | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| OWASP Agentic AI Threats and Mitigations | 2025 | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| Open Policy Agent Documentation | Current | https://www.openpolicyagent.org/docs/ |
| NIST SP 800-63B | 3 | https://pages.nist.gov/800-63-3/sp800-63b.html |
| RFC 7517 (JSON Web Key) | — | https://datatracker.ietf.org/doc/html/rfc7517 |
| RFC 6238 (TOTP) | — | https://datatracker.ietf.org/doc/html/rfc6238 |
| RFC 7644 (SCIM 2.0) | — | https://datatracker.ietf.org/doc/html/rfc7644 |

---

*This document was prepared for Yashigani version as of 2026-03-27. Security control implementations should be verified against the current release. This document does not constitute a formal security certification and should be used as one input to a comprehensive security assessment.*
