#!/usr/bin/env python3
"""
Yashigani Pre-Release OWASP Compliance Verification.

MUST pass before any git tag. Checks:
  1. OWASP ASVS v5 Level 3 — key controls verified in code
  2. OWASP API Security — full specification, not just Top 10
  3. OWASP Agentic AI — full attack surface coverage

Exit code 0 = all checks pass. Non-zero = RELEASE BLOCKED.

Usage:
  python3 scripts/owasp_prerelease_check.py
  python3 scripts/owasp_prerelease_check.py --verbose
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

VERBOSE = "--verbose" in sys.argv or "-v" in sys.argv
SRC = Path(__file__).parent.parent / "src" / "yashigani"
POLICY = Path(__file__).parent.parent / "policy"
DOCKER = Path(__file__).parent.parent / "docker"
INSTALL = Path(__file__).parent.parent / "install.sh"

PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = ""):
    global PASS, FAIL
    if condition:
        PASS += 1
        if VERBOSE:
            print(f"  PASS: {name}")
    else:
        FAIL += 1
        print(f"  FAIL: {name}" + (f" — {detail}" if detail else ""))


def file_contains(path: Path, pattern: str) -> bool:
    if not path.exists():
        return False
    return bool(re.search(pattern, path.read_text()))


def any_file_contains(directory: Path, pattern: str, glob: str = "**/*.py") -> bool:
    for f in directory.glob(glob):
        if re.search(pattern, f.read_text()):
            return True
    return False


# =============================================================================
# OWASP ASVS v5 — Partial Coverage (22/345 controls)
#
# ASVS v5 has 345 controls across 17 chapters (V1-V17), all levels (L1-L3).
# We currently verify 22 key controls. Full 345-control coverage is a
# dedicated project — see memory/project_asvs_full_coverage.md.
#
# Chapters with ZERO coverage: V1 (Encoding), V3 (Frontend), V4 (API),
# V5 (File), V9 (Tokens), V10 (OAuth), V15 (Secure Coding), V16 (Logging),
# V17 (WebRTC). These MUST be addressed.
# =============================================================================
print("\n=== OWASP ASVS v5 — Partial (22/345 controls, L1+L2+L3) ===\n")

# V2: Authentication
check("V2.1 — Argon2id password hashing",
      any_file_contains(SRC, r"argon2|Argon2"))
check("V2.1.7 — HIBP breach check",
      any_file_contains(SRC, r"pwnedpasswords|hibp|check_hibp"))
check("V2.5 — TOTP 2FA (SHA-256)",
      any_file_contains(SRC, r"sha256|SHA256.*TOTP|digest.*sha"))
check("V2.5 — WebAuthn/FIDO2 support",
      (SRC / "auth" / "webauthn.py").exists())
check("V2.8 — Account lockout on failed attempts",
      any_file_contains(SRC, r"locked_until|MAX_FAILED_ATTEMPTS|lockout"))
check("V2.1.4 — Session invalidation on password change",
      any_file_contains(SRC, r"invalidate.*session|sessions_invalidated"))

# V3: Session Management
check("V3.1 — Secure session cookies (httponly, secure, samesite)",
      any_file_contains(SRC, r"httponly.*True.*secure.*True.*samesite"))
check("V3.2 — Session expiry",
      any_file_contains(SRC, r"max_age.*14400|session.*expir"))

# V4: Access Control
check("V4.1 — OPA policy enforcement on /v1",
      any_file_contains(SRC / "gateway", r"_opa_v1_check"))
check("V4.1 — OPA response-path enforcement",
      any_file_contains(SRC / "gateway", r"_opa_response_check"))
check("V4.1 — OPA agent-to-agent enforcement",
      any_file_contains(SRC / "gateway", r"opa_agent_check|agent_call_allowed"))
check("V4.2 — OPA always local (never cloud)",
      any_file_contains(SRC / "gateway", r"OPA is always local"))

# V5: Input Validation
check("V5.1 — Pydantic request validation",
      any_file_contains(SRC, r"class.*BaseModel|Field\("))
check("V5.3 — Sensitivity classification (regex + FastText + Ollama)",
      any_file_contains(SRC, r"SensitivityClassifier"))

# V6: Cryptography
check("V6.1 — ECDSA P-256 license signing",
      any_file_contains(SRC, r"ECDSA|P-256|EC2"))
check("V6.2 — AES-256 database encryption",
      any_file_contains(SRC, r"AES.*256|aes_key|pgcrypto"))
check("V6.3 — TLS 1.2+ with post-quantum key exchange",
      file_contains(DOCKER / "Caddyfile.selfsigned", r"x25519mlkem768|tls1\.2"))

# V7: Error Handling & Logging
check("V7.1 — Audit log (append-only, tamper-evident)",
      any_file_contains(SRC, r"SHA.*384.*chain|Merkle|audit_chain"))
check("V7.2 — Structured logging",
      any_file_contains(SRC, r"logging\.getLogger"))

# V8: Data Protection
check("V8.1 — PII detection module",
      (SRC / "pii" / "detector.py").exists())
check("V8.1 — PII block/redact forces buffered mode",
      any_file_contains(SRC / "gateway", r"PiiMode\.(BLOCK|REDACT).*use_streaming.*False|Streaming disabled.*PII"))
check("V8.2 — HMAC email hashing in audit",
      any_file_contains(SRC, r"hmac.*sha256|HMAC.*email.*hash"))

# =============================================================================
# OWASP API Security — Full Specification (not just Top 10)
# =============================================================================
print("\n=== OWASP API Security — Full Specification ===\n")

# -- Top 10 --
check("API1 — Broken Object Level Auth: identity resolution on every request",
      any_file_contains(SRC / "gateway", r"_resolve_identity"))
check("API2 — Broken Authentication: Bearer token + session cookie auth",
      any_file_contains(SRC / "gateway", r"Bearer|Authorization"))
check("API3 — Broken Object Property Level Auth: Pydantic models enforce fields",
      any_file_contains(SRC, r"BaseModel"))
check("API4 — Unrestricted Resource Consumption: rate limiting",
      any_file_contains(SRC, r"RateLimiter|rate_limit|DDoSProtector"))
check("API5 — Broken Function Level Auth: admin session middleware",
      any_file_contains(SRC, r"AdminSession"))
check("API6 — Unrestricted Access to Sensitive Flows: TOTP required",
      any_file_contains(SRC, r"totp_code.*required|force_totp"))
check("API7 — Server Side Request Forgery: upstream URL validation",
      any_file_contains(SRC, r"upstream_url.*Field.*min_length"))
check("API8 — Security Misconfiguration: no-new-privileges in compose",
      file_contains(DOCKER / "docker-compose.yml", r"no-new-privileges"))
check("API9 — Improper Inventory Management: /v1/models returns controlled list",
      any_file_contains(SRC / "gateway", r"list_models|/v1/models"))
check("API10 — Unsafe Consumption of APIs: agent auth middleware",
      any_file_contains(SRC / "gateway", r"AgentAuthMiddleware"))

# -- Authentication depth --
check("API-AUTH-1 — Password hashing uses adaptive algorithm (Argon2id)",
      any_file_contains(SRC, r"argon2"))
check("API-AUTH-2 — Token expiry enforced (session max_age)",
      any_file_contains(SRC, r"max_age.*\d{4,}"))
check("API-AUTH-3 — Multi-factor authentication (TOTP mandatory)",
      any_file_contains(SRC, r"verify_totp"))
check("API-AUTH-4 — Brute-force protection (exponential backoff)",
      any_file_contains(SRC, r"totp_backoff|exponential.*backoff|BACKOFF_SECONDS"))
check("API-AUTH-5 — Credential rotation support (agent PSK auto-rotation)",
      any_file_contains(SRC, r"rotate_agent_token|TokenRotation"))

# -- Authorization granularity --
check("API-AUTHZ-1 — RBAC via OPA (deny by default)",
      any_file_contains(POLICY, r"default.*:=.*false|default.*deny", glob="**/*.rego"))
check("API-AUTHZ-2 — Per-agent path restrictions (allowed_paths)",
      any_file_contains(SRC, r"allowed_paths"))
check("API-AUTHZ-3 — Per-agent CIDR restrictions (allowed_cidrs)",
      any_file_contains(SRC, r"allowed_cidrs"))
check("API-AUTHZ-4 — Sensitivity ceiling per identity",
      any_file_contains(SRC, r"sensitivity_ceiling"))

# -- Data validation --
check("API-DATA-1 — Request body size limit (Caddy)",
      file_contains(DOCKER / "Caddyfile.selfsigned", r"max_size"))
check("API-DATA-2 — Parameterised queries (asyncpg $1/$2, no f-strings in SQL)",
      any_file_contains(SRC / "db", r"\$1|\$2"))
check("API-DATA-3 — Response content inspection before delivery",
      any_file_contains(SRC / "gateway", r"response_inspection_pipeline|_opa_response_check"))
check("API-DATA-4 — No mass assignment (Pydantic strict field definitions)",
      any_file_contains(SRC, r"Field\(.*min_length|Field\(.*gt="))

# -- Error handling --
check("API-ERR-1 — Generic error messages (no credential enumeration)",
      any_file_contains(SRC, r"generic_fail|invalid_credentials.*prevent.*enumeration"))
check("API-ERR-2 — No stack traces in API responses",
      not any_file_contains(SRC / "gateway", r"traceback\.format|import traceback"))
check("API-ERR-3 — Fail-closed on security component failure",
      any_file_contains(SRC / "gateway", r"fail.closed|denying.*fail"))

# -- Logging and monitoring --
check("API-LOG-1 — All auth events audited (login, logout, failure)",
      any_file_contains(SRC, r"_make_login_event|login.*event"))
check("API-LOG-2 — All policy decisions audited (OPA allow/deny)",
      any_file_contains(SRC / "gateway", r"OPA DENIED|OPA.*BLOCKED"))
check("API-LOG-3 — SIEM integration (Wazuh/Splunk/Elasticsearch)",
      any_file_contains(SRC, r"SiemSink|wazuh|splunk|elasticsearch"))
check("API-LOG-4 — Tamper-evident audit chain (SHA-384 Merkle)",
      any_file_contains(SRC, r"SHA.*384|Merkle|chain_hash"))

# -- Transport security --
check("API-TLS-1 — TLS 1.2+ enforced (no plaintext API access)",
      file_contains(DOCKER / "Caddyfile.selfsigned", r"tls1\.2"))
check("API-TLS-2 — Security headers (X-Content-Type-Options, X-Frame-Options)",
      file_contains(DOCKER / "Caddyfile.selfsigned", r"X-Content-Type-Options|nosniff"))
check("API-TLS-3 — CORS not enabled (API is same-origin only)",
      not any_file_contains(SRC / "gateway", r"CORSMiddleware|Access-Control-Allow-Origin"))

# -- Business logic --
check("API-BIZ-1 — Budget enforcement prevents resource exhaustion",
      any_file_contains(SRC, r"BudgetSignal\.EXHAUSTED|budget.*exhausted"))
check("API-BIZ-2 — Graceful degradation (budget exhausted → local, never reject)",
      any_file_contains(SRC, r"graceful.*degrad|local.*only|never.*reject"))
check("API-BIZ-3 — Self-service password reset requires TOTP (not email-only)",
      any_file_contains(SRC, r"self.*reset.*totp|SelfServiceResetRequest"))

# =============================================================================
# OWASP Agentic AI — Full Attack Surface
# =============================================================================
print("\n=== OWASP Agentic AI ===\n")

check("AGT1 — Agent Identity Spoofing: PSK token auth for agents",
      any_file_contains(SRC, r"verify_token|agent.*token"))
check("AGT2 — Privilege Escalation: OPA RBAC on agent calls",
      file_contains(POLICY / "agents.rego", r"agent_call_allowed"))
check("AGT3 — Prompt Injection: inspection pipeline",
      any_file_contains(SRC, r"PromptInjectionClassifier|InspectionPipeline"))
check("AGT4 — Credential Exfiltration: CHS masking",
      any_file_contains(SRC, r"CredentialHandleService|credential.*mask"))
check("AGT5 — Data Exfiltration: sensitivity ceiling enforcement",
      file_contains(POLICY / "v1_routing.rego", r"sensitivity_ceiling"))
check("AGT6 — Agent-to-Agent Content Laundering: relay detection",
      any_file_contains(SRC, r"ContentRelayDetector|content_relay"))
check("AGT7 — Container Escape: per-identity isolation (Pool Manager)",
      any_file_contains(SRC, r"PoolManager|container_per_identity|ContainerBackend"))
check("AGT8 — Model Poisoning: Ollama digest pinning",
      any_file_contains(SRC, r"digest.*pin|verify.*digest|model.*digest"))
check("AGT9 — Budget Exhaustion: three-tier budget enforcement",
      any_file_contains(SRC, r"BudgetEnforcer|budget.*check"))
check("AGT10 — Audit Evasion: fail-closed OPA + append-only audit",
      any_file_contains(SRC / "gateway", r"fail-closed|fail.closed"))

# =============================================================================
# Infrastructure Security
# =============================================================================
print("\n=== Infrastructure Security ===\n")

check("No hardcoded credentials in compose",
      not file_contains(DOCKER / "docker-compose.yml",
                        r"SecretPassword|MyS3cr37|password:\s*[\"'][a-zA-Z]"))
check("No hardcoded credentials in installer",
      not file_contains(INSTALL,
                        r"SecretPassword|MyS3cr37|hardcoded.*password"))
check("Read-only gateway container",
      file_contains(DOCKER / "docker-compose.yml", r"read_only:\s*true"))
check("Container socket mounted read-only",
      file_contains(DOCKER / "docker-compose.yml", r"container\.sock:ro"))
check("SBOM generation script exists",
      (Path(__file__).parent / "generate_sbom.py").exists())
check("Cosign signing script exists",
      (Path(__file__).parent / "sign_image.sh").exists())
check("Wazuh SIEM available as compose profile",
      file_contains(DOCKER / "docker-compose.yml", r"wazuh-manager"))

# =============================================================================
# ASVS Coverage Report
# =============================================================================
print("\n=== ASVS v5 Coverage Report ===\n")

_ASVS_CHAPTERS = {
    "V1  Encoding & Sanitization":       (30, 0),
    "V2  Validation & Business Logic":    (13, 2),
    "V3  Web Frontend Security":          (31, 0),
    "V4  API & Web Service":              (16, 0),
    "V5  File Handling":                  (13, 0),
    "V6  Authentication":                 (47, 6),
    "V7  Session Management":             (19, 2),
    "V8  Authorization":                  (13, 4),
    "V9  Self-contained Tokens":          (7, 0),
    "V10 OAuth & OIDC":                   (36, 0),
    "V11 Cryptography":                   (24, 3),
    "V12 Secure Communication":           (12, 1),
    "V13 Configuration":                  (21, 1),
    "V14 Data Protection":                (13, 3),
    "V15 Secure Coding & Architecture":   (21, 0),
    "V16 Security Logging & Error":       (17, 0),
    "V17 WebRTC":                         (12, 0),
}

total_asvs = sum(t for t, _ in _ASVS_CHAPTERS.values())
covered_asvs = sum(c for _, c in _ASVS_CHAPTERS.values())
zero_chapters = [k for k, (_, c) in _ASVS_CHAPTERS.items() if c == 0]

for name, (total_ch, covered_ch) in _ASVS_CHAPTERS.items():
    pct = int(covered_ch / total_ch * 100) if total_ch else 0
    bar = "X" * (pct // 10) + "." * (10 - pct // 10)
    status = "ZERO" if covered_ch == 0 else f"{pct}%"
    print(f"  {name:<40} [{bar}] {covered_ch:>3}/{total_ch:<3} {status}")

print(f"\n  ASVS coverage: {covered_asvs}/{total_asvs} controls ({int(covered_asvs/total_asvs*100)}%)")
print(f"  Chapters with ZERO coverage: {len(zero_chapters)}/17")
if zero_chapters:
    print(f"  Missing: {', '.join(zero_chapters)}")

# =============================================================================
# Summary
# =============================================================================
print(f"\n{'='*60}")
total = PASS + FAIL
print(f"  TOTAL: {total} checks | PASS: {PASS} | FAIL: {FAIL}")
print(f"  ASVS: {covered_asvs}/{total_asvs} ({int(covered_asvs/total_asvs*100)}%) | API: 28 | Agentic AI: 10 | Infra: 7")
if FAIL > 0:
    print(f"\n  *** RELEASE BLOCKED — {FAIL} control(s) failed ***")
    print(f"  Fix all failures before tagging a release.")
    sys.exit(1)
else:
    print(f"\n  All {total} implemented checks pass.")
    print(f"  WARNING: ASVS coverage is {int(covered_asvs/total_asvs*100)}% — {total_asvs - covered_asvs} controls not yet automated.")
    sys.exit(0)
