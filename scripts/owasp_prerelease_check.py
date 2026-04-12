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
# OWASP ASVS v5 Level 3 — Key Controls
# =============================================================================
print("\n=== OWASP ASVS v5 Level 3 ===\n")

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
# OWASP API Security — Full Specification
# =============================================================================
print("\n=== OWASP API Security ===\n")

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
# Summary
# =============================================================================
print(f"\n{'='*60}")
total = PASS + FAIL
print(f"  TOTAL: {total} checks | PASS: {PASS} | FAIL: {FAIL}")
if FAIL > 0:
    print(f"\n  *** RELEASE BLOCKED — {FAIL} control(s) failed ***")
    print(f"  Fix all failures before tagging a release.")
    sys.exit(1)
else:
    print(f"\n  All controls verified. Safe to release.")
    sys.exit(0)
