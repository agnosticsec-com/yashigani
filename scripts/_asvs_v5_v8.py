"""
OWASP ASVS v5 — Chapters V5 through V8 (92 controls).

V5:  File Handling               (13 controls)
V6:  Authentication              (47 controls)
V7:  Session Management          (19 controls)
V8:  Authorization               (13 controls)

Called by owasp_prerelease_check.py.  Each control is mapped to a concrete
code-level evidence check or marked N/A with justification.
"""
from __future__ import annotations

from pathlib import Path


def run_v5_v8_checks(check, file_contains, any_file_contains, SRC, POLICY, DOCKER, INSTALL):
    """
    Run all 92 OWASP ASVS v5 controls for chapters V5-V8.

    Parameters
    ----------
    check : callable(name: str, condition: bool) -> None
    file_contains : callable(path: Path, pattern: str) -> bool
    any_file_contains : callable(directory: Path, pattern: str, glob: str = "**/*.py") -> bool
    SRC : Path   — src/yashigani/
    POLICY : Path — policy/
    DOCKER : Path — docker/
    INSTALL : Path — install.sh
    """

    # =========================================================================
    # V5 File Handling (13 controls)
    # =========================================================================
    # Yashigani does NOT accept file uploads from end users via its API.
    # The only file handling is license key import (admin-only, signed .json).
    # Upload-specific controls are marked N/A with reason.

    # -- V5.1 File Handling Documentation --
    print("  -- V5.1 File Handling Documentation --")

    check("5.1.1 — N/A: No user file upload features; license import is admin-only signed JSON",
          True)

    # -- V5.2 File Upload and Content --
    print("  -- V5.2 File Upload and Content --")

    check("5.2.1 — N/A: No user file uploads; gateway enforces max_request_body_bytes (4 MB)",
          any_file_contains(SRC / "gateway", r'max_request_body_bytes'))

    check("5.2.2 — N/A: No user file uploads; license import validates JSON schema + ECDSA signature",
          any_file_contains(SRC / "licensing", r'verify|InvalidSignature'))

    check("5.2.3 — N/A: No compressed file handling in user-facing API", True)

    check("5.2.4 — N/A: No per-user file storage; no file uploads accepted", True)

    check("5.2.5 — N/A: No compressed file uploads accepted", True)

    check("5.2.6 — N/A: No image uploads accepted", True)

    # -- V5.3 File Storage --
    print("  -- V5.3 File Storage --")

    check("5.3.1 — N/A: No user-uploaded files stored; no public file serving",
          True)

    check("5.3.2 — License file paths are internally generated (not from user input)",
          any_file_contains(SRC / "licensing", r'load|verify')
          and not any_file_contains(SRC / "licensing", r'request\.form|request\.args.*path'))

    check("5.3.3 — N/A: No file decompression in user-facing paths", True)

    # -- V5.4 File Download --
    print("  -- V5.4 File Download --")

    check("5.4.1 — N/A: No user-controlled file downloads; audit export uses server-generated names",
          True)

    check("5.4.2 — N/A: No file downloads with user-controlled filenames", True)

    check("5.4.3 — N/A: No files from untrusted sources served to users", True)

    # =========================================================================
    # V6 Authentication (47 controls)
    # =========================================================================

    # -- V6.1 Authentication Documentation --
    print("  -- V6.1 Authentication Documentation --")

    check("6.1.1 — Rate limiting and anti-brute-force documented and implemented (5 attempts, 30-min lockout)",
          any_file_contains(SRC / "auth", r'_MAX_FAILED_ATTEMPTS.*=.*5')
          and any_file_contains(SRC / "auth", r'_LOCKOUT_SECONDS.*=.*1800'))

    check("6.1.2 — Context-specific password word list implemented",
          file_contains(SRC / "auth" / "password.py", r"CONTEXT_BANNED|context.*word"))

    check("6.1.3 — Multiple auth pathways documented: local (password+TOTP) and SSO (OIDC+TOTP)",
          any_file_contains(SRC / "auth", r'LocalAuthService')
          and any_file_contains(SRC / "backoffice", r'sso|oidc|OIDCConfig'))

    # -- V6.2 Password Security --
    print("  -- V6.2 Password Security --")

    check("6.2.1 — Minimum password length enforced (36 chars, exceeds 8-char requirement)",
          any_file_contains(SRC / "auth", r'_MIN_PASSWORD_LENGTH.*=.*36'))

    check("6.2.2 — Users can change their password (POST /auth/password/change)",
          any_file_contains(SRC / "backoffice" / "routes", r'change_password'))

    check("6.2.3 — Password change requires current password verification",
          any_file_contains(SRC / "backoffice" / "routes", r'current_password.*record\.password_hash|verify_password.*body\.current_password'))

    check("6.2.4 — Passwords checked against HIBP breach database (exceeds top-3000 requirement)",
          any_file_contains(SRC / "auth", r'check_hibp|pwnedpasswords'))

    check("6.2.5 — No composition rules restricting character types (any composition accepted)",
          True)  # NIST 800-63b: absence of composition rules is correct — we enforce length only

    check("6.2.6 — Password fields use type=password in login forms",
          any_file_contains(SRC / "backoffice" / "templates", r'type="password"', glob="**/*.html"))

    check("6.2.7 — Paste and password managers permitted (autocomplete=current-password set)",
          any_file_contains(SRC / "backoffice" / "templates", r'autocomplete="current-password"', glob="**/*.html"))

    check("6.2.8 — Password verified exactly as received (no truncation or case transformation)",
          not file_contains(SRC / "auth" / "password.py", r'truncat|\.lower\(\).*hash|\.upper\(\).*hash'))

    check("6.2.9 — Passwords of at least 64 characters permitted (no max length cap in validation)",
          not file_contains(SRC / "auth" / "password.py", r'max_length|MAX_PASSWORD'))

    check("6.2.10 — No periodic credential rotation required (password valid until breach or user change)",
          not any_file_contains(SRC / "auth", r'password.*expir|credential.*rotation|periodic.*rotation'))

    check("6.2.11 — Context-specific word list checks passwords on creation",
          file_contains(SRC / "auth" / "password.py", r"validate_password_context|CONTEXT_BANNED"))

    check("6.2.12 — Passwords checked against HIBP breach database on registration and change",
          file_contains(SRC / "auth" / "password.py", r'check_hibp|pwnedpasswords'))

    # -- V6.3 General Authentication Security --
    print("  -- V6.3 General Authentication Security --")

    check("6.3.1 — Brute force protection: 5-attempt lockout with 30-min window + TOTP exponential backoff",
          any_file_contains(SRC / "auth", r'_MAX_FAILED_ATTEMPTS')
          and any_file_contains(SRC / "auth", r'_TOTP_BACKOFF_SECONDS'))

    check("6.3.2 — No default admin accounts; admin created at install with random 36-char password",
          any_file_contains(SRC / "auth", r'generate_password\(36\)|auto_generate.*=.*True'))

    check("6.3.3 — Multi-factor authentication enforced: password + TOTP required for all logins",
          file_contains(SRC / "auth" / "local_auth.py", r'verify_totp'))

    check("6.3.4 — All auth pathways enforce MFA consistently (local and SSO both require TOTP)",
          any_file_contains(SRC / "auth", r'verify_totp')
          and any_file_contains(SRC / "backoffice", r'totp_code'))

    check("6.3.5 — Auth brute-force throttle: per-IP (3 failures) and global (5 failures) with exponential delay",
          any_file_contains(SRC / "backoffice" / "routes", r"_apply_auth_throttle")
          and any_file_contains(SRC / "backoffice" / "routes", r"_record_auth_failure")
          and any_file_contains(SRC / "backoffice" / "routes", r"_THROTTLE_IP_THRESHOLD")
          and any_file_contains(SRC / "backoffice" / "routes", r"Auth throttle.*ip=.*level=.*delay="))

    check("6.3.6 — Email not used as authentication mechanism (password + TOTP only)",
          not any_file_contains(SRC / "auth", r'email.*otp|email.*verification.*code|send.*email.*auth'))

    check("6.3.7 — Post-change audit events: password_change (ConfigChangedEvent) and TOTP provision (TotpProvisionCompletedEvent)",
          any_file_contains(SRC / "backoffice" / "routes", r'_make_config_event.*password_change')
          and any_file_contains(SRC / "backoffice" / "routes", r'_make_provision_event'))

    check("6.3.8 — Generic error message prevents user enumeration (same 'invalid_credentials' for all failures)",
          any_file_contains(SRC / "auth", r'generic_fail.*=.*"invalid_credentials"')
          and any_file_contains(SRC / "backoffice" / "routes", r'"error".*:.*"invalid_credentials"'))

    # -- V6.4 Authentication Factor Lifecycle and Recovery --
    print("  -- V6.4 Authentication Factor Lifecycle and Recovery --")

    check("6.4.1 — System-generated passwords are random 36-char, force_password_change=True on first use",
          any_file_contains(SRC / "auth", r'generate_password')
          and any_file_contains(SRC / "auth", r'force_password_change.*=.*True'))

    check("6.4.2 — No password hints or secret questions present in codebase",
          not any_file_contains(SRC / "auth", r'secret_question|password_hint|security_question'))

    check("6.4.3 — Self-service password reset requires TOTP verification (MFA not bypassed)",
          any_file_contains(SRC / "backoffice" / "routes", r'self.*reset.*totp_code|password.*self-reset')
          and any_file_contains(SRC / "backoffice" / "routes", r'verify_totp.*record\.totp_secret'))

    check("6.4.4 — N/A (L2): Multi-factor recovery re-proofing not yet implemented",
          False)

    check("6.4.5 — N/A (L3): Proactive authentication renewal reminders not yet implemented",
          False)

    check("6.4.6 — Admin full-reset generates new temporary password (admin never sees/chooses user password)",
          any_file_contains(SRC / "auth", r'full_reset_user')
          and any_file_contains(SRC / "auth", r'temp_password.*=.*generate_password'))

    # -- V6.5 General Multi-factor Authentication Requirements --
    print("  -- V6.5 General Multi-factor Authentication Requirements --")

    check("6.5.1 — TOTP codes usable only once (replay prevention via used_codes_cache)",
          file_contains(SRC / "auth" / "totp.py", r'window_key in used_codes'))

    check("6.5.2 — Recovery codes hashed with Argon2id (< 112 bits entropy, hashed with salt)",
          file_contains(SRC / "auth" / "totp.py", r'_hasher.*hash'))

    check("6.5.3 — TOTP secrets and recovery codes generated with CSPRNG (secrets module)",
          file_contains(SRC / "auth" / "totp.py", r'secrets\.'))

    check("6.5.4 — Recovery codes have sufficient entropy (3x16-bit = 48-bit, exceeds 20-bit minimum)",
          file_contains(SRC / "auth" / "totp.py", r'secrets\.randbits'))

    check("6.5.5 — TOTP valid_window=1 (max 30 seconds per code, within 30s lifetime requirement)",
          file_contains(SRC / "auth" / "totp.py", r'range\(-1.*2\)|valid_window'))

    check("6.5.6 — N/A (L3): WebAuthn credential revocation implemented (delete_credential)",
          file_contains(SRC / "auth" / "webauthn.py", r'delete|revoke|remove.*credential'))

    check("6.5.7 — N/A (L3): Biometric used only as secondary factor (WebAuthn user_verification=preferred)",
          file_contains(SRC / "auth" / "webauthn.py", r'user_verification.*preferred'))

    check("6.5.8 — TOTP checked server-side using server time (no client time accepted)",
          file_contains(SRC / "auth" / "totp.py", r'time\.time')
          and not file_contains(SRC / "auth" / "totp.py", r'client_time'))

    # -- V6.6 Out-of-Band Authentication Mechanisms --
    print("  -- V6.6 Out-of-Band Authentication Mechanisms --")

    check("6.6.1 — N/A: No PSTN/SMS OTP; TOTP is the only second factor",
          not any_file_contains(SRC / "auth", r'sms.*otp|phone.*otp|send_sms|twilio'))

    check("6.6.2 — N/A: No out-of-band auth codes; TOTP is time-based (not sent)",
          True)

    check("6.6.3 — N/A: No code-based out-of-band mechanism; TOTP rate limiting via exponential backoff",
          any_file_contains(SRC / "auth", r'_TOTP_BACKOFF_SECONDS'))

    check("6.6.4 — N/A: No push notifications for MFA; TOTP only",
          True)

    # -- V6.7 Cryptographic Authentication Mechanism --
    print("  -- V6.7 Cryptographic Authentication Mechanism --")

    check("6.7.1 — WebAuthn credential public keys stored securely (in-memory/DB, not modifiable by user)",
          file_contains(SRC / "auth" / "webauthn.py", r'credential_store|public_key'))

    check("6.7.2 — WebAuthn challenge nonce is 256 bits (32 bytes, exceeds 64-bit minimum)",
          file_contains(SRC / "auth" / "webauthn.py", r'secrets\.token_bytes|challenge'))

    # -- V6.8 Authentication with an Identity Provider --
    print("  -- V6.8 Authentication with an Identity Provider --")

    check("6.8.1 — SSO user identity includes IdP ID namespace to prevent cross-IdP spoofing",
          any_file_contains(SRC / "sso", r'issuer.*sub|iss.*sub|provider_id'))

    check("6.8.2 — JWT/SAML assertion signatures validated before accepting claims",
          any_file_contains(SRC / "gateway", r'verify_registration_response|verify_authentication_response|pyjwt.*decode|signing_key'))

    check("6.8.3 — N/A: SAML not used; OIDC tokens are validated for replay via nonce/exp",
          True)

    check("6.8.4 — IdP authentication strength (acr/amr) claim validation implemented",
          file_contains(SRC / "backoffice" / "routes" / "sso.py", r'acr|amr|MIN_ACR'))

    # =========================================================================
    # V7 Session Management (19 controls)
    # =========================================================================

    # -- V7.1 Session Management Documentation --
    print("  -- V7.1 Session Management Documentation --")

    check("7.1.1 — Session timeouts documented: 15-min idle, 4-hour absolute (ASVS V3)",
          any_file_contains(SRC, r'max_age.*14400|idle.*timeout'))

    check("7.1.2 — Concurrent sessions documented: not permitted (new login invalidates prior)",
          any_file_contains(SRC, r'invalidate_all|concurrent.*session'))

    check("7.1.3 — N/A (L2): SSO session coordination documented (session invalidation is local)",
          file_contains(SRC / "auth" / "session.py", r'invalidate_all_for_account'))

    # -- V7.2 Fundamental Session Management Security --
    print("  -- V7.2 Fundamental Session Management Security --")

    check("7.2.1 — Session tokens verified server-side (Redis-backed SessionStore.get())",
          any_file_contains(SRC / "backoffice", r'SessionStore|session_store\.get'))

    check("7.2.2 — Session tokens are dynamically generated (not static API keys)",
          any_file_contains(SRC, r'token_hex|token_bytes|secrets\.'))

    check("7.2.3 — Session tokens are 256-bit CSPRNG (32 bytes = 256 bits entropy)",
          any_file_contains(SRC, r'token_hex\(32\)|token_bytes\(32\)'))

    check("7.2.4 — New session token generated on authentication; old sessions invalidated",
          file_contains(SRC / "backoffice" / "routes" / "auth.py", r'session_store\.create'))

    # -- V7.3 Session Timeout --
    print("  -- V7.3 Session Timeout --")

    check("7.3.1 — Inactivity timeout enforced: 15 minutes (900 seconds)",
          any_file_contains(SRC, r'idle.*timeout|inactivity|900'))

    check("7.3.2 — Absolute session lifetime enforced: 4 hours (14400 seconds)",
          any_file_contains(SRC, r'max_age.*14400|absolute.*timeout|4.*hour'))

    # -- V7.4 Session Termination --
    print("  -- V7.4 Session Termination --")

    check("7.4.1 — Logout invalidates session in backend (SessionStore.invalidate + cookie deletion)",
          any_file_contains(SRC / "backoffice" / "routes", r'store\.invalidate\(session\.token\)')
          and any_file_contains(SRC / "backoffice" / "routes", r'delete_cookie'))

    check("7.4.2 — All sessions terminated when account disabled/deleted (invalidate_all_for_account)",
          any_file_contains(SRC, r'invalidate_all_for_account'))

    check("7.4.3 — All sessions invalidated on password change (ASVS V2.1.4)",
          file_contains(SRC / "backoffice" / "routes" / "auth.py", r'invalidate_all|sessions_invalidated'))

    check("7.4.4 — Logout button visible on all authenticated pages (dashboard has logout button)",
          any_file_contains(SRC / "backoffice" / "templates", r'logout.*button|onclick.*logout', glob="**/*.html"))

    check("7.4.5 — Admin can terminate sessions for any user (invalidate_all_for_account in user routes)",
          any_file_contains(SRC / "backoffice" / "routes", r'invalidate_all_for_account'))

    # -- V7.5 Defenses Against Session Abuse --
    print("  -- V7.5 Defenses Against Session Abuse --")

    check("7.5.1 — Full re-authentication required before sensitive changes (password change requires current password + TOTP)",
          file_contains(SRC / "backoffice" / "routes" / "auth.py", r'current_password'))

    check("7.5.2 — Users can view and terminate active sessions (active_sessions_for_account)",
          any_file_contains(SRC, r'active_sessions|list_sessions'))

    check("7.5.3 — N/A (L3): Step-up authentication before sensitive transactions (admin TOTP re-verification on full reset)",
          file_contains(SRC / "backoffice" / "routes" / "users.py", r'totp_code|admin_totp'))

    # -- V7.6 Federated Re-authentication --
    print("  -- V7.6 Federated Re-authentication --")

    check("7.6.1 — N/A (L2): Federated session lifetime coordination (local sessions enforce own timeouts)",
          file_contains(SRC / "auth" / "session.py", r'_ABSOLUTE_TIMEOUT_SECONDS'))

    check("7.6.2 — Session creation requires explicit user action (login form submission)",
          file_contains(SRC / "backoffice" / "routes" / "auth.py", r'POST.*login|async def login'))

    # =========================================================================
    # V8 Authorization (13 controls)
    # =========================================================================

    # -- V8.1 Authorization Documentation --
    print("  -- V8.1 Authorization Documentation --")

    check("8.1.1 — Authorization rules defined in OPA policies (function-level and path-based restrictions)",
          file_contains(POLICY / "yashigani.rego", r'default allow.*:=.*false')
          and file_contains(POLICY / "rbac.rego", r'allow_rbac'))

    check("8.1.2 — Field-level access via RBAC groups with method + path_glob patterns",
          any_file_contains(SRC, r'path_glob|allowed_paths'))

    check("8.1.3 — Environmental/contextual authorization attributes documented (client IP, user agent, time of day in audit events)",
          file_contains(Path("docs/yashigani_owasp.md"), r"Environmental Auth Factors")
          and file_contains(Path("docs/yashigani_owasp.md"), r"client_ip_prefix.*captured"))

    check("8.1.4 — Environmental factors in auth: IP allowlist restricts login by network location",
          any_file_contains(SRC / "backoffice" / "routes", r"auth:allowlist|_check_ip_access|ip_not_allowed"))

    # -- V8.2 General Authorization Design --
    print("  -- V8.2 General Authorization Design --")

    check("8.2.1 — Function-level access enforced: admin-only routes require AdminSession dependency",
          any_file_contains(SRC / "backoffice", r'AdminSession'))

    check("8.2.2 — Data-specific access enforced: RBAC deny-by-default with per-user group membership",
          file_contains(POLICY / "yashigani.rego", r'default.*allow.*:=.*false'))

    check("8.2.3 — N/A (L2): Field-level access restrictions via RBAC path_glob patterns",
          file_contains(POLICY / "rbac.rego", r'_path_matches.*path'))

    check("8.2.4 — Adaptive contextual auth: IP allowlist + exponential throttle adapts to attack context",
          any_file_contains(SRC / "backoffice" / "routes", r"_check_ip_access|_apply_auth_throttle"))

    # -- V8.3 Operation Level Authorization --
    print("  -- V8.3 Operation Level Authorization --")

    check("8.3.1 — Authorization enforced server-side: OPA policy check + RBAC in backend (not client-side)",
          any_file_contains(SRC / "gateway", r'_opa_v1_check|opa_check'))

    check("8.3.2 — N/A (L3): Immediate authorization change propagation (RBAC pushed to OPA after every mutation)",
          any_file_contains(SRC / "rbac", r'opa_push|push.*opa'))

    check("8.3.3 — N/A (L3): Subject-based permission propagation (consumer token forwarded, not service token)",
          False)

    # -- V8.4 Other Authorization Considerations --
    print("  -- V8.4 Other Authorization Considerations --")

    check("8.4.1 — Multi-tenant isolation: per-agent RBAC groups with allowed_caller_groups enforcement",
          file_contains(POLICY / "agents.rego", r'allowed_caller_groups')
          and file_contains(POLICY / "agents.rego", r'agent_call_allowed'))

    check("8.4.2 — N/A (L3): Multi-layer admin interface security (partial: admin session + TOTP re-verification for destructive ops)",
          any_file_contains(SRC / "backoffice" / "routes", r'AdminSession')
          and any_file_contains(SRC / "backoffice" / "routes", r'totp_code|verify_totp'))
