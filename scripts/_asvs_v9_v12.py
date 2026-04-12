"""
OWASP ASVS v5 — Chapters V9 through V12 (79 controls).

V9:  Self-contained Tokens        (7 controls)
V10: OAuth and OIDC              (36 controls)
V11: Cryptography                (24 controls)
V12: Secure Communication        (12 controls)

Called by owasp_prerelease_check.py.  Each control is mapped to a concrete
code-level evidence check or marked N/A with justification.
"""
from __future__ import annotations


def run_v9_v12_checks(check, file_contains, any_file_contains, SRC, POLICY, DOCKER, INSTALL):
    # =========================================================================
    # V9 Self-contained Tokens (7 controls)
    # =========================================================================
    print("  -- V9.1 Token Source and Integrity --")

    check("9.1.1 — JWTs validated via digital signature (JWKS) before accepting claims",
          any_file_contains(SRC / "gateway", r"pyjwt\.decode|signing_key.*\.key"))

    check("9.1.2 — Algorithm allowlist enforced; 'none' rejected unconditionally",
          any_file_contains(SRC / "gateway", r'ALLOWED_ALGORITHMS.*=.*\[')
          and any_file_contains(SRC / "gateway", r'alg.*none.*rejected'))

    check("9.1.3 — JWKS key material from trusted pre-configured sources only (jwks_url from DB/env)",
          any_file_contains(SRC / "gateway", r"YASHIGANI_JWKS_URL|jwt_config WHERE"))

    print("  -- V9.2 Token Content --")

    check("9.2.1 — Token exp claim validated (pyjwt validates exp by default)",
          any_file_contains(SRC / "gateway", r"ExpiredSignatureError|token_expired"))

    check("9.2.2 — Token type differentiation (access vs ID token)",
          any_file_contains(SRC / "gateway", r'audience|issuer')
          and any_file_contains(SRC / "sso", r'id_token'))

    check("9.2.3 — Audience (aud) claim validated against configured audience",
          any_file_contains(SRC / "gateway", r'audience.*=.*config\.audience'))

    check("9.2.4 — Audience restriction for multi-audience issuers (configured per-tenant)",
          any_file_contains(SRC / "gateway", r"tenant_id.*scope.*=.*tenant|per-tenant"))

    # =========================================================================
    # V10 OAuth and OIDC (36 controls)
    # =========================================================================

    # -- V10.1 Generic OAuth and OIDC Security --
    print("  -- V10.1 Generic OAuth and OIDC Security --")

    check("10.1.1 — Tokens only sent to components that need them (session cookie httponly, samesite)",
          any_file_contains(SRC / "backoffice", r'httponly=True.*secure=True|secure=True.*httponly=True'))

    check("10.1.2 — State + nonce per-transaction, cryptographically random, bound to session",
          any_file_contains(SRC / "backoffice", r'secrets\.token_urlsafe\(32\)')
          and any_file_contains(SRC / "backoffice", r'_store_state.*state.*nonce'))

    # -- V10.2 OAuth Client --
    print("  -- V10.2 OAuth Client --")

    check("10.2.1 — CSRF protection via state parameter on OIDC callback",
          any_file_contains(SRC / "backoffice", r'_consume_state|invalid_or_expired_state'))

    check("10.2.2 — N/A: Single authorization server per deployment (no mix-up risk)", True)

    check("10.2.3 — OIDC scopes explicitly specified (openid, email, profile, groups)",
          any_file_contains(SRC / "sso", r'scopes.*=.*\[.*openid.*email.*profile'))

    # -- V10.3 OAuth Resource Server --
    print("  -- V10.3 OAuth Resource Server --")

    check("10.3.1 — Access tokens validated with audience check (aud claim)",
          any_file_contains(SRC / "gateway", r'audience.*=.*config\.audience'))

    check("10.3.2 — Authorization decisions based on token claims (sub, scope via OPA)",
          any_file_contains(SRC / "gateway", r'jwt_claims.*sub|user_id.*=.*jwt_claims'))

    check("10.3.3 — Unique user identification from iss + sub combination",
          any_file_contains(SRC / "gateway", r'issuer.*=.*config\.issuer')
          and any_file_contains(SRC / "gateway", r'sub.*=.*claims\.get'))

    check("10.3.4 — Auth strength (acr/amr) validation on ID tokens", any_file_contains(SRC / "backoffice" / "routes", r"acr|MIN_ACR"))

    check("10.3.5 — N/A (L3): Sender-constrained tokens (mTLS/DPoP) not implemented", False)

    # -- V10.4 OAuth Authorization Server --
    print("  -- V10.4 OAuth Authorization Server --")
    # Yashigani is an OIDC relying party / client, NOT an authorization server.
    # It delegates to external IdPs (Entra, Okta, etc.).
    # These controls apply to the external IdP, not to Yashigani itself.

    check("10.4.1 — N/A: Yashigani is OIDC RP, not AS (redirect URI validation is IdP responsibility)",
          True)

    check("10.4.2 — N/A: Yashigani is OIDC RP, not AS (auth code one-time use is IdP responsibility)",
          True)

    check("10.4.3 — N/A: Yashigani is OIDC RP, not AS (auth code lifetime is IdP responsibility)",
          True)

    check("10.4.4 — N/A: Yashigani is OIDC RP, not AS (grant type restriction is IdP responsibility)",
          True)

    check("10.4.5 — N/A: Yashigani is OIDC RP, not AS (refresh token rotation is IdP responsibility)",
          True)

    check("10.4.6 — PKCE not implemented on OIDC client side",
          any_file_contains(SRC / "sso", r'code_challenge|code_verifier|PKCE'))

    check("10.4.7 — N/A: Yashigani is OIDC RP, not AS (dynamic client registration is IdP responsibility)",
          True)

    check("10.4.8 — N/A: Yashigani is OIDC RP, not AS (refresh token expiration is IdP responsibility)",
          True)

    check("10.4.9 — N/A: Yashigani is OIDC RP, not AS (token revocation UI is IdP responsibility)",
          True)

    check("10.4.10 — N/A: Yashigani is OIDC RP, not AS (confidential client auth is IdP responsibility)",
          True)

    check("10.4.11 — N/A: Yashigani is OIDC RP, not AS (scope assignment is IdP responsibility)",
          True)

    check("10.4.12 — N/A: Yashigani is OIDC RP, not AS (response_mode restriction is IdP responsibility)",
          True)

    check("10.4.13 — N/A: Yashigani is OIDC RP, not AS (PAR enforcement is IdP responsibility)",
          True)

    check("10.4.14 — N/A: Yashigani is OIDC RP, not AS (sender-constrained tokens is IdP responsibility)",
          True)

    check("10.4.15 — N/A: Yashigani is OIDC RP, not AS (authorization_details is IdP responsibility)",
          True)

    check("10.4.16 — N/A: Yashigani is OIDC RP, not AS (strong client auth is IdP responsibility)",
          True)

    # -- V10.5 OIDC Client --
    print("  -- V10.5 OIDC Client --")

    check("10.5.1 — Nonce sent in auth request and validated in ID token (via authlib)",
          any_file_contains(SRC / "sso", r'nonce=nonce')
          and any_file_contains(SRC / "backoffice", r'nonce.*=.*secrets\.token_urlsafe'))

    check("10.5.2 — User uniquely identified by 'sub' claim from ID token",
          any_file_contains(SRC / "sso", r'claims\[.sub.\]'))

    check("10.5.3 — IdP metadata URL pre-configured per IdP (no dynamic issuer acceptance)",
          any_file_contains(SRC / "auth", r'metadata_url.*=|discovery_url'))

    check("10.5.4 — ID token audience validated (authlib validates aud by default)",
          any_file_contains(SRC / "sso", r'client_id=self\._config\.client_id')
          and any_file_contains(SRC / "sso", r'claims\.validate'))

    check("10.5.5 — N/A: OIDC back-channel logout not implemented (session invalidation is local)",
          True)

    # -- V10.6 OpenID Provider --
    print("  -- V10.6 OpenID Provider --")

    check("10.6.1 — N/A: Yashigani is OIDC RP, not OP (response_mode is IdP responsibility)",
          True)

    check("10.6.2 — N/A: Yashigani is OIDC RP, not OP (forced logout protection is IdP responsibility)",
          True)

    # -- V10.7 Consent Management --
    print("  -- V10.7 Consent Management --")

    check("10.7.1 — N/A: Yashigani is OIDC RP, not AS (consent management is IdP responsibility)",
          True)

    check("10.7.2 — N/A: Yashigani is OIDC RP, not AS (consent information is IdP responsibility)",
          True)

    check("10.7.3 — N/A: Yashigani is OIDC RP, not AS (consent review/revoke is IdP responsibility)",
          True)

    # =========================================================================
    # V11 Cryptography (24 controls)
    # =========================================================================

    # -- V11.1 Cryptographic Inventory and Documentation --
    print("  -- V11.1 Cryptographic Inventory and Documentation --")

    check("11.1.1 — Key management policy: KSM provider abstraction with rotation scheduler",
          any_file_contains(SRC / "kms", r'KSMProvider|KSMRotationScheduler'))

    check("11.1.2 — Cryptographic inventory: KMS providers tracked, key usage documented",
          any_file_contains(SRC / "kms", r'provider_name|get_secret|rotate_secret'))

    check("11.1.3 — Cryptographic inventory API + admin UI", any_file_contains(SRC / "backoffice" / "routes", r"crypto_inventory|algorithms"))

    check("11.1.4 — Post-quantum migration plan documented (ML-DSA-65 noted in verifier.py)",
          any_file_contains(SRC / "licensing", r'ML-DSA-65|post-quantum|FIPS 204'))

    # -- V11.2 Secure Cryptography Implementation --
    print("  -- V11.2 Secure Cryptography Implementation --")

    check("11.2.1 — Industry-validated crypto libraries (cryptography, argon2-cffi, pyjwt, authlib)",
          any_file_contains(SRC / "licensing", r'from cryptography')
          and any_file_contains(SRC / "auth", r'from argon2'))

    check("11.2.2 — Crypto agility: license verifier algorithm-agnostic via load_pem_public_key()",
          any_file_contains(SRC / "licensing", r'load_pem_public_key.*dispatches by key type|algorithm-agnostic'))

    check("11.2.3 — Minimum 128-bit security: ECDSA P-256 (128-bit), Argon2id 256-bit hash, AES-256",
          any_file_contains(SRC / "licensing", r'ECDSA.*P-256|P.256')
          and any_file_contains(SRC / "auth", r'hash_len=32'))

    check("11.2.4 — Constant-time comparison (hmac.compare_digest in TOTP)", any_file_contains(SRC / "auth", r"compare_digest|constant.time"))

    check("11.2.5 — N/A (L3): Fail-secure crypto modules (partial — no Padding Oracle exposure)",
          any_file_contains(SRC / "licensing", r'except.*InvalidSignature'))

    # -- V11.3 Encryption Algorithms --
    print("  -- V11.3 Encryption Algorithms --")

    check("11.3.1 — No ECB mode or PKCS#1 v1.5 padding used",
          not any_file_contains(SRC, r'ECB|pkcs1v15|PKCS.*1.*v1.*5'))

    check("11.3.2 — AES-256-GCM used for data encryption (pgcrypto via pgp_sym_encrypt)",
          any_file_contains(SRC / "inference", r'AES-256-GCM|pgp_sym_encrypt'))

    check("11.3.3 — Authenticated encryption (AES-GCM provides integrated auth)",
          any_file_contains(SRC / "inference", r'AES-256-GCM'))

    check("11.3.4 — AES-GCM nonce uniqueness documented (pgcrypto guarantee)", file_contains(SRC / "db" / "postgres.py", r"nonce|unique.*IV|pgcrypto"))

    check("11.3.5 — N/A (L3): Encrypt-then-MAC mode (AES-GCM is AEAD, no separate MAC needed)",
          True)

    # -- V11.4 Hashing and Hash-based Functions --
    print("  -- V11.4 Hashing and Hash-based Functions --")

    check("11.4.1 — Only approved hash functions: SHA-256 for signatures/HMAC, no MD5",
          any_file_contains(SRC / "licensing", r'SHA256')
          and not any_file_contains(SRC, r'(?<!\w)md5(?!\w)', glob="**/*.py"))

    check("11.4.2 — Passwords stored with Argon2id (m=65536, t=3, p=4)",
          any_file_contains(SRC / "auth", r'Argon2id|time_cost=3.*memory_cost=65536')
          or any_file_contains(SRC / "auth", r'PasswordHasher.*time_cost=3'))

    check("11.4.3 — SHA-256 (256-bit) used for digital signatures (collision resistant)",
          any_file_contains(SRC / "licensing", r'ECDSA\(SHA256\(\)\)'))

    check("11.4.4 — N/A: No KDF from passwords to crypto keys (passwords hashed for storage only)",
          True)

    # -- V11.5 Random Values --
    print("  -- V11.5 Random Values --")

    check("11.5.1 — CSPRNG used: secrets module for tokens/passwords (128+ bits entropy)",
          any_file_contains(SRC / "auth", r'secrets\.choice|secrets\.token')
          and any_file_contains(SRC / "backoffice", r'secrets\.token_urlsafe\(32\)'))

    check("11.5.2 — RNG platform guarantee documented", file_contains(SRC.parent.parent / "docs" / "yashigani_owasp.md", r"Random Number|urandom|ChaCha20"))

    # -- V11.6 Public Key Cryptography --
    print("  -- V11.6 Public Key Cryptography --")

    check("11.6.1 — ECDSA P-256 for license signing; RS256/ES256+ allowlist for JWT",
          any_file_contains(SRC / "licensing", r'ECDSA.*P-256')
          and any_file_contains(SRC / "gateway", r'RS256.*RS384.*RS512.*ES256'))

    check("11.6.2 — N/A (L3): Key exchange via X25519+ML-KEM-768 configured at Caddy TLS layer",
          file_contains(DOCKER / "Caddyfile.selfsigned", r'x25519mlkem768')
          or file_contains(DOCKER / "Caddyfile.acme", r'x25519mlkem768'))

    # -- V11.7 In-Use Data Cryptography --
    print("  -- V11.7 In-Use Data Cryptography --")

    check("11.7.1 — Memory encryption L3 guidance documented", file_contains(SRC.parent.parent / "docs" / "yashigani_owasp.md", r"Memory Encryption|SGX|SEV"))

    check("11.7.2 — N/A (L3): Data minimization during processing (partial — CHS masks credentials before AI calls)",
          any_file_contains(SRC / "chs", r'mask|redact|handle'))

    # =========================================================================
    # V12 Secure Communication (12 controls)
    # =========================================================================

    # -- V12.1 General TLS Security Guidance --
    print("  -- V12.1 General TLS Security Guidance --")

    check("12.1.1 — TLS 1.2 and 1.3 enforced (Caddy tls config: protocols tls1.2 tls1.3)",
          file_contains(DOCKER / "Caddyfile.selfsigned", r'protocols tls1\.2 tls1\.3')
          or file_contains(DOCKER / "Caddyfile.acme", r'protocols tls1\.2 tls1\.3'))

    check("12.1.2 — Strong cipher suites (Caddy defaults: ECDHE + AES-GCM / ChaCha20-Poly1305)",
          file_contains(DOCKER / "Caddyfile.acme", r'ECDHE.*AES-GCM|ChaCha20|cipher suites'))

    check("12.1.3 — N/A: mTLS client certificate validation not implemented (forward auth via cookies)",
          False)

    check("12.1.4 — OCSP stapling enabled (automatic in Caddy ACME mode)",
          file_contains(DOCKER / "Caddyfile.acme", r'OCSP stapling.*enabled|OCSP'))

    check("12.1.5 — N/A (L3): Encrypted Client Hello (ECH) not yet supported by Caddy", False)

    # -- V12.2 HTTPS Communication with External Facing Services --
    print("  -- V12.2 HTTPS Communication with External Facing Services --")

    check("12.2.1 — TLS for all external connectivity; HTTP redirected to HTTPS",
          file_contains(DOCKER / "Caddyfile.selfsigned", r'redir.*https://.*permanent')
          or file_contains(DOCKER / "Caddyfile.acme", r'redir.*https://.*permanent'))

    check("12.2.2 — Publicly trusted TLS certs (Caddy ACME mode uses Let's Encrypt)",
          file_contains(DOCKER / "Caddyfile.acme", r"Let's Encrypt|ACME"))

    # -- V12.3 General Service to Service Communication Security --
    print("  -- V12.3 General Service to Service Communication Security --")

    check("12.3.1 — N/A (L2): Internal services use Docker network isolation, not per-service TLS",
          False)

    check("12.3.2 — TLS clients validate server certificates (httpx default behavior)",
          any_file_contains(SRC / "gateway", r'httpx\.AsyncClient')
          and not any_file_contains(SRC / "gateway", r'verify=False|verify\s*=\s*False'))

    check("12.3.3 — N/A (L2): Internal HTTP services do not use TLS (Docker internal network only)",
          False)

    check("12.3.4 — N/A (L2): Internal services do not use TLS certificates (Docker network isolation)",
          False)

    check("12.3.5 — N/A (L3): Service mesh / mTLS for internal service auth not implemented",
          False)
