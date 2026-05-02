"""
Yashigani Backoffice — Cryptographic inventory endpoint (ASVS 11.1.3).

GET /admin/crypto/inventory — returns a JSON document listing every
cryptographic algorithm in use, deprecated algorithms, post-quantum
status, and compliance references.

Admin-authenticated. Useful for compliance audits and procurement teams.

A5 (2026-05-02): Added require_admin_session dependency to the handler.
The endpoint was declared as admin-authenticated in the docstring but had no
actual auth dependency — no Depends(), no router-level guard, no middleware
covering /admin/crypto/*. The CryptoBoM is not itself a secret (it describes
algorithm choices, not key material) but exposing it unauthenticated leaks
reconnaissance data to attackers (OWASP API1:2023 / ASVS V4.1.1).

Last updated: 2026-05-02T00:00:00+01:00
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from yashigani.backoffice.middleware import require_admin_session

router = APIRouter()

_CRYPTO_INVENTORY = {
    "algorithms": [
        {"name": "Argon2id", "usage": "password hashing", "strength": "256-bit"},
        {"name": "ECDSA P-256", "usage": "license signing", "strength": "128-bit equivalent"},
        {"name": "AES-256-GCM", "usage": "database column encryption", "strength": "256-bit"},
        {"name": "SHA-256", "usage": "TOTP digest, HMAC email hashing", "strength": "256-bit"},
        {"name": "SHA-384", "usage": "audit chain integrity", "strength": "384-bit"},
        {"name": "X25519+ML-KEM-768", "usage": "TLS key exchange (hybrid PQ)", "strength": "256-bit + PQ"},
        {"name": "bcrypt", "usage": "agent token hashing", "strength": "184-bit"},
        {"name": "HMAC-SHA256", "usage": "email hashing, API signing", "strength": "256-bit"},
        {"name": "ChaCha20 (CSPRNG)", "usage": "session token generation (via /dev/urandom)", "strength": "256-bit"},
    ],
    "deprecated": [],
    "post_quantum": [
        "ML-KEM-768 (key exchange)",
        "ML-DSA-65 (planned for license signing)",
    ],
    "compliance": "NIST SP 800-131A Rev 2, OWASP ASVS v5 V11",
}


@router.get("/crypto/inventory")
async def crypto_inventory(session=Depends(require_admin_session)):
    """
    Return the full cryptographic algorithm inventory.
    ASVS 11.1.3 — all algorithms, strength levels, and PQ readiness.
    Requires admin session (A5 fix 2026-05-02).
    """
    return JSONResponse(content=_CRYPTO_INVENTORY)
