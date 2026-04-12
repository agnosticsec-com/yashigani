"""
Yashigani Backoffice — Cryptographic inventory endpoint (ASVS 11.1.3).

GET /admin/crypto/inventory — returns a JSON document listing every
cryptographic algorithm in use, deprecated algorithms, post-quantum
status, and compliance references.

Admin-authenticated. Useful for compliance audits and procurement teams.
"""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

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
async def crypto_inventory():
    """
    Return the full cryptographic algorithm inventory.
    ASVS 11.1.3 — all algorithms, strength levels, and PQ readiness.
    """
    return JSONResponse(content=_CRYPTO_INVENTORY)
