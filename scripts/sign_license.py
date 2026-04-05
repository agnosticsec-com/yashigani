#!/usr/bin/env python3
"""
Yashigani License Signing Infrastructure — License Signer
=========================================================
YASHIGANI-INTERNAL ONLY — used by the Yashigani team to generate customer license files.

Signs a license payload with the Yashigani ECDSA P-256 private key.

Output formats:
  v3 (default, --counter-key omitted):
      {base64url(json)}.{base64url(primary_signature)}

  v4 (--counter-key provided):
      {base64url(json)}.{base64url(primary_signature)}.{base64url(counter_signature)}

  Counter-signature message:
      sha256(payload_bytes + sha256(primary_public_key_pem_bytes))

ECDSA P-256 with SHA-256.  Signatures are ~72 bytes DER-encoded.
Will migrate to ML-DSA-65 (FIPS 204) when cryptography library ships support.

Payload version: v3/v4 (current)
  Fields: tier, org_domain, max_agents, max_end_users, max_admin_seats, max_orgs,
          features, issued_at, expires_at, license_id, license_type, key_alg, v

Usage (v3 — no counter-key):
    python scripts/sign_license.py \\
        --private-key keys/yashigani_license_private.pem \\
        --tier professional \\
        --org-domain customer.example.com \\
        --max-agents 500 \\
        --max-end-users 1000 \\
        --max-admin-seats 50 \\
        --max-orgs 1 \\
        --expires 2027-04-01 \\
        --features saml,oidc,scim \\
        --out customer.ysg

Usage (v4 — with counter-key):
    python scripts/sign_license.py \\
        --private-key keys/yashigani_license_private.pem \\
        --public-key keys/yashigani_license_public.pem \\
        --counter-key keys/yashigani_counter_private.pem \\
        --tier professional \\
        --org-domain customer.example.com \\
        --out customer.ysg

    # Or pipe payload JSON directly:
    echo '{"tier":"professional",...}' | python scripts/sign_license.py \\
        --private-key keys/yashigani_license_private.pem \\
        --public-key keys/yashigani_license_public.pem \\
        --counter-key keys/yashigani_counter_private.pem \\
        --out customer.ysg
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Per-tier defaults for limit fields when not explicitly specified.
# Must stay in sync with yashigani.licensing.model.TIER_DEFAULTS.
_TIER_DEFAULTS: dict[str, dict] = {
    "community":          {"max_agents": 5,     "max_end_users": 10,     "max_admin_seats": 2,   "max_orgs": 1},
    "starter":            {"max_agents": 100,   "max_end_users": 250,    "max_admin_seats": 25,  "max_orgs": 1},
    "professional":       {"max_agents": 500,   "max_end_users": 1000,   "max_admin_seats": 50,  "max_orgs": 1},
    "professional_plus":  {"max_agents": 2000,  "max_end_users": 10000,  "max_admin_seats": 200, "max_orgs": 5},
    "enterprise":         {"max_agents": -1,    "max_end_users": -1,     "max_admin_seats": -1,  "max_orgs": -1},
    "academic_nonprofit": {"max_agents": 50,    "max_end_users": 500,    "max_admin_seats": 10,  "max_orgs": 1},
}

_VALID_TIERS = list(_TIER_DEFAULTS.keys())

_VALID_LICENSE_TYPES = ["production", "poc", "poc_extended", "nfr"]


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def build_payload(args) -> dict:
    tier = args.tier
    if tier not in _TIER_DEFAULTS:
        print(f"ERROR: unknown tier '{tier}'. Valid: {', '.join(_VALID_TIERS)}", file=sys.stderr)
        sys.exit(1)

    defaults = _TIER_DEFAULTS[tier]

    features: list[str] = []
    if args.features:
        features = [f.strip() for f in args.features.split(",") if f.strip()]

    issued_at: datetime
    if args.issued_at:
        issued_at = datetime.fromisoformat(args.issued_at.replace("Z", "+00:00"))
        if issued_at.tzinfo is None:
            issued_at = issued_at.replace(tzinfo=timezone.utc)
    else:
        issued_at = datetime.now(timezone.utc)

    expires_at = None
    if args.expires_at:
        expires_at = datetime.fromisoformat(args.expires_at.replace("Z", "+00:00"))
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
    elif args.expires:
        # Legacy --expires flag (date only, e.g. 2027-04-01)
        expires_at = datetime.fromisoformat(args.expires).replace(tzinfo=timezone.utc)

    license_id = args.license_id or str(uuid.uuid4())
    license_type = args.license_type or "production"

    if license_type not in _VALID_LICENSE_TYPES:
        print(f"ERROR: unknown license_type '{license_type}'. Valid: {', '.join(_VALID_LICENSE_TYPES)}", file=sys.stderr)
        sys.exit(1)

    # Resolve limits: explicit flag > tier default
    max_agents      = int(args.max_agents)      if args.max_agents      is not None else defaults["max_agents"]
    max_end_users   = int(args.max_end_users)   if args.max_end_users   is not None else defaults["max_end_users"]
    max_admin_seats = int(args.max_admin_seats) if args.max_admin_seats is not None else defaults["max_admin_seats"]
    max_orgs        = int(args.max_orgs)        if args.max_orgs        is not None else defaults["max_orgs"]

    payload = {
        "v": 3,
        "key_alg": "ECDSA-P256",
        "tier": tier,
        "license_type": license_type,
        "org_domain": args.org_domain,
        "license_id": license_id,
        "max_agents": max_agents,
        "max_end_users": max_end_users,
        "max_admin_seats": max_admin_seats,
        "max_orgs": max_orgs,
        "features": features,
        "issued_at": issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if expires_at:
        payload["expires_at"] = expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")

    return payload


def sign_payload(payload: dict, private_key_pem: bytes) -> str:
    """
    Sign a license payload with the ECDSA P-256 private key (SHA-256).

    Returns a v3 format string: {base64url(json)}.{base64url(signature)}.

    Requires cryptography>=42.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    from cryptography.hazmat.primitives.hashes import SHA256

    private_key = load_pem_private_key(private_key_pem, password=None)

    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    payload_bytes = payload_json.encode("utf-8")
    payload_b64 = base64url_encode(payload_bytes)

    signature = private_key.sign(payload_bytes, ECDSA(SHA256()))
    sig_b64 = base64url_encode(signature)

    return f"{payload_b64}.{sig_b64}"


def _compute_counter_sig_message(payload_bytes: bytes, primary_public_key_pem: str) -> bytes:
    """
    Compute the message covered by the counter-signature.

    counter_sig_message = sha256(payload_bytes + sha256(primary_public_key_pem_bytes))

    Must stay in sync with verifier._compute_counter_sig_message().
    """
    pem_bytes = primary_public_key_pem.encode("utf-8")
    pem_hash = hashlib.sha256(pem_bytes).digest()
    combined = payload_bytes + pem_hash
    return hashlib.sha256(combined).digest()


def sign_payload_v4(
    payload: dict,
    primary_private_key_pem: bytes,
    primary_public_key_pem: str,
    counter_private_key_pem: bytes,
) -> str:
    """
    Sign a license payload with both the primary key and the counter-signing key.

    Returns a v4 format string:
        {base64url(json)}.{base64url(primary_sig)}.{base64url(counter_sig)}

    The counter-signature covers:
        sha256(payload_bytes + sha256(primary_public_key_pem_bytes))

    Requires cryptography>=42.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    from cryptography.hazmat.primitives.hashes import SHA256

    # Primary signature
    primary_key = load_pem_private_key(primary_private_key_pem, password=None)
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    payload_bytes = payload_json.encode("utf-8")
    payload_b64 = base64url_encode(payload_bytes)

    primary_sig = primary_key.sign(payload_bytes, ECDSA(SHA256()))
    primary_sig_b64 = base64url_encode(primary_sig)

    # Counter-signature
    counter_key = load_pem_private_key(counter_private_key_pem, password=None)
    message = _compute_counter_sig_message(payload_bytes, primary_public_key_pem)
    counter_sig = counter_key.sign(message, ECDSA(SHA256()))
    counter_sig_b64 = base64url_encode(counter_sig)

    return f"{payload_b64}.{primary_sig_b64}.{counter_sig_b64}"


def _derive_public_key_pem_from_private(private_key_pem: bytes) -> str:
    """Derive the public key PEM string from a private key PEM."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    private_key = load_pem_private_key(private_key_pem, password=None)
    pub_pem = private_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    return pub_pem.decode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sign a Yashigani v3/v4 license payload (ECDSA P-256)"
    )
    parser.add_argument("--private-key", required=True, help="Path to primary ECDSA P-256 private key PEM")
    parser.add_argument(
        "--public-key", default=None,
        help=(
            "Path to primary ECDSA P-256 public key PEM (required when --counter-key is used). "
            "If omitted the public key is derived from --private-key automatically."
        ),
    )
    parser.add_argument(
        "--counter-key", default=None,
        help=(
            "Path to counter-signing ECDSA P-256 private key PEM. "
            "When provided, produces a v4 license with a counter-signature. "
            "Omit to produce a v3 license (backwards-compatible)."
        ),
    )
    parser.add_argument("--tier", choices=_VALID_TIERS, default="professional",
                        help="License tier")
    parser.add_argument("--license-type", choices=_VALID_LICENSE_TYPES, default="production",
                        help="License type: production | poc | poc_extended | nfr")
    parser.add_argument("--org-domain", required=True, help="Customer org domain (e.g. example.com)")
    parser.add_argument("--license-id", default=None, help="UUID for this license (auto-generated if omitted)")
    parser.add_argument("--max-agents", default=None, help="Max agents (-1 = unlimited; defaults to tier default)")
    parser.add_argument("--max-end-users", default=None, help="Max end users (-1 = unlimited; defaults to tier default)")
    parser.add_argument("--max-admin-seats", default=None, help="Max admin seats (-1 = unlimited; defaults to tier default)")
    parser.add_argument("--max-orgs", default=None, help="Max orgs (-1 = unlimited; defaults to tier default)")
    parser.add_argument("--features", default=None,
                        help="Comma-separated feature list (e.g. saml,oidc,scim). Defaults to tier defaults.")
    parser.add_argument("--issued-at", default=None, help="ISO-8601 issued_at (default: now)")
    parser.add_argument("--expires-at", default=None, help="ISO-8601 expires_at (preferred over --expires)")
    parser.add_argument("--expires", default=None, help="Expiry date YYYY-MM-DD (legacy; use --expires-at)")
    parser.add_argument("--out", required=True, help="Output .ysg license file path (use - for stdout)")
    parser.add_argument("--json", dest="payload_json", help="Raw JSON payload (overrides all other flags except --private-key and --out)")
    args = parser.parse_args()

    primary_key_path = Path(args.private_key)
    if not primary_key_path.exists():
        print(f"ERROR: private key not found: {primary_key_path}", file=sys.stderr)
        sys.exit(1)

    primary_private_key_pem = primary_key_path.read_bytes()

    if args.payload_json:
        payload = json.loads(args.payload_json)
    else:
        payload = build_payload(args)

    if args.counter_key:
        # v4 format: primary signature + counter-signature
        counter_key_path = Path(args.counter_key)
        if not counter_key_path.exists():
            print(f"ERROR: counter key not found: {counter_key_path}", file=sys.stderr)
            sys.exit(1)
        counter_private_key_pem = counter_key_path.read_bytes()

        # Resolve primary public key PEM
        if args.public_key:
            pub_key_path = Path(args.public_key)
            if not pub_key_path.exists():
                print(f"ERROR: public key not found: {pub_key_path}", file=sys.stderr)
                sys.exit(1)
            primary_public_key_pem = pub_key_path.read_text(encoding="utf-8")
        else:
            # Derive from private key — convenient but slightly slower
            primary_public_key_pem = _derive_public_key_pem_from_private(primary_private_key_pem)

        license_content = sign_payload_v4(
            payload,
            primary_private_key_pem,
            primary_public_key_pem,
            counter_private_key_pem,
        )
        format_version = 4
    else:
        # v3 format: primary signature only
        license_content = sign_payload(payload, primary_private_key_pem)
        format_version = 3

    if args.out == "-":
        print(license_content)
    else:
        out_path = Path(args.out)
        out_path.write_text(license_content)
        print(f"License written: {out_path}")

    print(f"  format=v{format_version}", file=sys.stderr)
    print(f"  v={payload.get('v', 3)}", file=sys.stderr)
    print(f"  tier={payload['tier']}", file=sys.stderr)
    print(f"  license_type={payload.get('license_type', 'production')}", file=sys.stderr)
    print(f"  org_domain={payload['org_domain']}", file=sys.stderr)
    print(f"  license_id={payload['license_id']}", file=sys.stderr)
    print(f"  max_agents={payload['max_agents']}", file=sys.stderr)
    print(f"  max_end_users={payload.get('max_end_users', '(not set)')}", file=sys.stderr)
    print(f"  max_admin_seats={payload.get('max_admin_seats', '(not set)')}", file=sys.stderr)
    print(f"  max_orgs={payload['max_orgs']}", file=sys.stderr)
    print(f"  features={payload.get('features', [])}", file=sys.stderr)
    print(f"  expires_at={payload.get('expires_at', 'never')}", file=sys.stderr)


if __name__ == "__main__":
    main()
