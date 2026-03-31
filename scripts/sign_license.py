#!/usr/bin/env python3
"""
Yashigani License Signing Infrastructure — License Signer
=========================================================
YASHIGANI-INTERNAL ONLY — used by the Yashigani team to generate customer license files.

Signs a license payload with the Yashigani ECDSA P-256 private key.
Output is a .ysg file: {base64url(json)}.{base64url(ecdsa_signature)}

ECDSA P-256 with SHA-256. Signatures are ~72 bytes DER-encoded.
Will migrate to ML-DSA-65 (FIPS 204) when cryptography library ships support.

Payload version: v3 (current)
  Fields: tier, org_domain, max_agents, max_end_users, max_admin_seats, max_orgs,
          features, issued_at, expires_at, license_id, license_type, key_alg, v

Usage:
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

    # Or pipe payload JSON directly:
    echo '{"tier":"professional",...}' | python scripts/sign_license.py \\
        --private-key keys/yashigani_license_private.pem \\
        --out customer.ysg
"""
from __future__ import annotations

import argparse
import base64
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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sign a Yashigani v3 license payload (ECDSA P-256)"
    )
    parser.add_argument("--private-key", required=True, help="Path to ECDSA P-256 private key PEM")
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

    private_key_path = Path(args.private_key)
    if not private_key_path.exists():
        print(f"ERROR: private key not found: {private_key_path}", file=sys.stderr)
        sys.exit(1)

    private_key_pem = private_key_path.read_bytes()

    if args.payload_json:
        payload = json.loads(args.payload_json)
    else:
        payload = build_payload(args)

    license_content = sign_payload(payload, private_key_pem)

    if args.out == "-":
        print(license_content)
    else:
        out_path = Path(args.out)
        out_path.write_text(license_content)
        print(f"License written: {out_path}")

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
