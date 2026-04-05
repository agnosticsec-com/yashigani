#!/usr/bin/env python3
"""
Yashigani License Signing Infrastructure — Key Generation
=========================================================
YASHIGANI-INTERNAL ONLY — never commit the private key output.

Generates two ECDSA P-256 keypairs:
  1. Primary license-signing keypair  (replaces _PUBLIC_KEY_PEM in verifier.py)
  2. Counter-signing keypair          (replaces COUNTER_PUBLIC_KEY_PEM in _integrity.py)

Will migrate to ML-DSA-65 (FIPS 204) when cryptography library ships support.

Usage:
    python scripts/keygen.py --out-dir keys/

Output:
    keys/yashigani_license_private.pem   — KEEP SECRET, never commit
    keys/yashigani_license_public.pem    — embed in verifier.py (_PUBLIC_KEY_PEM)
    keys/yashigani_counter_private.pem   — KEEP SECRET, never commit
    keys/yashigani_counter_public.pem    — embed in _integrity.py (COUNTER_PUBLIC_KEY_PEM)

Next steps after keygen:
  1. Embed yashigani_license_public.pem  → src/yashigani/licensing/verifier.py  (_PUBLIC_KEY_PEM)
  2. Embed yashigani_counter_public.pem  → src/yashigani/licensing/_integrity.py (COUNTER_PUBLIC_KEY_PEM)
  3. The VERIFIER_HASH in _integrity.py must be set by the build pipeline AFTER all
     source edits are finalised:
       sha256sum src/yashigani/licensing/verifier.py | cut -d' ' -f1
  4. Add keys/ to .gitignore immediately.

Requirements:
    cryptography>=42
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def _generate_keypair(out_dir: Path, name_prefix: str, force: bool) -> tuple[Path, Path]:
    """
    Generate one ECDSA P-256 keypair and write PEM files.

    Returns (private_key_path, public_key_path).
    Exits with error if files exist and --force not set.
    """
    from cryptography.hazmat.primitives.asymmetric.ec import (
        generate_private_key,
        SECP256R1,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PrivateFormat,
        PublicFormat,
        NoEncryption,
    )

    priv_path = out_dir / f"{name_prefix}_private.pem"
    pub_path = out_dir / f"{name_prefix}_public.pem"

    if priv_path.exists() and not force:
        print(f"ERROR: {priv_path} already exists. Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)

    private_key = generate_private_key(SECP256R1())

    priv_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    # Write with restricted permissions
    priv_path.write_bytes(priv_pem)
    os.chmod(priv_path, 0o600)

    pub_path.write_bytes(pub_pem)
    os.chmod(pub_path, 0o644)

    return priv_path, pub_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate Yashigani ECDSA P-256 license signing keypairs (primary + counter)"
    )
    parser.add_argument(
        "--out-dir",
        default="keys",
        help="Output directory for keypairs (default: keys/)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing keys",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # --- Primary keypair ---
    primary_priv, primary_pub = _generate_keypair(
        out_dir, "yashigani_license", args.force
    )
    primary_pub_pem = primary_pub.read_text(encoding="utf-8")

    # --- Counter-signing keypair ---
    counter_priv, counter_pub = _generate_keypair(
        out_dir, "yashigani_counter", args.force
    )
    counter_pub_pem = counter_pub.read_text(encoding="utf-8")

    print("=" * 70)
    print("PRIMARY LICENSE KEYPAIR")
    print("=" * 70)
    print(f"  Private key : {primary_priv}  (chmod 600 — NEVER COMMIT)")
    print(f"  Public key  : {primary_pub}")
    print()
    print("Embed in src/yashigani/licensing/verifier.py:")
    print("  Replace _PUBLIC_KEY_PEM with:\n")
    print(primary_pub_pem)

    print("=" * 70)
    print("COUNTER-SIGNING KEYPAIR")
    print("=" * 70)
    print(f"  Private key : {counter_priv}  (chmod 600 — NEVER COMMIT)")
    print(f"  Public key  : {counter_pub}")
    print()
    print("Embed in src/yashigani/licensing/_integrity.py:")
    print("  Replace COUNTER_PUBLIC_KEY_PEM with:\n")
    print(counter_pub_pem)

    print("=" * 70)
    print("NEXT STEPS")
    print("=" * 70)
    print("1. Embed primary public key in verifier.py (_PUBLIC_KEY_PEM).")
    print("2. Embed counter public key in _integrity.py (COUNTER_PUBLIC_KEY_PEM).")
    print("3. After all source edits, compute VERIFIER_HASH:")
    print("     sha256sum src/yashigani/licensing/verifier.py | cut -d' ' -f1")
    print("   Embed the result in _integrity.py (VERIFIER_HASH).")
    print("4. Add keys/ to .gitignore immediately.")
    print()
    print("WARNING: Add keys/ to .gitignore immediately.")


if __name__ == "__main__":
    main()
