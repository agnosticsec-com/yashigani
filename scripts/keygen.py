#!/usr/bin/env python3
"""
Yashigani License Signing Infrastructure — Key Generation
=========================================================
YASHIGANI-INTERNAL ONLY — never commit the private key output.

Generates an ML-DSA-65 (FIPS 204 / CRYSTALS-Dilithium Level 3) keypair
for license signing.

Usage:
    python scripts/keygen.py --out-dir keys/

Output:
    keys/yashigani_license_private.pem  — KEEP SECRET, never commit
    keys/yashigani_license_public.pem   — embed in verifier.py

The public key PEM replaces the PLACEHOLDER in:
    src/yashigani/licensing/verifier.py  (_PUBLIC_KEY_PEM constant)

Requirements:
    cryptography>=44  (ML-DSA-65 support shipped in 44.x)
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def _load_mldsa():
    """
    Return (generate_key_fn, Serialization_module) for ML-DSA-65.

    Tries cryptography>=44 first (preferred, FIPS 204).
    Falls back with a clear error if unavailable — structured so the
    import path just works once cryptography>=44 is installed.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSAPrivateKey
        from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa_mod
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, PublicFormat, NoEncryption,
        )
        return _mldsa_mod, Encoding, PrivateFormat, PublicFormat, NoEncryption
    except ImportError:
        print(
            "ERROR: ML-DSA-65 key generation requires cryptography>=44.\n"
            "       Install with: pip install 'cryptography>=44'\n"
            "       cryptography>=44 ships FIPS 204 (ML-DSA-65) support.",
            file=sys.stderr,
        )
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate Yashigani ML-DSA-65 (FIPS 204) license signing keypair"
    )
    parser.add_argument(
        "--out-dir",
        default="keys",
        help="Output directory for keypair (default: keys/)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing keys",
    )
    args = parser.parse_args()

    mldsa_mod, Encoding, PrivateFormat, PublicFormat, NoEncryption = _load_mldsa()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    priv_path = out_dir / "yashigani_license_private.pem"
    pub_path = out_dir / "yashigani_license_public.pem"

    if priv_path.exists() and not args.force:
        print(f"ERROR: {priv_path} already exists. Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)

    # Generate ML-DSA-65 keypair (FIPS 204, CRYSTALS-Dilithium Level 3)
    # Public key ~1.9 KB; signature ~3.3 KB — both larger than P-256 but post-quantum safe.
    private_key = mldsa_mod.generate_private_key(mldsa_mod.MLDSA65())

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

    print(f"Private key: {priv_path}  (chmod 600 — NEVER COMMIT)")
    print(f"Public key:  {pub_path}")
    print()
    print("Next step: embed the public key in src/yashigani/licensing/verifier.py")
    print(f"  Replace the _PUBLIC_KEY_PEM placeholder with:\n\n{pub_pem.decode()}")
    print()
    print("WARNING: Add keys/ to .gitignore immediately.")


if __name__ == "__main__":
    main()
