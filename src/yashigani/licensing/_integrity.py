"""
License anti-tampering — integrity constants.

This module holds two values that are PLACEHOLDERS in source control and are
replaced at Docker build time by the build pipeline:

  VERIFIER_HASH
      SHA-256 hex digest of src/yashigani/licensing/verifier.py, computed
      immediately after the file is written during the Docker image build.
      Used by verifier.py to detect post-build tampering of its own source.

  COUNTER_PUBLIC_KEY_PEM
      ECDSA P-256 public key (PEM) for the counter-signing keypair.  The
      matching private key is held exclusively by the Yashigani signing
      infrastructure and never leaves it.

Placeholder sentinel
--------------------
When either constant still contains _PLACEHOLDER_INTEGRITY the verifier
treats that check as disabled (fail-open) so that development and CI builds
work without real keys.

Build pipeline contract
-----------------------
The build script must:
  1. Compute SHA-256(verifier.py) AFTER all edits are finalised.
  2. Replace the placeholder strings in this file with the real values.
  3. Rebuild / reinstall the package so the updated constants are imported.
  4. Compute SHA-256(verifier.py) a second time to confirm the file has not
     changed since step 1, then re-embed if needed (idempotent).

Do NOT embed the real counter private key here or anywhere in the image.
"""
from __future__ import annotations

# Sentinel value.  Both placeholder constants must contain this string.
_PLACEHOLDER_INTEGRITY = "PLACEHOLDER_YASHIGANI_INTEGRITY"

# ---------------------------------------------------------------------------
# VERIFIER_HASH
# Replace with: sha256sum src/yashigani/licensing/verifier.py | cut -d' ' -f1
# ---------------------------------------------------------------------------
VERIFIER_HASH: str = _PLACEHOLDER_INTEGRITY + "_VERIFIER_HASH"

# ---------------------------------------------------------------------------
# COUNTER_PUBLIC_KEY_PEM
# Replace with the output of:
#   python scripts/keygen.py --out-dir keys/
#   cat keys/yashigani_counter_public.pem
# ---------------------------------------------------------------------------
COUNTER_PUBLIC_KEY_PEM: str = _PLACEHOLDER_INTEGRITY + "_COUNTER_KEY"


def is_verifier_hash_placeholder() -> bool:
    """Return True when VERIFIER_HASH has not been set at build time."""
    return _PLACEHOLDER_INTEGRITY in VERIFIER_HASH


def is_counter_key_placeholder() -> bool:
    """Return True when COUNTER_PUBLIC_KEY_PEM has not been set at build time."""
    return _PLACEHOLDER_INTEGRITY in COUNTER_PUBLIC_KEY_PEM
