#!/usr/bin/env python3
"""
generate_sbom.py — Yashigani SBOM and CryptoBoM generator

Produces two artifacts in dist/:
  sbom-yashigani-{version}.cdx.json     CycloneDX 1.5 SBOM (JSON)
  cryptobom-yashigani-{version}.json    Machine-readable cryptographic algorithm inventory

Usage:
  python scripts/generate_sbom.py [--version VERSION] [--output-dir DIR]

Requirements:
  pip install "cyclonedx-bom>=4.0"      (or: pip install "yashigani[sbom]")

Fallback:
  If cyclonedx-bom is not installed the script assembles a minimal CycloneDX
  document from `pip list --format=json` and dpkg output directly.  The result
  is valid CycloneDX 1.5 but component hashes are omitted.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Version resolution
# ---------------------------------------------------------------------------

def _resolve_version(override: str | None) -> str:
    if override:
        return override
    # Try pyproject.toml first (authoritative)
    root = Path(__file__).resolve().parent.parent
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        text = pyproject.read_text()
        m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
        if m:
            return m.group(1)
    # Fallback: installed package metadata
    try:
        from importlib.metadata import version
        return version("yashigani")
    except Exception:
        return "0.0.0"


# ---------------------------------------------------------------------------
# Dependency collection
# ---------------------------------------------------------------------------

def _pip_packages() -> list[dict]:
    """Return list of {name, version} dicts from pip list."""
    try:
        raw = subprocess.check_output(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            stderr=subprocess.DEVNULL,
        )
        return json.loads(raw)
    except Exception as exc:
        print(f"[WARN] pip list failed: {exc}", file=sys.stderr)
        return []


def _dpkg_packages() -> list[dict]:
    """Return list of {name, version} dicts from dpkg (Linux only)."""
    if platform.system() != "Linux":
        return []
    try:
        raw = subprocess.check_output(
            ["dpkg-query", "-W", "-f=${Package}\\t${Version}\\n"],
            stderr=subprocess.DEVNULL,
        )
        result = []
        for line in raw.decode().splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t", 1)
            if len(parts) == 2:
                result.append({"name": parts[0], "version": parts[1]})
        return result
    except FileNotFoundError:
        return []
    except Exception as exc:
        print(f"[WARN] dpkg-query failed: {exc}", file=sys.stderr)
        return []


def _base_image_info() -> dict:
    """Best-effort base image information from environment or Dockerfile labels."""
    info = {
        "os": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }
    # If running inside a container, /etc/os-release has more detail
    os_release = Path("/etc/os-release")
    if os_release.exists():
        fields: dict[str, str] = {}
        for line in os_release.read_text().splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                fields[k.strip()] = v.strip().strip('"')
        info["os_id"] = fields.get("ID", "unknown")
        info["os_version_id"] = fields.get("VERSION_ID", "unknown")
        info["os_pretty"] = fields.get("PRETTY_NAME", "unknown")
    return info


# ---------------------------------------------------------------------------
# CycloneDX 1.5 assembly (pure-Python fallback)
# ---------------------------------------------------------------------------

def _cdx_component_python(pkg: dict) -> dict:
    return {
        "type": "library",
        "bom-ref": f"pip:{pkg['name'].lower()}:{pkg['version']}",
        "name": pkg["name"],
        "version": pkg["version"],
        "purl": f"pkg:pypi/{pkg['name'].lower()}@{pkg['version']}",
    }


def _cdx_component_dpkg(pkg: dict) -> dict:
    return {
        "type": "library",
        "bom-ref": f"deb:{pkg['name']}:{pkg['version']}",
        "name": pkg["name"],
        "version": pkg["version"],
        "purl": f"pkg:deb/debian/{pkg['name']}@{pkg['version']}",
    }


def _build_cdx_fallback(version: str) -> dict:
    """Assemble a CycloneDX 1.5 SBOM without the cyclonedx-bom library."""
    pip_pkgs = _pip_packages()
    dpkg_pkgs = _dpkg_packages()
    base = _base_image_info()

    components: list[dict] = []
    for p in pip_pkgs:
        components.append(_cdx_component_python(p))
    for p in dpkg_pkgs:
        components.append(_cdx_component_dpkg(p))

    # Base image as an OS component
    os_name = base.get("os_pretty", f"{base['os']} {base['os_release']}")
    os_id = base.get("os_id", "linux")
    os_ver = base.get("os_version_id", "unknown")
    components.append({
        "type": "operating-system",
        "bom-ref": f"os:{os_id}:{os_ver}",
        "name": os_name,
        "version": os_ver,
        "description": "Container base OS",
    })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "AgnosticSec",
                    "name": "yashigani-sbom-generator",
                    "version": version,
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": f"pkg:pypi/yashigani@{version}",
                "name": "yashigani",
                "version": version,
                "description": "Security enforcement gateway for MCP servers and agentic AI systems",
                "licenses": [{"license": {"name": "Proprietary"}}],
                "purl": f"pkg:pypi/yashigani@{version}",
            },
        },
        "components": components,
        "dependencies": [
            {
                "ref": f"pkg:pypi/yashigani@{version}",
                "dependsOn": [c["bom-ref"] for c in components if c["type"] == "library"],
            }
        ],
    }


def _build_cdx_library(version: str) -> dict:
    """Build CycloneDX SBOM using cyclonedx-bom library (preferred path)."""
    # cyclonedx-bom>=4.0 exposes a programmatic API via cyclonedx.model and
    # cyclonedx.output.  Use it when available; fall back to CLI invocation.
    try:
        # Try programmatic import (cyclonedx-bom 4.x)
        from cyclonedx.model.bom import Bom
        from cyclonedx.model.component import Component, ComponentType
        from cyclonedx.output.json import JsonV1Dot5
        from cyclonedx.schema import SchemaVersion
        from packageurl import PackageURL

        bom = Bom()
        for pkg in _pip_packages():
            purl = PackageURL("pypi", name=pkg["name"].lower(), version=pkg["version"])
            comp = Component(
                name=pkg["name"],
                version=pkg["version"],
                component_type=ComponentType.LIBRARY,
                package_url=purl,
            )
            bom.components.add(comp)

        for pkg in _dpkg_packages():
            purl = PackageURL("deb", namespace="debian", name=pkg["name"], version=pkg["version"])
            comp = Component(
                name=pkg["name"],
                version=pkg["version"],
                component_type=ComponentType.LIBRARY,
                package_url=purl,
            )
            bom.components.add(comp)

        outputter = JsonV1Dot5(bom)
        raw = outputter.output_as_string()
        return json.loads(raw)

    except ImportError:
        # cyclonedx-bom not installed — use fallback assembler
        print("[INFO] cyclonedx-bom not installed; using built-in assembler.", file=sys.stderr)
        return _build_cdx_fallback(version)
    except Exception as exc:
        print(f"[WARN] cyclonedx-bom library error ({exc}); falling back to built-in assembler.", file=sys.stderr)
        return _build_cdx_fallback(version)


# ---------------------------------------------------------------------------
# CryptoBoM
# ---------------------------------------------------------------------------

# Canonical algorithm inventory for Yashigani v2.2.
# Derived from code audit: licensing/signer.py (ECDSA P-256), gateway/tls (ECDH),
# auth (Argon2id, TOTP), data-at-rest (AES-256-GCM), JWTs (HS256/RS256),
# TLS (ECDHE-ECDSA / ECDHE-RSA suites via TLS 1.3), integrity (SHA-256/SHA-384).
CRYPTOBOM_ALGORITHMS: list[dict] = [
    {
        "id": "A-01",
        "name": "ECDSA P-256",
        "usage": "License signing and verification (secp256r1 / prime256v1)",
        "pq_status": "not_resistant",
        "standard": "FIPS 186-4",
        "notes": "Used in scripts/keygen.py + licensing/signer.py",
    },
    {
        "id": "A-02",
        "name": "ECDH P-256",
        "usage": "TLS key exchange (ECDHE cipher suites in Caddy/TLS 1.3)",
        "pq_status": "not_resistant",
        "standard": "FIPS 186-4 / RFC 8422",
        "notes": "Negotiated by Caddy; not called directly by application code",
    },
    {
        "id": "A-03",
        "name": "AES-256-GCM",
        "usage": "Symmetric encryption of secrets at rest and in-transit payloads",
        "pq_status": "resistant",
        "standard": "FIPS 197 / SP 800-38D",
        "notes": "Used by KMS provider wrappers (aws, gcp, azure, vault)",
    },
    {
        "id": "A-04",
        "name": "SHA-256",
        "usage": "License fingerprint, HMAC-based integrity checks, audit log chaining",
        "pq_status": "resistant",
        "standard": "FIPS 180-4",
        "notes": "Primary digest throughout the codebase",
    },
    {
        "id": "A-05",
        "name": "SHA-384",
        "usage": "TLS certificate signatures (ECDSA P-384 suites)",
        "pq_status": "resistant",
        "standard": "FIPS 180-4",
        "notes": "Negotiated by Caddy for certificate chains; not called directly",
    },
    {
        "id": "A-06",
        "name": "Argon2id",
        "usage": "Password hashing for admin accounts",
        "pq_status": "resistant",
        "standard": "RFC 9106",
        "notes": "argon2-cffi library; replaces bcrypt for new accounts (v2.x)",
    },
    {
        "id": "A-07",
        "name": "bcrypt",
        "usage": "Legacy password hashing (pre-v2.0 accounts, migration path)",
        "pq_status": "resistant",
        "standard": "Provos & Mazieres 1999",
        "notes": "Retained for backward compat; new accounts use Argon2id",
    },
    {
        "id": "A-08",
        "name": "HMAC-SHA1",
        "usage": "TOTP token generation (RFC 6238) for two-factor authentication",
        "pq_status": "not_resistant",
        "standard": "RFC 2104 / RFC 6238",
        "notes": "SHA-1 in TOTP is mandated by the RFC; upgrade path is FIDO2/WebAuthn",
    },
    {
        "id": "A-09",
        "name": "HMAC-SHA256",
        "usage": "JWT signing (HS256) for internal service tokens",
        "pq_status": "resistant",
        "standard": "RFC 7518",
        "notes": "RS256 (RSA-PKCS1v15-SHA256) used for external JWTs when configured",
    },
    {
        "id": "A-10",
        "name": "RSA-PKCS1v15 / RSA-PSS",
        "usage": "JWT RS256 signing for SSO/IdP token issuance",
        "pq_status": "not_resistant",
        "standard": "PKCS #1 v2.2 / RFC 8017",
        "notes": "Optional; activated when SSO is configured with RS256 algorithm",
    },
    {
        "id": "A-11",
        "name": "TLS 1.3",
        "usage": "Transport encryption for all external and inter-service communication",
        "pq_status": "partially_resistant",
        "standard": "RFC 8446",
        "notes": "TLS 1.2 permitted as fallback; TLS 1.0/1.1 disabled in Caddy config",
    },
    {
        "id": "A-12",
        "name": "cosign / Sigstore",
        "usage": "Container image signing and SBOM attestation",
        "pq_status": "not_resistant",
        "standard": "Sigstore / Rekor transparency log",
        "notes": "Keyless (Fulcio) or local key; signatures recorded in Rekor",
    },
]


def _build_cryptobom(version: str) -> dict:
    return {
        "schema": "yashigani-cryptobom",
        "schema_version": "1.0",
        "product": "yashigani",
        "product_version": version,
        "generated": datetime.now(timezone.utc).isoformat(),
        "algorithms": CRYPTOBOM_ALGORITHMS,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate CycloneDX SBOM and CryptoBoM for Yashigani",
    )
    parser.add_argument(
        "--version",
        default=None,
        help="Override product version (default: read from pyproject.toml)",
    )
    parser.add_argument(
        "--output-dir",
        default="dist",
        help="Output directory for generated files (default: dist/)",
    )
    parser.add_argument(
        "--no-library",
        action="store_true",
        help="Skip cyclonedx-bom library; always use built-in assembler",
    )
    args = parser.parse_args()

    version = _resolve_version(args.version)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # --- CycloneDX SBOM ---
    print(f"[INFO] Generating CycloneDX 1.5 SBOM for yashigani {version}...")
    if args.no_library:
        cdx = _build_cdx_fallback(version)
    else:
        cdx = _build_cdx_library(version)

    sbom_path = out_dir / f"sbom-yashigani-{version}.cdx.json"
    sbom_path.write_text(json.dumps(cdx, indent=2, ensure_ascii=False))
    print(f"[OK]   SBOM written to {sbom_path}")

    # --- CryptoBoM ---
    print("[INFO] Generating CryptoBoM...")
    cryptobom = _build_cryptobom(version)
    cbom_path = out_dir / f"cryptobom-yashigani-{version}.json"
    cbom_path.write_text(json.dumps(cryptobom, indent=2, ensure_ascii=False))
    print(f"[OK]   CryptoBoM written to {cbom_path}")

    print()
    print("Artifacts:")
    print(f"  {sbom_path.resolve()}")
    print(f"  {cbom_path.resolve()}")


if __name__ == "__main__":
    main()
