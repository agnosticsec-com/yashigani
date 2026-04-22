"""
Service identity + manifest loader for Yashigani internal PKI.

This module is import-safe from any service entrypoint. It does no network
I/O, no cryptographic operations beyond SHA-256 (stdlib hashlib), and does
not depend on the heavier ``cryptography`` package. The cryptography package
is only required by :mod:`yashigani.pki.issuer` which runs inside install.sh
and admin-API rotation endpoints.

Environment inputs at runtime:
    YASHIGANI_SERVICE_NAME          — e.g. "gateway", "backoffice" (required)
    YASHIGANI_INTERNAL_CA_DIR       — where ca_root.crt + <svc>_client.{crt,key}
                                       + <svc>_bootstrap_token live.
                                       Default: /run/secrets
    YASHIGANI_SERVICE_MANIFEST_PATH — path to service_identities.yaml.
                                       Default: /etc/yashigani/service_identities.yaml
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import yaml  # PyYAML — present in base install (pydantic stack pulls it)
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "PyYAML is required for the service manifest. Install with: pip install pyyaml"
    ) from exc

logger = logging.getLogger(__name__)

_DEFAULT_SECRETS_DIR = "/run/secrets"
_DEFAULT_MANIFEST_PATH = "/etc/yashigani/service_identities.yaml"

_VALID_CA_MODES = {"yashigani_generated", "byo_intermediate", "byo_root", "remote_acme"}
_TIER_ORDER = ["community", "starter", "professional", "enterprise"]


class ManifestError(ValueError):
    """Raised when service_identities.yaml is missing, malformed, or the
    requested service is not in the allowlist."""


class TamperError(RuntimeError):
    """Raised when the on-disk bootstrap token does not hash to the manifest
    entry — indicates the secrets dir was tampered with after install."""


# ─────────────────────────────────────────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ServiceIdentity:
    """One entry from service_identities.yaml."""

    name: str
    dns_sans: tuple[str, ...]
    purpose: str
    mtls_capable: bool
    bootstrap_token_sha256: str
    revoked: bool

    # Runtime-only fields resolved from the filesystem
    cert_path: Optional[Path] = None
    key_path: Optional[Path] = None
    ca_root_path: Optional[Path] = None

    def expect_cert_files(self) -> tuple[Path, Path, Path]:
        """Return (cert_path, key_path, ca_root_path) or raise."""
        if not (self.cert_path and self.key_path and self.ca_root_path):
            raise ManifestError(
                f"Service {self.name!r} has no cert paths resolved — "
                "is YASHIGANI_INTERNAL_CA_DIR populated by install.sh?"
            )
        for p in (self.cert_path, self.key_path, self.ca_root_path):
            if not p.exists():
                raise ManifestError(
                    f"Service {self.name!r}: expected cert file missing: {p}"
                )
        return self.cert_path, self.key_path, self.ca_root_path


@dataclass(frozen=True)
class CertPolicy:
    """Hard bounds from service_identities.yaml cert_policy block."""

    root_lifetime_years_min: int
    root_lifetime_years_max: int
    root_lifetime_years_default: int
    root_rotation_requires_manual_confirmation: bool

    intermediate_lifetime_days_min: int
    intermediate_lifetime_days_max: int
    intermediate_lifetime_days_default: int

    leaf_lifetime_days_min: int
    leaf_lifetime_days_max: int
    leaf_lifetime_days_default: int

    renewal_threshold: float

    def clamp_leaf(self, days: int) -> int:
        return max(self.leaf_lifetime_days_min, min(self.leaf_lifetime_days_max, days))

    def clamp_intermediate(self, days: int) -> int:
        return max(
            self.intermediate_lifetime_days_min,
            min(self.intermediate_lifetime_days_max, days),
        )

    def clamp_root(self, years: int) -> int:
        return max(
            self.root_lifetime_years_min,
            min(self.root_lifetime_years_max, years),
        )


@dataclass(frozen=True)
class CASource:
    mode: str  # one of _VALID_CA_MODES
    byo_root_cert_path: str = ""
    byo_intermediate_cert_path: str = ""
    byo_intermediate_key_path: str = ""
    remote_acme_driver: str = ""
    remote_acme_directory_url: str = ""
    remote_acme_eab_kid: str = ""
    remote_acme_eab_hmac_key_secret_ref: str = ""
    min_license_tier: dict[str, str] = field(default_factory=dict)

    def requires_license_tier(self) -> str:
        return self.min_license_tier.get(self.mode, "community")


@dataclass(frozen=True)
class Manifest:
    schema_version: int
    services: tuple[ServiceIdentity, ...]
    cert_policy: CertPolicy
    ca_source: CASource

    def get(self, name: str) -> ServiceIdentity:
        for s in self.services:
            if s.name == name:
                return s
        raise ManifestError(
            f"Service {name!r} is not in service_identities.yaml — "
            "rogue service, refusing to operate in the mesh."
        )

    def live_services(self) -> tuple[ServiceIdentity, ...]:
        """Services eligible for cert issuance (not revoked)."""
        return tuple(s for s in self.services if not s.revoked)


# ─────────────────────────────────────────────────────────────────────────────
# Loader
# ─────────────────────────────────────────────────────────────────────────────

def load_manifest(path: Optional[str] = None) -> Manifest:
    """Parse and validate the service_identities.yaml manifest.

    Raises :class:`ManifestError` on missing file, unknown schema version,
    or violated invariants.
    """
    path = path or os.getenv("YASHIGANI_SERVICE_MANIFEST_PATH", _DEFAULT_MANIFEST_PATH)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except FileNotFoundError as exc:
        raise ManifestError(f"Service manifest not found at {path}") from exc
    except yaml.YAMLError as exc:
        raise ManifestError(f"Service manifest is not valid YAML: {exc}") from exc

    if not isinstance(doc, dict):
        raise ManifestError("Service manifest root must be a mapping")

    schema_version = doc.get("schema_version")
    if schema_version != 1:
        raise ManifestError(
            f"Unsupported schema_version {schema_version!r}; expected 1"
        )

    services_raw = doc.get("services", [])
    if not isinstance(services_raw, list) or not services_raw:
        raise ManifestError("service_identities.yaml has no services")

    services: list[ServiceIdentity] = []
    seen_names: set[str] = set()
    for idx, entry in enumerate(services_raw):
        if not isinstance(entry, dict):
            raise ManifestError(f"services[{idx}] is not a mapping")
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            raise ManifestError(f"services[{idx}].name is missing or non-string")
        if name in seen_names:
            raise ManifestError(f"duplicate service name {name!r}")
        seen_names.add(name)

        sans = entry.get("dns_sans", [])
        if not isinstance(sans, list) or not all(isinstance(s, str) for s in sans):
            raise ManifestError(f"{name}: dns_sans must be a list of strings")

        purpose = entry.get("purpose", "")
        if not isinstance(purpose, str):
            raise ManifestError(f"{name}: purpose must be a string")

        mtls_capable = bool(entry.get("mtls_capable", True))
        bootstrap_token_sha256 = entry.get("bootstrap_token_sha256", "")
        if not isinstance(bootstrap_token_sha256, str):
            raise ManifestError(f"{name}: bootstrap_token_sha256 must be a string")
        revoked = bool(entry.get("revoked", False))

        services.append(
            ServiceIdentity(
                name=name,
                dns_sans=tuple(sans),
                purpose=purpose,
                mtls_capable=mtls_capable,
                bootstrap_token_sha256=bootstrap_token_sha256,
                revoked=revoked,
            )
        )

    policy = _parse_cert_policy(doc.get("cert_policy", {}))
    ca_source = _parse_ca_source(doc.get("ca_source", {}))

    return Manifest(
        schema_version=schema_version,
        services=tuple(services),
        cert_policy=policy,
        ca_source=ca_source,
    )


def _parse_cert_policy(raw: Any) -> CertPolicy:
    if not isinstance(raw, dict):
        raise ManifestError("cert_policy must be a mapping")

    def _int(key: str, default: int) -> int:
        v = raw.get(key, default)
        if not isinstance(v, int) or isinstance(v, bool):
            raise ManifestError(f"cert_policy.{key} must be an integer")
        return v

    def _float(key: str, default: float) -> float:
        v = raw.get(key, default)
        if not isinstance(v, (int, float)) or isinstance(v, bool):
            raise ManifestError(f"cert_policy.{key} must be numeric")
        return float(v)

    policy = CertPolicy(
        root_lifetime_years_min=_int("root_lifetime_years_min", 5),
        root_lifetime_years_max=_int("root_lifetime_years_max", 20),
        root_lifetime_years_default=_int("root_lifetime_years_default", 10),
        root_rotation_requires_manual_confirmation=bool(
            raw.get("root_rotation_requires_manual_confirmation", True)
        ),
        intermediate_lifetime_days_min=_int("intermediate_lifetime_days_min", 90),
        intermediate_lifetime_days_max=_int("intermediate_lifetime_days_max", 365),
        intermediate_lifetime_days_default=_int("intermediate_lifetime_days_default", 180),
        leaf_lifetime_days_min=_int("leaf_lifetime_days_min", 30),
        leaf_lifetime_days_max=_int("leaf_lifetime_days_max", 90),
        leaf_lifetime_days_default=_int("leaf_lifetime_days_default", 90),
        renewal_threshold=_float("renewal_threshold", 0.33),
    )
    _validate_policy(policy)
    return policy


def _validate_policy(policy: CertPolicy) -> None:
    if not (
        policy.root_lifetime_years_min
        <= policy.root_lifetime_years_default
        <= policy.root_lifetime_years_max
    ):
        raise ManifestError("cert_policy root default outside min/max bounds")
    if not (
        policy.intermediate_lifetime_days_min
        <= policy.intermediate_lifetime_days_default
        <= policy.intermediate_lifetime_days_max
    ):
        raise ManifestError("cert_policy intermediate default outside min/max bounds")
    if not (
        policy.leaf_lifetime_days_min
        <= policy.leaf_lifetime_days_default
        <= policy.leaf_lifetime_days_max
    ):
        raise ManifestError("cert_policy leaf default outside min/max bounds")
    if not (0.05 <= policy.renewal_threshold <= 0.9):
        raise ManifestError("cert_policy renewal_threshold must be between 0.05 and 0.9")


def _parse_ca_source(raw: Any) -> CASource:
    if not isinstance(raw, dict):
        raise ManifestError("ca_source must be a mapping")

    mode = raw.get("mode", "yashigani_generated")
    if mode not in _VALID_CA_MODES:
        raise ManifestError(
            f"ca_source.mode {mode!r} not in {sorted(_VALID_CA_MODES)}"
        )
    byo = raw.get("byo", {}) or {}
    rem = raw.get("remote_acme", {}) or {}
    min_tier_raw = raw.get("min_license_tier", {}) or {}
    if not isinstance(min_tier_raw, dict):
        raise ManifestError("ca_source.min_license_tier must be a mapping")
    for k, v in min_tier_raw.items():
        if v not in _TIER_ORDER:
            raise ManifestError(
                f"ca_source.min_license_tier[{k!r}]={v!r} not a known tier"
            )

    return CASource(
        mode=mode,
        byo_root_cert_path=str(byo.get("root_cert_path", "")),
        byo_intermediate_cert_path=str(byo.get("intermediate_cert_path", "")),
        byo_intermediate_key_path=str(byo.get("intermediate_key_path", "")),
        remote_acme_driver=str(rem.get("driver", "")),
        remote_acme_directory_url=str(rem.get("directory_url", "")),
        remote_acme_eab_kid=str(rem.get("eab_kid", "")),
        remote_acme_eab_hmac_key_secret_ref=str(rem.get("eab_hmac_key_secret_ref", "")),
        min_license_tier=dict(min_tier_raw),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Runtime self-resolution
# ─────────────────────────────────────────────────────────────────────────────

def current_service(
    *,
    verify_token: bool = True,
    secrets_dir: Optional[str] = None,
    manifest_path: Optional[str] = None,
) -> ServiceIdentity:
    """Resolve the ServiceIdentity for this container, populated with cert paths.

    Steps:
      1. Read YASHIGANI_SERVICE_NAME (required).
      2. Load manifest — if name not present -> ManifestError (rogue).
      3. If verify_token: read bootstrap token file, SHA-256 it, compare
         to manifest entry in constant time. Mismatch -> TamperError.
      4. Resolve cert file paths inside secrets_dir.
      5. Return ServiceIdentity with paths populated.
    """
    name = os.environ.get("YASHIGANI_SERVICE_NAME", "").strip()
    if not name:
        raise ManifestError(
            "YASHIGANI_SERVICE_NAME is not set — the container does not know "
            "its own identity. Add it to the service environment in compose."
        )

    manifest = load_manifest(manifest_path)
    identity = manifest.get(name)

    if identity.revoked:
        raise ManifestError(
            f"Service {name!r} is marked revoked: true in the manifest — "
            "refusing to start. Operator must un-revoke and rotate certs."
        )

    secrets_dir_path = Path(secrets_dir or os.getenv("YASHIGANI_INTERNAL_CA_DIR", _DEFAULT_SECRETS_DIR))
    cert_path = secrets_dir_path / f"{name}_client.crt"
    key_path = secrets_dir_path / f"{name}_client.key"
    ca_root = secrets_dir_path / "ca_root.crt"
    bootstrap_token_path = secrets_dir_path / f"{name}_bootstrap_token"

    if verify_token:
        _verify_bootstrap_token(identity, bootstrap_token_path)

    return ServiceIdentity(
        name=identity.name,
        dns_sans=identity.dns_sans,
        purpose=identity.purpose,
        mtls_capable=identity.mtls_capable,
        bootstrap_token_sha256=identity.bootstrap_token_sha256,
        revoked=identity.revoked,
        cert_path=cert_path,
        key_path=key_path,
        ca_root_path=ca_root,
    )


def _verify_bootstrap_token(identity: ServiceIdentity, path: Path) -> None:
    """Read token from disk, hash it, compare constant-time to manifest."""
    if not identity.bootstrap_token_sha256:
        # First install path — install.sh will populate on rotation.
        # Refuse to start if the manifest declares the service at all
        # but the install step didn't complete.
        raise TamperError(
            f"Service {identity.name!r} has no bootstrap_token_sha256 in the "
            "manifest — install.sh bootstrap_internal_pki() did not run, or "
            "the manifest was not committed after install."
        )
    if not path.exists():
        raise TamperError(
            f"Bootstrap token for {identity.name!r} not found at {path} — "
            "secrets directory may have been tampered with."
        )
    try:
        token_bytes = path.read_bytes().strip()
    except OSError as exc:
        raise TamperError(f"Cannot read bootstrap token at {path}: {exc}") from exc
    actual_sha = hashlib.sha256(token_bytes).hexdigest()
    if not hmac.compare_digest(actual_sha, identity.bootstrap_token_sha256):
        raise TamperError(
            f"Bootstrap token SHA-256 mismatch for {identity.name!r}. "
            "The on-disk secret does not match the manifest. Refusing to start."
        )


def tier_at_least(actual: str, required: str) -> bool:
    """Return True if licensed tier *actual* meets *required* or higher."""
    try:
        return _TIER_ORDER.index(actual) >= _TIER_ORDER.index(required)
    except ValueError:
        return False
