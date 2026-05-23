"""
Unit tests for issuer.py bootstrap() BYO intermediate CA path (v2.24.0).

Covers:
  - Happy path: customer root + intermediate → leaves signed by customer intermediate
  - Trust anchor written correctly (root cert if provided, else intermediate)
  - Leaf chain verifies to customer root
  - Regression: yashigani_generated mode still works (no regression)
  - byo_root mode raises clear RuntimeError (not implemented in v2.24.0)
  - Guard: refuses to overwrite existing intermediate
  - Validation errors: missing cert/key, mismatched pair, expired, not-yet-valid,
    not a CA cert, missing keyUsage, chain mismatch between root and intermediate
  - rotate_leaves works after byo_intermediate bootstrap (reads existing intermediate)

All certs generated in-process via the cryptography library. No openssl shell calls.
No /tmp paths — uses pytest's tmp_path fixture (under /private/var/folders on macOS).
"""
from __future__ import annotations

import datetime as _dt
from pathlib import Path
from typing import Optional

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from yashigani.pki.issuer import IssuerPaths, bootstrap, rotate_leaves


# ---------------------------------------------------------------------------
# Cert-generation helpers (in-process, no shell)
# ---------------------------------------------------------------------------

def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _gen_ec_key(curve=None) -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(curve or ec.SECP256R1())


def _gen_rsa_key(bits: int = 3072) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _serial() -> int:
    import secrets
    return int.from_bytes(secrets.token_bytes(16), "big") | 1


def _make_root_ca(
    key: ec.EllipticCurvePrivateKey,
    cn: str = "Customer Root CA",
    *,
    days: int = 3650,
    not_before_offset: _dt.timedelta = _dt.timedelta(minutes=-5),
    not_after_offset: Optional[_dt.timedelta] = None,
) -> x509.Certificate:
    now = _utcnow()
    not_after = now + (not_after_offset or _dt.timedelta(days=days))
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(_serial())
        .not_valid_before(now + not_before_offset)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )


def _make_intermediate_ca(
    root_cert: x509.Certificate,
    root_key: ec.EllipticCurvePrivateKey,
    int_key: ec.EllipticCurvePrivateKey,
    cn: str = "Customer Intermediate CA",
    *,
    days: int = 1095,
    not_before_offset: _dt.timedelta = _dt.timedelta(minutes=-5),
    not_after_offset: Optional[_dt.timedelta] = None,
    include_basic_constraints: bool = True,
    ca_true: bool = True,
    include_key_usage: bool = True,
    key_cert_sign: bool = True,
) -> x509.Certificate:
    now = _utcnow()
    not_after = now + (not_after_offset or _dt.timedelta(days=days))
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(root_cert.subject)
        .public_key(int_key.public_key())
        .serial_number(_serial())
        .not_valid_before(now + not_before_offset)
        .not_valid_after(not_after)
    )
    if include_basic_constraints:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca_true, path_length=0 if ca_true else None), critical=True
        )
    if include_key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=key_cert_sign, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    return builder.sign(root_key, hashes.SHA256())


def _pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


# ---------------------------------------------------------------------------
# Fixture: standard customer PKI (root + intermediate, valid, EC P-256)
# ---------------------------------------------------------------------------

@pytest.fixture()
def customer_pki(tmp_path: Path):
    """Generate a valid customer root + intermediate CA and write to tmp_path/byo/."""
    byo_dir = tmp_path / "byo"
    byo_dir.mkdir()

    root_key = _gen_ec_key(ec.SECP256R1())
    root_cert = _make_root_ca(root_key, cn="Customer Root CA")

    int_key = _gen_ec_key(ec.SECP256R1())
    int_cert = _make_intermediate_ca(root_cert, root_key, int_key, cn="Customer Intermediate CA")

    root_cert_path = _write(byo_dir / "customer-root.crt", _pem_cert(root_cert))
    int_cert_path = _write(byo_dir / "customer-intermediate.crt", _pem_cert(int_cert))
    int_key_path = _write(byo_dir / "customer-intermediate.key", _pem_key(int_key))

    return {
        "root_cert": root_cert,
        "root_key": root_key,
        "int_cert": int_cert,
        "int_key": int_key,
        "root_cert_path": root_cert_path,
        "int_cert_path": int_cert_path,
        "int_key_path": int_key_path,
    }


# ---------------------------------------------------------------------------
# Manifest factories
# ---------------------------------------------------------------------------

_BASE_POLICY = """\
cert_policy:
  root_lifetime_years_min: 5
  root_lifetime_years_max: 20
  root_lifetime_years_default: 10
  root_rotation_requires_manual_confirmation: true
  intermediate_lifetime_days_min: 90
  intermediate_lifetime_days_max: 365
  intermediate_lifetime_days_default: 180
  leaf_lifetime_days_min: 30
  leaf_lifetime_days_max: 90
  leaf_lifetime_days_default: 90
  renewal_threshold: 0.33
"""

_BASE_SERVICES = """\
services:
  - name: gateway
    dns_sans: [gateway]
    purpose: "data plane"
    mtls_capable: true
    bootstrap_token_sha256: ""
    revoked: false
  - name: backoffice
    dns_sans: [backoffice]
    purpose: "admin"
    mtls_capable: true
    bootstrap_token_sha256: ""
    revoked: false
"""


def _make_byo_manifest(
    int_cert_path: Path,
    int_key_path: Path,
    root_cert_path: Optional[Path] = None,
) -> str:
    root_line = f'    root_cert_path: "{root_cert_path}"' if root_cert_path else ""
    return (
        "schema_version: 1\n"
        + _BASE_SERVICES
        + _BASE_POLICY
        + "ca_source:\n"
        + "  mode: byo_intermediate\n"
        + "  byo:\n"
        + f'    intermediate_cert_path: "{int_cert_path}"\n'
        + f'    intermediate_key_path: "{int_key_path}"\n'
        + (root_line + "\n" if root_line else "")
    )


def _make_ysg_manifest() -> str:
    return (
        "schema_version: 1\n"
        + _BASE_SERVICES
        + _BASE_POLICY
        + "ca_source:\n"
        + "  mode: yashigani_generated\n"
        + "  byo: {}\n"
    )


def _make_byo_root_manifest() -> str:
    return (
        "schema_version: 1\n"
        + _BASE_SERVICES
        + _BASE_POLICY
        + "ca_source:\n"
        + "  mode: byo_root\n"
        + "  byo: {}\n"
    )


# ---------------------------------------------------------------------------
# Helper to build IssuerPaths from a manifest string
# ---------------------------------------------------------------------------

def _paths_from_manifest(tmp_path: Path, manifest_text: str, subdir: str = "secrets") -> IssuerPaths:
    manifest_path = tmp_path / "service_identities.yaml"
    manifest_path.write_text(manifest_text)
    return IssuerPaths(secrets_dir=tmp_path / subdir, manifest_path=manifest_path)


# ---------------------------------------------------------------------------
# Happy path — byo_intermediate with customer root provided
# ---------------------------------------------------------------------------

class TestByoIntermediateHappyPath:
    def test_bootstrap_with_root_cert_writes_trust_bundle(self, tmp_path, customer_pki):
        """ca_root.crt should be the CUSTOMER ROOT cert (not intermediate)."""
        paths = _paths_from_manifest(
            tmp_path,
            _make_byo_manifest(
                customer_pki["int_cert_path"],
                customer_pki["int_key_path"],
                root_cert_path=customer_pki["root_cert_path"],
            ),
        )
        bootstrap(paths)

        assert paths.root_cert.exists()
        assert paths.intermediate_cert.exists()
        assert paths.intermediate_key.exists()
        assert not paths.root_key.exists(), "Customer root private key must NOT be written"

        written_root = x509.load_pem_x509_certificate(paths.root_cert.read_bytes())
        assert written_root.subject == customer_pki["root_cert"].subject, (
            f"ca_root.crt subject should be customer root "
            f"({customer_pki['root_cert'].subject.rfc4514_string()!r}) "
            f"but got {written_root.subject.rfc4514_string()!r}"
        )

    def test_bootstrap_intermediate_matches_customer(self, tmp_path, customer_pki):
        """ca_intermediate.crt should be the customer intermediate cert verbatim."""
        paths = _paths_from_manifest(
            tmp_path,
            _make_byo_manifest(
                customer_pki["int_cert_path"],
                customer_pki["int_key_path"],
                root_cert_path=customer_pki["root_cert_path"],
            ),
        )
        bootstrap(paths)

        written_int = x509.load_pem_x509_certificate(paths.intermediate_cert.read_bytes())
        assert written_int.serial_number == customer_pki["int_cert"].serial_number

    def test_bootstrap_leaf_signed_by_customer_intermediate(self, tmp_path, customer_pki):
        """Leaf cert issuer must be the customer intermediate, not Yashigani-generated."""
        paths = _paths_from_manifest(
            tmp_path,
            _make_byo_manifest(
                customer_pki["int_cert_path"],
                customer_pki["int_key_path"],
                root_cert_path=customer_pki["root_cert_path"],
            ),
        )
        bootstrap(paths)

        leaf_bundle = paths.leaf_cert("gateway").read_bytes()
        certs = x509.load_pem_x509_certificates(leaf_bundle)
        assert len(certs) == 2, "Leaf file should be leaf || intermediate bundle"
        leaf, bundled_int = certs

        assert leaf.issuer == customer_pki["int_cert"].subject, (
            f"Leaf issuer should be customer intermediate "
            f"({customer_pki['int_cert'].subject.rfc4514_string()!r}) "
            f"but got {leaf.issuer.rfc4514_string()!r}"
        )

    def test_bootstrap_leaf_cryptographic_chain_to_customer_root(self, tmp_path, customer_pki):
        """Leaf cert signature must verify against customer intermediate."""
        paths = _paths_from_manifest(
            tmp_path,
            _make_byo_manifest(
                customer_pki["int_cert_path"],
                customer_pki["int_key_path"],
                root_cert_path=customer_pki["root_cert_path"],
            ),
        )
        bootstrap(paths)

        leaf_bundle = paths.leaf_cert("gateway").read_bytes()
        leaf = x509.load_pem_x509_certificates(leaf_bundle)[0]

        # Cryptographic: leaf must be directly issued by customer intermediate
        leaf.verify_directly_issued_by(customer_pki["int_cert"])  # raises on failure

    def test_bootstrap_issues_leaves_for_all_live_services(self, tmp_path, customer_pki):
        paths = _paths_from_manifest(
            tmp_path,
            _make_byo_manifest(
                customer_pki["int_cert_path"],
                customer_pki["int_key_path"],
                root_cert_path=customer_pki["root_cert_path"],
            ),
        )
        hashes = bootstrap(paths)
        assert set(hashes.keys()) == {"gateway", "backoffice"}
        assert paths.leaf_cert("gateway").exists()
        assert paths.leaf_cert("backoffice").exists()

    def test_bootstrap_populates_manifest_token_hashes(self, tmp_path, customer_pki):
        """bootstrap_token_sha256 must be written back to the manifest."""
        from yashigani.pki.identity import load_manifest
        paths = _paths_from_manifest(
            tmp_path,
            _make_byo_manifest(
                customer_pki["int_cert_path"],
                customer_pki["int_key_path"],
                root_cert_path=customer_pki["root_cert_path"],
            ),
        )
        bootstrap(paths)
        reloaded = load_manifest(str(paths.manifest_path))
        gw = reloaded.get("gateway")
        assert gw.bootstrap_token_sha256
        assert len(gw.bootstrap_token_sha256) == 64

    def test_rotate_leaves_after_byo_bootstrap(self, tmp_path, customer_pki):
        """rotate_leaves() reads the written intermediate — must still work after BYO bootstrap."""
        paths = _paths_from_manifest(
            tmp_path,
            _make_byo_manifest(
                customer_pki["int_cert_path"],
                customer_pki["int_key_path"],
                root_cert_path=customer_pki["root_cert_path"],
            ),
        )
        bootstrap(paths)

        leaf_before = paths.leaf_cert("gateway").read_bytes()
        rotated = rotate_leaves(paths)
        assert set(rotated) == {"gateway", "backoffice"}
        leaf_after = paths.leaf_cert("gateway").read_bytes()
        assert leaf_after != leaf_before, "rotate_leaves should produce a new leaf cert"

        # New leaf still signed by customer intermediate
        new_leaf = x509.load_pem_x509_certificates(leaf_after)[0]
        new_leaf.verify_directly_issued_by(customer_pki["int_cert"])  # raises on failure


# ---------------------------------------------------------------------------
# Short-chain: no root cert provided — intermediate becomes trust anchor
# ---------------------------------------------------------------------------

class TestByoIntermediateShortChain:
    def test_bootstrap_without_root_uses_intermediate_as_trust_anchor(self, tmp_path, customer_pki):
        """When root cert is not provided, ca_root.crt = customer intermediate cert."""
        paths = _paths_from_manifest(
            tmp_path,
            _make_byo_manifest(
                customer_pki["int_cert_path"],
                customer_pki["int_key_path"],
                root_cert_path=None,  # no root
            ),
        )
        bootstrap(paths)

        assert paths.root_cert.exists()
        written_root = x509.load_pem_x509_certificate(paths.root_cert.read_bytes())
        # Trust anchor should be the intermediate itself
        assert written_root.serial_number == customer_pki["int_cert"].serial_number, (
            "Without root cert provided, ca_root.crt should be the intermediate cert"
        )

    def test_bootstrap_short_chain_leaves_issued(self, tmp_path, customer_pki):
        paths = _paths_from_manifest(
            tmp_path,
            _make_byo_manifest(
                customer_pki["int_cert_path"],
                customer_pki["int_key_path"],
                root_cert_path=None,
            ),
        )
        hashes = bootstrap(paths)
        assert set(hashes.keys()) == {"gateway", "backoffice"}


# ---------------------------------------------------------------------------
# Regression: yashigani_generated mode unchanged
# ---------------------------------------------------------------------------

class TestYashiganiGeneratedRegression:
    def test_yashigani_generated_still_works(self, tmp_path):
        """After adding BYO branch, yashigani_generated must still produce a self-signed root."""
        paths = _paths_from_manifest(tmp_path, _make_ysg_manifest())
        bootstrap(paths)

        assert paths.root_cert.exists()
        assert paths.root_key.exists()  # key IS written in yashigani_generated mode

        root = x509.load_pem_x509_certificate(paths.root_cert.read_bytes())
        cn = root.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert "Yashigani" in cn, f"Expected Yashigani root CN, got {cn!r}"

    def test_yashigani_generated_refuses_overwrite(self, tmp_path):
        paths = _paths_from_manifest(tmp_path, _make_ysg_manifest())
        bootstrap(paths)
        with pytest.raises(RuntimeError, match="already exists"):
            bootstrap(paths)


# ---------------------------------------------------------------------------
# byo_root mode — not implemented in v2.24.0
# ---------------------------------------------------------------------------

class TestByoRootNotImplemented:
    def test_byo_root_raises_clear_error(self, tmp_path):
        paths = _paths_from_manifest(tmp_path, _make_byo_root_manifest())
        with pytest.raises(RuntimeError, match="byo_root is not supported"):
            bootstrap(paths)

    def test_byo_root_error_mentions_byo_intermediate(self, tmp_path):
        paths = _paths_from_manifest(tmp_path, _make_byo_root_manifest())
        with pytest.raises(RuntimeError, match="byo_intermediate"):
            bootstrap(paths)


# ---------------------------------------------------------------------------
# Guard: refuse to overwrite existing BYO intermediate
# ---------------------------------------------------------------------------

class TestByoIntermediateOverwriteGuard:
    def test_refuses_overwrite_existing_intermediate(self, tmp_path, customer_pki):
        paths = _paths_from_manifest(
            tmp_path,
            _make_byo_manifest(
                customer_pki["int_cert_path"],
                customer_pki["int_key_path"],
                root_cert_path=customer_pki["root_cert_path"],
            ),
        )
        bootstrap(paths)
        with pytest.raises(RuntimeError, match="already exists"):
            bootstrap(paths)


# ---------------------------------------------------------------------------
# Validation error cases (_load_byo_intermediate)
# ---------------------------------------------------------------------------

class TestByoIntermediateValidation:
    def _paths_for(self, tmp_path: Path, int_cert: Path, int_key: Path,
                   root_cert: Optional[Path] = None) -> IssuerPaths:
        return _paths_from_manifest(
            tmp_path,
            _make_byo_manifest(int_cert, int_key, root_cert),
        )

    def test_missing_intermediate_cert(self, tmp_path, customer_pki):
        bad_cert = tmp_path / "nonexistent.crt"
        paths = self._paths_for(tmp_path, bad_cert, customer_pki["int_key_path"])
        with pytest.raises(RuntimeError, match="not found"):
            bootstrap(paths)

    def test_missing_intermediate_key(self, tmp_path, customer_pki):
        bad_key = tmp_path / "nonexistent.key"
        paths = self._paths_for(tmp_path, customer_pki["int_cert_path"], bad_key)
        with pytest.raises(RuntimeError, match="not found"):
            bootstrap(paths)

    def test_mismatched_key_cert_pair(self, tmp_path, customer_pki):
        # Generate a different key for the same cert — pair mismatch
        other_key = _gen_ec_key()
        other_key_path = tmp_path / "other.key"
        other_key_path.write_bytes(_pem_key(other_key))
        paths = self._paths_for(tmp_path, customer_pki["int_cert_path"], other_key_path)
        with pytest.raises(RuntimeError, match="matching pair"):
            bootstrap(paths)

    def test_expired_intermediate_cert(self, tmp_path, customer_pki):
        root_key = customer_pki["root_key"]
        root_cert = customer_pki["root_cert"]
        int_key = _gen_ec_key()
        # notAfter in the past
        expired_int = _make_intermediate_ca(
            root_cert, root_key, int_key,
            not_after_offset=_dt.timedelta(seconds=-1),
        )
        cert_path = tmp_path / "expired_int.crt"
        key_path = tmp_path / "expired_int.key"
        cert_path.write_bytes(_pem_cert(expired_int))
        key_path.write_bytes(_pem_key(int_key))
        paths = self._paths_for(tmp_path, cert_path, key_path)
        with pytest.raises(RuntimeError, match="expired"):
            bootstrap(paths)

    def test_not_yet_valid_intermediate_cert(self, tmp_path, customer_pki):
        root_key = customer_pki["root_key"]
        root_cert = customer_pki["root_cert"]
        int_key = _gen_ec_key()
        future_int = _make_intermediate_ca(
            root_cert, root_key, int_key,
            not_before_offset=_dt.timedelta(days=10),  # notBefore in the future
        )
        cert_path = tmp_path / "future_int.crt"
        key_path = tmp_path / "future_int.key"
        cert_path.write_bytes(_pem_cert(future_int))
        key_path.write_bytes(_pem_key(int_key))
        paths = self._paths_for(tmp_path, cert_path, key_path)
        with pytest.raises(RuntimeError, match="not yet valid"):
            bootstrap(paths)

    def test_non_ca_cert_rejected(self, tmp_path, customer_pki):
        """A leaf cert (basicConstraints CA:FALSE) must be rejected."""
        root_key = customer_pki["root_key"]
        root_cert = customer_pki["root_cert"]
        int_key = _gen_ec_key()
        leaf_as_int = _make_intermediate_ca(
            root_cert, root_key, int_key, ca_true=False
        )
        cert_path = tmp_path / "not_ca.crt"
        key_path = tmp_path / "not_ca.key"
        cert_path.write_bytes(_pem_cert(leaf_as_int))
        key_path.write_bytes(_pem_key(int_key))
        paths = self._paths_for(tmp_path, cert_path, key_path)
        with pytest.raises(RuntimeError, match="CA:TRUE"):
            bootstrap(paths)

    def test_missing_basic_constraints_rejected(self, tmp_path, customer_pki):
        root_key = customer_pki["root_key"]
        root_cert = customer_pki["root_cert"]
        int_key = _gen_ec_key()
        no_bc = _make_intermediate_ca(
            root_cert, root_key, int_key, include_basic_constraints=False
        )
        cert_path = tmp_path / "no_bc.crt"
        key_path = tmp_path / "no_bc.key"
        cert_path.write_bytes(_pem_cert(no_bc))
        key_path.write_bytes(_pem_key(int_key))
        paths = self._paths_for(tmp_path, cert_path, key_path)
        with pytest.raises(RuntimeError, match="BasicConstraints"):
            bootstrap(paths)

    def test_missing_key_usage_rejected(self, tmp_path, customer_pki):
        root_key = customer_pki["root_key"]
        root_cert = customer_pki["root_cert"]
        int_key = _gen_ec_key()
        no_ku = _make_intermediate_ca(
            root_cert, root_key, int_key, include_key_usage=False
        )
        cert_path = tmp_path / "no_ku.crt"
        key_path = tmp_path / "no_ku.key"
        cert_path.write_bytes(_pem_cert(no_ku))
        key_path.write_bytes(_pem_key(int_key))
        paths = self._paths_for(tmp_path, cert_path, key_path)
        with pytest.raises(RuntimeError, match="KeyUsage"):
            bootstrap(paths)

    def test_key_cert_sign_false_rejected(self, tmp_path, customer_pki):
        root_key = customer_pki["root_key"]
        root_cert = customer_pki["root_cert"]
        int_key = _gen_ec_key()
        no_kcs = _make_intermediate_ca(
            root_cert, root_key, int_key, key_cert_sign=False
        )
        cert_path = tmp_path / "no_kcs.crt"
        key_path = tmp_path / "no_kcs.key"
        cert_path.write_bytes(_pem_cert(no_kcs))
        key_path.write_bytes(_pem_key(int_key))
        paths = self._paths_for(tmp_path, cert_path, key_path)
        with pytest.raises(RuntimeError, match="keyCertSign"):
            bootstrap(paths)

    def test_chain_mismatch_root_rejected(self, tmp_path, customer_pki):
        """Intermediate not signed by the supplied root → chain validation fails."""
        # Generate an unrelated root
        other_root_key = _gen_ec_key()
        other_root = _make_root_ca(other_root_key, cn="Other Root CA")
        other_root_path = tmp_path / "other_root.crt"
        other_root_path.write_bytes(_pem_cert(other_root))

        # Customer intermediate signed by THEIR root, but we supply OTHER root
        paths = self._paths_for(
            tmp_path,
            customer_pki["int_cert_path"],
            customer_pki["int_key_path"],
            root_cert=other_root_path,
        )
        with pytest.raises(RuntimeError, match="cryptographic chain check"):
            bootstrap(paths)

    def test_missing_root_cert_file_rejected(self, tmp_path, customer_pki):
        nonexistent_root = tmp_path / "no_root.crt"
        paths = self._paths_for(
            tmp_path,
            customer_pki["int_cert_path"],
            customer_pki["int_key_path"],
            root_cert=nonexistent_root,
        )
        with pytest.raises(RuntimeError, match="root cert not found"):
            bootstrap(paths)

    def test_rsa_key_rejected(self, tmp_path, customer_pki):
        """Yashigani's issuer only supports EC keys for leaf signing; RSA intermediate must be rejected."""
        root_key = customer_pki["root_key"]
        root_cert = customer_pki["root_cert"]

        # Build an intermediate with an RSA key using a raw builder (not our helper, which uses EC)
        rsa_key = _gen_rsa_key(3072)
        now = _dt.datetime.now(_dt.timezone.utc)
        rsa_int_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RSA Intermediate")]))
            .issuer_name(root_cert.subject)
            .public_key(rsa_key.public_key())
            .serial_number(_serial())
            .not_valid_before(now - _dt.timedelta(minutes=5))
            .not_valid_after(now + _dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(root_key, hashes.SHA256())
        )

        cert_path = tmp_path / "rsa_int.crt"
        key_path = tmp_path / "rsa_int.key"
        cert_path.write_bytes(_pem_cert(rsa_int_cert))
        key_path.write_bytes(_pem_key(rsa_key))

        paths = self._paths_for(tmp_path, cert_path, key_path)
        with pytest.raises(RuntimeError, match="EC private key"):
            bootstrap(paths)
