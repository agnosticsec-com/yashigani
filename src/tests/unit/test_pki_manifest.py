"""Tests for yashigani.pki.identity — manifest loader + tamper detection."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from yashigani.pki.identity import (
    ManifestError,
    TamperError,
    current_service,
    load_manifest,
    tier_at_least,
)


# ─────────────────────────────────────────────────────────────────────────────
# Manifest fixtures
# ─────────────────────────────────────────────────────────────────────────────

_MINIMAL_MANIFEST = """\
schema_version: 1
services:
  - name: gateway
    dns_sans: [gateway, gateway.internal]
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
  - name: legacy-off
    dns_sans: [legacy-off]
    purpose: "decommissioned"
    mtls_capable: true
    bootstrap_token_sha256: ""
    revoked: true
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
ca_source:
  mode: yashigani_generated
  byo: {}
  remote_acme: {}
  min_license_tier:
    yashigani_generated: community
    byo_intermediate: professional
    byo_root: enterprise
    remote_acme: enterprise
"""


@pytest.fixture
def manifest_path(tmp_path: Path) -> Path:
    p = tmp_path / "service_identities.yaml"
    p.write_text(_MINIMAL_MANIFEST)
    return p


# ─────────────────────────────────────────────────────────────────────────────
# Manifest loader
# ─────────────────────────────────────────────────────────────────────────────

def test_load_manifest_parses_services(manifest_path: Path):
    m = load_manifest(str(manifest_path))
    assert m.schema_version == 1
    assert len(m.services) == 3
    names = [s.name for s in m.services]
    assert names == ["gateway", "backoffice", "legacy-off"]


def test_live_services_excludes_revoked(manifest_path: Path):
    m = load_manifest(str(manifest_path))
    live = [s.name for s in m.live_services()]
    assert "legacy-off" not in live
    assert "gateway" in live


def test_lookup_missing_service_raises(manifest_path: Path):
    m = load_manifest(str(manifest_path))
    with pytest.raises(ManifestError, match="rogue service"):
        m.get("unknown-attacker")


def test_cert_policy_defaults(manifest_path: Path):
    m = load_manifest(str(manifest_path))
    assert m.cert_policy.root_lifetime_years_default == 10
    assert m.cert_policy.intermediate_lifetime_days_default == 180
    assert m.cert_policy.leaf_lifetime_days_default == 90


def test_cert_policy_clamping(manifest_path: Path):
    m = load_manifest(str(manifest_path))
    # Below the min — clamped up
    assert m.cert_policy.clamp_leaf(1) == 30
    # Above the max — clamped down
    assert m.cert_policy.clamp_leaf(9999) == 90
    # Within — unchanged
    assert m.cert_policy.clamp_leaf(60) == 60

    assert m.cert_policy.clamp_intermediate(10) == 90
    assert m.cert_policy.clamp_intermediate(9999) == 365

    assert m.cert_policy.clamp_root(1) == 5
    assert m.cert_policy.clamp_root(999) == 20


def test_ca_source_mode_default(manifest_path: Path):
    m = load_manifest(str(manifest_path))
    assert m.ca_source.mode == "yashigani_generated"
    assert m.ca_source.requires_license_tier() == "community"


def test_load_manifest_missing_file_raises(tmp_path: Path):
    with pytest.raises(ManifestError, match="not found"):
        load_manifest(str(tmp_path / "nope.yaml"))


def test_load_manifest_bad_schema_version(tmp_path: Path):
    p = tmp_path / "bad.yaml"
    p.write_text("schema_version: 99\nservices: [{name: gateway}]\n")
    with pytest.raises(ManifestError, match="schema_version"):
        load_manifest(str(p))


def test_load_manifest_rejects_duplicate_service_names(tmp_path: Path):
    p = tmp_path / "dup.yaml"
    p.write_text(
        _MINIMAL_MANIFEST.replace("- name: backoffice", "- name: gateway")
    )
    with pytest.raises(ManifestError, match="duplicate"):
        load_manifest(str(p))


def test_load_manifest_rejects_invalid_cert_policy(tmp_path: Path):
    # Default outside min/max
    bad = _MINIMAL_MANIFEST.replace(
        "leaf_lifetime_days_default: 90",
        "leaf_lifetime_days_default: 500",
    )
    p = tmp_path / "bad.yaml"
    p.write_text(bad)
    with pytest.raises(ManifestError, match="leaf default outside"):
        load_manifest(str(p))


# ─────────────────────────────────────────────────────────────────────────────
# current_service() — runtime self-resolution
# ─────────────────────────────────────────────────────────────────────────────

def test_current_service_unknown_rejected(tmp_path: Path, manifest_path: Path, monkeypatch):
    monkeypatch.setenv("YASHIGANI_SERVICE_NAME", "rogue-container")
    monkeypatch.setenv("YASHIGANI_INTERNAL_CA_DIR", str(tmp_path))
    monkeypatch.setenv("YASHIGANI_SERVICE_MANIFEST_PATH", str(manifest_path))
    with pytest.raises(ManifestError, match="rogue"):
        current_service(verify_token=False)


def test_current_service_revoked_rejected(tmp_path: Path, manifest_path: Path, monkeypatch):
    monkeypatch.setenv("YASHIGANI_SERVICE_NAME", "legacy-off")
    monkeypatch.setenv("YASHIGANI_INTERNAL_CA_DIR", str(tmp_path))
    monkeypatch.setenv("YASHIGANI_SERVICE_MANIFEST_PATH", str(manifest_path))
    with pytest.raises(ManifestError, match="revoked"):
        current_service(verify_token=False)


def test_current_service_missing_env_rejected(monkeypatch, manifest_path: Path):
    monkeypatch.delenv("YASHIGANI_SERVICE_NAME", raising=False)
    monkeypatch.setenv("YASHIGANI_SERVICE_MANIFEST_PATH", str(manifest_path))
    with pytest.raises(ManifestError, match="does not know its own identity"):
        current_service(verify_token=False)


def test_current_service_tamper_detection(tmp_path: Path, manifest_path: Path, monkeypatch):
    # Write a token and put its hash into a modified manifest.
    real_token = b"sixteenbyteofentropy000000000001"
    real_sha = hashlib.sha256(real_token).hexdigest()
    modified = _MINIMAL_MANIFEST.replace(
        '- name: gateway\n    dns_sans: [gateway, gateway.internal]\n    purpose: "data plane"\n    mtls_capable: true\n    bootstrap_token_sha256: ""',
        f'- name: gateway\n    dns_sans: [gateway, gateway.internal]\n    purpose: "data plane"\n    mtls_capable: true\n    bootstrap_token_sha256: "{real_sha}"',
    )
    mp = tmp_path / "manifest.yaml"
    mp.write_text(modified)

    # Write the WRONG token to disk — must trigger TamperError.
    (tmp_path / "gateway_bootstrap_token").write_bytes(b"wrong_token_sixteen_bytes_of_00")

    monkeypatch.setenv("YASHIGANI_SERVICE_NAME", "gateway")
    monkeypatch.setenv("YASHIGANI_INTERNAL_CA_DIR", str(tmp_path))
    monkeypatch.setenv("YASHIGANI_SERVICE_MANIFEST_PATH", str(mp))
    with pytest.raises(TamperError, match="mismatch"):
        current_service(verify_token=True)


def test_current_service_tamper_ok_on_match(tmp_path: Path, manifest_path: Path, monkeypatch):
    real_token = b"genuine_token_sixteen_bytes_of01"
    real_sha = hashlib.sha256(real_token).hexdigest()
    modified = _MINIMAL_MANIFEST.replace(
        '- name: gateway\n    dns_sans: [gateway, gateway.internal]\n    purpose: "data plane"\n    mtls_capable: true\n    bootstrap_token_sha256: ""',
        f'- name: gateway\n    dns_sans: [gateway, gateway.internal]\n    purpose: "data plane"\n    mtls_capable: true\n    bootstrap_token_sha256: "{real_sha}"',
    )
    mp = tmp_path / "manifest.yaml"
    mp.write_text(modified)
    (tmp_path / "gateway_bootstrap_token").write_bytes(real_token)

    monkeypatch.setenv("YASHIGANI_SERVICE_NAME", "gateway")
    monkeypatch.setenv("YASHIGANI_INTERNAL_CA_DIR", str(tmp_path))
    monkeypatch.setenv("YASHIGANI_SERVICE_MANIFEST_PATH", str(mp))

    ident = current_service(verify_token=True)
    assert ident.name == "gateway"
    # Cert paths resolve to the secrets dir even if the files don't exist yet.
    assert ident.cert_path and ident.cert_path.name == "gateway_client.crt"
    assert ident.ca_root_path and ident.ca_root_path.name == "ca_root.crt"


# ─────────────────────────────────────────────────────────────────────────────
# Tier gating
# ─────────────────────────────────────────────────────────────────────────────

def test_tier_ordering():
    assert tier_at_least("professional", "community") is True
    assert tier_at_least("professional", "starter") is True
    assert tier_at_least("professional", "professional") is True
    assert tier_at_least("professional", "enterprise") is False
    assert tier_at_least("community", "professional") is False
    assert tier_at_least("garbage", "community") is False
