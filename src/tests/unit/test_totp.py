"""
Tests for yashigani.auth.totp.

Covers:
  - generate_totp_secret produces valid base32 secret
  - generate_provisioning returns TotpProvisioning with uri
  - generate_recovery_code_set count and format
  - verify_totp happy path (using pyotp)
  - verify_totp rejects wrong codes
  - verify_recovery_code happy path
  - verify_recovery_code rejects wrong codes
  - codes_remaining count
  - Recovery code format is constant (change detection for IC-11)
"""
from __future__ import annotations

import re

import pytest


def _import_totp():
    try:
        from yashigani.auth.totp import (
            TotpProvisioning,
            RecoveryCodeSet,
            _RECOVERY_CODE_COUNT,
            _RECOVERY_CODE_FORMAT,
            generate_totp_secret,
            generate_provisioning,
            generate_recovery_code_set,
            verify_totp,
            verify_recovery_code,
            codes_remaining,
        )
        return (
            TotpProvisioning, RecoveryCodeSet, _RECOVERY_CODE_COUNT, _RECOVERY_CODE_FORMAT,
            generate_totp_secret, generate_provisioning, generate_recovery_code_set,
            verify_totp, verify_recovery_code, codes_remaining,
        )
    except ImportError as exc:
        pytest.skip(f"totp module not importable: {exc}")


class TestRecoveryCodeConstants:
    def test_recovery_code_count_is_8(self):
        _, _, count, fmt, *_ = _import_totp()
        assert count == 8, (
            "IC-11: _RECOVERY_CODE_COUNT changed — existing recovery codes in DB are now invalid. "
            "Add a migration to regenerate codes before changing this constant."
        )

    def test_recovery_code_format_stable(self):
        _, _, _, fmt, *_ = _import_totp()
        assert fmt == "{:04X}-{:04X}-{:04X}", (
            "IC-11: _RECOVERY_CODE_FORMAT changed — existing recovery codes in DB are now invalid. "
            "Add a migration to regenerate codes before changing this constant."
        )


class TestGenerateTotpSecret:
    def test_returns_string(self):
        (_, _, _, _, generate_totp_secret, *_) = _import_totp()
        secret = generate_totp_secret()
        assert isinstance(secret, str)

    def test_is_valid_base32(self):
        import base64
        (_, _, _, _, generate_totp_secret, *_) = _import_totp()
        secret = generate_totp_secret()
        # Base32 characters only (A-Z, 2-7, optional padding)
        try:
            base64.b32decode(secret.upper().replace("-", "").replace(" ", "") + "===")
        except Exception as exc:
            pytest.fail(f"Secret is not valid base32: {exc}")

    def test_uniqueness(self):
        (_, _, _, _, generate_totp_secret, *_) = _import_totp()
        secrets = {generate_totp_secret() for _ in range(10)}
        assert len(secrets) == 10


class TestGenerateProvisioning:
    def test_provisioning_has_uri(self):
        (TotpProvisioning, _, _, _, _, generate_provisioning, *_) = _import_totp()
        prov = generate_provisioning(username="alice", issuer="Yashigani")
        assert hasattr(prov, "uri") or hasattr(prov, "provisioning_uri")

    def test_provisioning_has_secret(self):
        (TotpProvisioning, _, _, _, _, generate_provisioning, *_) = _import_totp()
        prov = generate_provisioning(username="alice", issuer="Yashigani")
        assert hasattr(prov, "secret")
        assert prov.secret


class TestGenerateRecoveryCodeSet:
    def test_correct_count(self):
        (_, RecoveryCodeSet, count, _, _, _, generate_recovery_code_set, *_) = _import_totp()
        rcs = generate_recovery_code_set()
        assert len(rcs.codes) == count

    def test_code_format_matches_constant(self):
        import re
        (_, _, _, _, _, _, generate_recovery_code_set, *_) = _import_totp()
        rcs = generate_recovery_code_set()
        pattern = re.compile(r"^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$")
        for code in rcs.codes:
            assert pattern.match(code), f"Code {code!r} doesn't match expected format"

    def test_codes_are_unique(self):
        (_, _, _, _, _, _, generate_recovery_code_set, *_) = _import_totp()
        rcs = generate_recovery_code_set()
        assert len(set(rcs.codes)) == len(rcs.codes)


class TestVerifyTotp:
    def test_valid_code_accepted(self):
        try:
            import pyotp
        except ImportError:
            pytest.skip("pyotp not installed")

        (_, _, _, _, generate_totp_secret, _, _, verify_totp, *_) = _import_totp()
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        current_code = totp.now()
        assert verify_totp(secret=secret, code=current_code) is True

    def test_wrong_code_rejected(self):
        (_, _, _, _, generate_totp_secret, _, _, verify_totp, *_) = _import_totp()
        secret = generate_totp_secret()
        assert verify_totp(secret=secret, code="000000") is False

    def test_empty_code_rejected(self):
        (_, _, _, _, generate_totp_secret, _, _, verify_totp, *_) = _import_totp()
        secret = generate_totp_secret()
        assert verify_totp(secret=secret, code="") is False


class TestVerifyRecoveryCode:
    def test_valid_code_accepted(self):
        (_, _, _, _, _, _, generate_recovery_code_set, _, verify_recovery_code, codes_remaining) = _import_totp()
        rcs = generate_recovery_code_set()
        first_code = list(rcs.codes)[0]
        result = verify_recovery_code(code_set=rcs, provided=first_code)
        assert result is True

    def test_wrong_code_rejected(self):
        (_, _, _, _, _, _, generate_recovery_code_set, _, verify_recovery_code, _) = _import_totp()
        rcs = generate_recovery_code_set()
        assert verify_recovery_code(code_set=rcs, provided="0000-0000-0000") is False

    def test_codes_remaining_decrements(self):
        (_, _, count, _, _, _, generate_recovery_code_set, _, verify_recovery_code, codes_remaining) = _import_totp()
        rcs = generate_recovery_code_set()
        initial = codes_remaining(rcs)
        assert initial == count
        first_code = list(rcs.codes)[0]
        verify_recovery_code(code_set=rcs, provided=first_code)
        assert codes_remaining(rcs) == initial - 1
