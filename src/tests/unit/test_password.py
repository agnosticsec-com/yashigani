"""
Tests for yashigani.auth.password.

Covers:
  - Minimum length enforcement (36 chars)
  - hash_password / verify_password roundtrip
  - verify_password returns False for wrong password (no exception)
  - needs_rehash returns bool
  - generate_password length, entropy, no repetition
  - generate_password raises for length < MIN
"""
from __future__ import annotations

import pytest

from yashigani.auth.password import (
    _MIN_PASSWORD_LENGTH,
    generate_password,
    hash_password,
    needs_rehash,
    verify_password,
)


class TestMinPasswordLength:
    def test_min_length_is_36(self):
        """IC-2 regression: gateway admin minimum must be 36 chars (not 34)."""
        assert _MIN_PASSWORD_LENGTH == 36

    def test_hash_rejects_short_password(self):
        short = "a" * (_MIN_PASSWORD_LENGTH - 1)
        with pytest.raises(ValueError, match="at least"):
            hash_password(short)

    def test_hash_accepts_exact_min_length(self):
        pw = "A" * _MIN_PASSWORD_LENGTH
        result = hash_password(pw, check_breach=False)
        assert result.startswith("$argon2")

    def test_hash_accepts_long_password(self):
        pw = "x" * 128
        result = hash_password(pw, check_breach=False)
        assert result.startswith("$argon2")


class TestHashVerify:
    def test_roundtrip(self):
        pw = "correct-horse-battery-staple-plus-extra-chars"
        hashed = hash_password(pw, check_breach=False)
        assert verify_password(pw, hashed) is True

    def test_wrong_password_returns_false(self):
        pw = "correct-horse-battery-staple-plus-extra-chars"
        hashed = hash_password(pw, check_breach=False)
        assert verify_password("wrong" + pw, hashed) is False

    def test_empty_password_returns_false(self):
        pw = "correct-horse-battery-staple-plus-extra-chars"
        hashed = hash_password(pw, check_breach=False)
        assert verify_password("", hashed) is False

    def test_case_sensitive(self):
        pw = "A" * _MIN_PASSWORD_LENGTH
        hashed = hash_password(pw, check_breach=False)
        assert verify_password("a" * _MIN_PASSWORD_LENGTH, hashed) is False

    def test_hash_is_different_each_time(self):
        """Argon2id uses a random salt per hash."""
        pw = "X" * _MIN_PASSWORD_LENGTH
        h1 = hash_password(pw, check_breach=False)
        h2 = hash_password(pw, check_breach=False)
        assert h1 != h2

    def test_needs_rehash_returns_bool(self):
        pw = "Y" * _MIN_PASSWORD_LENGTH
        hashed = hash_password(pw, check_breach=False)
        result = needs_rehash(hashed)
        assert isinstance(result, bool)

    def test_needs_rehash_bad_hash_returns_false(self):
        assert needs_rehash("not_a_real_hash") is False


class TestGeneratePassword:
    def test_default_length(self):
        pw = generate_password()
        assert len(pw) == 36

    def test_custom_length(self):
        pw = generate_password(length=64)
        assert len(pw) == 64

    def test_rejects_length_below_minimum(self):
        with pytest.raises(ValueError, match="at least"):
            generate_password(length=_MIN_PASSWORD_LENGTH - 1)

    def test_generated_password_is_hashable(self):
        pw = generate_password()
        # check_breach=False: avoids a live HIBP network call in unit tests.
        hashed = hash_password(pw, check_breach=False)
        assert verify_password(pw, hashed) is True

    def test_uniqueness(self):
        """Two generated passwords must not be identical."""
        pws = {generate_password() for _ in range(20)}
        assert len(pws) == 20

    def test_alphabet_chars_only(self):
        import string
        alphabet = set(string.ascii_letters + string.digits + "!@#$%^&*()-_=+")
        for _ in range(10):
            pw = generate_password()
            assert all(c in alphabet for c in pw), \
                f"Generated password contains char outside alphabet: {pw!r}"
