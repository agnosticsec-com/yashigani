"""Tests for audit.log_safety.safe_for_log (ASVS 16.6.1)."""

from yashigani.audit.log_safety import safe_for_log


def test_passthrough_on_safe_string():
    assert safe_for_log("admin@example.com") == "admin@example.com"


def test_newline_escaped():
    # attacker-controlled username with forged log-line separator
    assert safe_for_log("admin\nFAKE: bypassed_auth") == "admin\\nFAKE: bypassed_auth"


def test_ansi_escape_stripped():
    # attacker-controlled username with terminal escape (colour override)
    assert safe_for_log("admin\x1b[31;1mHACKER") == "admin\\x1bHACKER[31;1mHACKER" or \
           "\\x1b" in safe_for_log("admin\x1b[31;1mHACKER")


def test_carriage_return_escaped():
    assert safe_for_log("x\ry") == "x\\ry"


def test_tab_preserved():
    # Tabs are intentionally NOT escaped — they don't forge log-line
    # boundaries and are common in legitimate input. Regex skips 0x09.
    assert safe_for_log("a\tb") == "a\tb"


def test_null_byte_escaped():
    assert safe_for_log("admin\x00injected") == "admin\\x00injected"


def test_truncation():
    # Oversized values don't amplify log volume
    big = "a" * 600
    result = safe_for_log(big)
    assert len(result) <= 600
    assert "[..88 more]" in result


def test_coerces_non_string():
    assert safe_for_log(42) == "42"
    assert safe_for_log(None) == "None"
