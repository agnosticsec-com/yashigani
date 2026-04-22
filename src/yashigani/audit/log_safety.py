"""
Log-injection defence helpers (ASVS 16.6.1, Ava Wave 2 Issue #48).

Python's stdlib logging does not sanitise interpolated strings, so an
attacker-controlled value containing ``\\n``, ANSI escapes, or other
control characters can forge log-line boundaries that confuse SIEM
parsers and on-disk review.

Use :func:`safe_for_log` to sanitise values that come from user input
(usernames, agent names, paths, header values) BEFORE passing them to a
logger. Positional-argument form is still required — the helper
sanitises the string but does not format it.

    logger.info("Agent registered: %s", safe_for_log(agent_name))
"""

from __future__ import annotations

import re

# Strip anything below ASCII 0x20 except horizontal tab (\\t = 0x09), plus the
# DEL character (0x7F) and the C1 control range (0x80-0x9F). Replace each
# stripped byte with a backslash-escape so the substitution is visible in
# the log but cannot forge line boundaries or terminal escape sequences.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f]")

_MAX_LEN = 512  # Prevent log-volume amplification from untrusted strings.


def safe_for_log(value: object) -> str:
    """Return ``value`` as a string safe to include in a log entry.

    * Coerces to str.
    * Replaces every control character (newline, tab not excepted when it
      is being abused in sequence, ANSI escapes, DEL, C1 controls) with
      an escape like ``\\n`` or ``\\x1b`` so the substitution is visible
      but cannot break lines or drive terminal sequences.
    * Truncates to 512 chars with a ``[..N more]`` suffix.

    Idempotent on already-safe strings.
    """
    if not isinstance(value, str):
        value = str(value)

    def _replace(match: re.Match[str]) -> str:
        ch = match.group(0)
        if ch == "\n":
            return "\\n"
        if ch == "\r":
            return "\\r"
        if ch == "\t":
            return "\\t"
        return f"\\x{ord(ch):02x}"

    safe = _CONTROL_CHAR_RE.sub(_replace, value)
    if len(safe) > _MAX_LEN:
        safe = safe[:_MAX_LEN] + f"[..{len(safe) - _MAX_LEN} more]"
    return safe
