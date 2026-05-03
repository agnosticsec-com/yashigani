#!/usr/bin/env python3
"""
check_partition_helm_parity.py — CI parity gate for partition_maintenance.py
=============================================================================
Last updated: 2026-05-02T09:00:00+01:00

Asserts that the copy of partition_maintenance.py embedded in
helm/yashigani/templates/configmaps.yaml is byte-identical to
scripts/partition_maintenance.py for all SQL-bearing lines and all
security-critical functions.

Run as a pre-commit hook or CI step:
    python tools/check_partition_helm_parity.py

Exit 0 = PASS.
Exit 1 = FAIL — lists all differing lines with context.

Background (Lu re-audit YCS-20260502-v2.23.1-CWE89-reaudit-001, follow-up #3):
  Any drift in _quote_ident, _SAFE_IDENT_RE, _PARTITIONED_TABLES, or the
  CREATE TABLE DDL string between the source and the helm-embedded copy would
  silently erode the CWE-89 / YSG-RISK-001 controls for Kubernetes deployments
  (which mount the script from the ConfigMap, not from the container image).
  This tool makes that drift detectable in CI rather than at audit time.
"""
from __future__ import annotations

import re
import sys
import textwrap
from pathlib import Path

# ---------------------------------------------------------------------------
# Repo root detection (works from any CWD as long as the file lives in tools/)
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
_SOURCE = _REPO_ROOT / "scripts" / "partition_maintenance.py"
_CONFIGMAP = _REPO_ROOT / "helm" / "yashigani" / "templates" / "configmaps.yaml"

# ---------------------------------------------------------------------------
# Lines / blocks that are SECURITY-CRITICAL and must be byte-identical.
# These are matched as substrings in the source and checked to be present
# verbatim (modulo leading whitespace introduced by YAML indentation) in
# the embedded copy.
#
# Items here are drawn from Lu re-audit Q1–Q4 evidence table.
# ---------------------------------------------------------------------------
CRITICAL_LINES = [
    # Identifier allowlist regex
    r'_SAFE_IDENT_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")',
    # Core of _quote_ident — the allowlist check
    "if not _SAFE_IDENT_RE.match(name):",
    # Hardcoded table allowlist
    '_PARTITIONED_TABLES = ["audit_events", "inference_events"]',
    # DDL statement — all four SQL-bearing lines
    'f"CREATE TABLE IF NOT EXISTS {q_name}"',
    'f" PARTITION OF {q_table}"',
    "f\" FOR VALUES FROM ('{start.isoformat()}') TO ('{end.isoformat()}')\"",
    # Identifier quoting at call site
    "q_name = _quote_ident(name)",
    "q_table = _quote_ident(table)",
]

# Lines that are intentionally allowed to differ (cosmetic).
# Matched as prefix-stripped and stripped strings.
ALLOWED_DIFFS = {
    # Timestamp in docstring — Lu follow-up #2 (now fixed, but keep as safety)
    "Last updated:",
    # YAML-only comment
    "# Rebuild DSN without the extracted params",
}


def _strip_yaml_indent(line: str) -> str:
    """Remove leading spaces introduced by YAML block-scalar indentation.
    The configmap content is indented by 4 spaces (2-space base + 2-space data)."""
    return line.lstrip()


def _extract_embedded_script(configmap_text: str) -> list[str]:
    """Extract the embedded partition_maintenance.py from the ConfigMap YAML.

    Looks for the 'partition_maintenance.py: |' key and returns all indented
    lines that follow it until the next unindented key or end of file.
    """
    lines = configmap_text.splitlines()
    in_script = False
    script_lines: list[str] = []
    # The YAML block scalar is indented by at least 4 spaces
    for line in lines:
        if "partition_maintenance.py: |" in line:
            in_script = True
            continue
        if in_script:
            # End of block scalar: a line with no leading whitespace that
            # contains YAML structure (or end of file)
            stripped = line.lstrip()
            leading = len(line) - len(stripped)
            if leading == 0 and stripped and not stripped.startswith("#"):
                break
            script_lines.append(line)
    return script_lines


def check_critical_lines(
    source_text: str, embedded_lines: list[str]
) -> list[str]:
    """Verify every CRITICAL_LINE from the source appears verbatim (modulo
    YAML indent) in the embedded copy. Returns a list of failure messages."""
    failures: list[str] = []
    embedded_stripped = [_strip_yaml_indent(l) for l in embedded_lines]
    embedded_text = "\n".join(embedded_stripped)

    for critical in CRITICAL_LINES:
        if critical not in source_text:
            failures.append(
                f"CRITICAL LINE NOT FOUND IN SOURCE — tool out of sync:\n"
                f"  {critical!r}\n"
                f"  Update CRITICAL_LINES in {__file__} to match current source."
            )
            continue
        if critical not in embedded_text:
            failures.append(
                f"CRITICAL LINE MISSING FROM HELM EMBEDDED COPY:\n"
                f"  {critical!r}\n"
                f"  Ensure helm/yashigani/templates/configmaps.yaml embedded\n"
                f"  partition_maintenance.py is up to date."
            )
    return failures


def check_no_new_sql_fstrings(embedded_lines: list[str]) -> list[str]:
    """Detect any f-string that interpolates a variable directly into a SQL
    keyword context in the embedded copy.

    Pattern: any conn.execute / fetchval / fetchrow / fetch containing {var}
    where var is NOT q_name / q_table / start.isoformat() / end.isoformat().
    This guards against a future editor introducing a new raw-interpolation
    call site in the embedded copy that doesn't exist in source."""
    failures: list[str] = []
    sql_call_re = re.compile(r"await\s+conn\.(execute|fetchval|fetchrow|fetch|executemany)")
    fstring_var_re = re.compile(r"\{([^}]+)\}")

    ALLOWED_INTERP = {"q_name", "q_table", "start.isoformat()", "end.isoformat()"}

    in_sql_call = False
    for i, raw_line in enumerate(embedded_lines, 1):
        line = _strip_yaml_indent(raw_line)
        if sql_call_re.search(line):
            in_sql_call = True
        if in_sql_call:
            for m in fstring_var_re.finditer(line):
                token = m.group(1).strip()
                if token not in ALLOWED_INTERP:
                    failures.append(
                        f"UNEXPECTED f-string interpolation in SQL context "
                        f"at embedded line {i}:\n"
                        f"  {line.rstrip()}\n"
                        f"  Token: {token!r} — must use _quote_ident or isoformat()"
                    )
            # Simple heuristic: SQL call ends when we see a closing paren on
            # its own or a new statement.
            if line.strip() in {")", "):", ""}:
                in_sql_call = False
    return failures


def main() -> int:
    if not _SOURCE.exists():
        print(f"ERROR: source not found: {_SOURCE}", file=sys.stderr)
        return 1
    if not _CONFIGMAP.exists():
        print(f"ERROR: configmap not found: {_CONFIGMAP}", file=sys.stderr)
        return 1

    source_text = _SOURCE.read_text(encoding="utf-8")
    configmap_text = _CONFIGMAP.read_text(encoding="utf-8")
    embedded_lines = _extract_embedded_script(configmap_text)

    if not embedded_lines:
        print(
            "ERROR: Could not extract embedded partition_maintenance.py "
            "from configmaps.yaml — check for YAML structural changes.",
            file=sys.stderr,
        )
        return 1

    failures: list[str] = []
    failures.extend(check_critical_lines(source_text, embedded_lines))
    failures.extend(check_no_new_sql_fstrings(embedded_lines))

    if failures:
        print("FAIL — partition_maintenance.py helm parity check:")
        for f in failures:
            print(textwrap.indent(f, "  "))
        print(
            f"\n{len(failures)} issue(s) found. "
            "Sync helm/yashigani/templates/configmaps.yaml with "
            "scripts/partition_maintenance.py and re-run."
        )
        return 1

    print(
        f"PASS — {len(CRITICAL_LINES)} critical lines verified in helm embedded copy. "
        f"No unexpected SQL f-string interpolations found."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
