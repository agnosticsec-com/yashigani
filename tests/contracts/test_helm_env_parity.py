# Last updated: 2026-05-02T10:00:00+01:00
"""
Helm env-block parity contract tests.

Generalises the 1a6db9f regression where YASHIGANI_DB_DSN_DIRECT was stripped
from the gateway env block after re-templating, while backoffice retained it.
Runtime divergence caused silent migration failures — one service operated
without a direct-postgres path, no loud error surfaced.

Design
------
The test suite uses a DSL expressed as a list of ``EnvParity`` specs. Each spec
asserts that a named env var (or a pattern match) appears in EVERY listed
template file.  Adding a new "must appear everywhere" constraint means adding
one line to ``REQUIRED_ENV_PARITY``.

The templates are parsed as raw text (no Helm rendering required — no tiller /
helm dependency needed in CI). The contract is:

  For every spec in REQUIRED_ENV_PARITY:
    - ``key_name`` must appear as a ``name: <key_name>`` line inside the
      ``env:`` block of the main container in every template listed in
      ``in_templates``.
    - ``value_pattern`` (regex) must match the raw value string on the next
      non-comment, non-blank line after the ``name:`` line. Optional: set to
      None to skip value checking.
    - ``mount_path_pattern`` (regex) must match somewhere in the volumeMounts
      or volume blocks (for cert-path assertions). Optional.

Mutation test
-------------
Run with ``--mutate-dsn-direct`` to temporarily strip YASHIGANI_DB_DSN_DIRECT
from the gateway template before asserting; the tests must fail.  This flag is
only used internally by the ``test_mutation_*`` tests below — they do NOT write
to disk; they patch the in-memory content.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import pytest


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

HELM_DIR = Path(__file__).parent.parent.parent / "helm" / "yashigani" / "templates"

GATEWAY_YAML = HELM_DIR / "gateway.yaml"
BACKOFFICE_YAML = HELM_DIR / "backoffice.yaml"

# ---------------------------------------------------------------------------
# DSL
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnvParity:
    """
    Asserts that ``key_name`` appears in every template in ``in_templates``.

    Parameters
    ----------
    key_name:
        Exact env-var name, e.g. ``YASHIGANI_DB_DSN_DIRECT``.
    in_templates:
        List of template Path objects that must ALL contain this key.
    value_pattern:
        If not None, a regex that must match the value string associated with
        the key.  The value may be on the same line as ``value:`` or on a
        continuation.  Helm expressions like ``$(POSTGRES_PASSWORD)`` are
        included in the raw text and so are matchable.
    mount_path_pattern:
        If not None, a regex that must appear somewhere in the full template
        text (covers volumeMounts + volumes).
    label:
        Human-readable description for failure messages.
    """
    key_name: str
    in_templates: tuple[Path, ...]
    value_pattern: Optional[str] = None
    mount_path_pattern: Optional[str] = None
    label: str = ""

    def __post_init__(self) -> None:
        if not self.label:
            object.__setattr__(self, "label", self.key_name)


# ---------------------------------------------------------------------------
# Contract table
# ---------------------------------------------------------------------------

REQUIRED_ENV_PARITY: list[EnvParity] = [
    # -----------------------------------------------------------------------
    # DB DSN — direct-to-postgres path (regression 1a6db9f)
    # -----------------------------------------------------------------------
    EnvParity(
        key_name="YASHIGANI_DB_DSN_DIRECT",
        in_templates=(GATEWAY_YAML, BACKOFFICE_YAML),
        # Must point directly to yashigani-postgres (not pgbouncer)
        value_pattern=r"yashigani-postgres:5432",
        label="DSN_DIRECT must target yashigani-postgres in both services",
    ),
    # -----------------------------------------------------------------------
    # DB DSN — pgbouncer path
    # -----------------------------------------------------------------------
    EnvParity(
        key_name="YASHIGANI_DB_DSN",
        in_templates=(GATEWAY_YAML, BACKOFFICE_YAML),
        # Must route through pgbouncer
        value_pattern=r"yashigani-pgbouncer:5432",
        label="DSN must target yashigani-pgbouncer in both services",
    ),
    # -----------------------------------------------------------------------
    # CA bundle cert path — both DSNs must reference ca_bundle.crt not ca_root
    # -----------------------------------------------------------------------
    EnvParity(
        key_name="YASHIGANI_DB_DSN_DIRECT",
        in_templates=(GATEWAY_YAML, BACKOFFICE_YAML),
        value_pattern=r"sslrootcert=/run/secrets/ca_bundle\.crt",
        label="DSN_DIRECT must use ca_bundle.crt (not ca_root.crt) in both services",
    ),
    EnvParity(
        key_name="YASHIGANI_DB_DSN",
        in_templates=(GATEWAY_YAML, BACKOFFICE_YAML),
        value_pattern=r"sslrootcert=/run/secrets/ca_bundle\.crt",
        label="DSN must use ca_bundle.crt (not ca_root.crt) in both services",
    ),
    # -----------------------------------------------------------------------
    # Mount path — /run/secrets must appear as a volumeMount in both
    # -----------------------------------------------------------------------
    EnvParity(
        key_name="YASHIGANI_SECRETS_DIR",
        in_templates=(GATEWAY_YAML, BACKOFFICE_YAML),
        value_pattern=r"/run/secrets",
        mount_path_pattern=r"mountPath:\s*/run/secrets",
        label="SECRETS_DIR=/run/secrets and matching volumeMount in both services",
    ),
    # -----------------------------------------------------------------------
    # CADDY_INTERNAL_HMAC — must appear in both (EX-231-10 Layer B)
    # -----------------------------------------------------------------------
    EnvParity(
        key_name="CADDY_INTERNAL_HMAC",
        in_templates=(GATEWAY_YAML, BACKOFFICE_YAML),
        label="CADDY_INTERNAL_HMAC must be present in both services",
    ),
    # -----------------------------------------------------------------------
    # OTEL exporter cert — both services must reference ca_root.crt for OTEL
    # (Python ssl path — Pattern A per gate #58a)
    # -----------------------------------------------------------------------
    EnvParity(
        key_name="OTEL_EXPORTER_OTLP_CERTIFICATE",
        in_templates=(GATEWAY_YAML, BACKOFFICE_YAML),
        value_pattern=r"/run/secrets/ca_root\.crt",
        label="OTEL CA cert must be ca_root.crt in both services",
    ),
]


# ---------------------------------------------------------------------------
# Parser helpers
# ---------------------------------------------------------------------------


def _extract_env_entries(template_text: str) -> dict[str, list[str]]:
    """
    Extract env var names → list of raw value strings from a Helm YAML template.

    Works on raw Helm template text (Helm expressions preserved as-is).
    Handles the ``- name: FOO`` / ``  value: "..."`` pattern used throughout
    gateway.yaml and backoffice.yaml.  Comments and blank lines between the
    name and value lines are skipped.

    Returns a dict mapping env-var name → list of value strings found (one
    entry per occurrence in the template, since Helm conditionals can produce
    the same var name in both the ``if`` branch and the ``else`` branch).
    If an entry uses ``valueFrom`` rather than an inline value, the list entry
    is ``"__valueFrom__"``.
    """
    entries: dict[str, list[str]] = {}
    lines = template_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        # Match ``- name: FOO`` lines (may have leading whitespace)
        m = re.match(r'\s+-\s+name:\s+(\S+)', line)
        if m:
            var_name = m.group(1)
            # Scan ahead for the ``value:`` line, skipping comments/blanks
            j = i + 1
            value_str = ""
            while j < len(lines):
                vline = lines[j].strip()
                if vline.startswith("#") or vline == "":
                    j += 1
                    continue
                if vline.startswith("value:"):
                    # Capture everything after ``value:``
                    value_str = vline[len("value:"):].strip().strip('"').strip("'")
                    break
                if vline.startswith("valueFrom:"):
                    # Secret/field ref — no inline value; record empty
                    value_str = "__valueFrom__"
                    break
                # Next ``- name:`` reached without finding value — stop
                if re.match(r'-\s+name:', vline):
                    break
                j += 1
            entries.setdefault(var_name, []).append(value_str)
        i += 1
    return entries


def _load_template(path: Path) -> str:
    assert path.exists(), f"Template not found: {path}"
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Core assertion
# ---------------------------------------------------------------------------


def _assert_parity(spec: EnvParity, contents: dict[Path, str]) -> None:
    """
    Assert one EnvParity spec against a dict of {path: text} template contents.
    Raises AssertionError with a structured diff on failure.

    Value-pattern semantics
    -----------------------
    Helm templates often emit the same env-var name in BOTH the ``{{- if
    .Values.mtls.enabled }}`` block AND the ``{{- else }}`` block (e.g.
    YASHIGANI_DB_DSN appears with mTLS params and without).  The contract
    therefore requires that AT LEAST ONE occurrence of the key carries a value
    matching ``value_pattern`` — it does not require every occurrence to match.
    This correctly captures "the mTLS branch must have ca_bundle.crt" without
    rejecting the non-mTLS fallback entry.
    """
    failures: list[str] = []

    for tpl_path in spec.in_templates:
        text = contents[tpl_path]
        env_entries = _extract_env_entries(text)  # name → list[str]

        # 1. Key presence
        if spec.key_name not in env_entries:
            failures.append(
                f"  MISSING key '{spec.key_name}' in {tpl_path.name}"
            )
            continue  # no point checking value if key absent

        # 2. Value pattern — at least one occurrence must match.
        if spec.value_pattern is not None:
            all_values = env_entries[spec.key_name]
            # Also search raw text snippets around each key occurrence for
            # values that span past the 400-char inline heuristic (long DSNs
            # buried after multiline comments).
            raw_snippets: list[str] = []
            search_start = 0
            needle = f"name: {spec.key_name}"
            while True:
                idx = text.find(needle, search_start)
                if idx == -1:
                    break
                raw_snippets.append(text[idx: idx + 800])
                search_start = idx + len(needle)

            pattern_matched = any(
                re.search(spec.value_pattern, v) for v in all_values
            ) or any(
                re.search(spec.value_pattern, snip) for snip in raw_snippets
            )
            if not pattern_matched:
                failures.append(
                    f"  WRONG VALUE in {tpl_path.name} for '{spec.key_name}': "
                    f"expected pattern /{spec.value_pattern}/ in at least one "
                    f"occurrence, but got: {all_values!r}"
                )

        # 3. Mount path pattern
        if spec.mount_path_pattern is not None:
            if not re.search(spec.mount_path_pattern, text):
                failures.append(
                    f"  MISSING mount in {tpl_path.name}: "
                    f"expected pattern /{spec.mount_path_pattern}/ "
                    f"not found in template"
                )

    if failures:
        diff_block = "\n".join(failures)
        raise AssertionError(
            f"\nHelm env-parity contract FAILED: {spec.label}\n"
            f"Affected templates: {[p.name for p in spec.in_templates]}\n"
            f"\nFailures:\n{diff_block}\n"
            f"\nFix: ensure '{spec.key_name}' is present with matching value "
            f"in ALL listed templates."
        )


# ---------------------------------------------------------------------------
# Parametrised green-tip tests
# ---------------------------------------------------------------------------

# Load templates once at module level — fast, avoids repeated file I/O.
_TEMPLATE_CONTENTS: dict[Path, str] = {
    GATEWAY_YAML: _load_template(GATEWAY_YAML),
    BACKOFFICE_YAML: _load_template(BACKOFFICE_YAML),
}


@pytest.mark.parametrize("spec", REQUIRED_ENV_PARITY, ids=lambda s: s.label)
def test_helm_env_parity(spec: EnvParity) -> None:
    """
    Assert every EnvParity spec passes against the live templates on disk.
    Fails immediately with a structured diff if any key is missing or its
    value does not match the expected pattern.
    """
    _assert_parity(spec, _TEMPLATE_CONTENTS)


# ---------------------------------------------------------------------------
# Mutation tests — verify the contract actually catches regressions
# ---------------------------------------------------------------------------


def _strip_env_var(text: str, var_name: str) -> str:
    """
    Remove the ``- name: <var_name>`` block (name + value lines) from the
    env section of a Helm template.  Operates on raw text — no YAML parse.
    """
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r'(\s+)-\s+name:\s+' + re.escape(var_name) + r'\s*$', line)
        if m:
            # Skip this line and all following lines that are part of the block
            # (comment lines, value: line, valueFrom: lines) until next ``- name:``
            # or a line with equal/lesser indentation that isn't a list item.
            indent = len(m.group(1))
            i += 1
            while i < len(lines):
                inner = lines[i]
                stripped = inner.lstrip()
                inner_indent = len(inner) - len(stripped)
                # Stop when we hit another env entry at same level or shallower
                if inner_indent <= indent and stripped.startswith("- "):
                    break
                # Stop at blank / Helm control line at lesser indent
                if inner_indent < indent and stripped and not stripped.startswith("#"):
                    break
                i += 1
            continue
        out.append(line)
        i += 1
    return "".join(out)


def test_mutation_dsn_direct_missing_in_gateway_is_caught() -> None:
    """
    Regression guard: if YASHIGANI_DB_DSN_DIRECT is removed from gateway.yaml
    the contract test must fail with a clear message.  This is the exact
    1a6db9f regression pattern.
    """
    mutated_gateway = _strip_env_var(
        _TEMPLATE_CONTENTS[GATEWAY_YAML], "YASHIGANI_DB_DSN_DIRECT"
    )
    # Confirm the mutation actually removed the key from the parsed entries
    mutated_entries = _extract_env_entries(mutated_gateway)
    assert "YASHIGANI_DB_DSN_DIRECT" not in mutated_entries, (
        f"Mutation helper failed to strip YASHIGANI_DB_DSN_DIRECT from gateway text; "
        f"remaining values: {mutated_entries.get('YASHIGANI_DB_DSN_DIRECT')}"
    )

    # The spec that covers DSN_DIRECT must now raise AssertionError
    spec = next(
        s for s in REQUIRED_ENV_PARITY
        if s.key_name == "YASHIGANI_DB_DSN_DIRECT"
        and s.value_pattern == r"yashigani-postgres:5432"
    )
    mutated_contents = dict(_TEMPLATE_CONTENTS)
    mutated_contents[GATEWAY_YAML] = mutated_gateway

    with pytest.raises(AssertionError, match="MISSING key 'YASHIGANI_DB_DSN_DIRECT'"):
        _assert_parity(spec, mutated_contents)


def test_mutation_dsn_direct_missing_in_backoffice_is_caught() -> None:
    """
    Symmetric mutation: YASHIGANI_DB_DSN_DIRECT stripped from backoffice.yaml
    must also be caught.
    """
    mutated_backoffice = _strip_env_var(
        _TEMPLATE_CONTENTS[BACKOFFICE_YAML], "YASHIGANI_DB_DSN_DIRECT"
    )
    mutated_entries = _extract_env_entries(mutated_backoffice)
    assert "YASHIGANI_DB_DSN_DIRECT" not in mutated_entries, (
        f"Mutation helper failed to strip YASHIGANI_DB_DSN_DIRECT from backoffice text; "
        f"remaining values: {mutated_entries.get('YASHIGANI_DB_DSN_DIRECT')}"
    )

    spec = next(
        s for s in REQUIRED_ENV_PARITY
        if s.key_name == "YASHIGANI_DB_DSN_DIRECT"
        and s.value_pattern == r"yashigani-postgres:5432"
    )
    mutated_contents = dict(_TEMPLATE_CONTENTS)
    mutated_contents[BACKOFFICE_YAML] = mutated_backoffice

    with pytest.raises(AssertionError, match="MISSING key 'YASHIGANI_DB_DSN_DIRECT'"):
        _assert_parity(spec, mutated_contents)


def test_mutation_wrong_ca_cert_is_caught() -> None:
    """
    Mutation: replace ca_bundle.crt → ca_root.crt in gateway DSN_DIRECT value.
    The ca_bundle spec must fire.
    """
    mutated_gateway = _TEMPLATE_CONTENTS[GATEWAY_YAML].replace(
        "sslrootcert=/run/secrets/ca_bundle.crt&sslcert=/run/secrets/gateway_client.crt&sslkey=/run/secrets/gateway_client.key\"",
        "sslrootcert=/run/secrets/ca_root.crt&sslcert=/run/secrets/gateway_client.crt&sslkey=/run/secrets/gateway_client.key\"",
    )
    # Confirm the mutation took effect
    assert "ca_bundle.crt" not in mutated_gateway or \
        mutated_gateway.count("ca_bundle.crt") < _TEMPLATE_CONTENTS[GATEWAY_YAML].count("ca_bundle.crt"), \
        "Mutation helper failed to replace ca_bundle.crt"

    spec = next(
        s for s in REQUIRED_ENV_PARITY
        if s.key_name == "YASHIGANI_DB_DSN_DIRECT"
        and s.value_pattern == r"sslrootcert=/run/secrets/ca_bundle\.crt"
    )
    mutated_contents = dict(_TEMPLATE_CONTENTS)
    mutated_contents[GATEWAY_YAML] = mutated_gateway

    with pytest.raises(AssertionError, match="WRONG VALUE|MISSING"):
        _assert_parity(spec, mutated_contents)
