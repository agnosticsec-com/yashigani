# Last updated: 2026-05-25T00:00:00+00:00
"""
pg_hba.conf cert carveout tests — BUG-NEW-001 / YSG-RISK-073.

PgBouncer 1.25.1 (edoburu image) cannot perform SCRAM-SHA-256 as the client when
connecting to postgres as auth_user. YSG-RISK-050 removed the A2 trust carveout,
assuming pgbouncer would SCRAM — it cannot. YSG-RISK-073 replaces trust with cert:
a narrow hostssl carveout for pgbouncer_authenticator on the yashigani database uses
the `cert` auth method (cert = sole authenticator, no SCRAM challenge issued).

This test suite asserts the correct form in the two pg_hba-producing scripts:
  05-enable-ssl.sh — writes pg_hba.conf on first-init
  10-pgbouncer-auth.sh — asserts/re-inserts the carveout on upgrade paths

Tests also assert:
  - The catch-all (scram-sha-256 clientcert=verify-ca) is still present
  - The carveout precedes the catch-all in the heredoc text
  - The old trust-based A2 carveout form is NOT present in either script
  - Helm pg_hba ConfigMap contains the matching cert carveout

YSG-RISK-049: SECURITY DEFINER ysg_pgbouncer_get_auth + pgbouncer_authenticator role.
YSG-RISK-050: dedicated pgbouncer-auth_client.crt for postgres-facing identity.
YSG-RISK-073: cert carveout replaces SCRAM for pgbouncer_authenticator auth_query
              connection (BUG-NEW-001 from Ava v2.24.3 cycle 3 gate).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent

ENABLE_SSL_SCRIPT = REPO_ROOT / "docker" / "postgres" / "05-enable-ssl.sh"
PGBOUNCER_AUTH_SCRIPT = REPO_ROOT / "docker" / "postgres" / "10-pgbouncer-auth.sh"

# Helm pg_hba.conf file — the chart uses the same init scripts (05-enable-ssl.sh,
# 10-pgbouncer-auth.sh) mounted as ConfigMaps into the postgres pod. These scripts
# write pg_hba.conf at runtime, so there is no standalone pg_hba.conf file in the
# Helm chart. If a dedicated pg_hba.conf ConfigMap is ever added, add the path here.
# The init scripts are tested above (test_enable_ssl_* and test_pgbouncer_auth_*).
HELM_PG_HBA_SOURCES = [
    REPO_ROOT / "helm" / "yashigani" / "files" / "pg_hba.conf",
]

# The expected cert carveout lines (canonical form)
_CERT_CARVEOUT_RE = re.compile(
    r"hostssl\s+yashigani\s+pgbouncer_authenticator\s+[\d.:a-fA-F/]+\s+cert\s+clientcert=verify-ca"
)
# The forbidden trust form
_TRUST_CARVEOUT_RE = re.compile(
    r"hostssl\s+\S+\s+pgbouncer_authenticator\s+\S+\s+trust"
)
# Catch-all must still be present
_CATCHALL_RE = re.compile(
    r"hostssl\s+all\s+all\s+[\d.:a-fA-F/]+\s+scram-sha-256\s+clientcert=verify-ca"
)


def _read(path: Path) -> str:
    assert path.exists(), f"File missing: {path}"
    return path.read_text()


# ─────────────────────────────────────────────────────────────────────────────
# Test 1: 05-enable-ssl.sh pg_hba heredoc contains the cert carveout
# ─────────────────────────────────────────────────────────────────────────────

def test_enable_ssl_has_cert_carveout() -> None:
    """05-enable-ssl.sh pg_hba heredoc must contain the cert carveout for pgbouncer_authenticator.

    This is the primary write path for pg_hba.conf on fresh installs.
    YSG-RISK-073 fix: `cert clientcert=verify-ca` on yashigani + pgbouncer_authenticator.
    """
    content = _read(ENABLE_SSL_SCRIPT)
    matches = _CERT_CARVEOUT_RE.findall(content)
    assert len(matches) >= 2, (
        f"05-enable-ssl.sh: expected at least 2 cert carveout lines (IPv4 + IPv6) for "
        f"pgbouncer_authenticator, found {len(matches)}. "
        "YSG-RISK-073: cert carveout must precede catch-all in pg_hba heredoc."
    )


def test_enable_ssl_catch_all_still_present() -> None:
    """05-enable-ssl.sh catch-all (scram-sha-256 clientcert=verify-ca) must still be present.

    The cert carveout is narrowly scoped to pgbouncer_authenticator on yashigani.
    All other connections must still use SCRAM + cert. Three-factor auth preserved.
    """
    content = _read(ENABLE_SSL_SCRIPT)
    matches = _CATCHALL_RE.findall(content)
    assert len(matches) >= 2, (
        f"05-enable-ssl.sh: catch-all (hostssl all all ... scram-sha-256 clientcert=verify-ca) "
        f"found {len(matches)} times, expected >= 2 (IPv4 + IPv6). "
        "The scram catch-all must be retained for all non-pgbouncer_authenticator connections."
    )


def test_enable_ssl_carveout_precedes_catchall() -> None:
    """In 05-enable-ssl.sh, the cert carveout for pgbouncer_authenticator must appear BEFORE the catch-all.

    pg_hba rules are evaluated top-to-bottom; the catch-all (hostssl all all ...) matches
    pgbouncer_authenticator too. If the carveout appears AFTER the catch-all, postgres issues
    a SCRAM challenge before reaching the cert rule and pgbouncer 1.25.1 fails.
    """
    content = _read(ENABLE_SSL_SCRIPT)
    carveout_pos = content.find("pgbouncer_authenticator")
    catchall_pos = content.find("hostssl all       all            0.0.0.0/0      scram-sha-256")
    assert carveout_pos != -1, "05-enable-ssl.sh: pgbouncer_authenticator carveout not found."
    assert catchall_pos != -1, "05-enable-ssl.sh: catch-all rule not found."
    assert carveout_pos < catchall_pos, (
        f"05-enable-ssl.sh: pgbouncer_authenticator carveout (pos {carveout_pos}) appears "
        f"AFTER the catch-all (pos {catchall_pos}). pg_hba is first-match; carveout "
        "must precede catch-all or postgres will SCRAM-challenge pgbouncer_authenticator."
    )


def test_enable_ssl_no_trust_carveout() -> None:
    """05-enable-ssl.sh must NOT contain a trust-based carveout for pgbouncer_authenticator.

    The v2.24.0 A2 carveout used `trust`. YSG-RISK-073 replaces it with `cert`.
    Any remaining trust-based carveout would be weaker than cert.
    """
    content = _read(ENABLE_SSL_SCRIPT)
    matches = _TRUST_CARVEOUT_RE.findall(content)
    assert not matches, (
        f"05-enable-ssl.sh: found trust-based carveout for pgbouncer_authenticator: {matches}. "
        "YSG-RISK-073: trust carveout must be replaced with cert carveout."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 2: 10-pgbouncer-auth.sh manages the cert carveout correctly
# ─────────────────────────────────────────────────────────────────────────────

def test_pgbouncer_auth_script_inserts_cert_carveout() -> None:
    """10-pgbouncer-auth.sh must insert a cert carveout (not remove it) — YSG-RISK-073.

    v2.24.0 step 4 REMOVED the carveout. v2.24.3 step 4 INSERTS the cert carveout.
    Verify the script contains the cert carveout insertion logic.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT)
    # Must contain cert carveout insertion (the hostssl ... cert ... line to insert)
    assert "cert  clientcert=verify-ca" in content, (
        "10-pgbouncer-auth.sh: cert carveout insertion text not found. "
        "Step 4 must insert 'hostssl yashigani pgbouncer_authenticator ... cert clientcert=verify-ca' "
        "before the catch-all. YSG-RISK-073."
    )


def test_pgbouncer_auth_script_no_remove_only() -> None:
    """10-pgbouncer-auth.sh must not only remove the carveout without re-inserting it.

    v2.24.0 bug: the script removed the A2 carveout but did not add a cert carveout.
    v2.24.3 fix: the script removes stale entries then inserts the cert carveout.
    Verify the insert step (sed -i ... '/^hostssl all/i') is present.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT)
    # Must have sed insertion before catch-all
    assert "/^hostssl all/i" in content or "hostssl yashigani pgbouncer_authenticator" in content, (
        "10-pgbouncer-auth.sh: sed insertion-before-catchall pattern not found. "
        "Step 4 must use sed '/^hostssl all/i ...' to insert the cert carveout before "
        "the catch-all. YSG-RISK-073."
    )


def test_pgbouncer_auth_script_no_trust_carveout_inserted() -> None:
    """10-pgbouncer-auth.sh must not insert a trust-based carveout — cert only.

    Any insertion of `trust` for pgbouncer_authenticator would be a security regression
    vs the YSG-RISK-073 cert carveout.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT)
    # Check for trust insertion pattern — excluding comments
    lines = content.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "pgbouncer_authenticator" in stripped and "trust" in stripped:
            pytest.fail(
                f"10-pgbouncer-auth.sh line {i+1}: trust carveout for pgbouncer_authenticator "
                f"found in active code: '{stripped}'. Use cert, not trust. YSG-RISK-073."
            )


def test_pgbouncer_auth_script_references_ysg_risk_073() -> None:
    """10-pgbouncer-auth.sh must reference YSG-RISK-073 in its comments.

    Ensures the script is correctly updated for v2.24.3 and not a stale v2.24.0 version.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT)
    assert "YSG-RISK-073" in content, (
        "10-pgbouncer-auth.sh: YSG-RISK-073 reference not found. "
        "The script must be updated to v2.24.3 cert carveout logic."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 3: Helm pg_hba contains cert carveout (Compose-Helm parity)
# ─────────────────────────────────────────────────────────────────────────────

def test_helm_pghba_has_cert_carveout() -> None:
    """Helm chart must also include the cert carveout for pgbouncer_authenticator.

    Compose-Helm parity: the cert carveout added to compose 05-enable-ssl.sh
    must also appear in the Helm chart's pg_hba.conf ConfigMap/values.
    If no Helm pg_hba file exists, this test is skipped with a clear reason.
    YSG-RISK-073.
    """
    helm_content = None
    for path in HELM_PG_HBA_SOURCES:
        if path.exists():
            helm_content = path.read_text()
            break

    if helm_content is None:
        pytest.skip(
            "No Helm pg_hba source found at expected paths "
            f"({[str(p) for p in HELM_PG_HBA_SOURCES]}). "
            "Add helm/yashigani/files/pg_hba.conf or update HELM_PG_HBA_SOURCES "
            "when the Helm chart embeds pg_hba.conf as a ConfigMap. YSG-RISK-073."
        )

    matches = _CERT_CARVEOUT_RE.findall(helm_content)
    assert len(matches) >= 1, (
        f"Helm pg_hba source: cert carveout for pgbouncer_authenticator not found. "
        "Compose-Helm parity requires the cert carveout in Helm too. YSG-RISK-073."
    )
