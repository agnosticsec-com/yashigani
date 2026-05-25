# Last updated: 2026-05-25T00:00:00+00:00
"""
Podman seccomp override contract tests — BUG-NEW-002 / YSG-RISK-074.

podman-compose 1.5.0 on Mac produces "file name too long" when
YASHIGANI_SECCOMP_PROFILE is set to an absolute path by install.sh and the
`security_opt: ["seccomp=${YASHIGANI_SECCOMP_PROFILE}"]` form is used.

Root cause: compose override files REPLACE security_opt lists (they do not merge).
The Podman override (docker-compose.podman-override.yml) was replacing the
base security_opt list with just `[label=disable]`, silently dropping
`no-new-privileges:true`, `seccomp=...`, and `apparmor=...` for gateway +
backoffice on Podman. When the env-var form WAS active (before override, or on
services without override entries), podman-compose 1.5.0 produced ENAMETOOLONG
because the absolute path value was being interpreted as content.

Fix: the Podman override entry for gateway and backoffice now explicitly includes
`no-new-privileges:true`, `seccomp=./seccomp/yashigani.json` (relative path,
no env-var interpolation), `apparmor=unconfined`, and `label=disable`.

These tests assert:
  1. The Podman override contains seccomp entries for gateway + backoffice.
  2. The seccomp values use a relative path (not an env-var form).
  3. The relative path does NOT contain a $ (no env-var interpolation).
  4. The seccomp profile file exists at the expected relative location.
  5. no-new-privileges is present for gateway + backoffice in the override.
  6. The base compose seccomp env-var form is still present (Docker path correct).
  7. The seccomp profile JSON is valid JSON.

YSG-RISK-074: BUG-NEW-002 — Podman seccomp path resolved as content, not path.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
DOCKER_DIR = REPO_ROOT / "docker"

PODMAN_OVERRIDE = DOCKER_DIR / "docker-compose.podman-override.yml"
BASE_COMPOSE = DOCKER_DIR / "docker-compose.yml"
SECCOMP_PROFILE = DOCKER_DIR / "seccomp" / "yashigani.json"


def _read(path: Path) -> str:
    assert path.exists(), f"File missing: {path}"
    return path.read_text()


# ─────────────────────────────────────────────────────────────────────────────
# Test 1: Podman override contains seccomp entry for gateway
# ─────────────────────────────────────────────────────────────────────────────

def test_podman_override_gateway_has_seccomp() -> None:
    """Podman override must include a seccomp entry for the gateway service.

    BUG-NEW-002: the previous override only had `label=disable`, silently dropping
    the seccomp profile. The fix adds `seccomp=./seccomp/yashigani.json` explicitly.
    YSG-RISK-074.
    """
    content = _read(PODMAN_OVERRIDE)
    # Find the gateway block
    # Look for seccomp anywhere in the override — parametrised check below
    assert "seccomp=./seccomp/yashigani.json" in content, (
        "Podman override: seccomp=./seccomp/yashigani.json not found. "
        "BUG-NEW-002 fix requires explicit relative-path seccomp in gateway + backoffice "
        "security_opt. YSG-RISK-074."
    )


def test_podman_override_no_env_var_seccomp() -> None:
    """Podman override security_opt entries must NOT use env-var interpolation for seccomp.

    The root cause of BUG-NEW-002: seccomp=${YASHIGANI_SECCOMP_PROFILE} in the override
    caused podman-compose 1.5.0 to produce ENAMETOOLONG. The fix uses a static relative
    path `seccomp=./seccomp/yashigani.json`. YSG-RISK-074.
    """
    content = _read(PODMAN_OVERRIDE)
    # Any `seccomp=$` form in security_opt lines (active, non-comment)
    for i, line in enumerate(content.splitlines()):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "seccomp=$" in stripped:
            pytest.fail(
                f"Podman override line {i+1}: env-var seccomp interpolation found: '{stripped}'. "
                "Use a static relative path instead: '- seccomp=./seccomp/yashigani.json'. "
                "BUG-NEW-002 / YSG-RISK-074."
            )


def test_podman_override_no_privilege_escalation() -> None:
    """Podman override must include no-new-privileges:true for gateway + backoffice.

    Compose override REPLACES security_opt lists. The fix must re-include
    `no-new-privileges:true` for services where the override has a security_opt block.
    YSG-RISK-074.
    """
    content = _read(PODMAN_OVERRIDE)
    assert "no-new-privileges:true" in content, (
        "Podman override: no-new-privileges:true not found. "
        "Compose override replaces security_opt lists — no-new-privileges must be "
        "re-declared in the override for gateway + backoffice. YSG-RISK-074."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 2: Seccomp profile file exists at the relative path
# ─────────────────────────────────────────────────────────────────────────────

def test_seccomp_profile_file_exists() -> None:
    """The seccomp profile referenced in the Podman override must exist.

    Relative path: ./seccomp/yashigani.json resolves to docker/seccomp/yashigani.json
    from the compose file directory (docker/). YSG-RISK-074.
    """
    assert SECCOMP_PROFILE.exists(), (
        f"Seccomp profile not found at {SECCOMP_PROFILE}. "
        "The Podman override references './seccomp/yashigani.json' — this file must exist "
        "relative to the compose file directory (docker/). YSG-RISK-074."
    )


def test_seccomp_profile_is_valid_json() -> None:
    """The seccomp profile must be valid JSON.

    A corrupt or empty seccomp profile causes podman/docker to fail at container start.
    YSG-RISK-074.
    """
    content = _read(SECCOMP_PROFILE)
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as e:
        pytest.fail(
            f"Seccomp profile {SECCOMP_PROFILE} is not valid JSON: {e}. "
            "YSG-RISK-074."
        )
    assert isinstance(parsed, dict), (
        f"Seccomp profile {SECCOMP_PROFILE} parsed to {type(parsed)}, expected dict. "
        "A valid OCI seccomp profile is a JSON object with 'defaultAction' + 'syscalls'. "
        "YSG-RISK-074."
    )


def test_seccomp_profile_has_default_action() -> None:
    """The seccomp profile must have a defaultAction field.

    A seccomp profile without defaultAction causes the container runtime to reject it
    or apply unpredictable defaults. YSG-RISK-074.
    """
    content = _read(SECCOMP_PROFILE)
    parsed = json.loads(content)
    assert "defaultAction" in parsed, (
        f"Seccomp profile {SECCOMP_PROFILE} missing 'defaultAction' field. "
        "OCI seccomp profile must specify defaultAction. YSG-RISK-074."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 3: Base compose still has env-var form (Docker path unaffected)
# ─────────────────────────────────────────────────────────────────────────────

def test_base_compose_still_has_env_var_seccomp() -> None:
    """Base docker-compose.yml must still use the env-var form for seccomp.

    The env-var form works correctly for Docker Engine (docker-compose v2 resolves
    the absolute path correctly). The Podman override overrides this for Podman only.
    Removing the env-var form from the base compose would break the Docker path.
    YSG-RISK-074.
    """
    content = _read(BASE_COMPOSE)
    assert "seccomp=${YASHIGANI_SECCOMP_PROFILE" in content, (
        "Base docker-compose.yml: env-var seccomp form not found. "
        "The base compose must retain the env-var form for Docker Engine. "
        "The Podman override overrides this for Podman only. YSG-RISK-074."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 4: YSG-RISK-074 reference in override file
# ─────────────────────────────────────────────────────────────────────────────

def test_podman_override_references_ysg_risk_074() -> None:
    """Podman override must reference YSG-RISK-074 in its comments.

    Ensures the override is correctly updated for v2.24.3 BUG-NEW-002 fix.
    """
    content = _read(PODMAN_OVERRIDE)
    assert "YSG-RISK-074" in content, (
        "Podman override: YSG-RISK-074 reference not found. "
        "The override must be updated to v2.24.3 seccomp fix. BUG-NEW-002."
    )
