# Last updated: 2026-05-01T00:00:00+01:00
"""
Contract test: service_identities.yaml single-source enforcement.

Canonical source: docker/service_identities.yaml
Derived copy:    helm/yashigani/files/service_identities.yaml

The Helm copy exists because helm's .Files.Get cannot reach outside the chart
directory tree, so it must be a verbatim copy of the canonical source. The copy
is kept in sync by `make sync-service-identities` and validated here.

This test FAILS when the two files diverge by SHA-256. A divergence means the
Helm chart would enroll a different set of service identities than docker/
compose — exactly the class of cross-runtime drift that caused BUG-3/BUG-4 in
v2.23.1. There are no exceptions; the whole point of this test is that drift is
caught in CI before it reaches a release.

If you need to update service_identities.yaml:
  1. Edit docker/service_identities.yaml (canonical source).
  2. Run `make sync-service-identities` to copy it into helm/yashigani/files/.
  3. Commit BOTH files in the same commit.
  Never edit helm/yashigani/files/service_identities.yaml directly.
"""

import hashlib
import pathlib
import textwrap

import pytest

# Resolve paths relative to repo root (two levels up from tests/contracts/).
_REPO_ROOT = pathlib.Path(__file__).parent.parent.parent

CANONICAL = _REPO_ROOT / "docker" / "service_identities.yaml"
HELM_COPY  = _REPO_ROOT / "helm" / "yashigani" / "files" / "service_identities.yaml"


def _sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_canonical_source_exists() -> None:
    """Canonical source must exist — absence is a repo corruption."""
    assert CANONICAL.exists(), (
        f"Canonical source missing: {CANONICAL}\n"
        "Re-clone the repo or restore the file from git history."
    )


def test_helm_copy_exists() -> None:
    """Helm copy must exist — absence means sync-service-identities was never run."""
    assert HELM_COPY.exists(), (
        f"Helm copy missing: {HELM_COPY}\n"
        "Run `make sync-service-identities` to generate it from the canonical source."
    )


def test_sha256_identical() -> None:
    """Both copies must have identical SHA-256.

    A mismatch is a P0 drift finding: the Helm chart would issue a different
    set of mTLS identities than the docker-compose runtime, breaking cross-
    runtime parity at the PKI layer.
    """
    if not CANONICAL.exists() or not HELM_COPY.exists():
        pytest.skip("Prerequisite file(s) missing — see sibling tests for details.")

    canonical_sha = _sha256(CANONICAL)
    helm_sha      = _sha256(HELM_COPY)

    assert canonical_sha == helm_sha, textwrap.dedent(f"""
        service_identities.yaml DRIFT DETECTED — P0 integration finding.

        Canonical (docker/):  {canonical_sha}
        Helm copy (helm/...): {helm_sha}

        To fix:
          1. Edit docker/service_identities.yaml (canonical source ONLY).
          2. Run `make sync-service-identities`.
          3. Commit both files in the same commit.

        Never edit helm/yashigani/files/service_identities.yaml directly.
    """).strip()
