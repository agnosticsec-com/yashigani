"""
Version consistency tests.

Ensures __version__ in yashigani/__init__.py matches pyproject.toml.
These tests catch IC-1 class regressions (version string divergence).
"""
from __future__ import annotations

from pathlib import Path
import re

import pytest


def _read_pyproject_version() -> str:
    pyproject = Path(__file__).parents[3] / "pyproject.toml"
    if not pyproject.exists():
        pytest.skip("pyproject.toml not found")
    content = pyproject.read_text()
    match = re.search(r'^version\s*=\s*"([^"]+)"', content, re.MULTILINE)
    if not match:
        pytest.skip("version not found in pyproject.toml")
    return match.group(1)


class TestVersionConsistency:
    def test_init_version_matches_pyproject(self):
        """IC-1 regression: __version__ in __init__.py must match pyproject.toml."""
        import yashigani
        pyproject_version = _read_pyproject_version()
        assert yashigani.__version__ == pyproject_version, (
            f"yashigani.__version__ = {yashigani.__version__!r} "
            f"but pyproject.toml says {pyproject_version!r}. "
            "Update src/yashigani/__init__.py to match."
        )

    def test_version_is_semver(self):
        import yashigani
        semver_pattern = re.compile(r"^\d+\.\d+\.\d+")
        assert semver_pattern.match(yashigani.__version__), \
            f"__version__ {yashigani.__version__!r} is not a valid semver string"
