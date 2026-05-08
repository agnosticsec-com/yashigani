"""
Unit tests for generate_sbom.py runtime-mode guard (V232-CSCAN-01k-RES-02).

Verifies:
1. Importing the module does NOT raise when YASHIGANI_SERVICE_NAME is unset.
2. _check_not_runtime() is a no-op when YASHIGANI_SERVICE_NAME is unset.
3. _check_not_runtime() raises RuntimeError when YASHIGANI_SERVICE_NAME is set
   (simulating execution inside a runtime container).
4. main() raises RuntimeError when YASHIGANI_SERVICE_NAME is set.

Last updated: 2026-05-03
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Ensure scripts/ is importable.  It is not a package, so we load via spec.
_SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "scripts"


def _load_generate_sbom():
    """Import (or reload) generate_sbom from scripts/, with YASHIGANI_SERVICE_NAME unset."""
    spec = importlib.util.spec_from_file_location(
        "generate_sbom", _SCRIPTS_DIR / "generate_sbom.py"
    )
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_import_does_not_raise_without_service_name(monkeypatch):
    """Module-level import must succeed when YASHIGANI_SERVICE_NAME is not set."""
    monkeypatch.delenv("YASHIGANI_SERVICE_NAME", raising=False)
    # Should not raise.
    mod = _load_generate_sbom()
    assert hasattr(mod, "_check_not_runtime")
    assert hasattr(mod, "main")


def test_check_not_runtime_noop_without_service_name(monkeypatch):
    """_check_not_runtime() must be a no-op when YASHIGANI_SERVICE_NAME is absent."""
    monkeypatch.delenv("YASHIGANI_SERVICE_NAME", raising=False)
    mod = _load_generate_sbom()
    # Must not raise.
    mod._check_not_runtime()


@pytest.mark.parametrize("service_name", ["gateway", "backoffice"])
def test_check_not_runtime_raises_inside_runtime_container(monkeypatch, service_name):
    """_check_not_runtime() must raise RuntimeError when YASHIGANI_SERVICE_NAME is set."""
    monkeypatch.setenv("YASHIGANI_SERVICE_NAME", service_name)
    mod = _load_generate_sbom()
    with pytest.raises(RuntimeError, match="build/release tool"):
        mod._check_not_runtime()


@pytest.mark.parametrize("service_name", ["gateway", "backoffice"])
def test_main_raises_inside_runtime_container(monkeypatch, service_name):
    """main() must raise RuntimeError (not execute pip) when running in a runtime container."""
    monkeypatch.setenv("YASHIGANI_SERVICE_NAME", service_name)
    mod = _load_generate_sbom()
    with pytest.raises(RuntimeError, match="YASHIGANI_SERVICE_NAME"):
        mod.main()


def test_error_message_includes_service_name(monkeypatch):
    """RuntimeError message must include the actual YASHIGANI_SERVICE_NAME value."""
    monkeypatch.setenv("YASHIGANI_SERVICE_NAME", "gateway")
    mod = _load_generate_sbom()
    with pytest.raises(RuntimeError, match="'gateway'"):
        mod._check_not_runtime()
