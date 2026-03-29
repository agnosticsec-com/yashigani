"""
IC-6 regression: Path matching parity between Python _path_matches and OPA rbac.rego.

Automated tests cover the Python implementation.
Manual OPA verification commands are documented below.

To verify OPA agrees with each case (requires opa binary):
    opa eval -d policy/rbac.rego \
        'data.yashigani.rbac._path_matches("/tools/*", "/tools/list")'

Run the full manual parity check:
    for case in "tools/* tools/list true" "tools/* tools/list/extra false" ...; do
        pattern=$(echo $case | awk '{print $1}')
        path=$(echo $case | awk '{print $2}')
        expected=$(echo $case | awk '{print $3}')
        result=$(opa eval -d policy/rbac.rego \
            "data.yashigani.rbac._path_matches(\"/$pattern\", \"/$path\")" \
            | python3 -c "import sys,json; print(json.load(sys.stdin)['result'][0]['expressions'][0]['value'])")
        echo "/$pattern /$path -> $result (expected $expected)"
    done
"""
from __future__ import annotations

import pytest


def _import_path_matches():
    try:
        from yashigani.rbac.store import _path_matches
        return _path_matches
    except ImportError as exc:
        pytest.skip(f"rbac.store not importable: {exc}")


# ---------------------------------------------------------------------------
# Shared parameterised test table
# All cases must also hold true in policy/rbac.rego::_path_matches
# ---------------------------------------------------------------------------

PARITY_CASES = [
    # (pattern, path, expected, description)
    ("/tools/*",        "/tools/list",          True,  "single-segment wildcard matches leaf"),
    ("/tools/*",        "/tools/list/extra",    False, "single-segment * does NOT cross slash (IC-6 bug 1)"),
    ("/tools/**",       "/tools/list/extra",    True,  "** matches multi-segment subtree"),
    ("/tools/**",       "/tools/",              True,  "** matches trailing-slash form"),
    ("/tools/**",       "/tools",               False, "** requires trailing slash — bare prefix NOT matched (IC-6 bug 2)"),
    ("**",              "/anything/at/all",     True,  "bare ** matches any path"),
    ("**",              "/",                    True,  "bare ** matches root"),
    ("/exact",          "/exact",               True,  "exact match"),
    ("/exact",          "/exact/",              False, "trailing slash breaks exact match"),
    ("/exact/",         "/exact",               False, "pattern trailing slash, path without: no match"),
    ("/a/*/c",          "/a/b/c",               True,  "middle wildcard matches single segment"),
    ("/a/*/c",          "/a/b/d",               False, "middle wildcard with wrong leaf"),
    ("/a/*/c",          "/a/b/b/c",             False, "* is single-segment, not multi-segment (IC-6 bug 3)"),
    ("/finance/**",     "/finance/invoices",    True,  "** prefix matches direct child"),
    ("/finance/**",     "/finance/inv/sub",     True,  "** prefix matches deep subtree"),
    ("/finance/**",     "/financials/invoices", False, "** prefix does not extend past prefix boundary"),
]


@pytest.mark.parametrize("pattern,path,expected,desc", PARITY_CASES)
def test_python_path_matches(pattern, path, expected, desc):
    _path_matches = _import_path_matches()
    result = _path_matches(pattern, path)
    assert result == expected, (
        f"IC-6 parity failure:\n"
        f"  _path_matches({pattern!r}, {path!r})\n"
        f"  Expected: {expected}\n"
        f"  Got:      {result}\n"
        f"  Case:     {desc}\n"
        f"  If Python is wrong: fix rbac/store.py::_path_matches\n"
        f"  If OPA disagrees: fix policy/rbac.rego::_path_matches\n"
        f"  Both implementations must agree on every case in PARITY_CASES."
    )
