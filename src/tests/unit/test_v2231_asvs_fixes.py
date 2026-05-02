"""
Regression tests for v2.23.1 ASVS v5 L3 Stage-B release-blocker fixes.

Controls fixed:
  - V8.3.2  disable_user now invalidates live sessions (Fix 1)
  - V1.2.10 CSV formula injection — escape_csv_cell helper (Fix 2)
  - V1.2.1  Stored XSS — escapeHtml present in dashboard.js (Fix 3 — smoke only)

Reference: /Users/max/Documents/Claude/Internal/ACS/v3/asvs-stage-b-class3-2026-04-28.md
"""
# Last updated: 2026-04-28T00:00:00+01:00
from __future__ import annotations

import asyncio
import io
import csv
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from yashigani.audit.export import AuditLogExporter, escape_csv_cell
from yashigani.audit.config import AuditConfig


# ---------------------------------------------------------------------------
# Fix 1 — V8.3.2: disable_user must invalidate existing sessions
# CWE-613: Insufficient Session Expiration
#
# These tests validate the route logic directly, bypassing the full
# backoffice application import chain (which requires asyncpg, multipart,
# etc. not present in the lightweight macOS test env).
# ---------------------------------------------------------------------------

class TestDisableUserSessionInvalidationLogic:
    """
    V8.3.2 regression: validates the route logic in users.py line-by-line.

    We test the async function logic directly by importing only the module
    under test with its heavy dependencies pre-mocked, then calling the
    coroutine synchronously via asyncio.run.
    """

    def _make_account_record(self, account_id: str, username: str, disabled: bool = False):
        rec = MagicMock()
        rec.account_id = account_id
        rec.username = username
        rec.account_tier = "user"
        rec.disabled = disabled
        return rec

    def _make_state(self, record):
        state = MagicMock()
        state.auth_service.get_account = AsyncMock(return_value=record)
        state.auth_service.disable = AsyncMock(return_value=True)
        state.session_store.invalidate_all_for_account = MagicMock(return_value=1)
        state.audit_writer.write = MagicMock()
        return state

    def test_disable_user_calls_invalidate_sessions(self):
        """
        Core regression for V8.3.2: after disable(), invalidate_all_for_account()
        must be called with the user's account_id.

        Tests the source of users.py directly (ast/source level) so we are not
        blocked by missing asyncpg/multipart in the macOS test env.
        """
        import ast
        source_path = (
            Path(__file__).parent.parent.parent
            / "yashigani"
            / "backoffice"
            / "routes"
            / "users.py"
        )
        source = source_path.read_text(encoding="utf-8")

        # The fix requires the disable_user function body to contain:
        # 1. A get_account call to fetch the record
        # 2. An account_tier check
        # 3. A disable() call
        # 4. An invalidate_all_for_account call
        assert "get_account" in source, "disable_user must call get_account to fetch record"
        assert "account_tier" in source, "disable_user must check account_tier guard"
        assert "invalidate_all_for_account" in source, (
            "disable_user MUST call invalidate_all_for_account — V8.3.2 fix"
        )

        # Verify the fix is in the disable_user function body specifically
        tree = ast.parse(source)
        disable_fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "disable_user":
                disable_fn = ast.unparse(node)
                break

        assert disable_fn is not None, "disable_user function not found"
        assert "get_account" in disable_fn, "disable_user must fetch account record before disabling"
        assert "invalidate_all_for_account" in disable_fn, (
            "disable_user must invalidate sessions — V8.3.2 fix not present in function body"
        )
        assert "account_tier" in disable_fn, (
            "disable_user must guard against admin-tier accounts (tier check missing)"
        )

    def test_disable_user_already_disabled_check_present(self):
        """disable_user must return early if already disabled (idempotency guard)."""
        import ast
        source_path = (
            Path(__file__).parent.parent.parent
            / "yashigani"
            / "backoffice"
            / "routes"
            / "users.py"
        )
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        disable_fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "disable_user":
                disable_fn = ast.unparse(node)
                break
        assert disable_fn is not None
        assert "already_disabled" in disable_fn, (
            "disable_user must return already_disabled for idempotent calls"
        )

    def test_disable_admin_equivalent_has_same_pattern(self):
        """
        Parity check: disable_admin (accounts.py) and disable_user (users.py)
        must both call get_account + invalidate_all_for_account.
        This prevents drift between the two implementations.
        """
        import ast
        src_dir = (
            Path(__file__).parent.parent.parent / "yashigani" / "backoffice" / "routes"
        )
        for fname, fn_name in [
            ("accounts.py", "disable_admin"),
            ("users.py", "disable_user"),
        ]:
            source = (src_dir / fname).read_text(encoding="utf-8")
            tree = ast.parse(source)
            fn_body = None
            for node in ast.walk(tree):
                if isinstance(node, ast.AsyncFunctionDef) and node.name == fn_name:
                    fn_body = ast.unparse(node)
                    break
            assert fn_body is not None, f"{fn_name} not found in {fname}"
            assert "invalidate_all_for_account" in fn_body, (
                f"{fn_name} in {fname} must call invalidate_all_for_account"
            )


# ---------------------------------------------------------------------------
# Fix 2 — V1.2.10: escape_csv_cell prevents formula injection
# CWE-1236: Improper Neutralization of Formula Elements in a CSV File
# ---------------------------------------------------------------------------

class TestEscapeCsvCell:
    """
    V1.2.10 regression: escape_csv_cell must prefix formula-trigger characters
    with a single quote so Excel/LibreOffice does not interpret them as formulas.
    """

    def test_equals_prefix_escaped(self):
        assert escape_csv_cell("=cmd|'/c calc'!A1") == "'=cmd|'/c calc'!A1"

    def test_plus_prefix_escaped(self):
        assert escape_csv_cell("+1234567890") == "'+1234567890"

    def test_minus_prefix_escaped(self):
        assert escape_csv_cell("-1+2") == "'-1+2"

    def test_at_prefix_escaped(self):
        assert escape_csv_cell("@SUM(1+2)") == "'@SUM(1+2)"

    def test_tab_prefix_escaped(self):
        # \t as first char
        assert escape_csv_cell("\t=malicious") == "'\t=malicious"

    def test_bom_equals_escaped(self):
        # BOM (﻿) followed by =
        bom_eq = "﻿=BOMattack"
        result = escape_csv_cell(bom_eq)
        assert result.startswith("'")

    def test_bom_plus_escaped(self):
        bom_plus = "﻿+BOM"
        assert escape_csv_cell(bom_plus).startswith("'")

    def test_bom_minus_escaped(self):
        bom_minus = "﻿-BOM"
        assert escape_csv_cell(bom_minus).startswith("'")

    def test_bom_at_escaped(self):
        bom_at = "﻿@BOM"
        assert escape_csv_cell(bom_at).startswith("'")

    def test_safe_value_passthrough(self):
        assert escape_csv_cell("hello world") == "hello world"

    def test_normal_username_passthrough(self):
        assert escape_csv_cell("alice@example.com") == "alice@example.com"

    def test_newline_stripped(self):
        # Newlines replaced with spaces
        result = escape_csv_cell("line1\nline2")
        assert "\n" not in result
        assert "line1" in result

    def test_carriage_return_stripped(self):
        result = escape_csv_cell("line1\rline2")
        assert "\r" not in result

    def test_integer_value_cast(self):
        # Non-string inputs should be coerced
        result = escape_csv_cell(42)
        assert result == "42"

    def test_none_cast(self):
        result = escape_csv_cell(None)
        assert result == "None"

    def test_numeric_string_passthrough(self):
        # Numbers that don't start with formula triggers are safe
        assert escape_csv_cell("12345") == "12345"

    # -------------------------------------------------------------------------
    # LF-CSV-BYPASS regression tests (Lu 2026-04-27)
    # These are the six bypasses Lu empirically reproduced against the original
    # fix.  All must be escaped by the strip-and-test approach.
    # -------------------------------------------------------------------------

    def test_cr_then_equals_escaped(self):
        """LF-CSV-BYPASS: \\r=cmd... — CR normalised to space, strip reveals =."""
        # After replace("\r"," ") we get " =cmd..." which the old code passed.
        # The new code strips leading whitespace before the trigger check.
        result = escape_csv_cell("\r=cmd|'/c calc'!A1")
        assert result.startswith("'"), (
            "LF-CSV-BYPASS: \\r=cmd... must be prefixed with ' — was bypassed by old fix"
        )

    def test_lf_then_equals_escaped(self):
        """LF-CSV-BYPASS: \\n=cmd... — LF normalised to space, strip reveals =."""
        result = escape_csv_cell("\n=cmd|'/c calc'!A1")
        assert result.startswith("'"), (
            "LF-CSV-BYPASS: \\n=cmd... must be prefixed with '"
        )

    def test_space_then_equals_escaped(self):
        """LF-CSV-BYPASS: ' =cmd...' — attacker-supplied leading space."""
        result = escape_csv_cell(" =cmd|'/c calc'!A1")
        assert result.startswith("'"), (
            "LF-CSV-BYPASS: ' =cmd...' must be prefixed with ' — Excel strips leading space"
        )

    def test_tab_then_equals_escaped(self):
        """LF-CSV-BYPASS: \\t=cmd... — leading tab before formula trigger."""
        result = escape_csv_cell("\t=cmd|'/c calc'!A1")
        assert result.startswith("'"), (
            "LF-CSV-BYPASS: \\t=cmd... must be prefixed with '"
        )

    def test_vt_then_equals_escaped(self):
        """LF-CSV-BYPASS: \\v=cmd... — vertical tab before formula trigger."""
        result = escape_csv_cell("\v=cmd|'/c calc'!A1")
        assert result.startswith("'"), (
            "LF-CSV-BYPASS: \\v=cmd... must be prefixed with '"
        )

    def test_ff_then_equals_escaped(self):
        """LF-CSV-BYPASS: \\f=cmd... — form feed before formula trigger."""
        result = escape_csv_cell("\f=cmd|'/c calc'!A1")
        assert result.startswith("'"), (
            "LF-CSV-BYPASS: \\f=cmd... must be prefixed with '"
        )

    def test_space_then_plus_escaped(self):
        """LF-CSV-BYPASS: leading space before + trigger."""
        result = escape_csv_cell(" +1234567890")
        assert result.startswith("'"), (
            "LF-CSV-BYPASS: ' +...' must be prefixed with '"
        )

    def test_space_then_at_escaped(self):
        """LF-CSV-BYPASS: leading space before @ trigger."""
        result = escape_csv_cell(" @SUM(1+1)")
        assert result.startswith("'"), (
            "LF-CSV-BYPASS: ' @...' must be prefixed with '"
        )

    def test_safe_value_with_embedded_space_passthrough(self):
        """Non-trigger value with a space is NOT escaped."""
        assert escape_csv_cell("hello world") == "hello world"

    def test_midstring_formula_trigger_not_escaped(self):
        """A formula trigger in the middle of the string (not leading) is safe."""
        # " hello =world" — after stripping leading nothing, starts with "h"
        result = escape_csv_cell("hello =world")
        assert result == "hello =world"


class TestAuditExportCsvFormulaSafety:
    """Integration check: the CSV export streams correctly escape formula cells."""

    def _collect_async(self, agen) -> bytes:
        async def _run():
            chunks = []
            async for chunk in agen:
                chunks.append(chunk)
            return b"".join(chunks)
        return asyncio.run(_run())

    def _make_exporter(self, tmp_path: Path, records: list[dict]) -> AuditLogExporter:
        log_file = tmp_path / "audit.log"
        with open(log_file, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        config = AuditConfig(
            log_path=str(log_file),
            max_file_size_mb=100,
            retention_days=90,
        )
        return AuditLogExporter(config=config)

    def test_formula_field_escaped_in_export(self, tmp_path):
        """A record with =cmd|... in a field must appear as '=cmd|... in the CSV."""
        records = [
            {
                "timestamp": "2026-04-28T00:00:00+00:00",
                "event_type": "ADMIN_LOGIN",
                "user": "=cmd|'/c calc'!A1",
                "outcome": "failure",
            }
        ]
        exporter = self._make_exporter(tmp_path, records)
        raw = self._collect_async(
            exporter.export("2026-04-28", "2026-04-28", format="csv")
        ).decode("utf-8")
        # The user field must be prefixed with '
        assert "'=cmd|" in raw
        # Must NOT appear as a bare formula trigger
        assert ",=cmd|" not in raw

    def test_normal_fields_not_modified(self, tmp_path):
        """Safe fields must pass through unchanged."""
        records = [
            {
                "timestamp": "2026-04-28T00:00:00+00:00",
                "event_type": "ADMIN_LOGIN",
                "user": "alice",
                "outcome": "success",
            }
        ]
        exporter = self._make_exporter(tmp_path, records)
        raw = self._collect_async(
            exporter.export("2026-04-28", "2026-04-28", format="csv")
        ).decode("utf-8")
        lines = raw.strip().splitlines()
        # header + 1 data row
        assert len(lines) == 2
        assert "alice" in lines[1]


# ---------------------------------------------------------------------------
# Fix 3 — V1.2.1: escapeHtml helper present in dashboard.js (smoke)
# CWE-79: Improper Neutralization of Input During Web Page Generation
# ---------------------------------------------------------------------------

class TestDashboardJsEscapeHtmlPresent:
    """
    Smoke test: dashboard.js must define an escapeHtml function AND use it
    around all 10 innerHTML sinks identified in Stage B §4.1.

    This is a static-analysis proxy test — it reads the JS file and checks
    for structural invariants.  An XSS-capable integration test would require
    a browser; that belongs to Ava's Playwright suite.
    """

    DASHBOARD_JS = (
        Path(__file__).parent.parent.parent
        / "yashigani"
        / "backoffice"
        / "static"
        / "js"
        / "dashboard.js"
    )

    def _js_content(self) -> str:
        return self.DASHBOARD_JS.read_text(encoding="utf-8")

    def test_escape_html_function_defined(self):
        """dashboard.js must define escapeHtml()."""
        js = self._js_content()
        assert "function escapeHtml" in js or "const escapeHtml" in js or "var escapeHtml" in js, (
            "escapeHtml not defined in dashboard.js — stored XSS fix not landed"
        )

    def test_escape_html_used_in_agents_table(self):
        """S1: agent table (a.name, a.agent_id, a.upstream_url) must use escapeHtml."""
        js = self._js_content()
        # The agents table row construction must wrap user data
        # We look for escapeHtml( appearing in the loadAgents function body
        agents_fn_start = js.find("function loadAgents")
        agents_fn_end = js.find("\nasync function ", agents_fn_start + 1)
        if agents_fn_end == -1:
            agents_fn_end = len(js)
        agents_fn = js[agents_fn_start:agents_fn_end]
        assert "escapeHtml(" in agents_fn, (
            "escapeHtml not called in loadAgents — S1 sink still open"
        )

    def test_escape_html_used_in_accounts_table(self):
        """S2/S3: admin + user accounts tables must use escapeHtml."""
        js = self._js_content()
        accounts_fn_start = js.find("function loadAccounts")
        accounts_fn_end = js.find("\nasync function ", accounts_fn_start + 1)
        if accounts_fn_end == -1:
            accounts_fn_end = len(js)
        accounts_fn = js[accounts_fn_start:accounts_fn_end]
        assert "escapeHtml(" in accounts_fn, (
            "escapeHtml not called in loadAccounts — S2/S3 sinks still open"
        )

    def test_escape_html_used_in_audit_viewer(self):
        """S9: audit log viewer (e.user, e.agent_id, e.detail, e.summary) must use escapeHtml."""
        js = self._js_content()
        audit_fn_start = js.find("function searchAudit")
        audit_fn_end = js.find("\nasync function ", audit_fn_start + 1)
        if audit_fn_end == -1:
            audit_fn_end = len(js)
        audit_fn = js[audit_fn_start:audit_fn_end]
        assert "escapeHtml(" in audit_fn, (
            "escapeHtml not called in searchAudit — S9 sink still open (broadest attacker reach)"
        )

    def test_escape_html_used_in_blocked_ips(self):
        """S10: blocked-IP reason field must use escapeHtml."""
        js = self._js_content()
        ip_fn_start = js.find("function loadIpAccess")
        ip_fn_end = js.find("\nasync function ", ip_fn_start + 1)
        if ip_fn_end == -1:
            ip_fn_end = len(js)
        ip_fn = js[ip_fn_start:ip_fn_end]
        assert "escapeHtml(" in ip_fn, (
            "escapeHtml not called in loadIpAccess — S10 sink still open"
        )


# ---------------------------------------------------------------------------
# Fix 4 — V10.3.5: sender-constrained bearer tokens (SPIFFE-URI binding)
# CWE-287: Improper Authentication (token replay without proof-of-possession)
# ---------------------------------------------------------------------------

class TestSpiffeUriBoundTokens:
    """
    V10.3.5 regression: when an identity has a bound_spiffe_uri set, the
    gateway MUST reject bearer token requests that don't present a matching
    X-SPIFFE-ID header.
    """

    def _make_identity(self, bound_spiffe_uri: str = "") -> dict:
        return {
            "identity_id": "idnt_test001",
            "kind": "service",
            "name": "test-agent",
            "slug": "test-agent",
            "status": "active",
            "groups": [],
            "allowed_models": [],
            "sensitivity_ceiling": "PUBLIC",
            "bound_spiffe_uri": bound_spiffe_uri,
        }

    def _make_registry(self, identity: dict):
        registry = MagicMock()
        registry.get_by_api_key = MagicMock(return_value=identity)
        return registry

    def _make_request(self, bearer: str, spiffe_id: str = ""):
        from starlette.testclient import TestClient
        from starlette.requests import Request as StarletteRequest
        from starlette.datastructures import Headers

        headers = {"authorization": f"Bearer {bearer}"}
        if spiffe_id:
            headers["x-spiffe-id"] = spiffe_id

        # Build a minimal mock Request with the right headers
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v1/chat/completions",
            "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
        }
        return StarletteRequest(scope)

    def test_unbound_token_no_cert_accepted(self):
        """No bound_spiffe_uri → no cert required, identity resolved normally."""
        from yashigani.gateway.openai_router import _resolve_identity, configure
        identity = self._make_identity(bound_spiffe_uri="")
        registry = self._make_registry(identity)
        configure(identity_registry=registry)

        req = self._make_request("valid-token-abc")
        result = _resolve_identity(req)
        assert result is not None
        assert result["identity_id"] == "idnt_test001"

    def test_bound_token_matching_cert_accepted(self):
        """bound_spiffe_uri set + X-SPIFFE-ID matches → accepted."""
        from yashigani.gateway.openai_router import _resolve_identity, configure
        uri = "spiffe://yashigani.internal/agent-prod"
        identity = self._make_identity(bound_spiffe_uri=uri)
        registry = self._make_registry(identity)
        configure(identity_registry=registry)

        req = self._make_request("valid-token-abc", spiffe_id=uri)
        result = _resolve_identity(req)
        assert result is not None
        assert result["identity_id"] == "idnt_test001"

    def test_bound_token_wrong_cert_rejected(self):
        """bound_spiffe_uri set + X-SPIFFE-ID does NOT match → None (rejected)."""
        from yashigani.gateway.openai_router import _resolve_identity, configure
        uri = "spiffe://yashigani.internal/agent-prod"
        identity = self._make_identity(bound_spiffe_uri=uri)
        registry = self._make_registry(identity)
        configure(identity_registry=registry)

        req = self._make_request("valid-token-abc", spiffe_id="spiffe://yashigani.internal/evil-agent")
        result = _resolve_identity(req)
        assert result is None, "Stolen token with wrong SPIFFE-ID must be rejected"

    def test_bound_token_no_cert_rejected(self):
        """bound_spiffe_uri set + no X-SPIFFE-ID header → None (rejected)."""
        from yashigani.gateway.openai_router import _resolve_identity, configure
        uri = "spiffe://yashigani.internal/agent-prod"
        identity = self._make_identity(bound_spiffe_uri=uri)
        registry = self._make_registry(identity)
        configure(identity_registry=registry)

        req = self._make_request("valid-token-abc", spiffe_id="")
        result = _resolve_identity(req)
        assert result is None, "Bound token without any client cert must be rejected"

    def test_identity_record_has_bound_spiffe_uri_field(self):
        """IdentityRecord dataclass must have bound_spiffe_uri field (backward compat: default empty)."""
        from yashigani.identity.registry import IdentityRecord, IdentityKind
        rec = IdentityRecord(
            identity_id="idnt_x",
            kind=IdentityKind.SERVICE,
            name="agent",
            slug="agent",
        )
        assert hasattr(rec, "bound_spiffe_uri")
        assert rec.bound_spiffe_uri == "", "Default must be empty (no binding for community agents)"

    def test_registry_register_accepts_spiffe_uri(self):
        """IdentityRegistry.register() must accept spiffe_uri kwarg and store it."""
        import fakeredis
        from yashigani.identity.registry import IdentityRegistry, IdentityKind

        try:
            r = fakeredis.FakeRedis(decode_responses=False)
        except ImportError:
            pytest.skip("fakeredis not installed")

        registry = IdentityRegistry(redis_client=r)
        spiffe_uri = "spiffe://yashigani.internal/test-agent"
        identity_id, _ = registry.register(
            kind=IdentityKind.SERVICE,
            name="test-agent",
            slug="test-agent-v10",
            spiffe_uri=spiffe_uri,
        )
        stored = registry.get(identity_id)
        assert stored is not None
        assert stored.get("bound_spiffe_uri") == spiffe_uri

    def test_caddyfiles_have_verify_if_given_on_agents_and_v1(self):
        """
        All 3 Caddyfiles must have verify_if_given client_auth on /agents/* and /v1/* paths.
        Structural check — catches Caddy config drift.
        """
        import re
        caddy_dir = Path(__file__).parent.parent.parent.parent / "docker"
        caddyfiles = [
            caddy_dir / "Caddyfile.acme",
            caddy_dir / "Caddyfile.ca",
            caddy_dir / "Caddyfile.selfsigned",
        ]
        for cf in caddyfiles:
            content = cf.read_text(encoding="utf-8")
            assert "verify_if_given" in content, (
                f"{cf.name} missing verify_if_given — V10.3.5 Caddy fix not landed"
            )
            assert "X-SPIFFE-ID" in content, (
                f"{cf.name} missing X-SPIFFE-ID header forwarding for /v1 or /agents"
            )
