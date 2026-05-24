"""
Agent OPENAI_API_BASE port contract (BUG-V241-LANGFLOW-LETTA-BASE-URL regression gate).

Static contract: asserts that every agent bundle that calls back to the gateway
(langflow, letta) routes through the plain-HTTP mesh port (8081), NOT the
mTLS-only port (8080).

Background
----------
Gateway exposes two listeners:
  :8080 — full mTLS (ssl.CERT_REQUIRED); requires client cert on every connection.
  :8081 — plain HTTP; protected by network isolation (langflow_isolated /
           letta_isolated bridges, Docker internal networks).

Langflow and letta run with cap_drop:[ALL] and mount no client certs — they
cannot complete a TLS handshake with :8080.  They MUST use :8081.

Open WebUI was fixed to use :8081 in v2.23.4.  Langflow and letta still had
:8080 in the compose file at the time BUG-V241-LANGFLOW-LETTA-BASE-URL was
discovered (2026-05-24).

These tests:
  - FAIL against docker-compose.yml pre-Su-fix (8080 values present)
  - PASS after Su's fix (8080 → 8081)
  - Are added to the CI gate (ci.yml unit-test run) so they catch regression
    before any compose change ships

A1 amendment principle: absence of a dispatch test = SKIP, not PASS.
Prior E2E sweeps proved container-healthy and route-existence but NOT the
OPENAI_API_BASE callback leg.  This gate closes that assumption gap.

YSG-RISK-059 / OWASP ASVS v5 V11.1 / A1 amendment.

Last updated: 2026-05-24T00:00:00+00:00
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).parents[2]
_COMPOSE_FILE = _REPO_ROOT / "docker" / "docker-compose.yml"

# Canonical ports (see docker-compose.yml comments + mesh_entrypoint.py)
_MESH_PORT = 8081   # plain-HTTP internal mesh — agents MUST target this
_MTLS_PORT = 8080   # mTLS-only — agents MUST NOT use this as OPENAI_API_BASE


def _compose_text() -> str:
    assert _COMPOSE_FILE.exists(), f"Compose file not found: {_COMPOSE_FILE}"
    return _COMPOSE_FILE.read_text()


def _extract_service_section(compose_text: str, service_name: str) -> str:
    """
    Extract a service section from compose YAML text.

    Returns lines from the '  <service_name>:' header up to (but not including)
    the next sibling service definition at the same 2-space indent level.
    Sufficient for OPENAI_API_BASE extraction.
    """
    lines = compose_text.splitlines()
    result_lines: list[str] = []
    inside = False

    for line in lines:
        if re.match(rf'^  {re.escape(service_name)}:', line):
            inside = True
            result_lines = [line]
            continue
        if inside:
            # Stop at next sibling (2-space indent, letter, colon) — not a deeper level
            if re.match(r'^  [a-zA-Z_-]', line) and not line.startswith('   '):
                break
            result_lines.append(line)

    return '\n'.join(result_lines)


class TestAgentBaseUrlPort:
    """
    Regression gate for BUG-V241-LANGFLOW-LETTA-BASE-URL.

    Asserts that agent OPENAI_API_BASE values use port 8081 (mesh) not 8080 (mTLS).
    """

    def test_langflow_openai_api_base_uses_mesh_port(self):
        """
        Langflow MUST use http://gateway:8081/v1, NOT http://gateway:8080/v1.

        Port 8080 requires mutual TLS; langflow presents no client cert.
        Every langflow inference call fails silently with TLS handshake error
        when this is misconfigured.

        FAILS pre-Su-fix: OPENAI_API_BASE: http://gateway:8080/v1
        PASSES post-Su-fix: OPENAI_API_BASE: http://gateway:8081/v1

        Regression: BUG-V241-LANGFLOW-LETTA-BASE-URL / YSG-RISK-059.
        Control: ASVS V11.1 (Application Logic) / A1 amendment principle.
        """
        text = _compose_text()
        section = _extract_service_section(text, "langflow")
        assert section, "langflow service section not found in docker-compose.yml"

        match = re.search(r'OPENAI_API_BASE:\s*(\S+)', section)
        assert match, "OPENAI_API_BASE not found in langflow service section"

        url = match.group(1)
        assert f":{_MESH_PORT}" in url, (
            f"langflow OPENAI_API_BASE must use port {_MESH_PORT} (plain-HTTP mesh).\n"
            f"  Current value: {url}\n"
            f"  Required:      http://gateway:{_MESH_PORT}/v1\n"
            f"  Bug:           port {_MTLS_PORT} is mTLS-only (ssl.CERT_REQUIRED).\n"
            f"                 Langflow has no client cert — every LLM call fails.\n"
            f"  Fix:           change OPENAI_API_BASE to http://gateway:{_MESH_PORT}/v1"
        )
        assert f":{_MTLS_PORT}" not in url, (
            f"langflow OPENAI_API_BASE uses mTLS port {_MTLS_PORT}: {url}\n"
            f"  BUG-V241-LANGFLOW-LETTA-BASE-URL — fix: http://gateway:{_MESH_PORT}/v1"
        )

    def test_letta_openai_api_base_uses_mesh_port(self):
        """
        Letta MUST use http://gateway:8081/v1, NOT http://gateway:8080/v1.

        Same rationale as langflow. Letta also has cap_drop:[ALL] and no
        client cert mount for the gateway mTLS listener.

        FAILS pre-Su-fix: OPENAI_API_BASE: http://gateway:8080/v1
        PASSES post-Su-fix: OPENAI_API_BASE: http://gateway:8081/v1

        Regression: BUG-V241-LANGFLOW-LETTA-BASE-URL / YSG-RISK-059.
        """
        text = _compose_text()
        section = _extract_service_section(text, "letta")
        # Strip letta-pgbouncer from the section (starts before letta)
        # We want only the 'letta:' service block
        if "letta-pgbouncer" in section[:50]:
            # Fell into letta-pgbouncer — skip forward to letta proper
            section = _extract_service_section(text, "  letta\n")
        assert section, "letta service section not found in docker-compose.yml"

        match = re.search(r'OPENAI_API_BASE:\s*(\S+)', section)
        assert match, (
            f"OPENAI_API_BASE not found in letta service section.\n"
            f"  Section (first 500 chars): {section[:500]}"
        )

        url = match.group(1)
        assert f":{_MESH_PORT}" in url, (
            f"letta OPENAI_API_BASE must use port {_MESH_PORT} (plain-HTTP mesh).\n"
            f"  Current value: {url}\n"
            f"  Required:      http://gateway:{_MESH_PORT}/v1\n"
            f"  Bug:           port {_MTLS_PORT} is mTLS-only. Letta has no client cert.\n"
            f"  Fix:           change OPENAI_API_BASE to http://gateway:{_MESH_PORT}/v1"
        )
        assert f":{_MTLS_PORT}" not in url, (
            f"letta OPENAI_API_BASE uses mTLS port {_MTLS_PORT}: {url}\n"
            f"  BUG-V241-LANGFLOW-LETTA-BASE-URL — fix: http://gateway:{_MESH_PORT}/v1"
        )

    def test_open_webui_openai_api_base_url_uses_mesh_port(self):
        """
        Open WebUI MUST use http://gateway:8081/v1 (via OPENAI_API_BASE_URL).

        This is the correct reference implementation (fixed in v2.23.4).
        This test guards against regression to port 8080.
        """
        text = _compose_text()
        section = _extract_service_section(text, "open-webui")
        assert section, "open-webui service section not found in docker-compose.yml"

        match = re.search(r'OPENAI_API_BASE_URL:\s*(\S+)', section)
        assert match, "OPENAI_API_BASE_URL not found in open-webui service section"

        url = match.group(1)
        assert f":{_MESH_PORT}" in url, (
            f"open-webui OPENAI_API_BASE_URL does not use mesh port {_MESH_PORT}: {url}"
        )

    def test_all_agent_base_urls_use_same_mesh_port(self):
        """
        Parity: langflow, letta, and open-webui MUST all point at port 8081.

        Any divergence is a misconfiguration — one service will fail while
        others succeed, making the bug non-obvious.

        Documents the invariant: every service that calls the gateway for LLM
        inference MUST use the internal mesh port (8081), never the mTLS port.
        """
        text = _compose_text()
        ports: dict[str, int | None] = {}

        for service, env_var in [
            ("langflow",   "OPENAI_API_BASE"),
            ("letta",      "OPENAI_API_BASE"),
            ("open-webui", "OPENAI_API_BASE_URL"),
        ]:
            section = _extract_service_section(text, service)
            if not section:
                continue
            match = re.search(rf'{re.escape(env_var)}:\s*(\S+)', section)
            if match:
                url = match.group(1)
                port_match = re.search(r':(\d+)/', url)
                ports[service] = int(port_match.group(1)) if port_match else None

        assert len(ports) >= 2, f"Could not extract ports for parity check: {ports}"

        wrong = {svc: p for svc, p in ports.items() if p != _MESH_PORT}
        assert not wrong, (
            f"Services using wrong gateway port:\n"
            + "\n".join(f"  {svc}: port {p} (expected {_MESH_PORT})" for svc, p in wrong.items())
            + f"\n  BUG-V241-LANGFLOW-LETTA-BASE-URL — all must use port {_MESH_PORT}."
        )

    def test_no_agent_uses_mtls_port_as_base_url(self):
        """
        Exhaustive scan: no service's OPENAI_API_BASE / OPENAI_API_BASE_URL
        should reference gateway:8080.

        Catches new agent bundles added without the mesh-port requirement.
        """
        text = _compose_text()

        # Find all OPENAI_API_BASE* values across the entire compose file
        wrong_instances = []
        for match in re.finditer(
            r'(OPENAI_API_BASE(?:_URL)?:\s*(http://gateway:\d+/v1))',
            text
        ):
            full_match = match.group(1)
            url = match.group(2)
            if f":{_MTLS_PORT}" in url:
                # Find the service this belongs to (look backwards for service name)
                pos = match.start()
                preceding = text[:pos]
                service_matches = list(re.finditer(r'^  ([a-zA-Z_-]+):', preceding, re.MULTILINE))
                service_name = service_matches[-1].group(1) if service_matches else "unknown"
                wrong_instances.append(f"  {service_name}: {full_match.strip()}")

        assert not wrong_instances, (
            f"Found services using mTLS port {_MTLS_PORT} as OPENAI_API_BASE:\n"
            + "\n".join(wrong_instances)
            + f"\n\nFix: change all instances to gateway:{_MESH_PORT}/v1\n"
            f"BUG-V241-LANGFLOW-LETTA-BASE-URL / YSG-RISK-059"
        )
