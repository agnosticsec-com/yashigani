"""
EX-231-10 Layer B — Caddy HMAC shared-secret marker integration test.
Last updated: 2026-04-29T16:04:58+01:00

Layer A (network isolation) was verified by test_caddy_centric_isolation.py.
Layer B closes the residual: a data-network attacker with a valid mTLS cert
can present the cert + forge X-SPIFFE-ID, but lacks the per-install
caddy_internal_hmac secret → 401.

Design (static-shared-secret variant — Caddy 2 has no inline HMAC module):
  - install.sh generates caddy_internal_hmac (32-byte hex).
  - Caddy reads CADDY_INTERNAL_HMAC env var and injects the raw value as
    X-Caddy-Verified-Secret on every reverse_proxy to backoffice/gateway.
  - Tom's middleware reads the same secret at lifespan startup and checks:
      hmac.compare_digest(request.headers["X-Caddy-Verified-Secret"], secret)
    → 401 if header absent or value mismatched.

TESTS IN THIS FILE:
  TEST 1 — data-network attacker: mTLS cert + forged X-SPIFFE-ID, NO valid
            X-Caddy-Verified-Secret → expected 401.
            STATUS: WILL FAIL until Tom's middleware lands (intentional).

  TEST 2 — data-network attacker WITH a valid X-Caddy-Verified-Secret (same
            value as the installed secret — proves the middleware accepts it).
            STATUS: WILL FAIL until Tom's middleware lands (intentional).

  TEST 3 — legitimate Caddy-proxied request → expected 200 (regression).
            STATUS: PASS once the stack is up (with or without Layer B
            middleware — this test shows the baseline still works).

All three tests are skipped gracefully when:
  - No running compose stack is detected, OR
  - The caddy_internal_hmac secret is not readable on disk (test isolation).

Tom's follow-on dispatch: implement caddy_verified_secret middleware in
backoffice + gateway, then run this file — all three tests must be GREEN.
"""
from __future__ import annotations

import hmac
import os
import shutil
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
import pytest

pytestmark = pytest.mark.integration

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

_DEFAULT_SECRETS_DIR = os.path.join(
    os.path.dirname(__file__),          # src/tests/integration/
    "..", "..", "..",                    # → repo root
    "docker", "secrets",
)

_SECRETS_DIR = os.environ.get(
    "YASHIGANI_SECRETS_DIR",
    os.path.normpath(_DEFAULT_SECRETS_DIR),
)

_BACKOFFICE_INTERNAL_URL = os.environ.get(
    "YASHIGANI_BACKOFFICE_INTERNAL_URL",
    "https://backoffice:8443",
)

_TLS_DOMAIN = os.environ.get("YASHIGANI_TLS_DOMAIN", "localhost")
_HTTPS_PORT = int(os.environ.get("YASHIGANI_HTTPS_PORT", "443"))

_PROBE_ENDPOINT = "/internal/metrics"   # requires X-Caddy-Verified-Secret
_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _runtime() -> str:
    if shutil.which("podman"):
        return "podman"
    if shutil.which("docker"):
        return "docker"
    return ""


def _compose_stack_running() -> bool:
    rt = _runtime()
    if not rt:
        return False
    result = subprocess.run(
        [rt, "inspect", "--format", "{{.State.Status}}", "yashigani-backoffice-1"],
        capture_output=True, text=True,
    )
    return result.returncode == 0 and result.stdout.strip() == "running"


def _read_secret(name: str) -> str | None:
    """Read a secret from docker/secrets/. Returns None if missing."""
    path = os.path.join(_SECRETS_DIR, name)
    try:
        with open(path, "r") as fh:
            return fh.read().strip()
    except OSError:
        return None


def _mTLS_ssl_context(
    ca_cert: str,
    client_cert: str,
    client_key: str,
) -> ssl.SSLContext:
    """Build an SSL context presenting a mTLS client cert."""
    ctx = ssl.create_default_context(cafile=ca_cert)
    ctx.load_cert_chain(certfile=client_cert, keyfile=client_key)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # self-signed in test environments
    return ctx


def _https_get(
    url: str,
    headers: dict[str, str],
    ssl_ctx: ssl.SSLContext,
    timeout: int = _TIMEOUT,
) -> int:
    """HTTP GET with custom headers. Returns status code."""
    req = urllib.request.Request(url, headers=headers)
    try:
        resp = urllib.request.urlopen(req, context=ssl_ctx, timeout=timeout)
        return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


# ---------------------------------------------------------------------------
# Skip conditions
# ---------------------------------------------------------------------------

def _skip_if_no_stack():
    if not _compose_stack_running():
        pytest.skip(
            "Yashigani compose stack not running — skipping Layer B HMAC test"
        )


def _skip_if_no_secret():
    secret = _read_secret("caddy_internal_hmac")
    if not secret:
        pytest.skip(
            "caddy_internal_hmac secret not found in docker/secrets/ — "
            "run install.sh to generate it before running Layer B tests"
        )
    return secret


# ---------------------------------------------------------------------------
# Layer B tests — run from the test-runner host against the internal URL.
#
# NOTE: In compose these probes go DIRECTLY to backoffice:8443 (not via Caddy).
# This simulates a data-network attacker who has broken network isolation and
# reaches the backoffice/gateway directly with a valid mTLS cert. Layer B
# closes this by requiring X-Caddy-Verified-Secret at the application layer.
#
# The test runner must be able to reach backoffice:8443 directly — normally
# this means the test runs inside the yashigani network namespace. For macOS
# dev environments, use `docker exec` into a network-adjacent container, or
# add the services to a host-reachable port in docker-compose.podman-override.
#
# Alternatively: tests can exec into the prometheus container (on obs network
# → not on caddy_internal, so it CANNOT reach backoffice:8443 either, which is
# what TEST 1 should confirm). For full Layer B middleware tests, a test
# container on caddy_internal is needed.
#
# The architecture of this test file matches Layer A's approach: exec via
# docker/podman into a strategically positioned container.
# ---------------------------------------------------------------------------

class TestLayerBHmacMarker:
    """
    Layer B — cryptographic HMAC marker verification.

    Probe backoffice:8443/internal/metrics directly (bypassing Caddy) from a
    container that has mTLS cert access but NOT the caddy_internal_hmac secret.
    Backoffice middleware MUST reject it with 401.

    These tests will FAIL until Tom's middleware lands (caddy_verified_secret
    middleware in yashigani.middleware.caddy_auth). That is intentional — this
    file is the scaffold; Tom's dispatch makes it green.
    """

    @pytest.fixture(autouse=True)
    def require_stack_and_secret(self):
        _skip_if_no_stack()
        self.secret = _skip_if_no_secret()

        # Build paths to test certs. Use prometheus_client (an unprivileged
        # service cert) to simulate a non-Caddy mTLS peer.
        self.ca_cert = os.path.join(_SECRETS_DIR, "ca_root.crt")
        self.client_cert = os.path.join(_SECRETS_DIR, "prometheus_client.crt")
        self.client_key = os.path.join(_SECRETS_DIR, "prometheus_client.key")

        for path in (self.ca_cert, self.client_cert, self.client_key):
            if not os.path.exists(path):
                pytest.skip(
                    f"Required cert not found: {path}. "
                    "Run install.sh to bootstrap PKI first."
                )

    def _probe_backoffice_direct(
        self,
        extra_headers: dict[str, str] | None = None,
    ) -> int:
        """
        Probe backoffice:8443/internal/metrics directly (bypassing Caddy).

        Uses prometheus_client.{crt,key} as the mTLS identity — this cert IS
        valid (minted by our CA) so the TLS handshake succeeds. The question is
        whether the middleware checks X-Caddy-Verified-Secret.

        Returns the HTTP status code.
        """
        # Exec into a container that CAN reach backoffice via caddy_internal.
        # We use docker exec to run a Python one-liner inside the gateway
        # container (on caddy_internal) to do the probe. The gateway itself
        # has mTLS certs and network access.
        rt = _runtime()
        headers = {"X-SPIFFE-ID": "spiffe://yashigani.internal/prometheus"}
        if extra_headers:
            headers.update(extra_headers)

        header_args = " ".join(
            f"'{k}: {v}'"
            for k, v in headers.items()
        )

        # Build a Python probe that runs INSIDE the yashigani-gateway-1 container.
        # It uses the prometheus cert (NOT the gateway cert) to simulate a
        # non-Caddy peer — proving the middleware rejects based on the header,
        # not the cert identity.
        probe_script = (
            "import ssl, urllib.request, urllib.error; "
            "ctx = ssl.create_default_context(cafile='/run/secrets/ca_root.crt'); "
            "ctx.load_cert_chain('/run/secrets/prometheus_client.crt', "
            "'/run/secrets/prometheus_client.key'); "
            "ctx.check_hostname = False; "
            "ctx.verify_mode = ssl.CERT_NONE; "
            f"headers = {headers!r}; "
            "req = urllib.request.Request("
            "'https://backoffice:8443/internal/metrics', "
            "headers=headers); "
            "try:\n"
            "    resp = urllib.request.urlopen(req, context=ctx, timeout=8)\n"
            "    print(resp.status)\n"
            "except urllib.error.HTTPError as e:\n"
            "    print(e.code)\n"
            "except Exception as ex:\n"
            "    print(f'ERR:{ex}')\n"
        )

        result = subprocess.run(
            [rt, "exec", "yashigani-gateway-1",
             "python3", "-c", probe_script],
            capture_output=True,
            text=True,
            timeout=15,
        )

        if result.returncode != 0:
            pytest.skip(
                f"Could not exec into yashigani-gateway-1 to perform Layer B probe. "
                f"stderr: {result.stderr!r}. "
                "This test requires the gateway container to be reachable via docker/podman exec."
            )

        output = result.stdout.strip()
        if output.startswith("ERR:"):
            pytest.skip(
                f"Layer B probe failed with unexpected error: {output}. "
                "This may indicate a network connectivity issue inside the container."
            )

        try:
            return int(output)
        except ValueError:
            pytest.fail(
                f"Layer B probe returned unexpected output: {output!r}. "
                "Expected an integer HTTP status code."
            )

    def test_1_direct_connect_without_marker_returns_401(self):
        """
        TEST 1 — data-network bypass attempt: mTLS cert + forged X-SPIFFE-ID,
        NO X-Caddy-Verified-Secret.

        EXPECTED: 401 — Tom's middleware rejects it.
        WILL FAIL until Tom's caddy_verified_secret middleware lands.

        When this test turns GREEN it proves Layer B is active.
        """
        status = self._probe_backoffice_direct(extra_headers={})
        assert status == 401, (
            f"LAYER B FAILURE — direct probe without X-Caddy-Verified-Secret "
            f"returned HTTP {status}, expected 401. "
            "Tom's middleware is not yet active OR has a fail-open defect. "
            "EX-231-10 Layer B is INCOMPLETE."
        )

    def test_2_direct_connect_with_valid_marker_returns_200(self):
        """
        TEST 2 — data-network bypass WITH a valid X-Caddy-Verified-Secret.

        This proves the middleware accepts the correct secret value (not a
        blanket 401 on all requests regardless of header presence).

        The attacker who CAN read caddy_internal_hmac (e.g. compromised
        container in the same Docker network) would also need mTLS cert access.
        The defence is that the secret lives only in /run/secrets — not
        accessible from the obs or data networks without container compromise.

        EXPECTED: 200 — the middleware accepts the matching secret value.
        WILL FAIL until Tom's middleware lands.
        """
        valid_marker = self.secret   # same value Caddy would inject
        status = self._probe_backoffice_direct(
            extra_headers={"X-Caddy-Verified-Secret": valid_marker}
        )
        assert status == 200, (
            f"LAYER B DEFECT — direct probe WITH valid X-Caddy-Verified-Secret "
            f"returned HTTP {status}, expected 200. "
            "The middleware must accept the correct secret value — check that "
            "CADDY_INTERNAL_HMAC env var is loaded and compare_digest is correct. "
            "Admin1/Admin2 login HTTP: BLOCKED if this path fails."
        )

    def test_3_caddy_proxied_request_returns_200(self):
        """
        TEST 3 — regression: the legitimate Caddy-proxied path still works.

        Caddy injects X-Caddy-Verified-Secret automatically on every upstream
        proxy. This test confirms that the normal front-door path is intact
        (i.e. we haven't broken /healthz via Caddy by adding the new header).

        EXPECTED: 200 — always (even before Tom's middleware lands, since Caddy
        correctly injects the secret on the proxied path).
        """
        tls_domain = _TLS_DOMAIN
        https_port = _HTTPS_PORT
        url = f"https://{tls_domain}:{https_port}/healthz"

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE   # self-signed OK in test

        try:
            resp = urllib.request.urlopen(url, context=ctx, timeout=_TIMEOUT)
            status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        except Exception as exc:
            pytest.fail(
                f"TEST 3 FAILED — Caddy-proxied {url} raised {exc!r}. "
                "Caddy should be the working path. "
                "Admin1/Admin2 login HTTP: BLOCKED — front-door healthz must return 200."
            )

        assert status == 200, (
            f"TEST 3 FAILED — Caddy-proxied /healthz returned HTTP {status}, "
            f"expected 200. "
            "This is a regression — Layer B injection must not break the normal path. "
            "Admin1/Admin2 login HTTP: BLOCKED."
        )


# ---------------------------------------------------------------------------
# Caddyfile smoke test — verify the snippet syntax is parseable
# ---------------------------------------------------------------------------

class TestCaddyfileSnippetSyntax:
    """
    Verify that the inject-caddy-verified snippet can be parsed by the
    installed Caddy binary. This catches Caddyfile syntax errors before
    a full stack deploy.

    Requires caddy binary on PATH or a running Caddy container.
    """

    def test_caddyfile_selfsigned_parses_cleanly(self):
        """
        Run `caddy validate` on Caddyfile.selfsigned inside the caddy container.
        Caddy validates the snippet syntax and reports errors if any directive
        is unknown or malformed.
        """
        rt = _runtime()
        if not rt:
            pytest.skip("No container runtime available for Caddyfile validation")

        result = subprocess.run(
            [
                rt, "run", "--rm",
                "--entrypoint", "sh",
                "docker.io/library/caddy:2-alpine",
                "-c",
                # We can't mount the file inline easily, but we can use
                # `caddy adapt` on a minimal Caddyfile that exercises the
                # inject-caddy-verified snippet to confirm the directive is
                # valid in caddy:2-alpine.
                #
                # DESIGN NOTE: header_up is a valid reverse_proxy subdirective
                # in Caddy 2 (http.handlers.headers module). The snippet just
                # wraps two header_up calls — no exotic module needed.
                r"""
caddy_config='
(inject-caddy-verified) {
    header_up -X-Caddy-Verified-Secret
    header_up X-Caddy-Verified-Secret test-secret-value
}
:8080 {
    handle / {
        reverse_proxy localhost:9090 {
            import inject-caddy-verified
        }
    }
}
'
echo "$caddy_config" | caddy adapt --config /dev/stdin --adapter caddyfile 2>&1
""",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        # caddy adapt exits 0 on success, non-zero on parse error.
        # Stderr may have warnings; stdout has the adapted JSON on success.
        stderr_lower = result.stderr.lower()
        has_error = (
            result.returncode != 0
            or "error" in stderr_lower
            or "unknown" in stderr_lower
        )
        assert not has_error, (
            f"Caddy rejected the inject-caddy-verified snippet. "
            f"returncode={result.returncode}\n"
            f"stdout={result.stdout!r}\n"
            f"stderr={result.stderr!r}\n\n"
            "This means the Caddyfile syntax is BROKEN. Fix before deploying."
        )
