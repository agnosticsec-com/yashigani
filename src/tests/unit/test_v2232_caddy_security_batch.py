"""Tests for v2.23.2 Caddy/security/Python batch.

Covers:
  V232-P19 — HSTS preload header in all production Caddyfiles
  V232-P20 — tls_trust_pool (not deprecated tls_trusted_ca_certs) in all Caddyfiles
  V232-P29 — build_redis_url helper contract
  V232-P26 — K8s service SANs present in both service_identities.yaml copies
  V232-N12 — suspend_owned_by() uses org_id index, not full scan

# Last updated: 2026-05-03T00:00:00+01:00
"""
from __future__ import annotations

import os
import pathlib
import re
import textwrap
from unittest.mock import MagicMock, patch

import fakeredis
import pytest
import yaml

# ── Paths ────────────────────────────────────────────────────────────────────

REPO_ROOT = pathlib.Path(__file__).parents[3]
DOCKER_DIR = REPO_ROOT / "docker"
HELM_FILES_DIR = REPO_ROOT / "helm" / "yashigani" / "files"

CADDYFILE_CA = DOCKER_DIR / "Caddyfile.ca"
CADDYFILE_ACME = DOCKER_DIR / "Caddyfile.acme"
CADDYFILE_SELFSIGNED = DOCKER_DIR / "Caddyfile.selfsigned"
CADDYFILE_WAF = DOCKER_DIR / "caddy" / "Caddyfile.waf"

SVC_IDENTITIES_DOCKER = DOCKER_DIR / "service_identities.yaml"
SVC_IDENTITIES_HELM = HELM_FILES_DIR / "service_identities.yaml"

# K8s Service names emitted by Helm templates (confirmed from template audit).
# These names are used for intra-cluster DNS and MUST appear in each service's
# dns_sans list so that cert SANs match the hostname clients connect to.
K8S_SERVICE_NAMES = {
    "caddy": "yashigani-caddy",
    "gateway": "yashigani-gateway",
    "backoffice": "yashigani-backoffice",
    "policy": "yashigani-policy",
    "postgres": "yashigani-postgres",
    "pgbouncer": "yashigani-pgbouncer",
    "redis": "yashigani-redis",
    "budget-redis": "yashigani-budget-redis",
    "prometheus": "yashigani-prometheus",
    "grafana": "yashigani-grafana",
    "alertmanager": "yashigani-alertmanager",
    "loki": "yashigani-loki",
    # otel-collector K8s service is named "otel-collector" (verified template).
    "otel-collector": "otel-collector",
    "jaeger": "yashigani-jaeger",
    "ollama": "yashigani-ollama",
    # open-webui K8s service is named "open-webui" (verified template).
    "open-webui": "open-webui",
}


# ── V232-P19: HSTS preload ────────────────────────────────────────────────────

class TestHSTSPreload:
    """HSTS must include preload in production Caddyfiles."""

    PRELOAD_RE = re.compile(
        r'Strict-Transport-Security.*max-age=\d+.*includeSubDomains.*preload',
        re.IGNORECASE,
    )

    def _assert_preload(self, path: pathlib.Path) -> None:
        text = path.read_text()
        assert self.PRELOAD_RE.search(text), (
            f"{path.name} is missing HSTS preload directive. "
            "Expected: Strict-Transport-Security: max-age=...; includeSubDomains; preload"
        )

    def test_caddyfile_ca_has_hsts_preload(self):
        self._assert_preload(CADDYFILE_CA)

    def test_caddyfile_acme_has_hsts_preload(self):
        self._assert_preload(CADDYFILE_ACME)

    def test_caddyfile_waf_has_hsts_preload(self):
        self._assert_preload(CADDYFILE_WAF)

    def test_hsts_max_age_two_years(self):
        """Verify the 2-year (63072000 s) max-age in CA and ACME files."""
        for path in (CADDYFILE_CA, CADDYFILE_ACME):
            text = path.read_text()
            assert "63072000" in text, (
                f"{path.name}: HSTS max-age should be 63072000 (2 years), not 31536000 (1 year)"
            )

    def test_selfsigned_no_hsts_required(self):
        """Self-signed mode is for local/demo use — HSTS is optional.
        This test documents the deliberate omission; it does not assert
        presence. If HSTS is ever added to selfsigned, that's fine too."""
        text = CADDYFILE_SELFSIGNED.read_text()
        # No assertion — documenting intent only.
        _ = text  # consumed so linters don't flag unused var


# ── V232-P20: tls_trust_pool migration ───────────────────────────────────────

class TestTlsTrustPool:
    """transport http blocks must use tls_trust_pool, not tls_trusted_ca_certs."""

    def _check_file(self, path: pathlib.Path) -> None:
        text = path.read_text()
        # No deprecated directive.
        assert "tls_trusted_ca_certs" not in text, (
            f"{path.name} still contains deprecated tls_trusted_ca_certs. "
            "Migrate to: tls_trust_pool file /run/secrets/ca_intermediate.crt"
        )
        # The replacement must be present.
        assert "tls_trust_pool" in text, (
            f"{path.name} is missing tls_trust_pool directive in (internal-mtls) snippet."
        )

    def test_caddyfile_ca_uses_trust_pool(self):
        self._check_file(CADDYFILE_CA)

    def test_caddyfile_acme_uses_trust_pool(self):
        self._check_file(CADDYFILE_ACME)

    def test_caddyfile_selfsigned_uses_trust_pool(self):
        self._check_file(CADDYFILE_SELFSIGNED)

    def test_no_tls_trusted_ca_certs_anywhere(self):
        """Exhaustive search: no Caddyfile in the repo uses the deprecated directive."""
        for cf in DOCKER_DIR.rglob("Caddyfile*"):
            text = cf.read_text()
            assert "tls_trusted_ca_certs" not in text, (
                f"{cf} still uses deprecated tls_trusted_ca_certs"
            )


# ── V232-P29: build_redis_url helper ─────────────────────────────────────────

class TestBuildRedisUrl:
    """Verify build_redis_url contract: DB ordering, scheme, cert paths."""

    @pytest.fixture(autouse=True)
    def _clean_env(self, monkeypatch):
        # Clear Redis env vars so tests are hermetic.
        for var in ("REDIS_HOST", "REDIS_PORT", "REDIS_USE_TLS",
                    "REDIS_PASSWORD", "YASHIGANI_SECRETS_DIR"):
            monkeypatch.delenv(var, raising=False)

    def _get_helper(self):
        from yashigani.gateway._redis_url import build_redis_url
        return build_redis_url

    def test_plaintext_url_structure(self):
        fn = self._get_helper()
        url = fn(3, host="myredis", port="6379", password="secret", use_tls=False)
        assert url == "redis://:secret@myredis:6379/3"

    def test_plaintext_db_index_in_path(self):
        fn = self._get_helper()
        for db in (0, 1, 2, 3, 4, 15):
            url = fn(db, host="h", port="6379", password="p", use_tls=False)
            # DB must be the last path component, not a query param.
            assert f"/{db}" in url
            assert "?" not in url

    def test_tls_url_scheme(self):
        fn = self._get_helper()
        url = fn(2, host="h", port="6380", password="p", use_tls=True,
                 secrets_dir="/sec")
        assert url.startswith("rediss://")

    def test_tls_db_before_query(self):
        """DB index MUST appear before the query string in TLS URLs.

        redis-py parses the URL path for the DB; a query-string-first URL
        silently connects to DB 0 regardless of intent.  This was the root
        cause of the v2.23.1 gateway-DSN-DIRECT bug (gate #58b evidence).
        """
        fn = self._get_helper()
        url = fn(4, host="h", port="6380", password="p", use_tls=True,
                 secrets_dir="/sec")
        # DB path segment must precede '?'
        q_pos = url.index("?")
        db_pos = url.index("/4")
        assert db_pos < q_pos, f"DB index '/4' appears after '?' in: {url}"

    def test_tls_cert_paths_present(self):
        fn = self._get_helper()
        url = fn(1, host="h", port="6380", password="p", use_tls=True,
                 secrets_dir="/mysec", client_cert_name="gateway_client")
        assert "ssl_ca_certs=/mysec/ca_root.crt" in url
        assert "ssl_certfile=/mysec/gateway_client.crt" in url
        assert "ssl_keyfile=/mysec/gateway_client.key" in url

    def test_client_cert_name_parameterised(self):
        fn = self._get_helper()
        url = fn(1, host="h", port="6380", password="p", use_tls=True,
                 secrets_dir="/s", client_cert_name="backoffice_client")
        assert "backoffice_client.crt" in url
        assert "backoffice_client.key" in url

    def test_password_url_encoded(self):
        """Special chars in password must be percent-encoded."""
        fn = self._get_helper()
        url = fn(0, host="h", port="6379", password="p@ss!w0rd", use_tls=False)
        # '@' → %40, '!' → %21
        assert "@h:" in url  # only one @ (the host delimiter)
        assert "p@ss" not in url  # raw @ in password would corrupt the URL

    def test_reads_password_from_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(tmp_path))
        (tmp_path / "redis_password").write_text("filepassword")
        fn = self._get_helper()
        url = fn(0, use_tls=False)
        assert "filepassword" in url

    def test_falls_back_to_env_password(self, tmp_path, monkeypatch):
        monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(tmp_path))
        monkeypatch.setenv("REDIS_PASSWORD", "envpassword")
        # No redis_password file.
        fn = self._get_helper()
        url = fn(0, use_tls=False)
        assert "envpassword" in url

    def test_default_host_from_env(self, monkeypatch):
        monkeypatch.setenv("REDIS_HOST", "custom-redis")
        fn = self._get_helper()
        url = fn(0, password="p", use_tls=False)
        assert "custom-redis" in url

    def test_budget_redis_separate_host(self):
        """Budget Redis uses a different host than main Redis."""
        fn = self._get_helper()
        url = fn(0, host="budget-redis", port="6380", password="p", use_tls=False)
        assert "budget-redis" in url


# ── V232-P26: K8s service SANs ───────────────────────────────────────────────

class TestK8sServiceSANs:
    """Both service_identities.yaml copies must include K8s service names in dns_sans."""

    @pytest.fixture(scope="class")
    def docker_manifest(self):
        return yaml.safe_load(SVC_IDENTITIES_DOCKER.read_text())

    @pytest.fixture(scope="class")
    def helm_manifest(self):
        return yaml.safe_load(SVC_IDENTITIES_HELM.read_text())

    def _service_sans(self, manifest: dict) -> dict[str, list[str]]:
        return {
            svc["name"]: list(svc.get("dns_sans", []))
            for svc in manifest.get("services", [])
        }

    def test_docker_and_helm_manifests_identical(self):
        """Both files must be byte-identical (single-source-of-truth requirement)."""
        assert SVC_IDENTITIES_DOCKER.read_bytes() == SVC_IDENTITIES_HELM.read_bytes(), (
            "docker/service_identities.yaml and helm/yashigani/files/service_identities.yaml "
            "have diverged. They must be kept byte-identical. "
            "Update both files together (retro #3be)."
        )

    @pytest.mark.parametrize("service_name,k8s_name", K8S_SERVICE_NAMES.items())
    def test_k8s_service_name_in_docker_sans(
        self, docker_manifest, service_name, k8s_name
    ):
        sans_map = self._service_sans(docker_manifest)
        if service_name not in sans_map:
            pytest.skip(f"Service '{service_name}' not in manifest — optional service")
        assert k8s_name in sans_map[service_name], (
            f"K8s service name '{k8s_name}' not in docker/service_identities.yaml "
            f"dns_sans for '{service_name}'. TLS verification will fail in K8s."
        )

    @pytest.mark.parametrize("service_name,k8s_name", K8S_SERVICE_NAMES.items())
    def test_k8s_service_name_in_helm_sans(
        self, helm_manifest, service_name, k8s_name
    ):
        sans_map = self._service_sans(helm_manifest)
        if service_name not in sans_map:
            pytest.skip(f"Service '{service_name}' not in manifest — optional service")
        assert k8s_name in sans_map[service_name], (
            f"K8s service name '{k8s_name}' not in helm/yashigani/files/service_identities.yaml "
            f"dns_sans for '{service_name}'. TLS verification will fail in K8s."
        )


# ── V232-N12: suspend_owned_by() index ───────────────────────────────────────

class TestSuspendOwnedBy:
    """IdentityRegistry.suspend_owned_by() must use the org_id index, not full scan."""

    @pytest.fixture
    def r(self):
        return fakeredis.FakeRedis()

    @pytest.fixture
    def registry(self, r):
        from yashigani.identity.registry import IdentityRegistry
        return IdentityRegistry(r)

    def _register(self, registry, slug: str, org_id: str = ""):
        from yashigani.identity.registry import IdentityKind
        iid, _ = registry.register(
            kind=IdentityKind.SERVICE,
            name=f"Test {slug}",
            slug=slug,
            org_id=org_id,
        )
        return iid

    def test_suspend_owned_by_suspends_matching(self, registry):
        """Identities registered with org_id are suspended by suspend_owned_by."""
        iid = self._register(registry, "agent-a", org_id="user-123")
        count = registry.suspend_owned_by("user-123")
        assert count == 1
        identity = registry.get(iid)
        assert identity["status"] == "suspended"

    def test_suspend_owned_by_does_not_touch_others(self, registry):
        """Only identities matching org_id are suspended."""
        iid_match = self._register(registry, "agent-b", org_id="user-abc")
        iid_other = self._register(registry, "agent-c", org_id="user-xyz")
        registry.suspend_owned_by("user-abc")
        assert registry.get(iid_other)["status"] == "active"

    def test_suspend_owned_by_multiple(self, registry):
        """All identities for the same org_id are suspended atomically."""
        ids = [self._register(registry, f"agent-{i}", org_id="org-1") for i in range(5)]
        count = registry.suspend_owned_by("org-1")
        assert count == 5
        for iid in ids:
            assert registry.get(iid)["status"] == "suspended"

    def test_suspend_owned_by_empty_org_id(self, registry):
        """Empty org_id is a no-op — no crash, zero suspensions."""
        self._register(registry, "agent-d", org_id="")
        count = registry.suspend_owned_by("")
        assert count == 0

    def test_suspend_owned_by_unknown_org_id(self, registry):
        """Non-existent org_id returns 0 without error."""
        count = registry.suspend_owned_by("no-such-org")
        assert count == 0

    def test_org_id_index_populated_on_register(self, r, registry):
        """The identity:index:org:{org_id} Redis set must be populated at register time."""
        iid = self._register(registry, "agent-e", org_id="org-check")
        members = {
            m.decode() if isinstance(m, bytes) else m
            for m in r.smembers("identity:index:org:org-check")
        }
        assert iid in members, (
            "identity:index:org:org-check Redis set was not populated on register. "
            "SEC-240-7 org_id index is missing."
        )

    def test_org_id_index_cleaned_on_deactivate(self, r, registry):
        """Deactivating an identity must remove it from the org index."""
        iid = self._register(registry, "agent-f", org_id="org-deact")
        registry.deactivate(iid)
        members = {
            m.decode() if isinstance(m, bytes) else m
            for m in r.smembers("identity:index:org:org-deact")
        }
        assert iid not in members, (
            "identity:index:org:org-deact still contains deactivated identity. "
            "Org index cleanup on deactivate is missing."
        )

    def test_suspend_owned_by_skips_already_suspended(self, registry):
        """Already-suspended identities are not double-counted."""
        iid = self._register(registry, "agent-g", org_id="org-dup")
        registry.suspend(iid)  # pre-suspend
        count = registry.suspend_owned_by("org-dup")
        assert count == 0  # already suspended, not re-counted
        assert registry.get(iid)["status"] == "suspended"

    def test_does_not_call_list_all(self, registry):
        """suspend_owned_by must NOT call list_all() — that is the full-scan pattern."""
        with patch.object(registry, "list_all") as mock_list_all:
            registry.suspend_owned_by("any-org")
        mock_list_all.assert_not_called()
