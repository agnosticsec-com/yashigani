"""
Unit tests for the Yashigani KSM module.
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest

from yashigani.kms.base import (
    KSMProvider,
    KeyNotFoundError,
    ProviderError,
    RotationError,
    ScopeViolationError,
    SecretMetadata,
)
from yashigani.kms.providers.docker_secrets import DockerSecretsProvider
from yashigani.kms.factory import create_provider
from yashigani.kms.rotation import KSMRotationScheduler, _validate_cron


# ---------------------------------------------------------------------------
# DockerSecretsProvider
# ---------------------------------------------------------------------------

class TestDockerSecretsProvider:
    def _make_provider(self, tmp_path: Path) -> DockerSecretsProvider:
        return DockerSecretsProvider(
            environment_scope="dev",
            secrets_dir=tmp_path,
        )

    def test_get_secret_success(self, tmp_path):
        (tmp_path / "mykey").write_text("s3cr3t\n", encoding="utf-8")
        provider = self._make_provider(tmp_path)
        assert provider.get_secret("mykey") == "s3cr3t"

    def test_get_secret_strips_scope_prefix(self, tmp_path):
        (tmp_path / "mykey").write_text("value", encoding="utf-8")
        provider = self._make_provider(tmp_path)
        assert provider.get_secret("dev/mykey") == "value"

    def test_get_secret_not_found(self, tmp_path):
        provider = self._make_provider(tmp_path)
        with pytest.raises(KeyNotFoundError):
            provider.get_secret("missing")

    def test_scope_violation(self, tmp_path):
        provider = self._make_provider(tmp_path)
        with pytest.raises(ScopeViolationError):
            provider.get_secret("production/secret")

    def test_set_secret_raises(self, tmp_path):
        provider = self._make_provider(tmp_path)
        with pytest.raises(ProviderError):
            provider.set_secret("k", "v")

    def test_rotate_raises(self, tmp_path):
        provider = self._make_provider(tmp_path)
        with pytest.raises(ProviderError):
            provider.rotate_secret("k", "v")

    def test_revoke_raises(self, tmp_path):
        provider = self._make_provider(tmp_path)
        with pytest.raises(ProviderError):
            provider.revoke_token("k")

    def test_health_check_exists(self, tmp_path):
        provider = self._make_provider(tmp_path)
        assert provider.health_check() is True

    def test_health_check_missing(self, tmp_path):
        provider = DockerSecretsProvider(
            environment_scope="dev",
            secrets_dir=tmp_path / "nonexistent",
        )
        assert provider.health_check() is False

    def test_list_secrets(self, tmp_path):
        (tmp_path / "alpha").write_text("a", encoding="utf-8")
        (tmp_path / "beta").write_text("b", encoding="utf-8")
        provider = self._make_provider(tmp_path)
        names = {m.key for m in provider.list_secrets()}
        assert names == {"alpha", "beta"}

    def test_list_secrets_with_prefix(self, tmp_path):
        (tmp_path / "alpha").write_text("a", encoding="utf-8")
        (tmp_path / "beta").write_text("b", encoding="utf-8")
        provider = self._make_provider(tmp_path)
        names = {m.key for m in provider.list_secrets(prefix="al")}
        assert names == {"alpha"}

    def test_path_traversal_rejected(self, tmp_path):
        provider = self._make_provider(tmp_path)
        with pytest.raises(ProviderError):
            provider.get_secret("../etc/passwd")

    def test_provider_name(self, tmp_path):
        provider = self._make_provider(tmp_path)
        assert provider.provider_name == "docker"

    def test_environment_scope(self, tmp_path):
        provider = self._make_provider(tmp_path)
        assert provider.environment_scope == "dev"


# ---------------------------------------------------------------------------
# KSMProviderFactory
# ---------------------------------------------------------------------------

class TestKSMProviderFactory:
    def test_selects_docker_for_dev_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.setenv("YASHIGANI_KSM_PROVIDER", "docker")
        # Patch DockerSecretsProvider to avoid needing real /run/secrets
        with patch(
            "yashigani.kms.providers.docker_secrets.DockerSecretsProvider.__init__",
            return_value=None,
        ), patch.object(
            DockerSecretsProvider, "provider_name",
            new_callable=lambda: property(lambda self: "docker"),
        ), patch.object(
            DockerSecretsProvider, "environment_scope",
            new_callable=lambda: property(lambda self: "dev"),
        ):
            provider = create_provider()
            assert provider.provider_name == "docker"

    def test_missing_env_raises(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_ENV", raising=False)
        with pytest.raises(ProviderError, match="YASHIGANI_ENV"):
            create_provider()

    def test_unknown_provider_raises(self, monkeypatch):
        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.setenv("YASHIGANI_KSM_PROVIDER", "nonexistent")
        with pytest.raises(ProviderError, match="Unknown KSM provider"):
            create_provider()


# ---------------------------------------------------------------------------
# ScopeViolationError enforcement
# ---------------------------------------------------------------------------

class TestScopeViolation:
    def test_mismatched_prefix_raises(self, tmp_path):
        provider = DockerSecretsProvider(environment_scope="dev", secrets_dir=tmp_path)
        with pytest.raises(ScopeViolationError):
            provider._check_scope("production/secret")

    def test_matching_prefix_passes(self, tmp_path):
        provider = DockerSecretsProvider(environment_scope="dev", secrets_dir=tmp_path)
        provider._check_scope("dev/secret")  # should not raise

    def test_no_prefix_passes(self, tmp_path):
        provider = DockerSecretsProvider(environment_scope="dev", secrets_dir=tmp_path)
        provider._check_scope("plainsecret")  # should not raise


# ---------------------------------------------------------------------------
# KSMRotationScheduler
# ---------------------------------------------------------------------------

class _MockProvider(KSMProvider):
    def __init__(self, scope: str = "dev"):
        self._scope = scope
        self.rotate_calls: list[tuple[str, str]] = []
        self.get_calls: list[str] = []
        self._stored: dict[str, str] = {}
        self.fail_rotate = False

    def get_secret(self, key: str) -> str:
        self.get_calls.append(key)
        if key not in self._stored:
            raise KeyNotFoundError(key)
        return self._stored[key]

    def set_secret(self, key: str, value: str) -> None:
        self._stored[key] = value

    def rotate_secret(self, key: str, new_value: str) -> str:
        if self.fail_rotate:
            raise RotationError("Simulated failure")
        self.rotate_calls.append((key, new_value))
        self._stored[key] = new_value
        return "v2"

    def revoke_token(self, key: str) -> None:
        pass

    def list_secrets(self, prefix=None):
        return []

    def delete_secret(self, key: str) -> None:
        pass

    def health_check(self) -> bool:
        return True

    @property
    def provider_name(self) -> str:
        return "mock"

    @property
    def environment_scope(self) -> str:
        return self._scope


class TestKSMRotationScheduler:
    def test_validate_cron_rejects_too_frequent(self):
        with pytest.raises(ValueError, match="frequently"):
            _validate_cron("* * * * *")  # every minute

    def test_validate_cron_accepts_hourly(self):
        _validate_cron("0 * * * *")  # every hour — should pass

    def test_trigger_now_rotates(self):
        provider = _MockProvider()
        provider._stored["dev/key"] = "old"
        events: list[tuple] = []
        scheduler = KSMRotationScheduler(
            provider=provider,
            secret_key="dev/key",
            cron_expr="0 2 * * *",
            on_event=lambda name, data: events.append((name, data)),
        )
        scheduler.trigger_now()
        assert len(provider.rotate_calls) == 1
        assert any(e[0] == "KSM_ROTATION_SUCCESS" for e in events)

    def test_rotation_lock_prevents_concurrent(self):
        provider = _MockProvider()
        provider._stored["dev/key"] = "old"
        scheduler = KSMRotationScheduler(
            provider=provider,
            secret_key="dev/key",
            cron_expr="0 2 * * *",
        )
        # Acquire lock manually to simulate in-progress rotation
        scheduler._lock.acquire()
        scheduler._rotate(rotation_type="manual")
        scheduler._lock.release()
        # Lock was held, so rotation should have been skipped
        assert len(provider.rotate_calls) == 0

    def test_retry_on_failure_emits_critical(self):
        provider = _MockProvider()
        provider._stored["dev/key"] = "old"
        provider.fail_rotate = True
        events: list[tuple] = []

        # Patch retry delays to zero for speed
        import yashigani.kms.rotation as rot_module
        original_delays = rot_module._RETRY_DELAYS_SECONDS
        rot_module._RETRY_DELAYS_SECONDS = [0, 0, 0]
        try:
            scheduler = KSMRotationScheduler(
                provider=provider,
                secret_key="dev/key",
                cron_expr="0 2 * * *",
                on_event=lambda name, data: events.append((name, data)),
            )
            scheduler._rotate_with_retry()
        finally:
            rot_module._RETRY_DELAYS_SECONDS = original_delays

        assert any(e[0] == "KSM_ROTATION_CRITICAL" for e in events)

    def test_set_schedule_rejects_invalid(self):
        provider = _MockProvider()
        provider._stored["dev/key"] = "old"
        scheduler = KSMRotationScheduler(
            provider=provider,
            secret_key="dev/key",
            cron_expr="0 2 * * *",
        )
        with pytest.raises(ValueError):
            scheduler.set_schedule("not-a-cron")

    def test_set_schedule_rejects_too_frequent(self):
        provider = _MockProvider()
        provider._stored["dev/key"] = "old"
        scheduler = KSMRotationScheduler(
            provider=provider,
            secret_key="dev/key",
            cron_expr="0 2 * * *",
        )
        with pytest.raises(ValueError, match="frequently"):
            scheduler.set_schedule("*/30 * * * *")  # every 30 min
