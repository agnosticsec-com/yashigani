"""
Yashigani KSM — Docker Secrets provider.
Reads secrets from /run/secrets/<key> (Docker/Podman native secrets).
Intended for local / dev / demo deployments only.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from yashigani.kms.base import (
    KSMProvider,
    KeyNotFoundError,
    ProviderError,
    SecretMetadata,
)

_SECRETS_DIR = Path("/run/secrets")


class DockerSecretsProvider(KSMProvider):
    """
    Reads secrets from the Docker/Podman secrets filesystem mount.
    Rotation and token revocation are not supported — raise ProviderError.
    """

    def __init__(self, environment_scope: str, secrets_dir: Path = _SECRETS_DIR) -> None:
        self._environment_scope = environment_scope
        self._secrets_dir = secrets_dir

    # -- KSMProvider ---------------------------------------------------------

    def get_secret(self, key: str) -> str:
        self._check_scope(key)
        safe_key = self._safe_filename(key)
        secret_path = self._secrets_dir / safe_key
        if not secret_path.exists():
            raise KeyNotFoundError(f"Secret '{key}' not found in Docker Secrets")
        try:
            return secret_path.read_text(encoding="utf-8").rstrip("\n")
        except OSError as exc:
            raise ProviderError(f"Failed to read secret '{key}': {exc}") from exc

    def set_secret(self, key: str, value: str) -> None:
        self._check_scope(key)
        raise ProviderError(
            "Docker Secrets does not support programmatic secret creation. "
            "Mount secrets at container start via Docker/Podman configuration."
        )

    def rotate_secret(self, key: str, new_value: str) -> str:
        raise ProviderError(
            "Docker Secrets does not support rotation. "
            "Update the secret via Docker/Podman and restart the container."
        )

    def revoke_token(self, key: str) -> None:
        raise ProviderError(
            "Docker Secrets does not support token revocation."
        )

    def list_secrets(self, prefix: Optional[str] = None) -> list[SecretMetadata]:
        if not self._secrets_dir.exists():
            raise ProviderError(f"Secrets directory '{self._secrets_dir}' does not exist")
        try:
            entries = []
            for path in self._secrets_dir.iterdir():
                if path.is_file():
                    name = path.name
                    if prefix and not name.startswith(prefix):
                        continue
                    stat = path.stat()
                    entries.append(SecretMetadata(
                        key=name,
                        version="docker-static",
                        created_at=_format_ts(stat.st_ctime),
                        last_rotated_at=None,
                        expires_at=None,
                    ))
            return entries
        except OSError as exc:
            raise ProviderError(f"Failed to list secrets: {exc}") from exc

    def delete_secret(self, key: str) -> None:
        raise ProviderError(
            "Docker Secrets does not support programmatic deletion. "
            "Remove the secret via Docker/Podman configuration."
        )

    def health_check(self) -> bool:
        try:
            return self._secrets_dir.exists() and os.access(self._secrets_dir, os.R_OK)
        except Exception:
            return False

    @property
    def provider_name(self) -> str:
        return "docker"

    @property
    def environment_scope(self) -> str:
        return self._environment_scope

    # -- Helpers -------------------------------------------------------------

    @staticmethod
    def _safe_filename(key: str) -> str:
        """Strip scope prefix for filesystem lookup and sanitise path traversal."""
        name = key.split("/", 1)[-1] if "/" in key else key
        # Reject any path traversal attempt
        if ".." in name or "/" in name or "\\" in name:
            raise ProviderError(f"Invalid secret key: '{key}'")
        return name


def _format_ts(unix_ts: float) -> str:
    import datetime
    return datetime.datetime.fromtimestamp(
        unix_ts, tz=datetime.timezone.utc
    ).isoformat()
