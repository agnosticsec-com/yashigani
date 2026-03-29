"""
HashiCorp Vault KMS provider — Phase 11.

Auth: AppRole (role_id + secret_id from Docker secrets files).
Engine: KV v2 only.
Dev-mode: VAULT_TOKEN env var for local development only.

Secret path: kv/data/yashigani/{key_name}, field "value".
"""
from __future__ import annotations

import logging
import os
from typing import Optional

from yashigani.kms.base import KMSProvider

logger = logging.getLogger(__name__)

_VAULT_ADDR_DEFAULT = "http://vault:8200"
_KV_MOUNT = "kv"
_SECRET_PREFIX = "yashigani"


class VaultKMSProvider(KMSProvider):
    provider_name = "vault"

    def __init__(self) -> None:
        self._client = None
        self._vault_addr = os.getenv("VAULT_ADDR", _VAULT_ADDR_DEFAULT)
        self._namespace = os.getenv("VAULT_NAMESPACE")
        self._token = os.getenv("VAULT_TOKEN")
        self._role_id_file = os.getenv("VAULT_ROLE_ID_FILE", "/run/secrets/vault_role_id")
        self._secret_id_file = os.getenv("VAULT_SECRET_ID_FILE", "/run/secrets/vault_secret_id")
        self._authenticate()

    def _authenticate(self) -> None:
        try:
            import hvac
        except ImportError:
            raise RuntimeError("hvac is required for Vault KMS. Install with: pip install yashigani[vault]")

        client = hvac.Client(url=self._vault_addr, namespace=self._namespace)
        if self._token:
            logger.warning("Vault: direct token auth (dev mode — NOT for production)")
            client.token = self._token
        else:
            role_id = _read_file(self._role_id_file)
            secret_id = _read_file(self._secret_id_file)
            result = client.auth.approle.login(role_id=role_id, secret_id=secret_id)
            client.token = result["auth"]["client_token"]
            logger.info("Vault: AppRole authentication successful")

        if not client.is_authenticated():
            raise RuntimeError("Vault authentication failed")

        self._client = client
        logger.info("Vault KMS provider initialised: addr=%s", self._vault_addr)

    def get_secret(self, key_name: str) -> Optional[str]:
        self._ensure_authenticated()
        try:
            resp = self._client.secrets.kv.v2.read_secret_version(
                path=f"{_SECRET_PREFIX}/{key_name}", mount_point=_KV_MOUNT
            )
            return resp["data"]["data"].get("value")
        except Exception as exc:
            logger.warning("Vault get_secret failed for %s: %s", key_name, exc)
            return None

    def set_secret(self, key_name: str, value: str) -> None:
        self._ensure_authenticated()
        self._client.secrets.kv.v2.create_or_update_secret(
            path=f"{_SECRET_PREFIX}/{key_name}",
            secret={"value": value},
            mount_point=_KV_MOUNT,
        )
        logger.info("Vault secret written: %s/%s", _SECRET_PREFIX, key_name)

    def delete_secret(self, key_name: str) -> None:
        self._ensure_authenticated()
        self._client.secrets.kv.v2.delete_metadata_and_all_versions(
            path=f"{_SECRET_PREFIX}/{key_name}", mount_point=_KV_MOUNT
        )

    def list_secrets(self) -> list[str]:
        self._ensure_authenticated()
        try:
            resp = self._client.secrets.kv.v2.list_secrets(
                path=_SECRET_PREFIX, mount_point=_KV_MOUNT
            )
            return resp["data"]["keys"]
        except Exception as exc:
            logger.warning("Vault list_secrets failed: %s", exc)
            return []

    def rotate_secret(self, key_name: str, new_value: str) -> None:
        self.set_secret(key_name, new_value)

    def _ensure_authenticated(self) -> None:
        if self._client is None or not self._client.is_authenticated():
            logger.info("Vault token expired — re-authenticating")
            self._authenticate()

    def health(self) -> dict:
        try:
            status = self._client.sys.read_health_status(method="GET")
            return {
                "initialized": status.get("initialized", False),
                "sealed": status.get("sealed", True),
                "standby": status.get("standby", False),
                "version": status.get("version", "unknown"),
                "vault_addr": self._vault_addr,
            }
        except Exception as exc:
            return {"error": str(exc), "vault_addr": self._vault_addr}


def _read_file(path: str) -> str:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError as exc:
        raise RuntimeError(f"Cannot read Vault secret file {path}: {exc}")
