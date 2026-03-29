"""
Yashigani KSM — Google Cloud Secret Manager provider.
Uses google-cloud-secret-manager. Supports workload identity.
"""
from __future__ import annotations

import os
from typing import Optional

from yashigani.kms.base import (
    KSMProvider,
    KeyNotFoundError,
    ProviderError,
    RotationError,
    SecretMetadata,
)


def _import_gcp():
    try:
        from google.cloud import secretmanager
        from google.api_core.exceptions import NotFound, GoogleAPICallError
        return secretmanager, NotFound, GoogleAPICallError
    except ImportError as exc:
        raise ImportError(
            "google-cloud-secret-manager is required for GCPSecretManagerProvider. "
            "Install with: pip install google-cloud-secret-manager"
        ) from exc


class GCPSecretManagerProvider(KSMProvider):

    def __init__(self, environment_scope: str) -> None:
        self._environment_scope = environment_scope
        self._project_id = os.environ["KSM_GCP_PROJECT_ID"]
        credentials_file = os.environ.get("KSM_GCP_CREDENTIALS_FILE")
        if credentials_file:
            os.environ.setdefault("GOOGLE_APPLICATION_CREDENTIALS", credentials_file)
        self._client = self._build_client()

    def _build_client(self):
        secretmanager, _, _ = _import_gcp()
        return secretmanager.SecretManagerServiceClient()

    def _secret_path(self, key: str) -> str:
        name = key.split("/", 1)[-1] if "/" in key else key
        return f"projects/{self._project_id}/secrets/{name}/versions/latest"

    def _secret_parent(self, key: str) -> str:
        name = key.split("/", 1)[-1] if "/" in key else key
        return f"projects/{self._project_id}/secrets/{name}"

    def get_secret(self, key: str) -> str:
        self._check_scope(key)
        _, NotFound, GoogleAPICallError = _import_gcp()
        try:
            response = self._client.access_secret_version(name=self._secret_path(key))
            return response.payload.data.decode("utf-8")
        except NotFound as exc:
            raise KeyNotFoundError(f"Secret '{key}' not found in GCP Secret Manager") from exc
        except GoogleAPICallError as exc:
            raise ProviderError(f"GCP error retrieving '{key}': {exc}") from exc

    def set_secret(self, key: str, value: str) -> None:
        self._check_scope(key)
        _, NotFound, GoogleAPICallError = _import_gcp()
        parent = self._secret_parent(key)
        payload = {"data": value.encode("utf-8")}
        try:
            try:
                self._client.add_secret_version(parent=parent, payload=payload)
            except NotFound:
                self._client.create_secret(
                    parent=f"projects/{self._project_id}",
                    secret_id=key.split("/", 1)[-1] if "/" in key else key,
                    secret={"replication": {"automatic": {}}},
                )
                self._client.add_secret_version(parent=parent, payload=payload)
        except GoogleAPICallError as exc:
            raise ProviderError(f"GCP error setting '{key}': {exc}") from exc

    def rotate_secret(self, key: str, new_value: str) -> str:
        self._check_scope(key)
        try:
            self.set_secret(key, new_value)
            return f"gcp-rotated-{key}"
        except Exception as exc:
            raise RotationError(f"Rotation failed for '{key}': {exc}") from exc

    def revoke_token(self, key: str) -> None:
        self._check_scope(key)
        try:
            self.set_secret(key, "")
        except Exception as exc:
            raise ProviderError(f"Failed to revoke token '{key}': {exc}") from exc

    def list_secrets(self, prefix: Optional[str] = None) -> list[SecretMetadata]:
        _, _, GoogleAPICallError = _import_gcp()
        try:
            parent = f"projects/{self._project_id}"
            result = []
            for secret in self._client.list_secrets(parent=parent):
                name = secret.name.split("/")[-1]
                if prefix and not name.startswith(prefix):
                    continue
                ct = secret.create_time
                result.append(SecretMetadata(
                    key=name,
                    version="latest",
                    created_at=ct.isoformat() if ct else "",
                    last_rotated_at=None,
                    expires_at=None,
                ))
            return result
        except GoogleAPICallError as exc:
            raise ProviderError(f"GCP error listing secrets: {exc}") from exc

    def delete_secret(self, key: str) -> None:
        self._check_scope(key)
        _, NotFound, GoogleAPICallError = _import_gcp()
        try:
            self._client.delete_secret(name=self._secret_parent(key))
        except NotFound as exc:
            raise KeyNotFoundError(f"Secret '{key}' not found") from exc
        except GoogleAPICallError as exc:
            raise ProviderError(f"GCP error deleting '{key}': {exc}") from exc

    def health_check(self) -> bool:
        try:
            parent = f"projects/{self._project_id}"
            next(iter(self._client.list_secrets(parent=parent, page_size=1)), None)
            return True
        except Exception:
            return False

    @property
    def provider_name(self) -> str:
        return "gcp"

    @property
    def environment_scope(self) -> str:
        return self._environment_scope
