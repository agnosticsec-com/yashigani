"""
Yashigani KSM — Azure Key Vault provider.
Uses azure-keyvault-secrets + azure-identity.
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


def _import_azure():
    try:
        from azure.keyvault.secrets import SecretClient
        from azure.identity import ClientSecretCredential, DefaultAzureCredential
        from azure.core.exceptions import ResourceNotFoundError, HttpResponseError
        return SecretClient, ClientSecretCredential, DefaultAzureCredential, ResourceNotFoundError, HttpResponseError
    except ImportError as exc:
        raise ImportError(
            "azure-keyvault-secrets and azure-identity are required for AzureKeyVaultProvider. "
            "Install with: pip install azure-keyvault-secrets azure-identity"
        ) from exc


class AzureKeyVaultProvider(KSMProvider):

    def __init__(self, environment_scope: str) -> None:
        self._environment_scope = environment_scope
        self._vault_url = os.environ["KSM_AZURE_VAULT_URL"]
        self._client = self._build_client()

    def _build_client(self):
        SecretClient, ClientSecretCredential, DefaultAzureCredential, _, _ = _import_azure()
        tenant_id = os.environ.get("KSM_AZURE_TENANT_ID")
        client_id = os.environ.get("KSM_AZURE_CLIENT_ID")
        client_secret = os.environ.get("KSM_AZURE_CLIENT_SECRET")
        if tenant_id and client_id and client_secret:
            credential = ClientSecretCredential(tenant_id, client_id, client_secret)
        else:
            credential = DefaultAzureCredential()
        return SecretClient(vault_url=self._vault_url, credential=credential)

    def _safe_name(self, key: str) -> str:
        name = key.split("/", 1)[-1] if "/" in key else key
        return name.replace("_", "-")

    def get_secret(self, key: str) -> str:
        self._check_scope(key)
        _, _, _, ResourceNotFoundError, HttpResponseError = _import_azure()
        try:
            secret = self._client.get_secret(self._safe_name(key))
            return secret.value or ""
        except ResourceNotFoundError as exc:
            raise KeyNotFoundError(f"Secret '{key}' not found in Azure Key Vault") from exc
        except HttpResponseError as exc:
            raise ProviderError(f"Azure error retrieving '{key}': {exc.message}") from exc

    def set_secret(self, key: str, value: str) -> None:
        self._check_scope(key)
        _, _, _, _, HttpResponseError = _import_azure()
        try:
            self._client.set_secret(self._safe_name(key), value)
        except HttpResponseError as exc:
            raise ProviderError(f"Azure error setting '{key}': {exc.message}") from exc

    def rotate_secret(self, key: str, new_value: str) -> str:
        self._check_scope(key)
        try:
            self.set_secret(key, new_value)
            secret = self._client.get_secret(self._safe_name(key))
            return secret.properties.version or "azure-rotated"
        except Exception as exc:
            raise RotationError(f"Rotation failed for '{key}': {exc}") from exc

    def revoke_token(self, key: str) -> None:
        self._check_scope(key)
        try:
            self.set_secret(key, "")
        except Exception as exc:
            raise ProviderError(f"Failed to revoke token '{key}': {exc}") from exc

    def list_secrets(self, prefix: Optional[str] = None) -> list[SecretMetadata]:
        _, _, _, _, HttpResponseError = _import_azure()
        try:
            result = []
            for prop in self._client.list_properties_of_secrets():
                name = prop.name or ""
                if prefix and not name.startswith(prefix):
                    continue
                result.append(SecretMetadata(
                    key=name,
                    version=prop.version or "",
                    created_at=prop.created_on.isoformat() if prop.created_on else "",
                    last_rotated_at=prop.updated_on.isoformat() if prop.updated_on else None,
                    expires_at=prop.expires_on.isoformat() if prop.expires_on else None,
                ))
            return result
        except HttpResponseError as exc:
            raise ProviderError(f"Azure error listing secrets: {exc.message}") from exc

    def delete_secret(self, key: str) -> None:
        self._check_scope(key)
        _, _, _, ResourceNotFoundError, HttpResponseError = _import_azure()
        try:
            poller = self._client.begin_delete_secret(self._safe_name(key))
            poller.result()
        except ResourceNotFoundError as exc:
            raise KeyNotFoundError(f"Secret '{key}' not found") from exc
        except HttpResponseError as exc:
            raise ProviderError(f"Azure error deleting '{key}': {exc.message}") from exc

    def health_check(self) -> bool:
        try:
            next(iter(self._client.list_properties_of_secrets()), None)
            return True
        except Exception:
            return False

    @property
    def provider_name(self) -> str:
        return "azure"

    @property
    def environment_scope(self) -> str:
        return self._environment_scope
