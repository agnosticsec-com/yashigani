"""
Yashigani KSM — Abstract base class and custom exceptions.
All KSM providers must implement KSMProvider.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class ProviderError(Exception):
    """General KSM provider error."""


class KeyNotFoundError(ProviderError):
    """Secret key does not exist in the provider."""


class RotationError(ProviderError):
    """Secret rotation failed."""


class ScopeViolationError(ProviderError):
    """Request targets a key outside the provider's environment scope."""


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SecretMetadata:
    key: str
    version: str
    created_at: str           # ISO 8601
    last_rotated_at: Optional[str]
    expires_at: Optional[str]


# ---------------------------------------------------------------------------
# Abstract provider
# ---------------------------------------------------------------------------

class KSMProvider(ABC):
    """
    Provider-agnostic interface for secrets management.
    Implementations: KeeperKSMProvider, DockerSecretsProvider,
                     AWSSecretsManagerProvider, AzureKeyVaultProvider,
                     GCPSecretManagerProvider.
    """

    # -- Core operations -----------------------------------------------------

    @abstractmethod
    def get_secret(self, key: str) -> str:
        """
        Retrieve plaintext secret value by key.
        Raises KeyNotFoundError, ProviderError, ScopeViolationError.
        """

    @abstractmethod
    def set_secret(self, key: str, value: str) -> None:
        """
        Create or update a secret.
        Raises ProviderError, ScopeViolationError.
        """

    @abstractmethod
    def rotate_secret(self, key: str, new_value: str) -> str:
        """
        Rotate secret to new_value.
        Returns the new version identifier string.
        Raises RotationError, KeyNotFoundError, ProviderError.
        """

    @abstractmethod
    def revoke_token(self, key: str) -> None:
        """
        Invalidate / revoke a credential handle or token.
        Raises KeyNotFoundError, ProviderError.
        """

    @abstractmethod
    def list_secrets(self, prefix: Optional[str] = None) -> list[SecretMetadata]:
        """
        List available secret keys (metadata only — no values).
        Raises ProviderError.
        """

    @abstractmethod
    def delete_secret(self, key: str) -> None:
        """
        Permanently delete a secret.
        Raises KeyNotFoundError, ProviderError.
        """

    @abstractmethod
    def health_check(self) -> bool:
        """
        Verify provider connectivity and auth.
        Returns True if healthy, False otherwise.
        Never raises — absorb all errors and return False.
        """

    # -- Identity ------------------------------------------------------------

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider identifier, e.g. 'keeper', 'aws'."""

    @property
    @abstractmethod
    def environment_scope(self) -> str:
        """Environment this instance is scoped to, e.g. 'production'."""

    # -- Helpers -------------------------------------------------------------

    def _check_scope(self, key: str) -> None:
        """
        Raise ScopeViolationError if key contains a scope prefix that
        does not match this provider's environment_scope.

        Convention: keys may optionally be prefixed as '<scope>/<name>'.
        If a prefix is present and mismatches, raise.
        """
        if "/" in key:
            prefix, _ = key.split("/", 1)
            if prefix != self.environment_scope:
                raise ScopeViolationError(
                    f"Key scope '{prefix}' does not match provider scope "
                    f"'{self.environment_scope}'"
                )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(scope={self.environment_scope!r})"
