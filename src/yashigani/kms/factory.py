"""
Yashigani KSM — Provider factory.
Selects and instantiates the correct KSMProvider based on environment variables.
"""
from __future__ import annotations

import os

from yashigani.kms.base import KSMProvider, ProviderError

_PROVIDER_MAP: dict[str, str] = {
    "keeper": "yashigani.kms.providers.keeper.KeeperKSMProvider",
    "docker": "yashigani.kms.providers.docker_secrets.DockerSecretsProvider",
    "aws":    "yashigani.kms.providers.aws.AWSSecretsManagerProvider",
    "azure":  "yashigani.kms.providers.azure.AzureKeyVaultProvider",
    "gcp":    "yashigani.kms.providers.gcp.GCPSecretManagerProvider",
    "vault":  "yashigani.kms.providers.vault.VaultKMSProvider",
}

_DEV_ENVS = {"dev", "development", "local", "test", "demo"}


def create_provider() -> KSMProvider:
    """
    Instantiate and return a KSMProvider based on environment variables.

    YASHIGANI_KSM_PROVIDER  — provider name (default: 'keeper', or 'docker'
                               when YASHIGANI_ENV is dev/local/test)
    YASHIGANI_ENV           — environment scope label (required)
    """
    env_scope = os.environ.get("YASHIGANI_ENV", "").strip()
    if not env_scope:
        raise ProviderError(
            "YASHIGANI_ENV environment variable is required and must not be empty. "
            "Set it to e.g. 'production', 'staging', 'dev', or 'local'."
        )

    default_provider = "docker" if env_scope in _DEV_ENVS else "keeper"
    provider_name = os.environ.get("YASHIGANI_KSM_PROVIDER", default_provider).strip().lower()

    if provider_name not in _PROVIDER_MAP:
        raise ProviderError(
            f"Unknown KSM provider '{provider_name}'. "
            f"Valid values: {', '.join(sorted(_PROVIDER_MAP))}"
        )

    cls = _load_class(_PROVIDER_MAP[provider_name])
    instance: KSMProvider = cls(environment_scope=env_scope)

    if instance.provider_name != provider_name:
        raise ProviderError(
            f"Provider reported name '{instance.provider_name}' "
            f"but factory expected '{provider_name}'"
        )
    if not instance.environment_scope:
        raise ProviderError("Provider returned an empty environment_scope")

    return instance


def _load_class(dotted_path: str):
    """Lazily import a class by dotted module path."""
    module_path, class_name = dotted_path.rsplit(".", 1)
    import importlib
    module = importlib.import_module(module_path)
    cls = getattr(module, class_name, None)
    if cls is None:
        raise ProviderError(f"Class '{class_name}' not found in module '{module_path}'")
    return cls
