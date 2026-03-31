"""
Yashigani KSM — AWS Secrets Manager provider.
Prefers IAM role-based auth; falls back to explicit key/secret.
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


def _import_boto3():
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
        return boto3, ClientError, NoCredentialsError
    except ImportError as exc:
        raise ImportError(
            "boto3 is required for AWSSecretsManagerProvider. "
            "Install it with: pip install boto3"
        ) from exc


class AWSSecretsManagerProvider(KSMProvider):

    def __init__(self, environment_scope: str) -> None:
        self._environment_scope = environment_scope
        self._region = os.environ.get("KSM_AWS_REGION", "us-east-1")
        self._arn_prefix = os.environ.get("KSM_AWS_SECRET_ARN_PREFIX", "")
        self._client = self._build_client()

    def _build_client(self):
        boto3, _, _ = _import_boto3()
        kwargs: dict = {"region_name": self._region}
        key_id = os.environ.get("KSM_AWS_ACCESS_KEY_ID")
        secret_key = os.environ.get("KSM_AWS_SECRET_ACCESS_KEY")
        if key_id and secret_key:
            kwargs["aws_access_key_id"] = key_id
            kwargs["aws_secret_access_key"] = secret_key
        return boto3.client("secretsmanager", **kwargs)

    def _full_arn(self, key: str) -> str:
        name = key.split("/", 1)[-1] if "/" in key else key
        return f"{self._arn_prefix}{name}" if self._arn_prefix else name

    def get_secret(self, key: str) -> str:
        self._check_scope(key)
        _, ClientError, _ = _import_boto3()
        try:
            resp = self._client.get_secret_value(SecretId=self._full_arn(key))
            return resp.get("SecretString") or ""
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "InvalidRequestException"):
                raise KeyNotFoundError(f"Secret '{key}' not found in AWS Secrets Manager") from exc
            raise ProviderError(f"AWS error retrieving '{key}': {code}") from exc
        except Exception as exc:
            raise ProviderError(f"Failed to retrieve secret '{key}': {exc}") from exc

    def set_secret(self, key: str, value: str) -> None:
        self._check_scope(key)
        _, ClientError, _ = _import_boto3()
        try:
            try:
                self._client.put_secret_value(
                    SecretId=self._full_arn(key),
                    SecretString=value,
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                    self._client.create_secret(
                        Name=self._full_arn(key),
                        SecretString=value,
                    )
                else:
                    raise
        except ClientError as exc:
            raise ProviderError(f"AWS error setting '{key}': {exc.response['Error']['Code']}") from exc
        except Exception as exc:
            raise ProviderError(f"Failed to set secret '{key}': {exc}") from exc

    def rotate_secret(self, key: str, new_value: str) -> str:
        self._check_scope(key)
        try:
            self.set_secret(key, new_value)
            resp = self._client.describe_secret(SecretId=self._full_arn(key))
            versions = resp.get("VersionIdsToStages", {})
            if not versions:
                raise RotationError(f"No version stages found after rotation for '{key}'")
            return next(iter(versions))
        except Exception as exc:
            raise RotationError(f"Rotation failed for '{key}': {exc}") from exc

    def revoke_token(self, key: str) -> None:
        self._check_scope(key)
        try:
            self.set_secret(key, "")
        except Exception as exc:
            raise ProviderError(f"Failed to revoke token '{key}': {exc}") from exc

    def list_secrets(self, prefix: Optional[str] = None) -> list[SecretMetadata]:
        _, ClientError, _ = _import_boto3()
        try:
            paginator = self._client.get_paginator("list_secrets")
            result = []
            filters = [{"Key": "name", "Values": [prefix]}] if prefix else []
            for page in paginator.paginate(Filters=filters):
                for s in page.get("SecretList", []):
                    result.append(SecretMetadata(
                        key=s["Name"],
                        version=s.get("LastChangedDate", "").isoformat() if hasattr(s.get("LastChangedDate", ""), "isoformat") else "",
                        created_at=s.get("CreatedDate", "").isoformat() if hasattr(s.get("CreatedDate", ""), "isoformat") else "",
                        last_rotated_at=s.get("LastRotatedDate", "").isoformat() if hasattr(s.get("LastRotatedDate", ""), "isoformat") else None,
                        expires_at=None,
                    ))
            return result
        except ClientError as exc:
            raise ProviderError(f"AWS error listing secrets: {exc.response['Error']['Code']}") from exc

    def delete_secret(self, key: str) -> None:
        self._check_scope(key)
        _, ClientError, _ = _import_boto3()
        try:
            self._client.delete_secret(
                SecretId=self._full_arn(key),
                ForceDeleteWithoutRecovery=False,
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                raise KeyNotFoundError(f"Secret '{key}' not found") from exc
            raise ProviderError(f"AWS error deleting '{key}': {code}") from exc

    def health_check(self) -> bool:
        try:
            self._client.list_secrets(MaxResults=1)
            return True
        except Exception:
            return False

    @property
    def provider_name(self) -> str:
        return "aws"

    @property
    def environment_scope(self) -> str:
        return self._environment_scope
