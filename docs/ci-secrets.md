# CI/CD Secrets Reference

**Version:** v0.7.1
**Last updated:** 2026-03-28

All secrets are stored in GitHub Actions repository secrets (Settings > Secrets and variables > Actions).
No secret value may appear in workflow artifacts, logs, or `--set` flags on `helm upgrade`.
Kubeconfig files must be deleted in an `if: always()` cleanup step immediately after use.

---

## Secret Inventory

| Secret Name | Workflow(s) | Scope | Rotation Policy |
|---|---|---|---|
| `GHCR_TOKEN` | `build-push.yml` | Repository — write:packages | Rotate every 90 days or on team member departure |
| `COSIGN_PRIVATE_KEY` | `build-push.yml` | Repository | Rotate annually or on key compromise |
| `COSIGN_PASSWORD` | `build-push.yml` | Repository | Rotate with `COSIGN_PRIVATE_KEY` |
| `COSIGN_PUBLIC_KEY` | `deploy.yml` | Repository | Rotate with `COSIGN_PRIVATE_KEY` |
| `KUBECONFIG_B64` | `deploy.yml` | Environment (staging / production) | Rotate every 30 days; revoke immediately after first bootstrap use |
| `CERT_MANAGER_BOOTSTRAP_KUBECONFIG` | `deploy.yml` (bootstrap only) | Environment — one-time use | Revoke and delete after first successful cert-manager install |
| `CODECOV_TOKEN` | `ci.yml` | Repository | Rotate every 180 days |
| `SEMGREP_APP_TOKEN` | `ci.yml`, `security.yml` | Repository | Rotate every 90 days |

---

## Rules

1. **Secrets never in artifacts.** Workflow steps must not write secret values to files that are then uploaded via `actions/upload-artifact`.
2. **Kubeconfig deleted in `if: always()` step.** The `deploy.yml` workflow writes kubeconfig to `/tmp/kubeconfig` and removes it in a final cleanup step marked `if: always()` so deletion runs even on job failure.
3. **CERT_MANAGER_BOOTSTRAP_KUBECONFIG rotated after first use.** This credential has elevated cluster-admin scope. After cert-manager is bootstrapped, the kubeconfig must be revoked in the cluster and the secret deleted from GitHub.
4. **No `--set` for secrets in `helm upgrade`.** All runtime secrets (passwords, API keys) are injected via Kubernetes Secrets or external-secrets-operator. The `helm upgrade --install` command in `deploy.yml` must only pass image tags and environment values files.

---

## Cosign Key Generation

Generate a new key pair with a strong passphrase:

```bash
# Interactive — prompts for passphrase
cosign generate-key-pair

# Non-interactive — passphrase from env var (CI key rotation)
COSIGN_PASSWORD="$(openssl rand -base64 36)" cosign generate-key-pair
echo "Save COSIGN_PASSWORD securely before discarding the terminal session."
```

This produces `cosign.key` (private) and `cosign.pub` (public).

Store values in GitHub secrets:
- `COSIGN_PRIVATE_KEY` — contents of `cosign.key`
- `COSIGN_PASSWORD` — the passphrase used during generation
- `COSIGN_PUBLIC_KEY` — contents of `cosign.pub`

Delete local key files after upload:

```bash
rm -f cosign.key cosign.pub
```

---

## Kubeconfig Base64 Encoding

Encode a kubeconfig for storage as `KUBECONFIG_B64`:

```bash
# macOS
base64 -i ~/.kube/config | tr -d '\n'

# Linux
base64 -w 0 ~/.kube/config
```

Copy the output (no newlines) and paste into the GitHub secret value field.

The `deploy.yml` workflow decodes it at runtime:

```bash
echo "${{ secrets.KUBECONFIG_B64 }}" | base64 -d > /tmp/kubeconfig
chmod 600 /tmp/kubeconfig
```

Verify the decoded file is scoped to the minimum required namespace and service account before encoding. Do not use cluster-admin kubeconfigs for routine deployments.
