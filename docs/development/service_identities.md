# Service Identity Manifest — Update Process

Last updated: 2026-05-01T00:00:00+01:00

## What is service_identities.yaml?

`docker/service_identities.yaml` is the IaC-declared allowlist of every
container that participates in the Yashigani mTLS mesh. It is the single
authoritative document for:

- Service names and DNS SANs embedded in leaf certs.
- SPIFFE URI SANs used by the application-layer SPIFFE gate.
- `endpoint_acls` — per-path SPIFFE-ID allowlists enforced by
  `src/yashigani/auth/spiffe.py`.
- `cert_policy` — hard bounds on cert lifetimes enforced by `install.sh` and
  the `/admin/settings/internal-pki` API.
- `ca_source` — tier-gated CA mode selection.

Any service that is not listed here cannot obtain an mTLS client cert and will
be rejected at the mesh edge.

## The two-file reality and why it exists

Helm's `.Files.Get` function cannot reach files outside the chart directory
tree. As a result, the manifest must exist at two paths:

| Path | Role |
|------|------|
| `docker/service_identities.yaml` | Canonical source. Edit here ONLY. |
| `helm/yashigani/files/service_identities.yaml` | Derived copy for Helm. Never edit directly. |

The Helm copy is rendered into the `yashigani-pki-manifest` ConfigMap by
`helm/yashigani/templates/mtls-manifest-configmap.yaml` at `helm package`
time and at `helm install`/`helm upgrade` time.

## How to update service_identities.yaml

1. Edit `docker/service_identities.yaml`.
2. Run `make sync-service-identities`. This copies the canonical source into
   `helm/yashigani/files/service_identities.yaml`.
3. Verify: `make check-service-identities` (or run the contract test —
   `python3 -m pytest tests/contracts/test_service_identities_sha.py`).
4. Commit BOTH files in the same commit.

```
git add docker/service_identities.yaml helm/yashigani/files/service_identities.yaml
git commit -m "feat(pki): add <service-name> to service identity manifest"
```

Do NOT commit `helm/yashigani/files/service_identities.yaml` alone. A commit
that updates only the Helm copy without updating the canonical source, or vice
versa, will fail the CI gate on the next push.

## CI enforcement

Every push and pull request against `main`, `2.23.x`, or any `release/**`
branch runs `tests/contracts/test_service_identities_sha.py` as part of the
`contracts` CI job. The job fails hard if the SHA-256 digests of the two files
differ.

A failing contracts gate blocks merge. It cannot be overridden; the Helm copy
must be regenerated via `make sync-service-identities`.

## Design rationale — why not a symlink or single file?

- **Symlinks**: `helm package` does not follow symlinks inside the chart
  directory. A symlink in `helm/yashigani/files/` would result in a broken
  or missing file inside the packaged chart.
- **Single canonical path outside the chart**: `.Files.Get` enforces that the
  path argument is within the chart directory tree. A path traversal (e.g.
  `../../docker/service_identities.yaml`) is rejected by Helm.
- **Build-step copy with SHA enforcement** (chosen approach): lowest blast
  radius. No runtime path changes. The canonical source is clearly named.
  CI catches drift at the earliest possible point — on push, not on deploy.
