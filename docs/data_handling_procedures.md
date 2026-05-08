# Data Handling Procedures

> Version: 1.0.0
> Date: 2026-04-12
> Last reviewed: 2026-05-05 (v2.23.2 release — no content changes; v2.23.2 changes do not touch the policy areas covered by this document)
> Compliance: HIPAA §164.312 | SOC 2 P1–P8 | ISO 27001 A.5.12–A.5.14

## 1. Purpose

This document defines how data is classified, handled, stored, transmitted, retained, and deleted within Yashigani security gateway deployments. It ensures consistent data protection practices across all deployment environments.

## 2. Data Classification

All data processed or stored by Yashigani is classified into one of four levels:

| Level | Label | Description | Examples |
|-------|-------|-------------|----------|
| **L1** | PUBLIC | Information intended for public disclosure | Product documentation, open-source code, public APIs |
| **L2** | INTERNAL | Information for internal use, low risk if disclosed | Internal configuration defaults, non-sensitive logs, deployment guides |
| **L3** | CONFIDENTIAL | Sensitive business or personal data | Audit logs, user profiles, API keys, authentication events, OPA policies |
| **L4** | RESTRICTED | Highly sensitive data subject to regulatory requirements | ePHI, TOTP seeds, encryption keys, admin credentials, database passwords |

### Classification by Component

| Data | Classification | Storage Location |
|------|---------------|-----------------|
| MCP tool calls and responses | L3 (CONFIDENTIAL) or L4 (RESTRICTED) if containing ePHI | Audit log (PostgreSQL) |
| User authentication credentials | L4 (RESTRICTED) | PostgreSQL (bcrypt hashed) |
| TOTP seeds | L4 (RESTRICTED) | PostgreSQL (AES-256-GCM encrypted) |
| Admin API keys | L4 (RESTRICTED) | PostgreSQL (AES-256-GCM encrypted) |
| Session tokens | L3 (CONFIDENTIAL) | Redis (4h TTL) |
| Audit log entries | L3 (CONFIDENTIAL) | PostgreSQL (partitioned monthly) |
| OPA policies | L2 (INTERNAL) | Filesystem + OPA container |
| TLS certificates | L4 (RESTRICTED) private key / L1 (PUBLIC) certificate | Filesystem (Caddy data directory) |
| Docker Compose configuration | L3 (CONFIDENTIAL) | Filesystem |
| Backup archives | L4 (RESTRICTED) | Filesystem (encrypted) |

## 3. PII Handling

Yashigani provides three configurable modes for handling personally identifiable information (PII) detected in MCP traffic. The mode is configured via OPA policy by the deployment administrator.

| Mode | Behaviour | Use Case |
|------|-----------|----------|
| **log** | PII is logged in the audit trail for compliance review | Environments requiring full audit trail of all data |
| **redact** | PII is replaced with type-specific placeholders (e.g., `[EMAIL]`, `[SSN]`) before forwarding to the MCP server | Standard deployments balancing compliance and functionality |
| **block** | Requests containing PII are rejected with an error response and the attempt is logged | High-security environments where PII must never reach MCP servers |

### PII Detection

The gateway detects the following PII categories:

- Email addresses
- Phone numbers
- National identification numbers (SSN, NI number, etc.)
- Credit card numbers (Luhn-validated)
- Dates of birth
- Physical addresses
- Medical record numbers
- Custom patterns defined in OPA policy

### PII in Audit Logs

When the PII mode is set to `redact` or `block`, audit log entries store the redacted version. When the mode is set to `log`, the original data is stored in the audit log and is protected by the database encryption and access controls.

## 4. Data at Rest

### Encryption

| Component | Method | Key Management |
|-----------|--------|---------------|
| PostgreSQL sensitive columns | AES-256-GCM via pgcrypto | Application-managed encryption key, stored outside the database |
| Backup archives | AES-256-GCM | Backup encryption key, stored separately from backups |
| TLS private keys | Filesystem permissions (0600) | Managed by Caddy |
| Docker/Podman volumes | Host filesystem encryption (recommended) | Customer-managed (dm-crypt/LUKS recommended) |

### Database Security

- All L4 (RESTRICTED) data is encrypted at the application layer before storage
- Database access requires authentication (no trust-based local connections)
- Database connections are restricted to the Docker network (not exposed externally)
- Connection pooling limits prevent resource exhaustion

## 5. Data in Transit

### External Communications

| Protocol | Configuration |
|----------|--------------|
| TLS version | 1.3 (minimum and preferred) |
| Key exchange | X25519+ML-KEM-768 (post-quantum hybrid) |
| HSTS | Enabled, max-age=31536000 (1 year), includeSubDomains |
| HTTP | Redirected to HTTPS (no plaintext HTTP responses) |
| Certificate transparency | Monitored via Caddy |

### Internal Communications

| Path | Protection |
|------|-----------|
| Caddy to Gateway | Docker network (isolated, not exposed) |
| Gateway to PostgreSQL | Docker network + password authentication |
| Gateway to Redis | Docker network + password authentication |
| Gateway to OPA | Docker network + bearer token |
| Gateway to Wazuh | Docker network + agent authentication |

All internal communication occurs over the Docker bridge network, which is isolated from external access. No service ports are exposed on the host except Caddy (443).

## 6. Data Retention

### Retention Periods

| Data Type | Default Retention | Configurable | Notes |
|-----------|------------------|-------------|-------|
| Audit logs | 12 months | Yes (admin setting) | Partitioned monthly in PostgreSQL |
| Session data | 4 hours (absolute timeout) | No | Redis TTL, automatically purged |
| Authentication events | 12 months (within audit log) | Yes | Part of the audit log partition |
| Failed login attempts | 12 months | Yes | Logged in audit trail |
| Backup archives | 30 days (local), customer-defined (off-site) | Yes | Managed by backup rotation |
| OPA decision logs | 12 months | Yes | Stored in audit log |

### Partition Management

Audit logs are partitioned by month in PostgreSQL. Expired partitions are:

1. Exported to compressed archive format (if archival is enabled)
2. Dropped from the database
3. Verified as removed from active storage

The retention period and archival behaviour are configured by the deployment administrator.

## 7. Data Deletion

### User Account Deletion

When a user account is deleted via `DELETE /admin/users/{id}`:

1. **Export**: Audit records for the user are exported via `/admin/audit/export` (if configured)
2. **Session invalidation**: All active sessions for the user are invalidated in Redis
3. **Credential removal**: Password hash, TOTP seeds, and API keys are deleted
4. **Profile deletion**: User profile data is removed from the database
5. **Audit log retention**: Audit log entries are retained (with the user ID pseudonymised) for the configured retention period, as required for compliance
6. **Podman containers**: Any active agent containers for the user are stopped and removed

### Bulk Data Deletion

For decommissioning a Yashigani deployment:

1. Export all required audit data using `/admin/audit/export`
2. Stop all services: `docker compose down`
3. Remove all Docker volumes: `docker volume rm $(docker volume ls -q --filter name=yashigani)`
4. Remove configuration files from the host
5. Securely wipe the backup encryption key
6. Document the decommission date and data disposition

## 8. Data Subject Access Requests

Yashigani provides administrative APIs to fulfil data subject access requests (DSARs) under GDPR, CCPA, and similar regulations:

| Request Type | API Endpoint | Description |
|-------------|-------------|-------------|
| **Access** | `GET /admin/audit/search?user_id={id}` | Retrieve all audit records for a user |
| **Export** | `GET /admin/audit/export?user_id={id}&format=json` | Export user data in machine-readable format |
| **Correction** | `PATCH /admin/users/{id}` | Update user profile information |
| **Deletion** | `DELETE /admin/users/{id}` | Delete user account (see Section 7) |
| **Restriction** | `PATCH /admin/users/{id}` with `locked: true` | Restrict processing by locking the account |

### DSAR Process

1. Verify the identity of the requestor (admin must confirm before executing)
2. Execute the appropriate API call
3. Deliver the response within the regulatory timeframe (GDPR: 30 days, CCPA: 45 days)
4. Log the DSAR and its resolution in the audit trail

## 9. Consent Mechanisms

Yashigani is deployed on-premises within the customer's infrastructure. The customer acts as the data controller and is responsible for obtaining appropriate consent from their users.

The gateway supports consent management through:

- **Terms acceptance**: Configurable terms of service displayed at first login
- **Privacy notice**: Configurable privacy notice with acknowledgement tracking
- **Consent audit trail**: All consent events (acceptance, withdrawal) are logged in the audit trail
- **Withdrawal mechanism**: Users can withdraw consent via their profile settings, triggering account deactivation

## 10. Related Documents

- [Access Control Policy](access_control_policy.md) — authentication and authorisation controls
- [Incident Response Plan](incident_response_plan.md) — breach response procedures
- [PRIVACY_POLICY.md](../PRIVACY_POLICY.md) — product privacy policy
- [Supplier Security](supplier_security.md) — third-party data handling requirements
