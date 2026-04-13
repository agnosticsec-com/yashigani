# Privacy Policy

> Version: 1.0.0
> Date: 2026-04-12
> Compliance: SOC 2 P1–P8 | ISO 27001 A.5.34

## Overview

Yashigani is a security gateway for Model Context Protocol (MCP) deployments, developed by Agnostic Security. This privacy policy describes what data the product collects, how data is processed within customer deployments, and the rights of data subjects.

## Data We Collect

### Installation Telemetry (Optional)

During installation, the installer may optionally collect:

- **Email address** — for security advisory notifications only
- **Country** — for aggregate deployment statistics

This collection is strictly opt-in. The installer functions identically whether or not this information is provided. No telemetry is transmitted unless the customer explicitly consents.

### No Phone-Home

Yashigani does not:

- Send telemetry to Agnostic Security or any third party
- Contact external servers during normal operation
- Transmit customer data outside the deployment infrastructure

Update checks are opt-in only and transmit no customer data beyond the installed version number.

## Data the Gateway Processes

Yashigani operates as an on-premises security gateway. The data it processes is determined entirely by the customer's deployment configuration.

### Customer-Controlled Data

All data processed by Yashigani resides within the customer's own infrastructure. Agnostic Security has no access to:

- MCP tool calls and responses
- User queries or AI model outputs
- Audit logs
- Authentication credentials
- Any data stored in the customer's PostgreSQL database

### PII Handling Modes

The gateway provides three configurable modes for personally identifiable information (PII) detected in MCP traffic:

| Mode | Behaviour |
|------|-----------|
| **log** | PII is logged in the audit trail for compliance review |
| **redact** | PII is replaced with placeholders before forwarding |
| **block** | Requests containing PII are rejected with an error |

The deployment administrator configures the appropriate mode via OPA policy.

## Data Protection

### Data at Rest

- All sensitive data at rest is encrypted using AES-256-GCM via PostgreSQL pgcrypto
- Secrets (API keys, TOTP seeds) are encrypted at the application layer before database storage
- Backup files created by `backup.sh` inherit the encryption of the source data

### Data in Transit

- All external communications use TLS 1.3
- Key exchange uses X25519+ML-KEM-768 (post-quantum hybrid)
- HSTS is enforced with a minimum max-age of one year
- Internal service-to-service communication uses the Docker network with no external exposure

## Data Retention

- **Audit logs** are partitioned monthly in PostgreSQL and retained for a configurable period (default: 12 months)
- **Session data** is stored in Redis with a 4-hour absolute timeout
- **Authentication events** (login, logout, failed attempts) are retained in the audit log
- Retention periods are configurable by the deployment administrator

## Data Subject Rights

Yashigani provides administrative APIs to support data subject rights under GDPR and similar regulations:

| Right | Mechanism |
|-------|-----------|
| **Access** | `GET /admin/audit/search` — search and retrieve audit records by user |
| **Export** | `GET /admin/audit/export` — export user data in structured format |
| **Deletion** | `DELETE /admin/users/{id}` — delete user account and associated data |
| **Correction** | `PATCH /admin/users/{id}` — update user profile information |
| **Portability** | `GET /admin/audit/export?format=json` — export in machine-readable format |

Audit records are exported before account deletion to maintain compliance records.

## GDPR Compliance

Because Yashigani is deployed on-premises within the customer's infrastructure:

- **Data controller**: The customer
- **Data processor**: The customer (self-hosted, no third-party processing)
- **Data location**: Determined by the customer's infrastructure location
- **Cross-border transfers**: Not applicable — data does not leave the customer's infrastructure

Agnostic Security acts as a software vendor, not a data processor, for on-premises deployments.

## Children's Privacy

Yashigani does not knowingly collect or process data from children under the age of 16. The product is an enterprise security gateway and is not intended for use by children.

## Changes to This Policy

We may update this privacy policy from time to time. Changes will be documented with a new version number and date. Material changes will be communicated via the release notes.

## Contact

For privacy-related enquiries:

- **Email**: privacy@agnosticsec.com
- **Security issues**: security@agnosticsec.com (see SECURITY.md)
