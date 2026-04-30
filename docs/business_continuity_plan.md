<!-- last-updated: 2026-05-01T00:09:28+01:00 -->
# Business Continuity Plan

> Version: 1.0.1
> Date: 2026-05-01
> Compliance: ISO 27001 A.5.29, A.5.30 | HIPAA §164.308(a)(7)(i)

## 1. Purpose

This document defines the business continuity and disaster recovery procedures for Yashigani security gateway deployments. It ensures that information security is maintained during disruptions and that services can be restored within defined recovery targets.

## 2. Scope

This plan covers all components of a Yashigani deployment:

- Caddy reverse proxy (TLS termination, forward auth)
- Yashigani gateway application (Python/FastAPI)
- PostgreSQL database (audit logs, user data, configuration)
- Redis (session store, rate limiting)
- OPA (policy engine)
- Wazuh SIEM (security monitoring)
- Grafana and Prometheus (observability)
- Open WebUI (optional, user-facing interface)
- Podman agent containers (per-user isolation)

## 3. Recovery Objectives

| Metric | Target | Justification |
|--------|--------|---------------|
| **RPO** (Recovery Point Objective) | 1 hour | PostgreSQL WAL archiving + hourly automated backups via `backup.sh` |
| **RTO** (Recovery Time Objective) | 4 hours | Full stack rebuild via `install.sh` + data restore via `restore.sh` |
| **MTPD** (Maximum Tolerable Period of Disruption) | 8 hours | Based on typical MCP gateway usage patterns |

## 4. Roles and Responsibilities

| Role | Responsibility |
|------|---------------|
| **Incident Commander** | Declares BCP activation, coordinates recovery, communicates with stakeholders |
| **Infrastructure Lead** | Executes recovery procedures, validates system integrity |
| **Security Lead** | Assesses security impact, ensures controls are restored, manages credential rotation |
| **Communications Lead** | Notifies affected users, regulators (if required), and management |

For organisations deploying Yashigani, these roles should be mapped to specific individuals with documented deputies.

## 5. Backup Strategy

### 5.1 Automated Backups

Yashigani includes `backup.sh` which creates comprehensive backups:

| Component | Method | Frequency | Retention |
|-----------|--------|-----------|-----------|
| PostgreSQL database | `pg_dump` with compression | Hourly (cron) | 30 days |
| Docker/Podman volumes | Volume export | Daily | 14 days |
| Configuration files | File copy (docker-compose.yml, Caddyfile, OPA policies) | On change + daily | 30 days |
| Secrets | Encrypted export (AES-256-GCM) | On change + daily | 30 days |
| TLS certificates | File copy | On renewal + daily | 30 days |

### 5.2 Backup Storage

- Primary: Local backup directory on the host (`/opt/yashigani/backups/`)
- Secondary: Off-site storage (customer-configured, e.g., S3, NFS, rsync to remote host)
- Backups are encrypted at rest using the deployment's backup encryption key

### 5.3 Backup Verification

- Automated integrity checks run after each backup (checksum verification)
- Monthly restore tests to a staging environment (see Section 9)

## 6. Disruption Scenarios and Response

### 6.1 Partial Service Failure (Single Container)

**Impact**: One service is down; others continue operating.

**Response**:
1. Identify the failed container via Grafana alerts or `docker ps`
2. Restart the container: `docker compose restart <service>`
3. Verify service health via the `/health` endpoint
4. Review logs for root cause

**Expected recovery time**: 5–15 minutes.

### 6.2 Complete Server Loss

**Impact**: The host machine is destroyed or inaccessible.

**Response**:
1. Provision a new server meeting the Yashigani hardware requirements
2. Install prerequisites (Docker/Podman, system dependencies)
3. Run `install.sh` with the original configuration
4. Run `restore.sh` from the most recent off-site backup
5. Verify data integrity and service health
6. Rotate all credentials (the original server may be compromised)
7. Update DNS records if the server IP has changed

**Expected recovery time**: 2–4 hours.

### 6.3 Database Corruption

**Impact**: PostgreSQL data is inconsistent or unreadable.

**Response**:
1. Stop the gateway to prevent further writes
2. Attempt PostgreSQL recovery using WAL replay
3. If WAL recovery fails, restore from the most recent `pg_dump` backup via `restore.sh`
4. Verify audit log integrity (row counts, latest timestamps)
5. Restart the gateway
6. Document any data loss window

**Expected recovery time**: 30–90 minutes.

### 6.4 Compromised Credentials

**Impact**: Administrative or service credentials have been exposed.

**Response**:
1. Immediately revoke all active sessions (`DELETE /admin/sessions`)
2. Rotate all affected credentials:
   - Admin passwords
   - Database passwords
   - API keys and TOTP seeds
   - TLS certificates (if private keys were exposed)
3. Review audit logs for unauthorised access
4. Follow the Incident Response Plan for investigation
5. Re-enable services with new credentials

**Expected recovery time**: 1–2 hours.

### 6.5 Network Disruption

**Impact**: The server is running but unreachable.

**Response**:
1. Verify the gateway continues logging locally (no data loss)
2. Coordinate with network/hosting provider for restoration
3. Verify no security events occurred during the outage via audit log review
4. Confirm Wazuh SIEM reconnects and resumes monitoring

**Expected recovery time**: Dependent on network provider.

## 7. Information Security During Disruption

During any disruption, the following security controls must be maintained:

- **Access control**: No relaxation of authentication or authorisation requirements
- **Audit logging**: Logging continues to local storage even if the database is unavailable
- **Encryption**: All data remains encrypted at rest and in transit
- **Monitoring**: Wazuh SIEM alerts are reviewed as soon as connectivity is restored
- **Credential management**: Emergency access uses the same MFA requirements as normal operation

If a security control cannot be maintained during recovery, this must be:
1. Documented in the incident record
2. Approved by the Security Lead
3. Restored as the first priority after basic service recovery

## 8. Communication Plan

### 8.1 Internal Communication

| Trigger | Notification | Channel | Timeline |
|---------|-------------|---------|----------|
| Service disruption detected | Incident Commander + Infrastructure Lead | On-call pager / secure messaging | Immediate |
| BCP activated | All technical staff | Secure messaging channel | Within 15 minutes |
| Recovery complete | All technical staff + management | Email + secure messaging | Upon completion |

### 8.2 External Communication

| Trigger | Notification | Channel | Timeline |
|---------|-------------|---------|----------|
| User-facing disruption | Affected users | Status page / email | Within 30 minutes |
| Data breach suspected | Regulatory authorities | As per Incident Response Plan | Per regulatory requirements (e.g., HIPAA: 60 days) |
| Recovery complete | Affected users | Status page / email | Upon completion |

## 9. Recovery Testing Schedule

| Test | Frequency | Scope |
|------|-----------|-------|
| Backup restore validation | Monthly | Restore latest backup to staging, verify data integrity |
| Single-service failover | Quarterly | Kill a service, verify automatic restart and health checks |
| Full disaster recovery | Annually | Complete `install.sh` + `restore.sh` on clean infrastructure |
| Tabletop exercise | Bi-annually | Walk through scenarios with all role holders |

All test results must be documented, including:
- Date and participants
- Scenario tested
- Actual recovery time vs. target
- Issues identified and remediation actions
- Sign-off by the Incident Commander

## 10. Plan Maintenance

- This plan is reviewed and updated quarterly
- Updates are triggered by:
  - Significant changes to the Yashigani architecture
  - Lessons learned from incidents or recovery tests
  - Changes in regulatory requirements
  - Changes in organisational structure or responsibilities
- All updates are version-controlled in the Yashigani repository

## 11. Related Documents

- [Disaster Recovery Plan](disaster_recovery.md) — detailed recovery procedures
- [Incident Response Plan](incident_response_plan.md) — security incident handling
- [Yashigani Install Configuration](yashigani_install_config.md) — installation reference
- [SECURITY.md](../SECURITY.md) — vulnerability reporting
