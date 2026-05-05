<!-- last-updated: 2026-05-01T00:09:28+01:00 -->
# Disaster Recovery Plan

> Version: 1.0.1
> Date: 2026-05-01
> Last reviewed: 2026-05-05 (v2.23.2 release — no content changes since v2.23.1 revision)
> Compliance: HIPAA §164.308(a)(7)(ii)(B) | ISO 27001 A.5.29

## 1. Purpose

This document provides step-by-step disaster recovery procedures for Yashigani security gateway deployments. It covers three primary disaster scenarios: complete server loss, database corruption, and compromised credentials.

## 2. Recovery Objectives

| Metric | Target |
|--------|--------|
| **RPO** (Recovery Point Objective) | 1 hour |
| **RTO** (Recovery Time Objective) | 4 hours |

These targets assume off-site backups are available and current.

## 3. Prerequisites

Before a disaster occurs, the following must be in place:

- [ ] `backup.sh` running on an hourly cron schedule
- [ ] Off-site backup replication configured (rsync, S3, or equivalent)
- [ ] Backup encryption key stored securely and accessible to recovery personnel
- [ ] A tested copy of `install.sh` and `restore.sh` available (in the off-site backup or version control)
- [ ] Hardware or cloud provisioning capability for a replacement server
- [ ] Documented network configuration (IP addresses, DNS records, firewall rules)

## 4. Scenario 1 — Complete Server Loss

**Trigger**: The host machine is destroyed, stolen, or permanently inaccessible.

### Step-by-Step Recovery

#### 4.1 Provision Replacement Infrastructure

1. Provision a server meeting the minimum requirements:
   - 4 CPU cores, 8 GB RAM, 100 GB SSD (minimum)
   - Ubuntu 22.04+ or RHEL 9+ (supported distributions)
   - Network connectivity with the required ports (443, 8080)
2. Configure network settings to match the original deployment (static IP, DNS, firewall rules)
3. Ensure Docker or Podman is installed and running

#### 4.2 Retrieve Backups

1. Download the most recent backup archive from off-site storage:
   ```
   rsync -avz backup-server:/backups/yashigani/latest/ /opt/yashigani/backups/
   ```
2. Verify backup integrity using the checksum file:
   ```
   sha256sum -c /opt/yashigani/backups/latest.sha256
   ```
3. Decrypt the backup if encrypted:
   ```
   gpg --decrypt /opt/yashigani/backups/latest.tar.gz.gpg > /opt/yashigani/backups/latest.tar.gz
   ```

#### 4.3 Install and Restore

1. Clone the Yashigani repository or extract the installer from the backup:
   ```
   git clone https://github.com/agnosticsec/yashigani.git
   cd yashigani
   ```
2. Run the installer:
   ```
   ./install.sh
   ```
3. Once the base installation completes, restore data from backup:
   ```
   ./restore.sh /opt/yashigani/backups/latest.tar.gz
   ```
4. `restore.sh` handles:
   - PostgreSQL database restore (`pg_restore`)
   - Docker/Podman volume restoration
   - Configuration file restoration (docker-compose.yml, Caddyfile, OPA policies)
   - Secret restoration (encrypted credentials, API keys)
   - TLS certificate restoration

   > **v2.23.1 note:** `restore.sh` widens all secret files to `u+w` before copying from the backup archive. This handles the case where backup archives contain 0400 secrets (read-only), which previously caused restore failures on Linux Podman. No operator action required; this is automatic.

#### 4.4 Post-Recovery Validation

1. Verify all services are running:
   ```
   docker compose ps
   ```
2. Check the gateway health endpoint:
   ```
   curl -k https://localhost/health
   ```
3. Verify database integrity:
   ```
   docker compose exec postgres psql -U yashigani -c "SELECT count(*) FROM audit_log;"
   ```
4. Verify authentication works (log in as admin via the API)
5. Verify OPA policies are loaded:
   ```
   curl http://localhost:8181/v1/policies
   ```
6. Check Wazuh SIEM is receiving events
7. Confirm Grafana dashboards show current metrics

#### 4.5 Credential Rotation

Because the original server may have been compromised:

1. Rotate all admin passwords via the admin API
2. Rotate the PostgreSQL database password
3. Regenerate TOTP seeds for all admin accounts
4. Rotate any API keys used by external integrations
5. If TLS private keys may have been exposed, generate new certificates
6. Update DNS records if the server IP address changed

**Expected recovery time**: 2–4 hours.

## 5. Scenario 2 — Database Corruption

**Trigger**: PostgreSQL reports data corruption, inconsistent query results, or fails to start.

### Step-by-Step Recovery

#### 5.1 Assess the Damage

1. Stop the gateway to prevent further writes:
   ```
   docker compose stop gateway
   ```
2. Check PostgreSQL logs for error details:
   ```
   docker compose logs postgres --tail=200
   ```
3. Attempt to connect and assess:
   ```
   docker compose exec postgres psql -U yashigani -c "SELECT 1;"
   ```

#### 5.2 Attempt WAL Recovery

If PostgreSQL can start but data is inconsistent:

1. Set PostgreSQL to recovery mode
2. Replay WAL logs to a consistent point:
   ```
   docker compose exec postgres pg_resetwal /var/lib/postgresql/data
   ```
3. Restart PostgreSQL and verify data consistency

#### 5.3 Restore from Backup

If WAL recovery fails:

1. Stop all services:
   ```
   docker compose down
   ```
2. Remove the corrupted database volume:
   ```
   docker volume rm yashigani_postgres_data
   ```
3. Start only the PostgreSQL container:
   ```
   docker compose up -d postgres
   ```
4. Restore from the most recent backup:
   ```
   ./restore.sh --db-only /opt/yashigani/backups/latest.tar.gz
   ```
5. Verify the restore:
   ```
   docker compose exec postgres psql -U yashigani -c "SELECT count(*) FROM audit_log;"
   docker compose exec postgres psql -U yashigani -c "SELECT max(created_at) FROM audit_log;"
   ```
6. Start remaining services:
   ```
   docker compose up -d
   ```

#### 5.4 Document Data Loss

- Record the time window of any data loss (last backup timestamp to corruption detection)
- Notify affected users if audit data was lost
- File an incident report per the Incident Response Plan

**Expected recovery time**: 30–90 minutes.

## 6. Scenario 3 — Compromised Credentials

**Trigger**: Evidence of unauthorised access, credential leak, or suspected compromise.

### Step-by-Step Recovery

#### 6.1 Immediate Containment

1. Invalidate all active sessions:
   ```
   curl -X DELETE https://localhost/admin/sessions -H "Authorization: Bearer $ADMIN_TOKEN"
   ```
2. If the compromise is severe, take the gateway offline:
   ```
   docker compose stop caddy
   ```

#### 6.2 Assess the Scope

1. Review audit logs for unauthorised activity:
   ```
   curl https://localhost/admin/audit/search?start=<timestamp> -H "Authorization: Bearer $ADMIN_TOKEN"
   ```
2. Check Wazuh SIEM for alerts during the suspected compromise window
3. Review OPA decision logs for unusual policy evaluations
4. Identify which credentials were affected:
   - Admin accounts
   - Database credentials
   - API keys
   - TLS certificates
   - TOTP seeds

#### 6.3 Credential Rotation

Rotate all potentially compromised credentials:

1. **Admin passwords**: Reset via the admin API or direct database update
2. **TOTP seeds**: Regenerate for all affected accounts
3. **Database password**: Update in docker-compose.yml and restart
4. **API keys**: Revoke and reissue via the admin API
5. **TLS certificates**: If private keys were exposed, generate new certificates and update Caddy
6. **Redis authentication**: Update the Redis password if used
7. **OPA bearer token**: Rotate if the OPA management API was exposed

#### 6.4 Harden and Verify

1. Review and tighten IP allowlists if the attack originated from an unexpected source
2. Review fail2ban logs and adjust thresholds if needed
3. Verify OPA policies have not been tampered with
4. Confirm all security controls are operational:
   ```
   curl -k https://localhost/health
   ```
5. Monitor closely for 48 hours post-recovery

#### 6.5 Post-Incident

1. Follow the Incident Response Plan for full investigation
2. Document the compromise timeline, impact, and remediation
3. If ePHI may have been accessed, follow HIPAA breach notification procedures (see Incident Response Plan)
4. Conduct a post-incident review within 5 business days

**Expected recovery time**: 1–2 hours (credential rotation); investigation timeline varies.

## 7. Annual DR Testing

A full disaster recovery test must be conducted annually to validate this plan.

### Test Procedure

1. **Preparation**: Provision a clean test environment (separate from production)
2. **Scenario execution**: Execute Scenario 1 (complete server loss) using the most recent production backup
3. **Validation**: Verify all services are operational and data is intact
4. **Timing**: Record actual recovery time against RPO/RTO targets
5. **Documentation**: Produce a DR test report including:
   - Date and participants
   - Backup used (date, size, integrity)
   - Actual recovery time
   - Issues encountered
   - Remediation actions for any gaps
   - Sign-off by the Infrastructure Lead and Security Lead

### Test Schedule

| Test Type | Frequency |
|-----------|-----------|
| Backup restore validation | Monthly |
| Database recovery (Scenario 2) | Quarterly |
| Full DR test (Scenario 1) | Annually |
| Credential rotation drill (Scenario 3) | Bi-annually |

## 8. Related Documents

- [Business Continuity Plan](business_continuity_plan.md) — overarching BCP
- [Incident Response Plan](incident_response_plan.md) — security incident handling
- [Yashigani Install Configuration](yashigani_install_config.md) — installation reference
