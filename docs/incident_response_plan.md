# Incident Response Plan

> Version: 1.0.0
> Date: 2026-04-12
> Last reviewed: 2026-05-05 (v2.23.2 release — no content changes; v2.23.2 changes do not touch the policy areas covered by this document)
> Compliance: ISO 27001 A.5.24–A.5.28 | HIPAA §164.308(a)(6)

## 1. Purpose

This document defines the security incident response process for Yashigani security gateway deployments. It covers detection, triage, containment, eradication, recovery, and post-incident review.

## 2. Scope

This plan applies to all security incidents affecting Yashigani deployments, including but not limited to:

- Unauthorised access to the gateway, database, or administrative interfaces
- Credential compromise or leakage
- Data breaches involving audit logs, user data, or ePHI
- Denial-of-service attacks
- Malware or supply chain compromise
- OPA policy bypass or tampering
- Exploitation of vulnerabilities in Yashigani or its dependencies

## 3. Severity Classification

Incidents are classified using a P1–P5 severity scale, consistent with the Yashigani alert system:

| Severity | Description | Examples | Response Time |
|----------|-------------|----------|---------------|
| **P1 — Critical** | Active data breach or complete system compromise | ePHI exfiltration, admin account takeover, ransomware | Immediate (within 15 minutes) |
| **P2 — High** | Confirmed unauthorised access or security control failure | Successful authentication bypass, OPA policy circumvented, TLS downgrade | Within 1 hour |
| **P3 — Medium** | Attempted attack with partial success or degraded security | Brute-force attack causing lockouts, suspicious admin API usage, certificate expiry | Within 4 hours |
| **P4 — Low** | Security anomaly requiring investigation | Unusual login patterns, failed authentication spikes, unexpected OPA denials | Within 24 hours |
| **P5 — Informational** | Security event logged for awareness | Routine vulnerability scan detected, policy update applied, password rotation | Next business day |

## 4. Roles and Responsibilities

| Role | Responsibility |
|------|---------------|
| **Incident Commander** | Owns the incident lifecycle, makes escalation decisions, coordinates communication |
| **Security Analyst** | Performs technical investigation, collects evidence, executes containment |
| **Infrastructure Lead** | Executes recovery procedures, validates system integrity |
| **Communications Lead** | Manages internal and external notifications, regulatory reporting |
| **Executive Sponsor** | Approves public communications, authorises resource allocation for P1/P2 incidents |

## 5. Detection

Yashigani provides multiple detection mechanisms:

### 5.1 Automated Detection

| Source | What It Detects | Alert Channel |
|--------|----------------|---------------|
| **Wazuh SIEM** | Intrusion attempts, file integrity changes, log anomalies, CVE matches | Wazuh dashboard + configured alert channels |
| **OPA decision logs** | Policy denials, unusual access patterns, authorisation failures | Audit log + Grafana dashboard |
| **Fail2ban** | Brute-force attacks, repeated authentication failures | System log + ban notifications |
| **Audit log** | All API calls, authentication events, admin actions, data access | PostgreSQL audit_log table + `/admin/audit/search` |
| **Prometheus/Grafana** | Performance anomalies, resource exhaustion, service health | Grafana alerts |
| **Container monitoring** | Podman container escapes, resource abuse, unexpected processes | Wazuh agent + system metrics |

### 5.2 Manual Detection

- User reports of suspicious activity
- External vulnerability disclosures (via security@agnosticsec.com)
- Third-party security assessments
- Routine security reviews

## 6. Incident Response Phases

### 6.1 Phase 1 — Triage

**Objective**: Confirm the incident and classify severity.

1. **Receive alert**: Note the detection source, timestamp, and initial indicators
2. **Verify**: Confirm the alert is a true positive (not a false alarm or test)
3. **Classify**: Assign a severity level (P1–P5) based on the classification table
4. **Assign**: Designate an Incident Commander and notify the response team
5. **Document**: Create an incident record with:
   - Incident ID (format: `INC-YYYY-MM-DD-NNN`)
   - Detection time
   - Initial classification
   - Assigned responders

### 6.2 Phase 2 — Containment

**Objective**: Limit the impact and prevent escalation.

#### Immediate Containment (P1/P2)

| Action | Command / Procedure |
|--------|-------------------|
| Invalidate all sessions | `DELETE /admin/sessions` |
| Block attacker IP | Add to IP blocklist via admin API or `fail2ban-client set yashigani banip <IP>` |
| Take gateway offline (if needed) | `docker compose stop caddy` |
| Isolate compromised containers | `docker compose stop <service>` |
| Preserve evidence | Copy logs, database snapshots, and container state before any changes |

#### Standard Containment (P3/P4)

| Action | Command / Procedure |
|--------|-------------------|
| Lock affected user accounts | `PATCH /admin/users/{id}` with `locked: true` |
| Rotate affected credentials | Per the credential rotation procedure in the Disaster Recovery Plan |
| Increase monitoring | Enable verbose logging, tighten alert thresholds |

### 6.3 Phase 3 — Eradication

**Objective**: Remove the threat and its root cause.

1. **Identify root cause**: Analyse audit logs, Wazuh alerts, OPA decision logs, and system logs
2. **Remove threat**:
   - Revoke compromised credentials
   - Remove malicious OPA policies or configurations
   - Patch exploited vulnerabilities
   - Remove any backdoors or unauthorised accounts
3. **Verify eradication**:
   - Scan all containers for anomalies
   - Verify OPA policy integrity against the version-controlled source
   - Confirm no unauthorised database modifications
4. **Apply fixes**:
   - Deploy patched version via `install.sh --upgrade`
   - Update OPA policies if bypass was identified
   - Tighten access controls as needed

### 6.4 Phase 4 — Recovery

**Objective**: Restore normal operations with full security controls.

1. **Restore services**: Follow the Disaster Recovery Plan as appropriate
2. **Verify security controls**:
   - All OPA policies loaded and enforcing
   - TLS 1.3 operational on all endpoints
   - Authentication and MFA working
   - Audit logging capturing all events
   - Wazuh SIEM connected and monitoring
   - Fail2ban active with correct rules
3. **Credential rotation**: Rotate all credentials that may have been exposed
4. **Monitoring period**: Maintain heightened monitoring for a minimum of 48 hours
5. **Declare recovery**: Incident Commander confirms all services are operational and secure

### 6.5 Phase 5 — Post-Incident Review

**Objective**: Learn from the incident and improve defences.

1. **Timeline**: Conduct a post-incident review within 5 business days of recovery
2. **Participants**: All incident responders, relevant engineers, and management
3. **Report contents**:
   - Incident timeline (detection to recovery)
   - Root cause analysis
   - Impact assessment (data affected, users affected, duration)
   - What worked well
   - What needs improvement
   - Action items with owners and deadlines
4. **Action tracking**: All remediation actions are tracked to completion
5. **Knowledge base**: Update detection rules, runbooks, and this plan based on lessons learned

## 7. Evidence Collection

For all P1–P3 incidents, the following evidence must be preserved:

| Evidence Type | Collection Method | Retention |
|---------------|------------------|-----------|
| Audit logs | `GET /admin/audit/export?start=<timestamp>&end=<timestamp>` | Minimum 6 years (HIPAA) |
| Wazuh alerts | Export from Wazuh dashboard or API | Minimum 6 years |
| OPA decision logs | Export from the OPA API | Minimum 6 years |
| System logs | `journalctl` + Docker container logs | Minimum 6 years |
| Database snapshots | `pg_dump` at time of detection | Until investigation complete |
| Network captures | `tcpdump` if authorised and available | Until investigation complete |
| Container state | `docker inspect` + filesystem snapshots | Until investigation complete |

Evidence must be:
- Timestamped and integrity-protected (SHA-256 hash)
- Stored in a location inaccessible to the attacker
- Handled with a documented chain of custody for legal proceedings

## 8. Communication Plan

### 8.1 Internal Communication

| Severity | Notify | Timeline |
|----------|--------|----------|
| P1 | Incident Commander + full response team + Executive Sponsor | Immediate |
| P2 | Incident Commander + Security Analyst + Infrastructure Lead | Within 1 hour |
| P3 | Security Analyst + Infrastructure Lead | Within 4 hours |
| P4 | Security Analyst | Within 24 hours |
| P5 | Logged for review | Next business day |

### 8.2 External Communication

| Trigger | Recipient | Timeline | Method |
|---------|-----------|----------|--------|
| Confirmed data breach | Affected users | Without unreasonable delay | Direct notification |
| ePHI breach (>500 individuals) | HHS Secretary | Within 60 days of discovery | HHS breach reporting portal |
| ePHI breach (<500 individuals) | HHS Secretary | Annual log submission | HHS breach reporting portal |
| ePHI breach | Prominent media outlets (if >500 in a state/jurisdiction) | Within 60 days | Press release / notification |
| Significant vulnerability | Yashigani users | Within 7 days of patch availability | Security advisory |
| Law enforcement relevant | Appropriate authorities | As required by law | Formal referral |

### 8.3 HIPAA Breach Notification Requirements

Under HIPAA §164.404–164.408:

- **Individual notification**: Written notice to each affected individual within 60 days of discovering a breach of unsecured ePHI
- **HHS notification**: Report to the Secretary of Health and Human Services
  - Breaches affecting 500+ individuals: within 60 days
  - Breaches affecting fewer than 500 individuals: annually
- **Media notification**: For breaches affecting 500+ individuals in a single state or jurisdiction, notify prominent media outlets within 60 days
- **Content of notification**: Must include a description of the breach, types of information involved, steps individuals should take, what the organisation is doing, and contact information
- **Documentation**: Maintain records of all breach notifications for a minimum of 6 years

## 9. Contact Information

| Contact | Email | Use |
|---------|-------|-----|
| Security team | security@agnosticsec.com | Incident reporting, vulnerability disclosures |
| Privacy team | privacy@agnosticsec.com | Data breach impact, privacy concerns |
| Conduct team | conduct@agnosticsec.com | Policy violations, code of conduct issues |

## 10. Related Documents

- [Business Continuity Plan](business_continuity_plan.md) — recovery objectives and strategy
- [Disaster Recovery Plan](disaster_recovery.md) — step-by-step recovery procedures
- [Data Handling Procedures](data_handling_procedures.md) — data classification and protection
- [SECURITY.md](../SECURITY.md) — vulnerability reporting
