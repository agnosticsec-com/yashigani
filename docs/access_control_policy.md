# Access Control Policy

> Version: 1.0.0
> Date: 2026-04-12
> Last reviewed: 2026-05-05 (v2.23.2 release — no content changes; v2.23.2 changes do not touch the policy areas covered by this document)
> Compliance: ISO 27001 A.5.15–A.5.18, A.8.2–A.8.5 | HIPAA §164.312(a) | SOC 2 CC6.1–CC6.3

## 1. Purpose

This document defines the access control and identity management policies for Yashigani security gateway deployments. It covers authentication, authorisation, session management, and privileged access controls.

## 2. Principles

### 2.1 Least Privilege

All users and services are granted the minimum permissions necessary to perform their functions. Access is denied by default; explicit grants are required for each resource and action.

### 2.2 Defence in Depth

Access control is enforced at multiple layers:

1. **Network layer**: Caddy reverse proxy with IP allowlisting/blocklisting
2. **Authentication layer**: Credential verification with MFA
3. **Authorisation layer**: OPA RBAC policy evaluation for every API request
4. **Application layer**: Input validation, rate limiting, session management
5. **Data layer**: Row-level access controls, encrypted sensitive fields

### 2.3 Separation of Duties

- Administrative operations require a separate admin account (not a regular user account)
- Dual admin configuration ensures no single administrator can lock out all access
- Security-critical operations (credential rotation, policy changes) are logged immutably

## 3. Role-Based Access Control (RBAC)

### 3.1 Role Definitions

Yashigani uses OPA (Open Policy Agent) to enforce RBAC. All authorisation decisions are evaluated by OPA for every API request.

| Role | Permissions | Assignment |
|------|------------|------------|
| **admin** | Full system administration: user management, policy configuration, audit access, system settings | Assigned during installation; additional admins created by existing admins |
| **user** | Use the gateway for MCP interactions, manage own profile, view own audit history | Created by admin; self-registration if enabled |
| **readonly** | View-only access to dashboards and reports; no write operations | Assigned by admin for auditors and observers |
| **service** | Machine-to-machine API access with scoped permissions | Created by admin with specific API key scopes |

### 3.2 OPA Policy Enforcement

- Every API request is evaluated against OPA policies before execution
- Policies are version-controlled in the `policy/` directory
- Policy changes require code review and are deployed via the standard change management process
- OPA decision logs capture every authorisation decision for audit

### 3.3 Default Deny

If OPA is unreachable or returns an error, the gateway defaults to denying the request. This fail-closed behaviour prevents authorisation bypass during policy engine failures.

## 4. Admin Account Management

### 4.1 Dual Admin Requirement

Yashigani requires a minimum of two administrator accounts at all times. This prevents:

- Single point of failure if one admin account is compromised or locked
- Single admin self-elevation attacks
- Recovery lockouts

### 4.2 Admin Account Creation

1. Initial admin account is created during `install.sh`
2. A second admin account must be created immediately after installation
3. Additional admin accounts are created via `POST /admin/users` with the `admin` role
4. Admin creation is logged in the audit trail with the creating admin's identity

### 4.3 Admin Account Security

| Control | Requirement |
|---------|-------------|
| **MFA** | TOTP mandatory for all admin accounts (SHA-256, 6-digit, 30-second step) |
| **Password** | Must meet the password policy (Section 6) |
| **Session timeout** | 4-hour absolute timeout (not configurable for admin accounts) |
| **IP restriction** | Optional admin-only IP allowlist |
| **Brute-force protection** | Account lockout after configurable failed attempts (fail2ban escalation) |

## 5. User Provisioning and Deprovisioning

### 5.1 Provisioning

1. Admin creates the user account via `POST /admin/users`
2. User receives a temporary password (via secure channel, out-of-band)
3. User must change password on first login
4. User must enrol TOTP MFA on first login
5. OPA role is assigned at creation time

### 5.2 Modification

- Role changes are made by admin via `PATCH /admin/users/{id}`
- All role changes are logged in the audit trail
- Role elevation (e.g., user to admin) requires a second admin's confirmation

### 5.3 Deprovisioning

When a user is deprovisioned:

1. Account is locked immediately via `PATCH /admin/users/{id}` with `locked: true`
2. All active sessions are invalidated in Redis
3. Active Podman agent containers for the user are stopped and removed
4. API keys are revoked
5. Account may be deleted after audit export (per the Data Handling Procedures)

Deprovisioning must occur within the same business day for terminated employees.

## 6. Password Policy

Yashigani enforces a configurable password policy:

| Parameter | Default | Configurable |
|-----------|---------|-------------|
| **Minimum length** | 12 characters | Yes (minimum 8) |
| **Maximum age** | 13 months (395 days) | Yes |
| **Complexity** | At least 3 of: uppercase, lowercase, digit, special character | Yes |
| **History** | Last 12 passwords cannot be reused | Yes |
| **Breach check** | Checked against HIBP (Have I Been Pwned) Pwned Passwords API | Yes (can be disabled for air-gapped deployments) |
| **Lockout threshold** | 5 failed attempts | Yes |
| **Lockout duration** | Escalating via fail2ban (see Section 9) | Yes |

### 6.1 Password Storage

- Passwords are hashed using bcrypt with a cost factor of 12
- Raw passwords are never stored or logged
- Password changes invalidate all existing sessions

## 7. Multi-Factor Authentication (MFA)

### 7.1 TOTP Configuration

| Parameter | Value |
|-----------|-------|
| **Algorithm** | SHA-256 |
| **Digits** | 6 |
| **Period** | 30 seconds |
| **Skew** | 1 step (allows previous and next code) |
| **Backup codes** | 10 single-use recovery codes generated at enrolment |

### 7.2 MFA Requirements

| Account Type | MFA Required |
|-------------|-------------|
| Admin accounts | Mandatory (cannot be disabled) |
| User accounts | Mandatory by default (admin can configure) |
| Service accounts (API keys) | Not applicable (key-based authentication) |

### 7.3 MFA Recovery

If a user loses their TOTP device:

1. Use a backup recovery code to log in
2. Re-enrol TOTP with a new device
3. If no recovery codes remain, an admin must reset the user's MFA enrolment

## 8. Session Management

| Parameter | Value |
|-----------|-------|
| **Session backend** | Redis |
| **Absolute timeout** | 4 hours |
| **Idle timeout** | 30 minutes (configurable) |
| **Concurrent sessions** | Configurable per user (default: 3) |
| **Session invalidation on password change** | Yes (all sessions) |
| **Session invalidation on role change** | Yes (all sessions) |
| **Session token format** | Cryptographically random, 256-bit |
| **Cookie attributes** | `Secure`, `HttpOnly`, `SameSite=Strict` |

### 8.1 Session Monitoring

- Active sessions are visible to admins via `GET /admin/sessions`
- Users can view and revoke their own sessions via `GET /api/sessions`
- Bulk session invalidation: `DELETE /admin/sessions` (all users) or `DELETE /admin/sessions?user_id={id}` (specific user)

## 9. Authentication Throttling

Yashigani uses fail2ban with escalating penalties:

| Failed Attempts | Action | Duration |
|----------------|--------|----------|
| 5 | Account locked | 5 minutes |
| 10 | Account locked + IP banned | 15 minutes |
| 20 | Account locked + IP banned | 1 hour |
| 50 | Account locked + IP banned + admin notified | 24 hours |

### 9.1 IP-Based Controls

| Control | Description |
|---------|-------------|
| **IP allowlist** | Restrict access to specific IP ranges (CIDR notation) |
| **IP blocklist** | Permanently block known malicious IPs |
| **Geo-blocking** | Optional country-level restrictions |
| **Rate limiting** | Per-IP request rate limits enforced at the Caddy layer |

Allowlist and blocklist are managed via the admin API and enforced at the Caddy reverse proxy layer.

## 10. Privileged Access Review

A quarterly review of privileged access must be conducted:

### 10.1 Review Scope

- All admin accounts: verify each is still required and assigned to a current employee
- All service accounts: verify each is still in use and scoped appropriately
- Role assignments: verify no users have excessive permissions
- IP allowlists/blocklists: verify entries are current
- OPA policies: verify no unauthorised policy changes

### 10.2 Review Process

1. Generate the access report: `GET /admin/users?role=admin` and `GET /admin/users`
2. Cross-reference with current employee/contractor list
3. Revoke access for any accounts that are no longer required
4. Document the review findings and any changes made
5. Sign-off by the Security Lead

### 10.3 Review Schedule

| Review | Frequency |
|--------|-----------|
| Admin account audit | Quarterly |
| Service account audit | Quarterly |
| Full access review (all users) | Bi-annually |
| OPA policy review | Every release + quarterly |

## 11. Related Documents

- [Data Handling Procedures](data_handling_procedures.md) — data classification and protection
- [Change Management](change_management.md) — policy change process
- [Incident Response Plan](incident_response_plan.md) — compromised credential response
- [SECURITY.md](../SECURITY.md) — vulnerability reporting
