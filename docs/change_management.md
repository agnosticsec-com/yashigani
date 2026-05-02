# Change Management

> Version: 1.0.0
> Date: 2026-04-12
> Compliance: SOC 2 CC8.1 | ISO 27001 A.8.32

## 1. Purpose

This document defines the change management process for the Yashigani security gateway. All changes to the codebase, configuration, infrastructure, and policies follow this process to ensure traceability, quality, and security.

## 2. Scope

This process applies to:

- Application source code (Python gateway, OPA policies, API endpoints)
- Infrastructure configuration (Docker Compose, Caddyfile, Dockerfiles)
- Database schema changes (migrations)
- Dependency updates (Python packages, container images, JavaScript libraries)
- OPA policy changes (authorisation rules, PII handling, rate limits)
- Documentation updates
- Operational scripts (install.sh, backup.sh, restore.sh)

## 3. Change Classification

| Type | Description | Approval | Testing |
|------|-------------|----------|---------|
| **Standard** | Planned feature, enhancement, or scheduled maintenance | Pre-push review | Full test suite + e2e |
| **Normal** | Bug fix, dependency update, configuration change | Pre-push review | Full test suite |
| **Emergency** | Critical security patch or production outage fix | Post-deployment review | Targeted tests + regression |

## 4. Change Process

### 4.1 Version Control

All changes are made via Git:

- The `main` branch is the single source of truth
- All changes are committed with descriptive commit messages
- Every release is tagged with a semantic version number (e.g., `v2.23.0`)
- No direct pushes to `main` without review (see Section 4.3)

### 4.2 Pre-Commit Controls

Before a commit is accepted, the following automated checks run:

| Check | Tool | Scope |
|-------|------|-------|
| OWASP pre-release compliance | Manual review | OWASP ASVS v5, API Security, and Agentic AI controls reviewed against current code |
| Static analysis | Ruff, mypy | Code quality, type safety |
| Secret scanning | Gitleaks | Prevent credential commits |
| Licence compliance | pip-licences | Dependency licence verification |

### 4.3 Pre-Push Review

Before pushing to the remote repository, changes are reviewed by three automated review agents:

| Agent | Role | Focus |
|-------|------|-------|
| **Tom** | Security reviewer | Vulnerabilities, authentication, encryption, injection, OPA policy integrity |
| **Su** | Code quality reviewer | Architecture, maintainability, test coverage, performance |
| **Captain** | Integration reviewer | Cross-service compatibility, Docker configuration, upgrade path, data migration |

All three agents must approve before the push proceeds.

### 4.4 Continuous Integration

After push, the CI pipeline executes:

| Stage | Tests | Pass Criteria |
|-------|-------|---------------|
| Unit tests | 523 tests | 100% pass |
| End-to-end tests | 25 tests | 100% pass |
| Compliance review | Manual OWASP review | No regressions in PASS verdicts vs prior release |
| Container build | Docker build | Successful build, no vulnerabilities above configured threshold |
| SBOM generation | CycloneDX | SBOM produced and archived with the build |

### 4.5 Release Process

1. All CI checks pass
2. Version number incremented following semantic versioning:
   - **Major**: Breaking changes to the API or configuration format
   - **Minor**: New features, non-breaking enhancements
   - **Patch**: Bug fixes, security patches, dependency updates
3. Release tagged in Git (e.g., `v2.23.1`)
4. Release notes document all changes, security fixes, and upgrade instructions
5. Updated documentation committed (README, /docs/, compliance reports)
6. Clean slate test: nuke existing installation, fresh clone, run `install.sh`, verify functionality

## 5. Upgrade Path

### 5.1 Standard Upgrade

Customers upgrade using:

```
./install.sh --upgrade
```

This process:

1. Creates a backup via `backup.sh` (automatic, pre-upgrade)
2. Pulls the latest version from the repository
3. Runs database migrations
4. Rebuilds containers with updated images
5. Restarts services with zero-downtime rolling restart (where possible)
6. Verifies health of all services
7. Reports upgrade success/failure

### 5.2 Configuration Migration

When configuration formats change between versions:

1. The installer detects the existing configuration version
2. Automatic migration transforms the configuration to the new format
3. The original configuration is backed up
4. The administrator is notified of any manual changes required

## 6. Rollback

### 6.1 Standard Rollback

If an upgrade causes issues:

```
./restore.sh /opt/yashigani/backups/<pre-upgrade-backup>.tar.gz
```

This restores:

- The previous application version
- The previous database state
- The previous configuration
- The previous OPA policies

### 6.2 Rollback Policy

- Pre-upgrade backups are retained for a minimum of 30 days
- Rollback must be tested as part of the release process for major version upgrades
- Rollback procedures are documented in the release notes for each version

## 7. Emergency Changes

Emergency changes bypass the standard review process but require compensating controls:

### 7.1 Criteria for Emergency Change

An emergency change is permitted only when:

- A critical security vulnerability is actively being exploited (P1)
- A production outage is affecting all users
- A regulatory deadline requires immediate action

### 7.2 Emergency Change Process

1. **Authorisation**: Verbal or written approval from the Incident Commander or Security Lead
2. **Implementation**: Apply the fix with targeted testing
3. **Documentation**: Create the commit with `[EMERGENCY]` prefix in the commit message
4. **Post-deployment review**: Within 2 business days, conduct a full review including:
   - Tom/Su/Captain agent review of the changes
   - Full test suite execution
   - Compliance scan
   - Documentation update
5. **Follow-up**: If the emergency fix is suboptimal, schedule a proper fix as a standard change

### 7.3 Emergency Change Register

All emergency changes are recorded with:

- Date and time
- Authorising person
- Justification
- Changes made
- Post-deployment review date and findings

## 8. Change Audit Trail

All changes are traceable through:

| Record | Source | Retention |
|--------|--------|-----------|
| Git commit history | Git repository | Permanent |
| CI/CD build logs | CI platform | 12 months |
| Pre-push review results | Review agent logs | 12 months |
| OWASP review records | Per-release docs | 12 months |
| Release notes | Repository (docs/) | Permanent |
| Emergency change register | Internal documentation | 6 years |

## 9. Related Documents

- [Access Control Policy](access_control_policy.md) — who can make changes
- [Supplier Security](supplier_security.md) — dependency update process
- [Risk Management Framework](risk_management_framework.md) — risk assessment for changes
- [Business Continuity Plan](business_continuity_plan.md) — backup and recovery
