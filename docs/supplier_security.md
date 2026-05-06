# Supplier Security

> Version: 1.0.0
> Date: 2026-04-12
> Last reviewed: 2026-05-05 (v2.23.2 release — supplier inventory in §4.2 unchanged; no new suppliers introduced; image-version bumps tracked in CHANGELOG, not this document)
> Compliance: ISO 27001 A.5.19–A.5.22

## 1. Purpose

This document defines the processes for managing information security risks associated with third-party suppliers, components, and services used in or alongside Yashigani. It covers supplier assessment, supply chain security, ongoing monitoring, and incident handling.

## 2. Scope

This policy applies to:

- **Software dependencies**: Python packages, container base images, JavaScript libraries
- **Infrastructure components**: PostgreSQL, Redis, OPA, Caddy, Wazuh, Grafana, Prometheus, Podman
- **Container images**: All Docker/Podman images used in the Yashigani stack
- **Service providers**: Cloud hosting, DNS, certificate authorities (when used by customers)
- **Development tools**: CI/CD tools, code analysis tools, build systems

## 3. Supplier Assessment Criteria

Before adopting a new third-party component or service, the following criteria must be evaluated:

### 3.1 Security Assessment

| Criterion | Requirement |
|-----------|-------------|
| **Vulnerability history** | Review CVE history for severity and response times |
| **Security practices** | Evidence of secure development lifecycle (SDLC) |
| **Disclosure policy** | Published vulnerability disclosure process |
| **Patch cadence** | Regular security updates with documented changelog |
| **Authentication** | Supports modern authentication methods (no default credentials) |
| **Encryption** | Supports TLS 1.2+ for communications, AES-256 for data at rest |
| **Licence** | Compatible with Yashigani's licensing (no copyleft contamination of proprietary code) |

### 3.2 Risk Classification

| Risk Level | Criteria | Review Frequency |
|------------|----------|-----------------|
| **Critical** | Component handles authentication, encryption, or ePHI | Every release + quarterly |
| **High** | Component has network exposure or processes user data | Every release + bi-annually |
| **Medium** | Component is in the runtime but handles no sensitive data | Every release + annually |
| **Low** | Development-only dependency (test, lint, build tools) | Annually |

### 3.3 Approval Process

1. Engineer proposes the new dependency with a justification
2. Security review against the criteria in Section 3.1
3. Licence compatibility check
4. Risk classification assigned
5. Approval or rejection documented
6. If approved, added to the component inventory (Section 4)

## 4. Component Inventory

### 4.1 Software Bill of Materials (SBOM)

Yashigani generates an SBOM for each release using standard tooling:

- **Python dependencies**: Pinned in `requirements.txt` with hashes, SBOM generated via `pip-audit` and `cyclonedx-py`
- **Container images**: Base image versions pinned in Dockerfiles, scanned with `trivy`
- **JavaScript dependencies** (Open WebUI): Lockfile-pinned, scanned with `npm audit`
- **System packages**: Documented in Dockerfile build stages

The SBOM is produced in CycloneDX format and included with each release.

### 4.2 Core Component Inventory

| Component | Role | Risk Level | Licence |
|-----------|------|-----------|---------|
| Python (CPython) | Runtime | Critical | PSF |
| FastAPI | Web framework | Critical | MIT |
| PostgreSQL | Database | Critical | PostgreSQL Licence |
| Redis | Session store, rate limiting | High | BSD-3-Clause |
| OPA (Open Policy Agent) | Policy engine | Critical | Apache-2.0 |
| Caddy | Reverse proxy, TLS termination | Critical | Apache-2.0 |
| Wazuh | SIEM | High | GPL-2.0 (standalone component) |
| Grafana | Observability dashboard | Medium | AGPL-3.0 (standalone component) |
| Prometheus | Metrics collection | Medium | Apache-2.0 |
| Podman | Container isolation | High | Apache-2.0 |
| Open WebUI | User interface (optional) | High | MIT |

### 4.3 Lockfile Policy

All dependency manifests must use lockfiles with pinned versions:

- `requirements.txt` with `--hash` verification
- `package-lock.json` for JavaScript dependencies
- Dockerfile `FROM` directives use specific image digests (not `latest`)

## 5. Licence Compliance

### 5.1 Permitted Licences

| Category | Licences |
|----------|----------|
| **Permissive (preferred)** | MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0, ISC, PSF, PostgreSQL |
| **Weak copyleft (case-by-case)** | LGPL-2.1, LGPL-3.0, MPL-2.0 |
| **Strong copyleft (standalone only)** | GPL-2.0, GPL-3.0, AGPL-3.0 — only for components that run as separate processes (e.g., Wazuh, Grafana) |
| **Prohibited** | SSPL, Commons Clause, any licence with field-of-use restrictions |

### 5.2 Licence Review Process

1. Automated licence scanning during CI (every build)
2. Manual review for any new dependency or licence change
3. Legal consultation for weak or strong copyleft licences
4. Licence inventory maintained as part of the SBOM

## 6. Vulnerability Monitoring

### 6.1 Automated Scanning

| Scanner | Target | Frequency |
|---------|--------|-----------|
| `pip-audit` | Python dependencies | Every build + daily |
| `trivy` | Container images | Every build + daily |
| `npm audit` | JavaScript dependencies | Every build + daily |
| GitHub Dependabot / Advisory DB | All dependencies | Continuous |
| Wazuh vulnerability detector | Runtime packages | Continuous |

### 6.2 CVE Response Process

| Severity | Response Time | Action |
|----------|--------------|--------|
| **Critical** (CVSS 9.0+) | 24 hours | Immediate patch or mitigation. If no patch available, assess whether the component can be disabled or isolated. |
| **High** (CVSS 7.0–8.9) | 7 days | Patch in next release. Apply workaround if available. |
| **Medium** (CVSS 4.0–6.9) | 30 days | Patch in next scheduled release. |
| **Low** (CVSS 0.1–3.9) | 90 days | Patch when convenient. |

### 6.3 Dependency Update Process

1. Automated alerts trigger a review
2. Security impact assessment (does the CVE affect Yashigani's usage of the component?)
3. Update the dependency in the lockfile
4. Run the full test suite (523 unit tests + 25 e2e tests)
5. Pre-push review by Tom/Su/Captain agents
6. Release with updated SBOM

## 7. Supplier Incident Notification

### 7.1 Monitoring Channels

- GitHub Security Advisories for all direct dependencies
- Mailing lists for critical infrastructure (PostgreSQL, Redis, OPA, Caddy)
- NVD/CVE feeds via Wazuh vulnerability detector
- Vendor security pages and RSS feeds

### 7.2 Incident Response

When a supplier reports a security incident affecting a component used by Yashigani:

1. **Assess impact**: Determine whether the vulnerability is exploitable in Yashigani's deployment configuration
2. **Notify customers**: If affected, issue a security advisory with mitigation guidance
3. **Patch**: Apply the supplier's fix or implement a workaround
4. **Verify**: Run the full test suite and compliance checks
5. **Release**: Issue a patched version following the standard release process
6. **Document**: Record the incident in the supplier risk register

## 8. Annual Supplier Review

An annual review of all suppliers and components is conducted covering:

| Review Item | Description |
|-------------|-------------|
| **Component inventory** | Verify SBOM is accurate and complete |
| **Vulnerability history** | Review CVEs for each critical/high component over the past year |
| **Licence changes** | Check for licence changes in dependencies |
| **Patch compliance** | Verify all known CVEs have been addressed within SLA |
| **Supplier viability** | Assess ongoing maintenance and community health of open-source components |
| **Alternative assessment** | Identify alternatives for components with declining maintenance |

### Review Output

The annual review produces:

- Updated component inventory with risk classifications
- Risk register updates for any new or changed risks
- Action items for components requiring attention
- Sign-off by the Security Lead

## 9. Supplier Agreements

For commercial suppliers and service providers, agreements must include:

| Clause | Requirement |
|--------|-------------|
| **Data handling** | Specify how the supplier handles any data they access |
| **Breach notification** | Supplier must notify within 72 hours of discovering a breach |
| **Compliance** | Supplier must maintain compliance with applicable regulations |
| **Audit rights** | Right to audit or request evidence of security controls |
| **Termination** | Data return/deletion obligations upon contract termination |
| **Subprocessors** | Notification of any subprocessor changes |

## 10. Related Documents

- [Data Handling Procedures](data_handling_procedures.md) — data classification and protection
- [Change Management](change_management.md) — dependency update process
- [Risk Management Framework](risk_management_framework.md) — risk assessment methodology
- [SECURITY.md](../SECURITY.md) — vulnerability reporting
