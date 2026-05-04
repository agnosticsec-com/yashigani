# Risk Management Framework

> Version: 1.0.0
> Date: 2026-04-12
> Compliance: ISO 27001 A.5.7–A.5.8

## 1. Purpose

This document defines the risk management approach for the Yashigani security gateway. It establishes the methodology for identifying, assessing, treating, and monitoring information security risks throughout the product lifecycle.

## 2. Scope

This framework applies to all risks associated with:

- The Yashigani codebase and its dependencies
- Customer deployment environments
- Data processed by the gateway (MCP traffic, audit logs, credentials)
- Third-party components and suppliers
- Operational processes (development, testing, deployment, support)

## 3. Risk Assessment Methodology

### 3.1 Risk Matrix (5x5)

Risks are assessed on two dimensions — **Probability** and **Impact** — each scored from 1 to 5.

#### Probability Scale

| Score | Level | Description |
|-------|-------|-------------|
| 1 | Rare | May occur only in exceptional circumstances (<5% chance per year) |
| 2 | Unlikely | Could occur but not expected (5–20% chance per year) |
| 3 | Possible | Might occur at some time (20–50% chance per year) |
| 4 | Likely | Will probably occur in most circumstances (50–80% chance per year) |
| 5 | Almost Certain | Expected to occur in most circumstances (>80% chance per year) |

#### Impact Scale

| Score | Level | Description |
|-------|-------|-------------|
| 1 | Negligible | Minor inconvenience, no data impact, no regulatory consequence |
| 2 | Minor | Limited data exposure (<10 records), minor service disruption (<1 hour), no regulatory notification required |
| 3 | Moderate | Significant data exposure (10–500 records), service disruption (1–4 hours), potential regulatory enquiry |
| 4 | Major | Large data breach (500–10,000 records), extended outage (4–24 hours), regulatory notification required, financial penalty |
| 5 | Critical | Massive data breach (>10,000 records), complete system compromise, regulatory enforcement action, reputational damage |

#### Risk Rating Matrix

|  | Impact 1 | Impact 2 | Impact 3 | Impact 4 | Impact 5 |
|--|----------|----------|----------|----------|----------|
| **Prob 5** | 5 (Medium) | 10 (High) | 15 (Extreme) | 20 (Extreme) | 25 (Extreme) |
| **Prob 4** | 4 (Low) | 8 (Medium) | 12 (High) | 16 (Extreme) | 20 (Extreme) |
| **Prob 3** | 3 (Low) | 6 (Medium) | 9 (High) | 12 (High) | 15 (Extreme) |
| **Prob 2** | 2 (Low) | 4 (Low) | 6 (Medium) | 8 (Medium) | 10 (High) |
| **Prob 1** | 1 (Low) | 2 (Low) | 3 (Low) | 4 (Low) | 5 (Medium) |

#### Risk Response by Rating

| Rating | Range | Required Response |
|--------|-------|-------------------|
| **Extreme** | 15–25 | Immediate action required. Risk must be treated before release. CEO sign-off on any residual risk. |
| **High** | 9–14 | Treatment plan required within 30 days. Security Lead approval for any residual risk. |
| **Medium** | 5–8 | Treatment plan required within 90 days. Documented in risk register. |
| **Low** | 1–4 | Accept and monitor. Document in risk register. Review at next scheduled assessment. |

## 4. Risk Assessment Process

### 4.1 When to Assess

Risk assessments are conducted:

| Trigger | Scope |
|---------|-------|
| **Every release** | New features, changed functionality, updated dependencies |
| **New feature design** | Before implementation begins |
| **Security incident** | Root cause and related risks |
| **Dependency CVE** | Affected components and exposure |
| **Architecture change** | All affected components and data flows |
| **Annual review** | Full risk register review |

### 4.2 Assessment Steps

1. **Identify**: Enumerate threats and vulnerabilities
   - Review OWASP Agentic AI top 10 for MCP-specific risks
   - Review OWASP API Security top 10 for API risks
   - Review OWASP ASVS v5 for application security risks
   - Analyse threat intelligence (Wazuh feeds, CVE databases, security advisories)
   - Consider insider threats, supply chain risks, and operational risks

2. **Analyse**: For each identified risk:
   - Determine probability (1–5)
   - Determine impact (1–5)
   - Calculate risk rating (probability x impact)
   - Identify existing controls that mitigate the risk

3. **Evaluate**: Compare risk rating against acceptance criteria
   - Risks rated Extreme or High require treatment
   - Risks rated Medium are reviewed for cost-effective treatment
   - Risks rated Low are accepted and monitored

4. **Document**: Record in the risk register (see Section 5)

## 5. Risk Register

The risk register is maintained internally (not in the public repository) and contains:

| Field | Description |
|-------|-------------|
| **Risk ID** | Unique identifier (format: `RISK-YYYY-NNN`) |
| **Title** | Short description of the risk |
| **Category** | Technical, operational, compliance, supply chain, or personnel |
| **Threat** | What could go wrong |
| **Vulnerability** | What weakness could be exploited |
| **Existing controls** | Current mitigations in place |
| **Probability** | Score (1–5) with justification |
| **Impact** | Score (1–5) with justification |
| **Risk rating** | Calculated score and category |
| **Treatment** | Accept, mitigate, transfer, or avoid |
| **Treatment plan** | Specific actions to reduce the risk |
| **Owner** | Person responsible for the risk and its treatment |
| **Status** | Open, in treatment, accepted, closed |
| **Review date** | Next scheduled review |

The risk register is referenced in `Internal/Risk Management/` and is accessible to the Security Lead and CEO.

## 6. Risk Treatment

### 6.1 Treatment Options

| Option | Description | When to Use |
|--------|-------------|-------------|
| **Mitigate** | Implement controls to reduce probability or impact | Most common; cost of mitigation is proportionate to the risk |
| **Accept** | Acknowledge the risk and monitor | Risk is Low or the cost of treatment exceeds the potential impact |
| **Transfer** | Shift risk to a third party (insurance, contractual) | Financial risks, risks outside direct control |
| **Avoid** | Eliminate the risk by removing the feature or component | Risk is Extreme and cannot be adequately mitigated |

### 6.2 Mitigation Examples (Yashigani-Specific)

| Risk | Mitigation | Controls |
|------|-----------|----------|
| MCP tool injection | Input sanitisation + OPA policy validation | OPA Rego rules, request schema validation |
| Authentication bypass | Multi-layer auth + fail2ban + TOTP MFA | Caddy forward auth, session management, brute-force protection |
| Supply chain compromise | Pinned dependencies + SBOM + automated scanning | pip-audit, trivy, lockfile hashes |
| Data breach via audit logs | Encryption at rest + access control + PII redaction | pgcrypto AES-256-GCM, OPA RBAC, PII handling modes |
| Container escape | Podman rootless + seccomp + capability dropping | Per-user container isolation, minimal container images |
| Credential stuffing | HIBP breach check + rate limiting + MFA | Password policy, fail2ban escalation, mandatory TOTP |

### 6.3 Residual Risk Acceptance

After treatment, any residual risk must be:

1. Documented in the risk register with the residual probability and impact scores
2. Reviewed and approved:
   - **Medium residual risk**: Security Lead approval
   - **High residual risk**: CEO approval
   - **Extreme residual risk**: CEO approval required; must include a timeline for further reduction
3. Reassessed at the next scheduled review

## 7. Risk Monitoring

### 7.1 Continuous Monitoring

| Mechanism | Monitors |
|-----------|----------|
| Wazuh SIEM | Real-time threat detection, vulnerability scanning, file integrity |
| Grafana/Prometheus | System health, resource utilisation, anomaly detection |
| OPA decision logs | Authorisation patterns, policy effectiveness |
| Audit log analysis | User behaviour, access patterns, failed operations |
| Dependency scanning | New CVEs in dependencies (pip-audit, trivy, npm audit) |

### 7.2 Periodic Review

| Review | Frequency | Participants |
|--------|-----------|-------------|
| Risk register review | Quarterly | Security Lead + Engineering Lead |
| Full risk assessment | Annually | Security Lead + CEO + External assessor (if applicable) |
| Post-incident risk update | After every P1/P2 incident | Incident responders + Security Lead |
| Release risk assessment | Every release | Engineering team + Security Lead |

## 8. Integration with Development

Risk management is integrated into the development lifecycle:

1. **Design phase**: Threat modelling for new features
2. **Implementation**: OWASP-aware coding practices, pre-commit checks
3. **Review**: Internal security, code-quality, and integration reviewers assess security risk
4. **Testing**: 523 unit tests + 25 e2e tests + compliance scan
5. **Release**: Risk assessment for each release, updated SBOM
6. **Operation**: Continuous monitoring via Wazuh, Grafana, and audit logs

## 9. Related Documents

- [Incident Response Plan](incident_response_plan.md) — responding to materialised risks
- [Supplier Security](supplier_security.md) — supply chain risk management
- [Change Management](change_management.md) — change-related risk assessment
- [Access Control Policy](access_control_policy.md) — authentication and authorisation controls
- [Business Continuity Plan](business_continuity_plan.md) — continuity and recovery planning
