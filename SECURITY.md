# Security Policy

## Supported Versions

Two release lines are actively supported. Security fixes are backported to both.

| Version | Supported | Branch | Notes |
|---------|-----------|--------|-------|
| 2.1.x   | ✅ Current | `main` | Full stack — Open WebUI, OE, budget system, Pool Manager, Admin Dashboard |
| 1.10.x  | ✅ Supported | `release/1.x` | Gateway-only — same security core, no Open WebUI |
| 2.0.x   | ❌ | — | Superseded by 2.1.x |
| 1.09.x  | ❌ | — | Superseded by 1.10.x |
| < 1.09  | ❌ | — | End of life |

**v1.x** is maintained on the `release/1.x` branch for deployments that do not require Open WebUI. It receives security patches and infrastructure improvements. Same security foundation as v2.x.

## Reporting a Vulnerability

Thank you for helping keep Yashigani secure.

**Please do not report security vulnerabilities via GitHub Issues.**

Report vulnerabilities by email to **bugs@agnosticsec.com** with:

1. A clear description of the vulnerability
2. Steps to reproduce
3. The version of Yashigani affected
4. Any proof-of-concept or supporting material

We aim to acknowledge all reports within **2 business days** and provide a remediation timeline within **7 business days**.

## Scope

Only vulnerabilities in Yashigani's own code are in scope. Vulnerabilities in third-party dependencies, optional agent bundle containers (LangGraph, Goose, OpenClaw), or upstream MCP tool servers should be reported directly to the respective project maintainers.

## Disclosure Policy

We follow a **90-day coordinated disclosure** policy. After a fix is released we will publish a security advisory. We ask that you do not disclose the vulnerability publicly before the fix is available.

## Recognition

Agnostic Security does not operate a paid bug bounty programme. Researchers who report valid, in-scope vulnerabilities will be credited in the security advisory (with their consent).
