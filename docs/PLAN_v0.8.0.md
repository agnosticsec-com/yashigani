# PLAN_v0.8.0.md
**Status:** IN PROGRESS — 2026-03-28
**Version:** 0.8.0
**Branch focus:** Optional agent bundle (Phase 1), agent detail UX (Phase 2), roadmap items (Phase 3)

---

## Summary

v0.8.0 introduces opt-in third-party agent containers as a courtesy bundle, alongside agent detail UX improvements and several roadmap items. All agent containers are provided as-is; Agnostic Security tracks upstream releases and pins image digests as part of the Yashigani release cycle. Support for bundled agents goes to upstream maintainers, not Agnostic Security.

---

## Phase 1 — Optional Agent Bundle

Four agents available as opt-in installs during `install.sh` / Helm upgrade. Selected via interactive prompt or `--agent-bundles` flag. Not installed by default.

### Agents

| Agent | Stack | License | Integration |
|-------|-------|---------|-------------|
| LangGraph | Python, MCP native | Apache 2.0 | MCP → Yashigani → tools |
| Goose | Python, MCP native | Apache 2.0 | MCP → Yashigani → tools |
| CrewAI | Python | MIT | MCP → Yashigani → tools |
| OpenClaw | Node.js 24, Docker | TBD (check openclaw.ai) | OpenClaw Gateway (:18789) → Yashigani → LLMs |

### Disclaimer surfaces
1. Installer prompt — printed before opt-in questions
2. Backoffice `GET /admin/agent-bundles/disclaimer` — for UI banner
3. `docs/yashigani_install_config.md` — callout box in new section

### Checklist

- [x] P1-A: Docker Compose profiles per agent (`docker/docker-compose.yml`)
- [x] P1-B: `install.sh` — new step 8 `select_agent_bundles()`, `--agent-bundles` flag, disclaimer, profile activation
- [x] P1-C: Backoffice `GET /admin/agent-bundles` + `GET /admin/agent-bundles/disclaimer`
- [x] P1-D: Helm `values.yaml` `agentBundles` section + `templates/agent-bundles.yaml`
- [ ] P1-E (manual): OpenClaw license confirmed at openclaw.ai before shipping
- [ ] P1-F (release automation): upstream digest pinning via GitHub Actions release watcher (tracked separately)

---

## Phase 2 — Agent Detail Page UX

- [x] P2-A: `GET /admin/agents/{agent_id}/quickstart` — MCP quick-start snippet for copy-to-clipboard (`agents.py`)
- [x] P2-B: Rate limiting panel `last_changed` timestamp — `ratelimit.py` GET /config + `BackofficeState.ratelimit_config_last_changed`

---

## Phase 3 — Roadmap (v0.8.0 carry-forward)

Items from `yashigani_objectives.md` targeted for v0.8.0. Not all implemented in this sprint — tracked here for scoping.

| ID | Feature | Status |
|----|---------|--------|
| S-04 | Licence key rotation + break-glass expiry | Deferred → v0.8.1 |
| S-06 | Licence key rotation policy | Deferred → v0.8.1 |
| S-12 | SBOM generation | Deferred → v0.8.1 |
| F-12 | Audit log tamper detection | Deferred → v0.8.1 |
| UX-03 | Real-time inspection feed | Deferred → v0.8.1 |
| UX-07 | Audit log search UI | Deferred → v0.8.1 |
| SC-04 | Async SIEM sink delivery | Deferred → v0.8.1 |
| F-16 | GitHub Actions integration | Deferred → v0.8.1 |

---

## Version bumps

- `pyproject.toml`: `0.7.1` → `0.8.0`
- `src/yashigani/__init__.py`: `0.7.1` → `0.8.0`
- `helm/yashigani/Chart.yaml`: `0.7.1` → `0.8.0`
- `install.sh`: `0.6.0` → `0.8.0`
- `docker/docker-compose.yml`: header comment → `v0.8.0`
- `src/yashigani/backoffice/app.py` FastAPI version: `0.7.1` → `0.8.0`

---

## Requires manual / external action

- Confirm OpenClaw license at openclaw.ai before tagging release
- Pin real upstream image digests for all four agents (release automation — P1-F)
- `git tag v0.8.0`
- Run `pytest src/tests/unit/ -v --cov=yashigani --cov-fail-under=80`
- Test: `docker compose --profile langgraph up -d` end-to-end
- Test: `docker compose --profile openclaw up -d` — verify port 18789 accessible
- Test: `helm upgrade --install yashigani helm/yashigani --set agentBundles.langgraph.enabled=true`
