# Yashigani — OPA Policy Manual

**Version:** v0.9.4
**Last updated:** 2026-03-30
**Policy engine:** Open Policy Agent (OPA) v0.x, rootless container
**Policy language:** Rego (v1 import keywords)

---

## Table of Contents

1. [Overview and Architecture](#1-overview-and-architecture)
2. [Policy Files and Package Structure](#2-policy-files-and-package-structure)
3. [The Input Document](#3-the-input-document)
4. [The Data Document](#4-the-data-document)
5. [Decision Flow — How `allow` Is Computed](#5-decision-flow--how-allow-is-computed)
6. [Path and Method Matching](#6-path-and-method-matching)
7. [Scenario Walkthroughs with Full Examples](#7-scenario-walkthroughs-with-full-examples)
   - 7.1 No RBAC — session + agent gate only
   - 7.2 RBAC enabled — read-only analyst group
   - 7.3 RBAC enabled — privileged operator group
   - 7.4 RBAC enabled — multi-group user
   - 7.5 Agent-to-agent calling — allowed
   - 7.6 Agent-to-agent calling — denied (wrong group)
   - 7.7 Agent-to-agent calling — denied (wrong path)
   - 7.8 Blocked system paths
   - 7.9 JWT user with RBAC
8. [RBAC Data Management](#8-rbac-data-management)
   - 8.1 Admin API (recommended)
   - 8.2 Direct OPA Data API
   - 8.3 bootstrap JSON file
9. [Rate Limit Overrides per Group](#9-rate-limit-overrides-per-group)
10. [Testing Policies with `opa eval`](#10-testing-policies-with-opa-eval)
11. [Extending and Customising Policies](#11-extending-and-customising-policies)
12. [Fail-Closed Guarantee](#12-fail-closed-guarantee)
13. [Troubleshooting](#13-troubleshooting)
14. [Reference — All Input Fields](#14-reference--all-input-fields)
15. [OPA Policy Assistant (v0.7.0)](#15-opa-policy-assistant-v070)

---

## 1. Overview and Architecture

OPA is the **sole authorization arbiter** in Yashigani. Every proxied MCP request is evaluated by OPA before it is forwarded to the upstream server. The gateway never makes its own allow/deny logic — it only enforces what OPA decides.

```
Agent / User
     │
     ▼
  [TLS — Caddy]
     │
     ▼
  [Authentication — session cookie / Bearer token]
     │
     ▼
  [Rate limiter — Redis fixed-window]
     │
     ▼
  [Inspection pipeline — FastText + LLM]
     │
     ▼
  [OPA policy check] ──── deny → 403 POLICY_DENIED
     │ allow
     ▼
  [Upstream MCP server]
```

**Key design decisions:**

- **Always local.** OPA runs in-process with the stack (Docker Compose service `policy`). It never makes a network call to an external authorization service. This is a hard requirement (OWASP ASVS V4.2, V11.1.8).
- **Fail-closed.** If OPA is unreachable or returns an error, the gateway denies the request. There is no fallback to "allow".
- **Single query per request.** The gateway POSTs to `/v1/data/yashigani/allow` once. The response is `{"result": true}` or `{"result": false}`.
- **Data is pushed, not pulled.** The backoffice pushes RBAC group + agent data to OPA via `PUT /v1/data/yashigani` after every mutation. OPA holds it in-memory; there is no database query at decision time.

---

## 2. Policy Files and Package Structure

All three policy files belong to `package yashigani`. OPA loads the entire `policy/` directory as a bundle.

```
policy/
├── yashigani.rego          # Main policy — default deny, session gate, blocked paths
├── rbac.rego               # RBAC module — user group membership → resource access
├── agents.rego             # Agent-to-agent authorization
└── data/
    └── rbac_data.json      # Bootstrap data (empty by default — populated at runtime)
```

### `yashigani.rego` — Main Policy

Responsibilities:
- Sets `default allow := false`
- Defines the positive `allow` rule (authenticated session + agent + allowed method + path not blocked)
- Delegates RBAC enforcement to `deny_rbac` (which calls `allow_rbac` from `rbac.rego`)
- Delegates agent-to-agent enforcement to `deny_agent_call` (which calls `agent_call_allowed` from `agents.rego`)
- Override rules: `allow := false if { deny_rbac }` and `allow := false if { deny_agent_call }`

### `rbac.rego` — RBAC Module

Responsibilities:
- Defines `allow_rbac`: walks `input.session.email → user_groups → group → allowed_resources → pattern`
- Method helper `_method_matches`: exact match or `"*"` wildcard
- Path helper `_path_matches`: exact match, `"**"` wildcard, or `/prefix/**` prefix match

### `agents.rego` — Agent-to-Agent Module

Responsibilities:
- Defines `agent_call_allowed`: verifies caller's groups are in target's `allowed_caller_groups`, then checks path against `allowed_paths`
- Defines `agent_call_deny_reason`: human-readable string used in audit events (one of three reasons)
- Path helper `_agent_path_matches`: exact match, `"**"`, `/prefix/**`, or bare prefix (implicit subtree)

---

## 3. The Input Document

The gateway builds a single JSON object and sends it to OPA as `{"input": {...}}`. Every field is described below.

```json
{
  "input": {
    "method":     "POST",
    "path":       "/tools/call",
    "session_id": "sess_9f3a2b...",
    "agent_id":   "agt_7c1d4e...",
    "user_id":    "alice@example.com",

    "session": {
      "email": "alice@example.com"
    },

    "request": {
      "method": "POST",
      "path":   "/tools/call"
    },

    "headers": {
      "content-type": "application/json",
      "x-yashigani-agent-id": "agt_7c1d4e..."
    },

    "principal": {
      "type":     "agent",
      "agent_id": "agt_caller_abc",
      "groups":   ["grp_operators", "grp_readers"]
    },

    "target_agent": {
      "agent_id":             "agt_target_xyz",
      "allowed_caller_groups": ["grp_operators"],
      "allowed_paths":         ["/tools/**"]
    },

    "request": {
      "remainder_path": "/tools/call"
    }
  }
}
```

### Field Reference

| Field | Type | Set By | Used In | Notes |
|-------|------|--------|---------|-------|
| `input.method` | string | Gateway | `yashigani.rego` | HTTP method of the inbound request |
| `input.path` | string | Gateway | `yashigani.rego` | Full request path (e.g. `/tools/read`) |
| `input.session_id` | string | Gateway | `yashigani.rego` | Session cookie hash. `""` or `"anonymous"` = unauthenticated |
| `input.agent_id` | string | Gateway | `yashigani.rego` | Value of `X-Yashigani-Agent-Id` header. `""` or `"unknown"` = no agent |
| `input.user_id` | string | Gateway | `yashigani.rego` | Resolved user email from session |
| `input.session.email` | string | Gateway | `rbac.rego` | Same as `user_id`. Separated for RBAC readability |
| `input.request.method` | string | Gateway | `rbac.rego` | Duplicates `input.method` — consumed by RBAC pattern matching |
| `input.request.path` | string | Gateway | `rbac.rego` | Duplicates `input.path` — consumed by RBAC pattern matching |
| `input.headers` | object | Gateway | Custom rules | Sanitized headers (no `Authorization`, no `Cookie`) |
| `input.principal.type` | string | Gateway | `agents.rego` | `"agent"` for agent-to-agent calls; absent for user calls |
| `input.principal.agent_id` | string | Gateway | `agents.rego` | Calling agent's ID |
| `input.principal.groups` | array | Gateway | `agents.rego` | RBAC group IDs the calling agent belongs to |
| `input.target_agent.agent_id` | string | Gateway | `agents.rego` | Target agent ID (resolved from `/agents/{id}/...` path) |
| `input.target_agent.allowed_caller_groups` | array | Data doc | `agents.rego` | Groups permitted to call the target |
| `input.target_agent.allowed_paths` | array | Data doc | `agents.rego` | Path patterns the target agent accepts |
| `input.request.remainder_path` | string | Gateway | `agents.rego` | Path after `/agents/{target_id}` |

> **Note:** `input.headers` intentionally omits `Authorization` and `Cookie`. The gateway strips these before building the OPA input to prevent policies from accidentally leaking credential values into audit logs.

---

## 4. The Data Document

The data document is pushed to OPA by `rbac/opa_push.py` after every Admin API mutation. It lives at `data.yashigani` inside OPA.

### Shape

```json
{
  "rbac": {
    "groups": {
      "<group_id>": {
        "id":           "<group_id>",
        "display_name": "Operators",
        "members":      ["alice@example.com", "bob@example.com"],
        "allowed_resources": [
          {"method": "*",    "path_glob": "/tools/**"},
          {"method": "GET",  "path_glob": "/resources/**"}
        ],
        "rate_limit_override": {
          "per_session_rps":   50.0,
          "per_session_burst": 200
        }
      }
    },
    "user_groups": {
      "alice@example.com": ["grp_operators"],
      "bob@example.com":   ["grp_operators", "grp_readers"]
    }
  },
  "agents": {
    "<agent_id>": {
      "allowed_caller_groups": ["grp_operators"],
      "allowed_paths":          ["/tools/**", "/resources/read"],
      "groups":                 ["grp_operators"]
    }
  }
}
```

### Data Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `rbac.groups` | object | Map of group ID → group definition |
| `rbac.groups[id].allowed_resources` | array | List of `{method, path_glob}` patterns |
| `rbac.groups[id].rate_limit_override` | object or null | Per-session RPS and burst override for this group |
| `rbac.user_groups` | object | Map of email → list of group IDs |
| `agents` | object | Map of agent ID → agent ACL |
| `agents[id].allowed_caller_groups` | array | Which RBAC groups may call this agent |
| `agents[id].allowed_paths` | array | Which paths this agent accepts from callers |
| `agents[id].groups` | array | Which RBAC groups this agent belongs to (for agent-as-caller) |

### RBAC disabled (default)

When `data.yashigani.rbac.groups` is empty (`{}`), the RBAC gate is **open** — `deny_rbac` never fires. This is the default after a fresh install, allowing the administrator to access the system before groups are configured.

```json
{ "rbac": { "groups": {}, "user_groups": {} }, "agents": {} }
```

> **Warning:** Leave RBAC disabled only during initial setup. Enable it before going to production by creating at least one group and assigning users.

---

## 5. Decision Flow — How `allow` Is Computed

The OPA engine evaluates all rules in `package yashigani` and combines them. Here is the exact logic:

```
1. Start with default: allow = false

2. Try to prove the positive rule:
   allow = true  IF
     input.session_id not in {"", "anonymous"}
     AND input.agent_id not in {"", "unknown"}
     AND input.method in {"GET","POST","PUT","PATCH","DELETE","OPTIONS"}
     AND NOT path_blocked(input.path)

3. Check RBAC override:
   IF data.yashigani.rbac.groups is non-empty
     AND allow_rbac(input.session.email, input.request.method, input.request.path) = false
   THEN allow = false  (deny_rbac fires)

4. Check agent-to-agent override:
   IF input.principal.type = "agent"
     AND agent_call_allowed = false
   THEN allow = false  (deny_agent_call fires)

5. Return allow
```

The override rules (steps 3 and 4) use `allow := false if { ... }` which in Rego means: if the condition is met, the rule contributes `false` to the set of `allow` values. Since there is also a rule that contributes `true` (step 2), the overall result is the *least permissive* value — `false` wins.

---

## 6. Path and Method Matching

### Method Patterns

Used in RBAC `allowed_resources[].method` and agent `allowed_paths` (methods are not part of agent paths).

| Pattern | Matches |
|---------|---------|
| `"*"` | Any HTTP method |
| `"GET"` | GET only |
| `"POST"` | POST only |
| `"PUT"` | PUT only |
| `"DELETE"` | DELETE only |
| Any exact string | Exact case-sensitive match |

### Path Patterns

Used in RBAC `allowed_resources[].path_glob` and agent `allowed_paths[]`.

| Pattern | Matches | Example |
|---------|---------|---------|
| `"**"` | Any path | `/tools/call`, `/resources/data/items` |
| `"/tools/**"` | Exact `/tools/` prefix + anything after | `/tools/call`, `/tools/read/file` |
| `"/tools/call"` | Exact path only | `/tools/call` only — NOT `/tools/call/extra` |
| `"/tools"` (bare, agents.rego only) | `/tools` and any sub-path | `/tools/call`, `/tools/read` |

> **Important:** In `rbac.rego`, a bare prefix like `/tools` only matches exactly `/tools`. To match subtrees use `/tools/**`. In `agents.rego`, `_agent_path_matches` has an additional rule that treats a bare pattern (no `*`) as a prefix — so `/tools` matches `/tools/call`. This difference is intentional: RBAC is stricter by default.

### Path Blocking (yashigani.rego)

These patterns are blocked **before** RBAC is evaluated. They are hardcoded and cannot be overridden by RBAC groups:

| Blocked prefix/path | Reason |
|---------------------|--------|
| `/admin` (prefix) | Admin control plane — backoffice only, never via gateway |
| `/.well-known/internal` (prefix) | Internal discovery endpoints |
| `/metrics` (exact) | Prometheus metrics endpoint |
| `/healthz` (exact) | Health check endpoint |

---

## 7. Scenario Walkthroughs with Full Examples

Each example shows the exact OPA input document, the relevant data document state, and the step-by-step evaluation result.

---

### 7.1 No RBAC — Session + Agent Gate Only

**Scenario:** RBAC data is empty. Any authenticated session with a valid agent ID can reach any non-blocked path.

**Data document:**
```json
{ "rbac": { "groups": {}, "user_groups": {} }, "agents": {} }
```

**Input:**
```json
{
  "input": {
    "method": "POST",
    "path": "/tools/call",
    "session_id": "sess_abc123",
    "agent_id": "agt_xyz789",
    "user_id": "alice@example.com",
    "session": { "email": "alice@example.com" },
    "request": { "method": "POST", "path": "/tools/call" }
  }
}
```

**Evaluation:**
1. `session_id = "sess_abc123"` ✓ (not empty, not anonymous)
2. `agent_id = "agt_xyz789"` ✓ (not empty, not unknown)
3. `method = "POST"` ✓ (in allowed_methods)
4. `path_blocked("/tools/call")` → false ✓ (doesn't start with /admin, not /metrics, not /healthz)
5. Positive `allow` rule fires → `allow = true`
6. `count(data.yashigani.rbac.groups) = 0` → `deny_rbac` does NOT fire
7. `input.principal.type` is absent → `deny_agent_call` does NOT fire

**Result: `allow = true` → 200 forwarded to upstream**

---

### 7.2 RBAC Enabled — Read-Only Analyst Group

**Scenario:** RBAC is active. A "readers" group can only call GET on `/resources/**`. Alice is a reader. She tries to POST to `/tools/call`.

**Data document:**
```json
{
  "rbac": {
    "groups": {
      "grp_readers": {
        "id": "grp_readers",
        "display_name": "Readers",
        "members": ["alice@example.com"],
        "allowed_resources": [
          { "method": "GET", "path_glob": "/resources/**" }
        ]
      }
    },
    "user_groups": {
      "alice@example.com": ["grp_readers"]
    }
  },
  "agents": {}
}
```

**Input (Alice, POST /tools/call):**
```json
{
  "input": {
    "method": "POST",
    "path": "/tools/call",
    "session_id": "sess_alice01",
    "agent_id": "agt_claude01",
    "session": { "email": "alice@example.com" },
    "request": { "method": "POST", "path": "/tools/call" }
  }
}
```

**Evaluation:**
1. Session + agent check passes ✓
2. Path not blocked ✓
3. Positive `allow = true` fires
4. `count(data.yashigani.rbac.groups) = 1 > 0` → RBAC gate activates
5. `allow_rbac` check:
   - Alice's groups: `["grp_readers"]`
   - `grp_readers` has `{method: "GET", path_glob: "/resources/**"}`
   - `_method_matches("GET", "POST")` → false ✗
   - No pattern matches → `allow_rbac = false`
6. `deny_rbac = true` → `allow = false`

**Result: `allow = false` → 403 POLICY_DENIED**

---

**Same user, allowed request (GET /resources/data):**

```json
{
  "input": {
    "method": "GET",
    "path": "/resources/data",
    "session_id": "sess_alice01",
    "agent_id": "agt_claude01",
    "session": { "email": "alice@example.com" },
    "request": { "method": "GET", "path": "/resources/data" }
  }
}
```

**Evaluation:**
1. Session + agent + method + path checks pass ✓
2. `allow_rbac`:
   - Pattern `{method: "GET", path_glob: "/resources/**"}`
   - `_method_matches("GET", "GET")` → true ✓
   - `_path_matches("/resources/**", "/resources/data")`:
     - `endswith("/resources/**", "/**")` → true
     - prefix = `/resources`
     - `startswith("/resources/data", "/resources/")` → true ✓
   - `allow_rbac = true`
3. `deny_rbac = false`

**Result: `allow = true` → 200 forwarded**

---

### 7.3 RBAC Enabled — Privileged Operator Group

**Scenario:** Operators get unrestricted access to all tools and resources via `"**"`.

**Group configuration:**
```json
{
  "grp_operators": {
    "id": "grp_operators",
    "display_name": "Operators",
    "members": ["bob@example.com"],
    "allowed_resources": [
      { "method": "*", "path_glob": "**" }
    ]
  }
}
```

**Input (Bob, DELETE /tools/dangerous):**
```json
{
  "input": {
    "method": "DELETE",
    "path": "/tools/dangerous",
    "session_id": "sess_bob01",
    "agent_id": "agt_ops",
    "session": { "email": "bob@example.com" },
    "request": { "method": "DELETE", "path": "/tools/dangerous" }
  }
}
```

**Evaluation:**
1. `_method_matches("*", "DELETE")` → true ✓ (wildcard method)
2. `_path_matches("**", "/tools/dangerous")` → true ✓ (wildcard path)
3. `allow_rbac = true`, `deny_rbac = false`

**Result: `allow = true`**

> **Note:** Even with `"**"` path glob, hardcoded blocked paths in `yashigani.rego` still apply. Bob cannot reach `/admin/**` or `/metrics` — those are denied by `path_blocked` before RBAC is evaluated.

---

### 7.4 RBAC Enabled — Multi-Group User

**Scenario:** Carol is in both `grp_readers` (GET /resources/**) and `grp_analysts` (POST /tools/analyze). She can reach both.

**Data document (partial):**
```json
{
  "rbac": {
    "groups": {
      "grp_readers": {
        "allowed_resources": [
          { "method": "GET", "path_glob": "/resources/**" }
        ]
      },
      "grp_analysts": {
        "allowed_resources": [
          { "method": "POST", "path_glob": "/tools/analyze" }
        ]
      }
    },
    "user_groups": {
      "carol@example.com": ["grp_readers", "grp_analysts"]
    }
  }
}
```

`allow_rbac` iterates all of Carol's groups. It only needs **one** matching pattern to return true.

**Input (Carol, POST /tools/analyze):**
- Group `grp_readers`: `{method: "GET", path_glob: "/resources/**"}` — method mismatch ✗
- Group `grp_analysts`: `{method: "POST", path_glob: "/tools/analyze"}`:
  - `_method_matches("POST", "POST")` → true ✓
  - `_path_matches("/tools/analyze", "/tools/analyze")` → exact match ✓
  - `allow_rbac = true` ✓

**Result: `allow = true`**

**Input (Carol, DELETE /tools/analyze):**
- Neither group has a DELETE pattern for this path
- `allow_rbac = false` → `deny_rbac = true`

**Result: `allow = false` → 403**

---

### 7.5 Agent-to-Agent Calling — Allowed

**Scenario:** Agent `agt_orchestrator` calls agent `agt_file_reader` at `/tools/read/config.json`. The orchestrator is in group `grp_operators`, which is in the file reader's `allowed_caller_groups`.

**Data document (agents section):**
```json
{
  "agents": {
    "agt_file_reader": {
      "allowed_caller_groups": ["grp_operators", "grp_readers"],
      "allowed_paths":         ["/tools/read/**", "/tools/list"],
      "groups":                ["grp_file_services"]
    }
  }
}
```

**Input:**
```json
{
  "input": {
    "method": "GET",
    "path": "/agents/agt_file_reader/tools/read/config.json",
    "session_id": "sess_orch01",
    "agent_id": "agt_orchestrator",
    "session": { "email": "system@yashigani.local" },
    "request": {
      "method": "GET",
      "path": "/agents/agt_file_reader/tools/read/config.json",
      "remainder_path": "/tools/read/config.json"
    },
    "principal": {
      "type":     "agent",
      "agent_id": "agt_orchestrator",
      "groups":   ["grp_operators"]
    },
    "target_agent": {
      "agent_id":              "agt_file_reader",
      "allowed_caller_groups": ["grp_operators", "grp_readers"],
      "allowed_paths":         ["/tools/read/**", "/tools/list"]
    }
  }
}
```

**Evaluation of `agent_call_allowed`:**
1. `input.principal.type = "agent"` ✓
2. `input.principal.agent_id = "agt_orchestrator"` (not empty) ✓
3. Caller group check: `"grp_operators" in ["grp_operators", "grp_readers"]` → true ✓
4. Path check: `_agent_path_matches("/tools/read/**", "/tools/read/config.json")`:
   - `endswith("/tools/read/**", "/**")` → true
   - prefix = `/tools/read`
   - `startswith("/tools/read/config.json", "/tools/read/")` → true ✓
5. `agent_call_allowed = true`
6. `deny_agent_call = false`

**Result: `allow = true`**

---

### 7.6 Agent-to-Agent Calling — Denied (Wrong Group)

**Scenario:** Same setup, but `agt_untrusted` is in `grp_external` which is NOT in `agt_file_reader`'s `allowed_caller_groups`.

**Input (principal.groups only):**
```json
"principal": {
  "type":     "agent",
  "agent_id": "agt_untrusted",
  "groups":   ["grp_external"]
}
```

**Evaluation:**
1. Caller group check: `"grp_external" in ["grp_operators", "grp_readers"]` → false ✗
2. No group matches → `agent_call_allowed = false`
3. `deny_agent_call = true` → `allow = false`
4. `agent_call_deny_reason = "caller_group_not_in_allowed_caller_groups"`

**Result: `allow = false` → 403**
**Audit event includes:** `deny_reason: "caller_group_not_in_allowed_caller_groups"`

---

### 7.7 Agent-to-Agent Calling — Denied (Wrong Path)

**Scenario:** `agt_orchestrator` (grp_operators, allowed) tries to call `/tools/write/config.json` on `agt_file_reader`, but the file reader only allows `/tools/read/**` and `/tools/list`.

**Input (remainder_path only):**
```json
"request": {
  "remainder_path": "/tools/write/config.json"
}
```

**Evaluation:**
1. Caller group `grp_operators` in allowed groups ✓
2. `_caller_group_allowed = true`
3. Path check: `/tools/write/config.json` vs `["/tools/read/**", "/tools/list"]`:
   - `/tools/read/**`: prefix is `/tools/read` → `startswith("/tools/write/...", "/tools/read/")` → false ✗
   - `/tools/list`: exact match `/tools/list` vs `/tools/write/config.json` → false ✗
4. `_path_allowed = false` → `agent_call_allowed = false`
5. `agent_call_deny_reason = "path_not_in_allowed_paths"`

**Result: `allow = false` → 403**
**Audit event includes:** `deny_reason: "path_not_in_allowed_paths"`

---

### 7.8 Blocked System Paths

These are blocked before RBAC is checked. Even a superuser group with `"**"` cannot bypass them.

**Input (any session/agent, path = /admin/license):**
```json
{
  "input": {
    "method": "GET",
    "path": "/admin/license",
    "session_id": "sess_superuser",
    "agent_id": "agt_super"
  }
}
```

**Evaluation:**
1. `path_blocked`:
   - `startswith("/admin/license", "/admin")` → true ✓
   - `path_blocked = true`
2. Positive `allow` rule condition `not path_blocked` → fails
3. `allow` stays `false`

**Result: `allow = false` → 403**

Other blocked paths:

| Request | Reason |
|---------|--------|
| `GET /metrics` | Prometheus metrics (internal only, Caddy-gated) |
| `GET /healthz` | Health check (internal only) |
| `GET /.well-known/internal/keys` | Internal JWKS endpoint |
| `POST /admin/sso/saml/acs` | Admin plane — backoffice handles this, not gateway |

---

### 7.9 JWT User with RBAC

**Scenario:** A corporate deployment uses JWT bearer tokens. The JWT inspector resolves the user's email from the `sub` or `email` claim and writes it to `input.session.email`. RBAC rules then apply normally.

The gateway builds the input with:
```python
"session": {"email": jwt_claims.get("email") or jwt_claims.get("sub", "")}
```

So for a JWT with `{"sub": "carol@corp.example.com", "email": "carol@corp.example.com"}`, the RBAC lookup uses `carol@corp.example.com` as the key into `data.yashigani.rbac.user_groups`.

No policy changes are needed — the RBAC module is identity-source-agnostic. Whether the user authenticated via password+TOTP, SAML, OIDC, or JWT, the email lands in `input.session.email` and RBAC evaluates identically.

---

## 8. RBAC Data Management

### 8.1 Admin API (Recommended)

The backoffice exposes a REST API for managing groups. Every mutation automatically calls `push_rbac_data()` which PUTs the updated document to OPA.

**Create a group:**
```bash
curl -X POST https://your-domain/admin/rbac/groups \
  -H "Cookie: yashigani_session=<session>" \
  -H "Content-Type: application/json" \
  -d '{
    "display_name": "Readers",
    "allowed_resources": [
      {"method": "GET", "path_glob": "/resources/**"},
      {"method": "GET", "path_glob": "/tools/list"}
    ]
  }'
# Response: {"id": "grp_<uuid>", "display_name": "Readers", ...}
```

**Add a user to a group:**
```bash
curl -X POST https://your-domain/admin/rbac/groups/grp_<uuid>/members \
  -H "Cookie: yashigani_session=<session>" \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com"}'
```

**List groups:**
```bash
curl https://your-domain/admin/rbac/groups \
  -H "Cookie: yashigani_session=<session>"
```

**Delete a group:**
```bash
curl -X DELETE https://your-domain/admin/rbac/groups/grp_<uuid> \
  -H "Cookie: yashigani_session=<session>"
```

Each of these calls triggers an OPA push. Changes take effect on the next request — typically within milliseconds.

### 8.2 Direct OPA Data API

For advanced use or scripting, push data directly to OPA. This bypasses the backoffice but the backoffice will overwrite it on the next Admin API mutation.

```bash
# Replace the entire yashigani data namespace
curl -X PUT http://localhost:8181/v1/data/yashigani \
  -H "Content-Type: application/json" \
  -d '{
    "rbac": {
      "groups": {
        "grp_operators": {
          "id": "grp_operators",
          "display_name": "Operators",
          "members": ["bob@example.com"],
          "allowed_resources": [
            {"method": "*", "path_glob": "**"}
          ],
          "rate_limit_override": null
        }
      },
      "user_groups": {
        "bob@example.com": ["grp_operators"]
      }
    },
    "agents": {}
  }'
```

**Query OPA for a policy decision (debugging):**
```bash
curl -X POST http://localhost:8181/v1/data/yashigani/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "method": "GET",
      "path": "/resources/data",
      "session_id": "sess_test",
      "agent_id": "agt_test",
      "session": {"email": "alice@example.com"},
      "request": {"method": "GET", "path": "/resources/data"}
    }
  }'
# Response: {"result": true}
```

**Inspect current data in OPA:**
```bash
# Full data document
curl http://localhost:8181/v1/data/yashigani

# RBAC groups only
curl http://localhost:8181/v1/data/yashigani/rbac/groups

# Agent ACLs only
curl http://localhost:8181/v1/data/yashigani/agents
```

### 8.3 Bootstrap JSON File

`policy/data/rbac_data.json` is loaded by OPA at startup as the initial data document. The default is empty:

```json
{"rbac": {"groups": {}, "user_groups": {}}, "agents": {}}
```

For environments where the Admin API is not used (e.g. GitOps pipelines), you can pre-populate this file. Format it as the full `data.yashigani` namespace:

```json
{
  "rbac": {
    "groups": {
      "grp_ops": {
        "id": "grp_ops",
        "display_name": "Operators",
        "members": ["ops@corp.com"],
        "allowed_resources": [
          {"method": "*", "path_glob": "**"}
        ],
        "rate_limit_override": null
      },
      "grp_readonly": {
        "id": "grp_readonly",
        "display_name": "Read-Only",
        "members": ["dev@corp.com"],
        "allowed_resources": [
          {"method": "GET", "path_glob": "/resources/**"}
        ],
        "rate_limit_override": {
          "per_session_rps": 5.0,
          "per_session_burst": 20
        }
      }
    },
    "user_groups": {
      "ops@corp.com":  ["grp_ops"],
      "dev@corp.com":  ["grp_readonly"]
    }
  },
  "agents": {}
}
```

> **Note:** Any data pushed via the Admin API or direct OPA API will overwrite this file's data at runtime (but not the file itself). The file is only read at OPA startup.

---

## 9. Rate Limit Overrides per Group

Each RBAC group can optionally carry a `rate_limit_override`. The gateway reads this when it resolves a user's group membership and applies the **most permissive** override among all the user's groups.

**Group definition with rate limit override:**
```json
{
  "grp_premium": {
    "id": "grp_premium",
    "display_name": "Premium Users",
    "members": ["premium@example.com"],
    "allowed_resources": [
      { "method": "*", "path_glob": "**" }
    ],
    "rate_limit_override": {
      "per_session_rps": 100.0,
      "per_session_burst": 500
    }
  }
}
```

**Default rate limits** (no override): configured in `YASHIGANI_RATE_LIMIT_PER_SESSION_RPS` and `YASHIGANI_RATE_LIMIT_PER_SESSION_BURST`.

**Common configurations:**

| Group | Use Case | per_session_rps | per_session_burst |
|-------|----------|-----------------|-------------------|
| Community user | Standard access | 10.0 | 50 |
| Developer | Testing and integration | 30.0 | 100 |
| Operator | Production management | 100.0 | 500 |
| Automation service account | CI/CD pipelines | 200.0 | 1000 |
| Read-only analyst | Dashboard queries | 5.0 | 20 |

The rate limit override is **not** enforced by OPA — OPA just carries the data. The gateway reads `data.yashigani.rbac.groups` to resolve the override before it reaches OPA.

---

## 10. Testing Policies with `opa eval`

Install OPA CLI: https://www.openpolicyagent.org/docs/latest/#1-download-opa

### Evaluate a single decision

```bash
cd /path/to/yashigani

opa eval \
  --data policy/ \
  --input - \
  'data.yashigani.allow' <<'EOF'
{
  "method": "POST",
  "path": "/tools/call",
  "session_id": "sess_test",
  "agent_id": "agt_test",
  "session": { "email": "alice@example.com" },
  "request": { "method": "POST", "path": "/tools/call" }
}
EOF
# Output: {"result": [[{"expressions": [{"value": false, "text": "..."}]}]]}
```

### Test with custom RBAC data

Create a test data file `test_data.json`:
```json
{
  "yashigani": {
    "rbac": {
      "groups": {
        "grp_writers": {
          "id": "grp_writers",
          "display_name": "Writers",
          "members": ["alice@example.com"],
          "allowed_resources": [
            {"method": "POST", "path_glob": "/tools/**"}
          ],
          "rate_limit_override": null
        }
      },
      "user_groups": {
        "alice@example.com": ["grp_writers"]
      }
    },
    "agents": {}
  }
}
```

```bash
opa eval \
  --data policy/ \
  --data test_data.json \
  --input - \
  'data.yashigani.allow' <<'EOF'
{
  "method": "POST",
  "path": "/tools/call",
  "session_id": "sess_test",
  "agent_id": "agt_test",
  "session": { "email": "alice@example.com" },
  "request": { "method": "POST", "path": "/tools/call" }
}
EOF
```

### Evaluate intermediate rules

```bash
# Check path_blocked
opa eval --data policy/ --input - 'data.yashigani.path_blocked' <<'EOF'
{"path": "/admin/users"}
EOF

# Check allow_rbac in isolation
opa eval --data policy/ --data test_data.json --input - 'data.yashigani.allow_rbac' <<'EOF'
{
  "session": {"email": "alice@example.com"},
  "request": {"method": "GET", "path": "/resources/data"}
}
EOF

# Check agent_call_deny_reason
opa eval --data policy/ --input - 'data.yashigani.agent_call_deny_reason' <<'EOF'
{
  "principal": {
    "type": "agent",
    "agent_id": "agt_bad",
    "groups": ["grp_external"]
  },
  "target_agent": {
    "agent_id": "agt_target",
    "allowed_caller_groups": ["grp_internal"],
    "allowed_paths": ["**"]
  },
  "request": {"remainder_path": "/tools/call"}
}
EOF
```

### Run the full OPA REPL for interactive debugging

```bash
opa run --data policy/ --data test_data.json

# Inside the REPL:
> data.yashigani.allow with input as {"method": "GET", "path": "/tools/list", "session_id": "s", "agent_id": "a", "session": {"email": "alice@example.com"}, "request": {"method": "GET", "path": "/tools/list"}}
true

> data.yashigani.path_blocked with input as {"path": "/metrics"}
true
```

### Unit test with `opa test`

Create `policy/yashigani_test.rego`:

```rego
package yashigani_test

import data.yashigani

# Test: unauthenticated request is denied
test_deny_no_session if {
    not yashigani.allow with input as {
        "method": "GET",
        "path": "/tools/list",
        "session_id": "",
        "agent_id": "agt_x"
    }
}

# Test: admin path is always blocked
test_deny_admin_path if {
    not yashigani.allow with input as {
        "method": "GET",
        "path": "/admin/license",
        "session_id": "sess_valid",
        "agent_id": "agt_valid"
    }
}

# Test: metrics path is always blocked
test_deny_metrics if {
    not yashigani.allow with input as {
        "method": "GET",
        "path": "/metrics",
        "session_id": "sess_valid",
        "agent_id": "agt_valid"
    }
}
```

```bash
opa test policy/ -v
# Output:
# PASS: test_deny_no_session (0.001s)
# PASS: test_deny_admin_path (0.001s)
# PASS: test_deny_metrics (0.001s)
# 3 tests, 0 failures
```

---

## 11. Extending and Customising Policies

The policy bundle is open for extension. Add new `.rego` files to `policy/` — OPA loads the entire directory. All files in the same package share rules.

### Adding a New Blocked Path

Add to `yashigani.rego` or a new file `policy/custom_blocks.rego`:

```rego
package yashigani

# Block access to legacy API
path_blocked if {
    startswith(input.path, "/legacy/")
}

# Block DELETE on /resources (read-only resources)
path_blocked if {
    input.method == "DELETE"
    startswith(input.path, "/resources/")
}
```

No restart needed — changes to mounted policy files are picked up by OPA on reload (or restart the `policy` container).

### Adding a Time-Based Rule

```rego
package yashigani
import future.keywords.if

# Only allow requests during business hours (UTC)
allow := false if {
    # time.now_ns() returns nanoseconds since epoch
    hour := time.clock(time.now_ns())[0]
    hour < 8
}

allow := false if {
    hour := time.clock(time.now_ns())[0]
    hour >= 18
}
```

### Adding a Header-Based Rule

```rego
package yashigani
import future.keywords.if

# Require a specific API version header for /tools/** paths
path_blocked if {
    startswith(input.path, "/tools/")
    not input.headers["x-api-version"]
}

path_blocked if {
    startswith(input.path, "/tools/")
    input.headers["x-api-version"] != "2"
}
```

### Adding an IP Allowlist

Extend the input document first (gateway code) to include `input.client_ip`, then:

```rego
package yashigani
import future.keywords.if
import future.keywords.in

# IP allowlist for privileged operations
_privileged_ops_allowed_ips := {"10.0.1.0/24", "192.168.100.50"}

allow := false if {
    startswith(input.path, "/tools/admin/")
    not _ip_in_allowlist(input.client_ip)
}

_ip_in_allowlist(ip) if {
    ip in _privileged_ops_allowed_ips
}
```

### Exposing an Audit Helper Rule

`agent_call_deny_reason` is already defined in `agents.rego` and included in audit events. You can add similar reason rules for RBAC:

```rego
package yashigani
import future.keywords.if

# Human-readable deny reason for RBAC failures — used in audit events
rbac_deny_reason := "no_rbac_groups_for_user" if {
    deny_rbac
    email := input.session.email
    not data.yashigani.rbac.user_groups[email]
}

rbac_deny_reason := "no_matching_resource_pattern" if {
    deny_rbac
    email := input.session.email
    data.yashigani.rbac.user_groups[email]
}
```

---

## 12. Fail-Closed Guarantee

The gateway implements fail-closed at two levels:

### Level 1 — Network / HTTP errors

```python
async def _opa_check(...) -> bool:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(cfg.opa_url + cfg.opa_policy_path, ...)
            resp.raise_for_status()
            data = resp.json()
            return bool(data.get("result", False))
    except Exception as exc:
        logger.error("OPA check failed ... — denying (fail-closed)")
        return False  # DENY on any error
```

- OPA container down: deny
- OPA timeout (> 5 seconds): deny
- OPA returns non-2xx: deny
- OPA returns malformed JSON: deny

### Level 2 — OPA evaluation errors

If OPA's Rego evaluation encounters an error (e.g. undefined reference in a custom rule), OPA returns `{}` (undefined result). The gateway interprets `data.get("result", False)` = `False` → deny.

### Level 3 — OPA policy default

```rego
default allow := false
```

If no positive rule fires (because none of the conditions are met), `allow` is `false`. OPA never returns "undefined" for `allow` because the default covers all cases.

### What "fail-closed" means in practice

| Event | Outcome |
|-------|---------|
| OPA container crashes | All requests denied with 403 until OPA restarts |
| OPA container restarting | All requests denied |
| OPA RBAC data push fails | Stale data in OPA — users retain last-known permissions |
| Custom rule typo causing eval error | Request denied (not allowed) |
| `input.session.email` missing | `allow_rbac = false` → if RBAC active, request denied |
| Network partition between gateway and OPA | All requests denied |

> **Operational note:** OPA restarts are fast (< 1 second typically). The Docker Compose `restart: unless-stopped` and the gateway's 5-second timeout mean that brief OPA restarts cause at most a few 403 responses before service resumes.

---

## 13. Troubleshooting

### "403 POLICY_DENIED" but the request looks correct

**Step 1 — Reproduce the exact OPA decision:**
```bash
# From inside the gateway container or host (if OPA port is exposed locally):
curl -X POST http://localhost:8181/v1/data/yashigani/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "method": "POST",
      "path": "/tools/call",
      "session_id": "sess_<your_session>",
      "agent_id": "agt_<your_agent>",
      "session": {"email": "alice@example.com"},
      "request": {"method": "POST", "path": "/tools/call"}
    }
  }'
```

**Step 2 — Check which rule is causing the deny:**
```bash
# Is path_blocked the issue?
curl -X POST http://localhost:8181/v1/data/yashigani/path_blocked \
  -d '{"input": {"path": "/tools/call", "method": "POST"}}'

# Is RBAC the issue?
curl -X POST http://localhost:8181/v1/data/yashigani/deny_rbac \
  -d '{"input": {"session": {"email": "alice@example.com"}, "request": {"method": "POST", "path": "/tools/call"}}}'

# What does allow_rbac return?
curl -X POST http://localhost:8181/v1/data/yashigani/allow_rbac \
  -d '{"input": {"session": {"email": "alice@example.com"}, "request": {"method": "POST", "path": "/tools/call"}}}'
```

**Step 3 — Check current RBAC data in OPA:**
```bash
curl http://localhost:8181/v1/data/yashigani/rbac/user_groups
# Check that alice@example.com is in the right groups

curl http://localhost:8181/v1/data/yashigani/rbac/groups
# Check that the group has the right patterns
```

**Step 4 — Check audit log for the deny reason:**
```bash
docker compose logs gateway | grep '"action":"DENIED"' | tail -20
```

---

### User is in RBAC group but still getting 403

**Check the email key exactly:**
```bash
# RBAC is keyed by exact email. Check for case mismatch or typo.
curl http://localhost:8181/v1/data/yashigani/rbac/user_groups | jq 'keys'
```

**Check path pattern:**
```bash
# Use opa eval to test the specific pattern
opa eval --data policy/ 'data.yashigani._path_matches("/tools/**", "/tools/call")' \
  --format pretty
# Should return: true
```

---

### OPA policy changes not taking effect

OPA loads policy files at startup. After editing a `.rego` file:
```bash
docker compose restart policy
```

RBAC data changes (via Admin API) take effect immediately without restart.

---

### RBAC data was pushed but OPA is returning stale decisions

Verify the push succeeded:
```bash
docker compose logs backoffice | grep "OPA data pushed"
# Expected: "OPA data pushed: N groups, M users with group assignments, K active agents"
```

If push failed, trigger a manual push:
```bash
# Force backoffice restart (re-pushes all data on startup)
docker compose restart backoffice
```

---

### Agent-to-agent calls returning 403

**Check deny reason in audit log:**
```bash
docker compose logs gateway | grep '"agent_call_deny_reason"' | tail -10
```

**Possible values:**
- `"caller_group_not_in_allowed_caller_groups"` → Add the calling agent's group to the target's `allowed_caller_groups`
- `"path_not_in_allowed_paths"` → Add the path pattern to the target's `allowed_paths`
- `"target_agent_not_in_data"` → Target agent ID not in OPA data — push data again or check agent registration

---

## 14. Reference — All Input Fields

Quick reference of every field the gateway sets in the OPA input document.

```
input
├── method                  string   HTTP method (GET, POST, ...)
├── path                    string   Full request path (/tools/call)
├── session_id              string   Hashed session cookie. "" = unauthenticated
├── agent_id                string   X-Yashigani-Agent-Id value. "" = no agent
├── user_id                 string   Resolved user email from session
├── session
│   └── email               string   User email — used by RBAC matching
├── request
│   ├── method              string   Same as input.method (RBAC alias)
│   ├── path                string   Same as input.path (RBAC alias)
│   └── remainder_path      string   Path after /agents/{target_id} (agent calls only)
├── headers
│   └── <header-name>       string   Lowercase header names, no Authorization/Cookie
├── principal                        Only present for agent-to-agent calls
│   ├── type                string   "agent"
│   ├── agent_id            string   Calling agent's registered ID
│   └── groups              array    RBAC group IDs the calling agent belongs to
└── target_agent                     Only present for agent-to-agent calls
    ├── agent_id            string   Target agent's registered ID
    ├── allowed_caller_groups array  Groups permitted to call this target
    └── allowed_paths       array    Path patterns this target accepts
```

---

## 15. OPA Policy Assistant (v0.7.0)

The OPA Policy Assistant allows administrators to describe an access control requirement in plain English and receive a validated RBAC data document JSON suggestion, which must be reviewed and explicitly approved before anything changes.

### 15.1 What It Does (and Does Not Do)

**Does:**
- Accept a natural language description of an access control requirement
- Generate the RBAC data document JSON (`groups` + `user_groups`) using the internal Ollama model (`qwen2.5:3b`)
- Validate the generated document against the RBAC JSON schema
- Present the suggestion to the admin for review
- On approval, push the document to OPA and write an audit event
- On rejection, write an audit event and make no changes

**Does not:**
- Generate or modify Rego policy files — only the data document
- Apply any change without explicit admin approval
- Make external API calls — air-gapped compatible

### 15.2 API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/admin/opa-assistant/suggest` | Generate a suggestion from a description |
| `POST` | `/admin/opa-assistant/apply` | Apply a validated suggestion to OPA |
| `POST` | `/admin/opa-assistant/reject` | Record a rejection (audit log only) |
| `GET`  | `/admin/opa-assistant/schema` | Return the RBAC document JSON schema |

### 15.3 Generate a Suggestion

```bash
curl -X POST https://your-domain/admin/opa-assistant/suggest \
  -H "Cookie: yashigani_session=YOUR_SESSION_COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Engineering team can call any tool. Finance team can only call tools under /finance/**. No other users get access.",
    "include_current": true
  }'
```

**Response (success):**
```json
{
  "suggestion": {
    "groups": {
      "engineering": {
        "id": "engineering",
        "display_name": "Engineering Team",
        "allowed_resources": [{"method": "*", "path_glob": "**"}]
      },
      "finance-readonly": {
        "id": "finance-readonly",
        "display_name": "Finance Team (Read-Only)",
        "allowed_resources": [{"method": "GET", "path_glob": "/finance/**"}]
      }
    },
    "user_groups": {}
  },
  "valid": true,
  "raw_response": "..."
}
```

**Response (validation failure):**
```json
{
  "suggestion": null,
  "valid": false,
  "error": "json_parse_error: Expecting value: line 1 column 1 (char 0)",
  "raw_response": "..."
}
```

### 15.4 Apply a Suggestion

The `/apply` endpoint re-validates the document before pushing to OPA. Never blindly trust client-supplied data — the re-validation is not optional.

```bash
curl -X POST https://your-domain/admin/opa-assistant/apply \
  -H "Cookie: yashigani_session=YOUR_SESSION_COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "suggestion": { "groups": {...}, "user_groups": {...} },
    "description": "Initial RBAC: engineering full access, finance /finance/** read-only"
  }'
```

### 15.5 Path Glob Rules for Generated Policies

The assistant is instructed to use these path glob conventions, which match the `_path_matches` implementation in `rbac/store.py`:

| Pattern | Matches |
|---------|---------|
| `/tools/list` | Exact path only |
| `/tools/*` | Any single-segment path under `/tools/` (does not cross `/`) |
| `/tools/**` | Any path that starts with `/tools/` (multi-segment) |
| `**` | Any path |

> **Note:** `*` is a single-segment wildcard — it matches `/tools/list` but NOT `/tools/list/extra`. Use `**` for multi-segment subtrees. This was fixed in v0.7.0 (IC-6).

### 15.6 Audit Events

Every assistant action writes to the audit log:

| Event | When |
|-------|------|
| `OPA_ASSISTANT_SUGGESTION_GENERATED` | On every `/suggest` call, regardless of validity |
| `OPA_ASSISTANT_SUGGESTION_APPLIED` | When admin approves and applies |
| `OPA_ASSISTANT_SUGGESTION_REJECTED` | When admin rejects |

### 15.7 Ollama Model Configuration

The assistant uses the Ollama instance at `http://ollama:11434` (default). Override at startup via `backoffice_state.ollama_url`. The model is `qwen2.5:3b` — the same model used by the inspection pipeline.

If Ollama is unavailable, `/suggest` returns `{"valid": false, "error": "ollama_timeout"}`. No changes are made.

---

*OPA runs entirely local. Policy decisions never leave the host. The private key to the universe stays with you.*
