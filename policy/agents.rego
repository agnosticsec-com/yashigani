package yashigani

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# agent_call_allowed — true when a calling agent is permitted to reach
# the target agent's path.
#
# Input fields (set by the gateway for /agents/* requests):
#   input.principal.type                  "agent"
#   input.principal.agent_id              calling agent's ID
#   input.principal.groups                list of RBAC group IDs the caller belongs to
#   input.target_agent.agent_id           target agent ID
#   input.target_agent.allowed_caller_groups  groups allowed to call this agent
#   input.target_agent.allowed_paths      path prefixes or exact paths the agent accepts
#   input.request.remainder_path          path after /agents/{target_agent_id}
# ---------------------------------------------------------------------------

agent_call_allowed if {
    input.principal.type == "agent"
    input.principal.agent_id != ""

    # Caller must be in at least one of the target's allowed_caller_groups
    group := input.principal.groups[_]
    group in input.target_agent.allowed_caller_groups

    # The remainder path must match at least one allowed path pattern
    _path_allowed(input.request.remainder_path, input.target_agent.allowed_paths)
}

# Path matching helper — exact or prefix
_path_allowed(path, allowed_paths) if {
    p := allowed_paths[_]
    _agent_path_matches(p, path)
}

_agent_path_matches(pattern, path) if { pattern == "**" }
_agent_path_matches(pattern, path) if { pattern == path }
_agent_path_matches(pattern, path) if {
    endswith(pattern, "/**")
    prefix := trim_suffix(pattern, "/**")
    startswith(path, concat("", [prefix, "/"]))
}
_agent_path_matches(pattern, path) if {
    not endswith(pattern, "/**")
    not contains(pattern, "*")
    startswith(path, concat("", [pattern, "/"]))
}

# ---------------------------------------------------------------------------
# agent_call_deny_reason — human-readable explanation used in audit events
# ---------------------------------------------------------------------------

agent_call_deny_reason := "caller_group_not_in_allowed_caller_groups" if {
    input.principal.type == "agent"
    not _caller_group_allowed
}

agent_call_deny_reason := "path_not_in_allowed_paths" if {
    input.principal.type == "agent"
    _caller_group_allowed
    not _path_allowed(input.request.remainder_path, input.target_agent.allowed_paths)
}

agent_call_deny_reason := "target_agent_not_in_data" if {
    input.principal.type == "agent"
    not input.target_agent.agent_id
}

_caller_group_allowed if {
    group := input.principal.groups[_]
    group in input.target_agent.allowed_caller_groups
}
