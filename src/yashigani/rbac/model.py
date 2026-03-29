"""
Yashigani RBAC — Data model definitions.

ResourcePattern  — glob-style matcher for upstream MCP paths/methods.
RateLimitOverride — per-group session-level rate limit override.
RBACGroup        — group with members, resource patterns, and optional override.
RBACMapping      — maps a provisioning source to a list of groups.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ResourcePattern:
    """
    Glob-style pattern that matches an MCP request.

    method:    HTTP method string, or "*" to match any method.
    path_glob: Path pattern.  Supported forms:
               "**"           — any path
               "/tools/**"    — anything under /tools/
               "/tools/call"  — exact match
    """
    method: str
    path_glob: str

    def to_dict(self) -> dict:
        return {"method": self.method, "path_glob": self.path_glob}

    @classmethod
    def from_dict(cls, d: dict) -> "ResourcePattern":
        return cls(method=d["method"], path_glob=d["path_glob"])


@dataclass
class RateLimitOverride:
    """
    Per-group override for the session-level token bucket.

    per_session_rps:   Refill rate (requests per second) for sessions whose
                       most permissive group matches this override.
    per_session_burst: Bucket capacity for those sessions.
    """
    per_session_rps: float
    per_session_burst: int

    def to_dict(self) -> dict:
        return {
            "per_session_rps": self.per_session_rps,
            "per_session_burst": self.per_session_burst,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RateLimitOverride":
        return cls(
            per_session_rps=float(d["per_session_rps"]),
            per_session_burst=int(d["per_session_burst"]),
        )


@dataclass
class RBACGroup:
    """
    A named group of users with a shared set of resource permissions.

    id:                  Opaque string identifier (UUID recommended).
    display_name:        Human-readable label.
    members:             Set of user email addresses belonging to this group.
    allowed_resources:   List of ResourcePatterns that define what MCP paths
                         this group may access. Deny-by-default — an empty
                         list allows nothing.
    rate_limit_override: Optional session-level rate limit override applied
                         when the gateway resolves the user's groups.
    """
    id: str
    display_name: str
    members: set[str] = field(default_factory=set)
    allowed_resources: list[ResourcePattern] = field(default_factory=list)
    rate_limit_override: Optional[RateLimitOverride] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "display_name": self.display_name,
            "members": sorted(self.members),
            "allowed_resources": [r.to_dict() for r in self.allowed_resources],
            "rate_limit_override": (
                self.rate_limit_override.to_dict()
                if self.rate_limit_override is not None
                else None
            ),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RBACGroup":
        override_raw = d.get("rate_limit_override")
        return cls(
            id=d["id"],
            display_name=d["display_name"],
            members=set(d.get("members", [])),
            allowed_resources=[
                ResourcePattern.from_dict(r) for r in d.get("allowed_resources", [])
            ],
            rate_limit_override=(
                RateLimitOverride.from_dict(override_raw)
                if override_raw is not None
                else None
            ),
        )


@dataclass
class RBACMapping:
    """
    Associates a provisioning source with a list of RBAC groups.

    provisioning_source: "scim" | "allow_list"
    groups:              Groups managed by this source.
    """
    provisioning_source: str  # "scim" | "allow_list"
    groups: list[RBACGroup] = field(default_factory=list)
