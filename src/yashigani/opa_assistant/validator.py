"""
OPA Policy Assistant — RBAC document schema validator.
Validates generated documents before presenting them to admin for review.
"""
from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

_RBAC_SCHEMA = {
    "type": "object",
    "required": ["groups", "user_groups"],
    "additionalProperties": False,
    "properties": {
        "groups": {
            "type": "object",
            "additionalProperties": {
                "type": "object",
                "required": ["id", "display_name", "allowed_resources"],
                "additionalProperties": False,
                "properties": {
                    "id": {"type": "string", "minLength": 1},
                    "display_name": {"type": "string", "minLength": 1},
                    "allowed_resources": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["method", "path_glob"],
                            "additionalProperties": False,
                            "properties": {
                                "method": {"type": "string", "minLength": 1},
                                "path_glob": {"type": "string", "minLength": 1},
                            },
                        },
                    },
                },
            },
        },
        "user_groups": {
            "type": "object",
            "additionalProperties": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
    },
}


def validate_rbac_document(doc: object) -> tuple[bool, Optional[str]]:
    """
    Validate an RBAC document against the expected schema.
    Returns (is_valid, error_message_or_None).

    Uses jsonschema when available; falls back to manual structural check.
    """
    try:
        import jsonschema
        jsonschema.validate(instance=doc, schema=_RBAC_SCHEMA)
        return True, None
    except ImportError:
        pass  # Fall through to manual check
    except Exception as exc:
        return False, str(exc)

    # ── Manual structural check (fallback) ───────────────────────────────────
    if not isinstance(doc, dict):
        return False, "document must be a JSON object"
    for required in ("groups", "user_groups"):
        if required not in doc:
            return False, f"document missing required key '{required}'"
    if not isinstance(doc["groups"], dict):
        return False, "'groups' must be an object"
    if not isinstance(doc["user_groups"], dict):
        return False, "'user_groups' must be an object"

    for gid, group in doc["groups"].items():
        if not isinstance(group, dict):
            return False, f"group '{gid}' must be an object"
        for field in ("id", "display_name", "allowed_resources"):
            if field not in group:
                return False, f"group '{gid}' missing required field '{field}'"
        if not isinstance(group["allowed_resources"], list):
            return False, f"group '{gid}'.allowed_resources must be an array"
        for i, res in enumerate(group["allowed_resources"]):
            if not isinstance(res, dict):
                return False, f"group '{gid}'.allowed_resources[{i}] must be an object"
            if "method" not in res or "path_glob" not in res:
                return False, (
                    f"group '{gid}'.allowed_resources[{i}] must have 'method' and 'path_glob'"
                )

    for email, groups in doc["user_groups"].items():
        if not isinstance(groups, list):
            return False, f"user_groups['{email}'] must be an array"
        for gid in groups:
            if gid not in doc["groups"]:
                return False, f"user_groups['{email}'] references unknown group '{gid}'"

    return True, None
