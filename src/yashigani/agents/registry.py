"""
Yashigani Agent Registry — Manages registered agent identities and PSK tokens.
# Last updated: 2026-05-03T00:00:00+01:00

Key schema (Redis db/3, namespace agent:*):
  agent:reg:{agent_id}      Hash: name, upstream_url, status, created_at,
                             last_seen_at, groups (JSON), allowed_caller_groups (JSON),
                             allowed_paths (JSON)
  agent:token:{agent_id}    String: bcrypt hash of PSK (cost 12)
  agent:index:all           Set: all agent_id values
  agent:index:active        Set: active agent_id values
"""
from __future__ import annotations

import bcrypt
import datetime
import json
import logging
import re
import secrets
import uuid
from typing import Optional

from yashigani.licensing.enforcer import check_agent_limit, LicenseLimitExceeded

logger = logging.getLogger(__name__)

_BCRYPT_COST = 12

# V232-CSCAN-01a: canonical agent-name pattern (must match AgentRegisterRequest.name).
# Any existing registry entry whose name does not match is flagged at startup.
_AGENT_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


def _now_iso() -> str:
    return datetime.datetime.now(tz=datetime.timezone.utc).isoformat()


class AgentRegistry:
    """
    Thread-safe agent registry backed by Redis db/3.

    Agent IDs use the prefix agnt_ followed by 12 hex chars.
    PSK tokens are 256-bit hex strings (64 chars).
    Token hashes use bcrypt cost 12 — never store plaintext.
    """

    def __init__(self, redis_client) -> None:
        self._r = redis_client
        total = self._r.scard("agent:index:all") or 0
        logger.info("AgentRegistry initialised: %d agent(s) in index", total)
        # V232-CSCAN-01a migration check: warn on names that pre-date the slug constraint.
        # These entries are not deleted (non-breaking), but the gateway will skip their
        # secret-file lookup due to the path-resolution guard in openai_router.py.
        self._warn_non_compliant_names()

    # ── Startup integrity check (V232-CSCAN-01a) ─────────────────────────────

    def _warn_non_compliant_names(self) -> None:
        """Log a structured warning for any existing agent whose name does not satisfy
        the slug pattern '^[a-z][a-z0-9_-]{0,63}$' introduced in v2.23.2.

        Non-compliant entries are NOT deleted — that would break existing deployments.
        They are flagged here and surfaced as ``legacy_name_violation=True`` in list_all()
        so the admin UI can display them as a flagged row.
        """
        try:
            for agent in self.list_all():
                name = agent.get("name", "")
                if not _AGENT_NAME_RE.fullmatch(name):
                    logger.warning(
                        "V232-CSCAN-01a: agent %r (id=%s) has a name %r that does not satisfy "
                        "the slug pattern -- secret-file lookup will be skipped for this agent; "
                        "re-register with a compliant name or remove this entry",
                        name, agent.get("agent_id", "?"), name,
                    )
        except Exception as exc:
            logger.warning("V232-CSCAN-01a name-compliance check failed (non-fatal): %s", exc)

    # ── Registration ─────────────────────────────────────────────────────────

    def register(
        self,
        name: str,
        upstream_url: str,
        groups: list,
        allowed_caller_groups: list,
        allowed_paths: list,
        allowed_cidrs: list | None = None,
        protocol: str = "openai",
    ) -> tuple[str, str]:
        """
        Register a new agent.

        Returns (agent_id, plaintext_token). The plaintext token is never
        stored again — the caller is responsible for delivering it securely.
        """
        current_count = self.count("active")
        check_agent_limit(current_count)

        agent_id = f"agnt_{uuid.uuid4().hex[:12]}"
        plaintext_token = secrets.token_bytes(32).hex()

        token_hash = bcrypt.hashpw(
            plaintext_token.encode("utf-8"), bcrypt.gensalt(rounds=_BCRYPT_COST)
        ).decode("utf-8")

        now = _now_iso()

        # Store the registration hash
        reg_key = f"agent:reg:{agent_id}"
        self._r.hset(reg_key, mapping={
            b"name": name.encode("utf-8"),
            b"upstream_url": upstream_url.encode("utf-8"),
            b"protocol": protocol.encode("utf-8"),
            b"status": b"active",
            b"created_at": now.encode("utf-8"),
            b"last_seen_at": b"",
            b"groups": json.dumps(groups).encode("utf-8"),
            b"allowed_caller_groups": json.dumps(allowed_caller_groups).encode("utf-8"),
            b"allowed_paths": json.dumps(allowed_paths).encode("utf-8"),
            b"allowed_cidrs": json.dumps(allowed_cidrs or []).encode("utf-8"),
        })

        # Store bcrypt hash
        token_key = f"agent:token:{agent_id}"
        self._r.set(token_key, token_hash.encode("utf-8"))

        # Update indexes
        self._r.sadd("agent:index:all", agent_id.encode("utf-8"))
        self._r.sadd("agent:index:active", agent_id.encode("utf-8"))

        logger.info("AgentRegistry: registered %s (%s)", agent_id, name)
        return agent_id, plaintext_token

    # ── Reads ─────────────────────────────────────────────────────────────────

    def get(self, agent_id: str) -> Optional[dict]:
        """Return agent dict or None if not found."""
        reg_key = f"agent:reg:{agent_id}"
        raw = self._r.hgetall(reg_key)
        if not raw:
            return None
        return self._decode_agent(agent_id, raw)

    def list_all(self) -> list[dict]:
        """Return all agents (active and inactive)."""
        agent_ids = [
            aid.decode("utf-8") if isinstance(aid, bytes) else aid
            for aid in self._r.smembers("agent:index:all")
        ]
        result = []
        for aid in sorted(agent_ids):
            agent = self.get(aid)
            if agent is not None:
                result.append(agent)
        return result

    def list_active(self) -> list[dict]:
        """Return active agents only."""
        agent_ids = [
            aid.decode("utf-8") if isinstance(aid, bytes) else aid
            for aid in self._r.smembers("agent:index:active")
        ]
        result = []
        for aid in sorted(agent_ids):
            agent = self.get(aid)
            if agent is not None:
                result.append(agent)
        return result

    # ── Mutations ─────────────────────────────────────────────────────────────

    def update(self, agent_id: str, **fields) -> None:
        """
        Update mutable fields: name, upstream_url, groups,
        allowed_caller_groups, allowed_paths.
        """
        allowed_fields = {
            "name", "upstream_url", "groups",
            "allowed_caller_groups", "allowed_paths", "allowed_cidrs",
        }
        reg_key = f"agent:reg:{agent_id}"
        mapping = {}
        for k, v in fields.items():
            if k not in allowed_fields:
                logger.warning("AgentRegistry.update: ignoring unknown field %r", k)
                continue
            if isinstance(v, (list, dict)):
                mapping[k.encode("utf-8")] = json.dumps(v).encode("utf-8")
            else:
                mapping[k.encode("utf-8")] = str(v).encode("utf-8")
        if mapping:
            self._r.hset(reg_key, mapping=mapping)
            logger.info("AgentRegistry: updated %s fields=%s", agent_id, list(fields.keys()))

    def deactivate(self, agent_id: str) -> None:
        """Set status=inactive and remove from active index."""
        reg_key = f"agent:reg:{agent_id}"
        self._r.hset(reg_key, b"status", b"inactive")
        self._r.srem("agent:index:active", agent_id.encode("utf-8"))
        logger.info("AgentRegistry: deactivated %s", agent_id)

    # ── Token operations ──────────────────────────────────────────────────────

    def verify_token(self, agent_id: str, plaintext_token: str) -> bool:
        """
        Verify a plaintext PSK against the stored bcrypt hash.
        Calls _update_last_seen on success.
        Always returns False on any error (fail-closed).
        """
        try:
            token_key = f"agent:token:{agent_id}"
            stored = self._r.get(token_key)
            if not stored:
                return False
            stored_hash = stored if isinstance(stored, bytes) else stored.encode("utf-8")
            candidate = plaintext_token.encode("utf-8")
            ok = bcrypt.checkpw(candidate, stored_hash)
            if ok:
                self._update_last_seen(agent_id)
            return ok
        except Exception as exc:
            logger.error("AgentRegistry.verify_token error for %s: %s", agent_id, exc)
            return False

    def rotate_token(self, agent_id: str) -> str:
        """
        Generate a new 256-bit token, hash and store it, return the plaintext.
        """
        plaintext_token = secrets.token_bytes(32).hex()
        token_hash = bcrypt.hashpw(
            plaintext_token.encode("utf-8"), bcrypt.gensalt(rounds=_BCRYPT_COST)
        ).decode("utf-8")
        token_key = f"agent:token:{agent_id}"
        self._r.set(token_key, token_hash.encode("utf-8"))
        logger.info("AgentRegistry: token rotated for %s", agent_id)
        return plaintext_token

    # ── Counts ────────────────────────────────────────────────────────────────

    def count(self, status: str = "active") -> int:
        """Return count of agents by status ('active' or 'inactive' or 'all')."""
        if status == "active":
            return self._r.scard("agent:index:active") or 0
        if status == "all":
            return self._r.scard("agent:index:all") or 0
        # inactive = all - active
        total = self._r.scard("agent:index:all") or 0
        active = self._r.scard("agent:index:active") or 0
        return max(0, total - active)

    # ── Internal ─────────────────────────────────────────────────────────────

    def _update_last_seen(self, agent_id: str) -> None:
        reg_key = f"agent:reg:{agent_id}"
        self._r.hset(reg_key, b"last_seen_at", _now_iso().encode("utf-8"))

    @staticmethod
    def _decode_agent(agent_id: str, raw: dict) -> dict:
        """Decode Redis hash (bytes keys/values) into a Python dict."""

        def _b(key: bytes) -> str:
            val = raw.get(key, b"")
            return val.decode("utf-8") if isinstance(val, bytes) else val

        def _j(key: bytes) -> list:
            try:
                return json.loads(_b(key))
            except Exception:
                return []

        return {
            "agent_id": agent_id,
            "name": _b(b"name"),
            "upstream_url": _b(b"upstream_url"),
            "protocol": _b(b"protocol") or "openai",
            "status": _b(b"status"),
            "created_at": _b(b"created_at"),
            "last_seen_at": _b(b"last_seen_at"),
            "groups": _j(b"groups"),
            "allowed_caller_groups": _j(b"allowed_caller_groups"),
            "allowed_paths": _j(b"allowed_paths"),
            "allowed_cidrs": _j(b"allowed_cidrs"),
            # v0.9.0 — token rotation fields (F-09)
            "token_last_rotated": _b(b"token_last_rotated"),
            "token_rotation_schedule": _b(b"token_rotation_schedule"),
        }
