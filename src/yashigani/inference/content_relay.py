"""
Content relay detection — identifies potential content laundering attacks.

Attack pattern: Agent A returns sensitive content → Agent B embeds it in a
"clean" prompt → content bypasses PII/sensitivity detection at the gateway.

Defence: hash response content from agent-to-agent calls, store briefly in
Redis. On subsequent /v1 requests, check if prompt contains substantial
chunks that match recent agent response hashes. If so, flag for review.

Uses rolling SHA-256 hashes on 256-char sliding windows for fuzzy matching
without storing actual content.
"""
from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)

_WINDOW_SIZE = 256       # characters per hash window
_STEP_SIZE = 128         # overlap between windows
_TTL_SECONDS = 300       # 5 minutes — agent chains should resolve quickly
_KEY_PREFIX = "relay:hash:"
_ALERT_THRESHOLD = 3     # minimum matching windows to flag


@dataclass
class RelayDetectionResult:
    """Result of content relay check."""
    relay_detected: bool
    matching_windows: int
    source_agent: str       # agent whose response matched (empty if no match)
    confidence: float       # 0.0-1.0


class ContentRelayDetector:
    """
    Detects content laundering in agent-to-agent communication.

    Call record_agent_response() when an agent returns a response.
    Call check_request() on incoming /v1 requests.
    """

    def __init__(self, redis_client) -> None:
        self._redis = redis_client

    def record_agent_response(
        self,
        agent_id: str,
        response_text: str,
    ) -> int:
        """
        Hash the agent's response content and store in Redis.
        Returns the number of hash windows stored.
        """
        if not response_text or len(response_text) < _WINDOW_SIZE:
            return 0

        pipe = self._redis.pipeline(transaction=False)
        count = 0
        for i in range(0, len(response_text) - _WINDOW_SIZE + 1, _STEP_SIZE):
            window = response_text[i:i + _WINDOW_SIZE]
            h = hashlib.sha256(window.lower().encode()).hexdigest()[:16]
            key = f"{_KEY_PREFIX}{h}"
            pipe.setex(key, _TTL_SECONDS, f"{agent_id}:{int(time.time())}")
            count += 1
        pipe.execute()
        return count

    def check_request(
        self,
        prompt_text: str,
    ) -> RelayDetectionResult:
        """
        Check if incoming prompt contains content from recent agent responses.
        """
        if not prompt_text or len(prompt_text) < _WINDOW_SIZE:
            return RelayDetectionResult(
                relay_detected=False, matching_windows=0,
                source_agent="", confidence=0.0,
            )

        matches = 0
        source_agents: dict[str, int] = {}

        pipe = self._redis.pipeline(transaction=False)
        windows = []
        for i in range(0, len(prompt_text) - _WINDOW_SIZE + 1, _STEP_SIZE):
            window = prompt_text[i:i + _WINDOW_SIZE]
            h = hashlib.sha256(window.lower().encode()).hexdigest()[:16]
            key = f"{_KEY_PREFIX}{h}"
            pipe.get(key)
            windows.append(key)

        results = pipe.execute()
        for val in results:
            if val:
                matches += 1
                agent_id = val.split(":")[0] if isinstance(val, str) else val.decode().split(":")[0]
                source_agents[agent_id] = source_agents.get(agent_id, 0) + 1

        total_windows = max(1, len(windows))
        confidence = min(1.0, matches / total_windows)
        top_agent = max(source_agents, key=lambda k: source_agents.get(k, 0)) if source_agents else ""

        detected = matches >= _ALERT_THRESHOLD
        if detected:
            logger.warning(
                "Content relay detected: %d/%d windows match, source_agent=%s, confidence=%.2f",
                matches, total_windows, top_agent, confidence,
            )

        return RelayDetectionResult(
            relay_detected=detected,
            matching_windows=matches,
            source_agent=top_agent,
            confidence=confidence,
        )
