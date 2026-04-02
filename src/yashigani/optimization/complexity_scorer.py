"""
Yashigani Optimization — Complexity scorer.

Evaluates whether a local model can handle a request well, based on:
  - Token count (primary signal)
  - Content heuristics (code blocks, math, structured data)

Returns LOW (prefer local), MEDIUM (policy decides), HIGH (prefer cloud).
All thresholds are admin-configurable.
"""
from __future__ import annotations

import enum
import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class ComplexityLevel(str, enum.Enum):
    LOW = "LOW"        # Local model can handle well
    MEDIUM = "MEDIUM"  # Policy decides
    HIGH = "HIGH"      # Cloud model preferred


@dataclass(frozen=True)
class ComplexityResult:
    """Result of complexity scoring."""
    level: ComplexityLevel
    token_count: int
    heuristic_score: float  # 0.0 - 1.0, higher = more complex
    reasons: list[str]


# Default heuristic weights
_CODE_BLOCK_WEIGHT = 0.3
_MATH_WEIGHT = 0.2
_STRUCTURED_DATA_WEIGHT = 0.2
_MULTI_LANGUAGE_WEIGHT = 0.1
_LONG_CONTEXT_WEIGHT = 0.2

# Heuristic detection patterns
_CODE_BLOCK_RE = re.compile(r"```[\s\S]*?```", re.MULTILINE)
_MATH_RE = re.compile(r"(?:\$\$.+?\$\$|\\\(.+?\\\)|\b(?:integral|derivative|equation|theorem|proof)\b)", re.IGNORECASE)
_STRUCTURED_RE = re.compile(r"(?:\{[\s\S]*?\}|\[[\s\S]*?\]|<[a-zA-Z]+[\s\S]*?>)", re.MULTILINE)
_CHARS_PER_TOKEN = 4


class ComplexityScorer:
    """
    Score request complexity to inform the Optimization Engine.

    Admin-configurable token threshold (default 2000).
    Heuristic score adds weight for complex content types.
    """

    def __init__(
        self,
        token_threshold: int = 2000,
        heuristic_threshold: float = 0.5,
    ) -> None:
        """
        Args:
            token_threshold: Token count above which complexity is HIGH (default 2000)
            heuristic_threshold: Heuristic score above which to bump complexity up
        """
        self._token_threshold = token_threshold
        self._heuristic_threshold = heuristic_threshold
        logger.info(
            "ComplexityScorer: token_threshold=%d, heuristic_threshold=%.2f",
            token_threshold, heuristic_threshold,
        )

    def score(self, text: str, token_count: int | None = None) -> ComplexityResult:
        """
        Score the complexity of a request.

        Args:
            text: The prompt/message content
            token_count: Pre-computed token count (if available). Estimated from text if None.

        Returns:
            ComplexityResult with level, token count, heuristic score, and reasons
        """
        if token_count is None:
            token_count = max(1, len(text) // _CHARS_PER_TOKEN)

        reasons = []
        heuristic_score = 0.0

        # Token count signal
        if token_count >= self._token_threshold:
            reasons.append(f"tokens={token_count} (>= {self._token_threshold})")

        # Heuristic signals
        code_blocks = len(_CODE_BLOCK_RE.findall(text))
        if code_blocks > 0:
            heuristic_score += _CODE_BLOCK_WEIGHT * min(code_blocks, 3) / 3
            reasons.append(f"code_blocks={code_blocks}")

        math_matches = len(_MATH_RE.findall(text))
        if math_matches > 0:
            heuristic_score += _MATH_WEIGHT
            reasons.append(f"math_content={math_matches}")

        structured_matches = len(_STRUCTURED_RE.findall(text))
        if structured_matches > 2:
            heuristic_score += _STRUCTURED_DATA_WEIGHT
            reasons.append(f"structured_data={structured_matches}")

        # Long context (> 1000 tokens even if below threshold)
        if token_count > 1000:
            heuristic_score += _LONG_CONTEXT_WEIGHT * min(token_count / self._token_threshold, 1.0)

        heuristic_score = min(heuristic_score, 1.0)

        # Determine level
        if token_count >= self._token_threshold:
            level = ComplexityLevel.HIGH
        elif heuristic_score >= self._heuristic_threshold:
            level = ComplexityLevel.HIGH
            reasons.append(f"heuristic={heuristic_score:.2f} (>= {self._heuristic_threshold})")
        elif token_count < self._token_threshold // 2 and heuristic_score < 0.2:
            level = ComplexityLevel.LOW
        else:
            level = ComplexityLevel.MEDIUM

        return ComplexityResult(
            level=level,
            token_count=token_count,
            heuristic_score=round(heuristic_score, 3),
            reasons=reasons,
        )

    def update_threshold(self, token_threshold: int) -> None:
        """Update the token threshold (admin action)."""
        self._token_threshold = token_threshold
        logger.info("ComplexityScorer: threshold updated to %d", token_threshold)
