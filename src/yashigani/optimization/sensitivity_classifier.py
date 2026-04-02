"""
Yashigani Optimization — Sensitivity classifier.

Three-layer pipeline, all ON by default:
  Layer 1: Regex patterns (microseconds) — CANNOT be disabled
  Layer 2: FastText classifier (milliseconds) — admin can opt-out
  Layer 3: Ollama deep scan (200-500ms) — admin can opt-out

Returns the HIGHEST sensitivity level detected by any layer.
Conservative: if any layer says RESTRICTED, the result is RESTRICTED.
"""
from __future__ import annotations

import enum
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


class SensitivityLevel(str, enum.Enum):
    """Data sensitivity classification levels."""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"

    @property
    def rank(self) -> int:
        return _LEVEL_RANK[self]


_LEVEL_RANK = {
    SensitivityLevel.PUBLIC: 0,
    SensitivityLevel.INTERNAL: 1,
    SensitivityLevel.CONFIDENTIAL: 2,
    SensitivityLevel.RESTRICTED: 3,
}


@dataclass
class SensitivityResult:
    """Result of sensitivity classification."""
    level: SensitivityLevel
    triggers: list[str] = field(default_factory=list)  # which patterns matched
    layer_results: dict[str, SensitivityLevel] = field(default_factory=dict)  # per-layer
    conflict: bool = False  # True if layers disagreed


# Default regex patterns (seeded in DB, loaded at startup)
_DEFAULT_PATTERNS: list[tuple[str, SensitivityLevel, str]] = [
    # (regex, level, description)
    (r"\b\d{3}-\d{2}-\d{4}\b", SensitivityLevel.CONFIDENTIAL, "US SSN"),
    (r"\b(?:\d[ -]*?){13,19}\b", SensitivityLevel.RESTRICTED, "Credit/debit card"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", SensitivityLevel.INTERNAL, "Email address"),
    (r"\b\d{3}[- ]?\d{3}[- ]?\d{4}\b", SensitivityLevel.CONFIDENTIAL, "US/CA phone"),
    (r"\b(?:sk-|sk-ant-|sk-proj-)[A-Za-z0-9_-]{20,}\b", SensitivityLevel.RESTRICTED, "API key"),
    (r"\b(?:CONFIDENTIAL|TOP SECRET|RESTRICTED)\b", SensitivityLevel.RESTRICTED, "Classification marker"),
    (r"\b[A-Z]{2}\d{2}[ ]?\d{4}[ ]?\d{4}[ ]?\d{4}[ ]?\d{4}[ ]?\d{0,2}\b", SensitivityLevel.CONFIDENTIAL, "IBAN"),
]


class SensitivityClassifier:
    """
    Three-layer sensitivity classification pipeline.

    Layer 1 (regex) cannot be disabled.
    Layers 2 and 3 are opt-out via constructor flags.
    """

    def __init__(
        self,
        patterns: list[tuple[str, SensitivityLevel, str]] | None = None,
        enable_fasttext: bool = True,
        enable_ollama: bool = True,
        fasttext_backend=None,
        ollama_url: str = "http://ollama:11434",
        ollama_model: str = "qwen2.5:3b",
    ) -> None:
        self._patterns = [
            (re.compile(p, re.IGNORECASE), level, desc)
            for p, level, desc in (patterns or _DEFAULT_PATTERNS)
        ]
        self._enable_fasttext = enable_fasttext
        self._enable_ollama = enable_ollama
        self._fasttext = fasttext_backend
        self._ollama_url = ollama_url
        self._ollama_model = ollama_model
        logger.info(
            "SensitivityClassifier: regex=%d patterns, fasttext=%s, ollama=%s",
            len(self._patterns), enable_fasttext, enable_ollama,
        )

    def classify(self, text: str) -> SensitivityResult:
        """
        Run all enabled layers and return the highest sensitivity detected.

        Args:
            text: The prompt or message content to classify

        Returns:
            SensitivityResult with level, triggers, and per-layer details
        """
        triggers = []
        layer_results = {}

        # Layer 1: Regex (always on, cannot be disabled)
        regex_level = self._scan_regex(text, triggers)
        layer_results["regex"] = regex_level

        # Layer 2: FastText (opt-out)
        fasttext_level = SensitivityLevel.PUBLIC
        if self._enable_fasttext and self._fasttext:
            try:
                fasttext_level = self._scan_fasttext(text, triggers)
                layer_results["fasttext"] = fasttext_level
            except Exception as exc:
                logger.warning("FastText sensitivity scan failed: %s", exc)
                layer_results["fasttext"] = SensitivityLevel.PUBLIC

        # Layer 3: Ollama deep scan (opt-out)
        ollama_level = SensitivityLevel.PUBLIC
        if self._enable_ollama:
            try:
                ollama_level = self._scan_ollama(text, triggers)
                layer_results["ollama"] = ollama_level
            except Exception as exc:
                logger.warning("Ollama sensitivity scan failed: %s", exc)
                layer_results["ollama"] = SensitivityLevel.PUBLIC

        # Take the highest (most conservative) result
        all_levels = [regex_level, fasttext_level, ollama_level]
        final_level = max(all_levels, key=lambda l: l.rank)

        # Detect conflicts between layers
        unique_levels = set(l for l in all_levels if l != SensitivityLevel.PUBLIC)
        conflict = len(unique_levels) > 1

        if conflict:
            logger.warning(
                "Sensitivity classification conflict: regex=%s fasttext=%s ollama=%s -> %s (conservative)",
                regex_level.value, fasttext_level.value, ollama_level.value, final_level.value,
            )

        return SensitivityResult(
            level=final_level,
            triggers=triggers,
            layer_results=layer_results,
            conflict=conflict,
        )

    def _scan_regex(self, text: str, triggers: list[str]) -> SensitivityLevel:
        """Layer 1: Regex pattern matching. Cannot be disabled."""
        highest = SensitivityLevel.PUBLIC
        for pattern, level, desc in self._patterns:
            if pattern.search(text):
                triggers.append(f"regex:{desc}")
                if level.rank > highest.rank:
                    highest = level
        return highest

    def _scan_fasttext(self, text: str, triggers: list[str]) -> SensitivityLevel:
        """Layer 2: FastText classifier."""
        if not self._fasttext:
            return SensitivityLevel.PUBLIC
        # FastText returns a label and confidence
        label, confidence = self._fasttext.predict(text)
        if confidence > 0.5:
            level = _label_to_level(label)
            if level != SensitivityLevel.PUBLIC:
                triggers.append(f"fasttext:{label}({confidence:.2f})")
            return level
        return SensitivityLevel.PUBLIC

    def _scan_ollama(self, text: str, triggers: list[str]) -> SensitivityLevel:
        """Layer 3: Ollama deep contextual scan."""
        try:
            import httpx
            prompt = (
                "Classify the sensitivity of the following text. "
                "Reply with ONLY one word: PUBLIC, INTERNAL, CONFIDENTIAL, or RESTRICTED.\n"
                "Rules:\n"
                "- RESTRICTED: contains credit card numbers, API keys, passwords, government classified info\n"
                "- CONFIDENTIAL: contains SSN, phone numbers, IBAN, medical records, personally identifiable info\n"
                "- INTERNAL: contains email addresses, internal project names, employee names\n"
                "- PUBLIC: no sensitive data detected\n\n"
                f"Text: {text[:2000]}\n\n"  # Truncate to avoid overwhelming small models
                "Classification:"
            )
            resp = httpx.post(
                f"{self._ollama_url}/api/generate",
                json={"model": self._ollama_model, "prompt": prompt, "stream": False},
                timeout=10.0,
            )
            if resp.status_code == 200:
                body = resp.json()
                answer = body.get("response", "").strip().upper()
                for level in SensitivityLevel:
                    if level.value in answer:
                        if level != SensitivityLevel.PUBLIC:
                            triggers.append(f"ollama:{level.value}")
                        return level
        except Exception as exc:
            logger.warning("Ollama sensitivity scan error: %s", exc)
        return SensitivityLevel.PUBLIC

    def add_pattern(self, pattern: str, level: SensitivityLevel, description: str) -> None:
        """Add a custom regex pattern at runtime."""
        self._patterns.append((re.compile(pattern, re.IGNORECASE), level, description))

    def reload_patterns(self, patterns: list[tuple[str, SensitivityLevel, str]]) -> None:
        """Replace all patterns (e.g. after admin updates via API)."""
        self._patterns = [
            (re.compile(p, re.IGNORECASE), level, desc)
            for p, level, desc in patterns
        ]
        logger.info("SensitivityClassifier: reloaded %d patterns", len(self._patterns))


def _label_to_level(label: str) -> SensitivityLevel:
    """Map a FastText label to a sensitivity level."""
    label = label.upper().replace("__LABEL__", "").strip()
    for level in SensitivityLevel:
        if level.value in label:
            return level
    return SensitivityLevel.PUBLIC
