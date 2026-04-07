"""
FastText first-pass content classifier — Phase 12.

Model bundled in gateway image at /app/models/fasttext_classifier.bin.
Inference < 5ms. Two-stage pipeline:
  confidence >= high_threshold (0.8) → direct decision (CLEAN or UNSAFE)
  confidence < high_threshold        → UNCERTAIN → LLM second-pass

If model unavailable, returns UNCERTAIN (always routes to LLM).
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

MODEL_PATH = os.getenv("FASTTEXT_MODEL_PATH", "/app/models/fasttext_classifier.bin")
DEFAULT_HIGH_THRESHOLD = 0.8
DEFAULT_LOW_THRESHOLD = 0.4


@dataclass
class FastTextResult:
    label: str           # "CLEAN" | "UNSAFE" | "UNCERTAIN"
    confidence: float
    latency_ms: float
    needs_llm_pass: bool


class FastTextBackend:
    name = "fasttext"

    def __init__(
        self,
        model_path: str = MODEL_PATH,
        high_threshold: float = DEFAULT_HIGH_THRESHOLD,
        low_threshold: float = DEFAULT_LOW_THRESHOLD,
    ) -> None:
        self._model_path = model_path
        self._high_threshold = high_threshold
        self._low_threshold = low_threshold
        self._model = None
        self._available = False
        self._load_model()

    def _load_model(self) -> None:
        if not os.path.exists(self._model_path):
            logger.warning(
                "FastText model not found at %s — disabled. All requests use LLM second-pass.",
                self._model_path,
            )
            return
        try:
            import fasttext
            self._model = fasttext.load_model(self._model_path)
            self._available = True
            logger.info("FastText model loaded from %s", self._model_path)
        except ImportError:
            logger.warning("fasttext package not installed — FastText classifier disabled")
        except Exception as exc:
            logger.error("FastText model load error: %s", exc)

    @property
    def model_path(self) -> str:
        return self._model_path

    @property
    def available(self) -> bool:
        return self._available

    def classify(self, text: str) -> FastTextResult:
        """Classify text. Returns FastTextResult. Never raises."""
        if not self._available or self._model is None:
            return FastTextResult(label="UNCERTAIN", confidence=0.0, latency_ms=0.0, needs_llm_pass=True)

        start = time.monotonic()
        try:
            clean_text = text.replace("\n", " ").replace("\r", " ").strip()
            if not clean_text:
                return FastTextResult(label="CLEAN", confidence=1.0, latency_ms=0.0, needs_llm_pass=False)

            import numpy as np
            # Workaround for numpy >= 2.0 + fasttext compatibility:
            # fasttext internally calls np.array(x, copy=False) which numpy 2.0
            # changed to raise ValueError. Temporarily patch np.array if needed.
            _orig_array = np.array
            def _compat_array(*args, **kwargs):
                kwargs.pop("copy", None)
                return _orig_array(*args, **kwargs)
            np.array = _compat_array
            try:
                labels, probabilities = self._model.predict(clean_text, k=2)
            finally:
                np.array = _orig_array
            latency_ms = (time.monotonic() - start) * 1000
            primary_label_raw = labels[0].replace("__label__", "").upper()
            confidence = float(probabilities[0])

            self._record_metrics(primary_label_raw, confidence, latency_ms)

            if confidence >= self._high_threshold:
                label = "CLEAN" if "CLEAN" in primary_label_raw else "UNSAFE"
                return FastTextResult(label=label, confidence=confidence, latency_ms=latency_ms, needs_llm_pass=False)
            else:
                return FastTextResult(label="UNCERTAIN", confidence=confidence, latency_ms=latency_ms, needs_llm_pass=True)

        except Exception as exc:
            latency_ms = (time.monotonic() - start) * 1000
            logger.error("FastText classify error: %s", exc)
            return FastTextResult(label="UNCERTAIN", confidence=0.0, latency_ms=latency_ms, needs_llm_pass=True)

    def _record_metrics(self, label: str, confidence: float, latency_ms: float) -> None:
        try:
            from yashigani.metrics.registry import fasttext_classifications_total, fasttext_latency_ms
            result = "clean" if "CLEAN" in label else "unsafe"
            if confidence < self._high_threshold:
                result = "uncertain"
            fasttext_classifications_total.labels(result=result).inc()
            fasttext_latency_ms.observe(latency_ms)
        except Exception:
            pass

    def update_thresholds(self, high: float, low: float) -> None:
        self._high_threshold = high
        self._low_threshold = low
        logger.info("FastText thresholds updated: high=%.2f low=%.2f", high, low)
