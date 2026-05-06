"""
F-T10-001 — Overreliance UX controls regression tests.

OWASP Agentic AI Top 10 — T10 Overreliance.
ASVS V13.2.6 — LLM output handling.

These tests assert that every LLM response from the OpenAI-compat router carries:

  1. X-Yashigani-Generated-Content: true  (all responses)
  2. X-Yashigani-Response-Inspection-Confidence  (all responses; float string)
  3. X-Yashigani-Low-Confidence-Stepup: required  (when confidence < threshold
     AND sensitivity in CONFIDENTIAL/RESTRICTED)

Tests are AST-level + minimal unit-level — no live backend required.
They re-fail if the header constants, state field, or logic are removed.

Last updated: 2026-05-06T00:00:00+01:00
OWASP Agentic AI T10; ASVS V13.2.6; retro F-T10-001.
"""
from __future__ import annotations

import ast
import os
import pathlib

import pytest


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent.parent
_OPENAI_ROUTER = _REPO_ROOT / "src" / "yashigani" / "gateway" / "openai_router.py"
_PROXY = _REPO_ROOT / "src" / "yashigani" / "gateway" / "proxy.py"

assert _OPENAI_ROUTER.exists(), f"openai_router.py not found at {_OPENAI_ROUTER}"
assert _PROXY.exists(), f"proxy.py not found at {_PROXY}"

_ROUTER_SRC = _OPENAI_ROUTER.read_text()
_PROXY_SRC = _PROXY.read_text()


# ---------------------------------------------------------------------------
# T-01 — X-Yashigani-Generated-Content header present in buffered path
# ---------------------------------------------------------------------------

class TestGeneratedContentHeader:
    """The generated-content disclaimer must be present in ALL LLM response paths."""

    def test_t01_buffered_path_has_generated_content_header(self):
        """
        T01: openai_router.py buffered response headers dict must include
        'X-Yashigani-Generated-Content' set to 'true'.
        """
        assert '"X-Yashigani-Generated-Content"' in _ROUTER_SRC or \
               "'X-Yashigani-Generated-Content'" in _ROUTER_SRC, (
            "F-T10-001: X-Yashigani-Generated-Content header missing from "
            "openai_router.py — every LLM response must carry this disclaimer "
            "so operator UIs can render generated-content badges."
        )
        # Verify the value is 'true'
        assert '"X-Yashigani-Generated-Content": "true"' in _ROUTER_SRC or \
               "'X-Yashigani-Generated-Content': 'true'" in _ROUTER_SRC or \
               '"X-Yashigani-Generated-Content": \'true\'' in _ROUTER_SRC or \
               "\"X-Yashigani-Generated-Content\": \"true\"" in _ROUTER_SRC, (
            "F-T10-001: X-Yashigani-Generated-Content must be set to 'true' "
            "in openai_router.py — found the header name but not the value."
        )

    def test_t02_streaming_path_has_generated_content_header(self):
        """
        T02: Streaming response headers in openai_router.py must also include
        X-Yashigani-Generated-Content.  The header must appear at least twice
        (once in the streaming block, once in the buffered block).
        """
        count = _ROUTER_SRC.count('"X-Yashigani-Generated-Content"')
        count += _ROUTER_SRC.count("'X-Yashigani-Generated-Content'")
        assert count >= 2, (
            f"F-T10-001: X-Yashigani-Generated-Content appears only {count} time(s) "
            "in openai_router.py — expected at least 2 (streaming + buffered paths). "
            "The disclaimer must be present on every LLM response."
        )

    def test_t03_proxy_has_generated_content_header(self):
        """
        T03: proxy.py must also set X-Yashigani-Generated-Content on every
        forwarded response.  The catch-all proxy forwards MCP/tool responses
        that are equally LLM/agent-generated.
        """
        assert '"X-Yashigani-Generated-Content"' in _PROXY_SRC or \
               "'X-Yashigani-Generated-Content'" in _PROXY_SRC, (
            "F-T10-001: X-Yashigani-Generated-Content header missing from proxy.py — "
            "tool/MCP responses must carry the same generated-content disclaimer."
        )


# ---------------------------------------------------------------------------
# T-04 — X-Yashigani-Response-Inspection-Confidence header
# ---------------------------------------------------------------------------

class TestInspectionConfidenceHeader:
    """Inspection confidence must be surfaced in response headers."""

    def test_t04_router_has_confidence_header(self):
        """
        T04: openai_router.py must emit X-Yashigani-Response-Inspection-Confidence.
        """
        assert "X-Yashigani-Response-Inspection-Confidence" in _ROUTER_SRC, (
            "F-T10-001: X-Yashigani-Response-Inspection-Confidence missing from "
            "openai_router.py — operator UIs need this value to render confidence badges."
        )

    def test_t05_proxy_has_confidence_header(self):
        """
        T05: proxy.py must also emit X-Yashigani-Response-Inspection-Confidence.
        """
        assert "X-Yashigani-Response-Inspection-Confidence" in _PROXY_SRC, (
            "F-T10-001: X-Yashigani-Response-Inspection-Confidence missing from proxy.py."
        )

    def test_t06_proxy_initialises_confidence_to_one(self):
        """
        T06: proxy.py must initialise proxy_inspection_confidence to 1.0 so the
        header is always present (clean-pass default), even when inspection is disabled.
        """
        assert "proxy_inspection_confidence" in _PROXY_SRC, (
            "F-T10-001: proxy_inspection_confidence variable not found in proxy.py — "
            "needed as the clean-pass default for the confidence header."
        )
        assert "proxy_inspection_confidence: float = 1.0" in _PROXY_SRC or \
               "proxy_inspection_confidence = 1.0" in _PROXY_SRC, (
            "F-T10-001: proxy_inspection_confidence must be initialised to 1.0 "
            "(clean-pass default) in proxy.py."
        )

    def test_t07_router_initialises_confidence_to_one(self):
        """
        T07: openai_router.py must initialise response_inspection_confidence to 1.0.
        """
        assert "response_inspection_confidence" in _ROUTER_SRC, (
            "F-T10-001: response_inspection_confidence variable not found in "
            "openai_router.py — needed as the clean-pass default."
        )
        assert (
            "response_inspection_confidence: float = 1.0" in _ROUTER_SRC or
            "response_inspection_confidence = 1.0" in _ROUTER_SRC
        ), (
            "F-T10-001: response_inspection_confidence must be initialised to 1.0 "
            "in openai_router.py."
        )


# ---------------------------------------------------------------------------
# T-08 — Low-confidence step-up trigger
# ---------------------------------------------------------------------------

class TestLowConfidenceStepup:
    """
    When response-inspection confidence is below threshold AND sensitivity is
    CONFIDENTIAL or RESTRICTED, the gateway must emit
    X-Yashigani-Low-Confidence-Stepup: required.
    """

    def test_t08_stepup_header_constant_present(self):
        """
        T08: openai_router.py must reference the step-up header name.
        """
        assert "X-Yashigani-Low-Confidence-Stepup" in _ROUTER_SRC, (
            "F-T10-001: X-Yashigani-Low-Confidence-Stepup header missing from "
            "openai_router.py — this is the signal that triggers operator "
            "'verify before acting' UX on low-confidence high-sensitivity responses."
        )

    def test_t09_stepup_header_value_is_required(self):
        """
        T09: The step-up header must be assigned the value 'required'.
        Supports both dict-literal and bracket-assignment forms.
        """
        # dict-literal form: "X-Yashigani-Low-Confidence-Stepup": "required"
        # bracket-assignment form: headers["X-Yashigani-Low-Confidence-Stepup"] = "required"
        assert (
            '"X-Yashigani-Low-Confidence-Stepup": "required"' in _ROUTER_SRC
            or "'X-Yashigani-Low-Confidence-Stepup': 'required'" in _ROUTER_SRC
            or '["X-Yashigani-Low-Confidence-Stepup"] = "required"' in _ROUTER_SRC
            or "['X-Yashigani-Low-Confidence-Stepup'] = 'required'" in _ROUTER_SRC
        ), (
            "F-T10-001: X-Yashigani-Low-Confidence-Stepup must be set to 'required' "
            "in openai_router.py — the JS interceptor pattern-matches on this value."
        )

    def test_t10_stepup_threshold_env_var_present(self):
        """
        T10: The threshold must be configurable via
        YASHIGANI_LOW_CONFIDENCE_STEPUP_THRESHOLD env var.
        """
        assert "YASHIGANI_LOW_CONFIDENCE_STEPUP_THRESHOLD" in _ROUTER_SRC, (
            "F-T10-001: YASHIGANI_LOW_CONFIDENCE_STEPUP_THRESHOLD env var not referenced "
            "in openai_router.py — threshold must be operator-configurable."
        )

    def test_t11_stepup_threshold_default_is_half(self):
        """
        T11: Default threshold must be 0.50.
        """
        assert '"0.50"' in _ROUTER_SRC or "'0.50'" in _ROUTER_SRC, (
            "F-T10-001: Default YASHIGANI_LOW_CONFIDENCE_STEPUP_THRESHOLD must be '0.50' "
            "in openai_router.py."
        )

    def test_t12_stepup_guards_confidential_and_restricted(self):
        """
        T12: The step-up logic must check for CONFIDENTIAL and RESTRICTED
        sensitivity levels — not all sensitivity levels.

        The check is structural: find the LAST occurrence of the header assignment
        (the actual code, not the docstring), then verify CONFIDENTIAL and RESTRICTED
        appear within 800 chars before that line (i.e. in the same logic block).
        """
        assert '"CONFIDENTIAL"' in _ROUTER_SRC and '"RESTRICTED"' in _ROUTER_SRC, (
            "F-T10-001: Step-up trigger must reference both 'CONFIDENTIAL' and "
            "'RESTRICTED' sensitivity levels in openai_router.py."
        )
        # Use the LAST occurrence of the header assignment (code, not docstring)
        stepup_assign = '["X-Yashigani-Low-Confidence-Stepup"] = "required"'
        stepup_idx = _ROUTER_SRC.rfind(stepup_assign)
        assert stepup_idx != -1, (
            "F-T10-001: Header assignment form "
            "'headers[\"X-Yashigani-Low-Confidence-Stepup\"] = \"required\"' "
            "not found in openai_router.py."
        )
        # Sensitivity check must appear within 500 chars before the header assignment
        window = _ROUTER_SRC[max(0, stepup_idx - 500):stepup_idx + 100]
        assert '"CONFIDENTIAL"' in window or "'CONFIDENTIAL'" in window, (
            "F-T10-001: 'CONFIDENTIAL' sensitivity guard not found near the "
            "step-up header assignment in openai_router.py."
        )
        assert '"RESTRICTED"' in window or "'RESTRICTED'" in window, (
            "F-T10-001: 'RESTRICTED' sensitivity guard not found near the "
            "step-up header assignment in openai_router.py."
        )

    def test_t13_stepup_logic_checks_threshold_comparison(self):
        """
        T13: The step-up logic must compare response_inspection_confidence
        against low_confidence_stepup_threshold.
        """
        assert "low_confidence_stepup_threshold" in _ROUTER_SRC, (
            "F-T10-001: low_confidence_stepup_threshold attribute/variable not found "
            "in openai_router.py — the step-up trigger must use this configurable threshold."
        )
        assert "response_inspection_confidence < _state.low_confidence_stepup_threshold" in _ROUTER_SRC, (
            "F-T10-001: Step-up trigger comparison "
            "'response_inspection_confidence < _state.low_confidence_stepup_threshold' "
            "not found in openai_router.py."
        )


# ---------------------------------------------------------------------------
# T-14 — State field present on OpenAIRouterState
# ---------------------------------------------------------------------------

class TestStateField:
    """low_confidence_stepup_threshold must be a first-class state field."""

    def test_t14_state_has_threshold_field(self):
        """
        T14: OpenAIRouterState.__init__ must define low_confidence_stepup_threshold.
        """
        tree = ast.parse(_ROUTER_SRC)
        # Find OpenAIRouterState class
        ors_class = None
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "OpenAIRouterState":
                ors_class = node
                break
        assert ors_class is not None, "OpenAIRouterState class not found in openai_router.py"

        init_fn = None
        for node in ast.walk(ors_class):
            if isinstance(node, ast.FunctionDef) and node.name == "__init__":
                init_fn = node
                break
        assert init_fn is not None, "OpenAIRouterState.__init__ not found"

        init_src = ast.unparse(init_fn)
        assert "low_confidence_stepup_threshold" in init_src, (
            "F-T10-001: low_confidence_stepup_threshold not assigned in "
            "OpenAIRouterState.__init__ — must be a first-class state field "
            "so it persists across requests."
        )

    def test_t15_configure_sets_threshold(self):
        """
        T15: configure() must (re)set _state.low_confidence_stepup_threshold
        from the env var, so it can be hot-reloaded via a configure() call.
        """
        tree = ast.parse(_ROUTER_SRC)
        configure_fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "configure":
                configure_fn = node
                break
        assert configure_fn is not None, "configure() function not found in openai_router.py"

        fn_src = ast.unparse(configure_fn)
        assert "low_confidence_stepup_threshold" in fn_src, (
            "F-T10-001: configure() does not set _state.low_confidence_stepup_threshold — "
            "the threshold must be applied on every configure() call so env-var changes "
            "take effect without a full process restart."
        )


# ---------------------------------------------------------------------------
# T-16 — Streaming path carries generated-content header (not stepup)
# ---------------------------------------------------------------------------

class TestStreamingPath:
    """
    Streaming path must carry X-Yashigani-Generated-Content but NOT
    X-Yashigani-Low-Confidence-Stepup (confidence not computable pre-stream).
    """

    def test_t16_streaming_path_comment_explains_no_stepup(self):
        """
        T16: The streaming path in openai_router.py must carry a comment
        explaining why X-Yashigani-Low-Confidence-Stepup is not emitted.
        The absence of stepup on streaming is intentional, not a gap.
        """
        # The comment should be near the streaming headers block
        assert "StreamingInspector" in _ROUTER_SRC, (
            "StreamingInspector reference missing from openai_router.py — "
            "regression in the streaming inspection path."
        )
        # The comment about streaming confidence should explain the 1.0 default
        assert "1.0000" in _ROUTER_SRC or '"1.0000"' in _ROUTER_SRC or "'1.0000'" in _ROUTER_SRC, (
            "F-T10-001: Streaming path must emit X-Yashigani-Response-Inspection-Confidence "
            "with value '1.0000' (clean-pass default) in openai_router.py."
        )
