"""
MCP Broker — v1 prompt-injection content filter (M4).

Implements the Phase-2 M4 SHIP-BLOCKER finding:

  When the broker fetches a tool catalogue (tools/list) or a prompt
  (prompts/get), each tool description / prompt text is run through this
  filter BEFORE it can reach the downstream agent.

Filter pipeline (per description/prompt text):
  1. NFKC-normalise the input (collapses ligatures, fullwidth chars used to
     evade byte-level pattern matching).
  2. 2048-char hard cap — reject anything over the cap (large blobs have no
     legitimate place in a tool description).
  3. Control-char scan — reject any text containing ASCII control characters
     outside the normal printable/whitespace range (0x00-0x1F except 0x09/
     0x0A/0x0D, and 0x7F).  These are not valid prose.
  4. Pattern scan — case-insensitive search for prompt-injection markers.
     On match: the text is REJECTED (FilterResult.rejected=True) and a
     sanitised replacement is substituted ("") before being offered to the
     caller.  The caller decides whether to drop the tool/prompt entirely
     or pass the replacement.

Per-tenant catalogue isolation:
  ToolCatalogueStore holds catalogues keyed by (tenant_id, server_id).
  Catalogues are NEVER shared across tenants.

Audit:
  Callers MUST emit McpToolDescriptionFetchedEvent after every fetch; see
  broker.py fetch_and_filter_tools() / fetch_and_filter_prompt() for
  integration.

TODO [M4-v2]: replace heuristic pattern set with an LLM-classifier sidecar
              (off-by-default, operator-opt-in, rate-limited).  The v1
              heuristic approach is conservative by design — it rejects
              injections that match common patterns and caps description size;
              it does NOT catch all semantic injection variants.

v2.25.0 / P1 Phase-2 / M4 / YSG-RISK-054 (tool-description audit) /
  LAURA-MCP-005 (injection vector in tool descriptions).
"""
from __future__ import annotations

import re
import threading
import unicodedata
from dataclasses import dataclass, field
from typing import Optional

_MAX_DESCRIPTION_CHARS: int = 2048
_REPLACEMENT_TEXT: str = ""   # substituted for a rejected description

# ---------------------------------------------------------------------------
# Pattern set — v1 heuristic
#
# Design notes:
#   • Applied AFTER NFKC normalisation — collapses lookalike chars.
#   • Case-insensitive (re.IGNORECASE).
#   • \b word-boundary anchors avoid false-positives on mid-word occurrences
#     (e.g. "systematic" must not match "system").
#   • The OR list is ordered longest-first where alternatives overlap so that
#     the more-specific variant is tried first; no correctness dependency.
#   • This is a conservative v1 set. It is expected to have false-positives
#     on unusual-but-legitimate tool descriptions.  Operator can whitelist
#     specific server_ids via allow_server_ids if needed in a future version.
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[str] = [
    # Direct override instructions
    r"\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\b",
    r"\bdisregard\s+(?:all\s+)?(?:previous|prior|above|earlier|the\s+above)\b",
    r"\bforget\b.{0,30}?\b(?:instructions?|context|rules?|guidelines?)\b",
    # Role/identity injection
    r"\byou\s+are\s+(?:now\s+)?(?:an?\s+)?(?:a\s+)?\S+",
    r"\bact\s+as\s+(?:an?\s+)?\S+",
    r"\bbehave\s+as\s+(?:an?\s+)?\S+",
    r"\bpretend\s+(?:to\s+be|you\s+are)\b",
    r"\brole[\s-]?play\b",
    # System/context manipulation markers
    r"\bSYSTEM\b",
    r"\b(?:NEW\s+)?SYSTEM\s+PROMPT\b",
    r"\bSYSTEM_PROMPT\b",
    r"\bINSTRUCTION[S]?\b",
    r"\bOVERRIDE\b",
    r"\bDAN\s+MODE\b",
    r"\bJAILBREAK\b",
    # Prompt-structure injection (attempts to inject fake turn boundaries)
    r"\bassistant\s*:",
    r"\buser\s*:",
    r"\bhuman\s*:",
    r"<\s*/?(?:system|assistant|user|human|im_start|im_end)\s*>",
    r"\[INST\]",
    r"\[/INST\]",
    # Confidentiality / leak instructions
    r"\breveal\b.{0,30}?\b(?:system\s+)?(?:prompt|instructions?|context|secrets?)\b",
    r"\brepeat\b.{0,30}?\b(?:system\s+)?(?:prompt|instructions?|context)\b",
    r"\bprint\b.{0,30}?\b(?:system\s+)?(?:prompt|instructions?|context)\b",
    r"\bshow\b.{0,30}?\b(?:system\s+)?(?:prompt|instructions?|context)\b",
    r"\bexfiltrat",
    # Separator / injection attempt signals
    r"---\s*SYSTEM\s*---",
    r"###\s*(?:SYSTEM|INSTRUCTION)",
    r"<\?xml",
    r"<\!DOCTYPE",
]

_COMPILED_PATTERN = re.compile(
    "|".join(f"(?:{p})" for p in _INJECTION_PATTERNS),
    re.IGNORECASE | re.DOTALL,
)

# Control characters outside normal whitespace (tab=0x09, LF=0x0A, CR=0x0D)
_CONTROL_CHAR_PATTERN = re.compile(
    r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]"
)


# ---------------------------------------------------------------------------
# FilterResult
# ---------------------------------------------------------------------------


@dataclass
class FilterResult:
    """
    Result of filtering a single tool description or prompt text.

    Attributes
    ----------
    original_length:
        Character length of the input BEFORE NFKC normalisation.
    normalised_length:
        Character length AFTER NFKC normalisation.
    rejected:
        True when the filter rejected the text (pattern match, over-cap,
        or control-char hit).  The caller should use ``safe_text`` instead.
    reject_reason:
        Human-readable rejection reason; empty string when not rejected.
    safe_text:
        The text to use downstream.  When not rejected, this is the
        NFKC-normalised input (identical semantics, normalised encoding).
        When rejected, this is ``_REPLACEMENT_TEXT`` ("").
    matched_pattern:
        The first pattern that matched (for audit logging only).
        Never sent to the downstream agent.
    """

    original_length: int
    normalised_length: int
    rejected: bool
    reject_reason: str
    safe_text: str
    matched_pattern: Optional[str] = None


def filter_description(text: str) -> FilterResult:
    """
    Run the M4 content filter on a single tool description or prompt text.

    Returns a FilterResult.  The caller is responsible for emitting the
    audit event (McpToolDescriptionFetchedEvent) — see broker.py.

    Thread-safe (stateless function; uses pre-compiled regex).
    """
    original_length = len(text)

    # Step 1: NFKC normalise
    normalised = unicodedata.normalize("NFKC", text)
    normalised_length = len(normalised)

    # Step 2: 2048-char cap (applied AFTER normalisation)
    if normalised_length > _MAX_DESCRIPTION_CHARS:
        return FilterResult(
            original_length=original_length,
            normalised_length=normalised_length,
            rejected=True,
            reject_reason=f"over_char_cap:{normalised_length}>{_MAX_DESCRIPTION_CHARS}",
            safe_text=_REPLACEMENT_TEXT,
        )

    # Step 3: control-char scan
    ctrl_match = _CONTROL_CHAR_PATTERN.search(normalised)
    if ctrl_match:
        return FilterResult(
            original_length=original_length,
            normalised_length=normalised_length,
            rejected=True,
            reject_reason=f"control_char:0x{ord(ctrl_match.group()):02X}",
            safe_text=_REPLACEMENT_TEXT,
        )

    # Step 4: injection pattern scan
    pattern_match = _COMPILED_PATTERN.search(normalised)
    if pattern_match:
        return FilterResult(
            original_length=original_length,
            normalised_length=normalised_length,
            rejected=True,
            reject_reason="injection_pattern",
            safe_text=_REPLACEMENT_TEXT,
            matched_pattern=pattern_match.group()[:64],  # truncated for audit only
        )

    # Clean — pass through NFKC-normalised text
    return FilterResult(
        original_length=original_length,
        normalised_length=normalised_length,
        rejected=False,
        reject_reason="",
        safe_text=normalised,
    )


# ---------------------------------------------------------------------------
# Tool catalogue entry + per-tenant store
# ---------------------------------------------------------------------------


@dataclass
class ToolDescriptor:
    """
    A single tool entry from a tools/list response, after filtering.

    ``safe_description`` is the value that MUST be sent downstream.
    ``filter_result`` is retained for audit emission only — never forward it.
    """

    tool_name: str
    safe_description: str
    filter_result: FilterResult


@dataclass
class PromptDescriptor:
    """
    A single prompt entry from a prompts/get response, after filtering.
    """

    prompt_name: str
    safe_content: str
    filter_result: FilterResult


@dataclass
class TenantCatalogue:
    """
    Filtered tool + prompt catalogue for one (tenant_id, server_id) pair.

    Per-tenant isolation: never shared across tenant_ids.
    """

    tenant_id: str
    server_id: str
    tools: list[ToolDescriptor] = field(default_factory=list)
    prompts: list[PromptDescriptor] = field(default_factory=list)

    # Aggregate stats for audit emission
    @property
    def tool_count(self) -> int:
        return len(self.tools)

    @property
    def filtered_tool_count(self) -> int:
        """Tools whose description was NFKC-normalised (may or may not have been rejected)."""
        return sum(
            1 for t in self.tools
            if t.filter_result.normalised_length != t.filter_result.original_length
        )

    @property
    def rejected_tool_count(self) -> int:
        return sum(1 for t in self.tools if t.filter_result.rejected)

    @property
    def prompt_count(self) -> int:
        return len(self.prompts)

    @property
    def rejected_prompt_count(self) -> int:
        return sum(1 for p in self.prompts if p.filter_result.rejected)


class ToolCatalogueStore:
    """
    Per-tenant in-memory catalogue store.

    Keyed by (tenant_id, server_id).  Never shares entries across tenant_ids.

    Thread-safety: a single threading.Lock guards all mutations.  In
    production, callers update the catalogue on every tools/list fetch and
    read on every mcp.tools.call — reads and writes are fast (in-memory dict).

    Production note: in a multi-worker deployment, this in-memory store is
    per-process.  Each worker maintains its own independent catalogue.  This
    is acceptable for v1 — catalogue staleness across workers is bounded by
    the refresh interval and does not create a cross-tenant leak because keys
    include tenant_id.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._store: dict[tuple[str, str], TenantCatalogue] = {}

    def store(self, catalogue: TenantCatalogue) -> None:
        """Replace the catalogue for (tenant_id, server_id)."""
        key = (catalogue.tenant_id, catalogue.server_id)
        with self._lock:
            self._store[key] = catalogue

    def get(self, tenant_id: str, server_id: str) -> Optional[TenantCatalogue]:
        """Retrieve the catalogue for (tenant_id, server_id), or None."""
        key = (tenant_id, server_id)
        with self._lock:
            return self._store.get(key)

    def evict(self, tenant_id: str, server_id: str) -> None:
        """Remove the catalogue for (tenant_id, server_id) if present."""
        key = (tenant_id, server_id)
        with self._lock:
            self._store.pop(key, None)

    def evict_tenant(self, tenant_id: str) -> int:
        """Remove all catalogues for a tenant; returns count removed."""
        with self._lock:
            to_remove = [k for k in self._store if k[0] == tenant_id]
            for k in to_remove:
                del self._store[k]
        return len(to_remove)

    def size(self) -> int:
        with self._lock:
            return len(self._store)


def build_catalogue(
    tenant_id: str,
    server_id: str,
    raw_tools: list[dict],
    raw_prompts: Optional[list[dict]] = None,
) -> TenantCatalogue:
    """
    Build a TenantCatalogue from raw tools/list and optional prompts/list
    responses by running each description through filter_description().

    Parameters
    ----------
    tenant_id:
        Tenant the catalogue belongs to.
    server_id:
        Upstream MCP server identifier.
    raw_tools:
        List of tool dicts from the tools/list response.  Each dict is
        expected to have at least ``name`` (str) and ``description`` (str).
        Missing keys are tolerated — treated as empty string.
    raw_prompts:
        List of prompt dicts from prompts/list or prompts/get.  Expected
        keys: ``name`` (str) and ``description``/``content`` (str).
    """
    tools: list[ToolDescriptor] = []
    for raw in raw_tools:
        name = str(raw.get("name") or "")
        desc = str(raw.get("description") or "")
        result = filter_description(desc)
        tools.append(ToolDescriptor(
            tool_name=name,
            safe_description=result.safe_text,
            filter_result=result,
        ))

    prompts: list[PromptDescriptor] = []
    for raw in (raw_prompts or []):
        name = str(raw.get("name") or "")
        # MCP prompts/get response uses "content" or "description"
        content = str(raw.get("content") or raw.get("description") or "")
        result = filter_description(content)
        prompts.append(PromptDescriptor(
            prompt_name=name,
            safe_content=result.safe_text,
            filter_result=result,
        ))

    return TenantCatalogue(
        tenant_id=tenant_id,
        server_id=server_id,
        tools=tools,
        prompts=prompts,
    )
