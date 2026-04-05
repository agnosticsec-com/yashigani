"""
Yashigani PII detection package.

Public surface:
    PiiDetector  — main detector class (regex-based, no external deps)
    PiiResult    — scan outcome dataclass
    PiiFinding   — single match dataclass
    PiiMode      — LOG | REDACT | BLOCK
    PiiType      — SSN | CREDIT_CARD | EMAIL | PHONE | IBAN | PASSPORT |
                   NHS_NUMBER | DRIVERS_LICENCE | IP_ADDRESS | DATE_OF_BIRTH
"""
from yashigani.pii.detector import (
    PiiDetector,
    PiiFinding,
    PiiMode,
    PiiResult,
    PiiType,
)

__all__ = [
    "PiiDetector",
    "PiiFinding",
    "PiiMode",
    "PiiResult",
    "PiiType",
]
