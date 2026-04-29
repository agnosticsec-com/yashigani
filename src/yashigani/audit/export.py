"""
Yashigani Audit — Streaming log exporter.
Reads from volume sink log files and streams JSON or CSV output.
Never buffers the full result set in memory.
"""
# Last updated: 2026-04-27T00:00:00+01:00
from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Optional

from yashigani.audit.config import AuditConfig


# ---------------------------------------------------------------------------
# V1.2.10 — CSV formula injection prevention (CWE-1236)
# LF-CSV-BYPASS fix: leading-whitespace bypass closed (2026-04-27).
#
# Excel / LibreOffice strip leading whitespace BEFORE evaluating cell content,
# so " =cmd..." is treated as "=cmd..." and executed as a formula.
# The original fix normalised \n/\r to space BEFORE the trigger check, which
# converted "\r=cmd..." into " =cmd..." — bypassing startswith("=").
#
# Fix: strip leading whitespace from a copy of the string first, then test
# the stripped copy for formula triggers.  The original (with embedded spaces
# preserved for readability) is what gets returned with the single-quote prefix.
#
# Triggers: = + - @ \t \r  and their BOM-prefixed variants (﻿= ﻿+ ﻿- ﻿@).
# Leading whitespace class: space, \t, \n, \r, \v, \f, BOM (U+FEFF).
# ---------------------------------------------------------------------------

_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r", "﻿=", "﻿+", "﻿-", "﻿@")
_LEADING_WHITESPACE = re.compile(r"^[\s﻿]+")


def escape_csv_cell(v: object) -> str:
    """
    Sanitise a single CSV cell value.

    - Replaces embedded \\n and \\r with a space (prevents row-splitting
      injection, i.e. an attacker inserting a newline to inject a new CSV row).
    - Prefixes formula-trigger characters with a single quote so spreadsheet
      applications (Excel, LibreOffice, Google Sheets) do not execute the cell
      as a formula.

    LF-CSV-BYPASS (2026-04-27): the trigger test is performed on a *stripped*
    copy of the string — leading whitespace (space, \\t, \\n, \\r, \\v, \\f,
    BOM) is removed before the startswith check.  This closes the bypass where
    "\\r=cmd..." was normalised to " =cmd..." and then passed the trigger check
    because startswith("=") returned False on the space-prefixed string.

    The returned value always carries the leading whitespace from the original
    string so the cell content is not silently modified beyond the safety prefix.

    Safe for all non-trigger values: returned unchanged after newline
    normalisation.
    """
    s = str(v).replace("\n", " ").replace("\r", " ")
    # Strip leading whitespace/BOM before the trigger check — this is what
    # spreadsheet engines do before deciding whether to evaluate a formula.
    s_stripped = _LEADING_WHITESPACE.sub("", s)
    if s_stripped.startswith(_FORMULA_TRIGGERS):
        return "'" + s
    return s


class AuditLogExporter:

    def __init__(self, config: AuditConfig) -> None:
        self._log_path = Path(config.log_path)

    async def export(
        self,
        start_date: str,
        end_date: str,
        format: str = "json",
    ) -> AsyncIterator[bytes]:
        """
        Stream audit records within [start_date, end_date] (ISO 8601 dates).
        format: 'json' (NDJSON) | 'csv'
        """
        if format not in ("json", "csv"):
            raise ValueError(f"Unsupported export format: {format!r}")

        log_files = self._collect_log_files()
        lines = self._iter_lines_in_range(log_files, start_date, end_date)

        if format == "json":
            async for chunk in self._stream_json(lines):
                yield chunk
        else:
            async for chunk in self._stream_csv(lines):
                yield chunk

    # -- File collection -----------------------------------------------------

    def _collect_log_files(self) -> list[Path]:
        """Return the active log file and all rotated files, oldest first."""
        parent = self._log_path.parent
        rotated = sorted(parent.glob("audit.log.*"))
        files = rotated
        if self._log_path.exists():
            files = files + [self._log_path]
        return files

    # -- Line iteration ------------------------------------------------------

    def _iter_lines_in_range(
        self,
        files: list[Path],
        start_date: str,
        end_date: str,
    ):
        """Yield parsed dicts for log lines whose timestamp falls in range."""
        # Normalise to date prefix for simple string comparison (ISO 8601)
        start_prefix = start_date[:10]
        end_prefix = end_date[:10]
        for path in files:
            try:
                with open(path, encoding="utf-8") as f:
                    for raw in f:
                        raw = raw.strip()
                        if not raw:
                            continue
                        try:
                            record = json.loads(raw)
                        except json.JSONDecodeError:
                            continue
                        ts = str(record.get("timestamp", ""))[:10]
                        if start_prefix <= ts <= end_prefix:
                            yield record
            except OSError:
                continue

    # -- Streaming formats ---------------------------------------------------

    @staticmethod
    async def _stream_json(lines) -> AsyncIterator[bytes]:
        for record in lines:
            yield (json.dumps(record, default=str) + "\n").encode("utf-8")

    @staticmethod
    async def _stream_csv(lines) -> AsyncIterator[bytes]:
        header_written = False
        for record in lines:
            if not header_written:
                buf = io.StringIO()
                writer = csv.DictWriter(
                    buf,
                    fieldnames=list(record.keys()),
                    extrasaction="ignore",
                    lineterminator="\n",
                )
                writer.writeheader()
                header_written = True
                yield buf.getvalue().encode("utf-8")

            # Sanitise values: escape formula triggers + strip newlines (V1.2.10)
            clean = {k: escape_csv_cell(v) for k, v in record.items()}
            buf = io.StringIO()
            writer = csv.DictWriter(
                buf,
                fieldnames=list(record.keys()),
                extrasaction="ignore",
                lineterminator="\n",
            )
            writer.writerow(clean)
            yield buf.getvalue().encode("utf-8")
