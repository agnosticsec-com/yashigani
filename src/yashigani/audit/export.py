"""
Yashigani Audit — Streaming log exporter.
Reads from volume sink log files and streams JSON or CSV output.
Never buffers the full result set in memory.
"""
# Last updated: 2026-04-28T00:00:00+01:00
from __future__ import annotations

import csv
import io
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Optional

from yashigani.audit.config import AuditConfig


# ---------------------------------------------------------------------------
# V1.2.10 — CSV formula injection prevention (CWE-1236)
# Excel / LibreOffice interpret fields starting with = + - @ \t \r as formulas.
# Prefix any such field with a single quote so the spreadsheet treats it as text.
# Also handles BOM-prefixed variants (﻿= ﻿+ ﻿- ﻿@).
# ---------------------------------------------------------------------------

_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r", "﻿=", "﻿+", "﻿-", "﻿@")


def escape_csv_cell(v: object) -> str:
    """
    Sanitise a single CSV cell value.

    - Replaces \\n and \\r with a space (prevents row-splitting injection).
    - Prefixes formula-trigger characters with a single quote so spreadsheet
      applications (Excel, LibreOffice) do not execute the cell as a formula.

    Safe for all non-trigger values: they are returned unchanged (after newline
    normalisation).
    """
    s = str(v).replace("\n", " ").replace("\r", " ")
    if any(s.startswith(trigger) for trigger in _FORMULA_TRIGGERS):
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
