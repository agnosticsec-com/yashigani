"""
Yashigani Audit — Streaming log exporter.
Reads from volume sink log files and streams JSON or CSV output.
Never buffers the full result set in memory.
"""
from __future__ import annotations

import csv
import io
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Optional

from yashigani.audit.config import AuditConfig


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

            # Sanitise values: replace newlines to prevent CSV injection
            clean = {
                k: str(v).replace("\n", " ").replace("\r", " ")
                for k, v in record.items()
            }
            buf = io.StringIO()
            writer = csv.DictWriter(
                buf,
                fieldnames=list(record.keys()),
                extrasaction="ignore",
                lineterminator="\n",
            )
            writer.writerow(clean)
            yield buf.getvalue().encode("utf-8")
