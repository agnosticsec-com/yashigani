"""
Yashigani Backoffice — Audit log search and filtered export.
GET /admin/audit/search  — search with filters, cursor-based pagination
GET /admin/audit/export  — filtered CSV or JSON export, 10,000 row cap

Filters: date_from, date_to, event_type, agent_id, verdict, user, free_text
Pagination: 100 rows per page, opaque cursor (base64-encoded file offset).
Export: CSV or JSON, same filter set, hard cap of 10,000 rows.

Security: never exposes raw file paths; all user inputs validated via Pydantic.
"""
from __future__ import annotations

import base64
import csv
import io
import json
import logging
import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import StreamingResponse

from yashigani.backoffice.middleware import AdminSession
from yashigani.backoffice.state import backoffice_state

logger = logging.getLogger(__name__)

router = APIRouter()

_PAGE_SIZE = 100
_EXPORT_ROW_CAP = 10_000


# ---------------------------------------------------------------------------
# Search endpoint
# ---------------------------------------------------------------------------

@router.get("/search")
async def search_audit_log(
    session: AdminSession,
    date_from: Optional[str] = Query(
        default=None,
        description="ISO 8601 date prefix, e.g. 2025-01-01",
        max_length=32,
    ),
    date_to: Optional[str] = Query(
        default=None,
        description="ISO 8601 date prefix, e.g. 2025-12-31",
        max_length=32,
    ),
    event_type: Optional[str] = Query(
        default=None,
        description="Exact event_type string, e.g. ADMIN_LOGIN",
        max_length=128,
    ),
    agent_id: Optional[str] = Query(
        default=None,
        description="agent_id to filter on",
        max_length=256,
    ),
    verdict: Optional[str] = Query(
        default=None,
        description="Inspection verdict (FORWARDED, DISCARDED, DENIED, BLOCKED)",
        max_length=64,
    ),
    user: Optional[str] = Query(
        default=None,
        description="admin_account or user_handle substring match",
        max_length=256,
    ),
    free_text: Optional[str] = Query(
        default=None,
        description="Case-insensitive substring match against raw JSON line",
        max_length=256,
    ),
    cursor: Optional[str] = Query(
        default=None,
        description="Opaque pagination cursor from previous response",
        max_length=512,
    ),
) -> dict:
    """
    Search the audit log with optional filters.
    Returns up to 100 rows per page. Provide cursor from a previous response
    to fetch the next page.
    """
    log_path = _get_log_path()
    if log_path is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "audit_log_not_configured"},
        )

    filters = _Filters(
        date_from=date_from,
        date_to=date_to,
        event_type=event_type,
        agent_id=agent_id,
        verdict=verdict,
        user=user,
        free_text=free_text,
    )

    start_offset = _decode_cursor(cursor)
    rows, next_offset, total_scanned = _read_page(
        log_path, filters, start_offset, _PAGE_SIZE
    )

    next_cursor = _encode_cursor(next_offset) if next_offset is not None else None
    return {
        "rows": rows,
        "count": len(rows),
        "total_scanned": total_scanned,
        "cursor": next_cursor,
        "has_more": next_cursor is not None,
    }


# ---------------------------------------------------------------------------
# Export endpoint
# ---------------------------------------------------------------------------

@router.get("/export")
async def export_filtered_audit_log(
    session: AdminSession,
    output_format: str = Query(
        default="json",
        pattern=r"^(json|csv)$",
        description="Output format: json (NDJSON) or csv",
    ),
    date_from: Optional[str] = Query(default=None, max_length=32),
    date_to: Optional[str] = Query(default=None, max_length=32),
    event_type: Optional[str] = Query(default=None, max_length=128),
    agent_id: Optional[str] = Query(default=None, max_length=256),
    verdict: Optional[str] = Query(default=None, max_length=64),
    user: Optional[str] = Query(default=None, max_length=256),
    free_text: Optional[str] = Query(default=None, max_length=256),
) -> StreamingResponse:
    """
    Export filtered audit log as NDJSON or CSV.
    Hard cap of 10,000 rows regardless of filter breadth.
    Never buffers the full result set in memory.
    """
    log_path = _get_log_path()
    if log_path is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "audit_log_not_configured"},
        )

    filters = _Filters(
        date_from=date_from,
        date_to=date_to,
        event_type=event_type,
        agent_id=agent_id,
        verdict=verdict,
        user=user,
        free_text=free_text,
    )

    if output_format == "csv":
        media_type = "text/csv"
        filename = "yashigani-audit-search.csv"
        stream = _stream_csv(log_path, filters)
    else:
        media_type = "application/x-ndjson"
        filename = "yashigani-audit-search.ndjson"
        stream = _stream_ndjson(log_path, filters)

    return StreamingResponse(
        stream,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Filter logic
# ---------------------------------------------------------------------------

class _Filters:
    __slots__ = (
        "date_from", "date_to", "event_type", "agent_id",
        "verdict", "user", "free_text",
    )

    def __init__(
        self,
        date_from: Optional[str],
        date_to: Optional[str],
        event_type: Optional[str],
        agent_id: Optional[str],
        verdict: Optional[str],
        user: Optional[str],
        free_text: Optional[str],
    ) -> None:
        self.date_from = date_from[:10] if date_from else None
        self.date_to = date_to[:10] if date_to else None
        self.event_type = event_type
        self.agent_id = agent_id
        self.verdict = verdict
        self.user = user
        self.free_text = free_text.lower() if free_text else None

    def matches_raw(self, raw_line: str) -> bool:
        """Quick pre-filter on the raw line before JSON parsing."""
        if self.free_text and self.free_text not in raw_line.lower():
            return False
        return True

    def matches_record(self, record: dict) -> bool:
        """Full filter on parsed record."""
        if self.date_from or self.date_to:
            ts = str(record.get("timestamp", ""))[:10]
            if self.date_from and ts < self.date_from:
                return False
            if self.date_to and ts > self.date_to:
                return False

        if self.event_type and record.get("event_type") != self.event_type:
            return False

        if self.agent_id:
            rec_agent = record.get("agent_id", record.get("caller_agent_id", ""))
            if self.agent_id not in rec_agent:
                return False

        if self.verdict:
            rec_verdict = record.get("action", record.get("verdict", ""))
            if self.verdict.upper() not in rec_verdict.upper():
                return False

        if self.user:
            user_lower = self.user.lower()
            admin_account = record.get("admin_account", "").lower()
            user_handle = record.get("user_handle", "").lower()
            if user_lower not in admin_account and user_lower not in user_handle:
                return False

        return True


# ---------------------------------------------------------------------------
# Page reader
# ---------------------------------------------------------------------------

def _read_page(
    log_path: Path,
    filters: _Filters,
    start_offset: int,
    page_size: int,
) -> tuple[list[dict], Optional[int], int]:
    """
    Read up to page_size matching rows from the log file starting at
    byte offset start_offset. Returns (rows, next_offset, total_scanned).
    next_offset is None when end-of-file is reached.
    """
    rows: list[dict] = []
    total_scanned = 0
    next_offset: Optional[int] = None

    log_files = _collect_log_files(log_path)

    # Build a virtual flat file by chaining log files with cumulative offsets
    cumulative = 0
    for file_path in log_files:
        file_size = file_path.stat().st_size if file_path.exists() else 0
        file_end = cumulative + file_size

        if start_offset >= file_end:
            cumulative = file_end
            continue

        # This file contains our start position
        file_start_offset = max(0, start_offset - cumulative)
        try:
            with open(file_path, "rb") as f:
                f.seek(file_start_offset)
                # Align to line boundary
                if file_start_offset > 0:
                    f.readline()  # skip partial line

                while True:
                    pos = f.tell()
                    raw_bytes = f.readline()
                    if not raw_bytes:
                        break  # end of this file

                    total_scanned += 1
                    raw = raw_bytes.decode("utf-8", errors="replace").strip()
                    if not raw:
                        continue

                    if not filters.matches_raw(raw):
                        continue

                    try:
                        record = json.loads(raw)
                    except json.JSONDecodeError:
                        continue

                    if not filters.matches_record(record):
                        continue

                    rows.append(record)
                    if len(rows) >= page_size:
                        # Record position after this line as the next cursor
                        next_offset = cumulative + f.tell()
                        return rows, next_offset, total_scanned

        except OSError as exc:
            logger.warning("audit_search: cannot read %s: %s", file_path, exc)

        cumulative = file_end

    return rows, None, total_scanned


# ---------------------------------------------------------------------------
# Streaming generators
# ---------------------------------------------------------------------------

async def _stream_ndjson(log_path: Path, filters: _Filters):
    """Async generator yielding NDJSON lines, capped at _EXPORT_ROW_CAP."""
    count = 0
    for file_path in _collect_log_files(log_path):
        if count >= _EXPORT_ROW_CAP:
            break
        try:
            with open(file_path, encoding="utf-8", errors="replace") as f:
                for raw in f:
                    if count >= _EXPORT_ROW_CAP:
                        break
                    raw = raw.strip()
                    if not raw:
                        continue
                    if not filters.matches_raw(raw):
                        continue
                    try:
                        record = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    if not filters.matches_record(record):
                        continue
                    yield (json.dumps(record, default=str) + "\n").encode("utf-8")
                    count += 1
        except OSError as exc:
            logger.warning("audit_search stream: cannot read %s: %s", file_path, exc)


async def _stream_csv(log_path: Path, filters: _Filters):
    """Async generator yielding CSV rows, capped at _EXPORT_ROW_CAP."""
    count = 0
    header_written = False
    field_names: list[str] = []

    for file_path in _collect_log_files(log_path):
        if count >= _EXPORT_ROW_CAP:
            break
        try:
            with open(file_path, encoding="utf-8", errors="replace") as f:
                for raw in f:
                    if count >= _EXPORT_ROW_CAP:
                        break
                    raw = raw.strip()
                    if not raw:
                        continue
                    if not filters.matches_raw(raw):
                        continue
                    try:
                        record = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    if not filters.matches_record(record):
                        continue

                    if not header_written:
                        field_names = list(record.keys())
                        buf = io.StringIO()
                        writer = csv.DictWriter(
                            buf,
                            fieldnames=field_names,
                            extrasaction="ignore",
                            lineterminator="\n",
                        )
                        writer.writeheader()
                        header_written = True
                        yield buf.getvalue().encode("utf-8")

                    # CSV injection prevention: strip newline chars from values
                    clean = {
                        k: str(v).replace("\n", " ").replace("\r", " ")
                        for k, v in record.items()
                    }
                    buf = io.StringIO()
                    writer = csv.DictWriter(
                        buf,
                        fieldnames=field_names,
                        extrasaction="ignore",
                        lineterminator="\n",
                    )
                    writer.writerow(clean)
                    yield buf.getvalue().encode("utf-8")
                    count += 1

        except OSError as exc:
            logger.warning("audit_search csv stream: cannot read %s: %s", file_path, exc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_log_path() -> Optional[Path]:
    """Return the audit log path from backoffice state, or None."""
    state = backoffice_state
    if state.audit_writer is None:
        return None
    try:
        return Path(state.audit_writer._config.log_path)
    except AttributeError:
        return None


def _collect_log_files(log_path: Path) -> list[Path]:
    """Return rotated log files + the active file, oldest first."""
    parent = log_path.parent
    rotated = sorted(parent.glob("audit.log.*"))
    result = list(rotated)
    if log_path.exists():
        result.append(log_path)
    return result


def _encode_cursor(offset: int) -> str:
    """Encode a byte offset as an opaque base64 cursor string."""
    return base64.urlsafe_b64encode(str(offset).encode()).decode("ascii")


def _decode_cursor(cursor: Optional[str]) -> int:
    """Decode a cursor back to a byte offset. Returns 0 if None or invalid."""
    if not cursor:
        return 0
    try:
        return int(base64.urlsafe_b64decode(cursor.encode()).decode())
    except Exception:
        return 0
