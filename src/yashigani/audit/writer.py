"""
Yashigani Audit — Log writer with volume sink and multi-SIEM forwarding.
Volume sink is always active and cannot be disabled.
SIEM forwarding is optional and failure-tolerant.
"""
from __future__ import annotations

import dataclasses
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from yashigani.audit.config import AuditConfig
from yashigani.audit.masking import CredentialMasker
from yashigani.audit.schema import AuditEvent, SiemDeliveryFailedEvent
from yashigani.audit.scope import MaskingScopeConfig

logger = logging.getLogger(__name__)

_RETRY_DELAYS = [1.0, 5.0, 25.0]  # seconds


class AuditWriteError(Exception):
    """Raised when the volume sink write fails. Callers must abort the operation."""


# ---------------------------------------------------------------------------
# SIEM target
# ---------------------------------------------------------------------------

@dataclass
class SiemTarget:
    name: str
    target_type: str       # webhook | splunk_hec | elastic_opensearch
    url: str
    auth_header: str       # e.g. "Authorization"
    auth_value: str        # secret — never logged
    enabled: bool = True


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

class AuditLogWriter:
    """
    Thread-safe audit log writer.
    Primary: newline-delimited JSON to a mounted volume file.
    Secondary: optional SIEM forwarding (webhook / Splunk HEC / Elastic).
    """

    def __init__(
        self,
        config: AuditConfig,
        masking_scope: Optional[MaskingScopeConfig] = None,
        siem_targets: Optional[list[SiemTarget]] = None,
    ) -> None:
        self._config = config
        self._masking_scope = masking_scope or MaskingScopeConfig()
        self._siem_targets: list[SiemTarget] = siem_targets or []
        self._masker = CredentialMasker()
        self._lock = threading.Lock()
        self._log_path = Path(config.log_path)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self._open_log_file()

    # -- Public API ----------------------------------------------------------

    def write(
        self,
        event: AuditEvent,
        agent_id: Optional[str] = None,
        user_handle: Optional[str] = None,
        component: Optional[str] = None,
    ) -> None:
        """
        Write an audit event to the volume sink (always) and forward to
        enabled SIEM targets (best-effort). Raises AuditWriteError if the
        volume write fails — the caller MUST abort their operation.
        """
        if self._masking_scope.should_mask(event, agent_id, user_handle, component):
            event = self._masker.mask_event(event)
            object.__setattr__(event, "masking_applied", True) if dataclasses.is_dataclass(event) else setattr(event, "masking_applied", True)

        record = json.dumps(event.to_dict(), default=str)

        with self._lock:
            try:
                self._rotate_if_needed()
                self._file.write(record + "\n")
                self._file.flush()
            except OSError as exc:
                raise AuditWriteError(
                    f"Audit volume write failed: {exc}. "
                    "The triggering operation must be aborted."
                ) from exc

        # SIEM forwarding is fire-and-forget (never blocks volume write)
        if self._siem_targets:
            threading.Thread(
                target=self._forward_to_siem,
                args=(event, record),
                daemon=True,
            ).start()

    def _write_raw(self, line: str) -> None:
        """
        Write a raw newline-terminated string to the volume sink.
        Used by FileSink (multi-sink writer) to delegate file I/O here
        so rotation, locking, and path management remain centralised.
        Raises AuditWriteError if the write fails.
        """
        with self._lock:
            try:
                self._rotate_if_needed()
                self._file.write(line + "\n")
                self._file.flush()
            except OSError as exc:
                raise AuditWriteError(
                    f"Audit volume write failed (_write_raw): {exc}. "
                    "The triggering operation must be aborted."
                ) from exc

    def close(self) -> None:
        with self._lock:
            try:
                self._file.close()
            except OSError:
                pass

    def add_siem_target(self, target: SiemTarget) -> None:
        self._siem_targets.append(target)

    # -- Volume sink ---------------------------------------------------------

    def _open_log_file(self):
        return open(self._log_path, "a", encoding="utf-8", buffering=1)

    def _rotate_if_needed(self) -> None:
        """Rotate log file if it exceeds max_file_size_mb. Lock must be held."""
        try:
            size_mb = self._log_path.stat().st_size / (1024 * 1024)
        except FileNotFoundError:
            return
        if size_mb < self._config.max_file_size_mb:
            return

        self._file.close()
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d-%H%M%S")
        rotated = self._log_path.with_suffix(f".log.{ts}")
        self._log_path.rename(rotated)
        self._file = self._open_log_file()
        self._delete_old_logs()

    def _delete_old_logs(self) -> None:
        """Remove rotated logs older than retention_days."""
        cutoff = time.time() - (self._config.retention_days * 86400)
        parent = self._log_path.parent
        for p in parent.glob("audit.log.*"):
            try:
                if p.stat().st_mtime < cutoff:
                    p.unlink()
            except OSError:
                pass

    # -- SIEM forwarding -----------------------------------------------------

    def _forward_to_siem(self, event: AuditEvent, raw_json: str) -> None:
        for target in self._siem_targets:
            if not target.enabled:
                continue
            self._send_with_retry(event, raw_json, target)

    def _send_with_retry(
        self, event: AuditEvent, raw_json: str, target: SiemTarget
    ) -> None:
        last_status: Optional[int] = None
        last_error: str = ""
        for attempt, delay in enumerate(_RETRY_DELAYS):
            try:
                self._send_to_target(raw_json, target)
                return
            except Exception as exc:
                last_error = str(exc)
                last_status = getattr(exc, "status_code", None)
                if attempt < len(_RETRY_DELAYS) - 1:
                    time.sleep(delay)

        # All retries exhausted — log delivery failure to volume sink
        failure = SiemDeliveryFailedEvent(
            account_tier="system",
            siem_target_name=target.name,
            siem_target_type=target.target_type,
            failed_audit_event_id=event.audit_event_id,
            http_status=last_status,
            error=last_error,
            retry_attempted=True,
        )
        try:
            record = json.dumps(failure.to_dict(), default=str)
            with self._lock:
                self._file.write(record + "\n")
                self._file.flush()
        except OSError:
            logger.error(
                "SIEM delivery failure AND volume write failure for event %s",
                event.audit_event_id,
            )

    def _send_to_target(self, raw_json: str, target: SiemTarget) -> None:
        import urllib.request
        import urllib.error

        body, content_type = self._format_for_target(raw_json, target)
        req = urllib.request.Request(
            url=target.url,
            data=body.encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": content_type,
                target.auth_header: target.auth_value,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status >= 300:
                    raise RuntimeError(f"HTTP {resp.status}")
        except urllib.error.HTTPError as exc:
            exc.status_code = exc.code  # type: ignore[attr-defined]
            raise

    @staticmethod
    def _format_for_target(raw_json: str, target: SiemTarget) -> tuple[str, str]:
        if target.target_type == "webhook":
            return raw_json, "application/json"

        event_dict = json.loads(raw_json)

        if target.target_type == "splunk_hec":
            import time as _time
            payload = json.dumps({
                "time": _time.time(),
                "event": event_dict,
                "sourcetype": "yashigani",
            })
            return payload, "application/json"

        if target.target_type == "elastic_opensearch":
            index_line = json.dumps({"index": {"_index": "yashigani-audit"}})
            ndjson = index_line + "\n" + raw_json + "\n"
            return ndjson, "application/x-ndjson"

        raise ValueError(f"Unknown SIEM target type: {target.target_type!r}")
