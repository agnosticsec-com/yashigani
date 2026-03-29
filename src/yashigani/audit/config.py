"""
Yashigani Audit — Configuration loaded from environment variables.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AuditConfig:
    log_path: str
    max_file_size_mb: int
    retention_days: int

    @classmethod
    def from_env(cls) -> "AuditConfig":
        return cls(
            log_path=os.environ.get(
                "YASHIGANI_AUDIT_LOG_PATH",
                "/var/log/yashigani/audit.log",
            ),
            max_file_size_mb=int(
                os.environ.get("YASHIGANI_AUDIT_MAX_FILE_SIZE_MB", "100")
            ),
            retention_days=int(
                os.environ.get("YASHIGANI_AUDIT_RETENTION_DAYS", "90")
            ),
        )
