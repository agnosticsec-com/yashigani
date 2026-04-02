"""
Yashigani Pool Manager — Postmortem forensic evidence collection.

When a container is replaced (unhealthy, crashed, or idle timeout),
the Pool Manager collects forensic evidence before killing it:
  1. Container logs
  2. Docker inspect (full state)
  3. Filesystem diff (what changed)
  4. Trigger reason

Packaged and sent to SIEM sinks via the audit writer.
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

_POSTMORTEM_DIR = "/data/postmortem"


@dataclass
class PostmortemReport:
    """Forensic evidence from a replaced container."""
    container_id: str
    container_name: str
    trigger_reason: str
    timestamp: str
    logs: str
    inspect_json: dict
    filesystem_diff: str
    saved_to: str


def collect_postmortem(
    docker_client,
    container_id: str,
    container_name: str,
    trigger_reason: str,
    postmortem_dir: str = _POSTMORTEM_DIR,
) -> Optional[PostmortemReport]:
    """
    Collect forensic evidence from a container before killing it.

    Args:
        docker_client: Docker SDK client (docker.from_env())
        container_id: Container ID
        container_name: Human-readable container name
        trigger_reason: Why the container is being replaced
        postmortem_dir: Directory to save postmortem files

    Returns:
        PostmortemReport or None if collection failed
    """
    try:
        ts = time.strftime("%Y-%m-%dT%H%M%SZ", time.gmtime())
        safe_name = container_name.replace("/", "_").replace(":", "_")
        report_dir = os.path.join(postmortem_dir, f"{safe_name}_{ts}")
        os.makedirs(report_dir, exist_ok=True)

        container = docker_client.containers.get(container_id)

        # 1. Logs
        logs = ""
        try:
            logs = container.logs(tail=500).decode("utf-8", errors="replace")
            with open(os.path.join(report_dir, "container_logs.txt"), "w") as f:
                f.write(logs)
        except Exception as exc:
            logger.warning("Postmortem: failed to collect logs for %s: %s", container_name, exc)

        # 2. Docker inspect
        inspect_data = {}
        try:
            inspect_data = container.attrs
            with open(os.path.join(report_dir, "container_inspect.json"), "w") as f:
                json.dump(inspect_data, f, indent=2, default=str)
        except Exception as exc:
            logger.warning("Postmortem: failed to inspect %s: %s", container_name, exc)

        # 3. Filesystem diff
        diff_text = ""
        try:
            diff = container.diff()
            if diff:
                diff_text = "\n".join(
                    f"{'A' if d['Kind'] == 0 else 'M' if d['Kind'] == 1 else 'D'} {d['Path']}"
                    for d in diff
                )
            with open(os.path.join(report_dir, "filesystem_diff.txt"), "w") as f:
                f.write(diff_text or "(no changes)")
        except Exception as exc:
            logger.warning("Postmortem: failed to diff %s: %s", container_name, exc)

        # 4. Trigger reason
        with open(os.path.join(report_dir, "trigger_reason.txt"), "w") as f:
            f.write(f"Trigger: {trigger_reason}\n")
            f.write(f"Timestamp: {ts}\n")
            f.write(f"Container: {container_name} ({container_id[:12]})\n")

        report = PostmortemReport(
            container_id=container_id,
            container_name=container_name,
            trigger_reason=trigger_reason,
            timestamp=ts,
            logs=logs[:5000],  # Truncate for the report object
            inspect_json=inspect_data,
            filesystem_diff=diff_text[:2000],
            saved_to=report_dir,
        )

        logger.info(
            "Postmortem collected: %s (%s) -> %s",
            container_name, trigger_reason, report_dir,
        )
        return report

    except Exception as exc:
        logger.error("Postmortem collection failed for %s: %s", container_name, exc)
        return None
