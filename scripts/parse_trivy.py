"""
parse_trivy.py — Read a Trivy SARIF output file, count HIGH and CRITICAL CVE findings,
and push the count as a Prometheus gauge to a Pushgateway instance.

Uses only Python stdlib. Non-fatal if Pushgateway is unreachable.

Usage:
    python scripts/parse_trivy.py \
        --input trivy-gateway.sarif \
        --image gateway \
        --pushgateway http://localhost:9091 \
        --job yashigani-ci
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request


_METRIC_NAME = "yashigani_trivy_high_cve_count"

# Trivy SARIF severity mapping:
#   CRITICAL -> level: "error"
#   HIGH     -> level: "warning"
_SEVERITY_LEVELS = {"error", "warning"}


def load_sarif(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def count_findings(sarif: dict) -> int:
    """Return total HIGH + CRITICAL findings from a Trivy SARIF document."""
    count = 0
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            level = result.get("level", "").lower()
            if level in _SEVERITY_LEVELS:
                count += 1
    return count


def build_pushgateway_payload(metric_name: str, image: str, value: int) -> bytes:
    """
    Build a Prometheus text-format payload for a single gauge metric.

    Format expected by Pushgateway:
        # HELP <name> <docstring>
        # TYPE <name> gauge
        <name>{label="value"} <value>
    """
    lines = [
        f"# HELP {metric_name} Number of HIGH+CRITICAL CVEs found by Trivy per image.",
        f"# TYPE {metric_name} gauge",
        f'{metric_name}{{image="{image}"}} {value}',
        "",  # trailing newline required by Prometheus text format
    ]
    return "\n".join(lines).encode("utf-8")


def push_to_gateway(pushgateway_url: str, job: str, payload: bytes) -> None:
    """
    HTTP PUT to Pushgateway. Non-fatal — prints warning and returns on any error.

    Endpoint: POST /metrics/job/<job>
    """
    url = f"{pushgateway_url.rstrip('/')}/metrics/job/{job}"
    req = urllib.request.Request(
        url,
        data=payload,
        method="PUT",
        headers={"Content-Type": "text/plain; version=0.0.4; charset=utf-8"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            if status not in (200, 202):
                print(
                    f"[parse_trivy] Pushgateway returned unexpected status {status}",
                    file=sys.stderr,
                )
            else:
                print(f"[parse_trivy] Metrics pushed to {url} (HTTP {status})")
    except urllib.error.URLError as exc:
        print(
            f"[parse_trivy] WARNING: Could not reach Pushgateway at {url}: {exc}",
            file=sys.stderr,
        )
    except OSError as exc:
        print(
            f"[parse_trivy] WARNING: Network error pushing to Pushgateway: {exc}",
            file=sys.stderr,
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse Trivy SARIF and push CVE count to Prometheus Pushgateway."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to the Trivy SARIF output file.",
    )
    parser.add_argument(
        "--image",
        required=True,
        help="Image label value (e.g. gateway, backoffice).",
    )
    parser.add_argument(
        "--pushgateway",
        default="http://localhost:9091",
        help="Pushgateway base URL (default: http://localhost:9091).",
    )
    parser.add_argument(
        "--job",
        default="yashigani-ci",
        help="Pushgateway job label (default: yashigani-ci).",
    )
    args = parser.parse_args()

    try:
        sarif = load_sarif(args.input)
    except FileNotFoundError:
        print(
            f"[parse_trivy] ERROR: SARIF file not found: {args.input}",
            file=sys.stderr,
        )
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(
            f"[parse_trivy] ERROR: Failed to parse SARIF JSON: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)

    count = count_findings(sarif)
    print(f"[parse_trivy] {args.image}: {count} HIGH/CRITICAL finding(s) found.")

    payload = build_pushgateway_payload(_METRIC_NAME, args.image, count)
    push_to_gateway(args.pushgateway, args.job, payload)


if __name__ == "__main__":
    main()
