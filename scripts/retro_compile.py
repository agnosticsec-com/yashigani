#!/usr/bin/env python3
"""
retro_compile.py — extract retro entries from agent-memory files and
compile a per-release retro.md outside the public repo.

Closes yashigani-retro #54.

Memory layout (auto-memory):
  /Users/max/.claude/projects/-Users-max-Documents-Claude/memory/
    project_v231_retro.md           ← living retro for a release
    project_v232_offline_save_*.md  ← session-end retro snapshots
    feedback_*.md                   ← rule-changes from retros
    MEMORY.md                       ← index

Output layout (intentionally OUTSIDE the public yashigani repo per
feedback_yashigani_repo_code_only.md — compliance docs never ship in
the install repo):
  /Users/max/Documents/Claude/Internal/Compliance/yashigani/v<version>/retro.md

Usage:
  scripts/retro_compile.py --version v2.23.2
  scripts/retro_compile.py --version v2.23.2 --memory-dir /custom/path
  scripts/retro_compile.py --version v2.23.2 --output /tmp/retro.md
  scripts/retro_compile.py --version v2.23.2 --dry-run
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_MEMORY_DIR = Path(
    os.environ.get(
        "YASHIGANI_AGENT_MEMORY_DIR",
        Path.home() / ".claude" / "projects" / "-Users-max-Documents-Claude" / "memory",
    )
)
DEFAULT_OUTPUT_BASE = Path("/Users/max/Documents/Claude/Internal/Compliance/yashigani")


def _normalise_version(v: str) -> str:
    """Accept v2.23.2, 2.23.2, v2.23.2-rc.1 → return v2.23.2 (canonical)."""
    v = v.strip()
    if not v.startswith("v"):
        v = "v" + v
    return v.split("-")[0]  # strip rc/build qualifiers


def _version_tag_for_filename(v: str) -> str:
    """Compute the no-dot tag used in agent-memory filenames.

    v2.23.2 → v232  (drop the major, concat minor+patch)
    v2.23.1 → v231
    v2.20.0 → v200

    Matches the existing `project_v23X_*.md` / `feedback_*.md` convention.
    """
    v = v.lstrip("v")
    parts = v.split(".")
    if len(parts) >= 3:
        # v2.23.2 → drop major, concat minor + patch
        return f"v{parts[1]}{parts[2]}"
    if len(parts) == 2:
        return f"v{parts[0]}{parts[1]}"
    return f"v{parts[0]}"


def _select_memory_files(memory_dir: Path, version: str) -> list[Path]:
    """Pick files relevant to the release. Match both 'v232' shorthand and
    'v2.23.2' literal — agent-memory files use both forms in practice."""
    if not memory_dir.is_dir():
        raise SystemExit(f"memory dir not found: {memory_dir}")

    short = _version_tag_for_filename(version)  # v232
    long = version.replace(".", r"\.")           # v2\.23\.2

    pattern = re.compile(
        rf"(?i)(project|feedback)_.*({short}|{long})", re.UNICODE
    )

    candidates = sorted(memory_dir.glob("project_*.md")) + sorted(
        memory_dir.glob("feedback_*.md")
    )
    selected = [p for p in candidates if pattern.search(p.name)]
    return selected


def _strip_frontmatter(text: str) -> tuple[dict, str]:
    """Return (metadata, body). Metadata is the YAML-ish key/value frontmatter
    block at the top. Body is everything after the closing '---'."""
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---\n", 4)
    if end < 0:
        return {}, text
    raw = text[4:end]
    body = text[end + 5 :]
    meta: dict = {}
    for line in raw.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            meta[k.strip()] = v.strip()
    return meta, body


def _make_section(path: Path) -> str:
    """Render one memory file as a retro.md section."""
    text = path.read_text(encoding="utf-8")
    meta, body = _strip_frontmatter(text)
    name = meta.get("name") or path.stem
    description = meta.get("description") or ""
    typ = meta.get("type") or "memory"

    header_lines = [
        f"## {name}",
        "",
        f"_Source:_ `{path.name}` &nbsp;·&nbsp; _Type:_ `{typ}`",
    ]
    if description:
        header_lines.append("")
        header_lines.append(f"> {description}")
    header_lines.append("")
    header_lines.append(body.rstrip() + "\n")
    return "\n".join(header_lines)


def _compile(memory_dir: Path, version: str) -> str:
    files = _select_memory_files(memory_dir, version)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lines = [
        f"# Yashigani {version} — Compiled Retro",
        "",
        "<!-- CONFIDENTIAL — Internal evidence repository. Do not commit to the yashigani public repo. -->",
        "",
        f"**Generated:** {now}",
        f"**Source:** `{memory_dir}`",
        f"**Files included:** {len(files)}",
        "",
        "This file is auto-compiled by `scripts/retro_compile.py` from agent-memory",
        "entries that reference this release. Edit memory, not this file — re-run",
        "the compiler to refresh.",
        "",
        "---",
        "",
    ]
    if not files:
        lines.append("_(No matching memory files for this release.)_")
        return "\n".join(lines) + "\n"

    for p in files:
        lines.append(_make_section(p))
        lines.append("---")
        lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument(
        "--version", required=True, help="Release version e.g. v2.23.2 or 2.23.2"
    )
    parser.add_argument(
        "--memory-dir",
        type=Path,
        default=DEFAULT_MEMORY_DIR,
        help=f"Agent-memory directory (default: {DEFAULT_MEMORY_DIR})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output retro.md path (default: <Internal>/Compliance/yashigani/<v>/retro.md)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print to stdout instead of writing the file",
    )
    args = parser.parse_args()

    version = _normalise_version(args.version)
    output = args.output or (DEFAULT_OUTPUT_BASE / version / "retro.md")

    compiled = _compile(args.memory_dir, version)

    if args.dry_run:
        sys.stdout.write(compiled)
        return 0

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(compiled, encoding="utf-8")
    print(f"wrote {output} ({len(compiled.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
