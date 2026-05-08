#!/usr/bin/env bash
# scripts/lint_tmp_paths.sh — V232-P23
# Last updated: 2026-05-03T14:00:00+01:00
#
# Grep for /tmp/ in installer/script/test/docker files and fail if any
# host-filesystem /tmp usage is found.  Excludes:
#   - helm/ tmpfs mounts (legitimate in-cluster ephemeral storage)
#   - Dockerfiles (container-internal build layers)
#   - n_minus_one.sh (all /tmp paths are inside SSH heredoc blocks on the VM)
#   - Container cp/exec target paths (paths after : in docker/podman cp)
#   - Comments documenting why /tmp is NOT used
#
# Usage: bash scripts/lint_tmp_paths.sh [repo_root]
set -euo pipefail

REPO_ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SELF="$(basename "${BASH_SOURCE[0]}")"

# Files/dirs to scan (host-side scripts and CI)
SCAN_TARGETS=(
  "install.sh"
  "restore.sh"
  "update.sh"
  "uninstall.sh"
  "scripts"
  "tests"
  "docker"
)

# Patterns that are legitimate /tmp usages (container-internal, tmpfs mounts,
# or references that are NOT host-side file creation):
#
#   1. Helm tmpfs volume mounts:     mountPath: /tmp
#   2. Helm/compose tmpfs declaration: tmpfs: /tmp
#   3. docker/podman cp into container: cp ... :/tmp/
#   4. exec inside container:         exec ... python3 /tmp/
#   5. Comments referencing the rule:  # never /tmp
EXCLUDE_PATTERNS=(
  "mountPath:[[:space:]]*/tmp"
  "tmpfs:[[:space:]]*/tmp"
  "cp[[:space:]].*:/tmp/"
  "exec.*python.*[[:space:]]/tmp/"
  "exec.*sh.*[[:space:]]/tmp/"
  "#.*never.*/tmp"
  "#.*V232-NEG04"
  "# V232-NEG04"
)

# Build the exclude-pattern grep arguments
EXCLUDE_GREP_ARGS=()
for pat in "${EXCLUDE_PATTERNS[@]}"; do
  EXCLUDE_GREP_ARGS+=("-e" "$pat")
done

HITS=0
FAIL_LINES=""

for target in "${SCAN_TARGETS[@]}"; do
  target_path="${REPO_ROOT}/${target}"
  [[ -e "$target_path" ]] || continue

  while IFS= read -r -d '' f; do
    # Skip the lint script itself
    [[ "$(basename "$f")" == "$SELF" ]] && continue

    # Skip helm/ directory entirely (all /tmp there are container-internal
    # tmpfs mounts — legitimate and reviewed)
    [[ "$f" == *"/helm/"* ]] && continue

    # Skip Dockerfiles — /tmp inside a Dockerfile RUN layer is container-
    # internal build space, not the host filesystem.
    [[ "$(basename "$f")" == "Dockerfile" ]] && continue
    [[ "$(basename "$f")" == Dockerfile.* ]] && continue

    # Skip n_minus_one.sh — all /tmp paths there are inside SSH heredoc
    # blocks that run on the remote test VM, not on the host filesystem.
    # (vm_run / HEREDOC+SSH pattern; reviewed 2026-05-03.)
    [[ "$(basename "$f")" == "n_minus_one.sh" ]] && continue

    # Find lines with /tmp/
    raw_hits="$(grep -n "/tmp/" "$f" 2>/dev/null || true)"
    [[ -z "$raw_hits" ]] && continue

    # Filter out the known-legitimate patterns
    if [[ ${#EXCLUDE_GREP_ARGS[@]} -gt 0 ]]; then
      filtered="$(printf "%s\n" "$raw_hits" | grep -v "${EXCLUDE_GREP_ARGS[@]}" || true)"
    else
      filtered="$raw_hits"
    fi
    [[ -z "$filtered" ]] && continue

    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      FAIL_LINES="${FAIL_LINES}${f}:${line}\n"
      HITS=$((HITS + 1))
    done <<< "$filtered"

  done < <(find "$target_path" \
    \( -name "*.sh" -o -name "*.py" -o -name "*.yml" -o -name "*.yaml" \
       -o -name "Dockerfile" -o -name "Dockerfile.*" -o -name "*.env" \
       -o -name "*.env.*" \) \
    -type f -print0 2>/dev/null)
done

if [[ "$HITS" -gt 0 ]]; then
  printf "ERROR: %d host-filesystem /tmp/ path(s) found (V232-NEG04 — all work must stay under the install dir):\n\n" "$HITS" >&2
  printf "%b" "$FAIL_LINES" >&2
  printf "\nFix: replace /tmp/... with \${WORK_DIR}/... or \${YSG_INSTALL_DIR}/.ysg_work/...\n" >&2
  exit 1
fi

printf "lint_tmp_paths: OK — no host-filesystem /tmp/ paths found (%s targets scanned)\n" "${#SCAN_TARGETS[@]}"
