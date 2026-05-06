# Yashigani Release Process

**Last updated:** 2026-05-02T06:58:47+01:00

This document covers the end-to-end process for cutting a Yashigani release from a clean branch tip to a signed, published GitHub release with full evidence archive. It is the authoritative source for M7 gate-check procedures.

---

## 1. Prerequisites

| Tool | Why needed | Install |
|------|-----------|---------|
| `git` | Commit, tag, push | OS package |
| `gh` CLI | Download CI artifacts, create release | `brew install gh` (macOS) / see [cli.github.com](https://cli.github.com) |
| `gh auth login` | PAT with `repo` + `read:packages` scopes | `gh auth login --scopes repo,read:packages` |

Note: workflow edits (anything under `.github/workflows/`) require a PAT with `workflow` scope in addition to `repo`. Split workflow commits from code commits when needed (see `feedback_pat_workflow_scope.md`).

---

## 2. CI Workflow Summary

Three workflows provide the M7 gate evidence:

### 2.1 CI (`ci.yml`)

Triggers on push/PR to: `main`, `release/**`, `v2.23.*`, `2.23.x`.

| Job | What it does | Artifacts uploaded |
|-----|--------------|--------------------|
| `test` (matrix: py3.12, py3.13) | `pytest src/tests/` with `--junitxml` | `unit-tests-py3.12-<sha>`, `unit-tests-py3.13-<sha>` |
| `mypy` (py3.12) | `mypy src/yashigani/` with `--xml-report` | `mypy-<sha>` |

Artifact retention: **90 days**.

### 2.2 Security Scan (`security.yml`)

Triggers on push/PR to same branches; scheduled runs add extended rule-packs.

| Job | Trigger | Artifacts uploaded |
|-----|---------|--------------------|
| `opengrep-push` | push/PR | `opengrep-<sha>` |
| `opengrep-full` | schedule (03:00 UTC) | SARIF only (Code Scanning) |
| `bandit-sast` | push/PR/schedule | `bandit-report` |
| `pip-audit` | push/PR/schedule | `pip-audit-report` |

Artifact retention: **90 days**.

---

## 3. Artifact Contents

### Unit-test artifact (`unit-tests-py<ver>-<sha>/`)

```
test-results-<ver>.xml    # JUnit XML, parseable by CI dashboards
verdict-<ver>.txt         # Grep-able verdict lines:
                          #   Unit tests: PASS|FAIL
                          #   Total: <n>
                          #   Passed: <n>
                          #   Failed: <n>
                          #   Skipped: <n>
                          #   Commit: <sha>
                          #   Workflow: CI
                          #   Run: <run-id>
```

### Mypy artifact (`mypy-<sha>/`)

```
mypy-xml/index.xml        # XML report from --xml-report
mypy-xml/any-exprs.txt    # Any-expression report
mypy-output.txt           # Full stdout/stderr from mypy run
mypy-summary.txt          # Grep-able verdict lines:
                          #   Type check: PASS|FAIL
                          #   Errors: <n>
                          #   Files checked: <n>
                          #   Commit: <sha>
                          #   Workflow: CI
                          #   Run: <run-id>
```

### Opengrep artifact (`opengrep-<sha>/`)

```
opengrep-results.json     # Full JSON output from opengrep scan
opengrep-summary.txt      # Grep-able verdict lines:
                          #   Opengrep: PASS|FAIL
                          #   Critical: <n>
                          #   High: <n>
                          #   Medium: <n>
                          #   Low: <n>
                          #   Info: <n>
                          #   Total findings: <n>
                          #   Scan errors: <n>
                          #   Commit: <sha>
                          #   Workflow: Security Scan
                          #   Run: <run-id>
```

**PASS/FAIL semantics:** `Opengrep: PASS` requires zero CRITICAL or HIGH findings AND zero scan errors. MEDIUM/LOW findings produce `PASS` with non-zero counts (non-blocking). A scan infrastructure error always produces `FAIL`.

---

## 4. Evidence Archive

CI evidence lives OUTSIDE the yashigani repo (in the DevOps evidence repository).

**Archive root:** a DevOps evidence directory, organised by version + commit SHA.

**Archive script:** `scripts/archive_ci_artifacts.sh`

```sh
# Usage (run from inside the yashigani repo directory):
scripts/archive_ci_artifacts.sh <commit-sha> <version>

# Example for v2.23.1 at ec46ab4:
scripts/archive_ci_artifacts.sh ec46ab4 2.23.1
```

The script:
1. Uses `gh run list --commit <sha>` to find all workflow runs for the commit.
2. Warns if any runs are not yet completed.
3. Downloads all artifacts from completed runs via `gh run download`.
4. Copies the three gate artifacts to the canonical evidence path.
5. Writes `archive-manifest.txt` listing all captured files.
6. Runs the gate verdict check inline and exits non-zero on any FAIL.

---

## 5. Pre-flight Gate Check (M7)

Run this one-liner before cutting any release tag. Every line must exit 0.

```sh
# Artifact dir names embed the full SHA. Use glob to match regardless of
# whether SHA is short or full. Resolve with git rev-parse first.
SHA=$(git rev-parse ec46ab4)
VER=2.23.1
BASE="${YASHIGANI_EVIDENCE_ROOT:?set to the DevOps evidence directory}/v${VER}/ci-evidence/${SHA}"

grep -q "Unit tests: PASS" "${BASE}"/unit-tests-py3.12-*/verdict-3.12.txt \
  && grep -q "Unit tests: PASS" "${BASE}"/unit-tests-py3.13-*/verdict-3.13.txt \
  && grep -q "Type check: PASS" "${BASE}"/mypy-*/mypy-summary.txt \
  && grep -q "Opengrep: PASS"   "${BASE}"/opengrep-*/opengrep-summary.txt \
  && echo "ALL CI GATES PASS — safe to tag" \
  || echo "FAIL — one or more gates not green"
```

SOP-5: M7 boxes tick ONLY when this grep passes on real downloaded artifacts. CI URL alone is not sufficient.

---

## 6. Full Release Checklist (M7)

Execute in order. Gate N does not start until Gate N-1 is GREEN.

| # | Gate | Owner | Evidence path | Verdict grep |
|---|------|-------|---------------|--------------|
| 1 | Unit tests (py3.12) | Tom / CI | `ci-evidence/<sha>/unit-tests-py3.12-<sha>/verdict-3.12.txt` | `Unit tests: PASS` |
| 2 | Unit tests (py3.13) | Tom / CI | `ci-evidence/<sha>/unit-tests-py3.13-<sha>/verdict-3.13.txt` | `Unit tests: PASS` |
| 3 | Type check (mypy) | Tom / CI | `ci-evidence/<sha>/mypy-<sha>/mypy-summary.txt` | `Type check: PASS` |
| 4 | Opengrep scan | CI | `ci-evidence/<sha>/opengrep-<sha>/opengrep-summary.txt` | `Opengrep: PASS` |
| 5 | Bandit SAST | CI | `bandit-report-<sha>.json` in evidence dir | No HIGH/CRITICAL net-new |
| 6 | pip-audit | CI | `pip-audit-report-<sha>.json` | Exit 0 |
| 7 | Docker restore | Captain | `macos-podman-<sha>-closure-*.log` | `RESTORE TEST GREEN` + both admin 200 lines |
| 8 | Podman restore | Captain | same format | same |
| 9 | K8s Helm restore | Captain | `k8s-helm-<sha>-closure-*.log` | `RESTORE TEST GREEN` + both admin 200 lines |
| 10 | OWASP ASVS v5 L3 | Lu | `YCS-<date>-v<ver>-OWASP-3X.md` | No FAIL above Medium |
| 11 | Laura adversarial sweep | Laura | `laura-pentest/` findings | No P0/P1 open |
| 12 | Risk register updated | Lu | exception-register.md | All accepted risks logged |
| 13 | Tiago HITL GO | Maxine | Verbal/chat confirmation | "GO release" |
| 14 | Tag + push | Captain | `git tag v<ver>` | Tag visible on GitHub |

---

## 7. Tagging

```sh
# On branch 2.23.x, tip at the release SHA:
git tag -a "v2.23.1" -m "Yashigani v2.23.1"
git push origin "v2.23.1"
```

The `build-push.yml` and `release.yml` workflows trigger automatically on `v*.*.*` tags and handle image build, cosign signing, SBOM generation, and GitHub release creation.

---

## 8. Post-release

1. Fast-forward `main` to the release tag: `git push origin 2.23.x:main`.
2. Update `README.md` and `docs/` for the new version.
3. Archive the release evidence directory to long-term storage.
4. Write the release retro (ISO 9001 §9.3/10.2/10.3) in the DevOps evidence repository.
5. Open the next version milestone on GitHub.
