# Last updated: 2026-05-01T00:00:00+01:00
# Yashigani — top-level Makefile
#
# Primary target relevant to service identity manifest management:
#
#   sync-service-identities  — copy docker/ canonical → helm/files/ derived copy
#   check-service-identities — verify the two copies have identical SHA-256 (CI gate)
#
# See docs/development/service_identities.md for the full workflow.

.PHONY: sync-service-identities check-service-identities

CANONICAL := docker/service_identities.yaml
HELM_COPY  := helm/yashigani/files/service_identities.yaml

## sync-service-identities: copy the canonical source into the Helm chart files dir.
## Run this every time you edit docker/service_identities.yaml, then commit both files.
sync-service-identities:
	@echo "[sync] Copying $(CANONICAL) → $(HELM_COPY)"
	@cp -f "$(CANONICAL)" "$(HELM_COPY)"
	@echo "[sync] Done. Verify with: make check-service-identities"

## check-service-identities: fail if canonical and helm copy have diverged.
## This is the same assertion run by tests/contracts/test_service_identities_sha.py.
check-service-identities:
	@CANONICAL_SHA=$$(shasum -a 256 "$(CANONICAL)"  | awk '{print $$1}'); \
	 HELM_SHA=$$(shasum -a 256 "$(HELM_COPY)" | awk '{print $$1}'); \
	 if [ "$$CANONICAL_SHA" != "$$HELM_SHA" ]; then \
	   echo "DRIFT DETECTED — service_identities.yaml copies have diverged."; \
	   echo "  Canonical ($(CANONICAL)):  $$CANONICAL_SHA"; \
	   echo "  Helm copy  ($(HELM_COPY)): $$HELM_SHA"; \
	   echo "  Fix: edit $(CANONICAL), then run: make sync-service-identities"; \
	   exit 1; \
	 fi
	@echo "OK — service_identities.yaml copies are identical."
