# SPDX-License-Identifier: AGPL-3.0-or-later
# Local entry points mirroring .github/workflows/ci.yml (27 §13 PR gate subset).
# Tool pins (install with `make tools`):
CARGO_DENY_VERSION      := 0.20.2
CARGO_VET_VERSION       := 0.10.2
CARGO_CYCLONEDX_VERSION := 0.5.9

CARGO   ?= cargo
PYTHON  ?= python3
SBOM_OUT ?= target/sbom

.PHONY: check fmt fmt-check clippy test deny vet docs-lint workflow-lint repro sbom tools help

help:
	@echo "make check      fmt-check, clippy (-D warnings), test, cargo-deny, cargo-vet, docs-lint"
	@echo "make repro      build twice in clean dirs and compare artefact sha256 (scripts/repro-check.sh)"
	@echo "make sbom       CycloneDX SBOMs into $(SBOM_OUT) (scripts/sbom.sh)"
	@echo "make tools      install pinned cargo-deny / cargo-vet / cargo-cyclonedx"

check: fmt-check clippy test deny vet docs-lint

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --workspace --all-targets --all-features --locked -- -D warnings

test:
	$(CARGO) test --workspace --all-features --locked

deny:
	$(CARGO) deny --locked check advisories bans licenses sources

vet:
	$(CARGO) vet --locked

docs-lint:
	$(PYTHON) tools/traceability.py
	$(PYTHON) tools/constants_lint.py

workflow-lint:
	sh scripts/check-actions-pinned.sh

repro:
	sh scripts/repro-check.sh

sbom:
	sh scripts/sbom.sh $(SBOM_OUT)

tools:
	$(CARGO) install --locked --version =$(CARGO_DENY_VERSION) cargo-deny
	$(CARGO) install --locked --version =$(CARGO_VET_VERSION) cargo-vet
	$(CARGO) install --locked --version =$(CARGO_CYCLONEDX_VERSION) cargo-cyclonedx
