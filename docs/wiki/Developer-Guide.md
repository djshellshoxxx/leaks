# Developer Guide

## Workspace

Rust workspace (`Cargo.toml`, edition 2024, rust-version 1.94). Members are `crates/*`. Dependencies are
pinned with exact versions and `Cargo.lock` is committed. `unsafe_code` is forbidden by workspace lints;
`unwrap`, `expect` and `panic` are denied by Clippy.

## Make targets

From the `Makefile`:

- `make check`: fmt-check, clippy, test, deny, vet, docs-lint
- `make test`, `make clippy`, `make fmt`, `make deny`, `make vet`
- `make docs-lint`, `make secret-scan`, `make sbom`, `make repro`

Run `make help` for the full list. CI is in `.github/workflows/` (`ci.yml`, `fuzz-nightly.yml`, `release-gate.yml`).

## Requirements traceability

Regenerate with the scripts in `tools/` (`traceability.py`, `review_report.py`, `constants_lint.py`);
see the README section "Regenerating the traceability matrix".

## Rules

- Read `specs/DECISIONS.md` before changing architecture; decisions are binding.
- Read `CONTRIBUTING.md` and `SECURITY.md` before submitting changes.
- Do not add real case data, credentials or personal data to the repository.
