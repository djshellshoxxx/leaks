<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-authz — implementation and integration status

**Status: experimental, partially implemented, not independently security-cleared.** This crate currently exposes a narrow, deny-by-default RM-3 authorization API. It is **not** the full policy engine described in the RM-3 specifications. The authoritative project/security gate summary is [process/STATUS.md](../../process/STATUS.md).

## What is compiled today

[src/lib.rs](src/lib.rs) defines the public `TenantId`, `UserId`, `CaseId`, `Role`, `Principal`, `CaseResource`, `authorize`, `authorize_case`, and `validate_wrap_recipients` types/functions. It imports and re-exports only [src/session.rs](src/session.rs), which supplies `Session`, `SessionToken`, audiences and session-expiry validation.

The current small API performs basic cross-tenant, role, assignment and conflict-of-interest denial checks. `authorize_case` also returns step-up and second-approver **obligations** for original export. These return values are not evidence that a caller has implemented obligation enforcement, persistence, step-up verification or production policy completeness. Its scope and tests are [tests/policy.rs](tests/policy.rs), [tests/rm3_contract.rs](tests/rm3_contract.rs), and [tests/session_contract.rs](tests/session_contract.rs).

## Unintegrated source modules

The repository also contains [src/model.rs](src/model.rs), [src/ids.rs](src/ids.rs), [src/policy.rs](src/policy.rs), and [src/coi.rs](src/coi.rs). They describe a substantially richer authorization model, including role/permission registries, scoped assignments, blind COI tags, canonical policy parsing and case-object facts. **At the pinned default SHA `9097f75f6529ed3dfa259de20d2fa9c78f434bda`, these four files are not declared by `src/lib.rs` and are not part of the compiled library API.** Their existence must not be counted as implemented or tested authorization functionality. Do not expose or wire these modules into an execution path without a separate test-first, owner-coordinated security review of the policy semantics and trust boundaries.

## Developer checks and acceptance

With the repository toolchain and locked dependencies available, run:

```sh
cargo test -p candor-authz --all-targets --locked
cargo clippy -p candor-authz --all-targets --locked -- -D warnings
cargo fmt -p candor-authz -- --check
```

These are **commands to run**, not a claim that they were executed by this documentation update. The mandatory workspace CI and independent authorization/security review remain separate acceptance gates. Current workspace-level blockers include DCO history, unrelated formatting/Clippy/compilation failures, cargo-deny advisories and Security Lead cargo-vet approvals. Check the [qualification runbook](../../docs/CI-QUALIFICATION-RUNBOOK.md) (in this documentation PR) and the latest [continuation handoff](https://github.com/djshellshoxxx/leaks/pull/13) (on separate draft PR #13) for source-pinned results; neither unmerged file is part of the current default branch.

## Integration next steps

Agree on the canonical public authorization contract and module ownership with the active RM-3/security owners, retain deny-by-default behavior, add regression tests for each intended policy/COI/approval contract, then verify against the normative specs and independent review gates. Do not infer production readiness, authorization assurance or privacy certification from this partial crate.
