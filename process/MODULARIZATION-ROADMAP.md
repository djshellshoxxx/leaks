<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Candor modularization roadmap

**Status:** Planned; no code refactor has been performed by this document.
**Owner direction (2026-10-13):** Every future code change must be modular. All existing code is to migrate **incrementally**, without changing observable behaviour, trust boundaries or the architecture's security properties. The standing developer rule is in [AGENTS.md](../AGENTS.md).

## Current architecture

Candor is **already modular at the crate level**: `candor-core`, `candor-safefs`, `candor-log`, `candor-source-ui`, `candor-intake-store`, `candor-intake-web`, `candor-sealer`, `candor-case-db`, and other focused crates already expose distinct responsibilities. The primary debt is inside **large files within those crates**. The safest changes are in tests and data-only modules, **not** splitting the workspace into additional crates.

This is a code-layout assessment of the development-branch snapshot `350435d0e243424df75f9c84117edb00a68e3bd3`, not an assertion that its full tests pass. File sizes and line counts are approximate and can change.

## First wave: low risk, small independent PRs

| Priority | Existing code | Proposed extraction / interface | Risk / difficulty | Behaviour and test preservation |
|---|---|---|---|---|
| **1** | `crates/candor-source-ui/tests/render.rs` (~1,314 lines) | Split test groups into `tests/render/{layout,security,locale,forms,content}.rs` behind existing test target; keep shared fixtures in one private `support` module. | **Very low / easy**. Tests only. | Exact same assertions and cases; ensure test runner still discovers all tests and property tests, same output snapshots. |
| **2** | `crates/candor-log/tests/chain.rs` (~1,912 lines) | Group chain-verification, timestamp, disposal/retention, checkpoint and failure-injection tests under `tests/chain/`; keep shared harness in `support.rs`. | **Very low / easy to moderate**. Tests only; helper scope needs attention. | Do not change golden records, signed bytes, failure assertions, fixture clocks or test count. Run `cargo test -p candor-log --all-targets --locked`. |
| **3** | `crates/candor-intake-store/tests/common/mod.rs` (~1,978 lines) | Split into focused test-harness modules: `fixtures`, `accounts`, `envelopes`, `mailbox`, `deletion`, `restore`, `statistics`, with explicit re-exports for existing integration test callers. | **Low / moderate**. Test-only, but generic fixtures/macros are widely shared. | Keep fixture bytes and outcomes identical; preserve public names used by tests, cargo feature matrices and PostgreSQL fixture setup. Run store integration tests with the existing ephemeral PostgreSQL harness. |
| **4** | `crates/candor-source-ui/src/model.rs` (~1,009 lines) | Keep `model/mod.rs` as the compatibility facade, and group existing types by `context`, `questions`, `report`, `messages`, `inbox` (final ownership determined from imports). Preserve `pub use model::*` as externally visible. | **Low / moderate**. Mostly data types, but derives, trait impls and custom redacted `Debug` matter. | Zero added dependencies; compare public API, `Debug` redaction, types, field visibility, and generated HTML byte-for-byte. Run `cargo test -p candor-source-ui --all-targets --locked`. |
| **5** | `crates/candor-source-ui/src/view.rs` (~956 lines) | Start with **display-only** helpers such as `size_parts` and `PartNav`, then extract more coherent display formatting into a private `view/format.rs` module. | **Low to moderate / easy** for display-only pieces. | Keep render strings, output padding, allocation and public visibility unchanged. **Do not** move XSS/HTML escaping, secret zeroization, bidi neutralization or URL allow-list handling in this first pass; those are security-sensitive. |

Each row should be its **own PR**, ideally one production module or one test-only suite per PR. These are opportunities, not approved implementations. Do not mechanically generate directories or split a file without checking cross-module ownership and privacy requirements.

## Second wave: valuable but higher integration risk

| Existing code | Candidate responsibility boundary | Risk and prerequisites |
|---|---|---|
| `crates/candor-intake-store/src/pg.rs` (~2,657 lines) | Private typed SQL row-decoding and, separately, a documented SQL statement catalog / repository responsibilities. | **Medium.** SQL strings, transaction scope, RLS and PostgreSQL errors are security contracts. Require the live PostgreSQL suite, exact schema/grant checks, transaction and failure-path tests; no SQL rewrites during structural changes. |
| `crates/candor-intake-web/src/flows.rs` (~2,408 lines) | Split small pure draft-to-view conversions from stateful GET/POST, session, upload and source identity flows. | **Medium to high.** Start only after request/response and anonymity invariants are green. Keep timing, source metadata, form limits, error uniformity and upload state unchanged. |
| `crates/candor-sealer/src/server/mod.rs` (~3,432 lines) | Independent configuration parsing, resource-limit validation, health adapters; later session/draft state orchestration. | **High Trust Path.** Resource budgets, cryptography, zeroization, timing and locking make even code movement sensitive. Separate audited PRs, with secure memory and concurrency verification. |
| `crates/candor-intake-store/src/pg.rs`, `crates/candor-case-db/src/repo/case.rs` and RLS/migrations | Domain-specific storage modules and dedicated atomic provisioning interface, only after security defects have been resolved. | **High.** Existing case membership self-enrollment and bootstrap/creation issues are active security work; **do not** refactor their SQL or public interfaces in a layout-only PR. |
| `crates/candor-log/src/metrics.rs` (~1,607 lines) | Separate counter aggregation, privacy threshold / suppression proof, persisted release-history. | **Medium to high.** Suppression mechanisms protect anonymity; requires release-equivalence and adversarial data-set tests. |
| `candor-core`, `candor-ekv`, `candor-authz`, `candor-retention` and cryptographic protocol code | Additional internal decomposition after isolated protocol and authorization contracts are specified. | **Defer pending security remediation and independent cryptographic/authorization review.** |

## Module contract and migration checklist

Before every extraction, write a concise implementation note in the PR:

1. **Ownership:** which crate owns the types, rules and data? Which consumers import them?
2. **Scope:** exact old-file to new-file mapping, exports, visibilities and imports; keep only one canonical implementation.
3. **Contracts:** list what **must not change**: function and API signatures, enum representation, serialization and wire bytes, schema/migration, error semantics, pagination, log fields and privacy-sensitive timing.
4. **Security:** assign T0/T1/T2 classification from `security/classification.toml`. Even test-only modifications must not weaken coverage or delete required negative cases. Do not broaden `pub` visibility to sidestep module privacy.
5. **Proof:** record baseline tests and compile result **before** moving code, run the same tests after; add contract/golden tests for affected boundaries and confirm no test disappearance. If the base is red, distinguish pre-existing failures from new ones.
6. **Integration:** maintain module index / crate README and use the existing `pub use` compatibility facade. No new dependency just for organization.
7. **Change control:** isolated branch/PR, DCO sign-off, scoped compile and test, rustfmt/Clippy, required independent security review, clear rollback (revert one PR).
8. **Acceptance:** merge only after an appropriate reviewer verifies interface equivalence and the same security checks have passed (or unrelated baseline failures are explicitly identified and the change is held).

## Known parallel work / conflict avoidance

As of this snapshot, security PRs **#4 (COI and case assignment), #5 (RLS membership), #6 (retention legal hold), and #7 (staff session primitives)** touch sensitive code. Do not reorganize their files in parallel with those fixes or rebase over an unrelated developer branch without coordination. Prefer the test-only and UI-model candidates first.

## Proposed order of work

Start with one test-suite extraction (`candor-source-ui/tests/render.rs`), prove that its test inventory and result are unchanged, then take the `candor-log` test split and intake-store test harness. Once security and baseline CI permit it, split the UI data model, then selected pure formatting. Save the main database, HTTP workflow, sealer, authorization, retention and cryptography refactors for separately scoped, audited migrations.

**Non-goal:** a wholesale rewrite, a change in runtime behavior, or multiplying crates simply to call code “modular.” Existing boundaries should be respected and improved gradually.
