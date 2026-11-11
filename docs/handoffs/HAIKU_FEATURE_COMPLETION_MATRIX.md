# Haiku feature completion matrix

Source-pinned at `9097f75f6529ed3dfa259de20d2fa9c78f434bda`. Local results come from `cargo` runs in this session. CI results come from remote run 42817477461. Status labels follow the directive. Nothing here is an estimated percentage.

Per-crate test counts are **not** given. Cargo interleaved test-binary output in this session, so counts could not be reliably attributed to crates. What was measured:

- `cargo test --workspace --exclude candor-auth --exclude candor-relay --exclude candor-case --no-fail-fast --locked`: **792 passed, 0 failed**, exit 0.
- `cargo test -p candor-case --test case_service --test schema --locked`: **4 passed** and **3 passed**, 0 failed.
- `cargo test -p candor-auth -p candor-relay -p candor-case -p candor-authz -p candor-worker --locked` at PR #16 head `bd33ef9`: **83 passed, 0 failed**, exit 0.
- `candor-intake-store/tests/pg.rs` and `candor-case-db/tests/pg.rs` return early without `CANDOR_TEST_PG`, so their passes are **vacuous**.

Audit gates are copied from `process/STATUS.md` §1 and were not re-derived this cycle. "Escalate" means the change falls under the directive's escalation list (§1).

| Feature / crate | Status | Owner (PR) | Local evidence | Audit gate | Risk | Haiku suitability | Next action |
|---|---|---|---|---|---|---|---|
| Workspace formatting | Partial | PR #11 | `fmt` FAIL at `9097f75` (candor-worker). PR #11 head `33dc579` PASS. | n/a | Low | Yes (owned) | Merge PR #11 |
| Workspace clippy (`-D warnings`) | Partial | PR #11, PR #16 | FAIL at `9097f75`: 4 `arithmetic_side_effects` errors in candor-worker `job.rs`. PR #11 head PASS except the three spec-ahead crates. | n/a | Low | Yes (owned) | Merge PR #11, then PR #16 |
| `candor-auth` session | Blocked (spec-ahead test) | PR #7, PR #16 | `tests/session_invariants.rs` does not compile at `9097f75`. PR #16 head: PASS (in the 83). | n/a | High (sessions) | Escalate | Review PR #16 and PR #7 |
| `candor-authz` engine | Implemented, unqualified | PR #4, PR #16 | `policy`, `rm3_contract`, `session_contract` PASS at `9097f75`; PR #16 head PASS | n/a | High (authorization) | Escalate | Independent audit |
| `candor-case` service | Partial | PR #16 | `case_service` 4 and `schema` 3 PASS. `tests/authz_invariants.rs` does not compile at `9097f75`. PR #16 head PASS. | n/a | High | Escalate | Review PR #16 |
| `candor-case-db` (RLS, TenantTx) | Partial | PR #5 | Unit and `pg.rs` pass, but `pg.rs` is vacuous without PostgreSQL | Not audited | High | Conditional (needs live PG run) | Run the PG suite with `CANDOR_TEST_PG` |
| `candor-relay` request auth | Blocked (spec-ahead tests) | PR #16 | `tests/relay_invariants.rs` does not compile at `9097f75`. PR #16 head PASS. | n/a | High (signatures, replay) | Escalate | Review PR #16 |
| `candor-worker` jobs and backoff | Implemented, unqualified | PR #11 (lint) | Crate tests inside the 792 PASS. Clippy FAIL at `9097f75`, PASS on PR #11 head. | Not audited. Jitter spec not implemented at `9097f75` (`process/STATUS.md` §6). | Medium | Conditional | Independent audit |
| `candor-retention` | Implemented, unqualified | PR #6 (hold) | Crate tests inside the 792 PASS | Not audited | Medium | Conditional | Review PR #6 |
| `candor-notify` / `candor-ekv` | Implemented, unqualified | none | Crate tests inside the 792 PASS | Not audited | Medium | Conditional | Audit |
| `candor-log` (audit log) | Partial | none | Crate tests inside the 792 PASS | **FAIL**: LOG-02, LOG-16 High open; LOG-17..19 Medium | High (privacy) | Escalate | Stronger model to fix, then re-audit |
| `candor-safefs` | Partial | none | Crate tests inside the 792 PASS | File gate **FAIL** (`fc64069`) | High (file handling) | Escalate | Re-audit |
| `candor-safe-read` | Implemented and qualified | none | Crate tests inside the 792 PASS | PASS (with `deploy/`) | Low | n/a | none |
| `candor-core` (crypto) | Implemented and qualified | none | Crate tests inside the 792 PASS, including `ct_timing` | PASS (`0d486a9`) | High (cryptography) | No (escalation list) | none this cycle |
| `candor-memlock` | Implemented and qualified | none | Crate tests inside the 792 PASS. Production memlock limit not reproduced. | PASS (`2c00f6f`) | Medium | No | none |
| `candor-sealer` | Implemented and qualified | none | Crate tests inside the 792 PASS | PASS (`3f41a3a`) | High | No | none |
| `candor-intake-store` (istore IPC) | Partial | none | Crate tests inside the 792 PASS. `pg.rs` vacuous. | **FAIL**: IPC-15 High open; round-4 re-audit pending | High | Escalate | Round-4 re-audit |
| `candor-intake-web` | Implemented, unqualified | PR #14 (review notes) | Crate tests inside the 792 PASS | PASS for in-scope files (`9ffeffd`); later changes void it | High (Tor-only intake) | Conditional | Fuzz runs not executed (per audit file) |
| `candor-source-ui` | Implemented and qualified | PR #13 (test isolation) | Crate tests inside the 792 PASS | PASS (`c9014b2`) | Low | Yes (tests only) | none |
| Remote CI (`ci` run 42817477461) | Partial | PR #1 | FAIL: fmt, clippy, test, test (unprivileged), cargo-deny, cargo-audit, cargo-vet. PASS: sbom, reproducibility, docs-lint, workflow-lint, repo-lints, secret-scan. DCO skipped. | n/a | Medium | Diagnosis only | Reproduce cargo-deny and cargo-audit |
| DCO (Signed-off-by) | Blocked | owner | Skipped on run | n/a | Low | No (owner) | Owner decides on epoch |
| cargo-vet | Blocked | owner | Policy-lint job FAIL | n/a | High (supply chain) | No (Security Lead) | Security Lead sign-off |
| Wiki and README | Partial | PR #9 | `docs/wiki/*` absent at `9097f75` | n/a | Low | Yes (after PR merge) | Review PR #9 |
| Zero-Codex continuation docs | Not on branch | PR #12, PR #15 | Absent at `9097f75` | n/a | Low | Yes (docs only) | Not read this cycle |
| `candor-auth` non-session parts | Not started at `9097f75` | PR #16 | None at `9097f75` | n/a | High | Escalate | none this cycle |
| CLI tooling | Not started | none | Not inventoried | n/a | Low | Yes | Inventory, then tests |
| Accessibility and UI | Not started | PR #13 | Not inventoried | n/a | Medium | Conditional | Inventory |
| End-to-end integration | Not started | none | No PostgreSQL run; `CANDOR_TEST_PG` unset | n/a | High | Conditional | Run PG suites first |
| Release, installers, TUF, RM-4/5/8 | Future-only | none | n/a | n/a | High | No | Outside Haiku scope |
| Independent audit ledger | Not started | none | No audit performed | n/a | n/a | n/a | No ledger created |
