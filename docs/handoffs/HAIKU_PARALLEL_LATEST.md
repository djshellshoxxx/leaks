# Haiku parallel cycle: latest report

Documentation-only cycle. No source, test, CI or policy file was changed. Every result below was produced by a command in this session or read from the GitHub API; nothing is inferred from earlier handoff text.

## 1. Pinned state (2026-11-11)

| Item | Value |
|---|---|
| Working branch | `claude/eager-sagan-wsuokn` (no remote branch existed before this cycle) |
| Base commit | `9097f75f6529ed3dfa259de20d2fa9c78f434bda` |
| Remote `HEAD` symref | `claude/tender-tesla-z8tfnl` (same commit as the base) |
| `main` | `065ac0c8304d654d494fa522880bda8414e7e4ed` (PR #1 targets `main`) |
| Toolchain | Rust 1.94.1, pinned in `rust-toolchain.toml` |
| Host | 4 vCPU, 15 GiB RAM |

Documents the directive names that are **absent from this branch**: `AGENTS.md`, `docs/CHATGPT_ZERO_CODEX_CONTINUATION.md`, `docs/handoffs/CHATGPT_ZERO_CODEX_LATEST.md`, `docs/wiki/*`, `docs/audits/HAIKU_RANDOM_AUDIT_LEDGER.md`. The zero-Codex and wiki documents appear to be added by open PRs #9, #12 and #15, judging by their titles. Their contents were not checked this cycle.

## 2. Local baseline at `9097f75`

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | **FAIL**: `crates/candor-worker/src/lib.rs`, `crates/candor-worker/tests/job_retention.rs` |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | **FAIL**: 4 × `arithmetic_side_effects` in `crates/candor-worker/src/job.rs` (lines 139, 140, 143, 144). The run stopped at `candor-worker`. |
| `cargo test --workspace --locked` | **FAIL to compile**, three spec-ahead test targets: `candor-auth/tests/session_invariants.rs` (imports types that do not exist), `candor-relay/tests/relay_invariants.rs` (missing `RelayAuthenticator`, `Backpressure`, `request_signing_message`; `ed25519_dalek` not a dependency), `candor-case/tests/authz_invariants.rs` (missing `AuthzContext`, `DenyCode`, `Obligation`, `validate_key_wraps`, private `authorize`). |
| `cargo test` excluding `candor-auth`, `candor-relay`, `candor-case` | **PASS**: 792 passed, 0 failed |
| `cargo test -p candor-case --test case_service --test schema` | **PASS**: 4 and 3 passed |

**Vacuous passes:** `candor-intake-store/tests/pg.rs` and `candor-case-db/tests/pg.rs` return early when `CANDOR_TEST_PG` is unset. Their "passed in 0.00s" results prove nothing about PostgreSQL. No database was started in this cycle, so live-database behaviour is **unverified**.

## 3. Checks on open PR heads (read-only; no branch was modified)

| Head | Check | Result |
|---|---|---|
| PR #11 `33dc579` | `cargo fmt --all -- --check` | PASS |
| PR #11 `33dc579` | `cargo clippy --workspace --all-targets --all-features --locked --exclude candor-auth --exclude candor-relay --exclude candor-case -- -D warnings` | PASS |
| PR #11 `33dc579` | same clippy without the excludes | FAIL only because of the three spec-ahead targets |
| PR #11 `33dc579` | `job.rs` change | Replaces arithmetic with saturating operations. Results are unchanged, and the comments justify why saturation never triggers. |
| PR #16 `bd33ef9` | `cargo test -p candor-auth -p candor-relay -p candor-case -p candor-authz -p candor-worker --locked --no-fail-fast` | PASS: 83 passed, 0 failed, exit 0 |

**Not tested:** PR #11 and PR #16 combined. Neither is merged, and no integration branch containing both was built.

## 4. Remote CI at `9097f75` (run 42817477461, scheduled, 2026-11-10)

- **Failed:** `fmt`, `clippy`, `test`, `test (unprivileged user)`, `cargo-deny`, `supply-chain (cargo audit)`, `cargo-vet (PR policy)`.
- **Skipped:** `dco`.
- **Passed:** `sbom`, `reproducibility`, `docs-lint`, `workflow-lint`, `repo-lints`, `secret-scan`.
- **Reproduced locally:** `fmt`, `clippy`, `test` (the compile blockers above).
- **Not reproduced (not run here):** `cargo-deny`, `cargo-audit`, `cargo-vet`, DCO, the unprivileged-user test, the memlock-limited test run. Their causes are unknown from this session.
- The same failure pattern appears in runs 188, 189 and 190.

## 5. Why no parallel worker fan-out

- The host has 4 cores. `process/STATUS.md` §5 sets a limit of two agents at a time.
- Every code workstream a Haiku worker could take is either owned by an open draft PR (#4–#7, #11, #16), which the directive forbids duplicating, or is gated on an owner decision or a stronger model: cryptography, IPC, log privacy, authorization policy, retention semantics, DCO and cargo-vet sign-off.
- No code was written, so no worker branches were created. Twelve parallel workers would have cost compute without producing work that could be merged.

## 6. Workstream ownership (directive §3 mapped to existing owners)

| Workstream | Current owner | State this cycle |
|---|---|---|
| 1 Build and CI | PR #11 (fmt, worker lint); PR #16 (spec-ahead tests) | Verified on PR heads above. Not merged. |
| 2 Submission intake | none open | Not audited this cycle. Intake-web audit PASS at `9ffeffd` (per `process/STATUS.md`); later changes void it. |
| 3 Sessions | PR #7 (staff session), PR #4 (case access) | Security-sensitive. Escalate. |
| 4 Case and recipient workflows | PR #4, PR #5 | No Haiku-appropriate work identified. |
| 5 Persistence and retention | PR #6 (retention hold) | `candor-log` audit FAIL (LOG-02, LOG-16 High). Escalate. |
| 6 CLI | none | Not started. Not audited. |
| 7 Accessibility | PR #13 (padding tests) | No work this cycle. |
| 8 Security regression tests | PR #16 | No new tests added. |
| 9 Integration and end-to-end | none | Not started. PostgreSQL suites are vacuous without `CANDOR_TEST_PG`. |
| 10 Documentation and wiki | PR #9 (wiki), PR #12, PR #15 (ledger), PR #14 (audit notes) | `docs/wiki/` absent on this branch. |
| 11 Build reproducibility and developer experience | none | Not started. |
| 12 Independent read-only audit | none | **No audit performed.** No ledger created. |

## 7. Blockers needing a person or a stronger model

1. Merge PR #11 and PR #16. Their order and combined CI are unknown until they are rebased together. PR #16 needs its own review because it changes relay authentication, staff sessions and authorization.
2. Owner decisions on the spec-ahead test files, listed in `process/STATUS.md` §6.
3. Audit gates recorded as FAIL: `candor-log` (LOG-02, LOG-16 High), istore IPC-15 (round-4 re-audit pending), `candor-safefs` file gate.
4. Security Lead sign-off on the imported cargo-vet sets (`supply-chain/trusted-importers.toml`). DCO sign-offs for imported commits are also owner-only.
5. Cause of the cargo-deny and cargo-audit failures, to be reproduced with the pinned tools.
6. Base-branch question: PR #1 targets `main`, while the remote `HEAD` is `claude/tender-tesla-z8tfnl`. The owner should decide which is the integration branch.

## 8. Next cycle (unblocked, Haiku-appropriate)

1. Run the PostgreSQL suites with `CANDOR_TEST_PG` set, against a disposable local cluster, to replace the vacuous passes with real results.
2. Reproduce the cargo-deny and cargo-audit failures locally with the versions pinned in `.github/actions/cargo-install`.
3. After the owner merges PR #11, rerun the full baseline in §2 and update this file.
