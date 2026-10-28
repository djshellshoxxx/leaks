# Restart handoff: Candor (djshellshoxxx/leaks), session z8tfnl, 2026-10-27

Read this first. It supersedes `process/HANDOFF-HAIKU-BATCH-z8tfnl.md` (on `claude/haiku-batch-z8tfnl`) for everything after that batch.

## 1. Identity and rules
- Repository: `djshellshoxxx/leaks` (origin verified). Default branch on GitHub: `claude/tender-tesla-z8tfnl` (PR #1, draft).
- `main` (`065ac0c`) shares NO history with the working branch. Do not compare against it.
- Working rules from the owner: Haiku-only for coordination, implementation and review; no new master plan; keep security decisions and production clearance with the owner; no real leaked documents or user data (synthetic fixtures only); no merge to `main`; no force-push; push tested slices to `claude/` branches.
- Workers are pinned to `claude-haiku-5-5` through the workflow tool. The coordinator (this session's model) is NOT verified as Haiku. `create_agent` cannot pin a model, so it was not used for workers.

## 2. Branch state (all pushed; local SHA = remote SHA verified)

| Branch | SHA | What it is | Status |
|---|---|---|---|
| `claude/tender-tesla-z8tfnl` | `4686d63` | Working base, PR #1 | Unchanged this session |
| `claude/split-render-tests-z8tfnl` | `4d3c420` | Test-only split of `candor-source-ui/tests/render.rs` into `tests/render/{layout,security,locale,forms,content}.rs` | Reviewed (Haiku reviewer APPROVE), 87 tests pass |
| `claude/split-chain-tests-z8tfnl` | `2bfcf03` | Test-only split of `candor-log/tests/chain.rs` into `tests/chain/{support,integrity,checkpoints,timestamps,disposal,sinks}.rs` | Reviewed (APPROVE), 104 tests pass. Adds `pub(super)` helpers in test code only |
| `claude/haiku-batch-z8tfnl` | `141127d` | Integration of the two splits + earlier handoff | Verified: fmt clean, clippy `-D warnings` clean, tests 87 + 104 pass |
| `claude/audit-reconcile-z8tfnl` | `cbee814` | `process/AUDIT-RECONCILIATION-78d516f.md`: reconciliation of the 2026-10-12 audit | Docs only. Based on `141127d` |
| `claude/fmt-worker-z8tfnl` | `2aeccd7` | Formatting only in `candor-worker` (2 spots). Fixes the only local `cargo fmt --check` failure at HEAD | `candor-worker` 9 tests pass. NOT yet run through full CI |

None of the `claude/` branches above is merged into `claude/tender-tesla-z8tfnl`.

Unmerged remote branches that exist and were NOT reviewed or merged by this session:
- `security/db-rls-no-self-enroll-20261012` (`13b4aa1`): fixes SEC-001 by removing `candor_case` writes to `core.case_member`. Based on `350435d`. Also makes SEC-003 (case creation) impossible, not fixed.
- `security/case-access-coi-20261012` (`e7c8878`): COI read path fix (SEC-002 partly) and a caller-supplied-actor `assign()`.
- `security/retention-hold-20261012` (`dd72981`): hold checks on retention transitions (SEC-006). Still trusts caller-supplied `today`.
- `security/auth-session-20261012` (`23dab5f`): session wrapper only (SEC-005 partial). No issuance, verification, revocation, step-up or RBAC.
- `docs/modular-first-roadmap-20261013` (`cd1cccf`, PR #8): AGENTS.md and modularisation roadmap. Owner direction; not merged.
- `docs/readme-and-wiki` (`445ccd0`, PR #9), `dependabot/github_actions/...` (`05578f7`, PR #10), `chatgpt/*` (PRs #2, #3) and `main`: not touched.

## 3. Audit reconciliation result (summary; full detail in the report)
The 2026-10-12 audit (`78d516f`) was checked against HEAD and the branches. Each finding has file:line evidence and, where relevant, a PostgreSQL 16 or Rust repro.

| ID | Status at HEAD `4686d63` |
|---|---|
| SEC-001 self-enrollment | STILL PRESENT (re-run by coordinator: `candor_case` inserted itself into another case) |
| SEC-002 COI and assign | PARTLY fixed on unmerged branch; `assign()` still lacks authenticated actor and audit commit |
| SEC-003 case creation impossible | STILL PRESENT. Audit's FK-ordering cause is only partly right: both orders fail |
| SEC-004 erasure approvals | STILL PRESENT; no branch touches `candor-ekv` |
| SEC-005 staff auth | PARTLY on branch; HEAD `candor-auth` is docs only and its test target does not compile |
| SEC-006 retention holds | STILL PRESENT at HEAD; FIXED on unmerged branch; `today` still caller-supplied |
| SEC-007 governance | STILL PRESENT: no branch protection, 0 rulesets, `@candor-project` teams return 404, SECURITY.md placeholders |
| SEC-008 CI | STILL PRESENT and worse: latest scheduled CI at HEAD failed 7 jobs (see §5) |
| SEC-009 relay | STILL PRESENT (absence confirmed): `candor-relay` is a rules library, no transport or daemon |

Reachability: no live request path was found for `candor-case`, `candor-ekv`, `candor-retention`'s transitions or `candor-relay` in this repository. That is INFERRED from wiring and grep, not proven against a deployment.

Repro tests (synthetic IDs, NOT committed because they fail on HEAD) are saved at `/mnt/session/outputs/audit-repro-78d516f/`: `audit_db_repro.rs` (SEC-001/003), `audit_sec002_repro.rs`, `zz_audit_repro_sec006.rs`, `zz_audit_repro_sec004.rs`. To use one, copy it into the matching crate's `tests/` directory in a clean worktree at `4686d63`.

## 4. Verified test state
- At `4686d63`, passing: `candor-source-ui` (87 across targets), `candor-log` (104), `candor-authz` (15), `candor-ekv`/`candor-retention`/`candor-worker` (17), `candor-auth` on branch `23dab5f` (7).
- At `4686d63`, NOT compiling or failing:
  - `candor-case` integration test `tests/authz_invariants.rs` (stale symbols), so `cargo test -p candor-case -p candor-authz` fails to compile.
  - `candor-auth` `tests/session_invariants.rs` (unresolved imports).
  - `candor-relay` `tests/relay_invariants.rs` (missing items and an unlisted `ed25519_dalek` dependency).
  - `candor-case-db` `tests/pg.rs::append_only_and_guard_triggers` fails (reported as pre-existing by the investigator; not yet diagnosed).
- Not run at all this session: full workspace test, `make check`, `cargo-deny`, `cargo-vet`, `scripts/check-*`, `cargo-vet` policy, fuzz, reproducibility, DB tests for the fix branches beyond the investigator's runs.

## 5. CI at HEAD (GitHub API, read-only)
- Latest scheduled CI at `4686d63` (run 40483603745, 2026-10-27): FAILED `cargo-deny`, `test (unprivileged user)`, `test (memlock limit)`, `supply-chain (cargo audit)`, `clippy -D warnings`, `cargo-vet`, `fmt`. Passed: `secret-scan`, `sbom`, `repo-lints`, `docs-lint`, `workflow-lint`, `reproducibility`. `dco` skipped.
- Fuzz nightly at `4686d63`: success.
- Local `cargo fmt --all -- --check` at HEAD: failed in `candor-worker` only; fixed on `claude/fmt-worker-z8tfnl`.
- The clippy, cargo-deny, cargo-vet and unprivileged-test failures are NOT yet diagnosed locally. Diagnose them from the job logs (GitHub API) or by running each command.

## 6. Credentials and environment
- GitHub token: saved at `/root/.config/candor/github-token` (mode 600, outside the repo). The repo-local `.git/config` has a github.com credential helper that resets the environment helper and reads that file. The environment's `ANTHROPIC_GIT` helper is still used for other hosts.
- The token was pasted into chat, and its scopes are broad (including `admin:org`, `admin:enterprise`, `workflow`, `repo`). The owner should REVOKE and re-issue as a fine-grained token limited to `djshellshoxxx/leaks`, then update the file.
- Commits are signed off (`git commit -s`) and carry `AI-Assisted: yes`. Git identity is the sandbox default (`Claude`).
- Local PostgreSQL 16 is available. Use `crates/candor-case-db/scripts/pg-test.sh <command>` (creates and removes a throwaway cluster; run as root in this sandbox).
- Cargo: `export CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0`; always `--locked` and `-p <crate>`. Four cores; run at most two cargo jobs at once.

## 7. Worktrees (scratch; safe to remove once this handoff is read)
`/workspace/leaks-wt/`: `split-render`, `split-chain`, `integration`, `reconcile`, `fmt-worker`, `audit-db`, `audit-case`, `audit-ret`, `audit-gov`. The audit worktrees are detached at `4686d63` and hold the untracked repro files (copies are in `/mnt/session/outputs/`). Do not remove the audit worktrees until the repros are no longer needed. Shared target directory: `/workspace/leaks/target` (about 0.7 GB now; disk has about 27 GB free).

## 8. Owner decisions (NOT decided by any agent; do not delegate)
1. SEC-003 bootstrap: which role or function may create a case and its first member, and on what authorization. No global RLS relaxation.
2. SEC-001 grants: whether removing all `candor_case` member writes (the fix branch) is acceptable, and what replaces it (a dedicated, audited membership service).
3. SEC-002 / SEC-005: whether a caller-supplied `Principal` can ever count as an authenticated actor (the audit says no). Whether assignment needs an audit commit.
4. SEC-004: design of erasure approvals (authenticated capabilities, durable two-person records, hold checks, separate restore privilege).
5. SEC-006: whether retention time may be caller-supplied.
6. SEC-007: create real teams and rulesets, publish disclosure channels and keys. The agent did not change any GitHub setting.
7. SEC-009: design and ownership of the authenticated relay transport.
8. Whether to merge any `security/*` branch. Each needs rebasing onto the current base and independent review first. Not merged.
9. Whether `docs/modular-first-roadmap` (PR #8) is accepted as project policy.

## 9. Next steps, in order
1. Owner: revoke and replace the GitHub token (§6).
2. Haiku-suitable (straightforward, no security design): diagnose and fix the HEAD CI failures that are not design issues (clippy, cargo-deny, unprivileged test, memlock test, cargo-vet policy). Do not weaken assertions, thresholds or lints; each fix needs a test or a documented reason. Run the same command CI runs. Record the result per job.
3. Haiku-suitable: make the three non-compiling test targets (§4) compile by updating stale imports, OR mark them clearly as unimplemented specs with an owner-approved `#[ignore]` reason. Do not delete them without owner approval (`process/STATUS.md` says owner approved deleting only two specific files).
4. Owner review, then rebase and review each `security/*` branch, one at a time, starting with `security/retention-hold-20261012` (smallest). Re-run the repros on each.
5. Owner decisions in §8, then implement the approved designs under independent review (builder ≠ reviewer), per `specs/impl/IMPL-00`.
6. After CI is green on a branch and the owner accepts it, open or update a draft PR. Do not merge to `main`.

## 10. Remaining unverified and blocked
- No production or release clearance exists. Audit disposition stands: NOT CLEARED FOR PRODUCTION.
- Independent cryptography review, external audits, anonymity and usability assessments, key ceremonies and deployment verification are all still required (`process/STATUS.md` §4).
- Nothing here establishes that the platform is secure, anonymous or production-ready.
