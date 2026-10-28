# Audit reconciliation: Candor security audit of revision 78d516f (2026-10-12)

Repository: `djshellshoxxx/leaks` (remote `https://github.com/djshellshoxxx/leaks.git`, confirmed).
Reconciled against: `4686d63` (current `claude/tender-tesla-z8tfnl` tip), plus the unmerged fix branches on origin.
Method: Haiku investigators (pinned model), each in its own worktree. Source reading, Rust tests, PostgreSQL 16 repro tests via `crates/candor-case-db/scripts/pg-test.sh`, and read-only GitHub REST GET requests. One repro (SEC-001 and SEC-003) was re-run by the coordinator on HEAD.
Synthetic fixtures only. No tracked file was changed in the investigation. No GitHub setting, branch protection, ruleset or secret was changed.

Status key: STILL_PRESENT, PARTIALLY_FIXED (on an unmerged branch), FIXED_ON_BRANCH_UNMERGED, UNVERIFIED. None of these is a clearance. Production clearance and security design decisions stay with the project owner.

## Summary table

| ID | Audit severity | Status at HEAD 4686d63 | Unmerged fix branch | Evidence in one line |
|---|---|---|---|---|
| SEC-001 | HIGH | STILL_PRESENT (re-run by coordinator) | `security/db-rls-no-self-enroll-20261012` (13b4aa1): refused | `0001_case_schema.sql:1326-1328` WITH CHECK still allows `user_id = candor.uid()`; a `candor_case` session inserted itself into another case and saw it |
| SEC-002 | HIGH | STILL_PRESENT (read path) | `security/case-access-coi-20261012` (e7c8878): PARTIAL | `candor-case/src/lib.rs:121` `coi_user: None`; `candor-authz/src/lib.rs:71-75` COI only when Some |
| SEC-003 | HIGH | STILL_PRESENT, cause partly mis-stated by audit | none fixes it; the 13b4aa1 fix makes member writes impossible | Case INSERT refused by RLS; membership-first refused by FK; no role can create a case |
| SEC-004 | HIGH (conditional) | STILL_PRESENT | none (ekv unchanged on every branch) | Two distinct `ApproverId` values from one caller erase a key; restore and rekey need no approval |
| SEC-005 | HIGH | PARTIALLY_FIXED on branch; HEAD test target does not compile | `security/auth-session-20261012` (23dab5f): PARTIAL | HEAD `candor-auth/src/lib.rs` has docs only; branch adds a session wrapper, no issuance, verification, revocation, step-up or RBAC |
| SEC-006 | MEDIUM/HIGH (conditional) | STILL_PRESENT at HEAD | `security/retention-hold-20261012` (dd72981): FIXED_ON_BRANCH_UNMERGED | HEAD: held item reaches Disposed through three `Ok` calls; branch refuses all three with `LegalHold` |
| SEC-007 | HIGH (governance) | STILL_PRESENT | none | GitHub API: no branch protection, 0 rulesets, `/orgs/candor-project` 404; SECURITY.md placeholders |
| SEC-008 | HIGH (release) | STILL_PRESENT, and worse than the audit described | none | Latest scheduled CI at HEAD (40483603745) failed 7 jobs including fmt, clippy, cargo-deny and both test jobs |
| SEC-009 | MEDIUM/HIGH | STILL_PRESENT (absence confirmed) | none | `candor-relay` is a rules library; no transport, daemon, unit or dependent |

## Per-finding reconciliation

### SEC-001: self-enrollment through `core.case_member` (HIGH). STILL_PRESENT
- HEAD: `crates/candor-case-db/migrations/0001_case_schema.sql:1326-1328` still has `WITH CHECK (user_id = candor.uid() OR acl.is_case_member(case_member.case_id))`. Grant at `:1406` gives `candor_case` INSERT, UPDATE and DELETE on `core.case_member`.
- Reproduced at HEAD by the coordinator and the investigator (untracked `tests/audit_db_repro.rs`, not committed): a `candor_case` session with an unrelated tenant user inserted a `lead` row for itself into another case (OK). The stranger then saw that case (count 1). `repo::case::add_member` as a Desk principal returned `Ok(())`. A self-UPDATE that moved a row to another user was also accepted. The audit's core claim holds.
- Fix branch `13b4aa1`: the stranger's INSERT and `add_member` are refused with SQLSTATE 42501 at the table-grant level, not by the rewritten RLS. Its test does not isolate the policy change. Note: the branch is not an ancestor of HEAD, and it is based on `350435d`.
- Owner decision: the branch removes all `candor_case` write access to `case_member`. That is fail-closed, but it also removes the path that any authorized grant workflow would use. A dedicated, audited membership service has to be designed (see Owner decisions).

### SEC-002: COI and assignment (HIGH). PARTIALLY_FIXED on branch; live exposure UNVERIFIED
- Read path, HEAD: `candor-case/src/lib.rs:117-123` builds `CaseResource` with `coi_user: None` and authorizes `ViewCase`. `candor-authz/src/lib.rs:71-75` applies COI only when `coi_user` is `Some`. Repro: an assigned user's read returns `Ok` with no exclusion input. This is confirmed.
- Read path, branch `e7c8878`: `open_case` takes a `CoiLookup`, sets `coi_user` from `is_excluded`, and fails closed (maps lookup errors to `NotFound`). Repro v2 (8 tests) passes, including open, exclude, then denied read. Confirmed on the branch.
- Assignment, HEAD: `assign(tenant, case, user)` (`lib.rs:96-109`) has no actor, no role check and no audit commit. Confirmed.
- Assignment, branch: now takes a `Principal` and requires `Role::Triage` and checks actor and recipient COI. It still has no audit commit. The `Principal` is caller-supplied and not authenticated inside the crate. A forged Principal succeeds in the repro. So the audit's requirement for an "authenticated actor and audit transaction" is NOT met on the branch.
- Export and modify: there are no service methods at HEAD or on the branch. They are covered only at the `authorize()` layer, if at all. They are MISSING at service level.
- Test-suite state: `cargo test -p candor-case -p candor-authz --locked` fails to compile at HEAD and on the branch because `candor-case/tests/authz_invariants.rs` imports symbols that do not exist. The same stale file is recorded in `process/STATUS.md`.
- Reachability: INFERRED not reachable. No binary, daemon, deployed unit or other crate depends on `candor-case` in this repository. `specs/07-BACKEND.md` describes a service that is not implemented. This is not proof that no future service would use it.

### SEC-003: case creation impossible under the regular role (HIGH). STILL_PRESENT; audit's cause partly wrong
- Repro at HEAD (investigator, coordinator also observed step 1): inserting `core."case"` as `candor_case` fails with `new row violates row-level security policy "p_case_acl" for table "case"` (`0001_case_schema.sql:1319-1321`). `repo::case::create` returns `Integrity("context or privilege refused")`.
- Audit said the FK ordering was the root cause. The investigator found the opposite order also fails: the membership-first insert is refused by the FK (`case_member_tenant_id_case_id_fkey`, SQLSTATE 23503). So reordering alone cannot fix it.
- Fix branch: unchanged for the case table. The creation step still fails, now with a grant error. No application role holds INSERT on `core.case` except the superuser fixture.
- Conclusion: there is no creation path under any application role. A bootstrap needs an explicit, owner-approved design. It must not be solved by loosening the restrictive policy.

### SEC-004: erasure-key approvals (HIGH, conditional). STILL_PRESENT
- `crates/candor-ekv/src/lib.rs`: `ApproverId` is a public tuple struct (`:21`). `approve_destroy` takes no tenant, case, policy or hold argument (`:225-229`). The duplicate check rejects only identical values (`:234-241`). Two distinct values erase the key (`:246-249`).
- Reproduced at HEAD: one caller with two distinct approver values erased the key, and the key could not be unsealed afterwards. `mark_missing_for_restore(handle)` and `rekey_missing(handle)` change key state from a handle alone.
- No `security/*` branch touches `crates/candor-ekv` (blob identical on all four).
- Reachability: INFERRED not reachable. No crate in the workspace depends on `candor-ekv`. `SPEC-NOTES.md` says the vault must move behind a dedicated service that is not implemented.
- This needs a design decision (authenticated capabilities, durable two-person approval, hold checks). It is not a Haiku task.

### SEC-005: staff authentication incomplete (HIGH, release blocker). PARTIALLY_FIXED on branch
- HEAD: `crates/candor-auth/src/lib.rs` contains only SPDX and doc comments. `candor-auth/tests/session_invariants.rs` imports types that do not exist, so the test target does not compile. `cargo test -p candor-auth -p candor-authz` fails at HEAD. `candor-authz` alone passes 15 tests.
- Branch `23dab5f`: adds a wrapper around `candor_authz::Session` that holds a caller-supplied subject reference. 7 tests pass. There is still no token issuance, no verification or lookup, no persisted or cross-instance revocation, no step-up and no RBAC call.
- This is missing functionality, not a bypass in running code, as the audit said. It stays open until the owner accepts an identity-provider design.

### SEC-006: legal hold not enforced at retention transitions (MEDIUM/HIGH, conditional). STILL_PRESENT at HEAD; FIXED_ON_BRANCH_UNMERGED
- File correction: `RetentionWorker` and `due()` live in `crates/candor-retention/src/lib.rs`, not `candor-worker`. `candor-worker/src/retention.rs` is a pure decision function.
- HEAD repro: a held item (due day 100) reached `Disposed` through `mark_tombstoned`, `mark_key_destroyed` and `mark_disposed`, each returning `Ok(())`. `due(101)` returned an empty list for it.
- Branch `dd72981`: the three transitions return `LegalHold` under a hold, and tombstoning before the due day returns `NotDue`. Tests pass (`hold_regressions.rs`).
- Remaining: the due check trusts a caller-supplied `today` (`today = u32::MAX` bypasses it, observed). The race between hold placement and deletion is not expressible in these crates. The SQL-layer hold model was not checked for deletion enforcement. The branch is not merged.

### SEC-007: review ownership and release gates (HIGH, governance). STILL_PRESENT
- `.github/CODEOWNERS:2-4` says the `@candor-project/*` teams do not exist. GitHub API: `/orgs/candor-project` and its teams return 404. The owner is a user account, not an org.
- GitHub API (read-only): `main` and `claude/tender-tesla-z8tfnl` return "Branch not protected" (404). The rulesets list is empty and `rules/branches/main` is empty. Token reports admin permission on the repo, so the 404 is meaningful.
- `SECURITY.md` contains placeholders only: `TODO: http://<v3-onion>.onion/`, `security@TODO-candor-domain`, `age1...`, `Advisory signing key: TODO`. No real onion address or key was found.
- `release-gate.yml` runs on version tags and manual dispatch only. No tags exist. It has never run.
- `scripts/check-codeowners.py` checks ordering only. It does not verify that teams exist, so a green workflow-lint does not prove ownership.
- Owner action required: create the teams, configure rulesets, publish disclosure channels and keys. This was not done here.

### SEC-008: CI verdict (HIGH, release blocker). STILL_PRESENT; the audit's detail needs correction
- The audited commit `78d516f` has one CI run (38242513210), conclusion `cancelled`. Its jobs: `test (unprivileged user)` and `dco` failed; fmt, clippy, unit test, cargo-vet, reproducibility and others were cancelled. The audit's wording (failing unit tests, Clippy and cargo-vet) is not what that run shows. The run shows cancellation, which the audit already recorded.
- Latest scheduled CI at HEAD (40483603745, 2026-10-27): failed `cargo-deny`, `test (unprivileged)`, `test (memlock limit)`, `supply-chain`, `clippy`, `cargo-vet` and `fmt`. `secret-scan`, `sbom`, `repo-lints`, `docs-lint`, `workflow-lint` and `reproducibility` passed. `dco` was skipped.
- The audit's statement that fmt and cargo-deny passed is no longer true at HEAD.
- Fuzz nightly (40469984147) succeeded, all 18 jobs.
- Fix branches also fail: `auth-session` 23dab5f fails clippy, test, unprivileged test, cargo-vet and fmt. The other three branches also fail tests, clippy or fmt.
- Failing `cargo test` at HEAD: `candor-case` (authz_invariants), `candor-auth` (session_invariants), `candor-relay` (relay_invariants). These are unimplemented-spec tests, recorded in `process/STATUS.md`.

### SEC-009: relay trust boundary (MEDIUM/HIGH). STILL_PRESENT (absence confirmed)
- `crates/candor-relay` has no `[dependencies]`, no `[[bin]]`, no socket, no signing code. It is a rule-checking library (counter, endpoints, object validation, schedule). `allow_inbound` always denies.
- No binary, service unit or crate in the workspace depends on it. `deploy/intake/systemd` contains only intake units. The `candor-relay` test target does not compile at HEAD (`relay_invariants.rs` imports missing items and an unlisted dependency).
- No branch contains a relay daemon.

## Corrections to the audit (recorded, not hidden)
1. SEC-003: the audit's FK-ordering explanation is incomplete; membership-first is also refused by the FK.
2. SEC-006: the retention transition methods are in `candor-retention`, not `candor-worker`.
3. SEC-008: the audited run was cancelled; its failing jobs differ from the audit's description. At HEAD fmt and cargo-deny now also fail.
4. The audit describes SEC-001's fix as "separate bootstrap"; the existing branch instead removes member writes entirely. Both are design questions, not settled here.
5. `origin/main` (`065ac0c`) shares no history with the working branch, and GitHub's default branch is `claude/tender-tesla-z8tfnl`. Any audit reference to `main` must be read against this.

## Owner decisions (not decided by this batch)
1. Case bootstrap (SEC-003): which role, function or service may create a case and its first member, and under what authorization. Options include a narrow security-definer provisioning function. The audit's warning applies: no global RLS relaxation.
2. Subsequent membership grants (SEC-001): the trusted service, actor and approval rules, and whether the branch's total removal of `candor_case` member writes is acceptable.
3. Authenticated actor (SEC-002, SEC-005): whether a caller-supplied `Principal` is ever acceptable. The audit says no. Also whether assignment needs an audit commit.
4. Erasure approvals (SEC-004): design of capabilities, durable two-person records, hold checks and restore privileges.
5. Trusted time for retention (SEC-006): whether `today` may be caller-supplied.
6. Governance (SEC-007): create real teams, rulesets, disclosure channels and keys.
7. Relay transport (SEC-009): design and ownership of the authenticated transport.

## Recommended next steps (Haiku-suitable only where marked)
- Haiku-suitable, straightforward: fix the fmt, clippy and cargo-deny failures at HEAD and make the three non-compiling test targets compile or be explicitly marked ignored with the owner's sign-off. Do not weaken assertions.
- Owner review before merge: `security/db-rls-no-self-enroll-20261012`, `security/retention-hold-20261012` and `security/case-access-coi-20261012`. They are based on `350435d` and are unmerged. Each needs rebase onto the current base and independent review. Do not merge them without that review.
- Owner review: `security/auth-session-20261012`. It is partial and needs design sign-off.
- Owner action: SEC-007 governance and SEC-003 bootstrap design.

## Verification limits
- Repros were not committed. They were untracked files in scratch worktrees, using synthetic IDs.
- Clippy and the whole workspace test were not run for the branches.
- Fix branches were tested only on their own bases, not combined with HEAD.
- No live service, Tor setup or deployed host was examined.
- The GitHub token was used for GET requests only and was not stored in the repository.
