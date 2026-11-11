# Candor Community Edition: status and hand-off (2026-10-09; updated 2026-11-11, §8)

Branch `claude/tender-tesla-z8tfnl`, pull request #1 (draft); the 2026-11-11 work is on `claude/happy-goldberg-ev3cj0`, pull request #16 (draft) against it. Build paused: the Fable usage limit was reached; the owner then chose Haiku "until it is beyond its ability". The remaining work is large and security-critical, and it needs the adversarial independent audits that gave the earlier steps their assurance, so it is left for a stronger model (see §4).

Nothing here is "unhackable", "perfectly anonymous" or "100% secure". Assurance claims below mean only what the audit files in `process/audits/` say.

## 1. Audit status by component

Verdicts are the final `Gate:` line in each audit file under `process/audits/` (reconciled 2026-10-28 against the files; the earlier table overstated several). "PASS" means no open Critical/High/Medium in scope at that commit. It is not a security certification.

| Area | Crate / path | Audit file | Final gate (commit) |
|---|---|---|---|
| Specifications, research, decisions (ADR-001..057), 2,400+ traceable requirements, three adversarial reviews, secure-implementation specs, source safety tips | `specs/`, `research/`, `process/` | `specs/REVIEW-REPORT.md` | complete draft |
| Foundations: CI, supply chain (cargo-deny/vet, SBOM), DCO, reproducible builds, nightly fuzz | `.github/`, `deny.toml`, `supply-chain/`, `scripts/` | `AUDIT-RM0-RM1-sourceui-infra.md` (infra part) | PASS-conditional, 2026-10-01 `c9014b2`: needs Security Lead import approvals and a green first CI run (cargo-vet still red, §4) |
| Crypto library (HPKE/X-Wing, STREAM, KDF, formats) | `crates/candor-core` | `AUDIT-RM1-candor-core.md` | PASS, 2026-10-01 `0d486a9` (round 2) |
| Safe file handling | `crates/candor-safefs` | `AUDIT-RM1-safefs-log.md` | PASS, 2026-10-01 `8163ede` (round 3; "PASS (unchanged)" in round 4). The §7 line of 2026-10-28 read the round-2 gate, not the file's last one |
| Privacy-preserving audit log | `crates/candor-log` | `AUDIT-RM1-safefs-log.md` | PASS, 2026-10-01 `8517304` (round 4): LOG-02/16/17/18/19/24 fixed and re-tested; open Lows LOG-26 (fix assigned) and the LOG-25 call site (C-24 must call `note_restart()`, integration test tracked); LOG-14 accepted 90 days (review by 2026-12-30, C-22 system-actor condition). The §7 line of 2026-10-28 read the round-2 gate |
| Source-facing HTML (no JS), safety tips | `crates/candor-source-ui` | `AUDIT-RM0-RM1-sourceui-infra.md` (source-ui part) | PASS, 2026-10-01 `c9014b2` |
| Intake store (PostgreSQL, erasure, deletion list) | `crates/candor-intake-store` | `AUDIT-RM2-intake-store.md` (round 7) | PASS, 2026-10-01 `e9e6a1a` |
| Sealer (in-RAM encryption for the no-JS path) | `crates/candor-sealer` | `AUDIT-RM2-sealer.md` | PASS, 2026-10-01 `3f41a3a` |
| Intake host configuration (units, AppArmor, nftables, config-check) | `deploy/` | `AUDIT-RM2-deploy.md` | PASS, 2026-10-01 `2956e4f` (latest delta in file) |
| systemd socket adoption, the only `unsafe` crate | `crates/candor-memlock` | `AUDIT-RM2-memlock-deploy.md` | PASS, 2026-10-07 `2c00f6f` (round 2) |
| Safe file reader (reproducibly built) | `crates/candor-safe-read` | `AUDIT-RM2-deploy.md` | PASS, 2026-10-01 `e9e6a1a` (with `deploy/`) |
| Source web service (Tor-only, no-JS) | `crates/candor-intake-web` | `AUDIT-RM2-intake-web.md` | PASS, 2026-10-01 `9ffeffd` (for in-scope files; later changes void it per file §G) |
| Preview site and donation page | `docs/` | n/a | live once Pages is enabled |

## 2. Built but NOT cleared

| Item | State | What is needed |
|---|---|---|
| istore IPC (store link: protocol, server, client, K31 deletion ops, SEAL_SIGNAL/DeleteReplies/CloseMailbox, idempotent retry, `mailbox_account` table) | audit rounds 1–3 found and the builder fixed IPC-01..14 (verified by the auditor). IPC-15 (shutdown flush lost queued writes) was fixed by a Haiku-class builder and checked by the lead with a mutation test (old behaviour: 2 of 7 tests fail; fix: all pass). | **Round 4 done 2026-11-11** by an independent AI auditor session (same model family as the lead; not external): IPC-15 **Fixed** and re-tested (PoC sequence, backoff-cap and store-down variants, mutation M1), 0 Critical/High, 12 attacker goals refuted with evidence, PG suite 40/40. Gate FAIL only for the new **IPC-16 (Medium)**: no drain around the shutdown pass (writes accepted while the pass runs were reported lost but never attempted; one after the final count exited silently), plus IPC-17/18 (Low). All three were fixed on `claude/happy-goldberg-ev3cj0` (`52eb19a`, see §8) with the auditor's PoCs as shipped regression tests, and the independent re-test gives **Gate PASS (round 4 re-test, 2026-11-11, `52eb19a`)**: zero Critical/High/Medium open; IPC-17(b) was a README fix made afterwards; new IPC-19 (Low, in-flight commits not awaited before the final count; reported, never silent) stays open as a documented residual. The RM-2 istore IPC gate is therefore PASS at that commit; later sealer changes void it per the file's §G. |
| `crates/candor-case-db` (RM-3: case schema, RLS, TenantTx) | migration 0001 and tests exist; its live schema lint still refuses; no lib.rs beyond a placeholder | finish, then audit |
| `crates/candor-authz` (RM-3: authorization engine, COI) | modules `model`, `coi`, `ids`, `policy` written; `lib.rs` is a placeholder; untested as a whole | finish, then audit |

## 3. Not started (software)

- **RM-2 leftovers:** SW-14/SW-15 pages wired to the istore ops; WEB-11 (Leave page when a token is unknown); draft-preserving re-authentication; S08 invisible-character normalisation; the daemon binaries (web, sealer, store) that use `candor-memlock`; an end-to-end test (Tor-less, Unix sockets); a dedicated `candor-log` health code for the account-queue backlog and dead letters; deploy settings `wmem_default >= 212,992` and distinct intake users; spec 07 §5.11 line; sealer README `openat2` note.
- **RM-3 core zone:** relay (C-09), case service (C-10), authentication (C-21), audit service (C-24), key directory (C-14), notifications (C-23), erasure key vault and retention, jobs/SLA, core self-test.
- **RM-4:** Candor Desk (recipient desktop app, hardware-bound keys), evidence viewer/containment, export package.
- **RM-5 operations:** installers, TUF update client, platform manifest/floors, backup agent and restore drills, upgrade/rollback orchestration (including the database schema upgrade mechanism), support bundles.
- **RM-8:** Source App (embedded Arti, encrypted vault). Arti migration is gated by ADR-049 (its onion-service DoS protection is not yet non-experimental).
- **RM-6, RM-7 (software parts):** i18n pipeline, accessibility fixes, release-candidate QA matrix, TUF repository tooling, reproducibility verification by two builders.

## 4. Needs people (cannot be done by an AI session, and must not be faked)

1. **Security Lead sign-off** of the four imported cargo-vet audit sets in `supply-chain/trusted-importers.toml` (bytecode-alliance, google, mozilla, zcash). This is the only reason the `cargo-vet` CI job is red.
2. `SECURITY.md` contacts and PGP/age keys; the EFF wordlist hash check against eff.org.
3. **External audits and a cryptography review** before any release (RM-6): including `ml-dsa 0.1.1`, `hpke`, `ml-kem`, `x-wing`, which are in the crypto set and have only exemptions today.
4. Usability and accessibility studies with real people; translation review.
5. Production key ceremonies, the TUF repository, transparency-log witnesses, bug bounty, vulnerability-disclosure process (RM-7).
6. GitHub Pages: set the source to branch `claude/tender-tesla-z8tfnl`, folder `/docs`. The optional copy of the repository to `djshellshoxxx/blowmywhistle` (the sandbox blocked the push; a script was provided).

## 5. How to continue

- Read `process/BUILD-BRIEF.md`, `process/WAVE-BRIEF.md`, `process/AUDIT-CHECKLIST.md`, `specs/impl/IMPL-RM*.md` and `specs/DECISIONS.md` (ADR-054..057 are the newest).
- Order: (1) round-4 independent audit of the istore IPC; (2) finish RM-2 (§3); (3) finish `candor-case-db` and `candor-authz`, then the rest of RM-3, each crate built by one agent and audited by a different one (builder ≠ auditor); (4) RM-4, RM-5, RM-8.
- Working rules that mattered: two agents at a time (API limits and 4 cores); `export CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0`; `cargo ... -p <crate>` only; delete scratch builds (the session disk allowance is about 9–14 GB); each fix needs a red-to-green regression test.
- Known CI facts: `cargo-vet` stays red until item 1 of §4 is done; all other checks were green at the last full run (see the pull request).

## 6. Update 2026-10-10: merged orphaned branches (built, NOT audited)
- Merged `chatgpt/rm3-core-zone-20261004` and `chatgpt/complete-rm3-core` (RM-3 core zone: candor-authz, case, ekv, notify, relay, auth, worker, retention). None of it has passed the independent audit gate.
- Lib clippy is clean for authz/notify/ekv. Policy (6), rm3_contract (4) and notify queue (3) tests pass.
- Still red (spec tests ahead of the implementation): candor-authz `session_contract` (2 of 5 fail); candor-notify `content_free` and candor-ekv `aead`/`erasure` tests do not compile (missing API: `for_daily_slot`, `create`, `NoKey`). CI `clippy --all-targets` and `test` will stay red until these are implemented. Next loop item.
- Older orphan files `crates/candor-authz/src/{model,coi,ids,policy}.rs` are unused by the merged `lib.rs`.
- Build loop: one Haiku worker, about 1h work then 3h break (reminder every 4h).
- 2026-10-10 cycle 3: candor-authz `session_contract` (2 of 5 fail) investigated, no code changed. Root cause (verified): the two *absolute*-limit sub-checks (recipient at t=29800, admin at t=8200, both issued at 1000) validate with no activity after issue, so the idle gap (28800 s / 7200 s) exceeds the idle limits (15 min / 10 min, AUTH-017). The implementation follows AUTH-017; the tests contradict it. Decision for the owner: amend those two tests to record activity inside the idle window before the absolute check (a test change, not made), or specify that the idle clock starts at first use (a spec change). Not decided by an AI session.
- Blocked on owner decisions: delete stale `candor-notify/tests/content_free.rs` (see above), the authz session tests, DCO sign-offs on the ~80 imported commits.
- 2026-10-10 cycle 4: loop PAUSED (not re-armed). Every remaining merged-branch item is blocked on an owner decision, and the rest needs a stronger model than Haiku. Same class as content_free.rs: `candor-ekv/tests/erasure_lifecycle.rs` exists only on the older zone branch (uses `ErasureVault::create/destroy`, `VaultError::NoKey`); the upstream `aead_lifecycle.rs` is the implemented spec and compiles. Owner decisions needed: (1) delete or keep the stale zone-branch specs (`candor-notify/tests/content_free.rs`, `candor-ekv/tests/erasure_lifecycle.rs`, and unchecked: `candor-auth/tests/session_invariants.rs`, `candor-relay/tests/relay_invariants.rs`, `candor-worker/tests/job_retention.rs`, `candor-case/tests/authz_invariants.rs`); (2) the `candor-authz` `session_contract` idle-vs-absolute question; (3) DCO sign-offs/epoch for the ~80 imported commits; (4) the cargo-vet Security Lead sign-off. To restart: tell the assistant to resume the build loop.
- 2026-10-10 (owner approved: delete stale specs, amend authz session tests, resume loop; DCO and cargo-vet left to the owner): 
  - Deleted `candor-notify/tests/content_free.rs` and `candor-ekv/tests/erasure_lifecycle.rs` (both fully superseded: same behaviours covered by `daily_constant.rs` and `aead_lifecycle.rs`). The other four zone-branch-only specs were checked and are NOT superseded: they call code that exists nowhere (`relay_invariants.rs`, `job_retention.rs`, `candor-case/tests/authz_invariants.rs`), or hold a test the authz copy lacks (`candor-auth/tests/session_invariants.rs`). They stay as real requirements to implement.
  - `candor-authz/tests/session_contract.rs`: the two absolute-limit checks now keep the session active inside the idle window (AUTH-017 unchanged). authz 15/15, notify, ekv green.
  - `candor-case`: `AuditCommit` now returns a named `AuditCommitFailed` instead of `Result<(), ()>`; three `assert!(false, ..)` in `case_service.rs` became `panic!` with the same messages. case_service 4 and schema 3 pass.
  - Still red (unimplemented requirements, loop work): `candor-case/tests/authz_invariants.rs`, `candor-relay/tests/relay_invariants.rs`, `candor-worker/tests/job_retention.rs`, `candor-auth/tests/session_invariants.rs`. All of this code is built, not audited.
- 2026-10-10 loop cycle 1 (resumed): `candor-worker` implemented by a Haiku worker to satisfy `job_retention.rs` as written (Job claim/renew with 5-min lease, `base_backoff_seconds` = min(30·2^n, 6 h), `RetentionCase::evaluate`: legal hold wins, no silent disposal). Lead-verified: 8/8 tests, clippy clean, fmt clean, safefs-lint and candor-log logging lint pass; code read, arithmetic checked. BUILT, NOT AUDITED. Open: the spec's ±20 % backoff jitter is not implemented (needs an RNG, untested); `candor-retention` types not reused (different model). Next in the loop: `candor-case/tests/authz_invariants.rs`, then `candor-auth/tests/session_invariants.rs`, then `candor-relay/tests/relay_invariants.rs`.

## 7. Update 2026-10-28: reconciliation of the handoff against the audit files (documentation only)

- Scope: `process/STATUS.md` only. No source, test, or policy file changed. Haiku-class documentation pass.
- Repository state checked: default branch `main` at `065ac0c`; this branch `claude/tender-tesla-z8tfnl` at `4686d63`, equal to the remote head. Draft PR #1 is open on this branch.
- Other owners, left untouched: draft PRs #4–#7 on `security/*` branches (case access and COI, PostgreSQL self-enrollment, retention hold, staff session); PRs #8 (modular-first roadmap) and #9 (wiki), which do not change this file; Dependabot PR #10.
- Evidence: the audit-file names cited in §1 were checked against `process/audits/`. Most did not exist and are corrected above. Each verdict now comes from the final `Gate:` line in its audit file, not from earlier wording in this handoff.
- Overstatements corrected: `candor-log` is FAIL (2 High open); the `candor-safefs` file gate is FAIL; the infra gate is PASS-conditional; the istore IPC gate is FAIL (IPC-15 High recorded open).
- Not present: `candor_leaks_security_audit_2026-10-12.md` is not in the repository, so no historical reconciliation against it was possible.
- Not run: no `cargo build`, `cargo test` or clippy in this session. Only `cargo --version` was attempted, which started a toolchain download. Nothing here is verified by a test run.
- Unresolved (no Haiku-class change proposed): IPC-15 re-audit; LOG-02 and LOG-16 (candor-log High); LOG-17..19 Medium acceptance; the intake-web fuzz runs (not run per its audit); cargo-vet sign-off (§4). All security-sensitive, so they wait for owner review and a stronger model.
- Next: an independent auditor, not the builder, re-tests the istore IPC-15 fix and the candor-log findings. This handoff is updated again after that result.

## 8. Update 2026-11-11: RM-3 core-zone contracts, case-db live suite, IPC round 4 (branch `claude/happy-goldberg-ev3cj0`, PR #16)

What was done (all built, tested and clippy-clean; `BUILT, NOT AUDITED` unless stated):

- **C-22 decision point** (`candor-authz::pdp`, re-exported by `candor-case`): the pure `authorize(principal, action, resource, context)` of 15 §5.9 in the normative 15 §5.4 order (audience/tenant → explicit deny for suspension and the blinded COI tag → the 15 §5.2 role matrix → case ACL relation → obligations: step-up, second approver, audited access), deny by default, admin ∉ case content, COI always wins and is reported uniformly as `NoRelation`. `validate_key_wraps` enforces 07 §5.5 / BE-018. `authorize_case` / `validate_wrap_recipients` are adapters onto it. Tests: an independent transcription of the §5.2 matrix for every role × action, the evaluation order step by step, 512-case property tests. The red spec test `candor-case/tests/authz_invariants.rs` passes. Decisions and a spec inconsistency (15 §5.2: RECORDS_CUSTODIAN row "—" vs. its note) in `crates/candor-authz/SPEC-NOTES.md`.
- **Relay request authentication** (`candor-relay::RelayAuthenticator`, 07 §5.4): strict Ed25519 and SHA-256 from `candor-core` over a length-prefixed, domain-separated message (`candor/relay-req/v1`); the persisted monotonic counter is committed only after the signature verifies. One shared counter rule with `RelayGuard`; `Backpressure`. The red `relay_invariants.rs` passes; negative and property tests added.
- **Staff sessions** (`candor-auth`): the owner's draft PR #7 commit cherry-picked (subject-bound sessions over the shared authz policy; the idle/absolute test amendment is the decision already approved for candor-authz in §6). `session_invariants.rs` passes. PR #11 (rustfmt, worker lint) cherry-picked too. PRs #4–#6 (`security/*`) were left for the owner.
- **candor-case-db:** the §2 line "no lib.rs beyond a placeholder; live schema lint still refuses" was stale. The crate has schema, roles, RLS, migrations, `TenantTx` and repositories (5.5 k lines, 18 unit tests). The live PostgreSQL suite (`scripts/pg-test.sh`, PostgreSQL 16) is **8/8** after one fix: the worker role had DELETE but no column SELECT on the six content tables, so `DELETE … WHERE tenant_id` failed with 42501 (PostgreSQL needs SELECT on the columns a WHERE reads). Key columns only are granted; every `*_ct` column stays out of the worker's reach (09 §6.4); the test grant matrix records it.
- **istore IPC round 4** (§2): the auditor's findings IPC-16/17/18 are fixed in `candor-sealer`: a `stopping` state set at SIGTERM (before the flush thread starts) makes `queue_has_room` refuse every new account write and every chaff shape with `BUSY` before any envelope commits; the flush lock is held across bounded extra passes (only for writes that arrived while a pass was writing) and the final count; a write arriving after the count is queued, counted (`late_arrivals`) and reported, and `spawn_sigterm_flush` retries once; a failed shutdown attempt re-arms no backoff; the thread-failure count is at least the taken batch and `inflight_replaced` is cleared by a drop guard; the README integrator pattern stops serving before awaiting the flush and exits non-zero on `ShutdownLoss`; the sealer unit gets `TimeoutStopSec=300` (a delta for the deploy audit). `chaff_event_shaped` makes the chaff shape explicit for tests (production still draws it). The auditor's P1/P2/P3/P5 PoCs are shipped tests. Full sealer suite and lints green. Details: `crates/candor-sealer/SPEC-NOTES.md` "Fixes for AUD-RM2-IPC round 4".

Verified this session: `cargo fmt --check`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test` for authz, case, relay, auth, worker, case-db (+ live PG), sealer; safefs and logging lints; docs lints. The full `cargo test --workspace` is what CI runs on PR #16.

Owner decisions and people items (new):
1. `cargo-deny` is red on RUSTSEC-2026-0429 (`zip 4.6.1`, `ZipArchive::extract()`; `candor-safefs` does not call it and sizes its own buffers from `max_entries`). Either a `deny.toml` ignore with a risk statement (needs Security Lead + TPM per the file's own rule) or a major upgrade to `zip ≥ 9` with a safefs re-audit of the zip path.
2. DCO sign-offs: the AI session's commits carry no `Signed-off-by` (it cannot attest the DCO); sign off on integration as for the imported commits.
3. Spec 15 §5.2: resolve the RECORDS_CUSTODIAN row vs. note (the note is implemented).
4. Deploy audit delta: `TimeoutStopSec=300` in `candor-sealer.service`.

Hardest remaining items, in order: (1) the independent re-test of the IPC-16/17/18 fixes, then the RM-2 exit; (2) independent audits of the RM-3 crates built so far (authz/pdp, relay, case, case-db, worker, ekv, notify, retention, auth); (3) the RM-3 pieces not started: route layer deriving `ResourceRef` inside the data transaction, C-21 WebAuthn verification, C-24 service over `candor-log`, C-14 key directory service, EKV IPC, jobs/SLA, core self-test; (4) RM-2 leftovers (§3); (5) RM-4/RM-5/RM-8.

### Handoff (2026-11-11, wind-down on the owner's pause order relayed by the coordinator session)
- Branch `claude/happy-goldberg-ev3cj0`, draft PR #16 against `claude/tender-tesla-z8tfnl`; every change is committed and pushed; the working tree is clean.
- IPC-15: fixed and independently re-tested (round 4). IPC-16/17/18: fixed and independently re-tested, **gate PASS at `52eb19a`**. Open: IPC-19 (Low, documented residual) and the auditor's info items (untested extra-pass/closed/retry branches, refusal count per shutdown pass); next step for the sealer is a drain that awaits in-flight commits plus regression tests for those branches.
- Local verification at `52eb19a`: fmt, workspace clippy, full `cargo test --workspace` (107 test binaries, all green), sealer suite 113/0, safefs and logging lints, docs lints, case-db live PostgreSQL suite 8/8, deploy config-check baseline integrity OK.
- CI on PR #16: `dco` red (no sign-offs by the AI session; owner signs off on integration), `cargo-vet` red (Security Lead import approval, §4), `cargo-deny` red on the base (zip advisory, owner decision above). The code jobs on the final head were still queued in the runner backlog when this session stopped; if one is red, it is this branch's to fix before merge.
- Not done: independent audits of the RM-3 crates (authz/pdp, relay, case, case-db, auth, worker, ekv, notify, retention); the RM-3 pieces listed above as not started; RM-2 leftovers (§3); PRs #4–#6 and #8–#15 untouched.
