# Candor Community Edition: status and hand-off (2026-10-09)

Branch `claude/tender-tesla-z8tfnl`, pull request #1 (draft). Build paused: the Fable usage limit was reached; the owner then chose Haiku "until it is beyond its ability". The remaining work is large and security-critical, and it needs the adversarial independent audits that gave the earlier steps their assurance, so it is left for a stronger model (see §4).

Nothing here is "unhackable", "perfectly anonymous" or "100% secure". Assurance claims below mean only what the audit files in `process/audits/` say.

## 1. Done and independently audited (zero open Critical/High; Mediums fixed or accepted in writing)

| Area | Crate / path | Audit file | Verdict |
|---|---|---|---|
| Specifications, research, decisions (ADR-001..057), 2,400+ traceable requirements, three adversarial reviews, secure-implementation specs, source safety tips | `specs/`, `research/`, `process/` | `specs/REVIEW-REPORT.md` | complete draft |
| Foundations: CI, supply chain (cargo-deny/vet, SBOM), DCO, reproducible builds, nightly fuzz | `.github/`, `deny.toml`, `supply-chain/`, `scripts/` | `AUDIT-RM0-INF.md` | pass |
| Crypto library (HPKE/X-Wing, STREAM, KDF, formats) | `crates/candor-core` | `AUDIT-RM1-core.md` | pass |
| Safe file handling | `crates/candor-safefs` | `AUDIT-RM1-safefs-log.md` | pass |
| Privacy-preserving audit log | `crates/candor-log` | `AUDIT-RM1-safefs-log.md` (round 4) | pass |
| Source-facing HTML (no JS), safety tips | `crates/candor-source-ui` | `AUDIT-RM1-source-ui.md` | pass |
| Intake store (PostgreSQL, erasure, deletion list) | `crates/candor-intake-store` | `AUDIT-RM2-intake-store.md` (round 7) | pass |
| Sealer (in-RAM encryption for the no-JS path) | `crates/candor-sealer` | `AUDIT-RM2-sealer.md` (round 7) | pass |
| Intake host configuration (units, AppArmor, nftables, config-check) | `deploy/` | `AUDIT-RM2-deploy.md`, `AUDIT-RM2-memlock-deploy.md` (round 2) | pass |
| systemd socket adoption, the only `unsafe` crate | `crates/candor-memlock` | `AUDIT-RM2-memlock-deploy.md` | pass |
| Safe file reader (reproducibly built) | `crates/candor-safe-read` | `AUDIT-RM2-memlock-deploy.md` | pass |
| Source web service (Tor-only, no-JS) | `crates/candor-intake-web` | `AUDIT-RM2-intake-web.md` (round 2) | pass |
| Preview site and donation page | `docs/` | n/a | live once Pages is enabled |

## 2. Built but NOT cleared

| Item | State | What is needed |
|---|---|---|
| istore IPC (store link: protocol, server, client, K31 deletion ops, SEAL_SIGNAL/DeleteReplies/CloseMailbox, idempotent retry, `mailbox_account` table) | audit rounds 1–3 found and the builder fixed IPC-01..14 (verified by the auditor). IPC-15 (shutdown flush lost queued writes) was fixed by a Haiku-class builder and checked by the lead with a mutation test (old behaviour: 2 of 7 tests fail; fix: all pass). | **A stronger independent round-4 re-audit of `Sealer::shutdown_flush`, `IstoreSink`, `classify_upsert` and migration 0001, plus a variant scan.** The gate is CONDITIONAL until then (`AUDIT-RM2-istore-ipc.md`). |
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
