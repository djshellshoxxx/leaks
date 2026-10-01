# AUDIT-RM2 — candor-sealer (C-07 Intake Sealer)

| Item | Value |
|---|---|
| Step | RM-2 (intake zone), component C-07 |
| Audited commit | `d21981fea263b5a5926922b3f13147d6b0c00932` (crate last changed in `87839c2`; working tree clean for the crate) |
| Scope | `crates/candor-sealer/{src/lib.rs, src/proto/{mod,cbor}.rs, src/server/*.rs, tests/*.rs, tests/common/mod.rs, Cargo.toml, README.md, SPEC-NOTES.md}` (9,241 lines; 6,540 in `src`). For integration context only: `deploy/intake/systemd/candor-sealer.{service,socket}`, `candor-safefs::store` (`PendingObject`, `commit`), `candor-core::passphrase::normalize` |
| Tiering (27 §4) | T0: all of `src/server/*` (holds draft plaintext, passphrases, K36, source keys, K35). T1: `src/proto/*` (IPC decoder, untrusted peer bytes). T2: tests |
| Auditor | Independent security auditor (did not write this code) |
| Date | 2026-10-01 |
| Inputs read | R9 §4–§6, §8; AUDIT-CHECKLIST; BUILD-BRIEF "Security and OPSEC bar" + RM-2 addendum; IMPL-RM2-INTAKE §2.3, §2.4, §2.7, §4 (A1–A15), §9; 04 §9.13, §12.1–§12.7, §14.2/§14.4 (roster, time locks); 07 §4.1–§4.4, §5.2, §5.2a, §5.3, §11, BE-003/005/006/055/062; 09 envelope/chaff rows (§5.1, L-table); crate README + SPEC-NOTES (incl. "Security self-review"); prior reports AUDIT-RM1-candor-core, AUDIT-RM2-intake-store |
| Time per phase | A1 ≈ 10 %, A2 ≈ 10 %, A3 ≈ 55 % (every line of `src/`), A4 ≈ 20 % (tools + 3 PoC tests), A5 ≈ 5 % |

## Summary

| Severity | Count | IDs |
|---|---|---|
| Critical | 0 | — |
| High | 4 | SEA-01 … SEA-04 |
| Medium | 5 | SEA-05 … SEA-09 |
| Low | 5 | SEA-10 … SEA-14 |
| Info | 4 | SEA-15 … SEA-18 |

**Gate: FAIL** (4 open High, 5 open Medium).

The core of the crate is careful work. The IPC decoder is strict: deterministic CBOR only, ordered and unique keys, no tags, floats or indefinite lengths, an item budget, every length checked before allocation, trailing bytes rejected, and `BAD_FRAME` followed by a close. Secret buffers are `Zeroizing` and pre-sized (frames, encoders, NFC, lossy UTF-8). Staged parts are padded before STREAM encryption, and all exit paths I traced remove them. No content key is wrapped before `SEAL_FINISH`. Confirmation is constant-time with fresh positions and a 5-strike zeroize. Login does uniform work. Clock, freshness, rollback and suite failures fail closed. Nothing is logged or printed.

The open problems are:
- chaff that can be told apart from real envelopes (SEA-01, SEA-02);
- a COI filter that works per roster entry rather than per user (SEA-03);
- an IPC listener with no connection limits, which dies permanently on `EMFILE` (SEA-04);
- several fail-closed or hygiene gaps (SEA-05 … SEA-09).

## A2 — Threat model and attacker goals

Trust boundaries and who reaches each input:
- **IPC socket (peer = `candor-web` uid).** Source-controlled content (draft text, files, passphrases, reply entries supplied by the store) arrives here, along with whatever a compromised or buggy web process sends (ADV source-side attackers via C-06, compromised C-06).
- **Directory snapshot.** Supplied by the integrator from C-09/C-14 (ADV compromised Z-CORE / insider admin).
- **Clock.** Supplied by the integrator.
- **Store.** Through `EnvelopeSink` and `prefs_ct`/reply entries (ADV seized or compromised intake store).
- **Local host.** tmpfs staging, process memory (ADV intake-host root / seizure, THR-014/030).

Assets: source plaintext (draft, identity, filenames, attachments), passphrases and derived keys, COI ticks (which reveal whom the source distrusts), real-versus-chaff status and timing, availability of intake.

| # | Attacker goal | Result |
|---|---|---|
| G1 | Make the sealer write draft or attachment plaintext to disk, tmpfs, logs or stderr | **Refuted**: no print/log/`format!`/`std::fs`/env use in `src` (grep); staging only via `safefs` with STREAM ciphertext under `K_stage`; `hygiene.rs` marker scan; errors are static codes |
| G2 | Recover a passphrase or plaintext from freed heap / stale copies | **Partly refuted** (pre-sized `Zeroizing` buffers, `lossy_utf8`/`nfc` capacity, frame buffers). **Finding** SEA-08; inherited AUD-RM1-CORE-03 still reached on every `LOGIN_DERIVE` |
| G3 | Learn whether an account exists through `LOGIN_DERIVE` (timing / errors) | **Refuted**: the sealer holds no account knowledge; Argon2id runs for every input (invalid UTF-8 included); every overload cause gives the same `BUSY` |
| G4 | Deliver a submission to a COI-excluded or non-triage member | **Finding** SEA-03 (duplicate roster entries); SEA-10 (follow-up policy tightening). Time locks, MEK windows, ≤ 16 and the fail-closed empty set are refuted by unit tests and code reading |
| G5 | Seal before the recipient set is fixed / with a stale or rolled-back directory / wrong clock | **Refuted**: wraps only in `seal_blocking`/`rotate_blocking` after `select`; `is_fresh`, HWM, suite and `Clock` errors → `UNAVAILABLE` (tests `fail_closed.rs`). Trust in the integrator's view → SEA-07 |
| G6 | Tell chaff from real envelopes (store seizure, relay, Desk) | **Finding** SEA-01 (size/shape, PoC), SEA-02 (account linkage, release offset) |
| G7 | Kill or wedge the sealer over IPC (panic, OOM, fd exhaustion, slowloris) | **Panics refuted** (clippy deny set clean, all indexing/arith checked, PoC fuzz-free proptests). **Finding** SEA-04 (PoC: `serve` returns on `EMFILE`) |
| G8 | Bypass peer authentication or the HELLO handshake | **Refuted**: `SO_PEERCRED` uid checked on accept before any read; non-`HELLO` first frame or a second `HELLO` → `BAD_FRAME` + close (`ipc.rs`). Socket mode is set by the unit (0660, group `candor-web`) |
| G9 | Weaken staged-part protection (padding, key, mtime, cleanup) | **Refuted** except SEA-05 (all-zero K36 on CSPRNG failure) and SEA-13 (orphans on rare error paths) |
| G10 | Run the sealer unhardened (dumpable, swappable, unconfined) without anyone noticing | **Finding** SEA-06 |
| G11 | Confuse the passphrase confirmation (skip, brute force, replay) | **Refuted**: `SEAL_FINISH`/`ROTATE_FINISH` require `confirmed`; `ct_eq` over 3 positions; new positions after each miss; 5 failures zeroize (new account: whole session); regeneration capped at 5 |
| G12 | Make rotation commit a half state or leak the new passphrase | **Refuted** (no state change before the sink returns `Ok`; `pending` dropped on success). Availability gap → SEA-14 |
| G13 | Suppress chaff or forge disposition markers through the IPC | **Finding** SEA-12 (Low; needs the web uid) |

## A4 — Tool runs (versions and triage)

| Tool | Version / pin | Command | Result | Triage |
|---|---|---|---|---|
| tests | rustc 1.94.1 | `cargo test -p candor-sealer --locked` | 45 pass (18 unit, 4 chaff, 10 fail_closed, 1 flow, 1 hardening, 3 hygiene, 2 ipc, 6 proto_props) | Hardening test passed with mlockall and Landlock enforced in this container (no "unavailable" output); see SEA-06 for its tolerance of failure |
| clippy deny set | 1.94.1 | `cargo clippy -p candor-sealer --all-targets --all-features -- -D warnings` | clean | — |
| clippy audit extras | 1.94.1 | §C list | 13 warnings in crate, all `as_conversions`: `proto/mod.rs:850,951,1136,1153,1234,1264` (fieldless `enum as u64/u8`), `rand.rs:60` (u64>>11 → f64), `seal.rs:87,259,261,281,396,565` (`CHUNK_SIZE as u64`, `usize as u64` of a chunk length, consts, `enum as u64`) | all false positive: widening or fieldless-enum casts; no truncation on a wire length |
| cargo-careful | nightly-2026-09-28 | `cargo +nightly-2026-09-28 careful test -p candor-sealer` | 45/45 pass | — |
| Miri | nightly-2026-09-28 | `cargo +nightly-2026-09-28 miri test -p candor-sealer --lib -- proto` | 8/8 pass (proto + CBOR unit tests) | server tests need syscalls/Argon2 (not run under Miri) |
| cargo-geiger | 0.13.0 | `--manifest-path …/candor-sealer/Cargo.toml --all-features --output-format Ratio` | crate: no `unsafe`; deps carry the expected unsafe (tokio, rustix, libc, landlock, zeroize) | no growth beyond the existing intake set; landlock/enumflags2 are new → SEA-17 |
| cargo-audit | 0.22.1, advisory-db `9b3a3b7` (2026-09-30, 1,277 advisories) | `cargo audit --db … --no-fetch --deny warnings` | exit 0 | — |
| cargo-deny | 0.20.2 | `cargo deny --offline check` | `advisories ok`, `licenses ok`, `sources ok`; bans: duplicate `sha2` (pre-existing STO-17). A full `check` run aborted with a stack overflow inside cargo-deny; per-check runs completed | SEA-17 |
| cargo-vet | 0.10.2 | `cargo vet --locked` | workspace FAIL, 169 unvetted incl. `landlock`, `enumflags2`, `hkdf`, `subtle`, `tokio` | SEA-17 |
| systemd-analyze | 255 | `systemd-analyze security --offline=true deploy/intake/systemd/candor-sealer.service` | exposure 0.4 | `SystemCallFilter` content → SEA-06 |
| fuzz | — | `ls crates/*/fuzz/fuzz_targets` | no `fuzz_sealer_ipc` | SEA-09 |
| PoC tests | scratch crate outside the repo (`sealer-poc2`, path deps on the audited crates; uses the crate's own `tests/common`) | `cargo test --offline --test poc -- --nocapture` | 3/3 confirm: SEA-01 (sizes/shape), SEA-03 (COI bypass), SEA-04 (listener death) | findings |
| grep sweeps | ripgrep | B1.1–B1.12, B3.3, B3.5, B6.1, B7.4 patterns on `src` | only hit: `format!` in a redaction unit test | — |

PoC output (verbatim):
```
real SUBMISSION padded=32768, max chaff SUBMISSION=16384
real IDENTITY padded=8192, max chaff IDENTITY=4096
real follow-up objects=2, chaff follow-up object counts={1}
real initial account=true, chaff accounts=0
excluded member (label 2) can open SUBMISSION: true
serve finished=true result=Some(Err(Some(24)))          # EMFILE
new connect after limit restored: Err(ConnectionRefused)
```

---

## Findings

### AUD-RM2-SEA-01 — Real envelopes take sizes and shapes that chaff never takes
- Severity: High
- Location: crates/candor-sealer/src/server/seal.rs:676-692 (`ChaffBuckets::default`), 738-835 (`build_chaff`), 791-801 (chaff IDENTITY fixed at `MESSAGE_BUCKET_UNIT`); src/server/inner.rs:177-181 (`identity_payload`); src/proto/mod.rs:35 (`MAX_DRAFT_TEXT = 40 KiB`), 39 (`MAX_IDENTITY_LEN = 4096`) (commit d21981f)
- Category: B1.7 (+ CWE-203); IMPL-RM2 §4 A12
- Description: chaff is meant to be "a complete envelope of the same shape as a real one". Three distinguishers remain:
  - **SUBMISSION and SOURCE_MESSAGE buckets.** Chaff draws SUBMISSION from {4, 8, 12, 16} KiB and SOURCE_MESSAGE from {4, 8, 12} KiB. Real text may reach 40 KiB, which gives buckets up to 48 KiB. PoC: a 30,000-byte message → a 32 KiB SUBMISSION.
  - **IDENTITY bucket.** A chaff IDENTITY is always 4 KiB. A real identity block near the 4,096-byte cap pads to 8 KiB (PoC: 4,090 bytes → 8,192). This reveals that the envelope is real *and* that its mode is CONFIDENTIAL/IDENTIFIED.
  - **Follow-up shape.** A chaff follow-up is always one SOURCE_MESSAGE. A real follow-up with attachments is SOURCE_MESSAGE + ATTACHMENT_BUNDLE (PoC: 2 objects; 200 chaff samples, all 1 object).

  04 §12.7 lists only "bundle sizes above the chaff distribution's maximum" as an honest limit. The text and identity limits and the follow-up shape are not covered.
- Exploit scenario: an observer with access to the store, the relay or a Desk (ADV store seizure, compromised relay, any Triage Set member who sees pending envelopes) sorts envelopes by padded length and object count. Every envelope outside the chaff support is certainly real. The observer learns its day (and, for a live host, its write time) and, for 8 KiB identities, that the source chose a non-anonymous mode. This narrows the anonymity set and defeats ADR-047(3) purpose (2) for these envelopes. A source writing a long report is the realistic trigger.
- Fix recommendation:
  - Make the chaff support cover the real support. Draw chaff SUBMISSION/SOURCE_MESSAGE from every legal bucket up to the real maximum, weighted to match the expected real distribution. Draw chaff IDENTITY from both reachable identity buckets. With probability p, give chaff follow-ups a bundle drawn from the bundle distribution.
  - Or lower the input caps so that real envelopes cannot leave the chaff support: `MAX_IDENTITY_LEN` so that the IDENTITY always fits 4 KiB, and text so that the SUBMISSION fits ≤ 16 KiB.
  - Register `CHAFF_BUCKETS_*` in the 39 registry (SPEC-NOTES item 11).
  - Regression test: for maximal inputs of every kind, assert that each real object's `(type, padded_len, object count)` lies in the support of the chaff distribution.
- Spec / requirement reference: 04 §12.7; ADR-047(3); 07 §5.2a; ST-168, AT-087; IMPL-RM2 A12.
- Status: Open

### AUD-RM2-SEA-02 — Commit metadata separates chaff from real: `account` linkage and `release_offset_days`
- Severity: High
- Location: crates/candor-sealer/src/server/seal.rs:828-834 (chaff: `release_offset_days: 0`, `account: None`); src/server/mod.rs:1578-1585, 1619-1625 (real initial: `account: Some(..)`, offset U{1,2,3} when opted in) (commit d21981f)
- Category: B1.7 (+ CWE-203); IMPL-RM2 §4 A12
- Description: a real initial Tier W commit carries an `AccountRecord` (new account row in the same store transaction, and per 09 the envelope's `source_account_id`). A delayed real commit carries `release_offset_days ∈ {1,2,3}`. Chaff always carries `account = None` and offset 0 (PoC: real accounts 1, chaff 0). 07 §5.2a and 09 ("chaff … `source_account_id` NULL, `release_day = received_date`") prescribe exactly this, so the code follows the spec. The spec contradicts its own requirement in the same paragraph ("No column … distinguishes chaff from real rows") and IMPL A12 ("DB residue").
- Exploit scenario: in a seized or compromised intake store (ADV intake seizure, hosting provider), every envelope row with a non-NULL `source_account_id` or with `release_day > received_date` is real. The adversary also gets the real envelope ↔ account linkage through the shared transaction. The chaff therefore does not hide Tier W submission days or volume from the store. That was purpose (2) of ADR-047(3).
- Fix recommendation (needs a spec/ADR change before the code can follow):
  - Chaff initial triples carry a dummy `AccountRecord`: random `lookup_tag` and `auth_pk`, and a `prefs_ct` of the real fixed size under a random key. The store then expires dummy accounts like abandoned ones.
  - Chaff draws `release_offset_days` from the same mixture as real envelopes: P(opt-in) × U{1,2,3}.
  - Alternatively, decouple the account write from the envelope transaction and from `source_account_id`.
  - Add the store-side regression from STO G13 for these columns.
- Spec / requirement reference: 04 §12.7; 07 §5.2a; 09 §5.1 chaff rows; ADR-047(3); ADR-038(4); AT-087; IMPL-RM2 A12. Flag for spec owners (07/09).
- Status: Open

### AUD-RM2-SEA-03 — COI exclusion is applied per roster entry, not per user: a second entry bypasses it
- Severity: High
- Location: crates/candor-sealer/src/server/select.rs:87-116 (commit d21981f)
- Category: B5.2-class authorization (+ CWE-863); IMPL-RM2 §4 A4
- Description:
  ```rust
  let mut eligible: Vec<[u8; 16]> = triage.iter()
      .filter(|m| !excluded.contains(&m.role_label)) ... .map(|m| m.user_id).collect();
  eligible.sort_unstable(); eligible.dedup();
  ```
  When a `user_id` appears in `ChannelView.members` more than once, an exclusion of one entry's label does not remove the user, because the other entry passes the filter and `dedup` keeps the user. Nothing rejects duplicate user IDs. The ≤ 16 check (`triage.len()`) also counts entries, not users. PoC: member 2 (label 2, excluded by the category COI policy) also listed under label 9 → member 2's MEK opens the SUBMISSION.
- Exploit scenario: the roster holds one user under two labels. This happens through a plausible configuration (one person holds two independent roles) or a malicious roster change (needs CIK + K15 + independent approver, ADV insider admin). The source ticks the label of the person they report on, or picks a category whose COI map excludes that label. The submission is still sealed to that person. Plaintext and the source's identity block reach the excluded member, a confidentiality and anonymity impact that is Critical-class. One level lower because it needs a roster with a duplicated user.
- Fix recommendation:
  - Compute exclusion per user: exclude `user_id` if *any* of its active entries carries an excluded label.
  - Better: fail closed (`UNAVAILABLE`) on a snapshot with duplicate `user_id` in a channel roster, and count distinct users for the 16 limit.
  - Regression: the PoC as a test in `fail_closed.rs`.
- Spec / requirement reference: 04 §12.1 steps 4–5, §14.4 rule 5; ADR-030, ADR-037(1); BE-051; ST-146/147.
- Status: Open

### AUD-RM2-SEA-04 — IPC listener: unbounded connections, no timeouts, and `accept()` errors end `serve` permanently
- Severity: High
- Location: crates/candor-sealer/src/server/listener.rs:20-35 (`listener.accept().await?`), 52-66 (`read_exact` with no deadline, `vec![0u8; n]` up to 128 KiB per connection) (commit d21981f)
- Category: B2.6, B8.3 (+ CWE-400/770)
- Description:
  - Every accepted connection spawns a task with no global connection cap, no read/idle timeout and no per-connection message limit.
  - A peer that sends a 4-byte prefix announcing 131,072 bytes and then stalls pins a 128 KiB, mlocked (MCL_FUTURE) buffer indefinitely.
  - When the fd limit is reached, `listener.accept()` returns `EMFILE` and the `?` returns from `serve`. The sealer then stops accepting forever: PoC → `Err(24)`, and later connects get `ConnectionRefused` after the limit is restored. Either the process keeps running with no listener (intake down until someone restarts it), or the integrator exits and systemd restarts it, which loses every draft and session.
- Exploit scenario: the peer must hold the `candor-web` uid, but its connection pattern is driven by sources. If C-06 opens a sealer connection per source request or per upload stream (or leaks connections on error), a flood of source requests over Tor exhausts fds or memory. A compromised C-06 does the same trivially. Result: intake outage, plus a crash and restart that a timing observer can correlate. Per §E, this is unbounded resource use on an IPC path → High.
- Fix recommendation:
  - Treat `accept` errors as transient: log a typed event, back off and continue. Never return from the loop.
  - Add a global connection semaphore, sized ≥ C-06's pool, with fail-fast `BUSY`.
  - Add a per-frame read deadline (for example 5 s once a prefix has arrived) and an idle timeout per connection.
  - Optionally cap requests per connection.
  - Regression: the PoC (`EMFILE` survives) plus a stalled-prefix test.
- Spec / requirement reference: 07 §5.2, §11 (limits), BE-006; IMPL-RM2 §2.4, §2.7, A6; R9 §6.2.
- Status: Open

### AUD-RM2-SEA-05 — CSPRNG failure after a commit installs an all-zero K36
- Severity: Medium
- Location: crates/candor-sealer/src/server/mod.rs:1635-1639 (commit d21981f)
- Category: B3/B4.8 fail-closed (+ CWE-1241, CWE-636)
  ```rust
  let fresh = match random_secret32() { Ok(k) => k, Err(_) => Secret32::from_bytes([0u8; 32]) };
  sess.clear_draft(fresh);
  ```
- Description: if `fill_random` fails after a successful commit, the session keeps working with a public K36. Later parts on the same session (follow-up attachments) are staged under `K_stage = HKDF(0³², part_id)`.
- Exploit scenario: needs a CSPRNG failure, and an attacker who later learns the `part_id` (held by C-06) and can read tmpfs (ADV intake root). Such an attacker could decrypt the staged parts. It violates "refuse rather than degrade". Medium because the trigger is very unlikely.
- Fix recommendation: on RNG failure, remove the session (zeroize everything) and still return `Sealed`; the commit has already happened. Static rule: no `from_bytes([0u8; 32])` in non-test code. Regression: an injectable RNG fault test.
- Spec / requirement reference: 04 §9.13 (K36 from the CSPRNG), §23.4; BUILD-BRIEF fail-closed.
- Status: Open

### AUD-RM2-SEA-06 — Hardening is not enforced by the crate; seccomp is delegated to a unit that does not use the 07 §4.3 allow-list
- Severity: Medium
- Location: crates/candor-sealer/src/server/hardening.rs:46-113; src/server/mod.rs:329-379 (`Sealer::new` does not check the process state); tests/hardening.rs:31-53; deploy/intake/systemd/candor-sealer.service (`SystemCallFilter=@system-service …`) (commit d21981f)
- Category: B1.12, B3.4, B10.1 (+ CWE-693)
- Description:
  - `harden_process` is optional library code. `LandlockLevel::{Off, BestEffort}` are public and return `Ok`. `Sealer::new`/`serve` do not verify that the process is non-dumpable, has `RLIMIT_CORE = 0`, has memory locked (VmLck) or runs under a Landlock domain, so an integrator can run an unhardened sealer silently.
  - In-process seccomp (07 §4.3: "installed in-process … before accepting the first connection") is delegated to systemd (SPEC-NOTES). The shipped unit allows `@system-service`, which is far wider than the §4.3 list or the README's list.
  - `tests/hardening.rs` prints instead of failing when mlockall or Landlock do not apply, and never tests `Required`.
- Exploit scenario: a packaging or integration mistake leaves plaintext swappable or dumpable, or the syscall surface wide. A later memory-safety bug in a dependency, or a root read of swap or a core file, then recovers plaintext (THR-014/030). No direct exploit today.
- Fix recommendation:
  - `Sealer::serve` (or `new`) checks `dumpable_behavior() == NotDumpable`, `getrlimit(Core) == 0` and VmLck > 0, refusing to start otherwise; record the Landlock status returned by `harden_process` and refuse unless it is `Required`/fully enforced (expose `Off` only under `cfg(test)` or a test feature).
  - Either install seccompiler in-process or narrow the unit's `SystemCallFilter=` to the README list.
  - Make the hardening test fail in CI when it cannot apply hardening, or `#[ignore]` it with an explicit runner.
- Spec / requirement reference: 07 §4.3, §4.4, BE-003; IMPL-RM2 A14; ST-110.
- Status: Open

### AUD-RM2-SEA-07 — The sealer trusts an unverified, freely constructible `DirectorySnapshot`
- Severity: Medium
- Location: crates/candor-sealer/src/server/directory.rs:14-187; src/server/mod.rs:397-413 (`install_snapshot`) (commit d21981f)
- Category: B4.4/B5 (typestate), B6-adjacent integrity (+ CWE-345)
- Description:
  - `DirectorySnapshot` is a plain `pub` struct. Every safety property of recipient selection depends on the integrator having verified it and flattened it correctly, including:
    - checkpoint and witness signatures and consistency;
    - roster activation per §14.4 rule 7 ("previous active entry" semantics);
    - current ROLE_LABEL_CERTs;
    - MEMBER_EPOCH signer validity;
    - uniqueness of members (see SEA-03).
  - There is no `Verified` typestate, no field binding the view to the verified checkpoint, and no check that the view is internally consistent: unique users, 2..16 `read_intake`, unique COI policy per `effective_day` (`max_by_key` silently picks the last).
  - The high-water mark stores `(tree_size, issued_hour)` but no root hash, so a fork at an equal tree size is admitted.
  - The HWM is not persisted by the crate (the integrator must call `high_water_mark()` after every install).
- Exploit scenario: a bug in the future C-14 verifier or in the flattening (INC-SL-04 "snapshot entries used by ID after verification") silently widens the recipient set. ADV compromised Z-CORE benefits from any such gap.
- Fix recommendation:
  - Make `install_snapshot` accept only a `VerifiedSnapshot` produced by the verifier crate (private constructor).
  - Validate structural invariants on install and fail closed: unique `user_id`, ≤ 16 `read_intake` users, ≤ 1 policy per `effective_day`, MEK `user_id` ∈ roster.
  - Store the root hash with the HWM and reject an equal size with a different root.
  - Document or enforce HWM persistence ordering (persist before use).
- Spec / requirement reference: 04 §12.1 steps 1–2, §14.4–§14.5; ADR-036(6); IMPL-RM2 §2.4 pitfalls; ST-172.
- Status: Open

### AUD-RM2-SEA-08 — Non-zeroized copies of COI ticks and draft-derived metadata
- Severity: Medium
- Location: crates/candor-sealer/src/server/select.rs:97 (`excluded: Vec<u16>`), 105-116 (`eligible`); src/server/seal.rs:378-380 (`concerns: Vec<u16>`), 381-436 (`Value::U` vectors for ticks, categories, field ids, mode); src/server/select.rs `Selection` (`eligible_user_ids`, derives `Debug`); src/server/inner.rs `ReportPrefs.original_eligible` (commit d21981f)
- Category: B3.2 (+ CWE-226)
- Description:
  - The source's COI ticks are draft-sensitive. They reveal whom the source distrusts, and 07 BE-055 requires them only in zeroizing sealer RAM. They are still copied into plain `Vec<u16>` buffers and into `Value::A(Vec<Value>)` arrays, which are freed without zeroizing.
  - The eligible set computed from them (`Selection.eligible_user_ids`, the follow-up `original_eligible` clone) is plain as well and reveals the same information by difference.
  - Separately, `LOGIN_DERIVE` passes every passphrase through `candor_core::passphrase::normalize`, which still reallocates (AUD-RM1-CORE-03, open). This report does not re-count that; it is noted as reached here.
- Exploit scenario: ADV intake root / memory capture reads freed heap and learns flagged role labels or categories of recent submissions after the session ended. Memory is mlocked and non-dumpable, so this is defence-in-depth.
- Fix recommendation: hold ticks, eligible IDs, categories and mode only in `Zeroizing` containers. Give `Value` a `Zeroize` impl, or encode the ticks directly into the zeroizing encoder. Drop `Debug` on `Selection`. Track the closure of CORE-03.
- Spec / requirement reference: 07 BE-055; 27 §12.3; BUILD-BRIEF "Secrets".
- Status: Open

### AUD-RM2-SEA-09 — No `fuzz_sealer_ipc` target
- Severity: Medium
- Location: crates/candor-sealer (no `fuzz/` directory) (commit d21981f)
- Category: B2.9
- Description: IMPL-RM2 §2.3 requires a `fuzz_sealer_ipc` target registered under ST-043, and ST-053 `fuzz_passphrase_input`. Neither exists. `proto_props.rs` proptests (arbitrary bytes, mutation canonicity) are good, but they are not coverage-guided and do not reach the server-side state machine.
- Exploit scenario: an undiscovered decoder or state-machine panic aborts the sealer (`panic = "abort"`), losing every session. Nothing is known today.
- Fix recommendation: add `fuzz/fuzz_targets/fuzz_sealer_ipc.rs` (`decode_request`/`decode_response` + a `Sealer::handle` sequence driver over an in-memory sink) and `fuzz_passphrase_input`. Run each for 600 s at 2 GiB RSS.
- Spec / requirement reference: IMPL-RM2 §2.3, §5; ST-043, ST-053; BUILD-BRIEF input handling.
- Status: Open

### AUD-RM2-SEA-10 — Follow-ups ignore a COI policy tightened after the initial submission
- Severity: Low
- Location: crates/candor-sealer/src/server/mod.rs:1062-1066 (`categories: if initial { … } else { &[] }`), 1136-1145 (commit d21981f)
- Category: B5 (+ CWE-863); spec ambiguity
- Description: for follow-ups and KEY_ROTATION, selection uses `original_eligible ∩ current active` with no category COI filter, because the category is not kept in `prefs_ct`. 04 §12.1 step 5 says the follow-up set is "*additionally*" intersected, which implies the current COI_POLICY still applies. 07 §5.2 describes only the intersection. A conflict recorded after the report (COI tightening) therefore does not stop follow-ups reaching that member.
- Exploit scenario: after an initial report, the tenant adds a COI exclusion for a member implicated by it. The source's follow-ups and identity hints still reach that member. Low: that member already received the initial submission.
- Fix recommendation: store the report's categories in `prefs_ct` (key ≥ 1000) and re-apply the active policy for follow-ups. Or resolve the 04/07 wording through the spec owners.
- Spec / requirement reference: 04 §12.1 step 5, §9.5; 07 §5.2 `SEAL_FINISH`; ADR-036(4).
- Status: Open

### AUD-RM2-SEA-11 — Secret wrappers derive `Clone`/`PartialEq`; `Debug` on protocol types exposes metadata
- Severity: Low
- Location: crates/candor-sealer/src/proto/mod.rs:81, 99, 123, 156 (`SecretBytes`, `SecretText`, `SecretWords`, `Coi` derive `Clone, PartialEq, Eq`); 172, 199, 320, 534 (`DraftSet`, `DraftView`, `Request`, `Response` derive `Debug`) (commit d21981f)
- Category: B3.1, B1.3 (+ CWE-208, CWE-532)
- Description:
  - The secret wrappers derive non-constant-time `PartialEq` and `Clone`.
  - The redacting `Debug` impls hide the bytes, but a derived `Debug` on the enclosing types prints the submission `mode`, questionnaire field IDs, `lookup_tag` (`Response::Locator`), confirmation positions, part IDs and size buckets. C-06 links this module, and any `{:?}` of a request or response in its error path would emit linkable metadata.
- Exploit scenario: a future C-06 log line or panic message carries `lookup_tag` or mode (ADV log reader).
- Fix recommendation: drop `PartialEq`/`Eq` from secret wrappers (tests can compare `expose()`), and keep `Clone` only where needed. Hand-write redacting `Debug` for `Request`/`Response`/`DraftSet`/`DraftView` that prints only the op.
- Spec / requirement reference: 27 §12.3; BUILD-BRIEF "Secrets", "Metadata".
- Status: Open

### AUD-RM2-SEA-12 — `NOTE_REAL` is always enabled: chaff can be suppressed and real-kind markers minted for any hash
- Severity: Low
- Location: crates/candor-sealer/src/server/mod.rs:1178-1201, 1261-1276 (commit d21981f)
- Category: B5.1-class (+ CWE-285)
- Description: `NOTE_REAL` (Tier V) needs no session and no proof that an envelope exists. Each call cancels the next chaff event of the channel (up to 64 queued, renewable) and returns a real-kind `disposition_ct` bound to any caller-chosen hash. Tier V is out of RM-2 scope (the store keeps `UPLOAD_*` disabled), but the sealer serves the op.
- Exploit scenario: the peer must hold the web uid. A compromised C-06, or a C-06 bug, can stop all chaff for a channel. That makes later real envelopes stand out, and lets real-kind markers be attached to non-real envelopes.
- Fix recommendation: put `NOTE_REAL` behind a disabled-by-default cargo feature or config flag until RM-8. Count cancellations against actual store commits (the store confirms the `first_object_hash`).
- Spec / requirement reference: 04 §12.7; 07 §5.2a; ADR-047(3).
- Status: Open

### AUD-RM2-SEA-13 — Rare error paths orphan staged ciphertext; blocking unlink under the global session lock
- Severity: Low
- Location: crates/candor-sealer/src/server/mod.rs:1458-1461 and src/server/seal.rs:279 (`commit` `Err` after a successful rename, e.g. `settle_dir` failure in `candor-safefs::store` `commit`); src/server/mod.rs:430-434 (`reap_expired` drops sessions, so `StagedPart::drop` → `remove`, while holding `sessions` `std::sync::Mutex` on a runtime thread) (commit d21981f)
- Category: B6.4, B7.2
- Description: `PendingObject::commit` can return `Err` after the file has already been renamed into place. The caller then treats the part or bundle as not staged, and the file stays on tmpfs until restart. The reaper performs filesystem unlinks while holding the global session table lock on an async worker.
- Exploit scenario: ciphertext residue in staging (parts are unreadable once K36 is gone; a bundle is sealed to recipients). There is a small stall and DoS amplification under many simultaneous expiries.
- Fix recommendation: on a `commit` error, attempt `remove(id)` when the id is known (safefs could return the id with the error), or have safefs unlink on post-rename failure. In the reaper, collect the expired entries under the lock and drop them after releasing it, via `spawn_blocking`.
- Spec / requirement reference: 04 §9.13; 07 BE-055; ADR-027.
- Status: Open

### AUD-RM2-SEA-14 — One unopenable pending reply blocks passphrase rotation
- Severity: Low
- Location: crates/candor-sealer/src/server/mod.rs:1662-1675 (commit d21981f)
- Category: B2 availability (+ CWE-754)
- Description: `ROTATE_FINISH` aborts with `CRYPTO` if any supplied `(object_hash, stanza)` fails to open. A corrupted, foreign or adversarial entry supplied by the store or web therefore prevents rotation indefinitely. Rotation is the source's recovery action after a suspected passphrase exposure.
- Exploit scenario: ADV compromised store inserts a bogus pending reply for a mailbox. The source cannot rotate.
- Fix recommendation: skip entries that do not open (the store keeps them and they remain unreadable to the new key). Return a count band if the UI needs it. Fail only on a sealer-side error.
- Spec / requirement reference: 04 §11.6; 07 §5.2 `ROTATE_PASSPHRASE`; BE-072.
- Status: Open

### AUD-RM2-SEA-15 — `chaff_event` is not gated on freshness or `enabled`; SPEC-NOTES claims "same conditions"
- Severity: Info
- Location: crates/candor-sealer/src/server/mod.rs:1281-1322 (commit d21981f)
- Category: documentation / B12
- Description: real sealing refuses a stale (≥ 7 d) snapshot, but chaff keeps writing. `chaff_event` (a public function) also ignores `ChannelView.enabled`; the loop filters for it. This is harmless for anonymity, because there are no real envelopes to hide during an outage. However, the SPEC-NOTES statement "Chaff skips its write on the same conditions" is inaccurate, and `ChaffConfig.enabled = false` is accepted with no profile check.
- Fix recommendation: align the doc or the gate, and have the config checker reject `enabled = false` outside test profiles.
- Status: Open

### AUD-RM2-SEA-16 — Integration mismatches with the shipped unit (fail closed)
- Severity: Info
- Location: deploy/intake/systemd/candor-sealer.socket (`ListenSequentialPacket`), candor-sealer.service (`InaccessiblePaths=-/run/candor/staging`, no `ReadWritePaths`, credential names `sealer_signing_key`/`argon2_salt`) vs crate README (stream framing, staging written by the sealer, `sealer-k35`)
- Category: B10
- Description: the crate frames over `SOCK_STREAM` (SPEC-NOTES item 9) and writes staging itself (item 7). The unit provides a SEQPACKET socket and denies staging access. As shipped, the sealer cannot start or talk (it fails closed). Whoever reconciles the two must keep `PrivateNetwork`, Landlock and the staging-only write scope.
- Fix recommendation: reconcile the deploy unit with SPEC-NOTES items 7 and 9 (or change the crate), then re-run `systemd-analyze` and the integration tests.
- Status: Open

### AUD-RM2-SEA-17 — Supply chain: new deps unvetted; deny/vet gates red
- Severity: Info
- Location: crates/candor-sealer/Cargo.toml (`landlock =0.4.7` → `enumflags2`, `hkdf`, `subtle`, `tokio`, `unicode-normalization`)
- Category: B11.1–B11.4
- Description:
  - `cargo vet --locked` fails workspace-wide (169 unvetted, including the sealer's new `landlock`/`enumflags2`, `hkdf`, `subtle`).
  - `cargo deny` bans still report the duplicate `sha2` (STO-17), and a full `cargo deny check` run aborted with a stack overflow inside the tool (per-check runs are clean).
  - Pins are exact and `default-features = false`.
- Fix recommendation: add vet audits or exemptions with reasons for the T0 deps (crypto-reviewed criteria for `hkdf`/`subtle`), and resolve STO-17.
- Status: Open

### AUD-RM2-SEA-18 — Residual metadata notes
- Severity: Info
- Location: src/server/mod.rs:907 (`create_random` during upload); src/server/listener.rs:24 (uid only); SealerConfig `allowed_peer_uid`
- Category: B1.2, B8.1
- Description:
  - While a part uploads, its tmpfs temp file has exact atime/mtime until `commit` normalises them. ctime and birth time on tmpfs stay exact. This is acceptable for a RAM filesystem holding ciphertext, but it should appear in the 09 residual list next to the disk ctime note.
  - `allowed_peer_uid` is not validated: a value of 0 or of the sealer's own uid is accepted.
  - The session-handle `HashMap` lookup is not constant-time. Only the web peer can time it, so there is no impact.
- Fix recommendation: document the first point; reject uid 0 or the sealer's own uid at startup.
- Status: Open

---

## Tests as evidence (B12)

- Strong: `fail_closed.rs` (COI-empty, MEK, stale/rollback/suite, clock, store failure, capacity), `hygiene.rs` (marker scan of staging, `$TMPDIR` and store inputs; timers on a paused clock), `chaff.rs` (structure, K41 kinds, schedule, cancellation), `proto_props.rs` (no panic, canonicity), `flow.rs` (full ADR-050 slot verification).
- Missing:
  - a duplicate-roster COI case (SEA-03);
  - chaff-vs-real *support* tests at maximal input sizes (SEA-01);
  - commit-metadata indistinguishability (SEA-02);
  - listener resource tests (SEA-04);
  - RNG-failure injection (SEA-05);
  - a hardening test that fails when hardening is not applied (SEA-06);
  - fuzz targets (SEA-09).
- Peer-UID coverage: there is no test that runs as a second OS user (ST-097 `peer_uid`). `ipc.rs` covers the logic by configuring a different allowed uid, which is acceptable.

Gate: FAIL 2026-10-01 d21981fea263b5a5926922b3f13147d6b0c00932

---

## Re-test (round 2)

| Item | Value |
|---|---|
| Re-tested revision | `candor-sealer` at `cbf7c0f` (HEAD). Builder notes: `crates/candor-sealer/SPEC-NOTES.md` "Fixes for AUD-RM2-SEA"; decisions in ADR-052 |
| Build setup | `candor-core` was mid-fix in the live tree, so I tested a scratch copy of the workspace outside the repo, as the builder did: `git archive HEAD`, with `candor-core`/`candor-safefs` replaced by commit `b38ae65` and the live `Cargo.lock` |
| Date | 2026-10-01 |
| Procedure | AUDIT-CHECKLIST §G: fix diff read (3,516+/653− lines in the crate); regression tests run; round-1 PoCs re-run; variant hunt; delta review of the new code (`directory.rs` verifier and Merkle code, `listener.rs`, `hardening.rs`, `sink.rs`, the `seal.rs` group builder, `select.rs`, the fuzz target) |

### Tool and test results (round 2)

| Check | Result |
|---|---|
| `cargo test -p candor-sealer` (scratch) | 63/63 pass: 23 unit; chaff 7, fail_closed 13, flow 1, hardening 2, hygiene 3, ipc 2, listener 3, listener_emfile 1, proto_props 6, shape 1 |
| Round-1 PoCs re-run against the new API | **PoC A (shape):** every real and chaff group is `[main 65,536 | bundle | IDENTITY 16,384]`, and real bundles without attachments are 262,144, inside the chaff support. Store op order is `AG` for initial (real and chaff) and `G` for follow-ups, and every account has `prefs_ct` length 2,095 with one mailbox. **PoC B (COI duplicate):** the excluded person can no longer open the SUBMISSION. **PoC C (EMFILE):** covered by `tests/listener_emfile.rs` (my PoC), which passes |
| New PoCs (scratch only, deleted after the run) | `rt2_view_not_bound_to_checkpoint` (SEA-19), `rt2_self_check_passes_for_unconfined_thread` (SEA-20), NFC-expansion seal (SEA-22). All three confirm |
| clippy deny set, lib | clean (`--no-deps`; `candor-log` HEAD fails its own lint, as the builder noted) |
| clippy deny set, `--all-targets` | **fails** on test fixtures (`tests/common/mod.rs:353-366` `Path::join`, `std::fs::create_dir`/`set_permissions`) under HEAD's workspace `clippy.toml` `disallowed-methods` → SEA-24 |
| clippy audit extras | 13 `as_conversions` (same benign class as round 1); no new arithmetic, indexing or print warnings |
| `fuzz_sealer_ipc` | builds with nightly-2026-09-28; my 60 s run: 3.9 M execs, no crash, **cov 154** → SEA-23 |
| grep sweeps (print/log/fs/env/fixed key) | no hits in `src`; no `from_bytes([0u8…` outside tests |

### Per-finding status

| ID | Sev | Status | Evidence / note |
|---|---|---|---|
| SEA-01 | High | **Fixed** | ADR-052(1). Text objects always use the maximum bucket; every group is main + bundle + IDENTITY; chaff groups are built identically. `tests/shape.rs` plus the PoC A re-run. Residuals: bundles above the chaff support (documented, ADR-052(1)); NFC variant → SEA-22 |
| SEA-02 | High | **Fixed (sealer side)** | ADR-052(2). `commit_envelope_group` has no account field; chaff initials write a dummy account of identical shape; chaff draws delays at `delayed_share_permille` × U{1,2,3}. Tests: `shape.rs`, `chaff_delay_follows_real_distribution`. The store side must match (no account reference on envelope rows). Residual linkage → SEA-21 |
| SEA-03 | High | **Fixed** | Exclusion and the 16-person limit are per `user_id` (`select.rs`); `check_invariants` counts persons. The PoC B re-run passes; regression tests `coi_applies_per_person_not_per_roster_entry` and `coi_excluded_person_listed_under_two_labels_gets_no_slot`. Variant (key rotation / new MEK): exclusion is keyed by `user_id` and MEKs are selected per `user_id`, so a new MEK for an excluded person stays excluded. Residual: one human holding two `user_id`s is outside the sealer's view (C-14 `person_ref` rule) |
| SEA-04 | High | **Fixed** | Connection cap of 128 with a non-blocking `ERR{BUSY}`; 256 B pre-HELLO frames; handshake/frame/idle/write timeouts of 5 s/5 s/120 s/5 s; `accept` errors counted with 10 ms→1 s back-off, and the loop never returns. Worst-case buffered memory is 128 × 128 KiB. Tests `listener.rs` and `listener_emfile.rs` pass |
| SEA-05 | Med | **Fixed** | `rekey_after_commit` removes the session on CSPRNG failure, and no fixed key remains in `src`. Test `rng_failure_after_commit_never_installs_a_fixed_key` |
| SEA-06 | Med | **Partially fixed** | `serve` now refuses unless `self_check` passes, or a dev token is present; uid 0 and the sealer's own uid are refused. Bypass → SEA-20. The unit allow-list is now explicit (outside this crate, not re-reviewed beyond `config-check.sh` being green per the builder) |
| SEA-07 | Med | **Partially fixed → superseded by SEA-19** | Checkpoint signature, cosignature policy, RFC 9162 consistency, equal-size ⇒ equal-root, HWM persist-before-swap (persist failure → no change) and view invariants are all correct; I read the Merkle code and the note body matches 04 §14.3. The view content is still unbound, which is SEA-19 |
| SEA-08 | Med | **Fixed** | `Value` wipes integers on drop; ticks, eligible and triage lists are `Zeroizing`; `Selection` has no `Debug`. Minor residual: `select.rs` `excluded.reserve(..)` can reallocate the zeroizing vec when policy labels exceed the pre-size (flags + 16), leaving one unzeroized copy (Info, mlocked memory) |
| SEA-09 | Med | **Fixed** (target exists, runs clean) | Shallow coverage → SEA-23 |
| SEA-10 | Low | **Fixed** | Categories are stored in `prefs_ct` (report key 1002) and re-applied to follow-ups and rotations; `follow_up_reapplies_tightened_coi_policy` |
| SEA-11 | Low | **Fixed** | Constant-time `PartialEq` on secret wrappers; `Debug` redacted across proto and sink types (verified in the PoC output: `Response::Sealed(<redacted>)`) |
| SEA-12 | Low | **Fixed** | `NOTE_REAL` is off unless `enable_note_real` is set; `note_real_disabled_by_default` |
| SEA-13 | Low | **Fixed** | `stage_create`/`stage_commit` remove by known id on commit failure; the reaper unlinks outside the lock via `spawn_blocking` |
| SEA-14 | Low | **Fixed** | Unopenable replies are skipped; covered in `flow.rs` |
| SEA-15 | Info | **Fixed** | `chaff_event` is gated like real sealing; disabling chaff needs the dev token (`chaff_gated_like_real_sealing`) |
| SEA-16 | Info | **Open** (deploy-owned) | Unchanged by design |
| SEA-17 | Info | **Open** (workspace) | No new third-party dependency (`candor-log` is a workspace crate); the vet and deny gates are workspace items under ADR-052(7)/(8) |
| SEA-18 | Info | **Fixed / residual documented** | uid 0 and own uid refused in `serve`; tmpfs ctime listed as a residual |

### New findings (round 2)

### AUD-RM2-SEA-19 — `VerifiedSnapshot` does not bind the view's content to the verified checkpoint
- Severity: High
- Location: crates/candor-sealer/src/server/directory.rs `VerifiedSnapshot::verify` ("The view must be bound to the checkpoint it claims": compares only `tree_size`, `root_hash`, `issued_hour`); src/server/mod.rs `install_snapshot` (commit cbf7c0f)
- Category: B4.4/B5 (+ CWE-345, CWE-347); IMPL-RM2 A4
- Description:
  - `verify` authenticates the checkpoint (LOG_KEY signature, cosignatures, consistency). However, `channels` (roster members, COI policies, MEK public keys), `user_keys`, `custodian_pk` and `disposition_pk` are not tied to the signed root. There are no inclusion proofs and no per-entry signatures.
  - When the tree size equals the high-water mark, an empty proof with an equal root is accepted, so a genuine, already-installed checkpoint can be **replayed with any view**.
  - PoC (`rt2_view_not_bound_to_checkpoint`): reuse the installed checkpoint, replace member 1's MEK with an attacker key → `install_snapshot` returns `Ok(())` → the next SUBMISSION opens with the attacker key.
  - The type name, ADR-052(6) ("produced by checking signatures, witness cosignatures, continuity…") and the self-review ("unsigned … snapshot" fails closed) suggest an assurance the code does not give. Integrators may therefore omit the C-14 entry verification that SPEC-NOTES still assigns to them.
- Exploit scenario: the snapshot feed reaches the sealer through the relay control cycle from Z-CORE (C-09). An adversary who controls that feed (compromised Z-CORE/relay, or ADV insider at the core) does not need the LOG_KEY or witnesses. They re-send the current signed checkpoint with a substituted MEK, an added Triage member, a loosened COI policy or a replaced custodian key. Every subsequent Tier W submission (plaintext and identity block) is then sealed to them. Directory transparency and witnesses exist to prevent exactly this. The impact is Critical-class; one level lower because the adversary must control the snapshot channel.
- Fix recommendation:
  - Bind every entry the sealer uses to the checkpoint root. The bundle carries the referenced KD entries (CHANNEL_ROSTER, COI_POLICY, MEMBER_EPOCH, USER_KEYS, CUSTODIAN, DISPOSITION_KEY) with RFC 9162 inclusion proofs against `cp.root_hash`, and their signatures are verified (§14.4 rules). The view is derived from those verified entries, never accepted as a free-standing struct.
  - Until that exists, do not construct `VerifiedSnapshot` from an unverified view. Name the current type for what it checks, and make RM-2 integration conditional on the entry verifier.
  - Also reject a same-size re-install whose view differs from the installed one.
  - Regression: the PoC (tampered view with replayed checkpoint → `Err`).
- Spec / requirement reference: 04 §12.1 steps 1–2, §14.3–§14.5 (VR-2..VR-5); ADR-036(5)/(6); ADR-052(6); ST-172.
- Status: Open

### AUD-RM2-SEA-20 — Hardening self-check trusts a process-global report; the serving threads may be unconfined
- Severity: Medium
- Location: crates/candor-sealer/src/server/hardening.rs `harden_process` (`REPORT.set`), `self_check` (commit cbf7c0f)
- Category: B1.12, B3.4 (+ CWE-693)
- Description: Landlock confines only the calling thread and threads it creates afterwards. `harden_process` records `landlock_enforced = true` in a process-global `OnceLock`, and `self_check` only reads that record plus dumpable state and `RLIMIT_CORE`. If the integrator calls `harden_process` anywhere other than the main thread before the runtime starts (inside `block_on`, from a helper thread, or after the runtime exists), the tokio workers that serve IPC run outside the Landlock domain while `serve` accepts. PoC (`rt2_self_check_passes_for_unconfined_thread`): `harden_process(Required)` on a helper thread → `self_check()` is `Ok` on the main thread, and that thread reads `/etc/hostname` and `/proc/self/status`. VmLck is not re-checked either.
- Exploit scenario: an integration error silently removes filesystem confinement (and the ABI-4 TCP denial) from the plaintext-holding threads, against ADR-052(5)'s intent to refuse to run unhardened. It needs a misuse, but the check exists precisely to catch misuse.
- Fix recommendation: make `self_check` probe the actual confinement from the serving context. Run it on every runtime worker, for example via `on_thread_start`, and from the serve task: attempt to open a path outside staging that must fail with `EACCES`, and attempt a TCP `socket`+`bind` that must fail. Re-check VmLck > 0. Alternatively, have `harden_process` refuse unless it runs on the process's main thread before any other thread exists (thread count from `/proc/self/status` `Threads: 1`).
- Spec / requirement reference: ADR-052(5); 07 §4.4, BE-003; IMPL-RM2 A14.
- Status: Open

### AUD-RM2-SEA-21 — Dummy and real accounts separate over time; write adjacency links an account to its initial envelope
- Severity: Low
- Location: crates/candor-sealer/src/server/mod.rs `seal_blocking` (`upsert_account` then `commit_envelope_group`), `chaff_event` (same order), `rotate_blocking` (`replaces: Some(..)` only for real accounts); `ChaffConfig::delayed_share_permille` default 500 (commit cbf7c0f)
- Category: B1.7 (+ CWE-203)
- Description:
  - Real and chaff initials both issue `A` immediately followed by `G` from one thread (PoC op trace `AGAG…G…`). A store that persists them as adjacent transactions links account ↔ initial envelope (insertion order or `xmin`) until the next `uniform_rewrite`. That holds for real and chaff alike.
  - Later account-level behaviour exists only for real accounts: rotations (`replaces` = old tag), login activity that keeps the account out of `purge_inactive_accounts`, and replies addressed to its mailbox.
  - So an adversary who seizes the store within the rewrite window, and later sees which accounts were rotated or survived, can mark the linked initial envelopes as real.
  - Separately, the chaff delay share is a fixed default (500 ‰) that operators are told to set to "the observed opt-in share". Observing that share means counting a source choice, and a mismatch shifts the per-row likelihood.
- Exploit scenario: ADV intake-host seizure with two snapshots in time, or a live store compromise. The result is a probabilistic real-or-chaff split for some initial envelopes; it needs store residue the store audit (STO-01) already tracks.
- Fix recommendation:
  - Have the store defer account inserts to the next fixed slot, or batch them with chaff dummies so no envelope adjacency exists. Alternatively, have the sealer queue account upserts and flush them at random times independent of envelope commits.
  - Give dummy accounts synthetic lifecycle events: occasional rotations and activity marks at the same rates as real accounts.
  - Set the delay share by policy (for example: always delay chaff by U{0..3} at the published real-choice prior) and document it in 39.
- Spec / requirement reference: ADR-052(2), (14); ADR-047(3); 09 §5.1.
- Status: Open

### AUD-RM2-SEA-22 — Draft text that cannot be sealed is accepted, and the refusal comes only after Argon2id and the passphrase are consumed
- Severity: Low
- Location: crates/candor-sealer/src/proto/mod.rs `MAX_DRAFT_TEXT` (bytes before NFC); src/server/seal.rs `nfc()` + `inner::length_prefixed_pad` (64 KiB maximum); src/server/mod.rs `seal_finish` (`g.pending = None` after `derive`, before `seal_blocking`) (commit cbf7c0f)
- Category: B2.10 (+ CWE-20)
- Description: the 40 KiB cap is checked on raw bytes, but the SUBMISSION carries the NFC form, which can expand up to 3× (for example U+0958, 3 B → 6 B). PoC: 13,653 × U+0958 (40,959 B) is accepted by `DRAFT_SET` and confirmed, then `SEAL_FINISH` returns `LIMIT`. By then the Argon2id derivation has run and the confirmed passphrase has been dropped, so the source must regenerate and re-confirm a passphrase. It fails closed (nothing is committed), but it is a source-facing availability and usability trap and wastes an Argon2 permit.
- Fix recommendation: enforce the cap on the NFC length at `DRAFT_SET` (or at least before `derive` in `SEAL_FINISH`), and keep the pending passphrase until the commit succeeds. Regression: the PoC input.
- Spec / requirement reference: 04 §13.4 key 13 (NFC); ADR-052(13); AT-094.
- Status: Open

### AUD-RM2-SEA-23 — `fuzz_sealer_ipc` reaches little of the server and skips the sealing path
- Severity: Low
- Location: crates/candor-sealer/fuzz/fuzz_targets/fuzz_sealer_ipc.rs (commit cbf7c0f)
- Category: B2.9
- Description:
  - The driver needs valid canonical CBOR frames but ships no seed corpus. A 60 s run reached `cov: 154`.
  - `SEAL_FINISH`, `LOGIN_DERIVE` and `ROTATE_FINISH` are always skipped. Recipient selection, the group builder, chaff, `rotate_blocking` and the prefs and reply parsers behind `LOAD_PREFS`/`OPEN_REPLY` with real data are therefore never fuzzed.
- Fix recommendation:
  - Add a seed corpus generated from `encode_request` of valid sequences, or derive `Request` structurally with `arbitrary` and encode it.
  - Add a `cfg(fuzzing)` hook for cheap Argon2 parameters so the derive-dependent ops run.
  - Record the coverage reached in SPEC-NOTES.
- Spec / requirement reference: IMPL-RM2 §2.3; ST-043.
- Status: Open

### AUD-RM2-SEA-24 — Observations
- Severity: Info
- Description:
  - (a) `InsecureDevMode::acknowledge` emits `sys.health{service=Upload, DEGRADED, READINESS}`, which a monitor cannot tell apart from an ordinary readiness degradation. The token is also obtainable with an in-memory log sink, as the test helper does. Add a dedicated code (the builder already flagged this for the `candor-log` owner) and require the production signer/sink type.
  - (b) Real groups always carry an IDENTITY with one K13 slot (follow-ups included now), while chaff IDENTITY slots are all dummies. The K13 holder can therefore classify every group as real or chaff by trial decryption. This is consistent with 04 §12.7 (chaff = all dummy slots) but extends what K13 learns to follow-ups. Add it to the §12.7 honest limits.
  - (c) `cargo clippy --all-targets -D warnings` fails on test-fixture `std::fs`/`Path::join` under the workspace `disallowed-methods` (the `// safefs-lint` comments do not satisfy clippy); add `#[allow(clippy::disallowed_methods)]` in `tests/common`.
  - (d) `excluded.reserve()` reallocation residue (see SEA-08 row).
- Status: Open

### Round-2 summary and gate

| Severity | Open after round 2 |
|---|---|
| Critical | 0 |
| High | 1 (SEA-19) |
| Medium | 1 (SEA-20); SEA-06/SEA-07 partially fixed and tracked through SEA-20/SEA-19 |
| Low | 3 (SEA-21, SEA-22, SEA-23) |
| Info | 3 (SEA-16, SEA-17, SEA-24) |

Fixed and re-tested: SEA-01, 02 (sealer side), 03, 04, 05, 08, 09, 10, 11, 12, 13, 14, 15, 18.

**Gate: FAIL 2026-10-01 cbf7c0f** (core/safefs at b38ae65): SEA-19 (High) is open, and SEA-20 (Medium) needs a fix or the lead's written acceptance.

---

## Re-test (round 3)

| Item | Value |
|---|---|
| Re-tested revision | HEAD `8517304`. This commit follows `837be04`, and its "Sealer round-3 fixes" contain the claimed changes. The working tree was clean for `crates/candor-sealer`, `candor-core`, `candor-safefs` and `candor-intake-store`. Tested against the **live** candor-core (migration complete) |
| Results | `cargo test -p candor-sealer --locked`: 72 pass (28 unit + 44 integration) plus the `harness = false` hardening binary (exit 0). `cargo clippy -p candor-sealer --all-targets --all-features -D warnings`: clean. No raw-key STREAM construction remains in `src`: no `StreamEncryptor::new`, `StreamDecryptor::new`, `derive_payload_key` or `derive_stage_part_key`. Fuzz, in a scratch `git archive` copy: `fuzz_sealer_ipc` with the shipped seeds ran 180 s, 3,530 execs, **cov 10,673**, no crash, leak or OOM |

### Status

| ID | Status | Evidence / note |
|---|---|---|
| SEA-19 | **Fixed** | `kd.rs`/`directory.rs` recompute the RFC 9162 root over every SignedKDEntry and require it to equal the signed root, with count = tree size. Entries are checked in leaf order for continuity and per-type signers; MEK usability requires the member's current unrevoked K08. My PoC (genuine checkpoint + attacker MEK) and its add/remove/reorder variants → `Inclusion` (`tests/directory.rs::genuine_checkpoint_with_attacker_mek_is_rejected`). A compromised LOG_KEY cannot introduce a MEK, CIK relabel or COI loosening (`entries_need_their_own_signers…`). The new variant is SEA-25 |
| SEA-20 | **Fixed** | `harden_process` refuses unless `gettid == getpid` and no runtime is active. `confined_runtime()` marks only its own threads (`on_thread_start`). `guard()` runs on every request, frame and blocking job, and a single unconfined thread poisons the sealer. My PoC (helper-thread hardening) is refused (`tests/hardening.rs`) |
| SEA-21 | **Partially fixed** | Account writes are queued in RAM and flushed every 15 min in a CSPRNG-shuffled batch (creates before replacements); dummy accounts rotate at 50 ‰; there is no `A` between envelope groups (`shape.rs`, `chaff.rs`). The residual is rated in SEA-28 |
| SEA-22 | **Fixed** | `DRAFT_SET` caps the NFC length (message + answers, identity) before storing. The pending passphrase survives a failed commit (`fail_closed.rs::nfc_expanding_draft_is_refused_at_draft_set`, which is my PoC) |
| SEA-23 | **Fixed** | A structure-aware stateful mode reaches sealing, login, rotation and account flush; seed corpus of 73 files. Residual: about 20 exec/s, because a real Argon2id runs per input. That is acceptable for the nightly job |
| SEA-24 | **Fixed** except (a) | (a) The dev-mode event still uses a generic code (candor-log C-2). (b), (c), (d) are done |
| SEA-16 | **Fixed (sealer side)** | Bundles are anonymous memfds sealed `WRITE|GROW|SHRINK|SEAL`; `fstat` size is checked before hand-over. `await_ack` accepts only exactly one byte `0x01` with no descriptors and no `TRUNC`/`CTRUNC`; it refuses `0x00`, other bytes, longer replies, returned fds and EOF (`tests/handover.rs`). The 41-byte format matches `candor-intake-store/src/staged.rs` (`STAGED_MSG_LEN`, version, `u64be len`, SHA-256; acks `0x01`/`0x00`). Receiver gaps known as STO-27, confirmed in this review: no `F_GET_SEALS` check, no peer-UID check, and the module doc still talks about "the sealer deletes its staged file". `await_ack` has no receive timeout, so a hung store pins one blocking thread per commit (Low; add `SO_RCVTIMEO`). Memory budget → SEA-26 |
| STREAM migration | **Verified** | `for_payload` / `for_staged_part(SessionKey, PartId)`; K36 is a `SessionKey` |
| ADR-055(2) KD encoding | **Info** | The numbering follows the 04 §14.2 field order, and composite subjects are domain-labelled SHA-256. This is acceptable as an interim canonical form. Until 04 §14.2 and 09 are amended, C-14 (the producer) has no normative source, so any divergence is a silent format break. 09 `kd_entry.signer_key_id bytea(16)` contradicts the 32-byte key id used here. Track as spec item C-3 |
| SEA-17 | Open (workspace) | unchanged |

### New findings (round 3)

**AUD-RM2-SEA-25 — Unsigned REVOCATION and OBJECTION entries are honoured (Medium).** `kd.rs` (`ty::REVOCATION`: no signer check; `ty::OBJECTION` with `resolved = false`: no signer check). 04 §14.2 requires REVOCATION to be signed by a "signer authorized for the subject type", and OBJECTION by the K08 of a current channel member or OVERSIGHT member. The builder's own test appends an attacker-signed REVOCATION of member 1's MEK and the sealer accepts it (`revocations_rotations_and_objections_shrink_the_recipient_set`). An adversary who can append and checkpoint (a compromised C-14/LOG_KEY; witnesses cosign anything consistent) can:
- remove chosen honest Triage Set members' MEKs or K08s, steering every new submission to the remaining (possibly colluding) members without the CIK+K15 tightening governance;
- revoke the K01, CIK or LOG_KEY to freeze the directory, or block any loosening with an unsigned objection.

This is not plaintext disclosure to a non-member. It is a governance bypass on the recipient set, which is why it is Medium. Fix: require the authorized signer per subject type (the key itself, its K01/CIK/K15 authority, or OVERSIGHT) and a channel-member or OVERSIGHT K08 on objections; regression = the existing test with `attacker()` expecting `Entry`.

**AUD-RM2-SEA-26 — Memfd bundles double the attachment memory; a source can OOM-kill the sealer (High).** `handover::BundleWriter` (unbounded memfd), `seal.rs` bundle sealing; unit `MemoryMax=6656M` (= 2560M + 4 GiB staging). At `SEAL_FINISH` the staged parts (tmpfs, charged to the sealer cgroup per the unit comment) still exist while the full padded bundle is written into a memfd in the same cgroup. Peak usage is therefore about 2× the attachment volume, plus working set.
- Before this change the bundle went to the size-limited staging tmpfs, so overflow gave `ENOSPC` → `BUSY`.
- Now nothing bounds memfd bytes. One source uploading a bit over 2 GiB (within `max_file_bytes`/`max_bundle_bytes` = 4 GiB and the staging size), or several concurrent large seals, pushes the cgroup past `MemoryMax`. The kernel OOM-kills the sealer and every session and draft is lost (also SEA-28's account queue).
- This is remotely triggerable at will through C-06, and the restart is observable.

Fix: a global byte budget for in-flight memfds (`try_acquire_many` on a byte semaphore → `BUSY` before writing); budget `MemoryMax` for parts + bundle (or cap `max_bundle_bytes` so that 2× fits); or stream the bundle to the store in chunks. Regression: a seal whose bundle exceeds the budget returns `BUSY` without allocating.

**AUD-RM2-SEA-27 — Only the Ed25519 halves of KD signatures are verified (Low).** `alg 2/3` signatures are "carried, not verified" (SPEC-NOTES, KD verification). Entries that 04 requires to be signed with "both algs" (ORG_ROOT, GOVERNANCE_ROLES, K01 entries) are accepted on Ed25519 alone, so the post-quantum half adds nothing at the sealer. Fix: verify the ML-DSA half where 04 requires it (candor-core API), or record the downgrade as an accepted residual with an expiry.

**AUD-RM2-SEA-28 — Queued account writes are not durable when the source is told "received" or "rotated" (Medium).** `mod.rs` `enqueue_account`, `flush_accounts` (15-min batches, RAM only), `rotate_blocking` (the replacement is queued, the session switches to the new keys and `Locator` is returned). Rating of the residual the coordinator asked about:
- **Crash loss.** Any sealer crash or restart within the window loses every queued real account (the source believes it can return for replies and cannot), and every queued rotation. Crashes include `Restart=on-failure`, a deploy restart, or SEA-26's OOM, which a source can trigger.
- **Rotation after suspected compromise.** The **old passphrase stays valid at the store** for up to 15 min, and indefinitely if the sealer crashes. That defeats the recovery action.
- **Double rotation within the window.** `enqueue_account` merges the second replacement into the first and **overwrites** `rewrapped_replies`. The second rotation cannot open replies still wrapped to the original key (skipped per SEA-14), so those replies become permanently unreadable.

Medium: integrity and availability of the source's reply channel, plus a rotation gap; no anonymity loss. Fix options:
- Make rotations durable immediately: replacements are rare and are a different row operation from creates, so the adjacency concern does not apply in the same way.
- For creates, keep batching but have the store persist an indistinguishable encrypted pending row at commit time.
- Merge `rewrapped_replies` by object hash instead of replacing them.
- Tell the source in the UI that the account becomes usable at the next slot.

A lead acceptance is possible for the create-loss part only.

### Gate (round 3)

| Severity | Open |
|---|---|
| Critical | 0 |
| High | 1 (SEA-26) |
| Medium | 2 (SEA-25, SEA-28) |
| Low | 1 (SEA-27) plus the `await_ack` timeout note |
| Info | SEA-16 receiver side (STO-27), SEA-17, SEA-24(a), ADR-055(2) / C-3 |

Fixed and re-tested in round 3: SEA-19, SEA-20, SEA-22, SEA-23, SEA-24(b–d); SEA-16 on the sealer side; STREAM migration. SEA-21 is partially fixed, with its residual tracked as SEA-28.

**Gate: FAIL 2026-10-01 8517304**: SEA-26 (High) is open, and SEA-25/SEA-28 (Medium) need fixes or the lead's written acceptance.

## Lead dispositions after round 3 (2026-10-01)
- **Gate: FAIL.** Fixes have been assigned to the builder:
  - **SEA-26 (High):** incremental memfd write that frees each part, plus global admission control against a memory budget below MemoryMax, using the uniform "busy" refusal.
  - **SEA-25 (Medium):** REVOCATION and OBJECTION must be signed per 04 §14.2; otherwise the snapshot fails closed.
  - **SEA-27 (Low):** both halves of the hybrid signature must verify.
  - **SEA-28 (Medium):**
    - immediate in-memory invalidation of the old passphrase;
    - coalesced double rotation, with a test that replies stay readable;
    - flush on SIGTERM.
    The residual crash loss is documented to sources in 11a §7.
  - **Info:** await_ack gets a receive timeout. `signer_key_id` is 32 bytes; spec 09 is amended under ADR-055(2).
- **C-2:** done in candor-log (`Service::Sealer`, `HealthCheck::InsecureDevOverride`); the sealer is switching to it.

---

## Re-test (round 4)

| Item | Value |
|---|---|
| Re-tested revision | Live tree at HEAD `aa2683b`. The working tree was clean for the sealer, `Cargo.lock` and `supply-chain`. The sealer changes since round 3 are in `4be7f7d`…`ff8b5c4` |
| Results | `cargo test -p candor-sealer --locked`: 78 pass (29 unit + 49 integration, 14 binaries), plus the hardening binary. `clippy --all-targets --all-features -D warnings`: clean. `cargo audit` (1,278 advisories): clean. `cargo deny --offline check` advisories, bans, licenses and sources: all ok. **`cargo vet --locked`: FAIL**, because `ml-dsa 0.1.1` and `signal-hook-registry 1.4.8` lack `safe-to-deploy`. Scratch build and target directories were removed after the run |

### Status

| ID | Status | Evidence / note |
|---|---|---|
| SEA-25 | **Fixed** | `kd.rs::revocation_authorized` accepts:<br>• K01 for any key;<br>• for a MEK: the member's current K08, or the CIK plus a K15;<br>• for a user key: the key itself, or a K15 plus an OVERSIGHT K08;<br>• for a K15 or CIK: the key itself.<br>Anything else (LOG_KEY, K01, unknown keys) → `Entry`. `objection_authorized` accepts a latest-roster member's K08 or an OVERSIGHT K08. My PoC (attacker-signed revocation) now returns `Entry` (`directory.rs`) |
| SEA-26 | **Fixed**, with residual SEA-29 | Parts are taken out of the session and freed while the bundle memfd is written, so the peak is the bundle plus one part. `PART_BEGIN` reserves the ciphertext of every declared part plus the bundle bucket of the declared total; when it does not fit, the source gets the uniform `BUSY`. My answers to the coordinator's questions:<br>• **Declared length enforced?** Yes. `part_chunk_blocking` aborts the part with `LIMIT` once `received + n > declared_len`. Padding goes to `bucket(declared_len)`, and `staged` uses each part's `real_len`, which is at most its declared length. An upload cannot exceed its reservation.<br>• **Budget below `MemoryMax`?** Yes, by arithmetic: 3,840 MiB + 2,560 MiB (07 §4.2 baseline) = 6,400 ≤ 6,656 MiB. The baseline has to absorb Argon2id (4 × 64 MiB), up to 128 × 128 KiB frames, ≤ 8 MiB chaff memfds and a KD bundle of up to 512 MiB plus its derived view. That leaves roughly 1.5 GiB margin under normal sizes. The budget is a fixed default and is not checked against the unit or a profile's `MemoryMax`, so a profile that lowers `MemoryMax` must lower `memory_budget_bytes` too; config-check rule recommended (Info).<br>• **Lost attachments after a failed seal: fail-closed and uniform?** Fail-closed, yes. `parts_lost` makes `SEAL_FINISH` return `BAD_STATE` until `DRAFT_GET`, `PART_BEGIN` or `SEAL_ABORT`, so nothing is ever committed silently without its attachments. The source sees the usual failure page, then a draft without parts. Note that the parts are taken before **any** failure in `seal_blocking`, including store outages before a single byte was copied, so every store hiccup costs the attachments. Acceptable as disclosed; Info |
| SEA-27 | **Fixed (code)** | K01 entries need both halves; every ML-DSA half present must verify; `alg` 3 is refused (`directory.rs::k01_entries_need_both_signature_halves`). **Dependency:** `ml-dsa =0.1.1` (RustCrypto/signatures, Apache-2.0/MIT, crates.io checksum `add6b9d9…`, `default-features = false`, verify-only use). It is the first stable line after the rc series and is not affected by RUSTSEC-2025-0144 (patched ≥ 0.1.0-rc.3). As far as I know it has no third-party audit. It is unvetted, so the PR vet gate is red → SEA-30 |
| SEA-28 | **Fixed (a)(b)(c); (d) residual documented** | (a) `LOGIN_DERIVE` consults the queue and returns a random locator for a pending-replaced account; this is the same work for every login. (b) Merge by object hash, newer wrap wins (`flow.rs::double_rotation_keeps_replies_readable`). (c) SIGTERM flush with 1–4 dummy creates (`tests/shutdown.rs`). Residual (crash or kill loses queued creates; a rotation reverts to the old passphrase after a crash) is per the lead disposition and the 11a §7 wording. **Accepted by lead** |
| Info: `await_ack` | **Fixed**, with a note | `SO_RCVTIMEO` of 60 s. Note: the acknowledgement byte is not bound to the bundle (no hash echo). An integrator that reuses `istore.sock` after a timeout could read a late `0x01` as the acknowledgement of the *next* bundle, and a timed-out commit may still land in the store as an orphan envelope with no queued account. Close the socket after any `await_ack` error, or echo the SHA-256 in the acknowledgement (Low, integration; fold into C-5) |
| Info: `signer_key_id` | **Fixed** | 32 bytes, no truncation (SPEC-NOTES; 09 amended under ADR-055(2) per the lead) |
| DEP-29 | **Fixed** | `MFD_NOEXEC_SEAL`; seals include `F_SEAL_EXEC`; start-up check refuses kernels below 6.3 (`StartError::Memfd`). `handover.rs` tests cover the seals, no exec bits, and `fchmod +x` being refused |
| C-2 / SEA-24(a) | **Fixed** | `sys.health{service=sealer, DEGRADED, INSECURE_DEV_OVERRIDE}` |
| SEA-16 / STO-27 receiver | Store-side, closed in the store audit | — |
| SEA-17 | Open (workspace) | see SEA-30 |

### New findings (round 4)

**AUD-RM2-SEA-29 — Attachment reservations are held without data and never shrink: cheap global upload denial and a probe of other sources' uploads (Medium).** `budget.rs` / `mod.rs::part_begin`. A `Grant` only grows (`grow_to`) and is released only when the draft is dropped: submit, abort, zeroize, or the 20 min idle / 2 h absolute expiry, which `TOUCH` keeps alive.
- **Denial.** `PART_BEGIN` reserves on the *declared* length (the web's `Content-Length`) before any byte arrives. A stalled or aborted upload, or a `PART_DROP`, leaves the reservation in place. Two sessions declaring about 1.9 GiB each, then stalling, therefore exhaust the 3,840 MiB budget, and every other source gets `BUSY` on uploads for up to 2 h. This costs only session-open PoW and two partial requests.
- **Probe.** The budget is at most about 2 per-session maxima wide, far below the "≥ 10× design peak" rule of ADR-038(5) / IMPL-RM2 §2.7. A `PART_BEGIN` probe with size X tells the prober whether other sessions currently hold more than `cap − X`, which leaks the presence and rough size of other sources' ongoing attachment uploads.

Fix:
- Shrink the grant on `PART_DROP`, on an aborted or over-declared upload, and when a part completes (re-reserve on `real_len` buckets).
- Reserve incrementally as bytes arrive (with the bundle term computed at seal time against a separate seal reservation), or cap the share of the budget held per session and expire reservations of stalled uploads quickly (for example after the web's body timeout).
- Size the budget, or the per-session cap, so that one probe cannot observe other sessions, per ADR-038(5).

Regression: a stalled `PART_BEGIN` followed by `PART_DROP` returns the budget, and N concurrent maximal declarations below the cap leave the probe answer unchanged.

**AUD-RM2-SEA-30 — `cargo vet` gate fails on the new dependencies (Medium, B11.3).** `ml-dsa 0.1.1` (crypto, T0 verification path) and `signal-hook-registry 1.4.8` (from tokio `signal` for the SIGTERM flush) have neither an audit nor an exemption. Under ADR-052(8), PR CI requires `safe-to-deploy`, and `ml-dsa` additionally needs `candor-crypto-reviewed` before release. Fix: record a reasoned safe-to-deploy audit or exemption for both now, and schedule the Crypto Reviewer audit of `ml-dsa` (its FIPS 204 verify path, with KAT/Wycheproof vectors run in CI) before RM-6. Alternatively, move ML-DSA verification into candor-core under C-1 with its own vetting.

### Gate (round 4)

| Severity | Open |
|---|---|
| Critical / High | 0 / 0 |
| Medium | 2 (SEA-29, SEA-30) |
| Low | `await_ack` acknowledgement binding / socket reuse (integration note, C-5) |
| Info | budget vs profile `MemoryMax` config-check rule; attachments lost on any seal failure; SEA-17 |

**Gate: FAIL 2026-10-01 aa2683b.** There are no open Critical or High findings. SEA-29 and SEA-30 (Medium) each need a fix or the lead's written acceptance with an expiry. Once both are fixed or accepted, the sealer meets §F.

## Lead dispositions after round 4 (2026-10-01)
- **No Critical/High open; gate FAIL pending SEA-29.**
- **SEA-29 (Medium): fix assigned.**
  - Per-session upload quota reserved at draft admission, with max drafts = budget / quota. Admission BUSY is capacity-revealing by design (ADR-038).
  - Uploads within a session's own quota never return BUSY.
  - A part that receives no bytes for 120 s is aborted.
  - Reservations are released on abort or at draft end.
- **SEA-30 (Medium): accepted for PR CI.** `ml-dsa 0.1.1` and `signal-hook-registry 1.4.8` get safe-to-deploy exemptions (expiry 2027-03-30, 28 §5.2). `ml-dsa` is added to `supply-chain/crypto-set.txt`, so the release gate requires a real `candor-crypto-reviewed` audit before any release. `cargo vet` passes.
- **Low (ack binding):** the sealer closes the socket on any error or timeout. Hash echo comes with C-5 (wave 2).
- **Budget vs MemoryMax:** config-check rule assigned to deploy (budget + staging ≤ MemoryMax − 256 MiB).
- **Info (seal failure loses parts):** the sealer keeps the parts if no byte was handed over, where that is simple; otherwise documented.

---

## Re-test (round 5, delta)

| Item | Value |
|---|---|
| Re-tested revision | Live tree, HEAD `35f851d` (on top of `d7931cf`); the working tree is clean for the sealer |
| Results | `cargo test -p candor-sealer --locked`: 81 pass, plus the hardening re-exec binary. `clippy --all-targets --all-features -D warnings`: clean. `lint-safefs.sh --include-tests`: 0 sealer hits. `lint-logging.sh`: ok. `cargo vet --locked`: **Vetting Succeeded** (SEA-30 exemptions, expiry 2027-03-30). One PoC ran in a scratch `git archive` copy, which has been removed |

### Status

| ID | Status | Evidence / note |
|---|---|---|
| SEA-29 | **Fixed as dispositioned**; residual → SEA-31 | Per-session quotas and stall handling, with the coordinator's questions answered:<br>• The first `PART_BEGIN` reserves a fixed quota (default 768 MiB; 5 drafts within 3,840 MiB). If no quota is free, the source gets the session-level `BUSY`. Inside its own quota a draft only ever sees `LIMIT` (`need > quota`), and that check depends only on the draft's own parts, so per-session answers do not depend on other sessions (`budget.rs::per_session_quotas_…`).<br>• Stall handling is in `reap_expired`, which runs every 10 s and uses `try_lock`. A part with no bytes for 120 s is aborted, and the quota is released **only if the draft then has no parts and no upload** (`release_quota_if_idle`).<br>• **Q: does a draft holding a quota without uploading release it at 120 s?** Only when it holds no completed part. A draft with one completed part, even a single byte, keeps its quota until the draft ends (20 min idle, renewed by `TOUCH`, up to 2 h absolute; PoC below)<br>• Declared-length enforcement is unchanged and correct |
| Env configuration | **OK** | `Sealer::new` reads `CANDOR_SEALER_MEMORY_BUDGET_MIB` / `…_SESSION_UPLOAD_MIB`. Parsing is strict: digits only, at most 6 characters, 1..=262,144 MiB, quota ≤ budget; any problem gives `StartError::Config` with no detail. Both variables are required without the dev override; with the override they are optional but validated. These are not secrets, so B3.5 does not apply. The value check against `MemoryMax` is deploy's config-check rule (assigned) |
| Hardening test `Command::new` | **Passes the lints** | `tests/hardening.rs` re-executes `current_exe()` with the two variables set. The file has a module-level `#![allow(clippy::disallowed_methods)]` with a `safefs-lint: allow(…)` marker, plus a per-line marker; clippy (workspace `disallowed-methods` lists `Command::new`) and lint-safefs are both clean. It is test-only, and no `Command` appears in `src` |
| Ack binding (Low) | **Fixed** | `handover::{send, await_ack_within}` are now `pub(crate)`. The only public path is `StoreConnection::hand_over`, which drops (closes) the socket on any send, acknowledgement or timeout error, and a closed connection refuses all further hand-overs. A late `0x01` therefore cannot be credited to a later bundle. The hash echo is wave 2 (C-5) |
| Outage keeps parts (Info) | **Fixed** | `seal_blocking` checks `sink.is_available()` before the parts are taken. A known-down store gives the uniform `INTERNAL` and the parts are kept (`budget.rs::known_store_outage_keeps_the_attachments`). A store that fails after the check still loses the parts (documented) |
| SEA-30 | **Accepted** (lead) | Vet passes; `ml-dsa` is in `crypto-set.txt` for the release gate |

### Cross-source leak assessment (SEA-29 design)

- **Inside a quota:** none. `LIMIT`/`Part` depend only on the draft's own declared and staged sizes, and the timing is unchanged (no shared lock beyond the budget mutex, which is taken only on admission).
- **Admission:** by design (lead, ADR-038), a `BUSY` on a draft's first `PART_BEGIN` reveals that all `budget/quota` slots (5 by default) are held. A prober who holds `slots − 1` quotas and polls admission learns *when* another draft releases its quota. A release happens when the victim's draft ends (submit, abort, zeroize, expiry) or at a stall abort (10 s reaper granularity). That is a submission-time signal about an otherwise unknown source, at minute resolution, and it is more useful in combination with network-level observation. With 5 slots this is far from the "≥ 10× design peak" sizing of ADR-038(5).
- **Cheap exhaustion:** confirmed below.

### New finding (round 5)

**AUD-RM2-SEA-31 — A few tiny uploads hold every upload slot for up to 2 h; admission polling reveals other drafts' end times (Medium).**

PoC (`r5_tiny_parts_hold_quota_until_draft_end`, scratch only, paused clock): budget = 2 × quota. Two sessions each complete a 1-byte part, then `TOUCH` every 10 min. After 60 min a third source's `PART_BEGIN` still returns `BUSY`, with `memory_reserved = 16 MiB`. The 120 s stall abort does not help, because the parts are complete.
- **Cost of the attack:** in the default configuration, 5 sessions (session-open PoW) and 5 one-byte uploads deny attachment uploads to every other source for 2 h, renewable with new sessions.
- **Same mechanism as an oracle:** it provides the admission-timing oracle described above.

Fix options (lead's choice):
- Size the quota from the bytes actually staged: reserve on demand per part, so a 1-byte draft holds about 1 byte plus the bundle minimum. Keep the fixed quota only as a per-draft upper bound, with admission BUSY only when real reserved bytes exceed the budget.
- Or raise the slot count (`budget/quota`) to at least 10× the design peak of concurrent uploading drafts.
- Or release a draft's quota after the idle timeout of *upload* activity even when it holds parts, re-admitting at seal (sealing needs no reservation; SEA-26).

Regression: the PoC (a third source is admitted while two 1-byte drafts stay alive). Alternatively, the lead may accept this residual in writing, with an expiry, as part of the ADR-038 capacity-revealing decision.

### Gate (round 5)

| Severity | Open |
|---|---|
| Critical / High | 0 / 0 |
| Medium | 1 (SEA-31). SEA-30 is accepted |
| Low / Info | SEA-17 (workspace); deploy config-check rule (assigned); C-5 hash echo (wave 2); the post-check store failure losing parts is documented |

**Gate: FAIL 2026-10-01 35f851d**: SEA-31 (Medium) needs a fix or the lead's written acceptance with an expiry. Everything else in scope is fixed or accepted. With SEA-31 fixed or accepted, the sealer gate is **PASS**.

---

## Re-test (round 6, delta: SEA-31)

| Item | Value |
|---|---|
| Re-tested revision | Live tree, HEAD `bed0377` (on top of `acf9721`); the working tree is clean for the sealer |
| Results | `cargo test -p candor-sealer --locked`: 81 pass, 0 fail. `clippy --all-targets --all-features -D warnings`: clean. lint-safefs (with tests): 0 sealer hits. PoCs ran in a scratch `git archive` copy, which has been removed |

### SEA-31 verification

The design is as stated. The budget is split by `guaranteed_permille` (500) into `upload_slots` (64) guaranteed slices of 30 MiB at the default 3,840 MiB budget, plus a shared pool of 1,920 MiB. Within its slice a draft only ever gets `LIMIT`. Above the slice, the draft draws from the shared pool, up to `per_session_upload_bytes`, and gets the uniform `BUSY` if the pool is exhausted. `rebalance` shrinks or releases both grants on drop, abort, the 120 s stall and draft end. A slice below 1 MiB, or any invalid `CANDOR_SEALER_UPLOAD_SLOTS`, is refused at start-up.

PoC results at production sizes (budget 3,840 MiB, cap 768 MiB, 64 slots, `max_sessions` 64, paused clock, 60 min of `TOUCH`; the probe is a new session sending `PART_BEGIN` of 10 MiB, which fits within the slice):

| 1-byte holders | Probe result |
|---|---|
| 5 | `Part` (admitted) |
| 10 | `Part` |
| 63 | `Part` |
| 64 | `SESSION_OPEN` → `BUSY` (the session table is full; that cap is 07 §11, not a slot effect) |

- **Within-slice responses do not depend on other drafts.** The same 10 MiB probe returns `Part` on an idle sealer and while three drafts hold 2.0 GiB of the shared pool (a fourth 300 MiB declaration got `BUSY` at that moment).
- **The pool recovers.** After one large part is dropped, the fourth 300 MiB declaration is admitted. After 121 s without bytes, the stall reap returns the reservation to 0.

**Status: SEA-31 Fixed.** The shared-pool `BUSY` reveals only aggregate large-upload pressure and is accepted by the lead as a Low residual. Exhausting it costs real bytes, since declared-but-unsent parts are reaped at 120 s.

### Design peak and the right slot default (ADR-038(5), PERF-019)

Spec 34 §3.1 gives concurrent source sessions at burst as 50 for the first population column and 500 for the second, with 20 % of envelopes carrying attachments. Applying the 10× rule:
- **Sessions:** ≥ 500 for the first column and ≥ 5,000 for the second.
- **Uploading drafts:** ≥ 100 and ≥ 1,000 respectively.

Because each session holds at most one slot, slot `BUSY` is unreachable whenever `upload_slots ≥ max_sessions`. **The right default is `upload_slots = max_sessions`, enforced as `upload_slots ≥ max_sessions` at start-up**, so that no draft can ever be refused a slice. Today that is 64, so the 64 default is correct for the current `max_sessions`. The code does not enforce the relation, though: `CANDOR_SEALER_UPLOAD_SLOTS=8` with 64 sessions would bring back the per-draft admission oracle.

The session cap itself is the remaining problem. 07 §11 sets "Sealer sessions 64", which is only about 1.3× the 34 §3.1 burst of 50. Session `BUSY` therefore triggers far below 10× peak and is itself an activity oracle, as the 64-holder row shows. Meeting PERF-019 means `max_sessions` ≥ 500 (first column), with `upload_slots` set to match. At the default budget that gives 1,920 MiB / 500 ≈ 3.8 MiB slices, which passes the 1 MiB floor. The second column (5,000 sessions) needs a budget of at least about 10 GiB, or a smaller guaranteed share; the start-up check already refuses smaller slices.

### New findings (round 6)

**AUD-RM2-SEA-32 — `upload_slots < max_sessions` is accepted (Low).** `Sealer::new` checks only `slots ≥ 1` and `slice ≥ 1 MiB`. A configuration with fewer slots than sessions recreates the slot-admission `BUSY` that SEA-31 removed. Fix: require `upload_slots ≥ max_sessions` (`StartError::Config`), and add the same rule to deploy's config-check.

**AUD-RM2-SEA-33 — Sealer session cap of 64 conflicts with the 10× design-peak rule (Info, spec).** 07 §11 (64) contradicts 34 §3.1 / PERF-019 / ADR-038(5) (≥ 500 for the first population column), and session `BUSY` is reachable at about 1.3× peak. Flag for the spec owners. Raising `max_sessions` is a sizing change only, and slots and budget follow from the rule above.

### Gate (round 6)

| Severity | Open |
|---|---|
| Critical / High / Medium | 0 / 0 / 0 |
| Low | SEA-32; shared-pool aggregate-pressure residual (accepted by the lead) |
| Info | SEA-33 (spec), SEA-17 (workspace), C-5 hash echo (wave 2), deploy config-check rule (assigned) |

**Gate: PASS 2026-10-01 bed0377**: there are no open Critical, High or Medium findings, and the Lows are tracked. SEA-30 and the residuals listed under round 5 remain accepted as recorded.

---

## Re-test (round 7, delta: ADR-056 / SEA-32, SEA-33)

| Item | Value |
|---|---|
| Re-tested revision | HEAD `3f41a3a`; the working tree is clean for the sealer |
| Results | `cargo test -p candor-sealer --locked`: 84 pass, 0 fail (scratch target directory, removed afterwards) |

| Claim | Verdict |
|---|---|
| `CANDOR_SEALER_MAX_SESSIONS` is parsed strictly and required in production | **Verified.** `parse_count` accepts digits only, at most 5 characters, 1..=65,536. With no dev override, a missing variable gives `StartError::Config`; with the override it is optional but still validated. Unit-tested with the same negative corpus as the slot variable |
| Defaults 512/512 | **Verified** (`Limits::default`) |
| Start-up refused when slots < sessions, or when the slice is < 1 MiB | **Verified.** `upload_slots < max_sessions` → `Config` (`budget.rs::startup_refused_when_slots_below_sessions`); the slice check is unchanged. Defaults give 1,920 MiB / 512 = 3.75 MiB slices |
| An idle session costs 6,616 B | **Verified as a shallow `size_of` figure** (`session_baseline_is_small` passes). Heap use of logged-in sessions is not included: source keys, prefs, and `seen_replies` up to 4,096 × 40 B. The worst case at 512 sessions is about 80 MiB, still inside the 2,560 MiB base. Info only |
| Argon2 is bounded by 4 permits + a 32-deep queue | **Verified.** `ArgonGate` is unchanged and independent of `max_sessions` |

**Argon2 queue at 512 sessions.** Raising the session cap adds no new signal. Argon2id concurrency is still 4 permits, 32 queued, 30 s wait, and the 34 §3.1 burst of 3,000 logins a day (about 0.035/s) keeps the queue empty at peak, so `BUSY` needs attack-level load (PERF-019 holds). Two signals remain, both covered elsewhere:
- **Queue-wait timing.** When ≥ 4 derivations run at once, a login waits measurably longer. The C-06 uniform 0–2 s delay and LT-7 cover this (34 F20).
- **New-account sealing shares the gate.** `SEAL_FINISH` for a new account can get `BUSY` under a login flood. It fails closed and the passphrase is kept.

Both are Info and already accounted for; there is no sealer finding.

SEA-32: **Fixed.** SEA-33: **Fixed** (ADR-056).

**Gate: PASS 2026-10-01 3f41a3a.**
