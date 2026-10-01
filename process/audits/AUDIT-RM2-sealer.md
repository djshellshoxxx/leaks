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
