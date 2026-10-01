# candor-log — spec notes

Sources: `DECISIONS.md` ADR-016, ADR-037(3), ADR-038, ADR-046(5)/(11);
`20-LOGGING-AUDITING.md` (all); `09-DATABASE.md` §8 L3 / `audit_event`;
`24-LICENSING-BUSINESS-MODEL.md` §9 (§TEL).

## Implementation decisions

1. **Crate name.** 20 §7 names the crate `candor-audit`; the build assignment
   names it `candor-log`. API shape (`emit(AuditEvent)`, newtypes, closed
   enums) follows 20 §7.
2. **Chain formula.** 20 §8 says `prev = SHA-256(canonical CBOR of previous
   event)`. Implemented the assignment's domain-separated chain
   `h_i = SHA-256("candor/v1/audit/chain" ‖ h_{i-1} ‖ canonical_bytes(event_i))`
   with `h_{-1} = SHA-256("candor/v1/audit/genesis" ‖ tenant ‖ stream_byte)`;
   the envelope field `prev` carries `h_{i-1}`. Strictly stronger (chained,
   domain-separated, stream/tenant-bound genesis).
3. **Canonical encoding: hand-rolled deterministic CBOR** (RFC 8949 §4.2.1
   core deterministic encoding: shortest heads, definite lengths, map keys
   sorted bytewise by encoding, no duplicates/tags/floats). `ciborium` was not
   used: its serde path does not sort map keys or reject non-canonical input.
   The strict decoder (depth ≤ 16, lengths checked before allocation) makes
   "canonical ⇔ decodes" testable (proptest + RFC 8949 App. A vectors).
4. **`ts` encoding.** Unsigned ms since epoch, already truncated: `DayDate` =
   midnight UTC (LOG-013 "zero time component"), SYSTEM = second, Z-INTAKE =
   hour, staff actions = ms.
5. **Timestamp policy details** (safest choices where 20 §4 is silent):
   SECURITY events with a system actor → second; CASE events with a system
   actor → date; import-related events (`case.imported`, `evidence.imported`,
   `case.envelope_rejected`) and `case.canary_escalated` → date even with a
   staff actor; `sys.relay_daily`, `sys.relay_slot_overrun` → date;
   `sys.health` from source-load-derived detectors (ABUSE_FLOOD,
   POW_PRESSURE, QUEUE_BACKLOG) → date (24 §9.4); on Z-INTAKE every
   non-date event is truncated to the hour (not only SYSTEM).
6. **Z-INTAKE emission set** (20 §3 "SECURITY events about administrative
   access"): `auth.login_*`, `auth.logout/session_*`, `authz.denied`,
   `secret.placement_violation`, `selftest.logging_violation`, `update.*`,
   `platform.mismatch`, plus SYSTEM except `sys.relay_*`. CASE events are
   refused (`EnvelopeError::NotAllowedOnHost`).
7. **Envelope `reason`** is the closed `ErrorReason` enum and only allowed
   with `outcome = ERROR`; type-specific reasons live in payloads. Staff-only
   envelope fields (`actor_person`, `session`, `device`) are refused for
   system actors. Optional fields are omitted, not `null`.
8. **`authz.denied`** carries no resource ID at all (20 §5.1 allows one "only
   if the actor already has metadata access"; the check belongs to C-22 and
   omission is the safe default).
9. **Open code spaces** (action, resource_kind, config key, legal basis,
   operation class, …) are numeric registry codes `Code<Space>` (20 §5
   `Code<T>`); spaces the specs enumerate are closed enums.
10. **§5.5 types without listed fields** (`device.enrolled`,
    `breakglass.key_wrapped`, `evidence.export_approved`, …) have empty
    payloads, per "carry only the fields named in the table".
11. **`case.disposed`** additionally carries `removed_event_count` (20 §12 /
    AUD-012 require the count in the tombstone). *(Superseded by round 2: the
    payload is the private `CaseDisposal` record, see "round 2" below.)*
12. **`audit.retention_tombstone`** (new name; 20 §12/AUD-005 require a
    tombstone event but name none): SECURITY class, payload `stream`,
    `seq_range`, `last_deleted_checkpoint_root`. *(Superseded: one tombstone
    type per pruned stream with a dual-approved `RetentionPrune` payload, see
    round 1 LOG-01 and round 2 LOG-16/20.)*
13. **`audit.read`** (20 §9) is included in the catalog although §5.1 does not
    list it.
14. **Checkpoints.** *(Superseded in part by "Fixes for AUD-RM1-LOG" below.)* Body: tenant, stream, first/last seq, chain head, RFC 6962
    root over leaves `SHA-256(0x00 ‖ canonical_bytes)`, previous checkpoint
    hash (genesis `SHA-256("candor/v1/audit/checkpoint-genesis" ‖ tenant ‖
    stream)`), `signed_at` (exact, allow-listed 09 L3 (e)), `clock_flagged`
    (AUD-015). Signature: Ed25519 (strict verify) over
    `"candor/v1/audit/checkpoint-sig" ‖ bytes`. Cadence configurable only
    stricter than 1000 events / 5 min. No checkpoint is produced when nothing
    is pending.
15. **Witness.** Protocol is open (OI-20-1); provisional cosignature message
    `"candor/v1/audit/witness-cosign" ‖ SHA-256("candor/v1/audit/checkpoint" ‖
    bytes)`. `verify_stream` takes the witness-held latest checkpoint and
    reports `ROLLBACK` on an older or forked head.
16. **Signer.** `CheckpointSigner` trait; `SoftwareSigner` (zeroized, no
    secret in `Debug`) is for tests/dev. TPM/HSM backends are out of scope;
    signer failure is an error, no fallback key (ADR-046(2)).
17. **Per-case redaction (AUD-012)** *(Superseded in part by "Fixes for AUD-RM1-LOG" below.)* replaces events with stubs
    `{seq, prev, leaf, hash}`; the verifier walks stubs by their stored hash
    (checked against `prev` continuity, the next record and the checkpoint
    Merkle root/chain head).
18. **Retention.** *(Superseded in part by "Fixes for AUD-RM1-LOG" below.)* Whole intervals only (plan = latest checkpoint signed before
    `now − retention`), refused without a matching committed tombstone;
    `verify_stream` accepts a pruned prefix only with
    `allow_pruned_prefix = true` and only when the first record directly
    follows a retained checkpoint.
19. **JSONL sink and ADR-027.** This crate does no path handling (the
    workspace safefs-lint forbids `std::fs` outside `candor-safefs`).
    `JsonlFileSink` writes through a caller-provided `JsonlTarget`
    (C-24 opens append-only 0600 files via `candor-safefs`/reviewed code and
    fsyncs per line). Lines contain only static names, integers and hex; the
    reader bounds line length (1 MiB) and denies unknown fields.
20. **SIEM export (C-26).** (Round 2: the date-only `case-slot` and
    `sys-slot` streams are never exported.) Pseudonym = `HMAC-SHA-256(K_siem,
    "candor/v1/siem/actor" ‖ UserRef)[..8]`. `date` fields follow the
    configured precision (Date default / Hour ADVANCED / Exact DANGEROUS);
    `ts` fields (cfg, integrity alarms) are hour-truncated unless Exact.
    HIGH/GOV: Exact refused and alarms are also batched daily. `sys.*` export
    only as a daily worst-status band per service (`sys.service_crashed` →
    DEGRADED); source-load-derived health checks, capacity and relay events
    are never exported. `secret.placement_violation` exports `secret_kind` as
    `check_code`. Break-glass: daily count per (type, reason_code).
21. **§TEL suppression algorithm.** *(Superseded in part by "Fixes for AUD-RM1-LOG" below.)* k = 10, configurable upward only. Primary:
    every cell < k (zeros included, displayed "0–9"). Complementary: any line
    with a published marginal whose suppressed cells are exactly one **or sum
    to < k** gets its next-smallest unsuppressed cell suppressed; if none is
    left, that marginal is withheld (withholding chosen over rounding to 5 —
    safer). Then an exact disclosure audit (rational Gaussian elimination
    over all facts published for the period + non-negativity bound
    propagation) checks that no suppressed cell, no micro-cell < k, no
    folded-channel micro-cell and no small line-sum of suppressed cells is
    derivable; on failure it escalates: withhold grand total → withhold all
    marginals → suppress the whole table. Arithmetic overflow fails closed.
22. **Differencing defence.** *(Superseded in part by "Fixes for AUD-RM1-LOG" below.)* `PeriodRegistry` refuses open periods
    (no month-to-date) and re-release of a report (frozen periods) and audits
    each new table jointly with all earlier tables of the same period. Tables
    must use consistent `MicroKey`s per underlying micro-cell.
23. **Per-channel rule.** "Cases" for the counter report = the `submissions`
    counter of the month. A channel is its own row only with ≥ 3 and a
    declared population ≥ 50; otherwise folded into its declared group (≥ 2
    channels, disjoint); a group with exactly one folded channel also folds
    its smallest shown channel; channels outside any group are refused.
24. **Counters.** Held per (channel, counter) for current and previous month
    only; a month is taken once after close (raw values leave memory); an
    increment for an older month is refused; an unreleased previous month is
    discarded at the next rollover (09 "current and previous month only").
25. **Magnitude statistics.** *(Removed entirely in round 2, AUD-RM1-LOG-18.)* median/percentile (nearest rank)/mean only for
    n ≥ k; durations rounded to whole weeks (half up); ratios (per-mille)
    only for denominator ≥ k and numerator ∉ {0, denominator}.
26. **Lint.** *(Superseded in part by "Fixes for AUD-RM1-LOG" below.)* All `crates/*` are trust-path unless allow-listed (with a
    reason) in `scripts/lint-logging.allow`; scans `src/` and `build.rs`
    (tests with `--include-tests`) for `println!`/`eprintln!`/`print!`/
    `eprint!`/`dbg!`, `log::`/`tracing::` macros and imports, and
    log/tracing dependencies. `clippy.toml` in this crate also sets
    `disallowed-macros`.

## Spec feedback / conflicts (not resolved here)

- **F-1 (P-16 vs 20 §5.2).** `case.identity_request_refused` lists refusal
  code `COI` together with `requester UserRef`, which associates a user
  identity with a COI situation on a specific case (P-16, ADR-037(3),
  LOG-020). Implemented **without** `COI` (codes: NO_LEGAL_BASIS,
  NOT_NECESSARY, SCOPE). Spec should drop or merge the code.
- **F-2 (retention defaults).** 20 §12: SECURITY 400 days, SYSTEM 30 days;
  09 `audit_event` row: "default SECURITY 7 years, … SYSTEM 90 days".
  Implemented 20 (09 defers to it).
- **F-3 (health band labels).** 20 §13 {OK, DEGRADED, DOWN} vs 24 §9.2
  {NORMAL, ELEVATED, UNDER_ATTACK}. SIEM export uses 20's labels.
- **F-4.** 20 §12 requires a retention tombstone event and §9 an
  `audit.read` event, neither is in the §5 catalog (added, see 12/13 above).
- **F-5.** The deletion of the most recent checkpoint(s) and unattested tail
  (≤ 5 min / 1000 events) is only detectable against a witness; 20 §8 already
  relies on the witness for truncation.

## Not implemented (out of this crate's scope)

Build-script generation of the enum *from* `audit/schema.yaml` (the
registry and its drift test exist, see "Schema registry and `diag!`"); the
global `tracing` subscriber that drops non-`candor-audit` events (no
`tracing` dependency here); Desk-signed events (AUD-013), TPM/HSM signers, witness service,
small-program yearly coarsening (GOV-013; the registry is keyed by month),
DB storage/grants (AUD-005 SQL side), anomaly detection (AUD-008).

## Schema registry and `diag!` (loose-ends pass)

**Implementation decision: schema registry (LOG-014).** `audit/schema.yaml`
lists every catalog event (type, class, stream, `ts` policy) and its
allow-listed fields with their Rust type and closed code set. It is rendered
deterministically by `schema::registry_yaml()` from `event::SCHEMA` (emitted
by the `catalog!` macro; codes via a hidden `AuditField::schema_codes()`
default overridden by `code_enum!` and `Option<T>`). `tests/schema_registry.rs`
fails on *any* byte difference in either direction and writes the expected
file to `$CARGO_TARGET_TMPDIR` for review; it also forbids COI codes
(LOG-020) and free-text/metadata field types (LOG-001). 20 §7 asks for a
build script that generates the enum from the YAML; this pass keeps the
`catalog!` macro as the generator and makes the registry an exact,
CI-enforced mirror. Drift protection is equivalent (neither can change
without the other in the same PR, so the `audit-schema` label/CODEOWNERS
rule on `audit/schema.yaml` gates every field change) while avoiding a
YAML parser in the build. Swapping the direction later is mechanical.

**Implementation decision: `diag!` (20 §7).** `diag!(Level, "literal", codes...)`:
the message must be a string literal of 1..=120 bytes of printable ASCII
(const-checked: no interpolation, no control characters, no log injection);
at most 4 codes, each a closed code enum or `Code<S>` (sealed `DiagCode`
trait; `String`, numbers, ids, paths are compile errors, `tests/ui/diag_*`).
Records carry no timestamp or runtime data, only the static call site.
Levels: `Error`, `Warn`, `Info`, `Trace` (named `Trace` so it never shadows
`fmt::Debug` in rustc diagnostics). With `debug_assertions` off in the
calling crate, `Info`/`Trace` are compiled out (the 20 §7
`release_max_level_warn` ceiling applied to `diag!` too: safest reading).
Delivery: one process-wide `DiagSink` set once (`set_sink`); without a sink
records are dropped; nothing writes to stdout/stderr/disk. `DiagRing` is a
bounded (≤ 4096 records) in-memory ring for the Z-RCP buffer. Z-INTAKE
callers must still not use `diag!` per request (20 §6.2); this is a usage
rule, not enforceable in the macro.

Tests: `diag::tests::*` (message check, release ceiling, bounds, ring),
`tests/diag.rs` (sink delivery, codes, compile-out; also run with
`--release`), `tests/ui/diag_*` (compile-fail), `tests/schema_registry.rs`
(LOG-014 drift, LOG-020, LOG-001; verified to fail on an injected `COI`).

### Security self-review (this pass)

Checked as an attacker: `diag!` cannot carry runtime text (literal-only,
const-validated ASCII, sealed code trait) so no filenames/IP/UA/bodies or
secrets can reach it; no timestamps (no source-time leak); bounded memory
(fixed-size record, clamped ring, poisoned mutex recovered without panic);
the sink is set-once, so a later component cannot redirect diagnostics.
The registry renderer only escapes compile-time constants; the drift test
writes only under cargo's test tmpdir. No new dependencies. Residual risk:
a static message could still be written to *describe* a sensitive fact
(e.g. "user exists"); review of `diag!` call sites remains necessary; the
module path/line in a record reveals code location only.

## Dependencies

| Crate | Version | Why |
|---|---|---|
| `sha2` | =0.11.0 | SHA-256 for chain, Merkle, checkpoint and session hashes (workspace pin) |
| `ed25519-dalek` | =3.0.0 | Ed25519 checkpoint signatures/verification (workspace pin) |
| `hmac` | =0.13.0 | HMAC-SHA-256 SIEM actor pseudonyms (20 §13), keyed audit identifiers/value hashes and per-case redaction salts |
| `zeroize` | =1.8.2 | zeroize secrets (salts, SIEM key, `Sensitive<T>`, signer seed, `AuditIdKey`, `CaseCommitKey`, commitment openings, session ids) |
| `getrandom` | =0.4.3 | OS CSPRNG (already in the workspace via candor-safefs): random-only identifiers, value-commitment openings, uniform slot shuffle (AUD-RM1-LOG-02/17) |
| `subtle` | =2.6.1 | constant-time comparison of identifier-token tags and commitment openings (workspace pin) |
| `serde` | =1.0.228 | `Deserialize` for the bounded JSONL reader |
| `serde_json` | =1.0.149 | JSONL parsing and SIEM JSON rendering |
| `proptest` (dev) | =1.11.0 | property tests (workspace pin) |
| `trybuild` (dev) | =1.0.116 | compile-fail tests (LOG-001/LOG-002) |

## Test map

- AUD-001/AUD-004 (`tests/chain.rs`, `tests/props.rs`): middle deletion,
  reordering, payload modification, last-record modification, truncation,
  head deletion, forged/tampered/dropped checkpoints, non-canonical record,
  cross-stream splice, witness rollback; proptest random tampering (bit
  flip, delete, swap, duplicate, truncate, drop checkpoint, foreign splice).
- AUD-002: checkpoint cadence by count and time. AUD-005/AUD-011:
  retention bounds, tombstone-gated interval deletion. AUD-012: redaction.
- LOG-001/LOG-002: `tests/not_loggable.rs` (compile-time not-impl
  assertions: `String`, `&str`, `IpAddr`, `SocketAddr`, `PathBuf`, `Vec<u8>`,
  `u64`, `usize`, `SystemTime`, `Sensitive<_>` ∉ `AuditField`;
  `Sensitive<_>` ∉ Debug/Display/Serialize) and `tests/ui/*.rs` (trybuild:
  IP string as `CaseRef`, free-text field, implementing sealed trait,
  formatting `Sensitive`); `tests/lint_logging.rs`.
- LOG-004/012/013/021, ADR-046(11): `timestamp_policy`, `intake_host_rules`,
  `envelope_rules`. LOG-020: `no_coi_reason_codes`, export replay.
- AUD-010/LOG-022/TEL-018: `tests/export.rs` full-catalog replay.
- 24 §9.6 `stats-inference`/TEL-010/011/015/016/020, LOG-011:
  `tests/suppression.rs` incl. differencing across reports, differencing via
  marginals, folded-channel subtraction, tumbling/frozen periods, and a
  512-case proptest with an independent brute-force completion attacker.
- 20 §4 canonical CBOR: RFC 8949 Appendix A vectors, strict-decoder negative
  tests, proptest determinism.

## Fixes for AUD-RM1-LOG (audit `process/audits/AUDIT-RM1-safefs-log.md`)

No new dependencies (fuzz crate: `libfuzzer-sys =0.4.10`, as candor-safefs).

| Finding | Fix (implementation decisions) | Regression test |
|---|---|---|
| LOG-01 (H) unbound redaction / prune | A stub is `{seq, commit, tombstone_seq}` and is accepted **only** in the CASE stream when the full record at `tombstone_seq` (> stub seq) is a `case.disposed` whose new field `redacted_set = SHA-256("candor/v1/audit/redaction-set\0" ‖ n ‖ (seq ‖ c_i)*)` and `removed_event_count` match exactly the stubs bound to it, and that tombstone is covered by a verified checkpoint (`UNBOUND_REDACTION` otherwise). Stub hash/leaf are recomputed from `prev` + `commit`, never trusted. Redaction goes through `MemoryStore::plan_case_redaction` → `RedactionPlan::tombstone` → `apply_case_redaction` (all-or-nothing). A pruned prefix needs `allow_pruned_prefix`, a non-empty anchor checkpoint ending at the first retained seq, and a checkpointed retention tombstone **in the same stream** (`audit.retention_tombstone` in `sec`, new `sys.retention_tombstone` in `sys`) naming that seq range end and the anchor's Merkle root, emitted at least the stream's minimum retention (90 / 7 days) after the anchor was signed (`UNBOUND_PRUNE`); CASE is never pruned; an empty store with attested records is truncation. `apply_interval_deletion` refuses until the tombstone is checkpointed. | `stub_in_security_stream_rejected` (audit PoC), `case_stub_without_matching_tombstone_rejected`, `case_disposal_redaction_verifies`, `retention_interval_deletion`, `premature_prune_rejected`, proptest `Tamper::Stub`, fuzz `fuzz_audit_log_verify` |
| LOG-02 (H) checkpoint timing | Fixed, data-independent schedule: one checkpoint per stream per slot boundary, **empty intervals included** (`[first_seq, end_seq)`, empty root `SHA-256("")`), `signed_at` = boundary (never a clock reading), no count trigger. SECURITY: 5 min (configurable shorter, must divide an hour), hourly on Z-INTAKE; CASE and SYSTEM (both carry date-only events: imports, envelope rejections, canary, relay, source-load health) once per UTC day at 00:00. A due slot is closed before the next record of the stream is appended, so no record is covered by a checkpoint dated before it; after downtime one checkpoint at the latest boundary. `checkpoint_now` removed. **Counts:** CASE/SYSTEM checkpoints reveal the per-day event count of the stream (staff + system events mixed) — the same granularity as the date-only records; SECURITY checkpoints reveal per-5-min counts of staff/security events, which are not source-caused. **Spec feedback (20 §8):** "every 5 min or 1,000 events" is replaced by the schedule above for CASE/SYSTEM; this weakens freshness (up to 24 h unattested tail for CASE) — accepted per lead decision. | `checkpoint_timing_independent_of_date_only_events` (failed on old code), `checkpoint_schedule` |
| LOG-03 (M) laundering constructors | `Code<S>` only via `Code::of::<N>()` (compile-time constant, `N ≤ S::MAX`, default 127). All opaque ids: raw `from_bytes` is `pub(crate)`; callers use `X::derive(&AuditIdKey, raw)` = `HMAC-SHA-256(key, "candor/v1/audit/id/<Type>" ‖ 0 ‖ raw)[..16]`. `Hash32::digest` removed; `Hash32/HashPrefix8::derive(&AuditIdKey, HashPurpose, data)` keyed and purpose-separated; `Hash32::checkpoint_root` only for a validly signed checkpoint. `Count` (≤ 10 000; internal for removed-event counts), `SmallCount` (≤ 100), `KeyGeneration` (≤ 65 535), `DurationMin` (≤ 1440), `AgeDays`, `ExitCode`, `SlotIndex` (≤ 95) have private fields + bounded `new`; `Seq`/`SeqRange` only from checkpoints / verification reports / failures (which are `#[non_exhaustive]`); `StaffTimer::after(&clock, minutes)` (no caller instant); `DayStamp` ≤ day 100 000; `Version` components ≤ 255. Residual: small bounded fields can still carry a few bits each — review of call sites remains. | `tests/ui/launder_raw_id.rs`, `launder_code_counter.rs` |
| LOG-04 (M) `diag!` internals | `DiagCodeValue` is opaque (private enum; only sealed `DiagCode` types create it). `DiagRecord::new` is `pub(crate)`. The macro defines a local `Site` type whose `MESSAGE`/`MODULE`/`LINE`/`LEVEL` are associated **constants**; `__private::emit::<S>` asserts the message at monomorphisation and again at run time — a runtime string (leaked `format!`) cannot be a `const`. | `tests/ui/diag_forged_internals.rs`, `tests/diag.rs` |
| LOG-05 (M) suppression audit | Audit is an exact rational two-phase simplex (Bland's rule; overflow ⇒ fail closed) over published cells/margins **plus attacker priors**: every primary-suppressed cell ∈ [0, k−1], every complementary cell ≥ k (worst case: the attacker knows which). Every protected quantity (primary cells, micro-cells < k, folded channels, small suppressed line/table sums) must keep a feasible range ≥ k−1 wide. Margins/grand totals < k are withheld. If the audit fails, extra complementary cells are added along published lines touching the failing cell, then grand total → all margins → whole table is withheld; the all-suppressed stage carries no priors (pattern is value-independent); if even that is unsafe with earlier releases, `DisclosureRisk`. Hidden figures display `"suppressed"` (never "0–9"). LP bounds are exact for 2-D tables with margins (totally unimodular); for exotic multi-table layouts the LP relaxation can be looser than an integer attacker — covered by the brute-force tests. | `primary_cell_not_narrowed_by_attacker_priors` (audit PoC), proptests `no_suppressed_cell_is_derivable`, `margins_and_differencing_across_releases_and_restarts` (attacker uses both releases' figures + priors across a restart) |
| LOG-06 (M) differencing persistence, magnitudes | `PeriodRegistry<H: ReleaseHistory>`: per-period state (reports, facts, priors, protections, magnitude populations) is canonical CBOR in a caller-provided durable store, loaded before and written before returning each release; load/decode/store errors ⇒ `ReleaseError::History` (fail closed). Magnitude statistics only via `release_magnitude` (n ≥ k; percentiles only p ∈ 10..=90; a population differing from an earlier one of the period by 1..k−1 members ⇒ suppressed) and `release_ratio` (num ≥ k and den − num ≥ k). Free functions are private. | `differencing_blocked_across_restart`, `magnitude_differencing_blocked`, `history_errors_fail_closed`, `magnitude_rules` |
| LOG-07 (M) multi-sink fork | Record + chain computed once; **primary** sink is the commit point (nothing committed, seq not consumed, if it fails; `NoPrimarySink` without one); secondaries get the identical items through per-sink ordered outboxes retried on each emit/tick (≤ 65 536 queued, then `desynced` until rebuilt from the primary); secondary failures never reach the caller (`Emitted.secondary_lag`, `secondary_status()`). A slot close that fails to sign aborts the emit **before** writing (no committed-but-`Err` record). | `failing_secondary_does_not_fork_chain`, `failing_primary_commits_nothing`, `signer_failure_writes_nothing` |
| LOG-08 (M) brute-forceable stubs | `c_i = SHA-256("candor/v1/audit/record-commit\0" ‖ salt_i ‖ bytes)`; leaf and chain are over `c_i`. Redactable CASE records (case-bearing, not `case.disposed`) get `salt_i = HMAC-SHA-256(K_case, "candor/v1/audit/redaction-salt" ‖ 0 ‖ tenant ‖ stream ‖ seq)` from a per-case `CaseCommitKey` (`CaseKeyStore`, missing key ⇒ `CaseKeyUnavailable`, fail closed); the salt is stored with the record (JSONL `salt`) and dropped with it; the caller destroys `K_case` at disposal. Salts never appear in `Debug`. Non-redactable records use an all-zero salt. | `redacted_stub_reveals_nothing_without_case_key`, `case_disposal_redaction_verifies` (key destroyed ⇒ further case events fail closed) |
| LOG-09 (M) logging lint | `disallowed-macros` (println/print/eprintln/eprint/dbg, log::*, tracing::*) and `disallowed-methods` (`std::io::stdout/stderr`) moved to the **workspace** `clippy.toml`; the crate-local `clippy.toml` (which shadowed the workspace file) is removed. `lint-logging.sh`: lexer-aware comment stripping with string-content masking (perl), alias macro calls (`lg::log!`), stdio handles, formatted panics, table-form/renamed deps via `cargo metadata`, fail-closed on tool errors; runs in CI (`repo-lints`). | `tests/lint_logging.rs` (5 audit bypass fixtures, 3 dependency forms, comment/string cases) |
| LOG-10 (M) fuzzing | `fuzz/`: `fuzz_cbor_decode` (accept ⇒ re-encodes identically), `fuzz_checkpoint_parse`, `fuzz_jsonl_read_verify`, `fuzz_audit_log_verify` (ST-051: mutations of a genuine signed stream incl. redaction must be rejected). Seeds in `fuzz/seeds/<target>/`. 40 s smoke runs: no crash. | — |
| LOG-11 (L) CBOR pre-allocation | Container pre-allocation capped at 64 elements. | existing decoder tests + fuzz |
| LOG-12 (I) labels/signer | All chain labels NUL-terminated (prefix-free); `CheckpointSigner::sign_checkpoint(bytes)` adds the context itself. | `chain::tests::labels_are_prefix_free` |
| LOG-13 (L) JSONL metadata | Reader cross-checks `seq`/`type` (`rec`) and `end_seq` (`cp`) against the CBOR (`MetadataMismatch`), rejects fields foreign to the line kind, caps lines per file (`MAX_LINES` = 4 Mi). Streaming verification not implemented (bounded by the caps) — residual. | `jsonl_round_trip` |
| LOG-14 (L) COI adjacency | Documented residual + spec feedback (20 §6.1 P-16): adjacency of `case.coi_tags_updated` and `case.member_removed` in the CASE stream can link a removal to COI. Decorrelation option available with the existing API: emit COI-caused membership changes with a **system** actor (CASE ⇒ date-only `ts`) in a once-daily batch mixed with other removals; a library batching helper is not added (low value vs. API surface). | — |
| LOG-15 (I) `Sensitive` docs | Module/README wording corrected: `expose()` returns a formattable `&T`; the output bans, not the type, stop it. | — |

### Security self-review (this pass)

Checked as an attacker: no raw-value constructor remains for any audit
field type outside the crate (ids/hashes keyed, codes const-only, counters
bounded, seq/ranges from artefacts); a stub can no longer stand in for any
record without a checkpoint-covered tombstone committing to it; checkpoint
times and existence no longer depend on events; redacted commitments need
the destroyed per-case key; sink faults cannot fork or duplicate; suppressed
cells survive margin arithmetic, cross-release differencing and restarts in
the tests' attacker model; release history and key-store failures fail
closed. Residuals: per-day (CASE/SYSTEM) and per-slot (SECURITY) event
counts are visible to the witness; bounded small fields can still carry a
few bits; LP relaxation vs. integer attacker for unusual table families;
secondary sinks may lag (reported, never silent); COI adjacency (LOG-14).

## Fixes for AUD-RM1-LOG round 2 (re-test of fc64069; lead decisions of 2026-10-01)

New fuzz-harness-only dependencies: `hmac =0.13.0`, `sha2 =0.11.0` in
`fuzz/Cargo.toml` (the harness re-implements the documented identifier-token
MAC under its own public test key to get reproducible fixtures/seeds).

| Finding | Fix (implementation decisions) | Regression test |
|---|---|---|
| LOG-02 (H) record-order channel | Two new **date-only streams**, `case-slot` and `sys-slot` (class-separated; own genesis, checkpoints, JSONL files). Every event whose envelope `ts` is date-only (imports, envelope rejection, canary, relay, source-load `sys.health`, CASE events by a system actor, `case.coi_tags_updated`) is routed there; no exact-time event ever is. Date-only events are **staged in memory and written only at the next import-slot boundary**, the slot's batch in uniformly random order (Fisher–Yates, rejection-sampled OS CSPRNG), `ts` = UTC date; then the slot stream is checkpointed with `signed_at` = boundary. Import slots: 15-min multiples of the UTC day, default 00/06/12/18 h (ADR-038(1) 4×/day; `CheckpointPolicy::with_import_slots`, HIGH/GOV e.g. `&[180]`); **00:00 is always a boundary** so a slot never spans two dates. With no date-only events left in CASE/SYS, their checkpoints return to the 5-minute schedule (hourly on Z-INTAKE; data-independent, empty intervals included). A flush that fails part-way keeps the rest of the already-shuffled batch queued and the slot open (no reshuffle, no early checkpoint); emissions to that stream fail closed until it succeeds. `emit` returns `Emitted { record: None }` for a staged event. **Residual:** staged events live in memory — a crash loses at most one slot's date-only events (the restart is visible in `sys.service_started`); a durable stage would need typed event decoding and reintroduce an arrival-ordered store. | `date_only_events_never_neighbour_exact_time_events` (no date-only record has an exact-time neighbour; nothing written before the boundary; permutation; order differs from arrival across runs), `checkpoint_timing_independent_of_date_only_events` (CASE/SYS checkpoints byte-identical with/without the import), `timestamp_policy`, `chain::tests::policy_bounds`, `shuffle_is_a_permutation_and_varies` |
| LOG-16 (H) forged `case.disposed` | (1) **Dual approval:** every tombstone carries two Ed25519 signatures by two *distinct pinned disposal-approver keys* (`ApproverKeys`: 2..=16 distinct keys, never the checkpoint key) over `"candor/v1/audit/disposal-auth\0" ‖ canonical request` (`disposal` module). Case request: `{kind, v, tenant, case, receipt_id, case_set: [n, H], slot_set: [n, H]}`. (2) **Construction only via the API:** tombstone payloads are the private-field types `CaseDisposal` / `RetentionPrune`; `AuditEvent::CaseDisposed { disposal }` cannot be built outside the crate; `emit` refuses every tombstone (`TombstoneViaApi`); `AuditLog::emit_case_disposal(ctx, &plan, &auth)` checks the authorization against the writer's pinned keys and the plan (case, both set commitments), requires a staff actor, refuses while records of the case are still staged, writes `case.disposed` (CASE) and stages `case.slot_disposed` (CASE-SLOT). `redaction_set_hash` and checkpoint-root helpers are crate-private; `Hash32::checkpoint_root` is gone. (3) **Verifier takes pinned keys:** `VerifyParams { key (checkpoint), approver_keys, .. }`; a checkpoint not signed by `key` or a tombstone without two valid approvals under distinct `approver_keys` fails (`BAD_SIGNATURE` / `UNBOUND_REDACTION` / `UNBOUND_PRUNE`), wherever it sits in the stream. (4) **Case binding (defence in depth):** `c_i = SHA-256("…/record-commit\0" ‖ tag ‖ inner_i)`, `tag = 0x01 ‖ CaseRef` for redactable records; a stub is `{seq, case, inner, tombstone_seq}` and must name the tombstone's case — so even a genuinely approved disposal of case Y cannot cover a record of case X (renaming the case breaks the chain). The verifier derives the tag from the record (`case` / `subject` payload field), proven equal to the writer's for every catalog type in every stream. (5) `RedactionPlan::build(&impl CaseRecordSource, case)` — any store can plan (LOG-23a). | `forged_disposal_tombstone_rejected` (round-2 PoC: (a) variant/`emit`, (b) insider-pinned approver keys ⇒ `UNBOUND_REDACTION` under the real pinned set, (c) approved disposal of another case cannot cover the victim), `tests/ui/forge_tombstone.rs`, `case_disposal_redaction_verifies` (both streams), `case_stub_without_matching_tombstone_rejected`, `chain::tests::case_tag_writer_and_verifier_agree`, fuzz `fuzz_audit_log_verify` (CASE and CASE-SLOT, stub naming arbitrary cases) |
| LOG-17 (M) laundering paths | **No constructor takes caller bytes.** Identifiers: `X::generate()` (OS CSPRNG) only; owners persist an `IdToken` = `id ‖ HMAC(K_audit_id, "candor/v1/audit/id-token/<Type>\0" ‖ id)[..16]` and load it with `X::unseal` (constant-time; wrong key/type/arbitrary bytes ⇒ `None`). `X::derive(&key, &[u8])` removed (no keyed pseudonym of addresses). Value hashes (`query_hash`, `old_value_hash`, `policy_hash`, `entry_hash`, `recipient_key_fingerprint`, `custody_mac`, `*_hash_prefix`): **randomized hiding commitments** `Hash32::commit(purpose, value)` / `HashPrefix8::commit` = `SHA-256("…/value-commit\0" ‖ label ‖ 0 ‖ r ‖ len ‖ value)` with an internal 256-bit `r` returned as an `Opening` (zeroized; `Opening::verifies` for auditors). The logged value is independent of the input for anyone without the opening — including the writer's key holder — so it cannot carry or be tested against an address; the caller cannot choose `r`. Session tags: `SessionTag::derive(&DaySalt, &StaffSessionId)` with a random, sealable `StaffSessionId`. Checkpoint-derived values: `Seq`, `SeqRange` and the new `CheckpointRoot` carry the checkpoint key they were derived under (`AuditLog::checkpoint_seq/range/root` verify the checkpoint under the writer's own key and tenant; `Seq::of_failure`/`SeqRange::within` take the verifier's key); `emit` refuses any event whose artefact fields were derived under another key (`ForeignArtefact`). `ConfigValue::Enum` takes a const `Code<ConfigEnumValue>`. **Residual:** a random field can be ground (k bits cost ~2^k calls); small bounded fields (dates ≤ day 100 000, versions, counts) carry a few bits (LOG-03 residual). | `checkpoint_values_cannot_be_laundered` (round-2 PoC: self-signed cp with IPv6 root / IPv4:port end_seq; values from a second writer; verification failure under another key), `tests/ui/launder_raw_id.rs` (`from_bytes`, `derive`, `digest`, `Hash32::derive`, `checkpoint_root`, `checkpoint_end`, `of_checkpoint`), `ids::tests::id_tokens_bind_key_and_type`, `value_commitments_hide_and_open`, `session_tag_rotates_with_salt`, `event::tests::origin_check_covers_artefact_fields` |
| LOG-18 (M) magnitude differencing | **Magnitude statistics removed**: `Magnitude`, `release_magnitude`, `release_ratio` and the mean/percentile/ratio helpers are gone; only k-thresholded counts (tables, `release_scalar`) are publishable. The release-history encoding is v2 without `magnitudes`; a v1 history is refused (`History`, fail closed). | `tests/ui/no_magnitude_api.rs`, `magnitude_era_history_is_refused` |
| LOG-19 (M) unattested CASE/SYS tail | Fixed by LOG-02 (CASE/SYS back to 5-minute checkpoints) plus a **witness feed**: `WitnessSink` trait, `AuditLog::set_witness`. Each stream publishes its head checkpoint at every witness tick — hourly for SECURITY/CASE/SYSTEM (first boundary of each hour), every import slot for `case-slot`/`sys-slot` — **empty ticks included**, so a silent witness means a missed tick (the witness must alarm on it). Only the newest head is queued per stream (it attests every earlier one), retried on every emit/tick; `witness_lag()` reports a backlog. The verifier, given the latest witnessed head (`trusted_latest`), rejects any truncation into it (`TRUNCATED`) or removal of it/rollback (`ROLLBACK`). **Residual ≤ one tick:** records after the last witnessed head (≤ 1 h exact-time, ≤ 1 slot date-only). | `witness_ticks_and_truncation_beyond_witnessed_head` (24 heads/day per exact-time stream, 4 per slot stream; truncation with and without dropping later checkpoints; queued head after witness outage) |
| LOG-20 (L) only minimum retention enforced | Retention tombstones are dual-approved standing authorizations `{kind: retention, tenant, stream, retention_days}` (`DisposalRequest::retention`, refused outside the 20 §12 bounds); the tombstone carries `retention_days` + approvals; `emit_retention_tombstone` refuses a plan younger than the authorized period (`TooEarly`) or an authorization for another stream/period (`Mismatch`). The verifier requires age ≥ `retention_days` and `retention_days` ≥ max(20 §12 minimum, `VerifyParams::min_retention_days`) — OVERSIGHT passes the configured policy. `DeletionPlan` fields are private; `apply_interval_deletion` finds the stored, checkpointed tombstone itself. `sys-slot` is pruned with SYSTEM retention (`sys.slot_retention_tombstone`, date-only). | `retention_interval_deletion` (90-day prune fails with `min_retention_days = 400`), `premature_prune_rejected` |
| LOG-21 (L) lint gaps | `lint-logging.sh`: `assert*!`/`debug_assert*!` with a formatted message (multi-line aware, perl pass over the masked source), `.expect(&format!(..))`/`expect(&<var>)`, `panic_any`/`resume_unwind`, `Command::new`/`process::Command`; test-only code is skipped precisely (`#[cfg(test)]` items, file-level `#![cfg(test)]`, files of `#[cfg(test)] mod x;` only when every declaration of `x` is cfg(test) and none uses `#[path]`) so production code cannot hide behind it. Workspace `clippy.toml` bans `std::panic::panic_any`, `resume_unwind`, `std::process::Command::new`. | `tests/lint_logging.rs` (7 round-2 fixtures incl. multi-line, test-only exemption and two abuse attempts) |
| LOG-22 (L) LP relaxation | The disclosure audit now computes the **integer** range of every protected quantity: exact rational simplex at the root, then depth-first branch and bound on fractional structural variables (bound constraints as single-cell priors, LP-bound pruning), failing closed past 4 096 branch nodes per audit (root solves do not count, so totally unimodular tables cost nothing extra). | `integer_attacker_narrower_than_lp_is_caught` (two odd cycles: LP 3, integer 2) and all existing suppression proptests |
| LOG-14 (L) COI adjacency | `case.coi_tags_updated` is date-only, so it lands in the shuffled `case-slot` stream; COI-caused membership changes are emitted with a system actor (date-only ⇒ `case-slot` as well). Neither is ever adjacent to the other in order. **Residual:** co-occurrence of both for the same case within one import slot window (the granularity imports already have); staff-made removals stay exact-time in CASE. Lead-auditor acceptance still required for that residual. | `timestamp_policy`, registry (`case.coi_tags_updated: case-slot, date_only`) |
| LOG-23 (I) | (a) `CaseRecordSource` + `RedactionPlan::build` (see LOG-16). (b) `diag::__private::emit` const- and run-time checks `MODULE` as a module path (`ident(::ident)*`, ≤ 200 bytes) and enforces the release ceiling itself from the site's `DEBUG_ASSERTIONS` constant (set by the macro from the calling crate's `cfg!(debug_assertions)`). A hand-written `Site` can still claim `DEBUG_ASSERTIONS = true` (Info, static data only). | `diag::tests::module_check`, `tests/ui/diag_forged_internals.rs` |

**Downstream (outside this crate, for the lead):** `candor-sealer` tests and
fuzz harness call the removed `TenantRef::derive(&AuditIdKey::new([3; 32]),
b"tenant")` (`tests/common/mod.rs`, `tests/hardening.rs`,
`fuzz/fuzz_targets/fuzz_sealer_ipc.rs`); replace with
`TenantRef::generate().unwrap()` (or `expect`) and drop the `AuditIdKey`
import. The sealer's production code (`EventContext`, `SysHealth`) is
unaffected; its `Readiness` health event stays exact-time in `sys`.

**Spec feedback (round 2):**

- **F-6 (20 §8 cadence).** Exact-time streams keep "every 5 min" (no count
  trigger, data-independent); date-only streams checkpoint at import-slot
  boundaries; witness publication is hourly / per slot with empty ticks.
  20 §4/§5 should name the slot streams and the staging rule.
- **F-7 (value hashes).** 20 §5 `*_hash` fields and 14 §10 `custody_mac`
  ("HMAC under case-derived key") are implemented as randomized hiding
  commitments whose opening stays with the producing component; a keyed,
  deterministic hash of caller data is a linkable pseudonym (P-01).
- **F-8 (tombstones).** New implementation-defined types
  `case.slot_disposed` and `sys.slot_retention_tombstone`; tombstone
  payloads are nested (`disposal` / `prune`) and carry two approver
  signatures; 20 §12 should require dual-approved disposal/retention
  authorization and name the approver key set (C-14).
- **F-9 (COI).** `case.coi_tags_updated` date-only (LOG-14).

### Security self-review (round 2)

Checked as an attacker with emit access and store write: no caller byte
string becomes an identifier, value hash, session tag, sequence number,
range or root; every tombstone needs two pinned approver signatures that the
verifier checks independently of the writer's configuration, and a stub must
name the tombstone's case, which its record commitment binds; date-only
records never sit next to exact-time ones and their stored order is random;
CASE/SYS checkpoints no longer change with date-only events; truncation
beyond the witnessed head is detected; magnitude statistics no longer exist;
the suppression audit reasons over integers and fails closed on budget;
RNG, key-store, sink, signer and history failures all fail closed (nothing
written). New secrets (`Opening`, `StaffSessionId`, staged case keys) are
zeroized and never printed; approval and token checks are constant-time or
strict Ed25519. Residuals: slot-stream checkpoints reveal the number of
date-only events per import slot (the schedule granularity ADR-038(1)
already exposes through commit/WAL times; never finer); staged date-only
events are lost on a crash (≤ one slot); random fields can be ground for a few bits; witness freshness
(≤ one tick) depends on the witness alarming on missed ticks; LOG-14
co-occurrence within a slot window; a hand-written diag `Site` can bypass
the release ceiling (static data only).
