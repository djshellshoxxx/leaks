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
    AUD-012 require the count in the tombstone).
12. **`audit.retention_tombstone`** (new name; 20 §12/AUD-005 require a
    tombstone event but name none): SECURITY class, payload `stream`,
    `seq_range`, `last_deleted_checkpoint_root`. Always written to `sec`, also
    when the `sys` stream is pruned.
13. **`audit.read`** (20 §9) is included in the catalog although §5.1 does not
    list it.
14. **Checkpoints.** Body: tenant, stream, first/last seq, chain head, RFC 6962
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
17. **Per-case redaction (AUD-012)** replaces events with stubs
    `{seq, prev, leaf, hash}`; the verifier walks stubs by their stored hash
    (checked against `prev` continuity, the next record and the checkpoint
    Merkle root/chain head).
18. **Retention.** Whole intervals only (plan = latest checkpoint signed before
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
20. **SIEM export (C-26).** Pseudonym = `HMAC-SHA-256(K_siem,
    "candor/v1/siem/actor" ‖ UserRef)[..8]`. `date` fields follow the
    configured precision (Date default / Hour ADVANCED / Exact DANGEROUS);
    `ts` fields (cfg, integrity alarms) are hour-truncated unless Exact.
    HIGH/GOV: Exact refused and alarms are also batched daily. `sys.*` export
    only as a daily worst-status band per service (`sys.service_crashed` →
    DEGRADED); source-load-derived health checks, capacity and relay events
    are never exported. `secret.placement_violation` exports `secret_kind` as
    `check_code`. Break-glass: daily count per (type, reason_code).
21. **§TEL suppression algorithm.** k = 10, configurable upward only. Primary:
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
22. **Differencing defence.** `PeriodRegistry` refuses open periods
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
25. **Magnitude statistics.** median/percentile (nearest rank)/mean only for
    n ≥ k; durations rounded to whole weeks (half up); ratios (per-mille)
    only for denominator ≥ k and numerator ∉ {0, denominator}.
26. **Lint.** All `crates/*` are trust-path unless allow-listed (with a
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

`audit/schema.yaml` registry + build-script generation and its CI drift check
(LOG-014; the `catalog!` macro is the current single source), `diag!`
macro, Desk-signed events (AUD-013), TPM/HSM signers, witness service,
small-program yearly coarsening (GOV-013; the registry is keyed by month),
DB storage/grants (AUD-005 SQL side), anomaly detection (AUD-008).

## Dependencies

| Crate | Version | Why |
|---|---|---|
| `sha2` | =0.11.0 | SHA-256 for chain, Merkle, checkpoint and session hashes (workspace pin) |
| `ed25519-dalek` | =3.0.0 | Ed25519 checkpoint signatures/verification (workspace pin) |
| `hmac` | =0.13.0 | HMAC-SHA-256 SIEM actor pseudonyms (20 §13) |
| `zeroize` | =1.8.2 | zeroize secrets (salts, SIEM key, `Sensitive<T>`, signer seed) |
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
