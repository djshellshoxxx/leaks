# candor-log

Privacy-preserving typed audit logging for Candor Community Edition
(AGPL-3.0-or-later). Implements ADR-016 and `specs/20-LOGGING-AUDITING.md`
(the spec's `candor-audit` crate), the ADR-037(3) "no COI reason codes"
rule, ADR-038(1) date-only import timing, ADR-046(11) staff-only exact
timestamps and the `24-LICENSING-BUSINESS-MODEL.md` §TEL metrics regime.

**Log staff actions richly, source activity never.**

## What is in the crate

| Module | Purpose | Spec |
|---|---|---|
| `event` | `AuditEvent`: one variant per catalog type (20 §5.1–§5.3, §5.5) with an allow-listed field schema | LOG-001, LOG-020, LOG-024 |
| `field`, `ids`, `codes` | sealed `AuditField` trait; pseudonymous IDs (`CaseRef`, `UserRef`, …) minted only from the CSPRNG and persisted as MAC-sealed `IdToken`s, randomized hiding value commitments (`Hash32::commit`), artefact-bound `Seq`/`SeqRange`/`CheckpointRoot`, bounded counters, `DayStamp`, closed code enums and compile-time-only numeric `Code<T>` registries. No type for IPs, UAs, filenames, sizes or source times exists, and no raw constructor lets one be laundered in | LOG-001, LOG-002, P-01..P-17 |
| `sensitive` | `Sensitive<T>`: no `Debug`/`Display`/`Serialize`/`AuditField`, zeroized on drop (the exposed `&T` is guarded by the output bans, not the type) | LOG-002 |
| `envelope` | 20 §4 envelope; timestamp policy (staff ms, import/system-actor CASE date-only, SYSTEM second, Z-INTAKE hour) | LOG-004, LOG-012, LOG-013, LOG-021 |
| `cbor` | hand-rolled deterministic CBOR (RFC 8949 §4.2.1) encoder + strict decoder | 20 §4 |
| `chain` | `AuditLog`: class-separated `sec`/`case`/`sys` streams plus date-only `case-slot`/`sys-slot` streams written only at import-slot boundaries in shuffled order, salted case-bound record commitments (per-case keys destroyed at disposal), `h_i = SHA-256("candor/v1/audit/chain\0" ‖ h_{i-1} ‖ c_i)`, RFC 6962 Merkle checkpoints on a fixed data-independent schedule (5 min / Z-INTAKE hourly; slot streams per import slot), Ed25519-signed (`CheckpointSigner`; TPM/HSM in production); heads published to a `WitnessSink` hourly / per slot; one primary commit-point sink, secondaries fed from an outbox | AUD-001, AUD-002, AUD-003 |
| `disposal` | dual-approved (two pinned approver keys) disposal and retention authorizations; the only way to write a tombstone | AUD-005, AUD-012 |
| `verify` | `verify_stream`: detects modification, deletion, reordering, non-canonical records, forged/missing checkpoints, truncation, witness rollback/fork, redaction stubs not bound to a checkpointed, dual-approved disposal tombstone of the same case, and pruned prefixes not bound to a checkpointed, dual-approved retention tombstone at least as old as the configured retention | AUD-004 |
| `retention` | §12 bounds; whole-interval deletion after a checkpointed tombstone in the pruned stream | AUD-005, AUD-011 |
| `sink` | `AuditSink` trait, `MemorySink` (+ per-case `RedactionPlan`, AUD-012), `JsonlFileSink` (over a caller-provided `JsonlTarget`; no path handling here, ADR-027), bounded JSONL reader with metadata cross-checks | — |
| `export` | `ScrubbedExport`: C-26 SIEM allow-list, HMAC actor pseudonyms, date-only staff times, daily batches, daily health bands, break-glass daily counts | AUD-010, LOG-022, TEL-018 |
| `metrics` | SOURCE-SENSITIVE counters (in-memory, monthly), k = 10 primary + complementary suppression audited by exact rational LP against an attacker who knows the suppression pattern, per-channel folding, release history persisted through a caller `ReleaseHistory` (differencing defence survives restarts), integer (branch-and-bound) disclosure audit, counts only (no magnitude statistics, AUD-RM1-LOG-18), M3 rounding | LOG-011, LOG-025, TEL-010/011/015/016/020 |
| `fuzz/` | cargo-fuzz targets: CBOR decode round-trip, checkpoint parse, JSONL read+verify, mutated signed stream (ST-051); seeds in `fuzz/seeds/` | ST-051 |
| `scripts/lint-logging.sh` | deny-free-text-logging gate over trust-path crates; exceptions in `scripts/lint-logging.allow` | LOG-001 |

## Usage

```rust
use candor_log::{AuditEvent, AuditLog, CheckpointPolicy, EventContext, SoftwareSigner, SystemClock};
use candor_log::codes::HostRole;
use candor_log::ids::{AuditIdKey, CaseRef, TenantRef, UserRef};

let ids = AuditIdKey::new(deployment_key);          // token MAC key
let case = CaseRef::generate()?;                    // at case creation
let token = case.seal(&ids);                        // stored by the case service
let case = CaseRef::unseal(&ids, &token).ok_or(Bad)?; // later
let mut log = AuditLog::new(tenant, HostRole::Core, signer, SystemClock, CheckpointPolicy::DEFAULT);
log.set_primary_sink(Box::new(durable_sink));         // commit point
log.set_case_keys(Box::new(case_key_store));          // per-case redaction keys
log.set_approver_keys(pinned_disposal_approvers);     // tombstones (dual control)
log.set_witness(Box::new(witness));                   // head feed (AUD-003)
log.emit(EventContext::staff(user), AuditEvent::CaseOpened { case })?;
log.tick()?;                                          // at least every 5 minutes
```

There is no way to log a string: payload fields are sealed types, events have
no message field, identifiers and codes have no raw constructors, and the
workspace clippy.toml bans every free-text output path (see `tests/ui/*.rs`,
`tests/not_loggable.rs`).

## Checks

```
cargo fmt --all
cargo clippy -p candor-log --all-targets -- -D warnings
cargo test -p candor-log
crates/candor-log/scripts/lint-logging.sh            # workspace gate (also in CI: repo-lints)
```

See `SPEC-NOTES.md` for implementation decisions and spec feedback.
