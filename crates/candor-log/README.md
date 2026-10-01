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
| `field`, `ids`, `codes` | sealed `AuditField` trait; pseudonymous IDs (`CaseRef`, `UserRef`, …), hashes, `DayStamp`, closed code enums and numeric `Code<T>` registries. No type for IPs, UAs, filenames, sizes or source times exists | LOG-001, LOG-002, P-01..P-17 |
| `sensitive` | `Sensitive<T>`: no `Debug`/`Display`/`Serialize`/`AuditField`, zeroized on drop | LOG-002 |
| `envelope` | 20 §4 envelope; timestamp policy (staff ms, import/system-actor CASE date-only, SYSTEM second, Z-INTAKE hour) | LOG-004, LOG-012, LOG-013, LOG-021 |
| `cbor` | hand-rolled deterministic CBOR (RFC 8949 §4.2.1) encoder + strict decoder | 20 §4 |
| `chain` | `AuditLog`: class-separated `sec`/`case`/`sys` streams, `h_i = SHA-256("candor/v1/audit/chain" ‖ h_{i-1} ‖ bytes_i)`, RFC 6962 Merkle checkpoints every ≤1000 events / ≤5 min, Ed25519-signed (`CheckpointSigner`; TPM/HSM in production) | AUD-001, AUD-002 |
| `verify` | `verify_stream`: detects modification, deletion, reordering, non-canonical records, forged/missing checkpoints, truncation, witness rollback/fork | AUD-004 |
| `retention` | §12 bounds; whole-interval deletion after a tombstone; per-case redaction stubs | AUD-005, AUD-011, AUD-012 |
| `sink` | `AuditSink` trait, `MemorySink`, `JsonlFileSink` (over a caller-provided `JsonlTarget`; no path handling here, ADR-027), JSONL reader | — |
| `export` | `ScrubbedExport`: C-26 SIEM allow-list, HMAC actor pseudonyms, date-only staff times, daily batches, daily health bands, break-glass daily counts | AUD-010, LOG-022, TEL-018 |
| `metrics` | SOURCE-SENSITIVE counters (in-memory, monthly), k = 10 primary + complementary suppression, per-channel folding, cross-report differencing audit, magnitude rules, M3 rounding | LOG-011, LOG-025, TEL-010/011/015/016/020 |
| `scripts/lint-logging.sh` | deny-free-text-logging gate over trust-path crates; exceptions in `scripts/lint-logging.allow` | LOG-001 |

## Usage

```rust
use candor_log::{AuditEvent, AuditLog, CheckpointPolicy, EventContext, SoftwareSigner, SystemClock};
use candor_log::codes::HostRole;
use candor_log::ids::{CaseRef, TenantRef, UserRef};
use candor_log::sink::MemorySink;

let mut log = AuditLog::new(tenant, HostRole::Core, signer, SystemClock, CheckpointPolicy::DEFAULT);
log.add_sink(Box::new(MemorySink::new()));
log.emit(EventContext::staff(user), AuditEvent::CaseOpened { case })?;
```

There is no way to log a string: payload fields are sealed types, events have
no message field, and `Sensitive<T>` cannot be formatted (see
`tests/ui/*.rs`, `tests/not_loggable.rs`).

## Checks

```
cargo fmt --all
cargo clippy -p candor-log --all-targets -- -D warnings
cargo test -p candor-log
crates/candor-log/scripts/lint-logging.sh            # workspace gate
```

See `SPEC-NOTES.md` for implementation decisions and spec feedback.
