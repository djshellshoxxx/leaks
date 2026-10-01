// SPDX-License-Identifier: AGPL-3.0-or-later
//! # candor-log
//!
//! Privacy-preserving typed audit logging for Candor (ADR-016,
//! `specs/20-LOGGING-AUDITING.md`). The specification calls this crate
//! `candor-audit`; see SPEC-NOTES.md.
//!
//! * [`AuditEvent`]: one enum variant per catalog type with an allow-listed
//!   field schema; fields are sealed [`AuditField`] types only (no `String`,
//!   no IP/UA/filename/size/source-time types).
//! * [`AuditLog`]: class-separated (`sec`/`case`/`sys`) hash-chained streams
//!   with timestamp policy enforcement and Ed25519-signed RFC 6962
//!   checkpoints; [`verify::verify_stream`] detects deletion, reordering,
//!   modification, truncation and rollback.
//! * [`sink`]: sink trait, in-memory store, JSON-lines file sink.
//! * [`export::ScrubbedExport`]: SIEM allow-list (20 §13, C-26).
//! * [`metrics`]: SOURCE-SENSITIVE counters released only under 24 §TEL
//!   (k = 10, monthly, complementary suppression, magnitude rules).
//! * [`diag!`]: restricted developer diagnostics (static message + closed
//!   codes only, 20 §7); [`schema`]: the `audit/schema.yaml` registry
//!   (LOG-014).

pub mod cbor;
pub mod chain;
pub mod codes;
pub mod diag;
pub mod envelope;
pub mod event;
pub mod export;
pub mod field;
pub mod ids;
pub mod metrics;
pub mod retention;
pub mod schema;
pub mod sensitive;
pub mod sink;
pub mod verify;

pub use chain::{
    AuditClock, AuditLog, CheckpointPolicy, CheckpointSigner, ClockReading, CommittedRecord,
    Emitted, LogError, SignedCheckpoint, SoftwareSigner, SystemClock,
};
pub use envelope::{Actor, EventContext};
pub use event::{AuditEvent, CATALOG, EventClass};
pub use field::AuditField;
