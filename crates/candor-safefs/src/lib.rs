// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `candor-safefs` — the single audited safe-path API of Candor (ADR-027).
//!
//! Every filesystem write or read of an object whose existence is caused by
//! source, recipient or server input goes through this crate:
//!
//! * [`SafeRoot`] — a capability handle on one storage root (via `cap-std`,
//!   which uses `openat2(RESOLVE_BENEATH)` on Linux). Objects are named only
//!   by [`ObjectId`] (random 128-bit or keyed content hash); there is no API
//!   that accepts a `&str` or `Path` name. Writes are atomic
//!   (temp + fsync + no-replace rename + directory fsync); symlinks,
//!   hardlinks and special files are refused; timestamps are normalized to a
//!   caller-provided [`SlotTime`] (ADR-038(1), DB-028).
//! * [`DisplayName`] — metadata-only sanitized display strings that are never
//!   paths.
//! * [`archive`] — bounded zip / tar / tar.gz / gzip extraction into a
//!   [`SafeRoot`] (10 §10, FILE-019, FILE-020, ST-081).
//!
//! See `README.md` and `SPEC-NOTES.md` for the threat model and decisions.

#[cfg(not(unix))]
compile_error!("candor-safefs currently supports unix targets only (see SPEC-NOTES.md)");

pub mod archive;
mod display;
mod error;
mod id;
mod store;
mod time;

pub use display::{DisplayName, MAX_DISPLAY_NAME_BYTES};
pub use error::SafeFsError;
pub use id::{ContentKey, ObjectId};
pub use store::{ObjectReader, PendingObject, RootPolicy, SafeRoot};
pub use time::SlotTime;
