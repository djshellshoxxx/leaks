// SPDX-License-Identifier: AGPL-3.0-or-later
//! `candor-sealer` — the Intake Sealer (component C-07).
//!
//! The sealer is the isolated, memory-locked, non-dumpable process that holds
//! Tier W plaintext (ADR-004, ADR-034): drafts live only in its RAM, attachment
//! parts are staged only as ciphertext under the per-session key K36, the
//! recipient set is fixed and the content keys are sealed only at Submit, and
//! source passphrases exist only transiently in its memory.
//!
//! * [`proto`] — the sealer IPC protocol (07 §5.2) owned by this crate. It needs
//!   only `zeroize` and is usable by `candor-web` without the `server` feature.
//! * `server` (feature `server`, default) — the sealer itself: Unix-socket
//!   listener, session table, Argon2id gate, sealing, chaff, process hardening.
//!
//! `unsafe` is forbidden (workspace lint). Nothing in this crate logs, prints or
//! writes plaintext to disk.

pub mod proto;

#[cfg(feature = "server")]
pub mod server;
