// SPDX-License-Identifier: AGPL-3.0-or-later
//! Wrappers for data that must never reach any log (20 §7, LOG-002).
//!
//! [`Sensitive`] implements neither `Debug`, `Display`, `serde::Serialize`
//! nor [`crate::AuditField`], and zeroizes on drop. Trust-path crates wrap
//! source passphrases, lookup IDs, filenames, client addresses, user
//! agents and request bodies in it so that the wrapper itself cannot be
//! formatted, serialized or passed to the audit API (see `tests/ui/*.rs`
//! and `tests/not_loggable.rs`).
//!
//! Limitation (AUD-RM1-LOG-15): [`Sensitive::expose`] returns `&T`, and
//! *that* can be formatted (`format!("{}", s.expose())`). What stops the
//! exposed value from reaching an output is the workspace-wide ban on
//! free-text output (clippy `disallowed-macros`/`disallowed-methods` and
//! `lint-logging.sh`), not this type; call sites of `expose()` remain a
//! code-review item.

use zeroize::Zeroize;

/// A value that can be used but never printed, serialized or logged.
#[allow(missing_debug_implementations)] // deliberate: LOG-002
pub struct Sensitive<T: Zeroize>(T);

impl<T: Zeroize> Sensitive<T> {
    /// Wrap.
    pub fn new(v: T) -> Self {
        Self(v)
    }
    /// Borrow the value for processing (not for logging).
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> Drop for Sensitive<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Source passphrase.
pub type SourcePassphrase = Sensitive<String>;
/// Source lookup ID.
pub type LookupId = Sensitive<Vec<u8>>;
/// Uploaded filename.
pub type Filename = Sensitive<String>;
/// Textual client/relay address (P-01).
pub type IpAddrText = Sensitive<String>;
/// User-Agent or other client header (P-02).
pub type UserAgent = Sensitive<String>;
/// Request or response body (P-05).
pub type RequestBody = Sensitive<Vec<u8>>;
