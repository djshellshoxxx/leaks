// SPDX-License-Identifier: AGPL-3.0-or-later
//! Store errors. Variants carry only static text: never values, identifiers,
//! SQL text or driver messages (a PostgreSQL error detail can echo row values such
//! as a `locator_hash`, so driver errors are reduced to a coarse class).

use core::fmt;

/// Intake Store error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StoreError {
    /// Uniform "does not exist / not in this batch" (08 §3.3).
    NotFound,
    /// Input violates a size, range or shape rule.
    InvalidInput(&'static str),
    /// The store has not been initialised with `init`.
    NotInitialized,
    /// `init` was called with a different tenant.
    TenantMismatch,
    /// An envelope with the same `header_sha256` is already stored.
    DuplicateEnvelope,
    /// A new account's `lookup_tag` already exists.
    AccountExists,
    /// The account's daily quota would be exceeded.
    QuotaExceeded,
    /// A relay request counter was not strictly increasing (07 §5.4 anti-replay).
    Replay,
    /// A Key Directory snapshot was older or smaller than the high-water mark, or
    /// not consistency-proven from it (ADR-036(6); BE-060).
    Rollback(&'static str),
    /// Conflicting state (e.g. the same snapshot version with a different body).
    Conflict(&'static str),
    /// A deletion list failed chain, signature, gap or fork verification.
    DeletionList(&'static str),
    /// A restore is pending: the newest verified deletion list must be applied
    /// before the store serves source requests (07 BE-074).
    RestorePending,
    /// Stored data or schema violates an invariant (fail closed).
    Integrity(&'static str),
    /// The OS CSPRNG failed (fail closed).
    Rng,
    /// The deletion-list signer failed.
    Signer,
    /// A bounded resource (published-set pages, reply backlog) is at capacity;
    /// the request is refused instead of growing memory (AUD-RM2-STO-07).
    Capacity,
    /// Database/driver failure; deliberately content-free.
    Backend,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("not found"),
            Self::InvalidInput(w) => write!(f, "invalid input: {w}"),
            Self::NotInitialized => f.write_str("store not initialised"),
            Self::TenantMismatch => f.write_str("tenant mismatch"),
            Self::DuplicateEnvelope => f.write_str("duplicate envelope"),
            Self::AccountExists => f.write_str("account exists"),
            Self::QuotaExceeded => f.write_str("quota exceeded"),
            Self::Replay => f.write_str("relay request counter replay"),
            Self::Rollback(w) => write!(f, "directory snapshot rejected: {w}"),
            Self::Conflict(w) => write!(f, "conflict: {w}"),
            Self::DeletionList(w) => write!(f, "deletion list rejected: {w}"),
            Self::RestorePending => f.write_str("restore pending"),
            Self::Integrity(w) => write!(f, "integrity failure: {w}"),
            Self::Rng => f.write_str("random number generator failure"),
            Self::Signer => f.write_str("signer failure"),
            Self::Capacity => f.write_str("capacity exhausted"),
            Self::Backend => f.write_str("storage backend failure"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Result alias.
pub type Result<T> = core::result::Result<T, StoreError>;
