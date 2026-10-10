// SPDX-License-Identifier: AGPL-3.0-or-later
//! Errors. Variants carry only static text: never values, identifiers, SQL
//! text or driver messages (a PostgreSQL error detail can echo row values), so
//! an error can be logged as a typed event without leaking metadata.

use core::fmt;

/// Case DB error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DbError {
    /// Uniform "does not exist / not visible" (08 §3.4; IDOR-safe lookups).
    NotFound,
    /// Input violates a size, range or shape rule (checked before any bind).
    InvalidInput(&'static str),
    /// Optimistic-concurrency mismatch: the row's `version` moved (07 §5.5).
    VersionConflict,
    /// A row with the same key already exists.
    AlreadyExists,
    /// The tenant of the principal is not visible from this connection
    /// (unknown tenant, or RLS hides everything: fail closed).
    TenantUnknown,
    /// The tenant exists but is suspended; staff and relay principals refuse.
    TenantSuspended,
    /// The principal kind is not served by the pool's database role.
    PrincipalMismatch,
    /// A DB guard refused the write (append-only, immutable, chain, dual control).
    Guard(&'static str),
    /// Stored data, schema, roles or session settings violate an invariant
    /// (schema drift, privileged role, missing RLS): refuse to run.
    Integrity(&'static str),
    /// The OS CSPRNG failed (fail closed).
    Rng,
    /// Database/driver failure; deliberately content-free.
    Backend,
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("not found"),
            Self::InvalidInput(w) => write!(f, "invalid input: {w}"),
            Self::VersionConflict => f.write_str("version conflict"),
            Self::AlreadyExists => f.write_str("already exists"),
            Self::TenantUnknown => f.write_str("tenant not visible"),
            Self::TenantSuspended => f.write_str("tenant suspended"),
            Self::PrincipalMismatch => f.write_str("principal kind not served by this role"),
            Self::Guard(w) => write!(f, "database guard refused: {w}"),
            Self::Integrity(w) => write!(f, "integrity failure: {w}"),
            Self::Rng => f.write_str("random number generator failure"),
            Self::Backend => f.write_str("storage backend failure"),
        }
    }
}

impl std::error::Error for DbError {}

/// Result alias.
pub type Result<T> = core::result::Result<T, DbError>;

/// Reduce a driver error to a content-free class, translating the SQLSTATEs
/// of our guards (`P0003` append-only/immutable, `P0004` chain, `P0005`
/// version, `P0006` dual-control/catalog) and RLS/context refusals (`42501`).
pub(crate) fn db(e: sqlx::Error) -> DbError {
    if matches!(e, sqlx::Error::RowNotFound) {
        return DbError::NotFound;
    }
    let code = e
        .as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned());
    match code.as_deref() {
        Some("P0003") => DbError::Guard("append-only or immutable row"),
        Some("P0004") => DbError::Guard("chain discipline"),
        Some("P0005") => DbError::VersionConflict,
        Some("P0006") => DbError::Guard("dual control or catalog rule"),
        Some("23505") => DbError::AlreadyExists,
        Some("23503" | "23514") => DbError::InvalidInput("constraint"),
        Some("42501") => DbError::Integrity("context or privilege refused"),
        Some("22003") => DbError::InvalidInput("numeric overflow"),
        _ => DbError::Backend,
    }
}
