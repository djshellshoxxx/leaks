// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Error type. Messages are static and never contain key material, plaintext or
//! attacker-controlled bytes (CRYPTO-057).

use core::fmt;

/// All errors returned by `candor-core`.
///
/// Authentication failures are deliberately coarse (`Authentication`) so that
/// callers cannot build an oracle out of distinct failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The suite identifier is not a known Candor suite (§13.9).
    UnknownSuite,
    /// The suite is known but not implemented by this build (CANDOR-FIPS-1 for now).
    UnsupportedSuite,
    /// Input has the wrong length for the field or structure.
    Length,
    /// A structure failed validation (magic, version, type, reserved bits, …).
    Malformed(&'static str),
    /// A MAC, AEAD tag or HPKE open failed. No plaintext is released.
    Authentication,
    /// The padded length is not a legal bucket for the object type (§13.6).
    IllegalBucket,
    /// Content does not fit in the largest bucket for the object type.
    TooLarge,
    /// More recipients than slots (§13.2).
    TooManyRecipients,
    /// Recipient slot block verification failed (THR-046).
    SlotVerification,
    /// A STREAM was truncated, had trailing data or was used out of order (§13.3).
    Stream(&'static str),
    /// Public or private key bytes are invalid.
    InvalidKey,
    /// Signature verification failed.
    Signature,
    /// The operating-system CSPRNG failed (fail closed, §23.4).
    Rng,
    /// Password hashing (Argon2id) failed, e.g. memory could not be allocated.
    PasswordHash,
    /// A wordlist violates §11.1 (size, uniqueness, separators).
    InvalidWordlist,
    /// A start-up known-answer self-test failed (CRYPTO-034).
    SelfTest(&'static str),
    /// An internal invariant failed; the operation was aborted with no output.
    Internal,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnknownSuite => f.write_str("unknown suite identifier"),
            Error::UnsupportedSuite => f.write_str("suite not supported by this build"),
            Error::Length => f.write_str("invalid length"),
            Error::Malformed(what) => write!(f, "malformed input: {what}"),
            Error::Authentication => f.write_str("authentication failed"),
            Error::IllegalBucket => f.write_str("illegal padding bucket"),
            Error::TooLarge => f.write_str("content too large"),
            Error::TooManyRecipients => f.write_str("too many recipients"),
            Error::SlotVerification => f.write_str("recipient slot verification failed"),
            Error::Stream(what) => write!(f, "stream error: {what}"),
            Error::InvalidKey => f.write_str("invalid key"),
            Error::Signature => f.write_str("signature verification failed"),
            Error::Rng => f.write_str("random number generator failure"),
            Error::PasswordHash => f.write_str("password hashing failed"),
            Error::InvalidWordlist => f.write_str("invalid wordlist"),
            Error::SelfTest(what) => write!(f, "self-test failed: {what}"),
            Error::Internal => f.write_str("internal error"),
        }
    }
}

impl std::error::Error for Error {}

/// Result alias.
pub type Result<T> = core::result::Result<T, Error>;
