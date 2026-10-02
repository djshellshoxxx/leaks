// SPDX-License-Identifier: AGPL-3.0-or-later
//! Independent day clock (04 §12.1 step 3, ADR-036(6), 07 BE-031).
//!
//! The sealer reads wall-clock time only as a UTC **day** through this trait. The
//! integrator's implementation performs the independent-time check of 16 §14.3
//! (Tor consensus `valid-after` floor and ceiling, Roughtime median) and returns
//! an error when it fails; the sealer then fails closed. Timers (session expiry,
//! chaff) use the monotonic clock only.

/// The independent-time check failed; intake must fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockError;

impl core::fmt::Display for ClockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("independent time check failed")
    }
}

impl std::error::Error for ClockError {}

/// Source of `today` (UTC day number since 1970-01-01).
pub trait Clock: Send + Sync {
    /// Today's UTC day, or an error if the independent-time check fails.
    fn today(&self) -> Result<u32, ClockError>;
}
