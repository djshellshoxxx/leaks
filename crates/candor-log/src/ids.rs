// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pseudonymous identifiers, hashes and coarse time types.
//!
//! Every type here is either an opaque random identifier (never derived
//! from source data), a hash/prefix of fixed width, or a time value whose
//! granularity is fixed by its type. There is deliberately **no** type for
//! IP addresses, ports, user agents, filenames, sizes or exact source-action
//! times (20 §6.1 P-01..P-17); see [`crate::sensitive`] for wrappers that
//! cannot reach any sink.

use core::fmt;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cbor::Value;

pub(crate) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let hi = HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0');
        let lo = HEX.get(usize::from(b & 0x0f)).copied().unwrap_or(b'0');
        s.push(char::from(hi));
        s.push(char::from(lo));
    }
    s
}

pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => c.checked_sub(b'0'),
            b'a'..=b'f' => c.checked_sub(b'a').and_then(|v| v.checked_add(10)),
            _ => None,
        }
    }
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks_exact(2) {
        if let [h, l] = pair {
            out.push((nib(*h)? << 4) | nib(*l)?);
        }
    }
    Some(out)
}

macro_rules! opaque_id {
    ($(#[$m:meta])* $name:ident, $len:expr) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Wrap raw identifier bytes (random IDs minted by the owning service).
            pub const fn from_bytes(b: [u8; $len]) -> Self {
                Self(b)
            }
            /// Raw bytes.
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), hex(&self.0))
            }
        }

        impl crate::field::sealed::Sealed for $name {}
        impl crate::field::AuditField for $name {
            fn to_value(&self) -> Value {
                Value::Bytes(self.0.to_vec())
            }
        }
    };
}

opaque_id!(
    /// Pseudonymous case ID (`CaseRef`).
    CaseRef, 16);
opaque_id!(
    /// Evidence ID (`EvidRef`, `evid_id`).
    EvidRef, 16);
opaque_id!(
    /// Staff user ID (`UserRef`). Never a source identifier.
    UserRef, 16);
opaque_id!(
    /// Person reference for dual-control accountability (`actor_person`).
    PersonRef, 16);
opaque_id!(
    /// Desk device key ID (staff). Not an OS/UA string.
    DeviceKeyId, 16);
opaque_id!(
    /// Tenant ID.
    TenantRef, 16);
opaque_id!(
    /// Channel ID (configuration object, not source-linked).
    ChannelId, 16);
opaque_id!(
    /// Export package ID.
    PackageId, 16);
opaque_id!(
    /// Transform ID.
    XformId, 16);
opaque_id!(
    /// Backup set ID.
    BackupId, 16);
opaque_id!(
    /// Disposal receipt ID.
    ReceiptId, 16);
opaque_id!(
    /// Pre-sharing review (PSR) ID.
    PsrId, 16);
opaque_id!(
    /// Legal hold reference.
    HoldRef, 16);
opaque_id!(
    /// SLA timer ID.
    TimerId, 16);
opaque_id!(
    /// Catalog report ID.
    ReportId, 16);
opaque_id!(
    /// Audit witness ID.
    WitnessId, 16);
opaque_id!(
    /// SHA-256 digest (entry hashes, policy hashes, roots, value hashes, fingerprints).
    Hash32, 32);
opaque_id!(
    /// 8-byte hash prefix (approval descriptor prefix, manifest hash prefix).
    HashPrefix8, 8);
opaque_id!(
    /// Salted, truncated (64-bit) staff session hash (20 §4, LOG-012).
    SessionTag, 8);

impl Hash32 {
    /// SHA-256 of `data`.
    pub fn digest(data: &[u8]) -> Self {
        Self(Sha256::digest(data).into())
    }
}

/// Per-day salt for [`SessionTag`] derivation. Secret; no `Debug`, zeroized.
#[allow(missing_debug_implementations)] // deliberate: secrets are never printed
pub struct DaySalt(Zeroizing<[u8; 32]>);

impl DaySalt {
    /// Wrap a salt (rotated every UTC day by the auth service).
    pub fn new(salt: [u8; 32]) -> Self {
        Self(Zeroizing::new(salt))
    }
}

impl SessionTag {
    /// `SHA-256("candor/v1/audit/session" ‖ day_salt ‖ session_id)[..8]`.
    /// The session ID is a staff session secret; it is consumed only here.
    pub fn derive(salt: &DaySalt, session_id: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(b"candor/v1/audit/session");
        h.update(salt.0.as_slice());
        h.update(session_id);
        let d: [u8; 32] = h.finalize().into();
        let mut out = [0u8; 8];
        for (o, i) in out.iter_mut().zip(d.iter()) {
            *o = *i;
        }
        Self(out)
    }
}

/// Milliseconds per day.
pub const MS_PER_DAY: u64 = 86_400_000;
/// Milliseconds per hour.
pub const MS_PER_HOUR: u64 = 3_600_000;
/// Milliseconds per second.
pub const MS_PER_SECOND: u64 = 1_000;

/// An instant on the audit service clock (UTC ms since the Unix epoch).
///
/// Only the audit clock produces these for envelopes; event payloads use
/// it only for staff timers (`cfg.dangerous_*` expiry). It is never a
/// source-action time (P-03).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct UtcMillis(pub u64);

impl UtcMillis {
    /// Truncate to the second.
    pub const fn to_second(self) -> Self {
        Self(self.0.saturating_sub(self.0 % MS_PER_SECOND))
    }
    /// Truncate to the hour.
    pub const fn to_hour(self) -> Self {
        Self(self.0.saturating_sub(self.0 % MS_PER_HOUR))
    }
    /// UTC day.
    pub fn day(self) -> DayStamp {
        DayStamp(u32::try_from(self.0 / MS_PER_DAY).unwrap_or(u32::MAX))
    }
}

/// A UTC date (days since 1970-01-01). The only time type for
/// source-originated or import-related facts (ADR-038(1), `DayDate`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct DayStamp(pub u32);

impl DayStamp {
    /// Construct from a civil date; `None` if invalid or before 1970.
    pub fn from_ymd(y: i32, m: u32, d: u32) -> Option<Self> {
        if !(1..=12).contains(&m) || d == 0 || d > days_in_month(y, m) {
            return None;
        }
        let days = days_from_civil(i64::from(y), i64::from(m), i64::from(d));
        u32::try_from(days).ok().map(Self)
    }
    /// Midnight UTC of this day.
    pub fn start(self) -> UtcMillis {
        UtcMillis(u64::from(self.0).saturating_mul(MS_PER_DAY))
    }
    /// Civil date `(year, month, day)`.
    pub fn ymd(self) -> (i32, u32, u32) {
        civil_from_days(i64::from(self.0))
    }
    /// Calendar month containing this day.
    pub fn month(self) -> MonthStamp {
        let (y, m, _) = self.ymd();
        MonthStamp { year: y, month: m }
    }
    /// ISO `YYYY-MM-DD`.
    pub fn iso(self) -> String {
        let (y, m, d) = self.ymd();
        format!("{y:04}-{m:02}-{d:02}")
    }
}

/// A calendar month (24 §TEL minimum period).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct MonthStamp {
    /// Year.
    pub year: i32,
    /// Month 1..=12.
    pub month: u32,
}

impl MonthStamp {
    /// Construct; `None` if month out of range.
    pub fn new(year: i32, month: u32) -> Option<Self> {
        (1..=12).contains(&month).then_some(Self { year, month })
    }
    /// The following month.
    pub fn next(self) -> Self {
        if self.month >= 12 {
            Self {
                year: self.year.saturating_add(1),
                month: 1,
            }
        } else {
            Self {
                year: self.year,
                month: self.month.saturating_add(1),
            }
        }
    }
    /// The preceding month.
    pub fn prev(self) -> Self {
        if self.month <= 1 {
            Self {
                year: self.year.saturating_sub(1),
                month: 12,
            }
        } else {
            Self {
                year: self.year,
                month: self.month.saturating_sub(1),
            }
        }
    }
    /// First day of the month.
    pub fn first_day(self) -> Option<DayStamp> {
        DayStamp::from_ymd(self.year, self.month, 1)
    }
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i32, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        2 => 28,
        _ => 0,
    }
}

// Howard Hinnant's civil-date algorithms; inputs are bounded (u32 days,
// i32 years), so i64 arithmetic cannot overflow.
#[allow(clippy::arithmetic_side_effects)]
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[allow(clippy::arithmetic_side_effects)]
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (
        i32::try_from(y).unwrap_or(i32::MAX),
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn civil_round_trip() {
        let d = DayStamp::from_ymd(2026, 10, 1).unwrap();
        assert_eq!(d.ymd(), (2026, 10, 1));
        assert_eq!(d.iso(), "2026-10-01");
        assert_eq!(DayStamp::from_ymd(1970, 1, 1), Some(DayStamp(0)));
        assert_eq!(DayStamp::from_ymd(2024, 2, 30), None);
        assert!(DayStamp::from_ymd(2024, 2, 29).is_some());
        assert_eq!(d.month(), MonthStamp::new(2026, 10).unwrap());
    }

    #[test]
    fn truncation() {
        let t = UtcMillis(1_790_000_123_456);
        assert_eq!(t.to_second().0 % 1000, 0);
        assert_eq!(t.to_hour().0 % MS_PER_HOUR, 0);
        assert_eq!(t.day().start().0 % MS_PER_DAY, 0);
    }

    #[test]
    fn session_tag_rotates_with_salt() {
        let a = SessionTag::derive(&DaySalt::new([1; 32]), b"session");
        let b = SessionTag::derive(&DaySalt::new([2; 32]), b"session");
        assert_ne!(a, b);
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!(unhex(&hex(&[0, 1, 0xab, 0xff])).unwrap(), vec![0, 1, 0xab, 0xff]);
        assert!(unhex("0g").is_none());
        assert!(unhex("abc").is_none());
    }
}
