// SPDX-License-Identifier: AGPL-3.0-or-later
//! The sealed [`AuditField`] trait: the closed set of types that may appear
//! in an audit payload.
//!
//! The trait is sealed, so no other crate can make `String`, `&str`,
//! `std::net::IpAddr`, a filename, a size or a source timestamp loggable.
//! It is implemented only for opaque IDs, hashes, enumerated codes, bounded
//! counts, booleans and coarse time types (LOG-001, LOG-002, P-12).

use crate::cbor::Value;
use crate::ids::{DayStamp, UtcMillis};

pub(crate) mod sealed {
    /// Sealing trait; not nameable outside the crate.
    pub trait Sealed {}
}

/// A value that may be written into an audit payload.
pub trait AuditField: sealed::Sealed {
    /// Canonical CBOR value of this field.
    fn to_value(&self) -> Value;
    /// Value as a payload entry; `None` omits the key (absent optional field).
    fn payload_value(&self) -> Option<Value> {
        Some(self.to_value())
    }
    /// Closed code set of this field type, for the schema registry
    /// (`audit/schema.yaml`, LOG-014); empty for non-enumerated types.
    #[doc(hidden)]
    fn schema_codes() -> &'static [&'static str]
    where
        Self: Sized,
    {
        &[]
    }
}

/// Deterministic sample values for catalog-wide tests (not for production use).
#[doc(hidden)]
pub trait Sample {
    /// A representative value.
    fn sample() -> Self;
}

impl Sample for bool {
    fn sample() -> Self {
        true
    }
}
impl<T: Sample> Sample for Option<T> {
    fn sample() -> Self {
        Some(T::sample())
    }
}
impl Sample for DayStamp {
    fn sample() -> Self {
        DayStamp(20_000)
    }
}
impl Sample for StaffTimer {
    fn sample() -> Self {
        StaffTimer(UtcMillis(1_790_000_000_000))
    }
}
impl Sample for SeqRange {
    fn sample() -> Self {
        SeqRange { first: 0, last: 9 }
    }
}
impl Sample for Version {
    fn sample() -> Self {
        Version {
            major: 1,
            minor: 2,
            patch: 3,
        }
    }
}
impl Sample for Percent {
    fn sample() -> Self {
        Percent(100)
    }
}
impl Sample for PercentBucket {
    fn sample() -> Self {
        PercentBucket(50)
    }
}
impl Sample for DcCode {
    fn sample() -> Self {
        DcCode(10)
    }
}
impl Sample for Approvers {
    fn sample() -> Self {
        Approvers(vec![
            crate::ids::UserRef::from_bytes([0xa1; 16]),
            crate::ids::UserRef::from_bytes([0xa2; 16]),
        ])
    }
}

impl sealed::Sealed for bool {}
impl AuditField for bool {
    fn to_value(&self) -> Value {
        Value::Bool(*self)
    }
}

impl<T: AuditField> sealed::Sealed for Option<T> {}
impl<T: AuditField> AuditField for Option<T> {
    fn to_value(&self) -> Value {
        match self {
            Some(v) => v.to_value(),
            None => Value::Null,
        }
    }
    fn payload_value(&self) -> Option<Value> {
        self.as_ref().map(AuditField::to_value)
    }
    fn schema_codes() -> &'static [&'static str] {
        T::schema_codes()
    }
}

impl sealed::Sealed for DayStamp {}
impl AuditField for DayStamp {
    fn to_value(&self) -> Value {
        // Encoded as midnight UTC in ms, the same unit as `ts` (DayDate).
        Value::Uint(self.start().0)
    }
}

/// A staff/system timer instant (e.g., `cfg.dangerous_*` expiry). Never a
/// source time; encoded truncated to the minute.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct StaffTimer(pub UtcMillis);

impl sealed::Sealed for StaffTimer {}
impl AuditField for StaffTimer {
    fn to_value(&self) -> Value {
        Value::Uint(self.0.0.saturating_sub(self.0.0 % 60_000))
    }
}

macro_rules! bounded_count {
    ($(#[$m:meta])* $name:ident, $inner:ty) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
        pub struct $name(pub $inner);
        impl sealed::Sealed for $name {}
        impl AuditField for $name {
            fn to_value(&self) -> Value {
                Value::Uint(u64::from(self.0))
            }
        }
        impl Sample for $name {
            fn sample() -> Self {
                Self(7)
            }
        }
    };
}

bounded_count!(
    /// A small count of staff-visible objects (evidence items in an export,
    /// transform inputs/outputs, removed audit events). Never a byte size or
    /// a per-submission attachment count (P-07).
    Count, u32);
bounded_count!(
    /// Small counter (authenticators remaining, relay slots, clock sources).
    SmallCount, u8);
bounded_count!(
    /// Case key generation.
    KeyGeneration, u32);
bounded_count!(
    /// Audit sequence number.
    Seq, u64);
bounded_count!(
    /// Break-glass grant duration in minutes.
    DurationMin, u16);
bounded_count!(
    /// Age of a sandbox image in days.
    AgeDays, u16);
bounded_count!(
    /// Process exit status.
    ExitCode, u8);
bounded_count!(
    /// Index of an import slot within a day.
    SlotIndex, u8);

/// Inclusive audit sequence range `[first, last]`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SeqRange {
    /// First sequence number.
    pub first: u64,
    /// Last sequence number.
    pub last: u64,
}

impl sealed::Sealed for SeqRange {}
impl AuditField for SeqRange {
    fn to_value(&self) -> Value {
        Value::Array(vec![Value::Uint(self.first), Value::Uint(self.last)])
    }
}

/// Software version `major.minor.patch`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Version {
    /// Major.
    pub major: u16,
    /// Minor.
    pub minor: u16,
    /// Patch.
    pub patch: u16,
}

impl sealed::Sealed for Version {}
impl AuditField for Version {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Uint(u64::from(self.major)),
            Value::Uint(u64::from(self.minor)),
            Value::Uint(u64::from(self.patch)),
        ])
    }
}

/// Tor bootstrap percentage, 0..=100.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Percent(u8);

impl Percent {
    /// `None` if above 100.
    pub fn new(p: u8) -> Option<Self> {
        (p <= 100).then_some(Self(p))
    }
}

impl sealed::Sealed for Percent {}
impl AuditField for Percent {
    fn to_value(&self) -> Value {
        Value::Uint(u64::from(self.0))
    }
}

/// Utilisation percentage floored to 10 % steps (`sys.capacity`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PercentBucket(u8);

impl PercentBucket {
    /// Floor `p` (clamped to 100) to a multiple of 10.
    pub fn from_percent(p: u8) -> Self {
        let p = p.min(100);
        Self(p.saturating_sub(p % 10))
    }
    /// Bucket lower bound.
    pub fn value(self) -> u8 {
        self.0
    }
}

impl sealed::Sealed for PercentBucket {}
impl AuditField for PercentBucket {
    fn to_value(&self) -> Value {
        Value::Uint(u64::from(self.0))
    }
}

/// Dual-control code DC-01..DC-17 (15 §dual control).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct DcCode(u8);

impl DcCode {
    /// `None` outside 1..=17.
    pub fn new(n: u8) -> Option<Self> {
        (1..=17).contains(&n).then_some(Self(n))
    }
}

impl sealed::Sealed for DcCode {}
impl AuditField for DcCode {
    fn to_value(&self) -> Value {
        Value::Text(format!("DC-{:02}", self.0))
    }
}

/// Approver list (dual control). Bounded to [`Approvers::MAX`].
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Approvers(Vec<crate::ids::UserRef>);

impl Approvers {
    /// Maximum number of approvers recorded per event.
    pub const MAX: usize = 8;
    /// `None` if empty or longer than [`Approvers::MAX`].
    pub fn new(v: Vec<crate::ids::UserRef>) -> Option<Self> {
        (!v.is_empty() && v.len() <= Self::MAX).then_some(Self(v))
    }
    /// The approvers.
    pub fn as_slice(&self) -> &[crate::ids::UserRef] {
        &self.0
    }
}

impl sealed::Sealed for Approvers {}
impl AuditField for Approvers {
    fn to_value(&self) -> Value {
        Value::Array(self.0.iter().map(AuditField::to_value).collect())
    }
}
