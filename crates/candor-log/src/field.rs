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
    /// Whether a value derived from an audit artefact (checkpoint,
    /// verification report or failure) was derived under the checkpoint key
    /// `key` of the log that is emitting it (AUD-RM1-LOG-17: a value from a
    /// self-signed or foreign checkpoint is refused) and, for sequence
    /// numbers, lies within the writer's own sequence space: a `Seq` ≤
    /// `max_seq` and a `SeqRange` ending below it, where `max_seq` is the
    /// largest `next_seq` of the writer's streams (AUD-RM1-LOG-24: a crafted
    /// verification failure cannot carry 64 chosen bits). `true` for every
    /// other field type.
    #[doc(hidden)]
    fn origin_ok(&self, _key: &[u8; 32], _bounds: &SeqBounds) -> bool {
        true
    }
}

/// The emitting writer's `next_seq` per stream (AUD-RM1-LOG-26). Built only
/// by the writer.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct SeqBounds(pub(crate) [u64; 5]);

impl SeqBounds {
    /// `next_seq` of `stream`.
    pub(crate) fn next(&self, stream: crate::codes::StreamId) -> u64 {
        let i = usize::from(crate::chain::stream_byte(stream)).saturating_sub(1);
        self.0.get(i).copied().unwrap_or(0)
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
        SeqRange {
            first: 0,
            last: 9,
            origin: [0; 32],
            stream: crate::codes::StreamId::Sec,
        }
    }
}
impl Sample for Count {
    fn sample() -> Self {
        Count(7)
    }
}
impl Sample for Seq {
    fn sample() -> Self {
        Seq {
            v: 7,
            origin: [0; 32],
            stream: crate::codes::StreamId::Sec,
        }
    }
}
impl Sample for CheckpointRoot {
    fn sample() -> Self {
        CheckpointRoot {
            root: [0x5a; 32],
            origin: [0; 32],
        }
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
    fn origin_ok(&self, key: &[u8; 32], bounds: &SeqBounds) -> bool {
        self.as_ref().is_none_or(|v| v.origin_ok(key, bounds))
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
/// source time; encoded truncated to the minute. Constructible only from the
/// audit clock plus a bounded duration, so no caller-supplied instant (e.g.
/// a source-event time) can be laundered into it (AUD-RM1-LOG-03).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct StaffTimer(UtcMillis);

impl StaffTimer {
    /// Maximum timer duration: 90 days, in minutes.
    pub const MAX_MINUTES: u32 = 90 * 24 * 60;
    /// `clock.now + minutes`; `None` above [`StaffTimer::MAX_MINUTES`].
    pub fn after(clock: &dyn crate::chain::AuditClock, minutes: u32) -> Option<Self> {
        if minutes > Self::MAX_MINUTES {
            return None;
        }
        let now = clock.read().now.0;
        Some(Self(UtcMillis(
            now.saturating_add(u64::from(minutes).saturating_mul(60_000)),
        )))
    }
    /// The instant (minute-truncated when encoded).
    pub fn instant(self) -> UtcMillis {
        self.0
    }
}

impl sealed::Sealed for StaffTimer {}
impl AuditField for StaffTimer {
    fn to_value(&self) -> Value {
        Value::Uint(self.0.0.saturating_sub(self.0.0 % 60_000))
    }
}

macro_rules! bounded_count {
    ($(#[$m:meta])* $name:ident, $inner:ty, $max:expr) => {
        $(#[$m])*
        ///
        /// The value is private and bounded (AUD-RM1-LOG-03): a field this
        /// small cannot carry an address, a size or a timestamp.
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
        pub struct $name($inner);
        impl $name {
            /// Largest accepted value.
            pub const MAX: $inner = $max;
            /// `None` above [`Self::MAX`].
            pub fn new(v: $inner) -> Option<Self> {
                (v <= Self::MAX).then_some(Self(v))
            }
            /// Value.
            pub fn get(self) -> $inner {
                self.0
            }
        }
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
    /// Small counter (authenticators remaining, relay slots, clock sources).
    SmallCount, u8, 100);
bounded_count!(
    /// Case key generation.
    KeyGeneration, u32, 65_535);
bounded_count!(
    /// Break-glass grant duration in minutes (≤ 24 h).
    DurationMin, u16, 1440);
bounded_count!(
    /// Age of a sandbox image in days.
    AgeDays, u16, 3660);
bounded_count!(
    /// Process exit status.
    ExitCode, u8, 255);
bounded_count!(
    /// Index of a 15-minute import slot within a day.
    SlotIndex, u8, 95);

/// A small count of staff-visible objects (evidence items in an export,
/// transform inputs/outputs). Never a byte size or a per-submission
/// attachment count (P-07). Bounded by [`Count::MAX`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Count(u32);

impl Count {
    /// Largest caller-constructible value.
    pub const MAX: u32 = 10_000;
    /// `None` above [`Count::MAX`].
    pub fn new(v: u32) -> Option<Self> {
        (v <= Self::MAX).then_some(Self(v))
    }
    /// Value.
    pub fn get(self) -> u32 {
        self.0
    }
}

impl sealed::Sealed for Count {}
impl AuditField for Count {
    fn to_value(&self) -> Value {
        Value::Uint(u64::from(self.0))
    }
}

/// Audit sequence number. Constructible only from audit artefacts of the
/// emitting log ([`crate::AuditLog::checkpoint_seq`], [`Seq::of_failure`]),
/// never from caller integers, and bound to the checkpoint key it was
/// derived under (AUD-RM1-LOG-17).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Seq {
    v: u64,
    origin: [u8; 32],
    stream: crate::codes::StreamId,
}

impl Seq {
    pub(crate) fn bound(v: u64, origin: [u8; 32], stream: crate::codes::StreamId) -> Self {
        Self { v, origin, stream }
    }
    /// The offending sequence number of a verification failure (bound to
    /// the key and stream it was verified under). Audit/verify tooling only:
    /// banned elsewhere by the workspace `clippy.toml` (AUD-RM1-LOG-26).
    pub fn of_failure(e: &crate::verify::VerifyError) -> Self {
        Self {
            v: e.seq,
            origin: e.origin,
            stream: e.stream,
        }
    }
    /// Value.
    pub fn get(self) -> u64 {
        self.v
    }
}

impl sealed::Sealed for Seq {}
impl AuditField for Seq {
    fn to_value(&self) -> Value {
        Value::Uint(self.v)
    }
    fn origin_ok(&self, key: &[u8; 32], bounds: &SeqBounds) -> bool {
        &self.origin == key && self.v <= bounds.next(self.stream)
    }
}

/// Inclusive audit sequence range `[first, last]`. Constructible only from
/// audit artefacts of the emitting log (its checkpoints, verification
/// reports under its key), never from caller integers (AUD-RM1-LOG-03,
/// AUD-RM1-LOG-17).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SeqRange {
    pub(crate) first: u64,
    pub(crate) last: u64,
    pub(crate) origin: [u8; 32],
    pub(crate) stream: crate::codes::StreamId,
}

impl SeqRange {
    /// The records covered by a successful verification, optionally
    /// narrowed to `[first, last]` inside it (viewer/exports). Audit/verify
    /// tooling only: banned elsewhere by the workspace `clippy.toml`
    /// (AUD-RM1-LOG-26).
    pub fn within(report: &crate::verify::VerifyReport, first: u64, last: u64) -> Option<Self> {
        let lo = report.first_seq?;
        (lo <= first && first <= last && last < report.next_seq).then_some(Self {
            first,
            last,
            origin: report.origin,
            stream: report.stream,
        })
    }
    /// First sequence number.
    pub fn first(self) -> u64 {
        self.first
    }
    /// Last sequence number.
    pub fn last(self) -> u64 {
        self.last
    }
}

impl sealed::Sealed for SeqRange {}
impl AuditField for SeqRange {
    fn to_value(&self) -> Value {
        Value::Array(vec![Value::Uint(self.first), Value::Uint(self.last)])
    }
    fn origin_ok(&self, key: &[u8; 32], bounds: &SeqBounds) -> bool {
        &self.origin == key && self.first <= self.last && self.last < bounds.next(self.stream)
    }
}

/// Merkle root of one of the emitting log's own checkpoints
/// (`audit.checkpoint_signed.root`), obtainable only through
/// [`crate::AuditLog::checkpoint_root`] (AUD-RM1-LOG-16/17: no arbitrary
/// 32 bytes through a self-signed checkpoint).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct CheckpointRoot {
    pub(crate) root: [u8; 32],
    pub(crate) origin: [u8; 32],
}

impl CheckpointRoot {
    /// Root bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.root
    }
}

impl sealed::Sealed for CheckpointRoot {}
impl AuditField for CheckpointRoot {
    fn to_value(&self) -> Value {
        Value::Bytes(self.root.to_vec())
    }
    fn origin_ok(&self, key: &[u8; 32], _bounds: &SeqBounds) -> bool {
        &self.origin == key
    }
}

/// Software version `major.minor.patch`, each component ≤ 255 (bounded so
/// the field cannot carry arbitrary data, AUD-RM1-LOG-03).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Version {
    major: u16,
    minor: u16,
    patch: u16,
}

impl Version {
    /// Largest accepted component.
    pub const MAX_COMPONENT: u16 = 255;
    /// `None` if any component exceeds [`Version::MAX_COMPONENT`].
    pub fn new(major: u16, minor: u16, patch: u16) -> Option<Self> {
        (major <= Self::MAX_COMPONENT
            && minor <= Self::MAX_COMPONENT
            && patch <= Self::MAX_COMPONENT)
            .then_some(Self {
                major,
                minor,
                patch,
            })
    }
    /// `(major, minor, patch)`.
    pub fn parts(self) -> (u16, u16, u16) {
        (self.major, self.minor, self.patch)
    }
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
