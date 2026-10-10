// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pseudonymous identifiers, hashes and coarse time types.
//!
//! Every type here is either an opaque random identifier (never derived
//! from source data), a hash/prefix of fixed width, or a time value whose
//! granularity is fixed by its type. There is deliberately **no** type for
//! IP addresses, ports, user agents, filenames, sizes or exact source-action
//! times (20 §6.1 P-01..P-17); see [`crate::sensitive`] for wrappers that
//! cannot reach any sink.
//!
//! **No constructor takes caller bytes** (AUD-RM1-LOG-03, AUD-RM1-LOG-17):
//! * identifiers are minted from the OS CSPRNG ([`CaseRef::generate`] etc.)
//!   and persisted by their owner as a MAC-sealed [`IdToken`]
//!   (`id ‖ HMAC(K_audit_id, "candor/v1/audit/id-token/<Type>\0" ‖ id)[..16]`);
//!   [`CaseRef::unseal`] accepts only tokens minted by this code under the
//!   deployment key, so arbitrary bytes (an address) cannot be loaded as an
//!   identifier and there is no keyed pseudonym of caller data;
//! * value hashes (`query_hash`, `policy_hash`, …) are **randomized hiding
//!   commitments** ([`Hash32::commit`]): the logged value is independent of
//!   the input for anyone without the opening, which stays with the producing
//!   component, so it cannot carry (or be tested against) a network
//!   identifier;
//! * session tags derive only from a random [`StaffSessionId`];
//! * checkpoint-derived values are obtainable only from the writing
//!   [`crate::AuditLog`] for its own checkpoints and are bound to its key.

use core::fmt;

use hmac::{Hmac, KeyInit, Mac};
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
            /// Wrap raw identifier bytes. Crate-internal only (stored records,
            /// samples): no raw caller data can be laundered into an
            /// identifier field (AUD-RM1-LOG-03, AUD-RM1-LOG-17).
            #[allow(dead_code)]
            pub(crate) const fn from_bytes(b: [u8; $len]) -> Self {
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

        impl crate::field::Sample for $name {
            fn sample() -> Self {
                Self([0x5a; $len])
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

/// Keyed pseudonymisation key for audit identifiers and value hashes
/// (deployment/stream key, AUD-RM1-LOG-03). Secret: zeroized, never printed,
/// not `Clone`.
pub struct AuditIdKey(Zeroizing<[u8; 32]>);

impl AuditIdKey {
    /// Wrap a 32-byte key (from the deployment key store).
    pub fn new(k: [u8; 32]) -> Self {
        Self(Zeroizing::new(k))
    }
}

impl fmt::Debug for AuditIdKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuditIdKey(<redacted>)")
    }
}

/// `HMAC-SHA-256(key, label ‖ 0x00 ‖ data)`. Labels are NUL-terminated,
/// so the encoding is prefix-free.
pub(crate) fn keyed32(key: &[u8; 32], label: &[u8], data: &[u8]) -> [u8; 32] {
    match <Hmac<Sha256> as KeyInit>::new_from_slice(key) {
        Ok(mut m) => {
            m.update(label);
            m.update(&[0]);
            m.update(data);
            m.finalize().into_bytes().into()
        }
        // HMAC accepts keys of any length, so this arm is unreachable; it
        // still yields a keyed (secret-prefixed) digest rather than panicking.
        Err(_) => {
            let mut h = Sha256::new();
            h.update(b"candor/v1/audit/keyed-fallback\0");
            h.update(key);
            h.update(label);
            h.update([0]);
            h.update(data);
            h.finalize().into()
        }
    }
}

/// The OS random number generator failed (fail closed: nothing is
/// generated or emitted).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RandomError;

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], RandomError> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| RandomError)?;
    Ok(b)
}

/// Persisted form of an identifier: `id ‖ tag` with
/// `tag = HMAC-SHA-256(K_audit_id, "candor/v1/audit/id-token/<Type>" ‖ 0 ‖ id)[..16]`.
/// Owners store tokens (e.g. next to their own row) and load them back with
/// `unseal`; a token for another type or key, or arbitrary bytes, is
/// refused (AUD-RM1-LOG-17).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdToken([u8; 32]);

impl IdToken {
    /// Wrap stored token bytes (unverified until `unseal`).
    pub const fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
    /// Token bytes for storage.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for IdToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdToken(..)")
    }
}

fn id_tag(key: &AuditIdKey, label: &[u8], id: &[u8; 16]) -> [u8; 16] {
    let d = keyed32(&key.0, label, id);
    let mut out = [0u8; 16];
    for (o, i) in out.iter_mut().zip(d.iter()) {
        *o = *i;
    }
    out
}

macro_rules! random_id {
    ($($name:ident),+ $(,)?) => { $(
        impl $name {
            /// Mint a fresh identifier from the OS CSPRNG (the only way to
            /// create one; AUD-RM1-LOG-17).
            pub fn generate() -> Result<Self, RandomError> {
                random_bytes::<16>().map(Self)
            }
            /// Persisted, MAC-sealed form (see [`IdToken`]).
            pub fn seal(&self, key: &AuditIdKey) -> IdToken {
                let tag = id_tag(
                    key,
                    concat!("candor/v1/audit/id-token/", stringify!($name)).as_bytes(),
                    &self.0,
                );
                let mut t = [0u8; 32];
                for (o, i) in t.iter_mut().zip(self.0.iter().chain(tag.iter())) {
                    *o = *i;
                }
                IdToken(t)
            }
            /// Load a token minted by [`Self::seal`] under `key`; `None` for
            /// any other bytes (constant-time tag check).
            pub fn unseal(key: &AuditIdKey, token: &IdToken) -> Option<Self> {
                use subtle::ConstantTimeEq;
                let (id, tag) = token.0.split_at(16);
                let id: [u8; 16] = id.try_into().ok()?;
                let want = id_tag(
                    key,
                    concat!("candor/v1/audit/id-token/", stringify!($name)).as_bytes(),
                    &id,
                );
                bool::from(want.ct_eq(tag)).then_some(Self(id))
            }
        }
    )+ };
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

random_id!(
    CaseRef,
    EvidRef,
    UserRef,
    PersonRef,
    DeviceKeyId,
    TenantRef,
    ChannelId,
    PackageId,
    XformId,
    BackupId,
    ReceiptId,
    PsrId,
    HoldRef,
    TimerId,
    ReportId,
    WitnessId,
);

/// Purpose label of a keyed value hash (domain separation per field).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum HashPurpose {
    /// `records.search_performed.query_hash`.
    Query,
    /// `cfg.changed.old_value_hash`.
    ConfigValue,
    /// `*.policy_hash` (channel membership, COI map, SLA pack).
    Policy,
    /// `keydir.entry_published.entry_hash`.
    KeydirEntry,
    /// `audit.exported.recipient_key_fingerprint`.
    RecipientKey,
    /// `custody.head.custody_mac`.
    CustodyHead,
    /// `auth.stepup_*.descriptor_hash_prefix`.
    ApprovalDescriptor,
    /// `platform.mismatch.expected_manifest_hash_prefix`.
    Manifest,
}

impl HashPurpose {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::Query => b"candor/v1/audit/hash/query",
            Self::ConfigValue => b"candor/v1/audit/hash/config-value",
            Self::Policy => b"candor/v1/audit/hash/policy",
            Self::KeydirEntry => b"candor/v1/audit/hash/keydir-entry",
            Self::RecipientKey => b"candor/v1/audit/hash/recipient-key",
            Self::CustodyHead => b"candor/v1/audit/hash/custody-head",
            Self::ApprovalDescriptor => b"candor/v1/audit/hash/approval-descriptor",
            Self::Manifest => b"candor/v1/audit/hash/manifest",
        }
    }
}

/// Domain label of a value commitment.
const VALUE_COMMIT_DOMAIN: &[u8] = b"candor/v1/audit/value-commit\0";

/// Opening (randomness) of a value commitment. Kept by the producing
/// component, never logged; with it and the value an auditor can check the
/// logged commitment ([`Opening::verifies`]). Zeroized, not printed.
pub struct Opening(Zeroizing<[u8; 32]>);

impl Opening {
    /// Stored opening bytes (only useful for [`Opening::verifies`]).
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(Zeroizing::new(b))
    }
    /// Opening bytes for the producer's own storage.
    pub fn to_bytes(&self) -> [u8; 32] {
        *self.0
    }
    /// Whether `commitment` commits to `value` under `purpose` with this
    /// opening (constant-time comparison).
    pub fn verifies(&self, purpose: HashPurpose, value: &[u8], commitment: &Hash32) -> bool {
        use subtle::ConstantTimeEq;
        bool::from(commit_with(&self.0, purpose, value).ct_eq(&commitment.0))
    }
    /// As [`Opening::verifies`] for an 8-byte prefix commitment.
    pub fn verifies_prefix(&self, purpose: HashPurpose, value: &[u8], c: &HashPrefix8) -> bool {
        use subtle::ConstantTimeEq;
        let full = commit_with(&self.0, purpose, value);
        full.get(..8).is_some_and(|p| bool::from(p.ct_eq(&c.0)))
    }
}

impl fmt::Debug for Opening {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Opening(<redacted>)")
    }
}

fn commit_with(r: &[u8; 32], purpose: HashPurpose, value: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(VALUE_COMMIT_DOMAIN);
    h.update(purpose.label());
    h.update([0]);
    h.update(r);
    h.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    h.update(value);
    h.finalize().into()
}

impl Hash32 {
    /// Randomized, purpose-separated **hiding commitment** to a value
    /// (AUD-RM1-LOG-17): `SHA-256("candor/v1/audit/value-commit\0" ‖
    /// label(purpose) ‖ 0 ‖ r ‖ len ‖ value)` with a fresh 256-bit `r` from
    /// the OS CSPRNG, returned as the [`Opening`]. The logged value is
    /// independent of `value` for anyone without the opening, so neither a
    /// log reader nor the writer's own key can test it against candidate
    /// addresses, names or terms; the caller cannot choose `r`.
    pub fn commit(purpose: HashPurpose, value: &[u8]) -> Result<(Self, Opening), RandomError> {
        let r = Zeroizing::new(random_bytes::<32>()?);
        Ok((Self(commit_with(&r, purpose, value)), Opening(r)))
    }
}

impl HashPrefix8 {
    /// First 8 bytes of a [`Hash32::commit`] commitment.
    pub fn commit(purpose: HashPurpose, value: &[u8]) -> Result<(Self, Opening), RandomError> {
        let (h, o) = Hash32::commit(purpose, value)?;
        let mut out = [0u8; 8];
        for (d, s) in out.iter_mut().zip(h.0.iter()) {
            *d = *s;
        }
        Ok((Self(out), o))
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
    /// Fresh random salt.
    pub fn generate() -> Result<Self, RandomError> {
        Ok(Self(Zeroizing::new(random_bytes::<32>()?)))
    }
}

/// A staff session secret (the auth service's session identifier). Minted
/// only from the CSPRNG and persisted only as a sealed token, so a session
/// tag cannot be a pseudonym of caller data (AUD-RM1-LOG-17). Secret:
/// zeroized, never printed, not `Clone`.
pub struct StaffSessionId(Zeroizing<[u8; 32]>);

const SESSION_TOKEN_LABEL: &[u8] = b"candor/v1/audit/session-token";

impl StaffSessionId {
    /// Fresh session secret.
    pub fn generate() -> Result<Self, RandomError> {
        Ok(Self(Zeroizing::new(random_bytes::<32>()?)))
    }
    /// Sealed form for the auth service's session store:
    /// `id ‖ HMAC(key, label ‖ 0 ‖ id)` (64 bytes).
    pub fn seal(&self, key: &AuditIdKey) -> Zeroizing<[u8; 64]> {
        let tag = keyed32(&key.0, SESSION_TOKEN_LABEL, self.0.as_slice());
        let mut t = Zeroizing::new([0u8; 64]);
        for (o, i) in t.iter_mut().zip(self.0.iter().chain(tag.iter())) {
            *o = *i;
        }
        t
    }
    /// Load a sealed session id; `None` unless minted by [`Self::seal`]
    /// under `key` (constant-time check).
    pub fn unseal(key: &AuditIdKey, token: &[u8; 64]) -> Option<Self> {
        use subtle::ConstantTimeEq;
        let (id, tag) = token.split_at(32);
        let want = keyed32(&key.0, SESSION_TOKEN_LABEL, id);
        let id: [u8; 32] = id.try_into().ok()?;
        bool::from(want.ct_eq(tag)).then(|| Self(Zeroizing::new(id)))
    }
}

impl fmt::Debug for StaffSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StaffSessionId(<redacted>)")
    }
}

impl SessionTag {
    /// `SHA-256("candor/v1/audit/session\0" ‖ day_salt ‖ session_id)[..8]`.
    pub fn derive(salt: &DaySalt, session: &StaffSessionId) -> Self {
        let mut h = Sha256::new();
        h.update(b"candor/v1/audit/session\0");
        h.update(salt.0.as_slice());
        h.update(session.0.as_slice());
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
pub struct DayStamp(pub(crate) u32);

impl DayStamp {
    /// Largest accepted day number (2243-10-17); bounds the field so it
    /// cannot carry 32 bits of arbitrary data (AUD-RM1-LOG-03).
    pub const MAX_DAYS: u32 = 100_000;
    /// From days since 1970-01-01; `None` above [`DayStamp::MAX_DAYS`].
    pub fn from_days(days: u32) -> Option<Self> {
        (days <= Self::MAX_DAYS).then_some(Self(days))
    }
    /// Days since 1970-01-01.
    pub const fn days(self) -> u32 {
        self.0
    }
    /// Construct from a civil date; `None` if invalid or before 1970.
    pub fn from_ymd(y: i32, m: u32, d: u32) -> Option<Self> {
        if !(1..=12).contains(&m) || d == 0 || d > days_in_month(y, m) {
            return None;
        }
        let days = days_from_civil(i64::from(y), i64::from(m), i64::from(d));
        u32::try_from(days).ok().and_then(Self::from_days)
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
        let s = StaffSessionId::generate().unwrap();
        let a = SessionTag::derive(&DaySalt::new([1; 32]), &s);
        let b = SessionTag::derive(&DaySalt::new([2; 32]), &s);
        assert_ne!(a, b);
        let k = AuditIdKey::new([4; 32]);
        let t = s.seal(&k);
        let back = StaffSessionId::unseal(&k, &t).unwrap();
        assert_eq!(SessionTag::derive(&DaySalt::new([1; 32]), &back), a);
        let mut bad = *t;
        bad[0] ^= 1;
        assert!(StaffSessionId::unseal(&k, &bad).is_none());
        assert!(StaffSessionId::unseal(&AuditIdKey::new([5; 32]), &t).is_none());
    }

    // AUD-RM1-LOG-17: identifiers load only from tokens minted under the
    // key and for the same type; arbitrary bytes (an address) are refused.
    #[test]
    fn id_tokens_bind_key_and_type() {
        let k = AuditIdKey::new([4; 32]);
        let c = CaseRef::generate().unwrap();
        let t = c.seal(&k);
        assert_eq!(CaseRef::unseal(&k, &t), Some(c));
        assert_eq!(UserRef::unseal(&k, &t), None);
        assert_eq!(CaseRef::unseal(&AuditIdKey::new([5; 32]), &t), None);
        let mut ip = [0u8; 32];
        ip[..4].copy_from_slice(&[203, 0, 113, 7]);
        assert_eq!(CaseRef::unseal(&k, &IdToken::from_bytes(ip)), None);
        assert_ne!(CaseRef::generate().unwrap(), CaseRef::generate().unwrap());
    }

    // AUD-RM1-LOG-17: value commitments are hiding (same input, different
    // commitments), purpose-separated and checkable with the opening.
    #[test]
    fn value_commitments_hide_and_open() {
        let (a, oa) = Hash32::commit(HashPurpose::Query, b"203.0.113.7").unwrap();
        let (b, _) = Hash32::commit(HashPurpose::Query, b"203.0.113.7").unwrap();
        assert_ne!(a, b);
        assert!(oa.verifies(HashPurpose::Query, b"203.0.113.7", &a));
        assert!(!oa.verifies(HashPurpose::Policy, b"203.0.113.7", &a));
        assert!(!oa.verifies(HashPurpose::Query, b"203.0.113.8", &a));
        let (p, op) = HashPrefix8::commit(HashPurpose::Manifest, b"m").unwrap();
        assert!(op.verifies_prefix(HashPurpose::Manifest, b"m", &p));
        assert!(!format!("{oa:?}").contains(&hex(&oa.to_bytes())));
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!(
            unhex(&hex(&[0, 1, 0xab, 0xff])).unwrap(),
            vec![0, 1, 0xab, 0xff]
        );
        assert!(unhex("0g").is_none());
        assert!(unhex("abc").is_none());
    }
}
