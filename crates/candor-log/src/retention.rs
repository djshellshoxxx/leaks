// SPDX-License-Identifier: AGPL-3.0-or-later
//! Retention (20 §12, AUD-005, AUD-011).
//!
//! SECURITY and SYSTEM streams lose whole checkpoint intervals older than
//! retention, after a SECURITY `audit.retention_tombstone` is written; the
//! remaining records stay verifiable from the retained checkpoint's chain
//! head. CASE events are removed per case at disposal (AUD-012) via
//! [`crate::sink::MemoryStore::redact_case`].

use crate::chain::{CommittedRecord, SignedCheckpoint};
use crate::codes::StreamId;
use crate::event::AuditEvent;
use crate::field::SeqRange;
use crate::ids::{Hash32, MS_PER_DAY, UtcMillis};
use crate::sink::MemoryStore;

/// Retention configuration with the 20 §12 bounds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RetentionPolicy {
    security_days: u32,
    system_days: u32,
    case_extra_days: u32,
    counter_months: u32,
}

/// Retention errors.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RetentionError {
    /// A value is outside its §12 bounds.
    OutOfBounds,
    /// The plan does not match a whole checkpoint interval.
    NotWholeInterval,
    /// No matching tombstone was written before deletion.
    MissingTombstone,
    /// CASE stream is not interval-deleted.
    CaseStream,
}

impl RetentionPolicy {
    /// SECURITY default (days).
    pub const SECURITY_DEFAULT: u32 = 400;
    /// SECURITY bounds (90 days .. 7 years).
    pub const SECURITY_BOUNDS: (u32, u32) = (90, 7 * 365 + 2);
    /// SYSTEM default (days).
    pub const SYSTEM_DEFAULT: u32 = 30;
    /// SYSTEM bounds.
    pub const SYSTEM_BOUNDS: (u32, u32) = (7, 90);
    /// CASE: days after case end (default 1 year; 0 .. 10 years).
    pub const CASE_EXTRA_DEFAULT: u32 = 365;
    /// CASE extra bounds.
    pub const CASE_EXTRA_BOUNDS: (u32, u32) = (0, 10 * 365 + 3);
    /// SOURCE-SENSITIVE monthly counters (months).
    pub const COUNTER_DEFAULT: u32 = 13;
    /// Counter bounds.
    pub const COUNTER_BOUNDS: (u32, u32) = (13, 60);

    /// Spec defaults.
    pub const DEFAULT: Self = Self {
        security_days: Self::SECURITY_DEFAULT,
        system_days: Self::SYSTEM_DEFAULT,
        case_extra_days: Self::CASE_EXTRA_DEFAULT,
        counter_months: Self::COUNTER_DEFAULT,
    };

    /// Validated policy.
    pub fn new(
        security_days: u32,
        system_days: u32,
        case_extra_days: u32,
        counter_months: u32,
    ) -> Result<Self, RetentionError> {
        let within = |v: u32, (lo, hi): (u32, u32)| (lo..=hi).contains(&v);
        if within(security_days, Self::SECURITY_BOUNDS)
            && within(system_days, Self::SYSTEM_BOUNDS)
            && within(case_extra_days, Self::CASE_EXTRA_BOUNDS)
            && within(counter_months, Self::COUNTER_BOUNDS)
        {
            Ok(Self {
                security_days,
                system_days,
                case_extra_days,
                counter_months,
            })
        } else {
            Err(RetentionError::OutOfBounds)
        }
    }

    /// Retention in days for an interval-deleted stream.
    pub fn days(&self, s: StreamId) -> Option<u32> {
        match s {
            StreamId::Sec => Some(self.security_days),
            StreamId::Sys => Some(self.system_days),
            StreamId::Case => None,
        }
    }

    /// Days CASE events are kept after case end.
    pub fn case_extra_days(&self) -> u32 {
        self.case_extra_days
    }

    /// Months monthly counters are kept.
    pub fn counter_months(&self) -> u32 {
        self.counter_months
    }
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A planned whole-interval deletion.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeletionPlan {
    /// Stream.
    pub stream: StreamId,
    /// Deleted range.
    pub range: SeqRange,
    /// Merkle root of the last deleted checkpoint.
    pub last_deleted_root: Hash32,
}

impl DeletionPlan {
    /// The tombstone event to emit **before** deleting.
    pub fn tombstone(&self) -> AuditEvent {
        AuditEvent::AuditRetentionTombstone {
            stream: self.stream,
            seq_range: self.range,
            last_deleted_checkpoint_root: self.last_deleted_root,
        }
    }
}

/// Plan deletion of every whole checkpoint interval signed more than the
/// retention period before `now`. `first_retained` is the first record
/// currently stored.
pub fn plan_interval_deletion(
    policy: &RetentionPolicy,
    stream: StreamId,
    checkpoints: &[SignedCheckpoint],
    first_retained: u64,
    now: UtcMillis,
) -> Result<Option<DeletionPlan>, RetentionError> {
    let days = policy.days(stream).ok_or(RetentionError::CaseStream)?;
    let cutoff = now.0.saturating_sub(u64::from(days).saturating_mul(MS_PER_DAY));
    let last = checkpoints
        .iter()
        .filter(|c| c.body().signed_at.0 <= cutoff && c.body().last_seq >= first_retained)
        .max_by_key(|c| c.body().last_seq);
    Ok(last.map(|c| DeletionPlan {
        stream,
        range: SeqRange {
            first: first_retained,
            last: c.body().last_seq,
        },
        last_deleted_root: Hash32::from_bytes(c.body().merkle_root),
    }))
}

/// Apply a plan to a store after its tombstone was committed.
pub fn apply_interval_deletion(
    store: &mut MemoryStore,
    plan: &DeletionPlan,
    tombstone: &CommittedRecord,
) -> Result<(), RetentionError> {
    if plan.stream == StreamId::Case {
        return Err(RetentionError::CaseStream);
    }
    if tombstone.event() != &plan.tombstone()
        || (plan.stream == StreamId::Sec && tombstone.header().seq <= plan.range.last)
    {
        return Err(RetentionError::MissingTombstone);
    }
    let whole = store
        .checkpoints(plan.stream)
        .iter()
        .any(|c| c.body().last_seq == plan.range.last);
    if !whole {
        return Err(RetentionError::NotWholeInterval);
    }
    store.drop_through(plan.stream, plan.range.last);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds() {
        assert_eq!(RetentionPolicy::default().days(StreamId::Sec), Some(400));
        assert_eq!(RetentionPolicy::default().days(StreamId::Sys), Some(30));
        assert!(RetentionPolicy::new(89, 30, 365, 13).is_err());
        assert!(RetentionPolicy::new(400, 91, 365, 13).is_err());
        assert!(RetentionPolicy::new(400, 30, 365, 12).is_err());
        assert!(RetentionPolicy::new(400, 30, 365, 61).is_err());
        assert!(RetentionPolicy::new(2557, 7, 0, 60).is_ok());
    }
}
