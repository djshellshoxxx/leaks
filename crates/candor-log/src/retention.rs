// SPDX-License-Identifier: AGPL-3.0-or-later
//! Retention (20 §12, AUD-005, AUD-011).
//!
//! SECURITY, SYSTEM and SYSTEM-slot streams lose whole checkpoint intervals
//! older than retention, after a dual-approved retention tombstone is
//! written into the pruned stream ([`crate::AuditLog::emit_retention_tombstone`],
//! AUD-RM1-LOG-16/20); the remaining records stay verifiable from the
//! retained checkpoint's chain head. CASE / CASE-SLOT events are removed per
//! case at disposal (AUD-012) via
//! [`crate::sink::MemoryStore::apply_case_redaction`].

use crate::chain::SignedCheckpoint;
use crate::codes::StreamId;
use crate::event::AuditEvent;
use crate::field::SeqRange;
use crate::ids::{MS_PER_DAY, UtcMillis};
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
    /// The tombstone is not yet covered by a checkpoint (the verifier would
    /// reject the pruned prefix).
    TombstoneNotAttested,
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
            StreamId::Sys | StreamId::SysSlot => Some(self.system_days),
            StreamId::Case | StreamId::CaseSlot => None,
        }
    }

    /// The 20 §12 retention bounds (days) of an interval-deleted stream.
    pub fn bounds(s: StreamId) -> Option<(u32, u32)> {
        match s {
            StreamId::Sec => Some(Self::SECURITY_BOUNDS),
            StreamId::Sys | StreamId::SysSlot => Some(Self::SYSTEM_BOUNDS),
            StreamId::Case | StreamId::CaseSlot => None,
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

/// A planned whole-interval deletion (fields private: only
/// [`plan_interval_deletion`] builds one from real checkpoints).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeletionPlan {
    pub(crate) stream: StreamId,
    pub(crate) range: SeqRange,
    pub(crate) anchor_root: [u8; 32],
    pub(crate) anchor_signed_at: u64,
    pub(crate) days: u32,
}

impl DeletionPlan {
    /// Stream.
    pub fn stream(&self) -> StreamId {
        self.stream
    }
    /// Deleted range.
    pub fn range(&self) -> (u64, u64) {
        (self.range.first, self.range.last)
    }
    /// Retention period (days) the plan was made for.
    pub fn days(&self) -> u32 {
        self.days
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
    let cutoff = now
        .0
        .saturating_sub(u64::from(days).saturating_mul(MS_PER_DAY));
    let last = checkpoints
        .iter()
        .filter(|c| {
            let b = c.body();
            b.stream == stream
                && b.signed_at.0 <= cutoff
                && b.end_seq > first_retained
                && !b.is_empty()
        })
        .max_by_key(|c| c.body().end_seq);
    Ok(last.map(|c| DeletionPlan {
        stream,
        range: SeqRange {
            first: first_retained,
            last: c.body().end_seq.saturating_sub(1),
            origin: [0; 32],
        },
        anchor_root: c.body().merkle_root,
        anchor_signed_at: c.body().signed_at.0,
        days,
    }))
}

/// Apply a plan to a store after its tombstone was committed **and**
/// covered by a checkpoint (the verifier rejects the pruned prefix
/// otherwise).
pub fn apply_interval_deletion(
    store: &mut MemoryStore,
    plan: &DeletionPlan,
) -> Result<(), RetentionError> {
    if matches!(plan.stream, StreamId::Case | StreamId::CaseSlot) {
        return Err(RetentionError::CaseStream);
    }
    let tseq = store
        .records(plan.stream)
        .iter()
        .find(|r| match r.event() {
            AuditEvent::AuditRetentionTombstone { prune }
            | AuditEvent::SysRetentionTombstone { prune }
            | AuditEvent::SysSlotRetentionTombstone { prune } => {
                prune.stream == plan.stream
                    && prune.first == plan.range.first
                    && prune.last == plan.range.last
                    && prune.anchor_root == plan.anchor_root
            }
            _ => false,
        })
        .map(|r| r.header().seq)
        .ok_or(RetentionError::MissingTombstone)?;
    if tseq <= plan.range.last {
        return Err(RetentionError::MissingTombstone);
    }
    let cps = store.checkpoints(plan.stream);
    let whole = cps
        .iter()
        .any(|c| !c.body().is_empty() && c.body().end_seq.checked_sub(1) == Some(plan.range.last));
    if !whole {
        return Err(RetentionError::NotWholeInterval);
    }
    if !cps.iter().any(|c| c.body().end_seq > tseq) {
        return Err(RetentionError::TombstoneNotAttested);
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
