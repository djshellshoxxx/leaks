// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Normalized slot times for file timestamps (ADR-038(1), DB-028).

use crate::SafeFsError;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Granularity every slot time must be aligned to (15 minutes).
pub const SLOT_GRANULARITY_SECS: u64 = 900;

/// A coarse, caller-provided timestamp (import slot start or UTC day start)
/// that is written as atime and mtime of every object and of the directories
/// touched, so timestamps reveal only the schedule slot (ADR-038(1)).
///
/// Construction rejects values that are not a multiple of
/// [`SLOT_GRANULARITY_SECS`], so a raw "now" cannot be passed by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotTime(u64);

impl SlotTime {
    /// Builds a slot time from Unix seconds; must be aligned to 15 minutes.
    pub fn from_unix_secs(secs: u64) -> Result<Self, SafeFsError> {
        if secs.is_multiple_of(SLOT_GRANULARITY_SECS) {
            Ok(Self(secs))
        } else {
            Err(SafeFsError::InvalidSlotTime)
        }
    }

    /// 00:00 UTC of the day containing `secs` (intake `received_date`, 07 §4).
    pub fn utc_day_start(secs: u64) -> Self {
        Self(secs.saturating_sub(secs % 86_400))
    }

    /// Unix seconds.
    pub fn unix_secs(self) -> u64 {
        self.0
    }

    pub(crate) fn system_time(self) -> SystemTime {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(self.0))
            .unwrap_or(UNIX_EPOCH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unaligned() {
        assert!(SlotTime::from_unix_secs(1_700_000_001).is_err());
        assert!(SlotTime::from_unix_secs(1_699_999_200).is_ok());
        assert_eq!(SlotTime::utc_day_start(86_400 * 3 + 5).unix_secs(), 86_400 * 3);
    }
}
