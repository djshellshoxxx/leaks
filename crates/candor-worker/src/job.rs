// SPDX-License-Identifier: AGPL-3.0-or-later

//! Job lease and retry-backoff rules (backend §6, BE-022).

/// Lease length granted on claim and on each renewal (backend §6: 5 minutes).
pub const LEASE_SECONDS: u64 = 300;

const BACKOFF_BASE_SECONDS: u64 = 30;
const BACKOFF_CAP_SECONDS: u64 = 6 * 60 * 60;
/// Shift at which `30 s << n` already exceeds the 6 h cap, so larger attempt
/// counts saturate instead of shifting further.
const BACKOFF_SATURATING_SHIFT: u32 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobState {
    Ready,
    Running,
    Dead,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobError {
    /// The job holds a live lease held by another runner.
    Leased,
    /// The job is, or has just become, `dead` (attempts exhausted).
    Dead,
    /// Renewal was attempted on a job that is not running.
    NotRunning,
    /// Renewal arrived after the lease expired; the job may already be reclaimed.
    LeaseExpired,
    /// A timestamp would overflow `u64`; the transition is refused.
    TimeOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Job {
    state: JobState,
    attempts: u32,
    max_attempts: u32,
    lease_until: Option<u64>,
}

impl Job {
    /// A new job in the `ready` state with no attempts made.
    #[must_use]
    pub const fn ready(max_attempts: u32) -> Self {
        Self {
            state: JobState::Ready,
            attempts: 0,
            max_attempts,
            lease_until: None,
        }
    }

    #[must_use]
    pub const fn state(&self) -> JobState {
        self.state
    }

    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    #[must_use]
    pub const fn lease_until(&self) -> Option<u64> {
        self.lease_until
    }

    /// Claims the job at time `now` (seconds). Succeeds when the job is `ready`,
    /// or `running` with an expired lease. Each successful claim increments
    /// `attempts` and sets a fresh five-minute lease. A job whose attempts are
    /// exhausted moves to `dead` and the claim is refused.
    pub fn claim(&mut self, now: u64) -> Result<(), JobError> {
        match self.state {
            JobState::Dead => return Err(JobError::Dead),
            JobState::Running if self.lease_is_live(now) => return Err(JobError::Leased),
            JobState::Running | JobState::Ready => {}
        }
        if self.attempts >= self.max_attempts {
            self.state = JobState::Dead;
            self.lease_until = None;
            return Err(JobError::Dead);
        }
        let until = now
            .checked_add(LEASE_SECONDS)
            .ok_or(JobError::TimeOverflow)?;
        let attempts = self.attempts.checked_add(1).ok_or(JobError::Dead)?;
        self.state = JobState::Running;
        self.attempts = attempts;
        self.lease_until = Some(until);
        Ok(())
    }

    /// Extends the lease to `now + 5 min`. Only valid while the lease is still
    /// live; a runner whose lease has lapsed must not reclaim silently.
    pub fn renew(&mut self, now: u64) -> Result<(), JobError> {
        if self.state != JobState::Running {
            return Err(JobError::NotRunning);
        }
        if !self.lease_is_live(now) {
            return Err(JobError::LeaseExpired);
        }
        let until = now
            .checked_add(LEASE_SECONDS)
            .ok_or(JobError::TimeOverflow)?;
        self.lease_until = Some(until);
        Ok(())
    }

    fn lease_is_live(&self, now: u64) -> bool {
        self.lease_until.is_some_and(|until| now < until)
    }
}

/// Un-jittered retry backoff in seconds: `min(2^attempts × 30 s, 6 h)`.
/// Callers apply the spec's ±20 % jitter on top of this value.
#[must_use]
pub fn base_backoff_seconds(attempts: u32) -> u64 {
    let shift = attempts.min(BACKOFF_SATURATING_SHIFT);
    BACKOFF_BASE_SECONDS
        .checked_shl(shift)
        .unwrap_or(u64::MAX)
        .min(BACKOFF_CAP_SECONDS)
}
