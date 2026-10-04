// SPDX-License-Identifier: AGPL-3.0-or-later

use candor_worker::{base_backoff_seconds, Job, JobError, JobState, RetentionAction, RetentionCase};

#[test]
fn st_rm3_job_claim_sets_five_minute_lease_and_increments_attempts() {
    let mut job = Job::ready(8);
    assert_eq!(job.claim(1_000), Ok(()));
    assert_eq!(job.state(), JobState::Running);
    assert_eq!(job.attempts(), 1);
    assert_eq!(job.lease_until(), Some(1_300));
}

#[test]
fn st_rm3_running_job_is_reclaimable_only_after_lease_expiry() {
    let mut job = Job::ready(8);
    assert_eq!(job.claim(1_000), Ok(()));
    assert_eq!(job.claim(1_299), Err(JobError::Leased));
    assert_eq!(job.claim(1_300), Ok(()));
    assert_eq!(job.attempts(), 2);
    assert_eq!(job.lease_until(), Some(1_600));
}

#[test]
fn st_rm3_job_renewal_extends_lease_by_five_minutes() {
    let mut job = Job::ready(8);
    assert_eq!(job.claim(1_000), Ok(()));
    assert_eq!(job.renew(1_060), Ok(()));
    assert_eq!(job.lease_until(), Some(1_360));
}

#[test]
fn st_rm3_retry_backoff_is_exponential_and_capped_at_six_hours() {
    assert_eq!(base_backoff_seconds(0), 30);
    assert_eq!(base_backoff_seconds(1), 60);
    assert_eq!(base_backoff_seconds(2), 120);
    assert_eq!(base_backoff_seconds(9), 15_360);
    assert_eq!(base_backoff_seconds(10), 21_600);
    assert_eq!(base_backoff_seconds(31), 21_600);
}

#[test]
fn st_rm3_exhausted_job_moves_to_dead_instead_of_running_forever() {
    let mut job = Job::ready(2);
    assert_eq!(job.claim(1_000), Ok(()));
    assert_eq!(job.claim(1_300), Ok(()));
    assert_eq!(job.claim(1_600), Err(JobError::Dead));
    assert_eq!(job.state(), JobState::Dead);
}

#[test]
fn st_rm3_retention_due_case_creates_proposal_never_silent_delete() {
    let due = RetentionCase {
        due: true,
        legal_hold: false,
        disposal_proposal_exists: false,
        auto_dispose_after_grace: false,
        grace_elapsed: false,
    };
    assert_eq!(due.evaluate(), RetentionAction::ProposeDisposal);
}

#[test]
fn st_rm3_legal_hold_always_blocks_retention_disposal() {
    let held = RetentionCase {
        due: true,
        legal_hold: true,
        disposal_proposal_exists: true,
        auto_dispose_after_grace: true,
        grace_elapsed: true,
    };
    assert_eq!(held.evaluate(), RetentionAction::Noop);
}

#[test]
fn st_rm3_auto_dispose_requires_explicit_option_and_grace() {
    let pending = RetentionCase {
        due: true,
        legal_hold: false,
        disposal_proposal_exists: true,
        auto_dispose_after_grace: false,
        grace_elapsed: true,
    };
    assert_eq!(pending.evaluate(), RetentionAction::Noop);

    let enabled = RetentionCase {
        auto_dispose_after_grace: true,
        ..pending
    };
    assert_eq!(enabled.evaluate(), RetentionAction::DisposeApprovedByPolicy);
}
