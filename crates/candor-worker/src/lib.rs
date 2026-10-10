// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]

//! Candor fixed-schedule core worker and retention engine.
//! Developed test-first from backend §6 and data-retention §5.3.

mod job;
mod retention;

pub use job::{Job, JobError, JobState, LEASE_SECONDS, base_backoff_seconds};
pub use retention::{RetentionAction, RetentionCase};
