// SPDX-License-Identifier: AGPL-3.0-or-later
//! AUD-RM2-IPC-18 (auditor's P3, red → green): when the SIGTERM flush thread
//! fails after taking its batch, the sealer reports at least that batch as
//! lost and raises the backlog event; it never answers with a smaller number
//! or a clean stop. Own binary: the SIGTERM handler is process-wide.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use candor_sealer::proto::*;
use candor_sealer::server::sink::{
    AccountUpsert, EnvelopeGroup, EnvelopeSink, SinkError, UpsertError,
};
use candor_sealer::server::{ChaffConfig, HealthSink, Limits, ShutdownLoss};
use common::*;

/// Commits succeed; every account write panics (a sink bug or an unconfined
/// thread), so the flush thread dies with the batch taken.
struct PanickingSink;

impl EnvelopeSink for PanickingSink {
    fn commit_envelope_group(
        &self,
        _group: EnvelopeGroup,
        _epoch_id: u32,
        _received_day: u32,
        _release_offset_days: u8,
    ) -> Result<(), SinkError> {
        Ok(())
    }

    fn upsert_account(&self, _op: AccountUpsert) -> Result<(), UpsertError> {
        panic!("sink failure inside the flush thread (test)")
    }
}

#[derive(Default)]
struct Backlog {
    events: AtomicUsize,
    last: AtomicUsize,
}

impl HealthSink for Backlog {
    fn account_write_dropped(&self) {}

    fn account_backlog(&self, queued: usize) {
        self.events.fetch_add(1, Ordering::SeqCst);
        self.last.store(queued, Ordering::SeqCst);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flush_thread_failure_reports_at_least_the_taken_batch() {
    let f = fixture_with_sink(
        ChaffConfig {
            enabled: false,
            ..ChaffConfig::default()
        },
        Limits::default(),
        rustix_uid(),
        Some(Arc::new(PanickingSink)),
        |_| {},
    );
    let health = Arc::new(Backlog::default());
    f.sealer.set_health_sink(health.clone());
    for s in [sess(1), sess(3)] {
        confirmed(&f, s, None).await;
        assert!(matches!(
            f.sealer
                .handle(Request::SealFinish {
                    sess: s,
                    delayed_delivery: false,
                })
                .await,
            Response::Sealed { .. }
        ));
    }
    assert_eq!(f.sealer.queued_accounts(), 2);
    let task = f.sealer.spawn_sigterm_flush().unwrap();
    rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM)
        .unwrap();
    let Err(ShutdownLoss(lost)) = task.await.unwrap() else {
        panic!("a failed flush thread is never a clean stop")
    };
    assert!(lost >= 2, "at least the two taken creates, got {lost}");
    assert!(
        health.events.load(Ordering::SeqCst) >= 1,
        "backlog reported"
    );
    assert_eq!(health.last.load(Ordering::SeqCst), lost, "count only");
    assert!(f.sealer.is_stopping());
}
