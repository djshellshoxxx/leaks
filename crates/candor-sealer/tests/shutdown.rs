// SPDX-License-Identifier: AGPL-3.0-or-later
//! AUD-RM2-SEA-28(c): on SIGTERM the sealer writes every queued account
//! operation as one shuffled batch, padded with dummy accounts. Own binary:
//! the SIGTERM handler is process-wide.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use candor_sealer::proto::*;
use common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigterm_flushes_the_queue_with_dummies() {
    let f = fixture();
    let s = sess(1);
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
    assert_eq!(f.sealer.queued_accounts(), 1);
    assert!(f.sink.accounts().is_empty());
    let task = f.sealer.spawn_sigterm_flush().unwrap();
    // The handler is installed: SIGTERM no longer terminates the process.
    rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM)
        .unwrap();
    let n = task.await.unwrap().unwrap();
    assert!(
        (2..=5).contains(&n),
        "real account plus 1..=4 dummies, got {n}"
    );
    let accts = f.sink.accounts();
    assert_eq!(accts.len(), n);
    assert!(accts.iter().all(|a| a.replaces.is_none()));
    let len = accts[0].account.prefs_ct.len();
    assert!(accts.iter().all(|a| a.account.prefs_ct.len() == len));
    assert_eq!(f.sealer.queued_accounts(), 0);
    assert_eq!(f.sink.ops(), format!("G{}", "A".repeat(n)));
}
