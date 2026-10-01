// SPDX-License-Identifier: AGPL-3.0-or-later
//! AUD-RM2-SEA-26: sealer-wide memory admission for attachments. Concurrent
//! large sessions never reserve more than the configured budget; uploads that
//! do not fit get the uniform BUSY; sealing itself is never refused for
//! memory and frees each staged part as it is written into the bundle.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use candor_sealer::proto::*;
use candor_sealer::server::{ChaffConfig, Limits};
use common::*;

const MIB: u64 = 1 << 20;

async fn begin(f: &Fixture, s: SessionHandle, len: u64) -> Response {
    f.sealer
        .handle(Request::PartBegin {
            sess: s,
            declared_len: len,
            display_name: SecretText::new("f.bin"),
            media_type: SecretText::new("application/octet-stream"),
        })
        .await
}

fn limits(budget: u64, quota: u64) -> Limits {
    Limits {
        memory_budget_bytes: budget,
        per_session_upload_bytes: quota,
        ..Limits::default()
    }
}

fn no_chaff() -> ChaffConfig {
    ChaffConfig {
        enabled: false,
        ..ChaffConfig::default()
    }
}

async fn open(f: &Fixture, s: SessionHandle) {
    ok(
        &f.sealer,
        Request::SessionOpen {
            sess: s,
            channel_id: CHANNEL,
        },
    )
    .await;
}

async fn drop_part(f: &Fixture, s: SessionHandle, part: [u8; 16]) {
    ok(&f.sealer, Request::PartDrop { sess: s, part }).await;
}

/// SEA-29: drafts are admitted with a fixed quota (session-level BUSY when
/// none is free); within its own quota a draft never gets BUSY, whatever the
/// other sessions do — only LIMIT when its own attachments exceed the quota.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_session_quotas_bound_memory_and_never_depend_on_others() {
    let (budget, quota) = (24 * MIB, 8 * MIB);
    let f = fixture_with(no_chaff(), limits(budget, quota));
    for i in 0..8u8 {
        open(&f, sess(10 + i)).await;
    }
    // 8 sessions start an upload concurrently: exactly budget / quota = 3 are
    // admitted, the rest get the session-level BUSY.
    let mut tasks = Vec::new();
    for i in 0..8u8 {
        let s = f.sealer.clone();
        tasks.push(tokio::spawn(async move {
            s.handle(Request::PartBegin {
                sess: sess(10 + i),
                declared_len: MIB,
                display_name: SecretText::new("f.bin"),
                media_type: SecretText::new("application/octet-stream"),
            })
            .await
        }));
    }
    let mut admitted = Vec::new();
    for (i, t) in tasks.into_iter().enumerate() {
        match t.await.unwrap() {
            Response::Part { part } => admitted.push((10 + i as u8, part)),
            r => assert_eq!(r, Response::error(ErrorCode::Busy)),
        }
        assert!(f.sealer.memory_reserved() <= budget);
    }
    assert_eq!(admitted.len(), 3);
    assert_eq!(f.sealer.memory_reserved(), 3 * quota);
    // With the budget exhausted by others, an admitted draft keeps uploading
    // within its own quota: never BUSY.
    let (a, part) = admitted[0];
    drop_part(&f, sess(a), part).await;
    for _ in 0..5 {
        let Response::Part { part } = begin(&f, sess(a), 2 * MIB).await else {
            panic!("own-quota upload refused")
        };
        drop_part(&f, sess(a), part).await;
    }
    // Over its own quota: LIMIT, independent of others.
    assert_eq!(
        begin(&f, sess(a), 6 * MIB).await,
        Response::error(ErrorCode::Limit)
    );
    // An admitted draft's answers are the same with or without other drafts.
    let (b, part_b) = admitted[1];
    ok(&f.sealer, Request::SealAbort { sess: sess(b) }).await;
    let _ = part_b;
    assert_eq!(
        begin(&f, sess(a), 6 * MIB).await,
        Response::error(ErrorCode::Limit)
    );
    // The freed quota admits a waiting draft.
    let waiting = (10..18u8)
        .find(|i| !admitted.iter().any(|(x, _)| x == i))
        .unwrap();
    assert!(matches!(
        begin(&f, sess(waiting), MIB).await,
        Response::Part { .. }
    ));
    assert!(f.sealer.memory_reserved() <= budget);
    // Dropping the draft's only part releases its quota.
    let before = f.sealer.memory_reserved();
    let (c, part_c) = admitted[2];
    drop_part(&f, sess(c), part_c).await;
    assert_eq!(f.sealer.memory_reserved(), before - quota);
    for i in 0..8u8 {
        ok(&f.sealer, Request::Zeroize { sess: sess(10 + i) }).await;
    }
    assert_eq!(f.sealer.memory_reserved(), 0);
}

/// SEA-29: two stalled uploads do not block a third source for long: a part
/// with no bytes for 120 s is aborted and its draft's quota released.
#[tokio::test(start_paused = true)]
async fn stalled_sessions_do_not_block_a_third() {
    let quota = 8 * MIB;
    let f = fixture_with(no_chaff(), limits(2 * quota, quota));
    for i in 1..=3u8 {
        open(&f, sess(i)).await;
    }
    for i in 1..=2u8 {
        assert!(matches!(
            begin(&f, sess(i), MIB).await,
            Response::Part { .. }
        ));
    }
    assert_eq!(
        begin(&f, sess(3), MIB).await,
        Response::error(ErrorCode::Busy)
    );
    // Neither admitted source sends a byte.
    tokio::time::advance(std::time::Duration::from_secs(119)).await;
    f.sealer.reap_expired();
    assert_eq!(
        begin(&f, sess(3), MIB).await,
        Response::error(ErrorCode::Busy)
    );
    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    f.sealer.reap_expired();
    // Both stalled parts are aborted (no bytes for 120 s) and their quotas
    // released: the third source is admitted.
    assert_eq!(f.sealer.memory_reserved(), 0);
    assert!(matches!(
        begin(&f, sess(3), MIB).await,
        Response::Part { .. }
    ));
    assert_eq!(
        read_all_files(&f.staging_path).len(),
        1,
        "only the new upload's file; the stalled parts left nothing"
    );
}

/// Sealing within the budget succeeds (never refused for memory), frees the
/// staged part, and releases the reservation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sealing_frees_parts_and_releases_the_reservation() {
    let f = fixture_with(no_chaff(), limits(4 * MIB, 4 * MIB));
    let s = sess(1);
    confirmed(&f, s, None).await;
    let Response::Part { part } = begin(&f, s, 300_000).await else {
        panic!()
    };
    ok(
        &f.sealer,
        Request::PartChunk {
            sess: s,
            part,
            data: SecretBytes::from_slice(&[7u8; 50_000]),
            last: true,
        },
    )
    .await;
    assert!(f.sealer.memory_reserved() > 0);
    assert_eq!(read_all_files(&f.staging_path).len(), 1);
    let r = f
        .sealer
        .handle(Request::SealFinish {
            sess: s,
            delayed_delivery: false,
        })
        .await;
    assert!(matches!(r, Response::Sealed { .. }), "{r:?}");
    assert!(read_all_files(&f.staging_path).is_empty());
    assert_eq!(f.sealer.memory_reserved(), 0);
    let env = &f.sink.envelopes()[0];
    assert!(
        env.objects[1].bytes.len() > 50_000,
        "bundle carries the part"
    );
}

/// Round-4 Info: a store known to be down fails the seal with the uniform
/// INTERNAL before any part is consumed; the draft keeps its attachment.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn known_store_outage_keeps_the_attachments() {
    let f = fixture_with(no_chaff(), limits(4 * MIB, 4 * MIB));
    let s = sess(1);
    confirmed(&f, s, None).await;
    let Response::Part { part } = begin(&f, s, 1_000).await else {
        panic!()
    };
    ok(
        &f.sealer,
        Request::PartChunk {
            sess: s,
            part,
            data: SecretBytes::from_slice(&[1u8; 1_000]),
            last: true,
        },
    )
    .await;
    f.sink
        .unavailable
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let seal = Request::SealFinish {
        sess: s,
        delayed_delivery: false,
    };
    assert_eq!(
        f.sealer.handle(seal.clone()).await,
        Response::error(ErrorCode::Internal)
    );
    assert_eq!(read_all_files(&f.staging_path).len(), 1, "part kept");
    f.sink
        .unavailable
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(
        f.sealer.handle(seal).await,
        Response::Sealed { .. }
    ));
    assert!(f.sink.envelopes()[0].objects[1].bytes.len() > 1_000);
}
