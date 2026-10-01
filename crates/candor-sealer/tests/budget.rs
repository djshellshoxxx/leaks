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

fn limits(budget: u64, cap: u64, slots: u32) -> Limits {
    Limits {
        memory_budget_bytes: budget,
        per_session_upload_bytes: cap,
        upload_slots: slots,
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

async fn one_byte_part(f: &Fixture, s: SessionHandle) {
    let Response::Part { part } = begin(f, s, 1).await else {
        panic!("admission refused")
    };
    ok(
        &f.sealer,
        Request::PartChunk {
            sess: s,
            part,
            data: SecretBytes::from_slice(&[1]),
            last: true,
        },
    )
    .await;
}

/// SEA-31 PoC: holders of 1-byte parts, kept alive with TOUCH, take only
/// their own slots (64 by default) and do not block admission.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tiny_part_holders_do_not_block_admission() {
    let f = fixture_with(no_chaff(), Limits::default());
    for i in 0..10u8 {
        open(&f, sess(10 + i)).await;
        one_byte_part(&f, sess(10 + i)).await;
        ok(&f.sealer, Request::Touch { sess: sess(10 + i) }).await;
    }
    open(&f, sess(99)).await;
    assert!(matches!(
        begin(&f, sess(99), 1_000_000).await,
        Response::Part { .. }
    ));
    assert!(f.sealer.memory_reserved() <= Limits::default().memory_budget_bytes);
}

/// SEA-31: within its guaranteed slice a draft never gets BUSY, even with
/// every slot taken and the shared pool exhausted; beyond the slice the
/// shared pool answers BUSY when exhausted and recovers once the holder's
/// idle part is aborted (120 s).
#[tokio::test(start_paused = true)]
async fn slices_never_busy_and_the_shared_pool_recovers() {
    // 16 MiB: 8 MiB guaranteed for 2 slots (4 MiB slices), 8 MiB shared.
    let f = fixture_with(no_chaff(), limits(16 * MIB, 8 * MIB, 2));
    for i in 1..=3u8 {
        open(&f, sess(i)).await;
    }
    // A: small part in its slice. B: a large part, mostly from the pool.
    one_byte_part(&f, sess(1)).await;
    assert!(matches!(
        begin(&f, sess(2), 5 * MIB).await,
        Response::Part { .. }
    ));
    // Both slots taken: admission BUSY for C.
    assert_eq!(
        begin(&f, sess(3), 1).await,
        Response::error(ErrorCode::Busy)
    );
    // A keeps uploading within its slice: never BUSY.
    for _ in 0..5 {
        let Response::Part { part } = begin(&f, sess(1), MIB).await else {
            panic!("within-slice upload refused")
        };
        drop_part(&f, sess(1), part).await;
    }
    // Beyond its slice, A needs the shared pool, which B holds: BUSY.
    assert_eq!(
        begin(&f, sess(1), 3 * MIB).await,
        Response::error(ErrorCode::Busy)
    );
    // Above slice + per-draft cap: LIMIT, whatever the pool holds.
    assert_eq!(
        begin(&f, sess(1), 7 * MIB).await,
        Response::error(ErrorCode::Limit)
    );
    assert!(f.sealer.memory_reserved() <= 16 * MIB);
    // B's part receives nothing; after 120 s it is aborted, its slot and pool
    // reservation are released, and both A and C proceed.
    tokio::time::advance(std::time::Duration::from_secs(121)).await;
    f.sealer.reap_expired();
    assert!(matches!(
        begin(&f, sess(1), 3 * MIB).await,
        Response::Part { .. }
    ));
    assert!(matches!(begin(&f, sess(3), 1).await, Response::Part { .. }));
    for i in 1..=3u8 {
        ok(&f.sealer, Request::Zeroize { sess: sess(i) }).await;
    }
    assert_eq!(f.sealer.memory_reserved(), 0);
}

/// Sealing within the budget succeeds (never refused for memory), frees the
/// staged part, and releases the reservation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sealing_frees_parts_and_releases_the_reservation() {
    let f = fixture_with(no_chaff(), limits(64 * MIB, 8 * MIB, 4));
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
    let f = fixture_with(no_chaff(), limits(64 * MIB, 8 * MIB, 4));
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
