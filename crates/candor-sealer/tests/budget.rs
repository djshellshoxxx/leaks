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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_large_sessions_cannot_exceed_the_budget() {
    let budget = 12 * MIB;
    let f = fixture_with(
        ChaffConfig {
            enabled: false,
            ..ChaffConfig::default()
        },
        Limits {
            memory_budget_bytes: budget,
            ..Limits::default()
        },
    );
    // 16 sessions each try to start a 2 MiB upload at the same time.
    for i in 0..16u8 {
        ok(
            &f.sealer,
            Request::SessionOpen {
                sess: sess(10 + i),
                channel_id: CHANNEL,
            },
        )
        .await;
    }
    let mut tasks = Vec::new();
    for i in 0..16u8 {
        let s = f.sealer.clone();
        tasks.push(tokio::spawn(async move {
            s.handle(Request::PartBegin {
                sess: sess(10 + i),
                declared_len: 2 * MIB,
                display_name: SecretText::new("f.bin"),
                media_type: SecretText::new("application/octet-stream"),
            })
            .await
        }));
    }
    let mut granted = Vec::new();
    let mut busy = 0;
    for (i, t) in tasks.into_iter().enumerate() {
        match t.await.unwrap() {
            Response::Part { .. } => granted.push(i as u8),
            r if r == Response::error(ErrorCode::Busy) => busy += 1,
            r => panic!("unexpected {r:?}"),
        }
        assert!(f.sealer.memory_reserved() <= budget);
    }
    assert!(
        !granted.is_empty() && busy > 0,
        "{} granted, {busy} busy",
        granted.len()
    );
    assert!(f.sealer.memory_reserved() <= budget);
    let s0 = sess(10 + granted[0]);
    // Releasing a session's draft frees its reservation for a waiting one.
    let before = f.sealer.memory_reserved();
    ok(&f.sealer, Request::SealAbort { sess: s0 }).await;
    assert!(f.sealer.memory_reserved() < before);
    let waiting = (0..16u8).find(|i| !granted.contains(i)).unwrap();
    assert!(matches!(
        begin(&f, sess(10 + waiting), 2 * MIB).await,
        Response::Part { .. }
    ));
    assert!(f.sealer.memory_reserved() <= budget);
    // A single upload larger than the budget can ever cover is BUSY, not an
    // out-of-memory kill.
    ok(
        &f.sealer,
        Request::SessionOpen {
            sess: sess(99),
            channel_id: CHANNEL,
        },
    )
    .await;
    assert_eq!(
        begin(&f, sess(99), 8 * MIB).await,
        Response::error(ErrorCode::Busy)
    );
    // Zeroizing every session returns the budget to zero.
    for i in 0..16u8 {
        ok(&f.sealer, Request::Zeroize { sess: sess(10 + i) }).await;
    }
    ok(&f.sealer, Request::Zeroize { sess: sess(99) }).await;
    assert_eq!(f.sealer.memory_reserved(), 0);
}

/// Sealing within the budget succeeds (never refused for memory), frees the
/// staged part, and releases the reservation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sealing_frees_parts_and_releases_the_reservation() {
    let f = fixture_with(
        ChaffConfig {
            enabled: false,
            ..ChaffConfig::default()
        },
        Limits {
            memory_budget_bytes: 4 * MIB,
            ..Limits::default()
        },
    );
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
