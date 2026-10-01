// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fail-closed conditions (04 §12.1 step 7, §12.6; ADR-030, ADR-036(6),
//! ADR-037(1), ADR-047(4); 07 BE-051, BE-056, BE-060; 08 API-036/039/058).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::sync::atomic::Ordering;

use candor_sealer::proto::*;
use candor_sealer::server::SnapshotError;
use common::*;

/// Open a session, draft, generate and confirm a passphrase.
async fn confirmed(f: &Fixture, s: SessionHandle, coi: Option<Coi>) {
    let sl = &f.sealer;
    ok(sl, Request::SessionOpen { sess: s, channel_id: CHANNEL }).await;
    ok(
        sl,
        Request::DraftSet(DraftSet {
            sess: s,
            mode: Mode::Anonymous,
            message: SecretText::new("report"),
            fields: vec![],
            identity: Some(SecretText::new("dropped in anonymous mode")),
            coi,
        }),
    )
    .await;
    let Response::Words { words, confirm_positions } = ok(sl, Request::GenAccount { sess: s }).await else {
        panic!()
    };
    let Response::Confirm { ok: true, .. } = ok(
        sl,
        Request::ConfirmPassphrase { sess: s, words: confirm_words(&words, confirm_positions) },
    )
    .await
    else {
        panic!()
    };
}

fn assert_nothing_written(f: &Fixture) {
    assert!(f.sink.envelopes().is_empty(), "an envelope was committed");
    assert!(read_all_files(&f.staging_path).is_empty(), "staging not empty");
}

#[tokio::test]
async fn coi_excluding_every_triage_member_redirects_to_alternative() {
    let f = fixture();
    let s = sess(1);
    // Flag labels 1 and 3, category excludes label 2 → nobody left (API-036).
    let coi = Coi {
        excluded_labels: zeroize::Zeroizing::new(vec![1, 3]),
        categories: zeroize::Zeroizing::new(vec![CATEGORY_FRAUD]),
    };
    confirmed(&f, s, Some(coi)).await;
    let r = f.sealer.handle(Request::SealFinish { sess: s, delayed_delivery: false }).await;
    assert_eq!(
        r,
        Response::Error { code: ErrorCode::NoEligibleTriage, alternative_channel_id: Some(ALT_CHANNEL) }
    );
    assert_nothing_written(&f);
    // The draft survives the refusal (the source is redirected, nothing is lost
    // silently) and can still be aborted.
    ok(&f.sealer, Request::SealAbort { sess: s }).await;
}

#[tokio::test]
async fn no_valid_member_epoch_key_fails_closed() {
    let f = fixture();
    let mut snap = f.snapshot.clone();
    snap.snapshot_version = 2;
    snap.tree_size += 1;
    for k in &mut snap.channels[0].meks {
        k.valid_until_day = TODAY; // expired today
    }
    f.sealer.install_snapshot(snap).unwrap();
    let s = sess(1);
    confirmed(&f, s, None).await;
    let r = f.sealer.handle(Request::SealFinish { sess: s, delayed_delivery: false }).await;
    assert_eq!(
        r,
        Response::Error { code: ErrorCode::NoEligibleTriage, alternative_channel_id: Some(ALT_CHANNEL) }
    );
    assert_nothing_written(&f);
}

#[tokio::test]
async fn stale_snapshot_fails_closed() {
    let f = fixture();
    // Checkpoint issued 7 days ago (KD_SNAPSHOT_MAX_AGE, ADR-047(4)).
    f.clock.day.store(TODAY + 7, Ordering::SeqCst);
    let s = sess(1);
    confirmed(&f, s, None).await;
    let r = f.sealer.handle(Request::SealFinish { sess: s, delayed_delivery: false }).await;
    assert_eq!(
        r,
        Response::Error { code: ErrorCode::Unavailable, alternative_channel_id: Some(ALT_CHANNEL) }
    );
    assert_nothing_written(&f);
    // Six days is still fresh enough to reach selection.
    f.clock.day.store(TODAY + 6, Ordering::SeqCst);
    let r = f.sealer.handle(Request::SealFinish { sess: s, delayed_delivery: false }).await;
    assert!(!matches!(r, Response::Error { code: ErrorCode::Unavailable, .. }), "{r:?}");
}

#[tokio::test]
async fn independent_time_failure_fails_closed() {
    let f = fixture();
    let s = sess(1);
    confirmed(&f, s, None).await;
    f.clock.fail.store(true, Ordering::SeqCst);
    let r = f.sealer.handle(Request::SealFinish { sess: s, delayed_delivery: false }).await;
    assert_eq!(r, Response::error(ErrorCode::Unavailable));
    assert_nothing_written(&f);
}

#[tokio::test]
async fn snapshot_rollback_and_suite_mismatch_rejected() {
    let f = fixture();
    let mut older = f.snapshot.clone();
    older.tree_size -= 1;
    assert_eq!(f.sealer.install_snapshot(older), Err(SnapshotError::Rollback));
    let mut older = f.snapshot.clone();
    older.issued_hour -= 1;
    assert_eq!(f.sealer.install_snapshot(older), Err(SnapshotError::Rollback));
    let mut fips = f.snapshot.clone();
    fips.suite = candor_core::Suite::CandorFips1;
    assert_eq!(f.sealer.install_snapshot(fips), Err(SnapshotError::Suite));
    // Restoring a persisted high-water mark also blocks the current snapshot's
    // predecessors.
    let hwm = f.sealer.high_water_mark();
    assert_eq!(hwm.tree_size, f.snapshot.tree_size);
}

#[tokio::test]
async fn seal_requires_confirmation_and_five_failures_zeroize() {
    let f = fixture();
    let s = sess(1);
    ok(&f.sealer, Request::SessionOpen { sess: s, channel_id: CHANNEL }).await;
    let r = f.sealer.handle(Request::SealFinish { sess: s, delayed_delivery: false }).await;
    assert_eq!(r, Response::error(ErrorCode::NotConfirmed));
    ok(&f.sealer, Request::GenAccount { sess: s }).await;
    let r = f.sealer.handle(Request::SealFinish { sess: s, delayed_delivery: false }).await;
    assert_eq!(r, Response::error(ErrorCode::NotConfirmed));
    let wrong = || SecretWords(zeroize::Zeroizing::new(vec![7777, 7777, 7777]));
    for i in 0..5 {
        let r = ok(&f.sealer, Request::ConfirmPassphrase { sess: s, words: wrong() }).await;
        let Response::Confirm { ok: false, confirm_positions } = r else { panic!() };
        assert_eq!(confirm_positions.is_none(), i == 4);
    }
    // Draft and passphrase are gone with the session (07 §5.2).
    let r = f.sealer.handle(Request::DraftGet { sess: s }).await;
    assert_eq!(r, Response::error(ErrorCode::UnknownSession));
    assert_nothing_written(&f);
}

#[tokio::test]
async fn regeneration_is_bounded() {
    let f = fixture();
    let s = sess(1);
    ok(&f.sealer, Request::SessionOpen { sess: s, channel_id: CHANNEL }).await;
    for _ in 0..5 {
        ok(&f.sealer, Request::GenAccount { sess: s }).await;
    }
    let r = f.sealer.handle(Request::GenAccount { sess: s }).await;
    assert_eq!(r, Response::error(ErrorCode::Limit));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn store_failure_commits_nothing_and_leaves_no_staged_ciphertext() {
    let f = fixture();
    let s = sess(1);
    ok(&f.sealer, Request::SessionOpen { sess: s, channel_id: CHANNEL }).await;
    let Response::Part { part } = ok(
        &f.sealer,
        Request::PartBegin {
            sess: s,
            declared_len: 10,
            display_name: SecretText::new("a.txt"),
            media_type: SecretText::new("text/plain"),
        },
    )
    .await
    else {
        panic!()
    };
    ok(&f.sealer, Request::PartChunk { sess: s, part, data: SecretBytes::from_slice(b"0123456789"), last: true }).await;
    let Response::Words { words, confirm_positions } = ok(&f.sealer, Request::GenAccount { sess: s }).await else {
        panic!()
    };
    ok(&f.sealer, Request::ConfirmPassphrase { sess: s, words: confirm_words(&words, confirm_positions) }).await;
    f.sink.fail.store(true, Ordering::SeqCst);
    let r = f.sealer.handle(Request::SealFinish { sess: s, delayed_delivery: false }).await;
    assert_eq!(r, Response::error(ErrorCode::Internal));
    assert!(f.sink.envelopes().is_empty());
    // Only the staged part remains (the sealed bundle file was removed).
    assert_eq!(read_all_files(&f.staging_path).len(), 1);
}

#[tokio::test]
async fn unknown_or_disabled_channel_and_bad_states() {
    let f = fixture();
    let r = f.sealer.handle(Request::SessionOpen { sess: sess(1), channel_id: [0x99; 16] }).await;
    assert_eq!(r, Response::error(ErrorCode::Unavailable));
    ok(&f.sealer, Request::SessionOpen { sess: sess(2), channel_id: CHANNEL }).await;
    // Duplicate handle.
    let r = f.sealer.handle(Request::SessionOpen { sess: sess(2), channel_id: CHANNEL }).await;
    assert_eq!(r, Response::error(ErrorCode::BadState));
    // Drafting sessions cannot sign, open replies or load prefs.
    let r = f.sealer.handle(Request::LoginSign { sess: sess(2), challenge: [0; 32] }).await;
    assert_eq!(r, Response::error(ErrorCode::BadState));
    let r = f.sealer.handle(Request::OpenReply { sess: sess(2), entry: vec![1, 2, 3] }).await;
    assert_eq!(r, Response::error(ErrorCode::BadState));
    let r = f.sealer.handle(Request::RotatePassphrase { sess: sess(2) }).await;
    assert_eq!(r, Response::error(ErrorCode::BadState));
    // Oversize part declaration.
    let r = f
        .sealer
        .handle(Request::PartBegin {
            sess: sess(2),
            declared_len: 5 << 30,
            display_name: SecretText::new("big"),
            media_type: SecretText::new("x"),
        })
        .await;
    assert_eq!(r, Response::error(ErrorCode::Limit));
    // Sending more than declared aborts the part.
    let Response::Part { part } = ok(
        &f.sealer,
        Request::PartBegin {
            sess: sess(2),
            declared_len: 4,
            display_name: SecretText::new("s"),
            media_type: SecretText::new("x"),
        },
    )
    .await
    else {
        panic!()
    };
    let r = f
        .sealer
        .handle(Request::PartChunk { sess: sess(2), part, data: SecretBytes::from_slice(b"12345"), last: true })
        .await;
    assert_eq!(r, Response::error(ErrorCode::Limit));
    assert!(read_all_files(&f.staging_path).is_empty());
    // Unknown session.
    let r = f.sealer.handle(Request::DraftGet { sess: sess(77) }).await;
    assert_eq!(r, Response::error(ErrorCode::UnknownSession));
}

#[tokio::test]
async fn session_capacity_gives_busy() {
    let limits = candor_sealer::server::Limits { max_sessions: 2, ..Default::default() };
    let f = fixture_with(
        candor_sealer::server::ChaffConfig { enabled: false, ..Default::default() },
        limits,
    );
    ok(&f.sealer, Request::SessionOpen { sess: sess(1), channel_id: CHANNEL }).await;
    ok(&f.sealer, Request::SessionOpen { sess: sess(2), channel_id: CHANNEL }).await;
    let r = f.sealer.handle(Request::SessionOpen { sess: sess(3), channel_id: CHANNEL }).await;
    assert_eq!(r, Response::error(ErrorCode::Busy));
    let r = f
        .sealer
        .handle(Request::LoginDerive { sess: sess(4), passphrase: SecretBytes::from_slice(b"x") })
        .await;
    assert_eq!(r, Response::error(ErrorCode::Busy));
}
