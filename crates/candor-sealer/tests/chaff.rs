// SPDX-License-Identifier: AGPL-3.0-or-later
//! Chaff envelopes (04 §12.7, ADR-047(3), 07 §5.2a, BE-075): same format and
//! write path as real envelopes, all-dummy slots, chaff-kind disposition
//! marker, Poisson schedule, cancellation by real commits.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::time::Duration;

use candor_core::Suite;
use candor_core::header::{CoreHeader, ObjectType};
use candor_core::slots::{SLOT_BLOCK_LEN, SlotContext};
use candor_core::{kem, labels, object, padding, stream};
use candor_sealer::proto::*;
use candor_sealer::server::{ChaffConfig, Limits};
use common::*;

fn chaff_cfg(share: u16, mean: Duration, enabled: bool) -> ChaffConfig {
    ChaffConfig {
        enabled,
        mean_interval: mean,
        followup_share_permille: share,
        ..ChaffConfig::default()
    }
}

fn disposition_kind(f: &Fixture, env: &StoredEnvelope) -> u8 {
    let info = [
        labels::WRAP_DISPOSITION,
        &Suite::CandorStd1.to_be_bytes(),
        &TENANT,
    ]
    .concat();
    let d = &env.disposition_ct;
    let pt = kem::open_base(
        &f.disposition.private,
        &d[..1120],
        &info,
        &env.objects[0].object_hash,
        &d[1120..],
    )
    .unwrap();
    pt[0]
}

/// Structural view of an object as the store, relay or a Desk without keys sees it.
fn shape(o: &StoredObject) -> (ObjectType, [u8; 16], [u8; 16], u32, u64, usize) {
    let h = CoreHeader::decode(&o.bytes[..128]).unwrap();
    let parsed = object::parse(&o.bytes).unwrap();
    let block = candor_core::slots::RecipientSlotBlock::decode(&o.slot_block).unwrap();
    parsed.check_slot_block(&block).unwrap();
    assert_eq!(o.slot_block.len(), SLOT_BLOCK_LEN);
    assert!(padding::is_legal_bucket(
        h.object_type,
        h.padded_plaintext_len
    ));
    assert_eq!(
        o.bytes.len() as u64,
        160 + stream::ciphertext_len(h.padded_plaintext_len).unwrap()
    );
    assert_eq!(h.day_stamp, 0);
    (
        h.object_type,
        h.tenant_id,
        h.channel_id,
        h.epoch_id,
        h.padded_plaintext_len,
        o.slot_block.len(),
    )
}

async fn real_anonymous_submission(f: &Fixture) {
    let s = sess(1);
    ok(
        &f.sealer,
        Request::SessionOpen {
            sess: s,
            channel_id: CHANNEL,
        },
    )
    .await;
    ok(
        &f.sealer,
        Request::DraftSet(DraftSet {
            sess: s,
            mode: Mode::Anonymous,
            message: SecretText::new("short report"),
            fields: vec![],
            identity: None,
            coi: None,
        }),
    )
    .await;
    let Response::Words {
        words,
        confirm_positions,
    } = ok(&f.sealer, Request::GenAccount { sess: s }).await
    else {
        panic!()
    };
    ok(
        &f.sealer,
        Request::ConfirmPassphrase {
            sess: s,
            words: confirm_words(&words, confirm_positions),
        },
    )
    .await;
    ok(
        &f.sealer,
        Request::SealFinish {
            sess: s,
            delayed_delivery: false,
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chaff_triple_is_structurally_identical_to_a_real_submission() {
    let f = fixture_with(
        chaff_cfg(0, Duration::from_secs(7200), false),
        Limits::default(),
    );
    real_anonymous_submission(&f).await;
    f.sealer.chaff_event(CHANNEL).await.unwrap();
    let envs = f.sink.envelopes();
    let (real, chaff) = (&envs[0], &envs[1]);
    assert_eq!(real.objects.len(), 3);
    assert_eq!(chaff.objects.len(), 3);
    for (r, c) in real.objects.iter().zip(&chaff.objects) {
        let (rt, rten, rch, rep, _, rsl) = shape(r);
        let (ct, cten, cch, cep, clen, csl) = shape(c);
        assert_eq!((rt, rten, rch, rep, rsl), (ct, cten, cch, cep, csl));
        if ct == ObjectType::AttachmentBundle {
            assert!(clen <= 8 << 20, "chaff bundles ≤ 8 MiB");
        }
        if ct == ObjectType::Identity {
            assert_eq!(clen, padding::IDENTITY_MAX, "identity at max bucket");
        }
        if ct == ObjectType::Submission {
            assert_eq!(clen, padding::MESSAGE_MAX, "submission at max bucket");
        }
    }
    // The store receives the same operations and fields (ADR-052(2)): an account
    // upsert (a dummy one for chaff) and then the group, with no account
    // reference on the group; same epoch and day.
    assert_eq!(f.sink.ops(), "AGAG");
    let accts = f.sink.accounts();
    assert_eq!(accts.len(), 2);
    let (ra, ca) = (&accts[0], &accts[1]);
    assert!(ra.replaces.is_none() && ca.replaces.is_none());
    assert_eq!(ra.account.prefs_ct.len(), ca.account.prefs_ct.len());
    assert_eq!(ra.account.mailbox_ids.len(), ca.account.mailbox_ids.len());
    assert_ne!(ra.account.lookup_tag, ca.account.lookup_tag);
    assert!(ca.rewrapped_replies.is_empty());
    assert_eq!(
        (chaff.epoch_id, chaff.received_day),
        (real.epoch_id, real.received_day)
    );
    assert!(chaff.release_offset_days <= 3);
    assert_eq!(chaff.channel_id, real.channel_id);
    assert_eq!(chaff.disposition_ct.len(), real.disposition_ct.len());
    assert_eq!(chaff.disposition_ct.len(), 1120 + 48);
    // No Triage Set member (nor the custodian) can open any chaff slot.
    for (i, o) in chaff.objects.iter().enumerate() {
        let ctx = if i == 2 {
            SlotContext::Custodian { tenant_id: TENANT }
        } else {
            member_ctx(0)
        };
        for m in &f.members {
            assert!(open_intake(o, ctx.clone(), &m.mek.private).is_none());
        }
        assert!(open_intake(o, ctx, &f.custodian.private).is_none());
    }
    // Only K41 tells them apart (04 §12.7).
    assert_eq!(disposition_kind(&f, real), 0);
    assert_eq!(disposition_kind(&f, chaff), 1);
    // Every slot block is unique (fresh object ids, CKs from the chaff seed).
    let mut blocks: Vec<&Vec<u8>> = envs
        .iter()
        .flat_map(|e| e.objects.iter().map(|o| &o.slot_block))
        .collect();
    blocks.sort();
    blocks.dedup();
    assert_eq!(blocks.len(), 6);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chaff_follow_up_matches_source_message_shape() {
    let f = fixture_with(
        chaff_cfg(1000, Duration::from_secs(7200), false),
        Limits::default(),
    );
    for _ in 0..3 {
        f.sealer.chaff_event(CHANNEL).await.unwrap();
    }
    for env in f.sink.envelopes() {
        assert_eq!(env.objects.len(), 3);
        let (t, ten, ch, ep, len, _) = shape(&env.objects[0]);
        assert_eq!(
            (t, ten, ch, ep),
            (ObjectType::SourceMessage, TENANT, CHANNEL, 0)
        );
        assert_eq!(len, padding::MESSAGE_MAX);
        assert_eq!(shape(&env.objects[1]).0, ObjectType::AttachmentBundle);
        let (it, _, _, _, ilen, _) = shape(&env.objects[2]);
        assert_eq!((it, ilen), (ObjectType::Identity, padding::IDENTITY_MAX));
        assert_eq!(disposition_kind(&f, &env), 1);
    }
    // Follow-up-shaped chaff writes no account (real follow-ups do not either).
    assert_eq!(f.sink.ops(), "GGG");
    assert!(read_all_files(&f.staging_path).is_empty());
}

/// NOTE_REAL is refused unless explicitly enabled (AUD-RM2-SEA-12).
#[tokio::test]
async fn note_real_disabled_by_default() {
    let f = fixture();
    let r = f
        .sealer
        .handle(Request::NoteReal {
            channel_id: CHANNEL,
            first_object_hash: [1; 32],
        })
        .await;
    assert_eq!(r, Response::error(ErrorCode::BadState));
}

/// Chaff delivery delays follow the configured share (ADR-052(2)): with share
/// 1000 every chaff group is delayed U{1,2,3}; with 0 none is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chaff_delay_follows_real_distribution() {
    for (share, delayed) in [(1000u16, true), (0, false)] {
        let f = fixture_with(
            ChaffConfig {
                enabled: false,
                followup_share_permille: 1000,
                delayed_share_permille: share,
                ..ChaffConfig::default()
            },
            Limits::default(),
        );
        for _ in 0..12 {
            f.sealer.chaff_event(CHANNEL).await.unwrap();
        }
        for env in f.sink.envelopes() {
            if delayed {
                assert!((1..=3).contains(&env.release_offset_days));
            } else {
                assert_eq!(env.release_offset_days, 0);
            }
        }
    }
}

/// Chaff is skipped on exactly the conditions under which real sealing refuses
/// (AUD-RM2-SEA-15): stale snapshot, disabled channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chaff_gated_like_real_sealing() {
    let f = fixture_with(
        chaff_cfg(0, Duration::from_secs(7200), false),
        Limits::default(),
    );
    f.clock
        .day
        .store(TODAY + 7, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        f.sealer.chaff_event(CHANNEL).await,
        Err(ErrorCode::Unavailable)
    );
    f.clock
        .day
        .store(TODAY, std::sync::atomic::Ordering::SeqCst);
    let mut snap = f.snapshot.clone();
    snap.snapshot_version = 2;
    snap.channels[0].enabled = false;
    f.install(snap).unwrap();
    assert_eq!(
        f.sealer.chaff_event(CHANNEL).await,
        Err(ErrorCode::Unavailable)
    );
    assert!(f.sink.envelopes().is_empty() && f.sink.accounts().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chaff_fails_closed_without_time_or_directory() {
    let f = fixture_with(
        chaff_cfg(0, Duration::from_secs(7200), false),
        Limits::default(),
    );
    f.clock
        .fail
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        f.sealer.chaff_event(CHANNEL).await,
        Err(ErrorCode::Unavailable)
    );
    f.clock
        .fail
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        f.sealer.chaff_event([0x99; 16]).await,
        Err(ErrorCode::Unavailable)
    );
    f.sink.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        f.sealer.chaff_event(CHANNEL).await,
        Err(ErrorCode::Internal)
    );
    assert!(
        read_all_files(&f.staging_path).is_empty(),
        "failed chaff left staged data"
    );
    // An account-write failure also leaves nothing behind.
    f.sink
        .fail
        .store(false, std::sync::atomic::Ordering::SeqCst);
    f.sink
        .fail_accounts
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        f.sealer.chaff_event(CHANNEL).await,
        Err(ErrorCode::Internal)
    );
    assert!(f.sink.envelopes().is_empty());
    assert!(read_all_files(&f.staging_path).is_empty());
}

#[tokio::test(start_paused = true)]
async fn poisson_schedule_runs_and_real_commits_cancel_events() {
    let mut f = fixture_with(
        chaff_cfg(1000, Duration::from_secs(600), true),
        Limits::default(),
    );
    // NOTE_REAL is off by default (AUD-RM2-SEA-12); this test enables it.
    let mut cfg = config(
        chaff_cfg(1000, Duration::from_secs(600), true),
        Limits::default(),
        rustix_uid(),
    );
    cfg.enable_note_real = true;
    f.sealer = candor_sealer::server::Sealer::new(
        cfg,
        candor_core::sig::SigningKey::from_seed(&f.k35),
        f.staging,
        f.clock.clone(),
        f.sink.clone(),
    )
    .unwrap();
    f.sealer
        .install_snapshot(signed_bundle(f.snapshot.clone(), 0), |_| true)
        .unwrap();
    let tasks = f.sealer.spawn_background();
    // 4 hours at a mean of 10 minutes: ~24 events.
    for _ in 0..240 {
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let n = f.sink.envelopes().len();
    assert!(
        (6..=60).contains(&n),
        "{n} chaff events in 4 h at mean 10 min"
    );
    // Each Tier V NOTE_REAL cancels the next chaff event (cap 64 pending).
    for _ in 0..64 {
        let r = f
            .sealer
            .handle(Request::NoteReal {
                channel_id: CHANNEL,
                first_object_hash: [1; 32],
            })
            .await;
        assert!(matches!(r, Response::Disposition { .. }));
    }
    for _ in 0..60 {
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(
        f.sink.envelopes().len(),
        n,
        "cancelled events must not write"
    );
    for t in tasks {
        t.abort();
    }
}
