// SPDX-License-Identifier: AGPL-3.0-or-later
//! `SEAL_SIGNAL`, `DELETE_REPLIES` and `CLOSE_MAILBOX` (07 §5.2 0x26, BE-078;
//! 08 SW-14/SW-15, API-055; 04 §13.4 kinds 2/3): signal envelopes have the
//! shape of every follow-up, carry an empty message, are sealed to the
//! original eligible set with the MEKs of the epoch containing the release
//! day, and the mailbox-closed signal is committed **before** the deletion.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use candor_sealer::proto::*;
use candor_sealer::server::{ChaffConfig, Limits};
use common::kdlog::MemberEpochKey;
use common::*;

/// A fixture whose Triage Set members have MEKs for epochs 0..=3, so a
/// release day up to 21 days ahead has a pre-published key.
fn fixture_epochs() -> Fixture {
    fixture_custom(
        ChaffConfig {
            enabled: false,
            ..ChaffConfig::default()
        },
        Limits::default(),
        rustix_uid(),
        |snap| {
            let ch = &mut snap.channels[0];
            let base: Vec<MemberEpochKey> = ch.meks.clone();
            for e in 1..=3u32 {
                for k in &base {
                    ch.meks.push(MemberEpochKey {
                        epoch_id: e,
                        valid_from_day: TODAY - 2 + 7 * e,
                        valid_until_day: TODAY - 2 + 7 * (e + 1),
                        ..k.clone()
                    });
                }
            }
        },
    )
}

/// New account, one submission without attachment, account flushed; then a
/// logged-in session `l`. Returns the account's lookup tag.
async fn submit_and_login(f: &Fixture, s: SessionHandle, l: SessionHandle) -> [u8; 32] {
    ok(
        &f.sealer,
        Request::Hello {
            proto: PROTO_VERSION,
        },
    )
    .await;
    confirmed(f, s, None).await;
    let Response::Sealed { .. } = ok(
        &f.sealer,
        Request::SealFinish {
            sess: s,
            delayed_delivery: false,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(f.sealer.flush_accounts(), Ok(1));
    let words = words_of(f, s).await;
    let Response::Locator { lookup_tag } = ok(
        &f.sealer,
        Request::LoginDerive {
            sess: l,
            passphrase: SecretBytes::from_slice(words.as_bytes()),
        },
    )
    .await
    else {
        panic!()
    };
    let account = f
        .sink
        .accounts()
        .iter()
        .find(|a| a.account.lookup_tag == lookup_tag)
        .map(|a| a.account.clone())
        .expect("this session's account row");
    assert_eq!(account.xwing_pk.len(), 1216);
    ok(
        &f.sealer,
        Request::LoadPrefs {
            sess: l,
            prefs_ct: account.prefs_ct.clone(),
        },
    )
    .await;
    lookup_tag
}

/// The passphrase of the drafting session `s` (regenerated through a fresh
/// drafting session is impossible: the words are only shown once), so the
/// helper remembers them via `confirmed`'s GEN_ACCOUNT response. Here we
/// re-run the generation path: `confirmed` already confirmed; we fetch the
/// words again through a second account only if needed. To keep one
/// account, `confirmed` is wrapped below.
async fn words_of(_f: &Fixture, _s: SessionHandle) -> String {
    WORDS.with(|w| w.borrow().clone().unwrap())
}

thread_local! {
    static WORDS: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// `common::confirmed` without the passphrase: redo it here so the words are
/// kept for the login.
async fn confirmed(f: &Fixture, s: SessionHandle, coi: Option<Coi>) {
    let sl = &f.sealer;
    ok(
        sl,
        Request::SessionOpen {
            sess: s,
            channel_id: CHANNEL,
        },
    )
    .await;
    ok(
        sl,
        Request::DraftSet(DraftSet {
            sess: s,
            mode: Mode::Anonymous,
            message: SecretText::new("report"),
            fields: vec![],
            identity: None,
            coi,
        }),
    )
    .await;
    let Response::Words {
        words,
        confirm_positions,
    } = ok(sl, Request::GenAccount { sess: s }).await
    else {
        panic!()
    };
    WORDS.with(|w| *w.borrow_mut() = Some(words_to_phrase(&words)));
    let Response::Confirm { ok: true, .. } = ok(
        sl,
        Request::ConfirmPassphrase {
            sess: s,
            words: confirm_words(&words, confirm_positions),
        },
    )
    .await
    else {
        panic!()
    };
}

/// Open the main object of envelope `i` with member 0 and return its inner
/// map.
fn open_main(f: &Fixture, i: usize) -> Item {
    let env = &f.sink.envelopes()[i];
    let (_, pt) = open_intake(
        &env.objects[0],
        member_ctx(env.epoch_id),
        &f.members[0].mek.private,
    )
    .unwrap();
    parse_padded(&pt).0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn seal_signal_kinds_offsets_and_release_epoch() {
    let f = fixture_epochs();
    let (s, l) = (sess(1), sess(2));
    submit_and_login(&f, s, l).await;
    let submission = open_main(&f, 0);
    let mailbox = submission.get(3).unwrap().b().to_vec();
    let sub_hash = f.sink.envelopes()[0].objects[0].object_hash;
    for (kind, lo, hi) in [
        (SignalKind::NoResponse, 1u8, 3u8),
        (SignalKind::MailboxClosed, 3, 21),
    ] {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..12 {
            let Response::Sealed {
                release_offset_days,
            } = ok(&f.sealer, Request::SealSignal { sess: l, kind }).await
            else {
                panic!()
            };
            assert!((lo..=hi).contains(&release_offset_days));
            seen.insert(release_offset_days);
            let env = f.sink.envelopes().pop().unwrap();
            assert_eq!(env.release_offset_days, release_offset_days);
            assert_eq!(env.received_day, TODAY);
            // MEKs of the epoch containing the release day (epoch 0 is
            // TODAY-2 .. TODAY+5, 7 days each).
            let expected_epoch = (TODAY + u32::from(release_offset_days) - (TODAY - 2)) / 7;
            assert_eq!(env.epoch_id, expected_epoch);
            // Same shape as a follow-up: three objects, same sizes.
            assert_eq!(env.objects.len(), 3);
            let n = f.sink.envelopes().len() - 1;
            let map = open_main(&f, n);
            assert_eq!(map.get(1).unwrap().u(), 2, "SOURCE_MESSAGE format");
            assert_eq!(map.get(7).unwrap().u(), kind as u64);
            assert_eq!(map.get(5).unwrap().t(), "");
            assert_eq!(map.get(3).unwrap().b(), &mailbox[..]);
            assert_eq!(map.get(9).unwrap().b(), &sub_hash[..]);
            assert_eq!(
                map.get(8).unwrap().get(1).unwrap().u(),
                u64::from(expected_epoch)
            );
        }
        // More than one offset appears (12 draws over ≥ 3 values).
        assert!(seen.len() >= 2, "{kind:?}: {seen:?}");
    }
    // Nothing was deleted by SEAL_SIGNAL; the draft session is untouched.
    assert!(f.sink.deleted_accounts.lock().unwrap().is_empty());
    assert!(f.sink.deleted_replies.lock().unwrap().is_empty());
    // A signal needs an authenticated session: the drafting session and an
    // unknown session are refused.
    let r = f
        .sealer
        .handle(Request::SealSignal {
            sess: sess(9),
            kind: SignalKind::NoResponse,
        })
        .await;
    assert_eq!(r, Response::error(ErrorCode::UnknownSession));
    ok(
        &f.sealer,
        Request::SessionOpen {
            sess: sess(7),
            channel_id: CHANNEL,
        },
    )
    .await;
    let r = f
        .sealer
        .handle(Request::SealSignal {
            sess: sess(7),
            kind: SignalKind::NoResponse,
        })
        .await;
    assert_eq!(r, Response::error(ErrorCode::BadState));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signal_fails_closed_without_a_key_for_the_release_epoch() {
    // The default fixture has MEKs for epoch 0 only (TODAY-2 .. TODAY+5):
    // a mailbox-closed signal (offset ≥ 3) can land in epoch 1 and then has
    // no eligible key: NO_ELIGIBLE_TRIAGE, nothing committed, nothing deleted.
    let f = fixture();
    let (s, l) = (sess(1), sess(2));
    submit_and_login(&f, s, l).await;
    let before = f.sink.envelopes().len();
    let mut refused = 0;
    for _ in 0..30 {
        let r = f
            .sealer
            .handle(Request::SealSignal {
                sess: l,
                kind: SignalKind::MailboxClosed,
            })
            .await;
        match r {
            Response::Sealed {
                release_offset_days,
            } => assert!(release_offset_days <= 4),
            Response::Error {
                code: ErrorCode::NoEligibleTriage,
                ..
            } => refused += 1,
            other => panic!("{other:?}"),
        }
    }
    assert!(refused > 0);
    let after = f.sink.envelopes().len();
    assert_eq!(after - before, 30 - refused);
    assert!(f.sink.deleted_accounts.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_replies_goes_to_the_store_with_the_account_tag() {
    let f = fixture_epochs();
    let (s, l) = (sess(1), sess(2));
    let tag = submit_and_login(&f, s, l).await;
    let refs = vec![[1u8; 16], [2u8; 16]];
    let r = ok(
        &f.sealer,
        Request::DeleteReplies {
            sess: l,
            replies: refs.clone(),
        },
    )
    .await;
    assert_eq!(r, Response::Deleted { count: 2 });
    assert_eq!(
        f.sink.deleted_replies.lock().unwrap().clone(),
        vec![(tag, refs.clone())]
    );
    // Store failure: uniform INTERNAL, session kept.
    f.sink.fail_delete.store(true, Ordering::SeqCst);
    let r = f
        .sealer
        .handle(Request::DeleteReplies {
            sess: l,
            replies: refs,
        })
        .await;
    assert_eq!(r, Response::error(ErrorCode::Internal));
    f.sink.fail_delete.store(false, Ordering::SeqCst);
    assert_eq!(
        ok(&f.sealer, Request::Touch { sess: l }).await,
        Response::Empty
    );
    // Not from a drafting session (`s` became AUTHENTICATED at SEAL_FINISH;
    // a fresh session has no account yet).
    ok(
        &f.sealer,
        Request::SessionOpen {
            sess: sess(7),
            channel_id: CHANNEL,
        },
    )
    .await;
    let r = f
        .sealer
        .handle(Request::DeleteReplies {
            sess: sess(7),
            replies: vec![],
        })
        .await;
    assert_eq!(r, Response::error(ErrorCode::BadState));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_mailbox_seals_the_signal_before_deleting_and_retries_safely() {
    let f = fixture_epochs();
    let (s, l) = (sess(1), sess(2));
    let tag = submit_and_login(&f, s, l).await;
    let mailbox = open_main(&f, 0).get(3).unwrap().b().to_vec();
    let ops_before = f.sink.ops();
    // First attempt: the signal is committed, then the deletion fails.
    f.sink.fail_delete.store(true, Ordering::SeqCst);
    let r = f.sealer.handle(Request::CloseMailbox { sess: l }).await;
    assert_eq!(r, Response::error(ErrorCode::Internal));
    assert_eq!(f.sink.ops(), format!("{ops_before}G"));
    assert_eq!(f.sink.envelopes().len(), 2);
    assert!(f.sink.deleted_accounts.lock().unwrap().is_empty());
    // The signal envelope is a MAILBOX_CLOSED SOURCE_MESSAGE.
    let m = open_main(&f, 1);
    assert_eq!(m.get(7).unwrap().u(), SignalKind::MailboxClosed as u64);
    let offset = f.sink.envelopes()[1].release_offset_days;
    assert!((3..=21).contains(&offset));
    // Retry: no second signal; the deletion goes through; the session ends.
    f.sink.fail_delete.store(false, Ordering::SeqCst);
    let r = ok(&f.sealer, Request::CloseMailbox { sess: l }).await;
    assert_eq!(
        r,
        Response::Sealed {
            release_offset_days: offset
        }
    );
    assert_eq!(f.sink.ops(), format!("{ops_before}GX"));
    assert_eq!(f.sink.envelopes().len(), 2);
    assert_eq!(
        f.sink.deleted_accounts.lock().unwrap().clone(),
        vec![vec![tag]]
    );
    assert_eq!(mailbox.len(), 32);
    let r = f.sealer.handle(Request::Touch { sess: l }).await;
    assert_eq!(r, Response::error(ErrorCode::UnknownSession));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_mailbox_drops_a_queued_account_write() {
    // Account created and closed within one batch window: the queued create
    // must not be written after the deletion.
    let f = fixture_epochs();
    let (s, l) = (sess(1), sess(2));
    ok(
        &f.sealer,
        Request::Hello {
            proto: PROTO_VERSION,
        },
    )
    .await;
    confirmed(&f, s, None).await;
    ok(
        &f.sealer,
        Request::SealFinish {
            sess: s,
            delayed_delivery: false,
        },
    )
    .await;
    // Not flushed yet: the close writes this source's queued create first
    // (ADR-057(3)), then the signal, then the deletion; nothing is left in
    // the queue (SEAL_FINISH leaves the session AUTHENTICATED with prefs).
    let _ = l;
    ok(&f.sealer, Request::CloseMailbox { sess: s }).await;
    assert_eq!(f.sealer.flush_accounts(), Ok(0));
    assert_eq!(f.sink.accounts().len(), 1);
    assert_eq!(f.sink.deleted_accounts.lock().unwrap().len(), 1);
    assert_eq!(f.sink.ops(), "GAGX");
}

// ---------------------------------------------------------------------------
// ADR-057 regressions (AUD-RM2-IPC-01/02/03/06)

/// Rotate the authenticated session `l` (queued replacement); returns the new
/// passphrase words and lookup tag.
async fn rotate(f: &Fixture, l: SessionHandle) -> (SecretWords, [u8; 32]) {
    let Response::Words {
        words,
        confirm_positions,
    } = ok(&f.sealer, Request::RotatePassphrase { sess: l }).await
    else {
        panic!()
    };
    ok(
        &f.sealer,
        Request::ConfirmPassphrase {
            sess: l,
            words: confirm_words(&words, confirm_positions),
        },
    )
    .await;
    let Response::Locator { lookup_tag } = ok(
        &f.sealer,
        Request::RotateFinish {
            sess: l,
            replies: vec![],
        },
    )
    .await
    else {
        panic!()
    };
    (words, lookup_tag)
}

/// Log a second session in with the current passphrase (store row known).
async fn login_again(f: &Fixture, l: SessionHandle, phrase: &str) -> [u8; 32] {
    let Response::Locator { lookup_tag } = ok(
        &f.sealer,
        Request::LoginDerive {
            sess: l,
            passphrase: SecretBytes::from_slice(phrase.as_bytes()),
        },
    )
    .await
    else {
        panic!()
    };
    let account = f
        .sink
        .accounts()
        .iter()
        .find(|a| a.account.lookup_tag == lookup_tag)
        .map(|a| a.account.clone())
        .expect("row in the store");
    ok(
        &f.sealer,
        Request::LoadPrefs {
            sess: l,
            prefs_ct: account.prefs_ct,
        },
    )
    .await;
    lookup_tag
}

/// AUD-RM2-IPC-01 (auditor's PoC, red → green): a rotation queued in the
/// batch window followed by `CLOSE_MAILBOX` must write the replacement
/// first, then delete under both tags; the old passphrase's account is gone
/// from the store and `mailbox` + `account` entries were requested.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_after_queued_rotation_deletes_the_account() {
    let f = fixture_epochs();
    f.sink.model_store.store(true, Ordering::SeqCst);
    let (s, l) = (sess(1), sess(2));
    let old_tag = submit_and_login(&f, s, l).await;
    let (_words, new_tag) = rotate(&f, l).await;
    assert_eq!(f.sealer.queued_accounts(), 1, "replacement queued");
    let r = ok(&f.sealer, Request::CloseMailbox { sess: l }).await;
    assert!(matches!(r, Response::Sealed { .. }));
    // Replacement written before the signal and the deletion.
    assert!(f.sink.ops().ends_with("AGX"), "{}", f.sink.ops());
    let deleted = f.sink.deleted_accounts.lock().unwrap().clone();
    assert_eq!(deleted.len(), 1);
    assert!(deleted[0].contains(&old_tag) && deleted[0].contains(&new_tag));
    assert_eq!(f.sealer.flush_accounts(), Ok(0));
    let known = f.sink.known_tags.lock().unwrap().clone();
    assert!(!known.contains(&old_tag) && !known.contains(&new_tag));
}

/// IPC-02 trigger (a): two sessions of one account; S1 rotates (queued), S2
/// closes. The close flushes the replacement and deletes under both tags;
/// the queue holds nothing stale and later rotations of other sources
/// proceed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotate_then_close_race_across_two_sessions() {
    let f = fixture_epochs();
    f.sink.model_store.store(true, Ordering::SeqCst);
    let (s, l1) = (sess(1), sess(2));
    let old_tag = submit_and_login(&f, s, l1).await;
    let phrase = WORDS.with(|w| w.borrow().clone().unwrap());
    let l2 = sess(3);
    assert_eq!(login_again(&f, l2, &phrase).await, old_tag);
    let (_w, new_tag) = rotate(&f, l1).await;
    let r = ok(&f.sealer, Request::CloseMailbox { sess: l2 }).await;
    assert!(matches!(r, Response::Sealed { .. }));
    let deleted = f.sink.deleted_accounts.lock().unwrap().clone();
    assert!(deleted[0].contains(&old_tag) && deleted[0].contains(&new_tag));
    assert_eq!(f.sealer.queued_accounts(), 0);
    // Another source's rotation still flushes.
    let (s2, l3) = (sess(4), sess(5));
    submit_and_login(&f, s2, l3).await;
    rotate(&f, l3).await;
    assert_eq!(f.sealer.flush_accounts(), Ok(1));
    assert_eq!(f.sealer.dead_letters(), 0);
}

/// IPC-03: two concurrent `CLOSE_MAILBOX` on one session coalesce: one
/// signal envelope, one deletion, both answers `Sealed` with the same offset.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_closes_seal_one_signal() {
    let f = fixture_epochs();
    let (s, l) = (sess(1), sess(2));
    submit_and_login(&f, s, l).await;
    let before = f.sink.envelopes().len();
    let (a, b) = tokio::join!(
        f.sealer.handle(Request::CloseMailbox { sess: l }),
        f.sealer.handle(Request::CloseMailbox { sess: l })
    );
    let offsets: Vec<u8> = [a, b]
        .iter()
        .filter_map(|r| match r {
            Response::Sealed {
                release_offset_days,
            } => Some(*release_offset_days),
            _ => None,
        })
        .collect();
    assert!(!offsets.is_empty(), "at least one close succeeds");
    assert!(offsets.windows(2).all(|w| w[0] == w[1]));
    assert_eq!(f.sink.envelopes().len(), before + 1);
    assert_eq!(f.sink.deleted_accounts.lock().unwrap().len(), 1);
}

/// `NotFound` from the store is an error on a first attempt (nothing was
/// confirmed), success only after an unknown-outcome attempt (ADR-057(3)).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn not_found_is_success_only_after_an_unknown_outcome() {
    let f = fixture_epochs();
    f.sink.model_store.store(true, Ordering::SeqCst);
    let (s, l) = (sess(1), sess(2));
    let tag = submit_and_login(&f, s, l).await;
    // The row vanished from the store (not through this sealer).
    f.sink.known_tags.lock().unwrap().retain(|t| *t != tag);
    let r = f.sealer.handle(Request::CloseMailbox { sess: l }).await;
    assert_eq!(r, Response::error(ErrorCode::Internal));
    assert!(f.sink.deleted_accounts.lock().unwrap().is_empty());
    // Session kept; the signal was sealed once.
    assert_eq!(
        ok(&f.sealer, Request::Touch { sess: l }).await,
        Response::Empty
    );
    let envs = f.sink.envelopes().len();
    // A transport failure makes the outcome unknown; the next NotFound is
    // then taken as "landed".
    f.sink.fail_delete.store(true, Ordering::SeqCst);
    let r = f.sealer.handle(Request::CloseMailbox { sess: l }).await;
    assert_eq!(r, Response::error(ErrorCode::Internal));
    f.sink.fail_delete.store(false, Ordering::SeqCst);
    let r = ok(&f.sealer, Request::CloseMailbox { sess: l }).await;
    assert!(matches!(r, Response::Sealed { .. }));
    assert_eq!(f.sink.envelopes().len(), envs, "no second signal");
}

struct CountingHealth(std::sync::atomic::AtomicU64);
impl candor_sealer::server::HealthSink for CountingHealth {
    fn account_write_dropped(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// IPC-02: a batch `[create, refused replace, good replace]` writes the
/// create and the good replacement; the refused one is retried a bounded
/// number of flushes and then dead-lettered with a health event. Other
/// sources are never blocked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_account_write_never_blocks_the_queue() {
    let f = fixture_epochs();
    f.sink.model_store.store(true, Ordering::SeqCst);
    let health = Arc::new(CountingHealth(std::sync::atomic::AtomicU64::new(0)));
    f.sealer.set_health_sink(health.clone());
    // Two accounts in the store.
    let (s1, l1) = (sess(1), sess(2));
    submit_and_login(&f, s1, l1).await;
    let (s2, l2) = (sess(3), sess(4));
    submit_and_login(&f, s2, l2).await;
    // A fresh create queued, a replacement the store refuses, a good one.
    confirmed(&f, sess(5), None).await;
    ok(
        &f.sealer,
        Request::SealFinish {
            sess: sess(5),
            delayed_delivery: false,
        },
    )
    .await;
    let (_w1, bad_tag) = rotate(&f, l1).await;
    f.sink.refuse_tags.lock().unwrap().push(bad_tag);
    let (_w2, good_tag) = rotate(&f, l2).await;
    assert_eq!(f.sealer.queued_accounts(), 3);
    assert_eq!(f.sealer.flush_accounts(), Ok(2));
    assert!(f.sink.known_tags.lock().unwrap().contains(&good_tag));
    assert_eq!(f.sealer.queued_accounts(), 1, "refused write retried later");
    assert_eq!(f.sealer.flush_accounts(), Ok(0));
    assert_eq!(f.sealer.flush_accounts(), Ok(0));
    assert_eq!(
        f.sealer.queued_accounts(),
        0,
        "dead-lettered after bounded retries"
    );
    assert_eq!(f.sealer.dead_letters(), 1);
    assert_eq!(health.0.load(Ordering::SeqCst), 1);
}

/// IPC-02 trigger (b): after an intake restore from a backup that predates
/// the dummy accounts, their synthetic rotations are `NotFound` at the store:
/// each is stale, dropped at once (dead letter), the dummy leaves the set,
/// chaff keeps running and the queue keeps flowing for real sources.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_dummy_rotation_after_restore_is_dropped() {
    let f = fixture_with(
        ChaffConfig {
            enabled: false,
            // Follow-up-shaped chaff: no new dummies; every event rotates one.
            followup_share_permille: 1000,
            dummy_rotation_permille: 1000,
            signal_share_permille: 0,
            ..ChaffConfig::default()
        },
        Limits::default(),
    );
    f.sink.model_store.store(true, Ordering::SeqCst);
    // 1–4 dummies written (the shutdown batch), then "restored away".
    let n = f.sealer.shutdown_flush().unwrap();
    assert!((1..=4).contains(&n));
    f.sink.known_tags.lock().unwrap().clear();
    for _ in 0..n {
        f.sealer.chaff_event(CHANNEL).await.unwrap();
        assert_eq!(f.sealer.flush_accounts(), Ok(0));
        assert_eq!(f.sealer.queued_accounts(), 0, "queue never wedges");
    }
    assert_eq!(
        f.sealer.dead_letters(),
        n as u64,
        "every stale rotation dropped"
    );
    // The dummy set is empty now: further events rotate nothing and nothing
    // is dead-lettered any more.
    f.sealer.chaff_event(CHANNEL).await.unwrap();
    assert_eq!(f.sealer.flush_accounts(), Ok(0));
    assert_eq!(f.sealer.dead_letters(), n as u64);
    // A real source is unaffected.
    let (s, l) = (sess(1), sess(2));
    submit_and_login(&f, s, l).await;
    rotate(&f, l).await;
    assert_eq!(f.sealer.flush_accounts(), Ok(1));
}

/// IPC-06 / IPC-12 (ADR-057(5)): under the production shares (follow-up
/// share 300, bundle distribution as shipped) the signal-shaped fraction of
/// chaff has exactly a real signal's shape — SOURCE_MESSAGE, empty bundle,
/// signal offset, release-epoch rule — and its share matches the configured
/// target within tolerance; nothing with a signal-only offset or epoch has a
/// SUBMISSION header or a non-empty bundle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signal_shaped_chaff_follows_the_production_shares() {
    // 250 ‰ (production: 30 ‰) only for statistical power; the shape logic
    // does not depend on the share.
    const SHARE: u16 = 250;
    const EVENTS: usize = 240;
    let f = fixture_custom(
        ChaffConfig {
            enabled: false,
            dummy_rotation_permille: 0,
            signal_share_permille: SHARE,
            ..ChaffConfig::default()
        },
        Limits::default(),
        rustix_uid(),
        |snap| {
            let ch = &mut snap.channels[0];
            let base: Vec<MemberEpochKey> = ch.meks.clone();
            for e in 1..=3u32 {
                for k in &base {
                    ch.meks.push(MemberEpochKey {
                        epoch_id: e,
                        valid_from_day: TODAY - 2 + 7 * e,
                        valid_until_day: TODAY - 2 + 7 * (e + 1),
                        ..k.clone()
                    });
                }
            }
        },
    );
    assert_eq!(ChaffConfig::default().followup_share_permille, 300);
    let (s, l) = (sess(1), sess(2));
    submit_and_login(&f, s, l).await;
    let skip = f.sink.envelopes().len();
    for i in 0..6 {
        let kind = if i % 2 == 0 {
            SignalKind::NoResponse
        } else {
            SignalKind::MailboxClosed
        };
        ok(&f.sealer, Request::SealSignal { sess: l, kind }).await;
    }
    let real: Vec<_> = f.sink.envelopes().into_iter().skip(skip).collect();
    let skip = f.sink.envelopes().len();
    for _ in 0..EVENTS {
        f.sealer.chaff_event(CHANNEL).await.unwrap();
    }
    let chaff: Vec<_> = f.sink.envelopes().into_iter().skip(skip).collect();
    assert_eq!(chaff.len(), EVENTS);
    let epoch_of =
        |e: &StoredEnvelope| (TODAY + u32::from(e.release_offset_days) - (TODAY - 2)) / 7;
    // Exactly a signal's resting shape: SOURCE_MESSAGE main, empty bundle,
    // identity at its bucket, offset 1..=21, epoch of the release day.
    let signal_shape = |e: &StoredEnvelope| {
        e.objects[0].object_type == candor_core::header::ObjectType::SourceMessage
            && e.objects[1].bytes.len() == real[0].objects[1].bytes.len()
            && e.objects[0].bytes.len() == real[0].objects[0].bytes.len()
            && e.objects[2].bytes.len() == real[0].objects[2].bytes.len()
            && (1..=21).contains(&e.release_offset_days)
            && e.epoch_id == epoch_of(e)
    };
    assert!(
        real.iter().all(signal_shape),
        "every real signal has the shape"
    );
    // Anything a seized store could read as "signal-only" (offset > 3 or an
    // epoch ahead of today's) must have the full signal shape.
    let today_epoch = (TODAY - (TODAY - 2)) / 7;
    for e in &chaff {
        if e.release_offset_days > 3 || e.epoch_id != today_epoch {
            assert!(signal_shape(e), "signal-only marker on a non-signal shape");
        }
    }
    // The share of chaff that is truly signal-shaped matches the target:
    // SHARE ‰, of which half carry offsets > 3 (mailbox-closed, 18/19 of
    // them beyond 3) and half offsets 1..=3 (C4). Count the unambiguous
    // mailbox-closed half and compare with SHARE/2 × 18/19 ± 5 σ.
    let mc = chaff.iter().filter(|e| e.release_offset_days > 3).count() as f64;
    let p = f64::from(SHARE) / 1000.0 * 0.5 * (18.0 / 19.0);
    let n = EVENTS as f64;
    let sigma = (n * p * (1.0 - p)).sqrt();
    assert!(
        (mc - n * p).abs() <= 5.0 * sigma,
        "mailbox-closed-shaped chaff {mc} vs expected {:.1} ± {:.1}",
        n * p,
        5.0 * sigma
    );
    // And the C4-shaped half exists too: signal-shaped chaff with offset
    // 1..=3 is at least as frequent as the delayed follow-ups would make it.
    let short_signal = chaff
        .iter()
        .filter(|e| (1..=3).contains(&e.release_offset_days) && signal_shape(e))
        .count();
    assert!(short_signal > 0);
}

/// AUD-RM2-IPC-14: the per-source state table is bounded: entries exist only
/// while an operation runs or a failed close keeps its state; a reply
/// deletion per account leaves nothing behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_state_table_does_not_grow() {
    let f = fixture_epochs();
    assert_eq!(f.sealer.source_states(), 0);
    let mut sessions = Vec::new();
    for i in 0..3u8 {
        let (s, l) = (sess(10 + i), sess(20 + i));
        submit_and_login(&f, s, l).await;
        sessions.push(l);
        ok(
            &f.sealer,
            Request::DeleteReplies {
                sess: l,
                replies: vec![[i; 16]],
            },
        )
        .await;
        assert_eq!(f.sealer.source_states(), 0, "released after the operation");
    }
    // A failed close keeps exactly one entry (its signal offset), which a
    // successful retry releases.
    f.sink.fail_delete.store(true, Ordering::SeqCst);
    let r = f
        .sealer
        .handle(Request::CloseMailbox { sess: sessions[0] })
        .await;
    assert_eq!(r, Response::error(ErrorCode::Internal));
    assert_eq!(f.sealer.source_states(), 1);
    f.sink.fail_delete.store(false, Ordering::SeqCst);
    ok(&f.sealer, Request::CloseMailbox { sess: sessions[0] }).await;
    assert_eq!(f.sealer.source_states(), 0);
}
