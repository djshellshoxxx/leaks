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
    let account = f.sink.accounts()[0].account.clone();
    assert_eq!(account.xwing_pk.len(), 1216);
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
    assert_eq!(lookup_tag, account.lookup_tag);
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
        vec![(tag, vec![<[u8; 32]>::try_from(mailbox.as_slice()).unwrap()])]
    );
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
    // Not flushed: log in through a second account path is impossible without
    // the store, so close from the drafting session after it became
    // authenticated (SEAL_FINISH leaves it AUTHENTICATED with prefs).
    let _ = l;
    ok(&f.sealer, Request::CloseMailbox { sess: s }).await;
    assert_eq!(f.sealer.flush_accounts(), Ok(0));
    assert!(f.sink.accounts().is_empty());
    assert_eq!(f.sink.deleted_accounts.lock().unwrap().len(), 1);
    assert_eq!(f.sink.ops(), "GGX");
}
