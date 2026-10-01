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
            identity: Some(SecretText::new("dropped in anonymous mode")),
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

fn assert_nothing_written(f: &Fixture) {
    assert!(f.sink.envelopes().is_empty(), "an envelope was committed");
    assert!(
        read_all_files(&f.staging_path).is_empty(),
        "staging not empty"
    );
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
    let r = f
        .sealer
        .handle(Request::SealFinish {
            sess: s,
            delayed_delivery: false,
        })
        .await;
    assert_eq!(
        r,
        Response::Error {
            code: ErrorCode::NoEligibleTriage,
            alternative_channel_id: Some(ALT_CHANNEL)
        }
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
    let n = snap.tree_size + 1;
    resize(&mut snap, n);
    for k in &mut snap.channels[0].meks {
        k.valid_until_day = TODAY; // expired today
    }
    f.install(snap).unwrap();
    let s = sess(1);
    confirmed(&f, s, None).await;
    let r = f
        .sealer
        .handle(Request::SealFinish {
            sess: s,
            delayed_delivery: false,
        })
        .await;
    assert_eq!(
        r,
        Response::Error {
            code: ErrorCode::NoEligibleTriage,
            alternative_channel_id: Some(ALT_CHANNEL)
        }
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
    let r = f
        .sealer
        .handle(Request::SealFinish {
            sess: s,
            delayed_delivery: false,
        })
        .await;
    assert_eq!(
        r,
        Response::Error {
            code: ErrorCode::Unavailable,
            alternative_channel_id: Some(ALT_CHANNEL)
        }
    );
    assert_nothing_written(&f);
    // Six days is still fresh enough to reach selection.
    f.clock.day.store(TODAY + 6, Ordering::SeqCst);
    let r = f
        .sealer
        .handle(Request::SealFinish {
            sess: s,
            delayed_delivery: false,
        })
        .await;
    assert!(
        !matches!(
            r,
            Response::Error {
                code: ErrorCode::Unavailable,
                ..
            }
        ),
        "{r:?}"
    );
}

#[tokio::test]
async fn independent_time_failure_fails_closed() {
    let f = fixture();
    let s = sess(1);
    confirmed(&f, s, None).await;
    f.clock.fail.store(true, Ordering::SeqCst);
    let r = f
        .sealer
        .handle(Request::SealFinish {
            sess: s,
            delayed_delivery: false,
        })
        .await;
    assert_eq!(r, Response::error(ErrorCode::Unavailable));
    assert_nothing_written(&f);
}

/// ADR-036(6), ADR-052(6), AUD-RM2-SEA-07: only a verified snapshot is ever
/// installed — rollback, fork at an equal or larger size, bad checkpoint
/// signature, unmet cosignature policy, a view not bound to its checkpoint, a
/// structurally invalid view and a failed high-water-mark persist are refused,
/// and nothing changes.
#[tokio::test]
async fn snapshot_rollback_fork_signature_and_invariants_rejected() {
    let f = fixture();
    let cur = f.sealer.high_water_mark();
    assert_eq!(cur.tree_size, f.snapshot.tree_size);
    assert_eq!(cur.root_hash, f.snapshot.root_hash);
    // Rollback: smaller tree, older checkpoint hour.
    let mut older = f.snapshot.clone();
    resize(&mut older, f.snapshot.tree_size - 1);
    assert_eq!(f.install(older), Err(SnapshotError::Rollback));
    let mut older = f.snapshot.clone();
    older.issued_hour -= 1;
    assert_eq!(f.install(older), Err(SnapshotError::Rollback));
    // Suite.
    let mut fips = f.snapshot.clone();
    fips.suite = candor_core::Suite::CandorFips1;
    assert_eq!(f.install(fips), Err(SnapshotError::Suite));
    // Fork at the same size (a different root, validly signed).
    let mut fork = f.snapshot.clone();
    fork.root_hash = [0xee; 32];
    assert_eq!(f.install(fork), Err(SnapshotError::Fork));
    // Fork at a larger size: a validly signed checkpoint whose tree does not
    // extend ours (the proof cannot verify).
    let mut fork = f.snapshot.clone();
    fork.tree_size += 5;
    fork.root_hash = [0xef; 32];
    assert_eq!(f.install(fork), Err(SnapshotError::Fork));
    // A consistent extension with a broken proof.
    let mut next = f.snapshot.clone();
    resize(&mut next, f.snapshot.tree_size + 7);
    let mut b = signed_bundle(next.clone(), cur.tree_size);
    b.consistency_proof[0][0] ^= 1;
    assert_eq!(
        f.sealer.install_snapshot(b, |_| true),
        Err(SnapshotError::Fork)
    );
    // Bad LOG_KEY signature.
    let mut b = signed_bundle(next.clone(), cur.tree_size);
    b.checkpoint.log_sig[0] ^= 1;
    assert_eq!(
        f.sealer.install_snapshot(b, |_| true),
        Err(SnapshotError::Signature)
    );
    // View not bound to the checkpoint.
    let mut b = signed_bundle(next.clone(), cur.tree_size);
    b.view.issued_hour += 1;
    assert_eq!(
        f.sealer.install_snapshot(b, |_| true),
        Err(SnapshotError::Invalid)
    );
    // Two COI policies with the same effective day: invalid.
    let mut bad = next.clone();
    let p = bad.channels[0].coi_policies[0].clone();
    bad.channels[0].coi_policies.push(p);
    assert_eq!(f.install(bad), Err(SnapshotError::Invalid));
    // More than 16 Triage Set persons: invalid.
    let mut bad = next.clone();
    for i in 0..16u8 {
        bad.channels[0]
            .members
            .push(candor_sealer::server::directory::RosterMember {
                user_id: [100 + i; 16],
                role_label: 70,
                read_intake: true,
                effective_day: 0,
            });
    }
    assert_eq!(f.install(bad), Err(SnapshotError::Invalid));
    // Persist failure: nothing installed, mark unchanged.
    let b = signed_bundle(next.clone(), cur.tree_size);
    assert_eq!(
        f.sealer.install_snapshot(b, |_| false),
        Err(SnapshotError::Persist)
    );
    assert_eq!(f.sealer.high_water_mark(), cur);
    // Nothing above changed the mark; a valid extension is accepted and the
    // mark persisted before use.
    let mut persisted = None;
    let b = signed_bundle(next.clone(), cur.tree_size);
    f.sealer
        .install_snapshot(b, |m| {
            persisted = Some(*m);
            true
        })
        .unwrap();
    assert_eq!(persisted, Some(f.sealer.high_water_mark()));
    assert_eq!(f.sealer.high_water_mark().tree_size, next.tree_size);
    // The same checkpoint again (equal size, equal root) is fine.
    assert!(f.install(next).is_ok());
}

/// VR-2 cosignature policy: two valid witness cosignatures incl. one external.
#[tokio::test]
async fn witness_cosignature_policy_enforced() {
    use candor_core::sig::SigningKey;
    use candor_sealer::server::directory::{
        Cosignature, DirectoryTrust, VerifiedSnapshot, WitnessKey, cosignature_message,
    };
    let f = fixture();
    let w_int = SigningKey::from_seed(&[0x71; 32]);
    let w_ext = SigningKey::from_seed(&[0x72; 32]);
    let trust = DirectoryTrust {
        witnesses: vec![
            WitnessKey {
                pk: w_int.verifying_key_bytes(),
                external: false,
            },
            WitnessKey {
                pk: w_ext.verifying_key_bytes(),
                external: true,
            },
        ],
        min_cosignatures: 2,
        min_external: 1,
        ..trust()
    };
    let cosign = |k: &SigningKey, b: &candor_sealer::server::directory::SnapshotBundle| {
        let body = b.checkpoint.note_body(&TENANT).unwrap();
        Cosignature {
            witness_pk: k.verifying_key_bytes(),
            timestamp: 1_700_000_000,
            sig: k.sign(&cosignature_message(&body, 1_700_000_000)),
        }
    };
    let hwm = Default::default();
    let suite = candor_core::Suite::CandorStd1;
    let base = signed_bundle(f.snapshot.clone(), 0);
    // No cosignatures, one, a duplicate, a forged one: refused.
    assert_eq!(
        VerifiedSnapshot::verify(base.clone(), &trust, suite, &hwm).unwrap_err(),
        SnapshotError::Signature
    );
    let mut b = base.clone();
    b.checkpoint.cosignatures = vec![cosign(&w_ext, &b), cosign(&w_ext, &b)];
    assert_eq!(
        VerifiedSnapshot::verify(b, &trust, suite, &hwm).unwrap_err(),
        SnapshotError::Signature
    );
    let mut b = base.clone();
    let mut forged = cosign(&w_int, &b);
    forged.timestamp += 1;
    b.checkpoint.cosignatures = vec![cosign(&w_ext, &b), forged];
    assert_eq!(
        VerifiedSnapshot::verify(b, &trust, suite, &hwm).unwrap_err(),
        SnapshotError::Signature
    );
    // Two internal-only witnesses do not satisfy w_external = 1.
    let t2 = DirectoryTrust {
        witnesses: vec![
            WitnessKey {
                pk: w_int.verifying_key_bytes(),
                external: false,
            },
            WitnessKey {
                pk: w_ext.verifying_key_bytes(),
                external: false,
            },
        ],
        ..trust.clone()
    };
    let mut b = base.clone();
    b.checkpoint.cosignatures = vec![cosign(&w_int, &b), cosign(&w_ext, &b)];
    assert_eq!(
        VerifiedSnapshot::verify(b.clone(), &t2, suite, &hwm).unwrap_err(),
        SnapshotError::Signature
    );
    // Policy met.
    assert!(VerifiedSnapshot::verify(b, &trust, suite, &hwm).is_ok());
}

/// AUD-RM2-SEA-03 regression (the auditor's PoC, ADR-052(3)): member 2 holds
/// label 2 (excluded by the category COI_POLICY) and is also listed under
/// label 9. The submission must not be sealed to member 2's MEK.
#[tokio::test]
async fn coi_excluded_person_listed_under_two_labels_gets_no_slot() {
    let f = fixture();
    let mut snap = f.snapshot.clone();
    snap.snapshot_version = 2;
    let n = snap.tree_size + 1;
    resize(&mut snap, n);
    snap.channels[0]
        .members
        .push(candor_sealer::server::directory::RosterMember {
            user_id: f.members[1].user_id,
            role_label: 9,
            read_intake: true,
            effective_day: TODAY - 30,
        });
    f.install(snap).unwrap();
    let s = sess(1);
    let coi = Coi {
        excluded_labels: zeroize::Zeroizing::new(vec![]),
        categories: zeroize::Zeroizing::new(vec![CATEGORY_FRAUD]),
    };
    confirmed(&f, s, Some(coi)).await;
    assert!(matches!(
        f.sealer
            .handle(Request::SealFinish {
                sess: s,
                delayed_delivery: false,
            })
            .await,
        Response::Sealed { .. }
    ));
    let env = &f.sink.envelopes()[0];
    for o in &env.objects[..2] {
        assert!(
            open_intake(o, member_ctx(0), &f.members[1].mek.private).is_none(),
            "COI-excluded person can open the submission"
        );
        assert!(open_intake(o, member_ctx(0), &f.members[0].mek.private).is_some());
    }
}

#[tokio::test]
async fn seal_requires_confirmation_and_five_failures_zeroize() {
    let f = fixture();
    let s = sess(1);
    ok(
        &f.sealer,
        Request::SessionOpen {
            sess: s,
            channel_id: CHANNEL,
        },
    )
    .await;
    let r = f
        .sealer
        .handle(Request::SealFinish {
            sess: s,
            delayed_delivery: false,
        })
        .await;
    assert_eq!(r, Response::error(ErrorCode::NotConfirmed));
    ok(&f.sealer, Request::GenAccount { sess: s }).await;
    let r = f
        .sealer
        .handle(Request::SealFinish {
            sess: s,
            delayed_delivery: false,
        })
        .await;
    assert_eq!(r, Response::error(ErrorCode::NotConfirmed));
    let wrong = || SecretWords(zeroize::Zeroizing::new(vec![7777, 7777, 7777]));
    for i in 0..5 {
        let r = ok(
            &f.sealer,
            Request::ConfirmPassphrase {
                sess: s,
                words: wrong(),
            },
        )
        .await;
        let Response::Confirm {
            ok: false,
            confirm_positions,
        } = r
        else {
            panic!()
        };
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
    ok(
        &f.sealer,
        Request::SessionOpen {
            sess: s,
            channel_id: CHANNEL,
        },
    )
    .await;
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
    ok(
        &f.sealer,
        Request::SessionOpen {
            sess: s,
            channel_id: CHANNEL,
        },
    )
    .await;
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
    ok(
        &f.sealer,
        Request::PartChunk {
            sess: s,
            part,
            data: SecretBytes::from_slice(b"0123456789"),
            last: true,
        },
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
    f.sink.fail.store(true, Ordering::SeqCst);
    let r = f
        .sealer
        .handle(Request::SealFinish {
            sess: s,
            delayed_delivery: false,
        })
        .await;
    assert_eq!(r, Response::error(ErrorCode::Internal));
    assert!(f.sink.envelopes().is_empty());
    // Only the staged part remains (the sealed bundle file was removed).
    assert_eq!(read_all_files(&f.staging_path).len(), 1);
}

#[tokio::test]
async fn unknown_or_disabled_channel_and_bad_states() {
    let f = fixture();
    let r = f
        .sealer
        .handle(Request::SessionOpen {
            sess: sess(1),
            channel_id: [0x99; 16],
        })
        .await;
    assert_eq!(r, Response::error(ErrorCode::Unavailable));
    ok(
        &f.sealer,
        Request::SessionOpen {
            sess: sess(2),
            channel_id: CHANNEL,
        },
    )
    .await;
    // Duplicate handle.
    let r = f
        .sealer
        .handle(Request::SessionOpen {
            sess: sess(2),
            channel_id: CHANNEL,
        })
        .await;
    assert_eq!(r, Response::error(ErrorCode::BadState));
    // Drafting sessions cannot sign, open replies or load prefs.
    let r = f
        .sealer
        .handle(Request::LoginSign {
            sess: sess(2),
            challenge: [0; 32],
        })
        .await;
    assert_eq!(r, Response::error(ErrorCode::BadState));
    let r = f
        .sealer
        .handle(Request::OpenReply {
            sess: sess(2),
            entry: vec![1, 2, 3],
        })
        .await;
    assert_eq!(r, Response::error(ErrorCode::BadState));
    let r = f
        .sealer
        .handle(Request::RotatePassphrase { sess: sess(2) })
        .await;
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
        .handle(Request::PartChunk {
            sess: sess(2),
            part,
            data: SecretBytes::from_slice(b"12345"),
            last: true,
        })
        .await;
    assert_eq!(r, Response::error(ErrorCode::Limit));
    assert!(read_all_files(&f.staging_path).is_empty());
    // Unknown session.
    let r = f.sealer.handle(Request::DraftGet { sess: sess(77) }).await;
    assert_eq!(r, Response::error(ErrorCode::UnknownSession));
}

#[tokio::test]
async fn session_capacity_gives_busy() {
    let limits = candor_sealer::server::Limits {
        max_sessions: 2,
        ..Default::default()
    };
    let f = fixture_with(
        candor_sealer::server::ChaffConfig {
            enabled: false,
            ..Default::default()
        },
        limits,
    );
    ok(
        &f.sealer,
        Request::SessionOpen {
            sess: sess(1),
            channel_id: CHANNEL,
        },
    )
    .await;
    ok(
        &f.sealer,
        Request::SessionOpen {
            sess: sess(2),
            channel_id: CHANNEL,
        },
    )
    .await;
    let r = f
        .sealer
        .handle(Request::SessionOpen {
            sess: sess(3),
            channel_id: CHANNEL,
        })
        .await;
    assert_eq!(r, Response::error(ErrorCode::Busy));
    let r = f
        .sealer
        .handle(Request::LoginDerive {
            sess: sess(4),
            passphrase: SecretBytes::from_slice(b"x"),
        })
        .await;
    assert_eq!(r, Response::error(ErrorCode::Busy));
}

/// AUD-RM2-SEA-10: a COI_POLICY tightened after the initial report applies to
/// follow-ups (the report's categories are kept in `prefs_ct`).
#[tokio::test]
async fn follow_up_reapplies_tightened_coi_policy() {
    let f = fixture();
    let s = sess(1);
    let coi = Coi {
        excluded_labels: zeroize::Zeroizing::new(vec![]),
        categories: zeroize::Zeroizing::new(vec![CATEGORY_FRAUD]),
    };
    confirmed(&f, s, Some(coi)).await;
    let seal = Request::SealFinish {
        sess: s,
        delayed_delivery: false,
    };
    assert!(matches!(
        f.sealer.handle(seal.clone()).await,
        Response::Sealed { .. }
    ));
    // Initial: members 1 and 3 (label 2 is excluded for the category).
    let env = &f.sink.envelopes()[0];
    assert!(open_intake(&env.objects[0], member_ctx(0), &f.members[2].mek.private).is_some());
    // Tightening: the category now also excludes label 3.
    let mut snap = f.snapshot.clone();
    snap.snapshot_version = 2;
    let n = snap.tree_size + 1;
    resize(&mut snap, n);
    snap.channels[0]
        .coi_policies
        .push(candor_sealer::server::directory::CoiPolicy {
            entry_hash: [0x67; 32],
            effective_day: TODAY,
            categories: vec![(CATEGORY_FRAUD, vec![2, 3])],
        });
    f.install(snap).unwrap();
    ok(
        &f.sealer,
        Request::DraftSet(DraftSet {
            sess: s,
            mode: Mode::Anonymous,
            message: SecretText::new("follow-up"),
            fields: vec![],
            identity: None,
            coi: None,
        }),
    )
    .await;
    assert!(matches!(
        f.sealer.handle(seal).await,
        Response::Sealed { .. }
    ));
    let fu = &f.sink.envelopes()[1];
    assert!(open_intake(&fu.objects[0], member_ctx(0), &f.members[2].mek.private).is_none());
    assert!(open_intake(&fu.objects[0], member_ctx(0), &f.members[0].mek.private).is_some());
}
