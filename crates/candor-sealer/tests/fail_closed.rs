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
use candor_sealer::server::{ChaffConfig, Limits, SnapshotError};
use common::*;

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
    use candor_sealer::server::directory::VerifiedSnapshot;
    let f = fixture();
    let cur = f.sealer.high_water_mark();
    let log0 = f.log.lock().unwrap().clone();
    let n0 = log0.entries.len();
    assert_eq!(cur.tree_size, n0 as u64);
    assert_eq!(cur.root_hash, log0.root(n0));
    let hour = f.snapshot.issued_hour;
    // Rollback: a validly signed older prefix of the same log, or an older hour.
    let b = log0.bundle_prefix(n0 - 1, hour, 1, 0, vec![]);
    assert_eq!(
        f.sealer.install_snapshot(b, |_| true),
        Err(SnapshotError::Rollback)
    );
    let b = log0.bundle_prefix(n0, hour - 1, 1, 0, vec![]);
    assert_eq!(
        f.sealer.install_snapshot(b, |_| true),
        Err(SnapshotError::Rollback)
    );
    // Suite: the ORG_ROOT does not allow the sealer's suite.
    assert_eq!(
        VerifiedSnapshot::verify(
            f.current_bundle(),
            &trust(),
            candor_core::Suite::CandorFips1,
            &SALT,
            &Default::default()
        )
        .unwrap_err(),
        SnapshotError::Suite
    );
    // Wrong deployment salt.
    assert_eq!(
        VerifiedSnapshot::verify(
            f.current_bundle(),
            &trust(),
            candor_core::Suite::CandorStd1,
            &[0; 32],
            &Default::default()
        )
        .unwrap_err(),
        SnapshotError::Invalid
    );
    // Fork at the same size: a different, validly signed log of the same size.
    let fork_entry = |tag: u8| {
        signed_entry(
            &kd_entry(0x0b, &[tag; 16], 1, None, 0, 1, m(vec![(1, t("fork"))])),
            &[&admin1()],
        )
    };
    let mut fork = log0.clone();
    fork.entries.pop();
    fork.push_raw(fork_entry(0xee));
    let b = fork.bundle_prefix(n0, hour, 2, 0, vec![]);
    assert_eq!(
        f.sealer.install_snapshot(b, |_| true),
        Err(SnapshotError::Fork)
    );
    // Fork at a larger size: the proof from our mark cannot verify.
    for k in 0..5 {
        fork.push_raw(fork_entry(0xf0 + k));
    }
    let b = fork.bundle_prefix(n0 + 5, hour, 2, n0 as u64, vec![]);
    assert_eq!(
        f.sealer.install_snapshot(b, |_| true),
        Err(SnapshotError::Fork)
    );
    // A consistent extension with a broken proof.
    let mut next = f.snapshot.clone();
    next.snapshot_version = 2;
    resize(&mut next, n0 as u64 + 7);
    let (mut b, _) = f.scratch_bundle(&next);
    b.consistency_proof[0][0] ^= 1;
    assert_eq!(
        f.sealer.install_snapshot(b, |_| true),
        Err(SnapshotError::Fork)
    );
    // Bad LOG_KEY signature.
    let (mut b, _) = f.scratch_bundle(&next);
    b.checkpoint.log_sig[0] ^= 1;
    assert_eq!(
        f.sealer.install_snapshot(b, |_| true),
        Err(SnapshotError::Signature)
    );
    // A checkpoint signed by a key that is not the log's LOG_KEY entry.
    let (mut b, _) = f.scratch_bundle(&next);
    b.checkpoint.log_sig = admin1().sign(&b.checkpoint.note_body(&TENANT).unwrap());
    assert_eq!(
        f.sealer.install_snapshot(b, |_| true),
        Err(SnapshotError::Signature)
    );
    // An ORG_ROOT other than the pinned K01 (VR-1).
    let mut t2 = trust();
    t2.org_root_pk = admin2().verifying_key_bytes();
    assert_eq!(
        VerifiedSnapshot::verify(
            f.current_bundle(),
            &t2,
            candor_core::Suite::CandorStd1,
            &SALT,
            &Default::default()
        )
        .unwrap_err(),
        SnapshotError::Signature
    );
    // More than 16 Triage Set persons: the roster entry is invalid (§14.4
    // rule 5), so the whole snapshot is refused.
    let mut bad = next.clone();
    for i in 0..16u8 {
        bad.channels[0].members.push(RosterMember {
            user_id: [100 + i; 16],
            role_label: 70,
            read_intake: true,
            effective_day: TODAY - 30,
        });
    }
    let (b, _) = f.scratch_bundle(&bad);
    assert_eq!(
        f.sealer.install_snapshot(b, |_| true),
        Err(SnapshotError::Entry)
    );
    // Persist failure: nothing installed, mark unchanged.
    let (b, _) = f.scratch_bundle(&next);
    assert_eq!(
        f.sealer.install_snapshot(b, |_| false),
        Err(SnapshotError::Persist)
    );
    assert_eq!(f.sealer.high_water_mark(), cur);
    // Nothing above changed the mark; a valid extension is accepted and the
    // mark persisted before use.
    let mut persisted = None;
    let b = f.bundle(&next);
    f.sealer
        .install_snapshot(b, |m| {
            persisted = Some(*m);
            true
        })
        .unwrap();
    assert_eq!(persisted, Some(f.sealer.high_water_mark()));
    assert_eq!(f.sealer.high_water_mark().tree_size, n0 as u64 + 7);
    // The same checkpoint again (equal size, equal root) is fine.
    assert!(f.install(next).is_ok());
}

/// VR-2 cosignature policy: two valid witness cosignatures incl. one external
/// (witness keys from the ORG_ROOT entry; the pinned floors apply).
#[tokio::test]
async fn witness_cosignature_policy_enforced() {
    use candor_sealer::server::directory::VerifiedSnapshot;
    let f = fixture();
    let mut trust = trust();
    trust.min_cosignatures = 2;
    trust.min_external = 1;
    let hwm = Default::default();
    let suite = candor_core::Suite::CandorStd1;
    let verify = |b| VerifiedSnapshot::verify(b, &trust, suite, &SALT, &hwm);
    let base = f.current_bundle();
    let (w_int, w_int2, w_ext) = (witness(0), witness(1), witness(2));
    // No cosignatures, a duplicate, a forged one, an unknown witness: refused.
    assert_eq!(verify(base.clone()).unwrap_err(), SnapshotError::Signature);
    let mut b = base.clone();
    b.checkpoint.cosignatures = vec![cosign(&w_ext, &b), cosign(&w_ext, &b)];
    assert_eq!(verify(b).unwrap_err(), SnapshotError::Signature);
    let mut b = base.clone();
    let mut forged = cosign(&w_int, &b);
    forged.timestamp += 1;
    b.checkpoint.cosignatures = vec![cosign(&w_ext, &b), forged];
    assert_eq!(verify(b).unwrap_err(), SnapshotError::Signature);
    let mut b = base.clone();
    b.checkpoint.cosignatures = vec![cosign(&w_ext, &b), cosign(&witness(5), &b)];
    assert_eq!(verify(b).unwrap_err(), SnapshotError::Signature);
    // Two internal-only witnesses do not satisfy w_external = 1.
    let mut b = base.clone();
    b.checkpoint.cosignatures = vec![cosign(&w_int, &b), cosign(&w_int2, &b)];
    assert_eq!(verify(b).unwrap_err(), SnapshotError::Signature);
    // Policy met.
    let mut b = base.clone();
    b.checkpoint.cosignatures = vec![cosign(&w_int, &b), cosign(&w_ext, &b)];
    assert!(verify(b).is_ok());
}

/// AUD-RM2-SEA-03 regression (the auditor's PoC, ADR-052(3)): member 2 holds
/// label 2 (excluded by the category COI_POLICY) and is also listed under
/// label 9. The submission must not be sealed to member 2's MEK.
#[tokio::test]
async fn coi_excluded_person_listed_under_two_labels_gets_no_slot() {
    // The second listing is in the initial (active) roster.
    let f = fixture_custom(
        ChaffConfig {
            enabled: false,
            ..ChaffConfig::default()
        },
        Limits::default(),
        rustix_uid(),
        |snap| {
            snap.channels[0].members.push(RosterMember {
                user_id: [2; 16],
                role_label: 9,
                read_intake: true,
                effective_day: TODAY - 30,
            });
        },
    );
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
    // AUD-RM2-SEA-22: the confirmed passphrase survives a refusal after
    // derivation, so the source can retry without a new passphrase.
    f.sink.fail.store(false, Ordering::SeqCst);
    let r = f
        .sealer
        .handle(Request::SealFinish {
            sess: s,
            delayed_delivery: false,
        })
        .await;
    assert!(matches!(r, Response::Sealed { .. }), "{r:?}");
    assert_eq!(f.sink.envelopes().len(), 1);
}

/// AUD-RM2-SEA-22 (the auditor's PoC): 13,653 × U+0958 is 40,959 bytes as
/// sent but 81,918 bytes after NFC, which the SUBMISSION carries. DRAFT_SET
/// refuses it with LIMIT, before any passphrase or Argon2id work; the same
/// size in characters that do not expand is accepted, as is text whose NFC
/// form is shorter.
#[tokio::test]
async fn nfc_expanding_draft_is_refused_at_draft_set() {
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
    let draft = |message: String, fields: Vec<(u16, SecretText)>| {
        Request::DraftSet(DraftSet {
            sess: s,
            mode: Mode::Anonymous,
            message: SecretText::new(&message),
            fields,
            identity: None,
            coi: None,
        })
    };
    let poc = "\u{0958}".repeat(13_653);
    assert_eq!(poc.len(), 40_959);
    assert_eq!(
        f.sealer.handle(draft(poc, vec![])).await,
        Response::error(ErrorCode::Limit)
    );
    // Expansion that only overflows together with the answers.
    let half = "\u{0958}".repeat(5_000); // 15,000 B, 30,000 B after NFC
    assert_eq!(
        f.sealer
            .handle(draft(
                half.clone(),
                vec![(1, SecretText::new(&"a".repeat(10_961)))]
            ))
            .await,
        Response::error(ErrorCode::Limit)
    );
    ok(
        &f.sealer,
        draft(half, vec![(1, SecretText::new(&"a".repeat(10_960)))]),
    )
    .await;
    ok(&f.sealer, draft("a".repeat(40_959), vec![])).await;
    // NFC composes "e" + U+0301 (3 B) into U+00E9 (2 B): fits.
    ok(&f.sealer, draft("e\u{0301}".repeat(13_653), vec![])).await;
    // A long identity is checked on its NFC form too.
    let r = f
        .sealer
        .handle(Request::DraftSet(DraftSet {
            sess: s,
            mode: Mode::Confidential,
            message: SecretText::new("m"),
            fields: vec![],
            identity: Some(SecretText::new(&"\u{0958}".repeat(1_365))),
            coi: None,
        }))
        .await;
    assert_eq!(r, Response::error(ErrorCode::Limit));
    // The refusal happened before any sealing work: nothing written.
    assert!(f.sink.envelopes().is_empty() && f.sink.accounts().is_empty());
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
    snap.channels[0].coi_policies.push(CoiPolicy {
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
