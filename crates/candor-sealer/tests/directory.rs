// SPDX-License-Identifier: AGPL-3.0-or-later
//! AUD-RM2-SEA-19 regressions: the sealer's view is derived from the directory
//! log itself, bound to the signed checkpoint (VR-4 full-tree recomputation),
//! and every entry is checked against the §14.2/§14.4 signature, continuity and
//! time-lock rules. Covers the auditor's PoC (genuine checkpoint + attacker
//! MEK), tampered role labels, wrong signers, missing or added entries, and a
//! compromised LOG_KEY (entries re-hashed under a validly signed checkpoint).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use candor_core::Suite;
use candor_core::kem::KemKeyPair;
use candor_core::sig::SigningKey;
use candor_sealer::proto::*;
use candor_sealer::server::SnapshotError;
use candor_sealer::server::directory::{SnapshotBundle, VerifiedSnapshot};
use candor_sealer::server::kd::{self, caps, ty};
use common::*;

fn attacker() -> SigningKey {
    SigningKey::from_seed(&[0xee; 32])
}

/// Index of the entry whose bytes contain `needle`.
fn find_entry(b: &SnapshotBundle, needle: &[u8]) -> usize {
    b.entries
        .iter()
        .position(|e| contains(e, needle))
        .expect("entry present")
}

/// What the sealer would derive from `b` (relative to its current mark).
fn verify(f: &Fixture, b: SnapshotBundle) -> Result<VerifiedSnapshot, SnapshotError> {
    VerifiedSnapshot::verify(
        b,
        &trust(),
        Suite::CandorStd1,
        &SALT,
        &f.sealer.high_water_mark(),
    )
}

/// A scratch copy of the fixture log extended by `edit`, with a checkpoint
/// validly signed by the LOG_KEY (as if C-14 or the LOG_KEY were compromised)
/// and a consistency proof from the sealer's mark.
fn compromised(f: &Fixture, edit: impl FnOnce(&mut TestLog)) -> SnapshotBundle {
    let mut log = f.log.lock().unwrap().clone();
    edit(&mut log);
    let from = f.sealer.high_water_mark().tree_size;
    let n = log.entries.len();
    log.bundle_prefix(n, f.snapshot.issued_hour, 9, from, vec![])
}

fn mek_subject(user: [u8; 16]) -> [u8; 32] {
    kd::member_epoch_subject(&CHANNEL, &user, 0)
}

fn mek_value(user: [u8; 16], pk: &KemKeyPair, log: &TestLog) -> candor_sealer::proto::cbor::Value {
    TestLog::mek_body(
        &CHANNEL,
        &MemberEpochKey {
            user_id: user,
            epoch_id: 0,
            valid_from_day: TODAY - 2,
            valid_until_day: TODAY + 5,
            revoked: false,
            public_key: pk.public.to_bytes(),
        },
        &log.user_hash[&user],
    )
}

/// The auditor's PoC: the genuine, already-installed checkpoint replayed with
/// member 1's MEK replaced by an attacker key. Refused; so are an added entry,
/// a missing entry and reordered entries under the genuine checkpoint.
#[tokio::test]
async fn genuine_checkpoint_with_attacker_mek_is_rejected() {
    let f = fixture();
    let mark = f.sealer.high_water_mark();
    let genuine = f.current_bundle();
    assert_eq!(genuine.checkpoint.tree_size, mark.tree_size);
    assert_eq!(genuine.checkpoint.root_hash, mark.root_hash);
    let evil = KemKeyPair::generate(Suite::CandorStd1).unwrap();
    let evil_entry = {
        let log = f.log.lock().unwrap();
        signed_entry(
            &kd_entry(
                ty::MEMBER_EPOCH,
                &mek_subject(f.members[0].user_id),
                1,
                None,
                0,
                1,
                mek_value(f.members[0].user_id, &evil, &log),
            ),
            &[&attacker()],
        )
    };
    // Substituted MEK entry.
    let mut b = genuine.clone();
    let i = find_entry(&b, &f.members[0].mek.public.to_bytes());
    b.entries[i] = evil_entry.clone();
    assert_eq!(
        f.sealer.install_snapshot(b, |_| true),
        Err(SnapshotError::Inclusion)
    );
    // Added entry.
    let mut b = genuine.clone();
    b.entries.push(evil_entry);
    assert_eq!(
        f.sealer.install_snapshot(b, |_| true),
        Err(SnapshotError::Inclusion)
    );
    // Missing entry (e.g. a withheld REVOCATION or newer roster).
    let mut b = genuine.clone();
    b.entries.remove(i);
    assert_eq!(
        f.sealer.install_snapshot(b, |_| true),
        Err(SnapshotError::Inclusion)
    );
    // Reordered entries.
    let mut b = genuine.clone();
    b.entries.swap(i, i - 1);
    assert_eq!(
        f.sealer.install_snapshot(b, |_| true),
        Err(SnapshotError::Inclusion)
    );
    assert_eq!(f.sealer.high_water_mark(), mark);
    // The genuine bundle itself re-installs, and sealing still goes only to
    // the real MEKs: the attacker key opens nothing.
    f.sealer.install_snapshot(genuine, |_| true).unwrap();
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
    let env = &f.sink.envelopes()[0];
    assert!(open_intake(&env.objects[0], member_ctx(0), &evil.private).is_none());
    assert!(open_intake(&env.objects[0], member_ctx(0), &f.members[0].mek.private).is_some());
}

/// With a compromised LOG_KEY (validly signed checkpoint over a doctored log),
/// entries still need their own signers: a MEK not signed by the member's
/// current K08 (attacker key, another member's K08), a roster or COI policy
/// not signed by the CIK, a role-label certificate not signed by OVERSIGHT, a
/// relabelled member in a "tightening" entry, a loosening entry without an
/// independent approver or inside its time lock, bit-flipped entries and
/// garbage are all refused.
#[test]
fn entries_need_their_own_signers_even_under_a_compromised_log() {
    let f = fixture();
    let u1 = f.members[0].user_id;
    let evil = KemKeyPair::generate(Suite::CandorStd1).unwrap();
    let entry_err = |bd: SnapshotBundle| verify(&f, bd).map(|_| ()).unwrap_err();

    // Control: the doctored log with only a filler entry verifies.
    let ok = compromised(&f, |log| {
        let a1 = admin1();
        log.append(0x0b, &[0x99; 16], 0, m(vec![(1, t("x"))]), &[&a1]);
    });
    assert!(verify(&f, ok).is_ok());

    // MEK signed by the attacker / by another member's K08.
    let bd = compromised(&f, |log| {
        let v = mek_value(u1, &evil, log);
        log.append(ty::MEMBER_EPOCH, &mek_subject(u1), 0, v, &[&attacker()]);
    });
    assert_eq!(entry_err(bd), SnapshotError::Entry);
    let bd = compromised(&f, |log| {
        let v = mek_value(u1, &evil, log);
        log.append(
            ty::MEMBER_EPOCH,
            &mek_subject(u1),
            0,
            v,
            &[&f.members[1].k08],
        );
    });
    assert_eq!(entry_err(bd), SnapshotError::Entry);
    // A MEK whose key id is not the key's (the Recipient List would lie).
    let bd = compromised(&f, |log| {
        let mut v = mek_value(u1, &evil, log);
        if let candor_sealer::proto::cbor::Value::M(kv) = &mut v {
            kv[5].1 = b(&[0x11; 32]);
        }
        log.append(
            ty::MEMBER_EPOCH,
            &mek_subject(u1),
            0,
            v,
            &[&f.members[0].k08],
        );
    });
    assert_eq!(entry_err(bd), SnapshotError::Entry);

    // Tampered role label: member 2 relabelled (label 9) in a roster signed by
    // an attacker "CIK" — and, separately, by the real CIK but declared as
    // tightening without the independent approver.
    let relabel = |log: &mut TestLog| {
        let mut rows = log.rows(&CHANNEL);
        rows[1].1 = 9;
        log.cert(CHANNEL, 9);
        rows
    };
    let bd = compromised(&f, |log| {
        let rows = relabel(log);
        let v = log.next_roster_version(&CHANNEL);
        let body = log.roster_body(CHANNEL, &rows, TODAY + 3, true, Some(ALT_CHANNEL), v);
        log.append(
            ty::CHANNEL_ROSTER,
            &CHANNEL,
            TODAY,
            body,
            &[&attacker(), &admin1(), &oversight_k08()],
        );
    });
    assert_eq!(entry_err(bd), SnapshotError::Entry);
    let bd = compromised(&f, |log| {
        let rows = relabel(log);
        let v = log.next_roster_version(&CHANNEL);
        let body = log.roster_body(CHANNEL, &rows, TODAY, false, Some(ALT_CHANNEL), v);
        log.append(
            ty::CHANNEL_ROSTER,
            &CHANNEL,
            TODAY,
            body,
            &[&cik(), &admin1()],
        );
    });
    assert_eq!(entry_err(bd), SnapshotError::Entry);
    // Loosening, CIK-signed, but no independent approver.
    let bd = compromised(&f, |log| {
        let rows = relabel(log);
        let v = log.next_roster_version(&CHANNEL);
        let body = log.roster_body(CHANNEL, &rows, TODAY + 3, true, Some(ALT_CHANNEL), v);
        log.append(
            ty::CHANNEL_ROSTER,
            &CHANNEL,
            TODAY,
            body,
            &[&cik(), &admin1()],
        );
    });
    assert_eq!(entry_err(bd), SnapshotError::Entry);
    // Fully approved loosening, but activating inside the time lock
    // (backdated `not_before`; the sealer's own mark is today).
    let bd = compromised(&f, |log| {
        let rows = relabel(log);
        let v = log.next_roster_version(&CHANNEL);
        let body = log.roster_body(CHANNEL, &rows, TODAY + 1, true, Some(ALT_CHANNEL), v);
        log.append(
            ty::CHANNEL_ROSTER,
            &CHANNEL,
            TODAY - 10,
            body,
            &[&cik(), &admin1(), &oversight_k08()],
        );
    });
    assert_eq!(entry_err(bd), SnapshotError::Entry);
    // Control: the same relabel, fully approved and time-locked, verifies.
    let bd = compromised(&f, |log| {
        let rows = relabel(log);
        let v = log.next_roster_version(&CHANNEL);
        let body = log.roster_body(CHANNEL, &rows, TODAY + 3, true, Some(ALT_CHANNEL), v);
        log.append(
            ty::CHANNEL_ROSTER,
            &CHANNEL,
            TODAY,
            body,
            &[&cik(), &admin1(), &oversight_k08()],
        );
    });
    assert!(verify(&f, bd).is_ok());
    // COI policy loosened (category 7 no longer excludes label 2) without CIK.
    let bd = compromised(&f, |log| {
        let body = m(vec![
            (1, u(2)),
            (2, u(u64::from(TODAY + 3))),
            (3, u(1)),
            (4, a(vec![])),
            (5, a(vec![])),
        ]);
        log.append(
            ty::COI_POLICY,
            &CHANNEL,
            TODAY,
            body,
            &[&attacker(), &admin1(), &oversight_k08()],
        );
    });
    assert_eq!(entry_err(bd), SnapshotError::Entry);
    // Control: the same loosening, CIK-signed, approved and time-locked.
    let bd = compromised(&f, |log| {
        let body = m(vec![
            (1, u(2)),
            (2, u(u64::from(TODAY + 3))),
            (3, u(1)),
            (4, a(vec![])),
            (5, a(vec![])),
        ]);
        log.append(
            ty::COI_POLICY,
            &CHANNEL,
            TODAY,
            body,
            &[&cik(), &admin1(), &oversight_k08()],
        );
    });
    assert!(verify(&f, bd).is_ok());
    // ... or declared "tightening" with the real CIK.
    let bd = compromised(&f, |log| {
        let body = m(vec![
            (1, u(2)),
            (2, u(u64::from(TODAY))),
            (3, u(0)),
            (4, a(vec![])),
            (5, a(vec![])),
        ]);
        log.append(ty::COI_POLICY, &CHANNEL, TODAY, body, &[&cik(), &admin1()]);
    });
    assert_eq!(entry_err(bd), SnapshotError::Entry);
    // Control: a MEK re-published by the member's own K08 verifies (it then
    // makes the epoch ambiguous, so neither key is used).
    let bd = compromised(&f, |log| {
        let v = mek_value(u1, &evil, log);
        log.append(
            ty::MEMBER_EPOCH,
            &mek_subject(u1),
            0,
            v,
            &[&f.members[0].k08],
        );
    });
    let s = verify(&f, bd).unwrap();
    assert!(
        s.channel(&CHANNEL)
            .unwrap()
            .meks
            .iter()
            .filter(|k| k.user_id == u1)
            .all(|k| k.revoked)
    );
    // Role-label certificate signed by a key admin instead of OVERSIGHT.
    let bd = compromised(&f, |log| {
        let subject = kd::role_label_subject(&CHANNEL, 40);
        let body = TestLog::cert_body(&CHANNEL, 40, true, TODAY + 30);
        log.append(ty::ROLE_LABEL_CERT, &subject, 0, body, &[&admin1()]);
    });
    assert_eq!(entry_err(bd), SnapshotError::Entry);
    // An existing entry bit-flipped (its signature no longer verifies).
    let bd = compromised(&f, |log| {
        let i = log
            .entries
            .iter()
            .position(|e| contains(e, &f.members[1].mek.public.to_bytes()))
            .unwrap();
        let k = log.entries[i].len() - 70;
        log.entries[i][k] ^= 1;
    });
    assert_eq!(entry_err(bd), SnapshotError::Entry);
    // Broken continuity: a second "seq 1" for an existing subject.
    let bd = compromised(&f, |log| {
        let v = mek_value(u1, &f.members[0].mek, log);
        let e = kd_entry(ty::MEMBER_EPOCH, &mek_subject(u1), 1, None, 0, 1, v);
        log.push_raw(signed_entry(&e, &[&f.members[0].k08]));
    });
    assert_eq!(entry_err(bd), SnapshotError::Entry);
    // Garbage and an unknown entry type.
    let bd = compromised(&f, |log| log.push_raw(vec![0xa2, 0x01, 0x40, 0x02, 0x80]));
    assert_eq!(entry_err(bd), SnapshotError::Entry);
    let bd = compromised(&f, |log| {
        let e = kd_entry(0x7f, &[1; 16], 1, None, 0, 1, m(vec![]));
        log.push_raw(signed_entry(&e, &[&admin1()]));
    });
    assert_eq!(entry_err(bd), SnapshotError::Entry);
    // Nothing above was installed.
    assert_eq!(
        f.sealer.high_water_mark().tree_size,
        f.current_bundle().checkpoint.tree_size
    );
}

/// Revocations and K08 rotations take effect; objections block loosening.
#[test]
fn revocations_rotations_and_objections_shrink_the_recipient_set() {
    let f = fixture();
    let (u1, u2) = (f.members[0].user_id, f.members[1].user_id);
    let usable = |snap: &VerifiedSnapshot, user: [u8; 16]| {
        snap.channel(&CHANNEL)
            .unwrap()
            .meks
            .iter()
            .any(|k| k.user_id == user && !k.revoked)
    };
    let base = verify(&f, f.current_bundle()).unwrap();
    assert!(usable(&base, u1) && usable(&base, u2));
    // AUD-RM2-SEA-25 PoC: a REVOCATION of member 1's MEK signed by an
    // attacker (or by a key admin alone) makes the snapshot invalid…
    let kid = candor_core::hash::key_id(
        Suite::CandorStd1,
        candor_core::hash::KeyKind::Mek,
        &f.members[0].mek.public.to_bytes(),
    );
    let revoke_mek = |signers: &[&SigningKey]| {
        compromised(&f, |log| {
            log.append(
                ty::REVOCATION,
                &kid,
                0,
                m(vec![(1, b(&kid)), (2, u(1)), (3, u(u64::from(TODAY)))]),
                signers,
            );
        })
    };
    let (att, a1, c, root) = (attacker(), admin1(), cik(), k01());
    for bad in [vec![&att], vec![&a1], vec![&f.members[1].k08]] {
        assert_eq!(
            verify(&f, revoke_mek(&bad)).map(|_| ()).unwrap_err(),
            SnapshotError::Entry
        );
    }
    // …while the member's own K08, the CIK with a K15, or K01 may revoke it.
    for good in [vec![&f.members[0].k08], vec![&c, &a1], vec![&root]] {
        let s = verify(&f, revoke_mek(&good)).unwrap();
        assert!(!usable(&s, u1) && usable(&s, u2));
    }
    // Member 2 rotates K08 (a valid USER_KEYS seq 2): the MEK signed by the old
    // K08 is no longer usable until re-published (§12.1 step 6).
    let bd = compromised(&f, |log| {
        log.add_user(u2, &SigningKey::from_seed(&[0x52; 32]));
    });
    let s = verify(&f, bd).unwrap();
    assert!(usable(&s, u1) && !usable(&s, u2));
    // Revoking member 2's K08 public key has the same effect, if signed by
    // that key itself (or K15 + OVERSIGHT, or K01); a K15 alone is refused.
    let revoke_k08 = |signers: &[&SigningKey]| {
        compromised(&f, |log| {
            let pk = f.members[1].k08.verifying_key_bytes();
            log.append(
                ty::REVOCATION,
                &pk,
                0,
                m(vec![(1, b(&pk)), (2, u(1)), (3, u(u64::from(TODAY)))]),
                signers,
            );
        })
    };
    assert_eq!(
        verify(&f, revoke_k08(&[&admin1()]))
            .map(|_| ())
            .unwrap_err(),
        SnapshotError::Entry
    );
    for s in [
        verify(&f, revoke_k08(&[&f.members[1].k08])).unwrap(),
        verify(&f, revoke_k08(&[&admin1(), &oversight_k08()])).unwrap(),
    ] {
        assert!(!usable(&s, u2));
        assert!(!s.user_keys.iter().any(|k| k.user_id == u2));
    }
    // Revoking an unknown key or the LOG_KEY needs K01.
    let revoke_other = |key: [u8; 32], signers: &[&SigningKey]| {
        compromised(&f, |log| {
            log.append(
                ty::REVOCATION,
                &key,
                0,
                m(vec![(1, b(&key)), (2, u(1)), (3, u(u64::from(TODAY)))]),
                signers,
            );
        })
    };
    let lk = log_key().verifying_key_bytes();
    assert_eq!(
        verify(&f, revoke_other(lk, &[&log_key()]))
            .map(|_| ())
            .unwrap_err(),
        SnapshotError::Entry
    );
    assert!(verify(&f, revoke_other([0x5a; 32], &[&k01()])).is_ok());
    // A properly approved loosening roster (adds member 5, active in 3 days)
    // activates — unless an OBJECTION references it (§14.4 rule 8).
    let k5 = SigningKey::from_seed(&[0x55; 32]);
    let add5 = |log: &mut TestLog| -> [u8; 32] {
        log.add_user([5; 16], &k5);
        log.cert(CHANNEL, 5);
        let mut rows = log.rows(&CHANNEL);
        rows.push(([5; 16], 5, caps::READ_INTAKE));
        let v = log.next_roster_version(&CHANNEL);
        let body = log.roster_body(CHANNEL, &rows, TODAY + 3, true, Some(ALT_CHANNEL), v);
        log.append(
            ty::CHANNEL_ROSTER,
            &CHANNEL,
            TODAY,
            body,
            &[&cik(), &admin1(), &oversight_k08()],
        )
    };
    let in_active = |s: &VerifiedSnapshot, day: u32| {
        s.channel(&CHANNEL)
            .unwrap()
            .active_roster(day)
            .unwrap()
            .members
            .iter()
            .any(|m| m.user_id == [5; 16])
    };
    let s = verify(
        &f,
        compromised(&f, |log| {
            add5(log);
        }),
    )
    .unwrap();
    assert!(!in_active(&s, TODAY + 2) && in_active(&s, TODAY + 3));
    let objected = |resolve: bool, objector: &SigningKey| {
        compromised(&f, |log| {
            let h = add5(log);
            let subject = kd::objection_subject(&CHANNEL, &h);
            let body = |r: bool| {
                m(vec![
                    (1, b(&CHANNEL)),
                    (2, b(&h)),
                    (3, u(1)),
                    (4, candor_sealer::proto::cbor::Value::Bool(r)),
                ])
            };
            log.append(ty::OBJECTION, &subject, 0, body(false), &[objector]);
            if resolve {
                // A resolution needs two OVERSIGHT signatures; one is refused.
                log.append(ty::OBJECTION, &subject, 0, body(true), &[&oversight_k08()]);
            }
        })
    };
    let s = verify(&f, objected(false, &f.members[2].k08)).unwrap();
    assert!(!in_active(&s, TODAY + 3));
    let s = verify(&f, objected(false, &oversight_k08())).unwrap();
    assert!(!in_active(&s, TODAY + 3));
    assert_eq!(
        verify(&f, objected(true, &f.members[2].k08))
            .map(|_| ())
            .unwrap_err(),
        SnapshotError::Entry
    );
    // SEA-25 PoC: an objection by a non-member cannot block the loosening.
    assert_eq!(
        verify(&f, objected(false, &attacker()))
            .map(|_| ())
            .unwrap_err(),
        SnapshotError::Entry
    );
}

/// AUD-RM2-SEA-27: K01 signatures are hybrid; both halves must verify, and
/// every ML-DSA half on any entry must verify against a known key.
#[test]
fn k01_entries_need_both_signature_halves() {
    let f = fixture();
    let verify_raw = |edit: &dyn Fn(&mut TestLog)| verify(&f, compromised(&f, |log| edit(log)));
    // A new KEY_ADMIN (K01-signed, 04 §14.2 "both algs").
    let body = || {
        m(vec![
            (
                1,
                b(&SigningKey::from_seed(&[0x77; 32]).verifying_key_bytes()),
            ),
            (2, u(1)),
        ])
    };
    let entry = |log: &TestLog| {
        let _ = log;
        kd_entry(ty::KEY_ADMIN, &[0x12; 16], 1, None, 0, 1, body())
    };
    let raw = |sigs: Vec<candor_sealer::proto::cbor::Value>, e: &[u8]| {
        m(vec![(1, b(e)), (2, a(sigs))]).encode().unwrap().to_vec()
    };
    let ed = |k: &SigningKey, e: &[u8]| {
        m(vec![
            (1, b(&k.verifying_key_bytes())),
            (2, u(kd::alg::ED25519)),
            (3, b(&k.sign(&kd::signing_message(e)))),
        ])
    };
    // Control: both halves.
    assert!(
        verify_raw(&|log| {
            let e = entry(log);
            log.push_raw(signed_entry(&e, &[&k01()]));
        })
        .is_ok()
    );
    // Ed25519 half only.
    assert_eq!(
        verify_raw(&|log| {
            let e = entry(log);
            log.push_raw(raw(vec![ed(&k01(), &e)], &e));
        })
        .map(|_| ())
        .unwrap_err(),
        SnapshotError::Entry
    );
    // ML-DSA half over a different message.
    assert_eq!(
        verify_raw(&|log| {
            let e = entry(log);
            let pq = mldsa_sig(k01_mldsa(), b"another message");
            log.push_raw(raw(vec![ed(&k01(), &e), pq], &e));
        })
        .map(|_| ())
        .unwrap_err(),
        SnapshotError::Entry
    );
    // An ML-DSA half by an unknown key on an otherwise valid entry.
    assert_eq!(
        verify_raw(&|log| {
            let e = entry(log);
            let other =
                ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_dsa::B32::from([9; 32]));
            let msg = kd::signing_message(&e);
            log.push_raw(raw(
                vec![
                    ed(&k01(), &e),
                    mldsa_sig(k01_mldsa(), &msg),
                    mldsa_sig(&other, &msg),
                ],
                &e,
            ));
        })
        .map(|_| ())
        .unwrap_err(),
        SnapshotError::Entry
    );
    // An ECDSA-P384 entry is not carried unverified.
    assert_eq!(
        verify_raw(&|log| {
            let e = entry(log);
            let msg = kd::signing_message(&e);
            let ec = m(vec![
                (1, b(&[1; 32])),
                (2, u(kd::alg::ECDSA_P384)),
                (3, b(&[0; 96])),
            ]);
            log.push_raw(raw(
                vec![ed(&k01(), &e), mldsa_sig(k01_mldsa(), &msg), ec],
                &e,
            ));
        })
        .map(|_| ())
        .unwrap_err(),
        SnapshotError::Entry
    );
}
