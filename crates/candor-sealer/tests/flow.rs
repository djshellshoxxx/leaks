// SPDX-License-Identifier: AGPL-3.0-or-later
//! Full Tier W flow in-process (ADR-034, 04 §12.3, §11, §13.4/13.5):
//! open → draft → stage → COI → passphrase → confirm → seal → login → reply,
//! follow-up and rotation, all verified from the recipient side with candor-core.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use candor_core::Suite;
use candor_core::hash::{KeyKind, sha256};
use candor_core::header::ObjectType;
use candor_core::kem::{self, KemKeyPair};
use candor_core::labels;
use candor_core::object::{self, SealRequest};
use candor_core::sig::{SigningKey, sign_with_context, verify_strict};
use candor_core::slots::SlotContext;
use candor_core::stanza::{HpkeWrapContext, WrapStanza};
use candor_sealer::proto::*;
use candor_sealer::server::AUTH_AUDIENCE;
use common::*;

const MARKER: &str = "ZZ-PLAINTEXT-MARKER-7f3a";

/// Build a REPLY dead-drop entry as a Desk would (04 §13.5).
fn make_reply(
    m: &Member,
    src_pk: &[u8],
    mailbox_id: [u8; 32],
    seq: u64,
    body: &str,
) -> (Vec<u8>, [u8; 32], Vec<u8>, Vec<u8>) {
    let req = SealRequest {
        suite: Suite::CandorStd1,
        object_type: ObjectType::Reply,
        tenant_id: TENANT,
        channel_id: [0; 16],
        epoch_id: 0,
        day_stamp: 0,
        recipients: None,
        padded_len: 4096,
    };
    let (ck, obj) = object::seal(&req, |pc| {
        let unsigned = Item::M(vec![
            (1, Item::U(1)),
            (2, Item::B(mailbox_id.to_vec())),
            (3, Item::U(seq)),
            (4, Item::U(u64::from(TODAY))),
            (5, Item::T(body.into())),
            (6, Item::B(m.entry_hash.to_vec())),
            (7, Item::T("Ombudsperson".into())),
        ]);
        let mut ub = Vec::new();
        encode_item(&unsigned, &mut ub);
        let sig = sign_with_context(
            &m.k08,
            labels::SIG_REPLY,
            &[&sha256(&[pc.header_bytes]), &sha256(&[&ub])],
        );
        let Item::M(mut entries) = unsigned else {
            panic!()
        };
        entries.push((8, Item::B(sig.to_vec())));
        let mut cbor = Vec::new();
        encode_item(&Item::M(entries), &mut cbor);
        let mut pt = (cbor.len() as u32).to_be_bytes().to_vec();
        pt.extend_from_slice(&cbor);
        pt.resize(4096, 0);
        Ok(pt)
    })
    .unwrap();
    let pk = kem::KemPublicKey::from_bytes(Suite::CandorStd1, src_pk).unwrap();
    let ctx = HpkeWrapContext::Reply {
        tenant_id: TENANT,
        channel_id: CHANNEL,
        mailbox_id,
    };
    let stanza = WrapStanza::seal_hpke_ck(
        Suite::CandorStd1,
        &pk,
        [0; 32],
        obj.object_hash,
        &ctx,
        ck.ck(),
    )
    .unwrap()
    .encode()
    .unwrap();
    let mut entry = ((obj.bytes.len() + stanza.len()) as u32)
        .to_be_bytes()
        .to_vec();
    entry.extend_from_slice(&obj.bytes);
    entry.extend_from_slice(&stanza);
    (entry, obj.object_hash, obj.bytes, stanza)
}

async fn new_account_submission(
    f: &Fixture,
    s: SessionHandle,
    coi: Option<Coi>,
    attachment: &[u8],
) -> SecretWords {
    let sl = &f.sealer;
    ok(
        sl,
        Request::Hello {
            proto: PROTO_VERSION,
        },
    )
    .await;
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
            mode: Mode::Confidential,
            message: SecretText::new(&format!("{MARKER} the CFO moved funds")),
            fields: vec![(3, SecretText::new(&format!("{MARKER}-answer")))],
            identity: Some(SecretText::new(&format!("{MARKER}-identity Jane"))),
            coi,
        }),
    )
    .await;
    let Response::Part { part } = ok(
        sl,
        Request::PartBegin {
            sess: s,
            declared_len: attachment.len() as u64 + 500,
            display_name: SecretText::new(&format!("{MARKER}.pdf")),
            media_type: SecretText::new("application/pdf"),
        },
    )
    .await
    else {
        panic!()
    };
    let chunks: Vec<&[u8]> = attachment.chunks(50_000).collect();
    for (i, c) in chunks.iter().enumerate() {
        ok(
            sl,
            Request::PartChunk {
                sess: s,
                part,
                data: SecretBytes::from_slice(c),
                last: i + 1 == chunks.len(),
            },
        )
        .await;
    }
    // The staging root holds only ciphertext, padded to a bucket (ADR-038(5)).
    for (_, bytes) in read_all_files(&f.staging_path) {
        assert!(!contains(&bytes, MARKER.as_bytes()));
        assert_eq!(
            bytes.len() % 65_552,
            0,
            "staged part not a whole number of chunks"
        );
    }
    // No passphrase exists before Submit; SEAL_FINISH refuses (ADR-034).
    let r = sl
        .handle(Request::SealFinish {
            sess: s,
            delayed_delivery: false,
        })
        .await;
    assert_eq!(r, Response::error(ErrorCode::NotConfirmed));
    let Response::Words {
        words,
        confirm_positions,
    } = ok(sl, Request::GenAccount { sess: s }).await
    else {
        panic!()
    };
    assert_eq!(words.0.len(), 10);
    // A wrong confirmation draws new positions.
    let wrong = SecretWords(zeroize::Zeroizing::new(vec![u16::MAX - 1; 3]));
    let Response::Confirm {
        ok: false,
        confirm_positions: Some(p2),
    } = ok(
        sl,
        Request::ConfirmPassphrase {
            sess: s,
            words: wrong,
        },
    )
    .await
    else {
        panic!()
    };
    let _ = confirm_positions;
    let Response::Confirm { ok: true, .. } = ok(
        sl,
        Request::ConfirmPassphrase {
            sess: s,
            words: confirm_words(&words, p2),
        },
    )
    .await
    else {
        panic!("confirmation failed")
    };
    let Response::Sealed {
        release_offset_days,
    } = ok(
        sl,
        Request::SealFinish {
            sess: s,
            delayed_delivery: true,
        },
    )
    .await
    else {
        panic!()
    };
    assert!((1..=3).contains(&release_offset_days));
    words
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_tier_w_flow() {
    let mut f = fixture();
    let s = sess(1);
    let attachment: Vec<u8> = (0..300_000u32)
        .map(|i| (i % 251) as u8)
        .chain(MARKER.bytes())
        .collect();
    // COI: the source flags role label 3 and picks the category whose policy
    // excludes label 2 → only member 1 remains (ADR-030/037).
    let coi = Coi {
        excluded_labels: zeroize::Zeroizing::new(vec![3]),
        categories: zeroize::Zeroizing::new(vec![CATEGORY_FRAUD]),
    };
    let words = new_account_submission(&f, s, Some(coi), &attachment).await;

    // Staged parts were unlinked after the commit (§9.13).
    assert!(read_all_files(&f.staging_path).is_empty());

    let envs = f.sink.envelopes();
    assert_eq!(envs.len(), 1);
    let env = &envs[0];
    assert_eq!(env.channel_id, CHANNEL);
    let types: Vec<_> = env.objects.iter().map(|o| o.object_type).collect();
    assert_eq!(
        types,
        [
            ObjectType::Submission,
            ObjectType::AttachmentBundle,
            ObjectType::Identity
        ]
    );
    // No plaintext anywhere in what the store receives.
    for o in &env.objects {
        assert!(!contains(&o.bytes, MARKER.as_bytes()));
    }
    // ADR-052(2): the account is a separate store operation and the group
    // carries no account reference; SEA-21: the account is not written next
    // to the group but in the next (shuffled, fixed-interval) batch.
    assert_eq!(f.sink.ops(), "G");
    assert_eq!(f.sealer.queued_accounts(), 1);
    assert_eq!(f.sealer.flush_accounts(), Ok(1));
    assert_eq!(f.sink.ops(), "GA");
    let upsert = f.sink.accounts()[0].clone();
    assert!(upsert.replaces.is_none());
    let account = upsert.account;

    // Recipient side: only member 1 can open; 2 (COI policy), 3 (flagged) and 4
    // (non-triage) cannot.
    let sub = &env.objects[0];
    for m in &f.members[1..] {
        assert!(open_intake(sub, member_ctx(0), &m.mek.private).is_none());
    }
    let (ck, pt) = open_intake(sub, member_ctx(0), &f.members[0].mek.private).unwrap();
    let (map, _) = parse_padded(&pt);
    assert_eq!(map.get(1).unwrap().u(), 1);
    assert_eq!(map.get(8).unwrap().u(), 0, "tier W");
    assert_eq!(map.get(9).unwrap().u(), Mode::Confidential as u64);
    assert!(map.get(13).unwrap().t().contains("CFO"));
    assert_eq!(map.get(14).unwrap().a(), &[Item::U(3)]);
    assert_eq!(map.get(17).unwrap().u(), u64::from(CATEGORY_FRAUD));
    let rl = map.get(16).unwrap();
    assert_eq!(rl.get(3).unwrap().u(), 0, "no member skipped");
    // AUD-RM2-SEA-19: the signed Recipient List and the SUBMISSION name the
    // verified checkpoint (which commits to every directory entry used), the
    // COI_POLICY entry and the active roster entry by their log hashes.
    let (coi_hash, roster_hash) = {
        let log = f.log.lock().unwrap();
        (log.coi_hashes[&CHANNEL][0], log.roster_hashes[&CHANNEL][0])
    };
    let hwm = f.sealer.high_water_mark();
    assert_eq!(rl.get(4).unwrap().b(), &coi_hash);
    let cp = [Item::U(hwm.tree_size), Item::B(hwm.root_hash.to_vec())];
    assert_eq!(rl.get(5).unwrap().a(), &cp);
    assert_eq!(map.get(7).unwrap().a(), &cp);
    assert_eq!(map.get(6).unwrap().b(), &roster_hash);
    // Full slot-block verification (ADR-050(3)) for all three objects.
    let mek_keys: Vec<(KeyKind, &KemKeyPair)> =
        f.members.iter().map(|m| (KeyKind::Mek, &m.mek)).collect();
    let list = entries(rl.get(2).unwrap());
    assert_eq!(list.len(), 1);
    verify_block(sub, &ck, member_ctx(0), &list, &mek_keys);
    // Signatures: source_sig (sign_pk, key 5) and sealer_sig (K35).
    let h_hdr = sha256(&[&sub.bytes[..128]]);
    let h_body = hash_without(&map, &[15, 19]);
    let mut msg = labels::SIG_SUBMISSION.to_vec();
    msg.extend_from_slice(&h_hdr);
    msg.extend_from_slice(&h_body);
    let sign_pk: [u8; 32] = map.get(5).unwrap().b().try_into().unwrap();
    verify_strict(&sign_pk, &msg, map.get(15).unwrap().b().try_into().unwrap()).unwrap();
    let mut msg = labels::SIG_SEALER.to_vec();
    msg.extend_from_slice(&h_hdr);
    msg.extend_from_slice(&h_body);
    let k35_pk = SigningKey::from_seed(&f.k35).verifying_key_bytes();
    verify_strict(&k35_pk, &msg, map.get(19).unwrap().b().try_into().unwrap()).unwrap();

    // Bundle: open with member 1, verify, compare bytes and manifest.
    let bundle = &env.objects[1];
    assert_eq!(map.get(10).unwrap().b(), &bundle.object_hash);
    let (bck, bpt) = open_intake(bundle, member_ctx(0), &f.members[0].mek.private).unwrap();
    verify_block(
        bundle,
        &bck,
        member_ctx(0),
        &entries(rl.get(1000).unwrap()),
        &mek_keys,
    );
    assert_eq!(&bpt[..4], b"CBDL");
    assert_eq!(u32::from_be_bytes(bpt[4..8].try_into().unwrap()), 1);
    let manifest = map.get(18).unwrap();
    let file = &manifest.get(2).unwrap().a()[0];
    assert_eq!(file.get(3).unwrap().u(), attachment.len() as u64);
    let off = file.get(6).unwrap().u() as usize;
    assert_eq!(&bpt[off..off + attachment.len()], &attachment[..]);
    assert_eq!(file.get(4).unwrap().b(), &sha256(&[&attachment]));
    assert!(file.get(1).unwrap().t().ends_with(".pdf"));
    // Identity: sealed to K13 only.
    let ident = &env.objects[2];
    let cctx = SlotContext::Custodian { tenant_id: TENANT };
    assert!(open_intake(ident, cctx.clone(), &f.members[0].mek.private).is_none());
    let (ick, ipt) = open_intake(ident, cctx.clone(), &f.custodian.private).unwrap();
    verify_block(
        ident,
        &ick,
        cctx,
        &entries(rl.get(1001).unwrap()),
        &[(KeyKind::Custodian, &f.custodian)],
    );
    let (imap, _) = parse_padded(&ipt);
    assert!(imap.get(2).unwrap().t().contains("Jane"));
    // Disposition marker: real (kind 0) for K41.
    let info = [
        labels::WRAP_DISPOSITION,
        &Suite::CandorStd1.to_be_bytes(),
        &TENANT,
    ]
    .concat();
    let d = kem::open_base(
        &f.disposition.private,
        &env.disposition_ct[..1120],
        &info,
        &sub.object_hash,
        &env.disposition_ct[1120..],
    )
    .unwrap();
    assert_eq!(d[0], 0);

    // --- Login with the passphrase (same sealer, new web session) -------------
    let phrase = words_to_phrase(&words);
    let l = sess(2);
    let Response::Locator { lookup_tag } = ok(
        &f.sealer,
        Request::LoginDerive {
            sess: l,
            passphrase: SecretBytes::from_slice(phrase.to_uppercase().as_bytes()),
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(
        lookup_tag, account.lookup_tag,
        "normalization (NFKC, lowercase)"
    );
    let challenge = [9u8; 32];
    let Response::Signature { sig } =
        ok(&f.sealer, Request::LoginSign { sess: l, challenge }).await
    else {
        panic!()
    };
    let mut m = labels::SIG_SOURCE_AUTH.to_vec();
    m.extend_from_slice(&challenge);
    m.extend_from_slice(&TENANT);
    m.extend_from_slice(AUTH_AUDIENCE);
    verify_strict(&account.auth_pk, &m, &sig).unwrap();
    ok(
        &f.sealer,
        Request::LoadPrefs {
            sess: l,
            prefs_ct: account.prefs_ct.clone(),
        },
    )
    .await;

    // A Desk reply, decrypted for rendering.
    let src_pk = map.get(4).unwrap().b().to_vec();
    let mailbox: [u8; 32] = map.get(3).unwrap().b().try_into().unwrap();
    assert_eq!(account.mailbox_ids, vec![mailbox]);
    let (entry, _, _, _) = make_reply(
        &f.members[0],
        &src_pk,
        mailbox,
        1,
        "Thank you, we are looking into it.",
    );
    let Response::Reply(Some(view)) = ok(
        &f.sealer,
        Request::OpenReply {
            sess: l,
            entry: entry.clone(),
        },
    )
    .await
    else {
        panic!("reply did not open")
    };
    assert_eq!(view.body.expose(), "Thank you, we are looking into it.");
    assert_eq!(view.reply_seq, 1);
    // Replay and garbage are indistinguishable "not verified".
    assert_eq!(
        ok(&f.sealer, Request::OpenReply { sess: l, entry }).await,
        Response::Reply(None)
    );
    assert_eq!(
        ok(
            &f.sealer,
            Request::OpenReply {
                sess: l,
                entry: vec![0; 300]
            }
        )
        .await,
        Response::Reply(None)
    );
    // A reply signed by a key not in the directory does not verify.
    let mut rogue = member(9, 1, true);
    rogue.entry_hash = [0xee; 32];
    let (bad, _, _, _) = make_reply(&rogue, &src_pk, mailbox, 2, "spoof");
    assert_eq!(
        ok(
            &f.sealer,
            Request::OpenReply {
                sess: l,
                entry: bad
            }
        )
        .await,
        Response::Reply(None)
    );

    // --- Follow-up: sealed only to the original eligible set (ADR-036(4)) ----
    // Member 5 joins the Triage Set later (a time-locked loosening roster
    // entry, active 3 days after the sealer's last checkpoint); once active it
    // holds a valid MEK but must still get no slot.
    f.members.push(member(5, 5, true));
    let snap2 = snapshot_for(&f.members, &f.custodian, &f.disposition, 2, TODAY);
    f.install(snap2).unwrap();
    f.clock
        .day
        .store(TODAY + 3, std::sync::atomic::Ordering::SeqCst);
    let members = &f.members;
    ok(
        &f.sealer,
        Request::DraftSet(DraftSet {
            sess: l,
            mode: Mode::Anonymous,
            message: SecretText::new("more details"),
            fields: vec![],
            identity: None,
            coi: None,
        }),
    )
    .await;
    ok(
        &f.sealer,
        Request::SealFinish {
            sess: l,
            delayed_delivery: false,
        },
    )
    .await;
    let envs = f.sink.envelopes();
    let fu = &envs[1];
    // ADR-052(1): SOURCE_MESSAGE + empty bundle + dummy identity (to K13).
    let ftypes: Vec<_> = fu.objects.iter().map(|o| o.object_type).collect();
    assert_eq!(
        ftypes,
        [
            ObjectType::SourceMessage,
            ObjectType::AttachmentBundle,
            ObjectType::Identity
        ]
    );
    assert_eq!(f.sink.ops(), "GAG", "a follow-up writes no account");
    let (_, bpt) = open_intake(&fu.objects[1], member_ctx(0), &members[0].mek.private).unwrap();
    assert_eq!(&bpt[..8], b"CBDL\0\0\0\0", "empty bundle");
    let (_, ipt) = open_intake(
        &fu.objects[2],
        candor_core::slots::SlotContext::Custodian { tenant_id: TENANT },
        &f.custodian.private,
    )
    .unwrap();
    let (imap, _) = parse_padded(&ipt);
    assert_eq!(imap.get(2).unwrap().t(), "");
    assert!(open_intake(&fu.objects[0], member_ctx(0), &members[4].mek.private).is_none());
    assert!(open_intake(&fu.objects[0], member_ctx(0), &members[1].mek.private).is_none());
    let (_, fpt) = open_intake(&fu.objects[0], member_ctx(0), &members[0].mek.private).unwrap();
    let (fmap, _) = parse_padded(&fpt);
    assert_eq!(fmap.get(1).unwrap().u(), 2);
    assert_eq!(fmap.get(7).unwrap().u(), 0);
    assert_eq!(fmap.get(9).unwrap().b(), &sub.object_hash);
    assert_eq!(fmap.get(5).unwrap().t(), "more details");
    assert_eq!(fmap.get(11).unwrap().b(), &fu.objects[1].object_hash);
    assert_eq!(fmap.get(1000).unwrap().b(), &fu.objects[2].object_hash);

    // --- Rotation (ADR-046(7), 04 §11.7) --------------------------------------
    // A reply still pending for the old key, to be re-wrapped.
    let (_, pending_hash, pending_obj, pending_stanza) =
        make_reply(&members[0], &src_pk, mailbox, 2, "rewrap me");
    let Response::Words {
        words: w2,
        confirm_positions: p,
    } = ok(&f.sealer, Request::RotatePassphrase { sess: l }).await
    else {
        panic!()
    };
    let r = f
        .sealer
        .handle(Request::RotateFinish {
            sess: l,
            replies: vec![],
        })
        .await;
    assert_eq!(r, Response::error(ErrorCode::NotConfirmed));
    ok(
        &f.sealer,
        Request::ConfirmPassphrase {
            sess: l,
            words: confirm_words(&w2, p),
        },
    )
    .await;
    let Response::Locator {
        lookup_tag: new_tag,
    } = ok(
        &f.sealer,
        Request::RotateFinish {
            sess: l,
            // An entry that does not open (corrupt or planted by a compromised
            // store) is skipped and cannot block rotation (AUD-RM2-SEA-14).
            replies: vec![
                PendingReply {
                    object_hash: [0xbb; 32],
                    stanza: pending_stanza.clone(),
                },
                PendingReply {
                    object_hash: pending_hash,
                    stanza: pending_stanza,
                },
            ],
        },
    )
    .await
    else {
        panic!()
    };
    assert_ne!(new_tag, account.lookup_tag);
    // KEY_ROTATION group first, then the account replacement (ADR-052(2)) in
    // the next batch (SEA-21).
    assert_eq!(f.sink.ops(), "GAGG");
    assert_eq!(f.sealer.flush_accounts(), Ok(1));
    assert_eq!(f.sink.ops(), "GAGGA");
    let req = f.sink.accounts()[1].clone();
    let kenvs = &f.sink.envelopes()[2..];
    assert_eq!(kenvs[0].objects.len(), 3);
    assert_eq!(req.replaces, Some(account.lookup_tag));
    assert_eq!(req.account.lookup_tag, new_tag);
    assert_eq!(req.account.mailbox_ids, vec![mailbox]);
    assert_eq!(req.rewrapped_replies.len(), 1);
    // The key-update follow-up carries the new keys, signed by old and new key.
    let (_, kpt) =
        open_intake(&kenvs[0].objects[0], member_ctx(0), &members[0].mek.private).unwrap();
    let (kmap, _) = parse_padded(&kpt);
    assert_eq!(kmap.get(7).unwrap().u(), 1);
    let nk = kmap.get(10).unwrap();
    let new_sign: [u8; 32] = nk.get(1).unwrap().b().try_into().unwrap();
    let h = sha256(&[&kenvs[0].objects[0].bytes[..128]]);
    let hb = hash_without(&kmap, &[6, 12, 13]);
    let mut msg = labels::SIG_SOURCE_MESSAGE.to_vec();
    msg.extend_from_slice(&h);
    msg.extend_from_slice(&hb);
    verify_strict(&sign_pk, &msg, kmap.get(6).unwrap().b().try_into().unwrap()).unwrap();
    verify_strict(
        &new_sign,
        &msg,
        kmap.get(13).unwrap().b().try_into().unwrap(),
    )
    .unwrap();
    // The new passphrase logs in and reads the re-wrapped reply.
    let l2 = sess(3);
    let Response::Locator { lookup_tag: t2 } = ok(
        &f.sealer,
        Request::LoginDerive {
            sess: l2,
            passphrase: SecretBytes::from_slice(words_to_phrase(&w2).as_bytes()),
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(t2, new_tag);
    ok(
        &f.sealer,
        Request::LoadPrefs {
            sess: l2,
            prefs_ct: req.account.prefs_ct.clone(),
        },
    )
    .await;
    assert_eq!(req.rewrapped_replies[0].0, pending_hash);
    let new_stanza = &req.rewrapped_replies[0].1;
    let mut orig_entry = ((pending_obj.len() + new_stanza.len()) as u32)
        .to_be_bytes()
        .to_vec();
    orig_entry.extend_from_slice(&pending_obj);
    orig_entry.extend_from_slice(new_stanza);
    let Response::Reply(Some(v2)) = ok(
        &f.sealer,
        Request::OpenReply {
            sess: l2,
            entry: orig_entry,
        },
    )
    .await
    else {
        panic!("re-wrapped reply did not open")
    };
    assert_eq!(v2.body.expose(), "rewrap me");
    // The old passphrase's prefs no longer open under the new session keys.
    let r = f
        .sealer
        .handle(Request::LoadPrefs {
            sess: l2,
            prefs_ct: account.prefs_ct,
        })
        .await;
    assert!(matches!(r, Response::Error { .. }));
}

/// Rotate the passphrase of the authenticated session `l`, re-sending the
/// given pending replies; returns the new words and lookup tag.
async fn rotate(f: &Fixture, l: SessionHandle, replies: Vec<PendingReply>) -> (SecretWords, [u8; 32]) {
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
    let Response::Locator { lookup_tag } =
        ok(&f.sealer, Request::RotateFinish { sess: l, replies }).await
    else {
        panic!()
    };
    (words, lookup_tag)
}

async fn login(f: &Fixture, s: SessionHandle, words: &SecretWords) -> [u8; 32] {
    let Response::Locator { lookup_tag } = ok(
        &f.sealer,
        Request::LoginDerive {
            sess: s,
            passphrase: SecretBytes::from_slice(words_to_phrase(words).as_bytes()),
        },
    )
    .await
    else {
        panic!()
    };
    lookup_tag
}

fn entry_with(obj: &[u8], stanza: &[u8]) -> Vec<u8> {
    let mut e = ((obj.len() + stanza.len()) as u32).to_be_bytes().to_vec();
    e.extend_from_slice(obj);
    e.extend_from_slice(stanza);
    e
}

/// AUD-RM2-SEA-28 (a)/(b): a rotation blocks the old passphrase at once
/// (login consults the queue), and two rotations inside one batch window
/// coalesce: the second re-wraps from the queued (latest) stanza, so the reply
/// stays readable with the final passphrase after the batch is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn double_rotation_keeps_replies_readable() {
    let f = fixture();
    let words = new_account_submission(&f, sess(1), None, b"attachment").await;
    assert_eq!(f.sealer.flush_accounts(), Ok(1));
    let account = f.sink.accounts()[0].account.clone();
    // The source's keys and mailbox, as a Desk sees them.
    let sub = &f.sink.envelopes()[0].objects[0];
    let (_, pt) = open_intake(sub, member_ctx(0), &f.members[0].mek.private).unwrap();
    let (map, _) = parse_padded(&pt);
    let src_pk = map.get(4).unwrap().b().to_vec();
    let mailbox: [u8; 32] = map.get(3).unwrap().b().try_into().unwrap();
    let (_, hash, obj, stanza0) = make_reply(&f.members[0], &src_pk, mailbox, 1, "keep me");
    let pending = || {
        vec![PendingReply {
            object_hash: hash,
            stanza: stanza0.clone(),
        }]
    };
    // Log in and unlock the inbox.
    let l = sess(2);
    assert_eq!(login(&f, l, &words).await, account.lookup_tag);
    ok(
        &f.sealer,
        Request::LoadPrefs {
            sess: l,
            prefs_ct: account.prefs_ct.clone(),
        },
    )
    .await;
    // First rotation (queued).
    let (_w1, t1) = rotate(&f, l, pending()).await;
    // (a) The old passphrase no longer logs in, although the store still
    // holds the old account until the batch is written.
    assert_ne!(login(&f, sess(3), &words).await, account.lookup_tag);
    // The reply stays readable in the session (the queued re-wrap is used).
    let Response::Reply(Some(v)) = ok(
        &f.sealer,
        Request::OpenReply {
            sess: l,
            entry: entry_with(&obj, &stanza0),
        },
    )
    .await
    else {
        panic!("reply unreadable after the first rotation")
    };
    assert_eq!(v.body.expose(), "keep me");
    // (b) Second rotation in the same window; the caller still sends the
    // store's stale stanza (wrapped to the original key).
    let (w2, t2) = rotate(&f, l, pending()).await;
    assert_ne!(t1, t2);
    assert_eq!(f.sealer.flush_accounts(), Ok(1), "rotations coalesce");
    let req = f.sink.accounts().last().unwrap().clone();
    assert_eq!(req.replaces, Some(account.lookup_tag));
    assert_eq!(req.account.lookup_tag, t2);
    assert_eq!(req.rewrapped_replies.len(), 1);
    assert_eq!(req.rewrapped_replies[0].0, hash);
    // The final passphrase reads the reply from the re-wrapped stanza.
    let l2 = sess(4);
    assert_eq!(login(&f, l2, &w2).await, t2);
    ok(
        &f.sealer,
        Request::LoadPrefs {
            sess: l2,
            prefs_ct: req.account.prefs_ct.clone(),
        },
    )
    .await;
    let Response::Reply(Some(v2)) = ok(
        &f.sealer,
        Request::OpenReply {
            sess: l2,
            entry: entry_with(&obj, &req.rewrapped_replies[0].1),
        },
    )
    .await
    else {
        panic!("re-wrapped reply unreadable after a double rotation")
    };
    assert_eq!(v2.body.expose(), "keep me");
}
