// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Verifies the published Candor vectors (`tests/vectors/*.json`, §22.2 `crypto-vectors`)
//! through the public API only, as an independent implementation would.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use candor_core::hash::{EvidenceHasher, KeyKind, key_id, lookup_tag};
use candor_core::kdf::{derive_case_record_key, derive_payload_key};
use candor_core::kem::KemKeyPair;
use candor_core::object::parse;
use candor_core::passphrase::{SourceKeys, Wordlist, normalize, source_salt};
use candor_core::record::{RecordAad, open_record};
use candor_core::secret::{AeadKey, CaseKey, ContentKey, ErasureKey};
use candor_core::slots::{RecipientSlotBlock, SlotContext};
use candor_core::stanza::{HpkeWrapContext, WrapStanza};
use candor_core::{Error, Suite, padding, stream};
use serde_json::Value;

const STD: Suite = Suite::CandorStd1;

fn load(name: &str) -> Value {
    let text = match name {
        "passphrase" => include_str!("vectors/passphrase.json"),
        "stream" => include_str!("vectors/stream.json"),
        "sealed_object" => include_str!("vectors/sealed_object.json"),
        "stanza" => include_str!("vectors/stanza.json"),
        "record" => include_str!("vectors/record.json"),
        "misc" => include_str!("vectors/misc.json"),
        _ => panic!("unknown"),
    };
    serde_json::from_str(text).unwrap()
}

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn a<const N: usize>(v: &Value) -> [u8; N] {
    hx(v).try_into().unwrap()
}

/// CRYPTO-072 / §11.3 vectors with the full Argon2id parameters.
#[test]
fn passphrase_vectors() {
    let v = load("passphrase");
    let list = Wordlist::eff_large().unwrap();
    for c in v["cases"].as_array().unwrap() {
        let p = c["passphrase"].as_str().unwrap();
        assert!(list.check(p));
        assert_eq!(normalize(c["input_as_typed"].as_str().unwrap()).as_str(), p);
        assert_eq!(c["normalized"].as_str().unwrap(), p);
        let ds: [u8; 32] = a(&c["deployment_salt"]);
        let t: [u8; 16] = a(&c["tenant_id"]);
        assert_eq!(source_salt(&ds, &t).to_vec(), hx(&c["salt"]));
        let k = SourceKeys::derive(STD, c["input_as_typed"].as_str().unwrap(), &ds, &t).unwrap();
        assert_eq!(k.lookup_id().expose().to_vec(), hx(&c["lookup_id"]));
        assert_eq!(k.lookup_tag().to_vec(), hx(&c["lookup_tag"]));
        assert_eq!(
            k.auth_key().verifying_key_bytes().to_vec(),
            hx(&c["auth_pk"])
        );
        assert_eq!(
            k.sign_key().verifying_key_bytes().to_vec(),
            hx(&c["sign_pk"])
        );
        assert_eq!(k.kem_private_key().to_bytes().to_vec(), hx(&c["src_sk"]));
        assert_eq!(k.mailbox_id(0).unwrap().to_vec(), hx(&c["mailbox_id"][0]));
        assert_eq!(k.mailbox_id(1).unwrap().to_vec(), hx(&c["mailbox_id"][1]));
        assert_eq!(k.k_prefs().expose().to_vec(), hx(&c["k_prefs"]));
    }
}

/// §13.3 positive and negative STREAM vectors (CRYPTO-007).
#[test]
fn stream_vectors() {
    use sha2::{Digest, Sha256};
    let v = load("stream");
    let ck = ContentKey::from_slice(&hx(&v["ck"])).unwrap();
    let k = derive_payload_key(STD, &ck, &a(&v["payload_nonce"])).unwrap();
    assert_eq!(k.expose().to_vec(), hx(&v["k_pay"]));
    let key = || AeadKey::from_bytes(*k.expose());
    let pattern = |n: usize| (0..n).map(|i| (i % 251) as u8).collect::<Vec<u8>>();
    let mut big = Vec::new();
    for c in v["cases"].as_array().unwrap() {
        let n = c["plaintext_len"].as_u64().unwrap() as usize;
        let ct = stream::encrypt(key(), &pattern(n)).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&ct)),
            c["ciphertext_sha256"].as_str().unwrap()
        );
        if let Some(full) = c.get("ciphertext") {
            assert_eq!(ct, hx(full));
        }
        assert_eq!(
            stream::decrypt(key(), n as u64, &ct).unwrap().as_slice(),
            pattern(n).as_slice()
        );
        if n == 196_618 {
            big = ct;
        }
    }
    let n = 196_618u64;
    let cs = stream::CHUNK_CT_SIZE;
    let mut muts: Vec<(&str, Vec<u8>, u64)> = vec![
        ("truncated", big[..3 * cs].to_vec(), n),
        ("no_final", big[..3 * cs].to_vec(), 196_608),
        ("trailing", [big.clone(), vec![0]].concat(), n),
    ];
    let mut re = big.clone();
    re[..cs].copy_from_slice(&big[cs..2 * cs]);
    re[cs..2 * cs].copy_from_slice(&big[..cs]);
    muts.push(("reordered", re, n));
    let mut dup = big.clone();
    dup[cs..2 * cs].copy_from_slice(&big[..cs]);
    muts.push(("duplicated", dup, n));
    let mut flip = big.clone();
    *flip.last_mut().unwrap() ^= 1;
    muts.push(("bitflip_last", flip, n));
    assert_eq!(muts.len(), v["negative"].as_array().unwrap().len());
    for (name, ct, len) in muts {
        assert!(stream::decrypt(key(), len, &ct).is_err(), "{name}");
    }
}

/// §13.1/§13.2 sealed-object and slot-block vectors incl. negative vectors
/// (header tamper, wrong suite, tampered slot_block_hash, salamander, hidden recipient).
#[test]
fn sealed_object_vectors() {
    let v = load("sealed_object");
    let tenant_id: [u8; 16] = a(&v["tenant_id"]);
    let channel_id: [u8; 16] = a(&v["channel_id"]);
    let epoch_id = v["epoch_id"].as_u64().unwrap() as u32;
    let ctx = SlotContext::MemberEpoch {
        tenant_id,
        channel_id,
        epoch_id,
    };
    let members: Vec<KemKeyPair> = v["member_ikm"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| KemKeyPair::derive(STD, &hx(i)).unwrap())
        .collect();
    let bytes = hx(&v["sealed_object"]);
    let blk = RecipientSlotBlock::decode(&hx(&v["slot_block"])).unwrap();
    assert_eq!(blk.hash().to_vec(), hx(&v["slot_block_hash"]));
    let p = parse(&bytes).unwrap();
    assert_eq!(p.object_hash().to_vec(), hx(&v["object_hash"]));
    p.check_slot_block(&blk).unwrap();
    let b = p.slot_binding(ctx.clone());
    let ck_expected = hx(&v["ck"]);
    for (i, m) in members.iter().enumerate() {
        let r = blk.trial_open(&m.private, &b);
        if i < 2 {
            let (ck, pos) = r.unwrap();
            assert_eq!(ck.expose().to_vec(), ck_expected);
            blk.verify(&ck, &b, 2, Some(pos)).unwrap();
        } else {
            assert_eq!(
                r.err(),
                Some(Error::Authentication),
                "non-recipient cannot open"
            );
        }
    }
    let ck = ContentKey::from_slice(&ck_expected).unwrap();
    let pt = p.open(&ck).unwrap();
    assert!(pt.starts_with(&hx(&v["inner_prefix"])));
    assert_eq!(pt.len(), 4096);

    // Dummy-slot KAT: an all-dummy block is deterministic.
    let dk = &v["dummy_slot_kat"];
    let dummy = RecipientSlotBlock::build(&ck, &b, &[]).unwrap();
    assert_eq!(dummy.hash().to_vec(), hx(&dk["slot_block_sha256"]));
    assert_eq!(
        dummy.encode()[4..4 + candor_core::slots::SLOT_LEN].to_vec(),
        hx(&dk["slot_0"])
    );
    dummy.verify(&ck, &b, 0, None).unwrap();

    let neg = &v["negative"];
    let mut t = bytes.clone();
    t[neg["header_tamper"]["offset"].as_u64().unwrap() as usize] ^= 1;
    assert_eq!(
        parse(&t).unwrap().open(&ck).err(),
        Some(Error::Authentication)
    );
    let mut t = bytes.clone();
    t[7] = 3;
    assert_eq!(parse(&t).err(), Some(Error::UnknownSuite));
    t[7] = 2;
    assert_eq!(parse(&t).err(), Some(Error::UnsupportedSuite));
    let mut t = bytes.clone();
    t[48] ^= 1;
    let pt2 = parse(&t).unwrap();
    assert!(pt2.check_slot_block(&blk).is_err());
    assert!(pt2.open(&ck).is_err());
    let other = ContentKey::from_slice(&hx(&neg["salamander_other_ck"]["ck"])).unwrap();
    assert_eq!(p.open(&other).err(), Some(Error::Authentication));

    let hr = &neg["hidden_recipient"];
    let hb = hx(&hr["sealed_object"]);
    let hp = parse(&hb).unwrap();
    let hblk = RecipientSlotBlock::decode(&hx(&hr["slot_block"])).unwrap();
    hp.check_slot_block(&hblk).unwrap();
    let hb2 = hp.slot_binding(ctx);
    let (hck, pos) = hblk.trial_open(&members[0].private, &hb2).unwrap();
    assert_eq!(
        hblk.verify(
            &hck,
            &hb2,
            hr["recipient_list_len"].as_u64().unwrap() as usize,
            Some(pos)
        )
        .err(),
        Some(Error::SlotVerification)
    );
}

/// §13.2 stanza vectors incl. `ek_direct_wrap` and stanza bound to another object.
#[test]
fn stanza_vectors() {
    let v = load("stanza");
    let tenant_id: [u8; 16] = a(&v["tenant_id"]);
    let case_id: [u8; 16] = a(&v["case_id"]);
    let ver = v["case_key_version"].as_u64().unwrap() as u32;
    let src = KemKeyPair::derive(STD, &hx(&v["source_ikm"])).unwrap();
    let member = KemKeyPair::derive(STD, &hx(&v["member_ikm"])).unwrap();
    assert_eq!(
        key_id(STD, KeyKind::UserEnc, &member.public.to_bytes()).to_vec(),
        hx(&v["member_key_id"])
    );
    let oh: [u8; 32] = a(&v["object_hash"]);
    let ck = hx(&v["ck"]);
    let reply = WrapStanza::decode(&hx(&v["reply_hpke_base"])).unwrap();
    let rctx = HpkeWrapContext::Reply {
        tenant_id,
        channel_id: [0; 16],
        mailbox_id: a(&v["mailbox_id"]),
    };
    assert_eq!(
        reply
            .open_hpke_ck(&src.private, &rctx, &oh)
            .unwrap()
            .expose()
            .to_vec(),
        ck
    );
    assert!(reply.open_hpke_ck(&src.private, &rctx, &[0u8; 32]).is_err());
    let case_key = CaseKey::from_slice(&hx(&v["case_key"])).unwrap();
    let ca = WrapStanza::decode(&hx(&v["case_aead"])).unwrap();
    assert_eq!(
        ca.open_case_aead(&case_key, tenant_id, case_id, ver, &oh)
            .unwrap()
            .expose()
            .to_vec(),
        ck
    );
    let ek = ErasureKey::from_slice(&hx(&v["erasure_key"])).unwrap();
    let outer = WrapStanza::decode(&hx(&v["casekey_ek"])).unwrap();
    let inner = outer.open_casekey_ek(&ek, tenant_id, case_id, ver).unwrap();
    assert_eq!(inner.encode().unwrap(), hx(&v["casekey_hpke_base"]));
    let got = inner
        .unwrap_case_key(&member.private, tenant_id, case_id, ver)
        .unwrap();
    assert_eq!(got.expose(), case_key.expose());
    let direct = WrapStanza::decode(&hx(&v["negative"]["ek_direct_wrap"])).unwrap();
    assert!(
        direct
            .open_casekey_ek(&ek, tenant_id, case_id, ver)
            .is_err()
    );
}

/// §13.8 record vectors (CRYPTO-054 stale-row negative).
#[test]
fn record_vectors() {
    let v = load("record");
    let case_key = CaseKey::from_slice(&hx(&v["case_key"])).unwrap();
    let table_id = v["table_id"].as_u64().unwrap() as u16;
    let k = derive_case_record_key(&case_key, table_id).unwrap();
    assert_eq!(k.expose().to_vec(), hx(&v["record_key"]));
    let mk = |row_version: u64| RecordAad::Case {
        tenant_id: a(&v["tenant_id"]),
        case_id: a(&v["case_id"]),
        table_id,
        column_id: v["column_id"].as_u64().unwrap() as u16,
        record_id: a(&v["record_id"]),
        row_version,
    };
    let rec = hx(&v["record"]);
    let pt = open_record(&k, &mk(v["row_version"].as_u64().unwrap()), &rec).unwrap();
    assert_eq!(pt.to_vec(), hx(&v["plaintext"]));
    assert!(
        open_record(
            &k,
            &mk(v["negative"]["stale_row_version"].as_u64().unwrap()),
            &rec
        )
        .is_err()
    );
}

#[test]
fn misc_vectors() {
    let v = load("misc");
    let files: Vec<u64> = v["file_buckets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap())
        .collect();
    assert_eq!(files, padding::file_buckets().collect::<Vec<_>>());
    for b in &files {
        assert!(padding::is_legal_bucket(
            candor_core::header::ObjectType::AttachmentBundle,
            *b
        ));
    }
    let pk = KemKeyPair::derive(STD, &hx(&v["key_id"]["pk_from_ikm"]))
        .unwrap()
        .public
        .to_bytes();
    assert_eq!(
        key_id(STD, KeyKind::Mek, &pk).to_vec(),
        hx(&v["key_id"]["key_id"])
    );
    assert_eq!(
        lookup_tag(&a(&v["lookup_tag"]["lookup_id"])).to_vec(),
        hx(&v["lookup_tag"]["lookup_tag"])
    );
    let e = EvidenceHasher::digest(b"abc");
    assert_eq!(e.sha256.to_vec(), hx(&v["evidence_abc"]["sha256"]));
    assert_eq!(e.blake3.to_vec(), hx(&v["evidence_abc"]["blake3"]));
}
