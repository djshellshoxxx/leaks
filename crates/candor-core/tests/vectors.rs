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
use candor_core::kdf::derive_case_record_key;
use candor_core::kem::{KemKeyPair, KemPublicKey};
use candor_core::object::parse;
use candor_core::passphrase::{SourceKeys, Wordlist, normalize, source_salt};
use candor_core::record::{RecordAad, open_record};
use candor_core::secret::{AeadKey, CaseKey, ContentKey, ErasureKey};
use candor_core::slots::{RecipientListEntry, RecipientSlotBlock, SlotContext};
use candor_core::stanza::{HpkeWrapContext, WrapStanza};
use candor_core::stream::StreamDecryptor;
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
        assert_eq!(
            normalize(c["input_as_typed"].as_str().unwrap())
                .unwrap()
                .as_str(),
            p
        );
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

/// An independent STREAM encoder (§13.3) over the `chacha20poly1305` crate, used to
/// rebuild large vector ciphertexts that are published only by hash.
fn independent_stream_encrypt(key: &[u8], pt: &[u8]) -> Vec<u8> {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
    let c = ChaCha20Poly1305::new_from_slice(key).unwrap();
    let chunks: Vec<&[u8]> = if pt.is_empty() {
        vec![&[][..]]
    } else {
        pt.chunks(stream::CHUNK_SIZE).collect()
    };
    let n = chunks.len();
    let mut out = Vec::new();
    for (i, ch) in chunks.into_iter().enumerate() {
        let nonce = stream::chunk_nonce(i as u64, i + 1 == n);
        out.extend_from_slice(&c.encrypt(&nonce.into(), ch).unwrap());
    }
    out
}

/// §13.3 positive and negative STREAM vectors (CRYPTO-007).
#[test]
fn stream_vectors() {
    use sha2::{Digest, Sha256};
    let v = load("stream");
    let ck = ContentKey::from_slice(&hx(&v["ck"])).unwrap();
    let nonce: [u8; 16] = a(&v["payload_nonce"]);
    // AUD-RM1-CORE-04: the public API has no raw-key STREAM encryptor; the vectors
    // are checked through the decrypt side (K_pay derived from CK and the nonce) and
    // the published k_pay through the raw-key decryptor.
    let key = || AeadKey::from_slice(&hx(&v["k_pay"])).unwrap();
    let pattern = |n: usize| (0..n).map(|i| (i % 251) as u8).collect::<Vec<u8>>();
    // Each ciphertext is rebuilt with an independent §13.3 encoder under the published
    // k_pay and must match the published hash (and bytes, where given); decrypting it
    // with the CK/nonce-derived decryptor proves k_pay = HKDF(CK, payload_nonce).
    let mut big = Vec::new();
    for c in v["cases"].as_array().unwrap() {
        let n = c["plaintext_len"].as_u64().unwrap() as usize;
        let ct = independent_stream_encrypt(&hx(&v["k_pay"]), &pattern(n));
        assert_eq!(
            hex::encode(Sha256::digest(&ct)),
            c["ciphertext_sha256"].as_str().unwrap()
        );
        if let Some(full) = c.get("ciphertext") {
            assert_eq!(ct, hx(full));
        }
        let d = StreamDecryptor::for_payload(STD, &ck, &nonce, n as u64).unwrap();
        assert_eq!(
            stream::decrypt_with(d, &ct).unwrap().as_slice(),
            pattern(n).as_slice()
        );
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
    // Key Directory stub: members 0 and 1 only.
    let directory: Vec<KemPublicKey> = members[..2].iter().map(|m| m.public.clone()).collect();
    let dir = |kid: &[u8; 32]| {
        directory
            .iter()
            .find(|pk| key_id(STD, KeyKind::Mek, &pk.to_bytes()) == *kid)
            .cloned()
    };
    let parse_list = |x: &Value| -> Vec<RecipientListEntry> {
        x.as_array()
            .unwrap()
            .iter()
            .map(|e| RecipientListEntry::from_bytes(&hx(e)).unwrap())
            .collect()
    };
    let list = parse_list(&v["recipient_list"]);
    assert_eq!(list.len(), 2);
    for (i, m) in members.iter().enumerate() {
        let r = blk.trial_open(&m.private, &b);
        if i < 2 {
            let (ck, pos) = r.unwrap();
            assert_eq!(ck.expose().to_vec(), ck_expected);
            assert!(list.iter().any(|e| usize::from(e.slot_index()) == pos));
            blk.verify_slot_block(&ck, &b, &list, dir).unwrap();
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
    // The Recipient List travels inside the payload (toy layout, see vector description).
    let off = hx(&v["inner_prefix"]).len();
    assert_eq!(usize::from(pt[off]), list.len());
    for (i, e) in list.iter().enumerate() {
        assert_eq!(pt[off + 1 + 97 * i..off + 1 + 97 * (i + 1)], *e.to_bytes());
    }
    assert_eq!(pt.len(), 4096);

    // Dummy-slot KAT: an all-dummy block is deterministic.
    let dk = &v["dummy_slot_kat"];
    let (dummy, _) = RecipientSlotBlock::build(&ck, &b, &[]).unwrap();
    assert_eq!(dummy.hash().to_vec(), hx(&dk["slot_block_sha256"]));
    assert_eq!(
        dummy.encode()[4..4 + candor_core::slots::SLOT_LEN].to_vec(),
        hx(&dk["slot_0"])
    );
    dummy.verify_slot_block(&ck, &b, &[], dir).unwrap();

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

    // ADR-050(3) negatives: hidden extra recipient; listed member swapped for another key.
    for name in ["hidden_recipient", "swapped_recipient"] {
        let n = &neg[name];
        let nb = hx(&n["sealed_object"]);
        let np = parse(&nb).unwrap();
        let nblk = RecipientSlotBlock::decode(&hx(&n["slot_block"])).unwrap();
        np.check_slot_block(&nblk).unwrap();
        let nbind = np.slot_binding(ctx.clone());
        let nlist = parse_list(&n["recipient_list"]);
        assert!(
            np.open(&ck).is_ok(),
            "{name}: envelope itself is well-formed"
        );
        assert_eq!(
            nblk.verify_slot_block(&ck, &nbind, &nlist, dir).err(),
            Some(Error::SlotVerification),
            "{name}"
        );
    }
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
