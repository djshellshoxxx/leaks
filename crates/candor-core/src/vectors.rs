// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Deterministic Candor test-vector generator (§22.2, CRYPTO-038). Test-only.
//!
//! All randomness comes from `TestRng` (ChaCha20 with fixed seeds), so the output is
//! reproducible. `CANDOR_REGEN_VECTORS=1 cargo test -p candor-core vectors` rewrites
//! `tests/vectors/*.json`; otherwise the test fails if a committed file differs from
//! what this code generates (format regression guard). The files are verified through
//! the public API by `tests/vectors.rs`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use crate::hash::{EvidenceHasher, KeyKind, casekey_bound_hash, key_id, lookup_tag};
use crate::header::ObjectType;
use crate::kdf::{derive_case_record_key, derive_payload_key};
use crate::kem::KemKeyPair;
use crate::object::{SealRequest, seal_with_ck_rng};
use crate::padding::{file_buckets, pad};
use crate::passphrase::{SourceKeys, Wordlist, generate_with, normalize, source_salt};
use crate::rand::{RandomSource, TestRng};
use crate::record::{RecordAad, seal_record_with};
use crate::secret::{AeadKey, CaseKey, ContentKey, ErasureKey};
use crate::slots::{RecipientSlotBlock, SlotBinding, SlotContext};
use crate::stanza::{HpkeWrapContext, StanzaType, WrapStanza};
use crate::stream;
use crate::suite::Suite;
use serde_json::{Value, json};

const STD: Suite = Suite::CandorStd1;

fn h(b: &[u8]) -> String {
    hex::encode(b)
}

fn arr<const N: usize>(rng: &mut TestRng) -> [u8; N] {
    let mut a = [0u8; N];
    rng.fill(&mut a).unwrap();
    a
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn passphrase_vectors() -> Value {
    let mut rng = TestRng::new(0xA0);
    let list = Wordlist::eff_large().unwrap();
    let mut cases = Vec::new();
    for _ in 0..2 {
        let p = generate_with(&mut rng, list).unwrap();
        let deployment_salt: [u8; 32] = arr(&mut rng);
        let tenant_id: [u8; 16] = arr(&mut rng);
        // A messy but equivalent rendering of the same passphrase (normalization input).
        let messy = format!(
            "  {}  ",
            p.expose().to_uppercase().replace(' ', " -\u{2014}\t")
        );
        let k = SourceKeys::derive(STD, &messy, &deployment_salt, &tenant_id).unwrap();
        cases.push(json!({
            "passphrase": p.expose(),
            "input_as_typed": messy,
            "normalized": normalize(&messy).as_str(),
            "deployment_salt": h(&deployment_salt),
            "tenant_id": h(&tenant_id),
            "suite": STD.id(),
            "argon2id": {"m_kib": 65536, "t": 3, "p": 1, "len": 32, "version": 19},
            "salt": h(&source_salt(&deployment_salt, &tenant_id)),
            "lookup_id": h(k.lookup_id().expose()),
            "lookup_tag": h(&k.lookup_tag()),
            "auth_pk": h(&k.auth_key().verifying_key_bytes()),
            "sign_pk": h(&k.sign_key().verifying_key_bytes()),
            "src_sk": h(&k.kem_private_key().to_bytes()),
            "src_pk_sha256": h(&crate::hash::sha256(&[&k.kem_public_key().to_bytes()])),
            "mailbox_id": [h(&k.mailbox_id(0).unwrap()), h(&k.mailbox_id(1).unwrap())],
            "k_prefs": h(k.k_prefs().expose()),
        }));
    }
    json!({
        "description": "Source passphrase derivation (§11.3). Wordlist: EFF large minus 4 hyphenated entries (SPEC-NOTES). src_pk = X-Wing DeriveKeyPair(kem_seed).",
        "wordlist_sha256": crate::passphrase::EFF_LARGE_WORDLIST_SHA256,
        "cases": cases,
    })
}

fn stream_vectors() -> Value {
    let mut rng = TestRng::new(0xB0);
    let ck = ContentKey::from_bytes(arr(&mut rng));
    let payload_nonce: [u8; 16] = arr(&mut rng);
    let k = derive_payload_key(STD, &ck, &payload_nonce).unwrap();
    let mut cases = Vec::new();
    for len in [0usize, 1, 100, 65_536, 65_537, 3 * 65_536 + 10] {
        let pt = pattern(len);
        let ct = stream::encrypt(AeadKey::from_bytes(*k.expose()), &pt).unwrap();
        let mut c = json!({
            "plaintext_len": len,
            "ciphertext_sha256": h(&crate::hash::sha256(&[&ct])),
            "ciphertext_len": ct.len(),
        });
        if len <= 100 {
            c["ciphertext"] = json!(h(&ct));
        }
        cases.push(c);
    }
    json!({
        "description": "Payload STREAM (§13.3). K_pay = HKDF(IKM=CK, salt=payload_nonce, info='candor/v1/payload' || u16be(suite)). plaintext byte i = i mod 251.",
        "ck": h(ck.expose()),
        "payload_nonce": h(&payload_nonce),
        "k_pay": h(k.expose()),
        "cases": cases,
        "negative": [
            {"name": "truncated", "base_plaintext_len": 196618, "mutation": "drop the final chunk", "expect": "reject"},
            {"name": "no_final", "base_plaintext_len": 196618, "mutation": "drop the final chunk and declare plaintext_len = 196608", "expect": "reject"},
            {"name": "reordered", "base_plaintext_len": 196618, "mutation": "swap chunks 0 and 1", "expect": "reject"},
            {"name": "duplicated", "base_plaintext_len": 196618, "mutation": "replace chunk 1 by chunk 0", "expect": "reject"},
            {"name": "trailing", "base_plaintext_len": 196618, "mutation": "append one 0x00 byte", "expect": "reject"},
            {"name": "bitflip_last", "base_plaintext_len": 196618, "mutation": "flip bit 0 of the last byte", "expect": "reject"},
        ],
    })
}

fn sealed_object_vectors() -> Value {
    let mut rng = TestRng::new(0xC0);
    let tenant_id: [u8; 16] = arr(&mut rng);
    let channel_id: [u8; 16] = arr(&mut rng);
    let epoch_id = 42u32;
    let ikms: Vec<[u8; 32]> = (0..3).map(|_| arr(&mut rng)).collect();
    let mems: Vec<KemKeyPair> = ikms
        .iter()
        .map(|i| KemKeyPair::derive(STD, i).unwrap())
        .collect();
    let ctx = SlotContext::MemberEpoch {
        tenant_id,
        channel_id,
        epoch_id,
    };
    let ck = ContentKey::from_bytes(arr(&mut rng));
    let mut inner = Vec::new();
    inner.extend_from_slice(&5u32.to_be_bytes());
    inner.extend_from_slice(b"hello");
    let pt = pad(ObjectType::Submission, &inner).unwrap();
    let pks: Vec<_> = mems.iter().take(2).map(|m| m.public.clone()).collect();
    let req = SealRequest {
        suite: STD,
        object_type: ObjectType::Submission,
        tenant_id,
        channel_id,
        epoch_id,
        day_stamp: 0,
        recipients: Some((ctx.clone(), &pks)),
        padded_plaintext: &pt,
    };
    let obj = seal_with_ck_rng(&mut rng, &ck, &req).unwrap();
    let blk = obj.slot_block.clone().unwrap();

    // Hidden-recipient negative: three real slots, Recipient List claims two.
    let pks3: Vec<_> = mems.iter().map(|m| m.public.clone()).collect();
    let req3 = SealRequest {
        recipients: Some((ctx.clone(), &pks3)),
        ..req
    };
    let obj3 = seal_with_ck_rng(&mut rng, &ck, &req3).unwrap();

    // All-dummy block: fully deterministic from (CK, object_id, payload_nonce, context) — dummy-slot KAT.
    let dummy_binding = SlotBinding {
        suite: STD,
        object_id: obj.header.object_id,
        payload_nonce: obj.header.payload_nonce,
        context: ctx.clone(),
    };
    let dummy_block = RecipientSlotBlock::build_with(&mut rng, &ck, &dummy_binding, &[]).unwrap();

    json!({
        "description": "SUBMISSION Sealed Object (§13.1) with RecipientSlotBlock (§13.2). Member keys: X-Wing DeriveKeyPair(ikm).",
        "suite": STD.id(),
        "tenant_id": h(&tenant_id),
        "channel_id": h(&channel_id),
        "epoch_id": epoch_id,
        "member_ikm": ikms.iter().map(|i| h(i)).collect::<Vec<_>>(),
        "recipients": [0, 1],
        "ck": h(ck.expose()),
        "padded_plaintext_sha256": h(&crate::hash::sha256(&[&pt])),
        "inner_prefix": h(&inner),
        "sealed_object": h(&obj.bytes),
        "object_hash": h(&obj.object_hash),
        "slot_block": h(&blk.encode()),
        "slot_block_hash": h(&blk.hash()),
        "dummy_slot_kat": {
            "description": "Slot block with zero recipients: every slot i is the dummy for position i; deterministic.",
            "object_id": h(&obj.header.object_id),
            "payload_nonce": h(&obj.header.payload_nonce),
            "slot_block_sha256": h(&dummy_block.hash()),
            "slot_0": h(&dummy_block.encode()[4..4 + crate::slots::SLOT_LEN]),
        },
        "negative": {
            "header_tamper": {"offset": 47, "xor": 1, "expect": "header_mac failure"},
            "wrong_suite_unknown": {"offset": 7, "set": 3, "expect": "UnknownSuite"},
            "wrong_suite_fips": {"offset": 7, "set": 2, "expect": "UnsupportedSuite"},
            "tampered_slot_block_hash": {"offset": 48, "xor": 1, "expect": "slot block mismatch / header_mac failure"},
            "salamander_other_ck": {"ck": h(&[0xEE; 32]), "expect": "header_mac failure"},
            "hidden_recipient": {
                "sealed_object": h(&obj3.bytes),
                "slot_block": h(&obj3.slot_block.unwrap().encode()),
                "recipient_list_len": 2,
                "expect": "slot verification failure (3 non-dummy slots)"
            },
        },
    })
}

fn stanza_vectors() -> Value {
    let mut rng = TestRng::new(0xD0);
    let tenant_id: [u8; 16] = arr(&mut rng);
    let channel_id: [u8; 16] = arr(&mut rng);
    let case_id: [u8; 16] = arr(&mut rng);
    let src_ikm: [u8; 32] = arr(&mut rng);
    let member_ikm: [u8; 32] = arr(&mut rng);
    let src = KemKeyPair::derive(STD, &src_ikm).unwrap();
    let member = KemKeyPair::derive(STD, &member_ikm).unwrap();
    let mailbox_id: [u8; 32] = arr(&mut rng);
    let object_hash: [u8; 32] = arr(&mut rng);
    let ck = ContentKey::from_bytes(arr(&mut rng));
    let case_key = CaseKey::from_bytes(arr(&mut rng));
    let ek = ErasureKey::from_bytes(arr(&mut rng));
    let version = 3u32;
    let reply_ctx = HpkeWrapContext::Reply {
        tenant_id,
        channel_id: [0; 16],
        mailbox_id,
    };
    let reply = WrapStanza::seal_hpke_with(
        &mut rng,
        STD,
        &src.public,
        [0; 32],
        object_hash,
        &reply_ctx,
        ck.expose(),
    )
    .unwrap();
    let case_aead = WrapStanza::seal_case_aead_with(
        &mut rng,
        &case_key,
        tenant_id,
        case_id,
        version,
        object_hash,
        &ck,
    )
    .unwrap();
    let kid = key_id(STD, KeyKind::UserEnc, &member.public.to_bytes());
    let inner_ctx = HpkeWrapContext::CaseKey {
        tenant_id,
        case_id,
        version,
        recipient_key_id: kid,
    };
    let inner = WrapStanza::seal_hpke_with(
        &mut rng,
        STD,
        &member.public,
        kid,
        casekey_bound_hash(&case_id, version),
        &inner_ctx,
        case_key.expose(),
    )
    .unwrap();
    let ek_stanza =
        WrapStanza::seal_casekey_ek_with(&mut rng, &ek, tenant_id, case_id, version, &inner)
            .unwrap();
    // ek_direct_wrap: EK layer around a raw case key instead of an HPKE_BASE stanza.
    let k = crate::kdf::derive_ek_layer_key(&ek, &case_id).unwrap();
    let nonce: [u8; 24] = arr(&mut rng);
    let mut aad = crate::labels::EK_LAYER.to_vec();
    aad.extend_from_slice(&tenant_id);
    aad.extend_from_slice(&case_id);
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(&kid);
    let direct_ct = crate::aead::xchacha_seal(&k, &nonce, &aad, case_key.expose()).unwrap();
    let direct = WrapStanza::raw(
        StanzaType::CasekeyEk,
        kid,
        casekey_bound_hash(&case_id, version),
        nonce.to_vec(),
        direct_ct,
    );
    json!({
        "description": "Wrap Stanzas (§13.2). Keys: X-Wing DeriveKeyPair(ikm).",
        "tenant_id": h(&tenant_id),
        "channel_id": h(&channel_id),
        "case_id": h(&case_id),
        "case_key_version": version,
        "source_ikm": h(&src_ikm),
        "member_ikm": h(&member_ikm),
        "member_key_id": h(&kid),
        "mailbox_id": h(&mailbox_id),
        "object_hash": h(&object_hash),
        "ck": h(ck.expose()),
        "case_key": h(case_key.expose()),
        "erasure_key": h(ek.expose()),
        "reply_hpke_base": h(&reply.encode().unwrap()),
        "case_aead": h(&case_aead.encode().unwrap()),
        "casekey_hpke_base": h(&inner.encode().unwrap()),
        "casekey_ek": h(&ek_stanza.encode().unwrap()),
        "negative": {
            "ek_direct_wrap": h(&direct.encode().unwrap()),
            "bound_to_other_object": {"stanza": "reply_hpke_base", "object_hash": h(&[0u8; 32]), "expect": "reject"},
        },
    })
}

fn record_vectors() -> Value {
    let mut rng = TestRng::new(0xE0);
    let case_key = CaseKey::from_bytes(arr(&mut rng));
    let tenant_id: [u8; 16] = arr(&mut rng);
    let case_id: [u8; 16] = arr(&mut rng);
    let record_id: [u8; 16] = arr(&mut rng);
    let (table_id, column_id, key_version, row_version) = (7u16, 2u16, 1u32, 5u64);
    let k = derive_case_record_key(&case_key, table_id).unwrap();
    let aad = RecordAad::Case {
        tenant_id,
        case_id,
        table_id,
        column_id,
        record_id,
        row_version,
    };
    let rec = seal_record_with(&mut rng, &k, key_version, &aad, b"Case title").unwrap();
    json!({
        "description": "Encrypted case record (§13.8). key = HKDF(IKM=CaseKey, salt='candor/v1/case', info='candor/v1/case/record/' || u16be(table_id)).",
        "case_key": h(case_key.expose()),
        "record_key": h(k.expose()),
        "tenant_id": h(&tenant_id),
        "case_id": h(&case_id),
        "table_id": table_id,
        "column_id": column_id,
        "record_id": h(&record_id),
        "key_version": key_version,
        "row_version": row_version,
        "plaintext": h(b"Case title"),
        "record": h(&rec),
        "negative": {"stale_row_version": row_version - 1, "expect": "reject"},
    })
}

fn misc_vectors() -> Value {
    let pk = KemKeyPair::derive(STD, &[0x42; 32])
        .unwrap()
        .public
        .to_bytes();
    let ev = EvidenceHasher::digest(b"abc");
    let lookup_id = [0x11u8; 32];
    json!({
        "description": "Padding buckets (§13.6), key_id (§13.2), lookup_tag (§11.4), evidence hashes (ADR-012).",
        "message_buckets": (1..=16).map(|k| 4096 * k).collect::<Vec<u64>>(),
        "identity_buckets": (1..=4).map(|k| 4096 * k).collect::<Vec<u64>>(),
        "file_buckets": file_buckets().collect::<Vec<u64>>(),
        "key_id": {"suite": STD.id(), "key_kind": KeyKind::Mek as u8, "pk_from_ikm": h(&[0x42; 32]), "key_id": h(&key_id(STD, KeyKind::Mek, &pk))},
        "lookup_tag": {"lookup_id": h(&lookup_id), "lookup_tag": h(&lookup_tag(&lookup_id))},
        "evidence_abc": {"sha256": h(&ev.sha256), "blake3": h(&ev.blake3)},
    })
}

#[test]
fn vectors_are_current() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/");
    let regen = std::env::var("CANDOR_REGEN_VECTORS").is_ok_and(|v| v == "1");
    let sets: [(&str, Value); 6] = [
        ("passphrase.json", passphrase_vectors()),
        ("stream.json", stream_vectors()),
        ("sealed_object.json", sealed_object_vectors()),
        ("stanza.json", stanza_vectors()),
        ("record.json", record_vectors()),
        ("misc.json", misc_vectors()),
    ];
    for (name, v) in sets {
        let text = serde_json::to_string_pretty(&v).unwrap() + "\n";
        let path = format!("{dir}{name}");
        if regen {
            std::fs::write(&path, &text).unwrap(); // safefs-lint: allow(test-only vector generation into this crate's tests/vectors)
        } else {
            let committed = std::fs::read_to_string(&path).unwrap_or_default(); // safefs-lint: allow(test-only vector check)
            assert!(
                committed == text,
                "{name} is stale; regenerate with CANDOR_REGEN_VECTORS=1"
            );
        }
    }
}
