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
use crate::kem::seal_base_with;
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
            "normalized": normalize(&messy).unwrap().as_str(),
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
    let pks: Vec<_> = mems.iter().take(2).map(|m| m.public.clone()).collect();
    let req = SealRequest {
        suite: STD,
        object_type: ObjectType::Submission,
        tenant_id,
        channel_id,
        epoch_id,
        day_stamp: 0,
        recipients: Some((ctx.clone(), &pks)),
        padded_len: 4096,
    };
    // Toy inner layout (not the §13.4 CBOR): u32be(5) ‖ "hello" ‖ u8 n ‖ n × entry(97 B).
    let build = |pc: &crate::object::PayloadContext<'_>| {
        let mut v = inner.clone();
        v.push(pc.recipient_list.len() as u8);
        for e in pc.recipient_list {
            v.extend_from_slice(e.to_bytes().as_slice());
        }
        pad(ObjectType::Submission, &v)
    };
    let (list, obj) = seal_with_ck_rng(&mut rng, &ck, &req, build).unwrap();
    let blk = obj.slot_block.clone().unwrap();
    let list_hex = |l: &[crate::slots::RecipientListEntry]| {
        l.iter().map(|e| h(e.to_bytes().as_slice())).collect::<Vec<_>>()
    };

    // Hidden-recipient negative: three real slots, Recipient List names only two.
    let pks3: Vec<_> = mems.iter().map(|m| m.public.clone()).collect();
    let req3 = SealRequest {
        recipients: Some((ctx.clone(), &pks3)),
        ..req
    };
    let (list3, obj3) = seal_with_ck_rng(&mut rng, &ck, &req3, build).unwrap();

    // Swapped-recipient negative (ADR-050(3)): slot sealed to member 2 ("attacker"),
    // list names member 0's key id at that slot.
    let attacker = [mems[2].public.clone()];
    let req4 = SealRequest {
        recipients: Some((ctx.clone(), &attacker)),
        ..req
    };
    let (list4, obj4) = seal_with_ck_rng(&mut rng, &ck, &req4, build).unwrap();
    let mut swapped = list4.as_slice()[0].to_bytes();
    swapped[1..33].copy_from_slice(&key_id(STD, KeyKind::Mek, &mems[0].public.to_bytes()));
    let swapped_list = [crate::slots::RecipientListEntry::from_bytes(swapped.as_slice()).unwrap()];

    // All-dummy block: fully deterministic from (CK, object_id, payload_nonce, context) — dummy-slot KAT.
    let dummy_binding = SlotBinding {
        suite: STD,
        object_id: obj.header.object_id,
        payload_nonce: obj.header.payload_nonce,
        context: ctx.clone(),
    };
    let (dummy_block, _) =
        RecipientSlotBlock::build_with(&mut rng, &ck, &dummy_binding, &[]).unwrap();

    json!({
        "description": "SUBMISSION Sealed Object (§13.1) with RecipientSlotBlock (§13.2) and ADR-050(3) Recipient List entries (u8 slot_index ‖ key_id ‖ enc_rand). Member keys: X-Wing DeriveKeyPair(ikm); key_id kind 1 (MEK). The Key Directory for verification contains members 0 and 1 only.",
        "suite": STD.id(),
        "tenant_id": h(&tenant_id),
        "channel_id": h(&channel_id),
        "epoch_id": epoch_id,
        "member_ikm": ikms.iter().map(|i| h(i)).collect::<Vec<_>>(),
        "recipients": [0, 1],
        "ck": h(ck.expose()),
        "inner_layout": "u32be(5) || 'hello' || u8 n || n x 97-byte Recipient List entries || zero padding",
        "inner_prefix": h(&inner),
        "recipient_list": list_hex(list.as_slice()),
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
                "recipient_list": list_hex(&list3.as_slice()[..2]),
                "expect": "slot verification failure (unlisted non-dummy slot)"
            },
            "swapped_recipient": {
                "sealed_object": h(&obj4.bytes),
                "slot_block": h(&obj4.slot_block.unwrap().encode()),
                "recipient_list": list_hex(&swapped_list),
                "expect": "slot verification failure (listed member's re-encapsulation differs)"
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

/// Fixed keys shared with the fuzz targets in `fuzz/fuzz_targets/` (AUD-RM1-CORE-06):
/// the committed seeds in `fuzz/seeds/<target>/` are valid under these keys, so the
/// structure-aware targets reach MAC verification, decryption, trial-open and full
/// slot verification. Keep in sync with `fuzz/fuzz_targets/common.rs`.
pub(crate) mod fuzzkeys {
    pub const CK: [u8; 32] = [0x5A; 32];
    pub const MEMBER_IKM: [u8; 32] = [0x6B; 32];
    pub const TENANT: [u8; 16] = [1; 16];
    pub const CHANNEL: [u8; 16] = [2; 16];
    pub const EPOCH: u32 = 3;
    pub const CASE_ID: [u8; 16] = [4; 16];
    pub const VERSION: u32 = 1;
    pub const CASE_KEY: [u8; 32] = [0x7C; 32];
    pub const EK: [u8; 32] = [0x8D; 32];
    pub const OBJECT_HASH: [u8; 32] = [0x9E; 32];
    pub const MAILBOX: [u8; 32] = [0xAF; 32];
    pub const HPKE_INFO: &[u8] = b"fuzz-info";
    pub const HPKE_AAD: &[u8] = b"fuzz-aad";
    pub const STREAM_KEY: [u8; 32] = [3; 32];
    pub const RECORD_KEY: [u8; 32] = [7; 32];
}

/// Seed inputs per fuzz target: `(target, file name, bytes)`.
fn fuzz_seeds() -> Vec<(&'static str, String, Vec<u8>)> {
    use fuzzkeys as fk;
    let mut rng = TestRng::new(0xF0);
    let mut out = Vec::new();
    let member = KemKeyPair::derive(STD, &fk::MEMBER_IKM).unwrap();
    let ck = ContentKey::from_bytes(fk::CK);
    let ctx = SlotContext::MemberEpoch {
        tenant_id: fk::TENANT,
        channel_id: fk::CHANNEL,
        epoch_id: fk::EPOCH,
    };
    // Envelope: slot block ‖ sealed object; inner = u32be(5) ‖ "hello" ‖ u8 n ‖ n × entry.
    let pks = [member.public.clone()];
    for (name, ty, recips) in [
        ("submission", ObjectType::Submission, Some((ctx.clone(), &pks[..]))),
        ("reply", ObjectType::Reply, None),
    ] {
        let req = SealRequest {
            suite: STD,
            object_type: ty,
            tenant_id: fk::TENANT,
            channel_id: if recips.is_some() { fk::CHANNEL } else { [0; 16] },
            epoch_id: if recips.is_some() { fk::EPOCH } else { 0 },
            day_stamp: 0,
            recipients: recips,
            padded_len: 4096,
        };
        let (_, obj) = seal_with_ck_rng(&mut rng, &ck, &req, |pc| {
            let mut v = 5u32.to_be_bytes().to_vec();
            v.extend_from_slice(b"hello");
            v.push(pc.recipient_list.len() as u8);
            for e in pc.recipient_list {
                v.extend_from_slice(e.to_bytes().as_slice());
            }
            pad(ty, &v)
        })
        .unwrap();
        out.push(("fuzz_header", name.to_string(), obj.bytes[..128].to_vec()));
        if let Some(b) = &obj.slot_block {
            let enc = b.encode();
            out.push(("fuzz_slot_block", name.to_string(), enc.clone()));
            let mut env = enc;
            env.extend_from_slice(&obj.bytes);
            out.push(("fuzz_envelope_parse", format!("{name}_with_block"), env));
        }
        out.push(("fuzz_envelope_parse", name.to_string(), obj.bytes.clone()));
    }
    let (dummy, list) = RecipientSlotBlock::build_with(
        &mut rng,
        &ck,
        &SlotBinding {
            suite: STD,
            object_id: [9; 16],
            payload_nonce: [8; 16],
            context: ctx.clone(),
        },
        &pks,
    )
    .unwrap();
    // `slot block ‖ entry`: trial-open with the fuzz member succeeds under the target's
    // fixed binding (object_id [9; 16], payload_nonce [8; 16]) and full verification
    // passes, so mutations start from the deepest path.
    let mut one = dummy.encode();
    one.extend_from_slice(list.as_slice()[0].to_bytes().as_slice());
    out.push(("fuzz_slot_block", "one_member".into(), one));
    out.push((
        "fuzz_recipient_entry",
        "entry".into(),
        list.as_slice()[0].to_bytes().to_vec(),
    ));
    // HPKE open: enc (1120) ‖ ct, sealed to the fuzz member with the fixed info/aad.
    for (name, pt) in [("ck", &[0x11u8; 32][..]), ("empty", &[][..])] {
        let (enc, ct) = seal_base_with(&mut rng, &member.public, fk::HPKE_INFO, fk::HPKE_AAD, pt)
            .unwrap();
        let mut v = enc;
        v.extend_from_slice(&ct);
        out.push(("fuzz_hpke_open", name.into(), v));
    }
    // Stanzas valid under the fixed keys/contexts.
    let reply_ctx = HpkeWrapContext::Reply {
        tenant_id: fk::TENANT,
        channel_id: fk::CHANNEL,
        mailbox_id: fk::MAILBOX,
    };
    let hpke = WrapStanza::seal_hpke_with(
        &mut rng,
        STD,
        &member.public,
        [0; 32],
        fk::OBJECT_HASH,
        &reply_ctx,
        &fk::CK,
    )
    .unwrap();
    let case_key = CaseKey::from_bytes(fk::CASE_KEY);
    let aead = WrapStanza::seal_case_aead_with(
        &mut rng,
        &case_key,
        fk::TENANT,
        fk::CASE_ID,
        fk::VERSION,
        fk::OBJECT_HASH,
        &ck,
    )
    .unwrap();
    let inner = WrapStanza::seal_hpke_with(
        &mut rng,
        STD,
        &member.public,
        key_id(STD, KeyKind::UserEnc, &member.public.to_bytes()),
        casekey_bound_hash(&fk::CASE_ID, fk::VERSION),
        &HpkeWrapContext::CaseKey {
            tenant_id: fk::TENANT,
            case_id: fk::CASE_ID,
            version: fk::VERSION,
            recipient_key_id: key_id(STD, KeyKind::UserEnc, &member.public.to_bytes()),
        },
        &fk::CASE_KEY,
    )
    .unwrap();
    let ek = WrapStanza::seal_casekey_ek_with(
        &mut rng,
        &ErasureKey::from_bytes(fk::EK),
        fk::TENANT,
        fk::CASE_ID,
        fk::VERSION,
        &inner,
    )
    .unwrap();
    for (name, st) in [("hpke_reply", &hpke), ("case_aead", &aead), ("casekey_ek", &ek)] {
        out.push(("fuzz_stanza", name.into(), st.encode().unwrap()));
    }
    // Records under the fixed key and the zero Case AAD used by the target.
    let aad = RecordAad::Case {
        tenant_id: [0; 16],
        case_id: [0; 16],
        table_id: 0,
        column_id: 0,
        record_id: [0; 16],
        row_version: 0,
    };
    let rec = seal_record_with(&mut rng, &AeadKey::from_bytes(fk::RECORD_KEY), 0, &aad, b"seed")
        .unwrap();
    out.push(("fuzz_record", "case".into(), rec));
    // STREAM: u16be(L) ‖ ciphertext of pattern(4·L) under the fixed key.
    for l in [0u16, 1, 16_384, 16_385] {
        let len = usize::from(l) * 4;
        let ct = stream::encrypt(AeadKey::from_bytes(fk::STREAM_KEY), &pattern(len)).unwrap();
        let mut v = l.to_be_bytes().to_vec();
        v.extend_from_slice(&ct);
        out.push(("fuzz_stream_decrypt", format!("len{len}"), v));
    }
    // Passphrase normalization / membership.
    for (name, p) in [
        ("plain", "abacus zoom abacus zoom abacus zoom abacus zoom abacus zoom"),
        ("messy", "  ABACUS -\u{2014}\tzoom,, kiwi  "),
        ("unicode", "\u{FF21}bacus \u{FB01}ve \u{0130}ΟΔΟΣ \u{FDFA}"),
    ] {
        out.push(("fuzz_normalize", name.into(), p.as_bytes().to_vec()));
    }
    out
}

#[test]
fn fuzz_seeds_are_current() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/seeds/");
    let regen = std::env::var("CANDOR_REGEN_VECTORS").is_ok_and(|v| v == "1");
    for (target, name, bytes) in fuzz_seeds() {
        let tdir = format!("{dir}{target}");
        let path = format!("{tdir}/{name}");
        if regen {
            std::fs::create_dir_all(&tdir).unwrap(); // safefs-lint: allow(test-only fuzz seed generation into this crate's fuzz/seeds)
            std::fs::write(&path, &bytes).unwrap(); // safefs-lint: allow(test-only fuzz seed generation into this crate's fuzz/seeds)
        } else {
            let committed = std::fs::read(&path).unwrap_or_default(); // safefs-lint: allow(test-only fuzz seed check)
            assert!(
                committed == bytes,
                "fuzz seed {target}/{name} is stale; regenerate with CANDOR_REGEN_VECTORS=1"
            );
        }
    }
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
