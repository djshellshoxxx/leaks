// SPDX-License-Identifier: Apache-2.0 OR MIT
//! ST-020 known-answer tests for the primitives behind CANDOR-STD-1.
//!
//! * `kat/xwing-draft.json` — draft-connolly-cfrg-xwing-kem test vectors (copied from the
//!   `x-wing` 0.1.0 crate's tests/test-vectors.json; byte-identical to
//!   github.com/dconnolly/draft-connolly-cfrg-xwing-kem spec/test-vectors.json).
//! * `kat/hpke-pq-xwing.json` — draft-ietf-hpke-pq vectors for KEM 0x647a (from `hpke`
//!   0.14.1 test-vectors/pq-6433c8f.json; matches github.com/hpkewg/hpke-pq test-vectors.json).
//! * `kat/rfc9180-x25519-base.json` — RFC 9180 Appendix A.1.1/A.2.1 base-mode vectors
//!   (DHKEM(X25519), HKDF-SHA256; from `hpke` 0.14.1 test-vectors/origrfc-5f503c5.json).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use candor_core::Suite;
use candor_core::kem::{KemKeyPair, KemPrivateKey, open_base};
use hpke::rand_core::{TryCryptoRng, TryRng, utils};
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use serde::Deserialize;
use std::convert::Infallible;

/// Serves exactly the given bytes (KAT encapsulation randomness).
struct FixedRng(Vec<u8>);

impl TryRng for FixedRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        utils::next_word_via_fill(self)
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        utils::next_word_via_fill(self)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        assert!(dest.len() <= self.0.len(), "KAT RNG exhausted");
        dest.copy_from_slice(&self.0[..dest.len()]);
        self.0.drain(..dest.len());
        Ok(())
    }
}
impl TryCryptoRng for FixedRng {}

#[derive(Deserialize)]
struct XWingVector {
    #[serde(with = "hex")]
    seed: Vec<u8>,
    #[serde(with = "hex")]
    eseed: Vec<u8>,
    #[serde(with = "hex")]
    ss: Vec<u8>,
    #[serde(with = "hex")]
    sk: Vec<u8>,
    #[serde(with = "hex")]
    pk: Vec<u8>,
    #[serde(with = "hex")]
    ct: Vec<u8>,
}

/// X-Wing draft vectors through the `hpke` KEM used by candor-core.
#[test]
fn xwing_draft_vectors() {
    let vs: Vec<XWingVector> =
        serde_json::from_str(include_str!("vectors/kat/xwing-draft.json")).unwrap();
    assert_eq!(vs.len(), 3);
    for v in vs {
        assert_eq!(v.sk, v.seed, "X-Wing sk is the 32-byte seed");
        let sk = <hpke::kem::XWing as Kem>::PrivateKey::from_bytes(&v.sk).unwrap();
        let pk = <hpke::kem::XWing as Kem>::sk_to_pk(&sk);
        assert_eq!(pk.to_bytes().as_slice(), v.pk.as_slice());
        let (ss, enc) =
            <hpke::kem::XWing as Kem>::encap_with_rng(&pk, None, &mut FixedRng(v.eseed.clone()))
                .unwrap();
        assert_eq!(enc.to_bytes().as_slice(), v.ct.as_slice());
        assert_eq!(ss.0.as_slice(), v.ss.as_slice());
        let ss2 = <hpke::kem::XWing as Kem>::decap(&sk, None, &enc).unwrap();
        assert_eq!(ss2.0.as_slice(), v.ss.as_slice());
        // And the candor-core wrapper agrees on the public key.
        let csk = KemPrivateKey::from_bytes(Suite::CandorStd1, &v.sk).unwrap();
        assert_eq!(csk.public_key().to_bytes(), v.pk);
    }
}

#[derive(Deserialize)]
struct Enc {
    #[serde(with = "hex")]
    aad: Vec<u8>,
    #[serde(with = "hex")]
    ct: Vec<u8>,
    #[serde(with = "hex")]
    pt: Vec<u8>,
}

#[derive(Deserialize)]
struct Export {
    #[serde(with = "hex")]
    exporter_context: Vec<u8>,
    #[serde(rename = "L")]
    l: usize,
    #[serde(with = "hex")]
    exported_value: Vec<u8>,
}

#[derive(Deserialize)]
struct HpkeVector {
    mode: u8,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    #[serde(with = "hex")]
    info: Vec<u8>,
    #[serde(rename = "ikmE", with = "hex")]
    ikm_e: Vec<u8>,
    #[serde(rename = "ikmR", with = "hex")]
    ikm_r: Vec<u8>,
    #[serde(rename = "skRm", with = "hex")]
    sk_rm: Vec<u8>,
    #[serde(rename = "pkRm", with = "hex")]
    pk_rm: Vec<u8>,
    #[serde(with = "hex")]
    enc: Vec<u8>,
    encryptions: Vec<Enc>,
    exports: Vec<Export>,
}

fn run_hpke_vector<K: Kem>(v: &HpkeVector) {
    type A = hpke::aead::ChaCha20Poly1305;
    type F = hpke::kdf::HkdfSha256;
    let (sk, pk) = K::derive_keypair(&v.ikm_r);
    assert_eq!(
        sk.to_bytes().as_slice(),
        v.sk_rm.as_slice(),
        "DeriveKeyPair skRm"
    );
    assert_eq!(
        pk.to_bytes().as_slice(),
        v.pk_rm.as_slice(),
        "DeriveKeyPair pkRm"
    );
    let (enc, mut sctx) = hpke::setup_sender_with_rng::<A, F, K>(
        &OpModeS::Base,
        &pk,
        &v.info,
        &mut FixedRng(v.ikm_e.clone()),
    )
    .unwrap();
    assert_eq!(enc.to_bytes().as_slice(), v.enc.as_slice(), "enc");
    let enc_r = K::EncappedKey::from_bytes(&v.enc).unwrap();
    let mut rctx = hpke::setup_receiver::<A, F, K>(&OpModeR::Base, &sk, &enc_r, &v.info).unwrap();
    for e in &v.encryptions {
        assert_eq!(sctx.seal(&e.pt, &e.aad).unwrap(), e.ct);
        assert_eq!(rctx.open(&e.ct, &e.aad).unwrap(), e.pt);
    }
    for x in &v.exports {
        let mut out = vec![0u8; x.l];
        rctx.export(&x.exporter_context, &mut out).unwrap();
        assert_eq!(out, x.exported_value);
    }
}

/// hpke-pq vectors for KEM 0x647a / HKDF-SHA256 / ChaCha20-Poly1305 (the exact
/// CANDOR-STD-1 HPKE suite), plus a single-shot open through candor-core.
#[test]
fn hpke_pq_xwing_vectors() {
    let vs: Vec<HpkeVector> =
        serde_json::from_str(include_str!("vectors/kat/hpke-pq-xwing.json")).unwrap();
    let mut ran = 0;
    for v in vs
        .iter()
        .filter(|v| v.mode == 0 && v.kem_id == 0x647a && v.kdf_id == 1 && v.aead_id == 3)
    {
        run_hpke_vector::<hpke::kem::XWing>(v);
        // candor-core open_base with the derived key opens the first (seq 0) ciphertext.
        let kp = KemKeyPair::derive(Suite::CandorStd1, &v.ikm_r).unwrap();
        assert_eq!(kp.public.to_bytes(), v.pk_rm);
        let e0 = &v.encryptions[0];
        let pt = open_base(&kp.private, &v.enc, &v.info, &e0.aad, &e0.ct).unwrap();
        assert_eq!(pt.as_slice(), e0.pt.as_slice());
        ran += 1;
    }
    assert_eq!(ran, 1);
}

/// RFC 9180 A.2.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, base mode.
#[test]
fn rfc9180_base_vectors() {
    let vs: Vec<HpkeVector> =
        serde_json::from_str(include_str!("vectors/kat/rfc9180-x25519-base.json")).unwrap();
    let mut ran = 0;
    for v in vs
        .iter()
        .filter(|v| v.mode == 0 && v.kem_id == 0x0020 && v.kdf_id == 1 && v.aead_id == 3)
    {
        run_hpke_vector::<hpke::kem::X25519HkdfSha256>(v);
        ran += 1;
    }
    assert_eq!(ran, 1);
}

/// KAT-file pinning (ST-020 "vector files pinned by hash").
#[test]
fn kat_files_pinned() {
    use sha2::{Digest, Sha256};
    let pins = [
        (
            include_str!("vectors/kat/xwing-draft.json"),
            "a8726596f4c7629590f727b1bbeb483f6932292fbf5fd85c9cbb803190014f00",
        ),
        (
            include_str!("vectors/kat/hpke-pq-xwing.json"),
            "52bc66ada2564d400ceed3a09995cbff2367f10402e629fabbf1c20580b6afc9",
        ),
        (
            include_str!("vectors/kat/rfc9180-x25519-base.json"),
            "1b3422b215ea596568eeb4e17a03d9e0ee4d81800156d0ba2f8d9d079e0834ab",
        ),
    ];
    for (text, pin) in pins {
        assert_eq!(hex::encode(Sha256::digest(text.as_bytes())), pin);
    }
}
