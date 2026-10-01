// SPDX-License-Identifier: Apache-2.0 OR MIT
//! X-Wing (KEM 0x647a) keys and HPKE base mode (RFC 9180) for CANDOR-STD-1:
//! X-Wing / HKDF-SHA256 / ChaCha20-Poly1305 via `hpke` 0.14.1.

use crate::error::{Error, Result};
use crate::rand::{ExactBytesRng, OsRandom, RandomSource};
use crate::suite::{Suite, XWING_NENC, XWING_NPK, XWING_NSK};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::XWing;
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use zeroize::{Zeroize, Zeroizing};

type XPk = <XWing as hpke::Kem>::PublicKey;
type XSk = <XWing as hpke::Kem>::PrivateKey;
type XEnc = <XWing as hpke::Kem>::EncappedKey;

/// Bytes of encapsulation randomness consumed by one X-Wing encapsulation.
pub(crate) const ENCAP_RANDOMNESS_LEN: usize = 64;

/// An X-Wing public key (1216 bytes), validated on parse.
#[derive(Clone, PartialEq, Eq)]
pub struct KemPublicKey(XPk);

impl core::fmt::Debug for KemPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KemPublicKey(X-Wing)")
    }
}

impl KemPublicKey {
    /// Parse and validate public key bytes (§23.3 key validation; length per §4.2).
    pub fn from_bytes(suite: Suite, bytes: &[u8]) -> Result<Self> {
        suite.require_supported()?;
        if bytes.len() != XWING_NPK {
            return Err(Error::Length);
        }
        // AUD-RM1-CORE-14 (defence in depth, IMPL-RM1 §4 A8): reject an X25519
        // component that is non-canonical or of low order.
        let (_, pk_x) = bytes
            .split_last_chunk::<32>()
            .ok_or(Error::Length)?;
        if !x25519_public_ok(pk_x) {
            return Err(Error::InvalidKey);
        }
        XPk::from_bytes(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }

    /// Serialize (1216 bytes).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

/// Little-endian encodings (top bit clear) of the X25519 u-coordinates of low order
/// that are below p = 2^255 − 19: 0, 1, the two points of order 8, and p − 1
/// (RFC 7748 §6.1 / libsodium blocklist). Values ≥ p are rejected separately as
/// non-canonical; this also covers p and p + 1.
const X25519_LOW_ORDER: [[u8; 32]; 5] = [
    [0; 32],
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// `true` iff `u` is a canonical (top bit clear, value < p) X25519 public key that is
/// not of low order. Public data: no constant-time requirement.
fn x25519_public_ok(u: &[u8; 32]) -> bool {
    // Top bit set: non-canonical encoding (RFC 7748 masks it; we refuse it).
    if u.last().is_some_and(|b| b & 0x80 != 0) {
        return false;
    }
    // Value ≥ p = 2^255 − 19 ⇔ bytes 1..31 are 0xff (byte 31 = 0x7f) and byte 0 ≥ 0xed.
    let (first, rest) = u.split_first().map_or((0, &[][..]), |(f, r)| (*f, r));
    let (top, mid) = rest.split_last().map_or((0, &[][..]), |(t, m)| (*t, m));
    if top == 0x7f && mid.iter().all(|b| *b == 0xff) && first >= 0xed {
        return false;
    }
    !X25519_LOW_ORDER.contains(u)
}

/// An X-Wing private key (32-byte seed). Zeroized on drop by the underlying type.
pub struct KemPrivateKey(XSk);

impl core::fmt::Debug for KemPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KemPrivateKey(<redacted>)")
    }
}

impl KemPrivateKey {
    /// Parse a 32-byte X-Wing private seed.
    pub fn from_bytes(suite: Suite, bytes: &[u8]) -> Result<Self> {
        suite.require_supported()?;
        if bytes.len() != XWING_NSK {
            return Err(Error::Length);
        }
        XSk::from_bytes(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }

    /// Export the private seed (for sealing into a keystore record only).
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        // AUD-RM1-CORE-07: the intermediate `Array` is zeroized before it is dropped.
        let mut arr = self.0.to_bytes();
        let out = Zeroizing::new(arr.to_vec());
        arr.as_mut_slice().zeroize();
        out
    }

    /// The matching public key.
    #[must_use]
    pub fn public_key(&self) -> KemPublicKey {
        KemPublicKey(XWing::sk_to_pk(&self.0))
    }
}

/// An X-Wing key pair.
#[derive(Debug)]
pub struct KemKeyPair {
    /// Private key.
    pub private: KemPrivateKey,
    /// Public key.
    pub public: KemPublicKey,
}

impl KemKeyPair {
    /// HPKE `DeriveKeyPair(ikm)` for KEM 0x647a (draft-ietf-hpke-pq; SHAKE256 labeled derive).
    pub fn derive(suite: Suite, ikm: &[u8]) -> Result<Self> {
        suite.require_supported()?;
        if ikm.len() < 32 {
            return Err(Error::Length);
        }
        let (sk, pk) = XWing::derive_keypair(ikm);
        Ok(Self {
            private: KemPrivateKey(sk),
            public: KemPublicKey(pk),
        })
    }

    /// Generate a fresh key pair from the OS CSPRNG, with a pairwise-consistency test
    /// (CRYPTO-036).
    pub fn generate(suite: Suite) -> Result<Self> {
        Self::generate_with(suite, &mut OsRandom)
    }

    pub(crate) fn generate_with(suite: Suite, rng: &mut dyn RandomSource) -> Result<Self> {
        let mut ikm = Zeroizing::new([0u8; 32]);
        rng.fill(ikm.as_mut())?;
        let kp = Self::derive(suite, ikm.as_ref())?;
        kp.pairwise_consistency_test(rng)?;
        Ok(kp)
    }

    fn pairwise_consistency_test(&self, rng: &mut dyn RandomSource) -> Result<()> {
        let mut r = [0u8; ENCAP_RANDOMNESS_LEN];
        rng.fill(&mut r)?;
        let mut erng = ExactBytesRng::new(&r);
        r.zeroize();
        let (ss1, enc) = XWing::encap_with_rng(&self.public.0, None, &mut erng)
            .map_err(|_| Error::InvalidKey)?;
        erng.check()?;
        let ss2 = XWing::decap(&self.private.0, None, &enc).map_err(|_| Error::InvalidKey)?;
        if crate::kdf::ct_eq(ss1.0.as_slice(), ss2.0.as_slice()) {
            Ok(())
        } else {
            Err(Error::InvalidKey)
        }
    }
}

/// X-Wing KAT helper for the start-up self-test: keypair from the 32-byte `seed`,
/// encapsulation with the 64-byte `eseed`, decapsulation; returns
/// `SHA-256(pk ‖ ct ‖ ss)` after checking both shared secrets agree.
pub(crate) fn xwing_kat_digest(
    seed: &[u8; 32],
    eseed: &[u8; ENCAP_RANDOMNESS_LEN],
) -> Result<[u8; 32]> {
    let sk = KemPrivateKey::from_bytes(Suite::CandorStd1, seed)?;
    let pk = sk.public_key();
    let mut rng = ExactBytesRng::new(eseed);
    let (ss, enc) = XWing::encap_with_rng(&pk.0, None, &mut rng).map_err(|_| Error::Internal)?;
    rng.check()?;
    let ss2 = XWing::decap(&sk.0, None, &enc).map_err(|_| Error::Internal)?;
    if !crate::kdf::ct_eq(ss.0.as_slice(), ss2.0.as_slice()) {
        return Err(Error::Internal);
    }
    Ok(crate::hash::sha256(&[
        &pk.to_bytes(),
        enc.to_bytes().as_slice(),
        ss.0.as_slice(),
    ]))
}

/// HPKE SealBase with caller-supplied encapsulation randomness. Returns `(enc, ct)`.
///
/// Crate-internal: the derandomized path is exposed only through the dummy-slot
/// function and the fresh-randomness wrappers below (§13.2).
pub(crate) fn seal_base_with_randomness(
    pk: &KemPublicKey,
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
    randomness: &[u8; ENCAP_RANDOMNESS_LEN],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = ExactBytesRng::new(randomness);
    let (enc, ct) = hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeS::Base,
        &pk.0,
        info,
        pt,
        aad,
        &mut rng,
    )
    .map_err(|_| Error::Internal)?;
    rng.check()?;
    let enc = enc.to_bytes().to_vec();
    if enc.len() != XWING_NENC {
        return Err(Error::Internal);
    }
    Ok((enc, ct))
}

/// HPKE SealBase with fresh randomness from `rng`.
pub(crate) fn seal_base_with(
    rng: &mut dyn RandomSource,
    pk: &KemPublicKey,
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut r = [0u8; ENCAP_RANDOMNESS_LEN];
    rng.fill(&mut r)?;
    let out = seal_base_with_randomness(pk, info, aad, pt, &r);
    r.zeroize();
    out
}

/// HPKE SealBase (RFC 9180 mode_base) to `pk` with OS randomness. Returns `(enc, ct)`.
pub fn seal_base(
    pk: &KemPublicKey,
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    seal_base_with(&mut OsRandom, pk, info, aad, pt)
}

/// HPKE OpenBase. Any failure is reported as [`Error::Authentication`].
pub fn open_base(
    sk: &KemPrivateKey,
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if enc.len() != XWING_NENC {
        return Err(Error::Length);
    }
    let enc = XEnc::from_bytes(enc).map_err(|_| Error::Authentication)?;
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeR::Base,
        &sk.0,
        &enc,
        info,
        ct,
        aad,
    )
    .map(Zeroizing::new)
    .map_err(|_| Error::Authentication)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::rand::TestRng;

    #[test]
    fn seal_open_roundtrip_and_context_binding() {
        let mut rng = TestRng::new(3);
        let kp = KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap();
        let (enc, ct) = seal_base_with(&mut rng, &kp.public, b"info", b"aad", b"hello").unwrap();
        assert_eq!(enc.len(), XWING_NENC);
        let pt = open_base(&kp.private, &enc, b"info", b"aad", &ct).unwrap();
        assert_eq!(pt.as_slice(), b"hello");
        // CRYPTO-006: any change of info or aad fails.
        assert_eq!(
            open_base(&kp.private, &enc, b"infO", b"aad", &ct).err(),
            Some(Error::Authentication)
        );
        assert_eq!(
            open_base(&kp.private, &enc, b"info", b"aaD", &ct).err(),
            Some(Error::Authentication)
        );
        let other = KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap();
        assert_eq!(
            open_base(&other.private, &enc, b"info", b"aad", &ct).err(),
            Some(Error::Authentication)
        );
        assert_eq!(
            open_base(&kp.private, &enc[1..], b"info", b"aad", &ct).err(),
            Some(Error::Length)
        );
    }

    #[test]
    fn key_parsing() {
        let kp = KemKeyPair::derive(Suite::CandorStd1, &[5u8; 32]).unwrap();
        let pkb = kp.public.to_bytes();
        assert_eq!(pkb.len(), XWING_NPK);
        assert_eq!(
            KemPublicKey::from_bytes(Suite::CandorStd1, &pkb).unwrap(),
            kp.public
        );
        assert!(KemPublicKey::from_bytes(Suite::CandorStd1, &pkb[1..]).is_err());
        assert_eq!(
            KemPublicKey::from_bytes(Suite::CandorFips1, &pkb).err(),
            Some(Error::UnsupportedSuite)
        );
        let skb = kp.private.to_bytes();
        let sk2 = KemPrivateKey::from_bytes(Suite::CandorStd1, &skb).unwrap();
        assert_eq!(sk2.public_key(), kp.public);
        assert!(KemKeyPair::derive(Suite::CandorStd1, &[0u8; 31]).is_err());
        assert_eq!(format!("{:?}", kp.private), "KemPrivateKey(<redacted>)");
    }
}
