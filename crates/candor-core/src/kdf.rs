// SPDX-License-Identifier: Apache-2.0 OR MIT
//! HKDF-SHA256 / HMAC-SHA-256 (§10) and the key derivations of §10/§13.

use crate::error::{Error, Result};
use crate::labels;
use crate::secret::{AeadKey, CaseKey, ContentKey, ErasureKey, MacKey, Secret32};
use crate::suite::Suite;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// HKDF-Extract then HKDF-Expand with `info` given as concatenated parts.
pub(crate) fn hkdf(ikm: &[u8], salt: &[u8], info: &[&[u8]], out: &mut [u8]) -> Result<()> {
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand_multi_info(info, out)
        .map_err(|_| Error::Length)
}

/// HKDF-Extract only, returning the PRK.
pub(crate) fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Secret32 {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(prk.as_slice());
    let out = Secret32::from_bytes(arr);
    arr.zeroize();
    out
}

/// HKDF-Expand from a PRK.
pub(crate) fn hkdf_expand(prk: &Secret32, info: &[&[u8]], out: &mut [u8]) -> Result<()> {
    Hkdf::<Sha256>::from_prk(prk.expose())
        .map_err(|_| Error::Length)?
        .expand_multi_info(info, out)
        .map_err(|_| Error::Length)
}

fn hkdf32(ikm: &[u8], salt: &[u8], info: &[&[u8]]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    hkdf(ikm, salt, info, &mut out)?;
    Ok(out)
}

macro_rules! derive_into {
    ($ty:ty, $ikm:expr, $salt:expr, $info:expr) => {{
        let mut k = hkdf32($ikm, $salt, $info)?;
        let out = <$ty>::from_bytes(k);
        k.zeroize();
        Ok(out)
    }};
}

/// HMAC-SHA-256.
pub(crate) fn hmac_sha256(key: &[u8], data: &[&[u8]]) -> Result<[u8; 32]> {
    let mut m = <HmacSha256 as KeyInit>::new_from_slice(key).map_err(|_| Error::Length)?;
    for d in data {
        m.update(d);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(m.finalize().into_bytes().as_slice());
    Ok(out)
}

/// Constant-time equality of byte strings (lengths are public).
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// `K_pay = HKDF(IKM=CK, salt=payload_nonce, info="candor/v1/payload" ‖ suite)` (§13.3).
pub fn derive_payload_key(
    suite: Suite,
    ck: &ContentKey,
    payload_nonce: &[u8; 16],
) -> Result<AeadKey> {
    suite.require_supported()?;
    derive_into!(
        AeadKey,
        ck.expose(),
        payload_nonce,
        &[labels::PAYLOAD, &suite.to_be_bytes()]
    )
}

/// `K_mac = HKDF(IKM=CK, salt=object_id, info="candor/v1/header-mac" ‖ suite)` (§13.1).
pub fn derive_header_mac_key(
    suite: Suite,
    ck: &ContentKey,
    object_id: &[u8; 16],
) -> Result<MacKey> {
    suite.require_supported()?;
    derive_into!(
        MacKey,
        ck.expose(),
        object_id,
        &[labels::HEADER_MAC, &suite.to_be_bytes()]
    )
}

/// Record key per table: `HKDF(IKM=CaseKey_v, salt="candor/v1/case", info="candor/v1/case/record/" ‖ u16 table_id)` (§10).
pub fn derive_case_record_key(case_key: &CaseKey, table_id: u16) -> Result<AeadKey> {
    derive_into!(
        AeadKey,
        case_key.expose(),
        labels::CASE_SALT,
        &[labels::CASE_RECORD, &table_id.to_be_bytes()]
    )
}

/// CASE_AEAD wrap key: `HKDF(CaseKey_v, salt="candor/v1/case", info="candor/v1/wrap/case")` (§13.2).
pub fn derive_case_wrap_key(case_key: &CaseKey) -> Result<AeadKey> {
    derive_into!(
        AeadKey,
        case_key.expose(),
        labels::CASE_SALT,
        &[labels::WRAP_CASE]
    )
}

/// Erasure-Key layer key: `HKDF(EK_case, salt=case_id, info="candor/v1/ek-layer")` (§13.2).
pub fn derive_ek_layer_key(ek: &ErasureKey, case_id: &[u8; 16]) -> Result<AeadKey> {
    derive_into!(AeadKey, ek.expose(), case_id, &[labels::EK_LAYER])
}

/// Per-case metadata key K43: `HKDF(EK_case, salt=case_id, info="candor/v1/ek-meta")` (§9.10a).
pub fn derive_ek_meta_key(ek: &ErasureKey, case_id: &[u8; 16]) -> Result<AeadKey> {
    derive_into!(AeadKey, ek.expose(), case_id, &[labels::EK_META])
}

/// Blinded COI exclusion key `K_case_excl_v`: `HKDF(CaseKey_v, salt=case_id, info="candor/coi-excl/v1")` (§9.11).
pub fn derive_coi_excl_key(case_key: &CaseKey, case_id: &[u8; 16]) -> Result<MacKey> {
    derive_into!(MacKey, case_key.expose(), case_id, &[labels::COI_EXCL])
}

/// Tier W staged part STREAM key: `HKDF(K36, salt=part_id, info="candor/v1/stage/part")` (§9.13).
pub fn derive_stage_part_key(k36: &Secret32, part_id: &[u8; 16]) -> Result<AeadKey> {
    derive_into!(AeadKey, k36.expose(), part_id, &[labels::STAGE_PART])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    /// ST-022: HKDF-SHA256 RFC 5869 A.1.
    #[test]
    fn rfc5869_case1() {
        let ikm = [0x0bu8; 22];
        let salt = hex_lit("000102030405060708090a0b0c");
        let info = hex_lit("f0f1f2f3f4f5f6f7f8f9");
        let mut okm = [0u8; 42];
        hkdf(&ikm, &salt, &[&info[..5], &info[5..]], &mut okm).unwrap();
        assert_eq!(
            okm.to_vec(),
            hex_lit(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            prk.expose().to_vec(),
            hex_lit("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );
    }

    /// ST-022: HMAC-SHA-256 RFC 4231 test case 2.
    #[test]
    fn rfc4231_case2() {
        let out = hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"]).unwrap();
        assert_eq!(
            out.to_vec(),
            hex_lit("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    }

    #[test]
    fn derivations_are_domain_separated() {
        let ck = ContentKey::from_bytes([7; 32]);
        let a = derive_payload_key(Suite::CandorStd1, &ck, &[1; 16]).unwrap();
        let b = derive_header_mac_key(Suite::CandorStd1, &ck, &[1; 16]).unwrap();
        assert_ne!(a.expose(), b.expose());
        assert_eq!(
            derive_payload_key(Suite::CandorFips1, &ck, &[1; 16]).err(),
            Some(Error::UnsupportedSuite)
        );
    }

    fn hex_lit(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }
}
