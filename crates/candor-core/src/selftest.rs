// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Start-up known-answer self-tests (§22.2 "Startup self-tests", CRYPTO-034, ST-028).
//! Processes using `candor-core` call [`self_test`] at start and refuse to start on error.

use crate::aead::{chacha_open, chacha_seal, xchacha_open, xchacha_seal};
use crate::error::{Error, Result};
use crate::hash::{EvidenceHasher, sha256};
use crate::kdf::{ct_eq, hkdf, hmac_sha256};
use crate::kem::xwing_kat_digest;
use crate::secret::AeadKey;
use crate::sig::{SigningKey, verify_strict};

fn hx<const N: usize>(s: &str) -> Result<[u8; N]> {
    let b = s.as_bytes();
    if b.len() != N.saturating_mul(2) {
        return Err(Error::SelfTest("vector"));
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        let pair = b
            .get(i.saturating_mul(2)..i.saturating_mul(2).saturating_add(2))
            .ok_or(Error::SelfTest("vector"))?;
        let s = core::str::from_utf8(pair).map_err(|_| Error::SelfTest("vector"))?;
        *o = u8::from_str_radix(s, 16).map_err(|_| Error::SelfTest("vector"))?;
    }
    Ok(out)
}

fn check(ok: bool, what: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error::SelfTest(what))
    }
}

/// Run all start-up KATs and the RNG health check.
pub fn self_test() -> Result<()> {
    // SHA-256 (FIPS 180-4 "abc") and BLAKE3 (empty input).
    check(
        sha256(&[b"abc"])
            == hx::<32>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")?,
        "sha256",
    )?;
    check(
        EvidenceHasher::digest(b"").blake3
            == hx::<32>("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")?,
        "blake3",
    )?;
    // HMAC-SHA-256 (RFC 4231 case 2).
    check(
        hmac_sha256(b"Jefe", &[b"what do ya want for nothing?"])?
            == hx::<32>("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")?,
        "hmac",
    )?;
    // HKDF-SHA256 (RFC 5869 A.1, first 32 bytes of OKM).
    let mut okm = [0u8; 32];
    hkdf(
        &[0x0b; 22],
        &hx::<13>("000102030405060708090a0b0c")?,
        &[&hx::<10>("f0f1f2f3f4f5f6f7f8f9")?],
        &mut okm,
    )?;
    check(
        okm == hx::<32>("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")?,
        "hkdf",
    )?;
    // ChaCha20-Poly1305 (RFC 8439 §2.8.2: ciphertext prefix and tag).
    let key = AeadKey::from_bytes(hx::<32>(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    )?);
    let aad = hx::<12>("50515253c0c1c2c3c4c5c6c7")?;
    let pt: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let ct = chacha_seal(&key, &hx::<12>("070000004041424344454647")?, &aad, pt)?;
    check(
        ct.get(..16) == Some(&hx::<16>("d31a8d34648e60db7b86afbc53ef7ec2")?[..])
            && ct.get(ct.len().saturating_sub(16)..)
                == Some(&hx::<16>("1ae10b594f09e26a7e902ecbd0600691")?[..]),
        "chacha20poly1305",
    )?;
    check(
        chacha_open(&key, &hx::<12>("070000004041424344454647")?, &aad, &ct)?.as_slice() == pt,
        "chacha20poly1305 open",
    )?;
    // XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03 A.3.1: tag).
    let xn = hx::<24>("404142434445464748494a4b4c4d4e4f5051525354555657")?;
    let xct = xchacha_seal(&key, &xn, &aad, pt)?;
    check(
        xct.get(xct.len().saturating_sub(16)..)
            == Some(&hx::<16>("c0875924c1c7987947deafd8780acf49")?[..]),
        "xchacha20poly1305",
    )?;
    check(
        xchacha_open(&key, &xn, &aad, &xct)?.as_slice() == pt,
        "xchacha20poly1305 open",
    )?;
    // Ed25519 (RFC 8032 §7.1 TEST 1).
    let sk = SigningKey::from_seed(&hx::<32>(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    )?);
    let sig = sk.sign(b"");
    check(
        ct_eq(
            &sig,
            &hx::<64>(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            )?,
        ),
        "ed25519 sign",
    )?;
    verify_strict(&sk.verifying_key_bytes(), b"", &sig)
        .map_err(|_| Error::SelfTest("ed25519 verify"))?;
    // X-Wing (draft-connolly-cfrg-xwing-kem vector 0): SHA-256(pk ‖ ct ‖ ss).
    let d = xwing_kat_digest(
        &hx::<32>("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")?,
        hx::<64>(
            "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
        )?,
    )?;
    check(
        d == hx::<32>("c2f4c2fdda6784454063b54c554d7fa58c08c1a09b354bb00503925eb34c7541")?,
        "x-wing",
    )?;
    // Argon2id (RFC 9106 §5.3; m = 32 KiB, so cheap at start-up).
    let params = argon2::ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(argon2::AssociatedData::new(&[4u8; 12]).map_err(|_| Error::SelfTest("argon2"))?)
        .output_len(32)
        .build()
        .map_err(|_| Error::SelfTest("argon2"))?;
    let a2 = argon2::Argon2::new_with_secret(
        &[3u8; 8],
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    )
    .map_err(|_| Error::SelfTest("argon2"))?;
    let mut tag = [0u8; 32];
    a2.hash_password_into(&[1u8; 32], &[2u8; 16], &mut tag)
        .map_err(|_| Error::SelfTest("argon2"))?;
    check(
        tag == hx::<32>("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")?,
        "argon2id",
    )?;
    // RNG health: two draws, non-zero and distinct.
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    crate::rand::fill(&mut a)?;
    crate::rand::fill(&mut b)?;
    check(a != b, "rng")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_test_passes() {
        assert_eq!(super::self_test(), Ok(()));
    }
}
