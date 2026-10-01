// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Start-up known-answer self-tests (§22.2 "Startup self-tests", CRYPTO-034, ST-028).
//! Processes using `candor-core` call [`self_test`] at start and refuse to start on error.

use crate::aead::{chacha_open, chacha_seal, xchacha_open, xchacha_seal};
use crate::error::{Error, Result};
use crate::hash::{EvidenceHasher, sha256};
use crate::kdf::{ct_eq, hkdf, hmac_sha256};
use crate::kem::{KemKeyPair, open_base, xwing_kat_digest};
use crate::secret::AeadKey;
use crate::sig::{SigningKey, verify_strict};

/// Variable-length hex (vector data only).
fn hxv(s: &str) -> Result<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    for pair in b.chunks(2) {
        if pair.len() != 2 {
            return Err(Error::SelfTest("vector"));
        }
        let s = core::str::from_utf8(pair).map_err(|_| Error::SelfTest("vector"))?;
        out.push(u8::from_str_radix(s, 16).map_err(|_| Error::SelfTest("vector"))?);
    }
    Ok(out)
}

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
        &hx::<64>(
            "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
        )?,
    )?;
    check(
        d == hx::<32>("c2f4c2fdda6784454063b54c554d7fa58c08c1a09b354bb00503925eb34c7541")?,
        "x-wing",
    )?;
    // HPKE base-mode open (AUD-RM1-CORE-16(b)): hpke-pq KEM 0x647a / HKDF-SHA256 /
    // ChaCha20-Poly1305 vector (tests/vectors/kat/hpke-pq-xwing.json, encryption 0):
    // DeriveKeyPair(ikmR), then OpenBase(enc, info, aad, ct) must return pt; a flipped
    // tag bit must fail.
    let kp = KemKeyPair::derive(
        crate::Suite::CandorStd1,
        &hx::<32>("c8575d137deab99ac98fb0873048c83c3a1f47ef5b409f609c0ca652f58c83e0")?,
    )
    .map_err(|_| Error::SelfTest("hpke derive"))?;
    let enc = hxv(concat!(
        "ab354dd589f74ee0eab7718a630cbec5df1d09058e177cd6dd141d883450ddd70c050d88bed3d07cce23415cab411108",
        "cc30906482a71adcb134a56e978a6152a8e063b24acd1534f264f10458152a9ed4f1f32b3d480c4f2453b7fdea772014",
        "6b3ee92cf8a13a4840076f68c911c65fa3db5053fb0aabf79e64cd5e7aa71b2b9641e713ec7df552e17d5020f8721ee4",
        "49b42c888e2a3f87cfd96e3a98c3e7c4cd8f647f899570f596bf17d2b6fa2cad19706d9cc3cf09493e1c7ffa0eb2a455",
        "9ae1d940fdbef97bed383e6ccfdb448d9f1a81805166b32c2af2e16878c6dc46ab43323ed9c136b925239782e3c329c3",
        "1a5cf2a80faf025a80766e244605c27afe4b624d9d8ca99b6ef5439ed1ad044b518c434385acd49f1369ded6624a2832",
        "a571ccdd70d08b3c04cb1cd3136166f9a485f536f69ec66f0293e840025ccaac42f8e5f7c9cb818076c272797047f5e5",
        "0c1e9f1dab81cfb48fe4c4998b2427f009702b145f34ad8dbc3e7ad4e4023057ba31cd02c4c0545ebf71eb02533e8eaa",
        "2b2f2690ee1407bf1f66dc5f4d836c45b82f10b720df72d237488a9af1b6dfb4741fd613379c2e211e77f7fae6b3734a",
        "d81de2d452005334857c4a3cbc82afc7428fe510495969b296d24e1a7431f557d48578cf92ae86c0392f0ba73755a9e5",
        "465c8e3495e4cd2a82d463244341e39414e26c9b242f31d2cf0e46b2aeb11dd5e56ec44834350d151344229e410faff2",
        "b2ace5c9b3fa12571db1d28da2c7133492781dac41b7a7e2bac2260fd12f56939033587824c9dfb17d41b3bceea53763",
        "193abe0c7c184d5de161ef5312f31fab42478c9a193b868e4d29b2b7624f3ebe740f393d03d843cd5327286a579fd2a6",
        "e37aca5b64f9316115d612c7781e704ea7d182701c5019975cad14fbf4ab3904d4a35acaf0be32d716a1ef5d7188fc41",
        "8ae9e60744325a3e8001655b756df94c24031c3ce32bd90c0ecdac52ca140fdad7f44d04bd0a7e2a726c54cf9793f878",
        "4a23296f65da3fd1cbc18300d503c5b27be99b9b0e32d20b3614dc8a999f30c2779dd7886cfd486dc1c93ebcf517b521",
        "0a4359d9fa1805381f0f2261ff47de01de555d98bc1a30dda557a83007b61636abaf9041f96890f0f565eefc45859fbc",
        "d32d91b203215541227a4fcc3d95be2ddb0702878caa20f2da62c4ff9fe33af591ba1ec241fbe2208e0480f8b1cca167",
        "9c096f8f5a02a33e9df445b3274ac112b43d51510135cd3f532a3379e90bb7f0cb43717e90555bb1a80924cc69577455",
        "687cceb9b1610c05839541e87ad83d79ef3ff24ace1934cfbe989691959d93ac48c716b672b370dd4c144ca1e3250870",
        "7a6ef8aa29b55759b3d054c56bee1baa6f41b84b9fc3fd681a1a1528eac578141529836a29dda1501a49ba2455367256",
        "d2fe6f74ebb74ef9a49a94a4c6cd1dd09810f0e9bffa69dd8c94d226d0b2977b11a35382888961004a44c60fd602e9ff",
        "4271287e9240ba96146515b9db9da60375aeeafeac1eeb764faebacd197df27817c35fe4c5c802e43349d7bc95c8b40c",
        "001449d3251c1d92ff6d5c3b08c4b27c",
    ))?;
    let info =
        hxv("34663634363532303666366532303631323034373732363536333639363136653230353537323665")?;
    let aad = hxv("436f756e742d30")?;
    let mut hct = hxv(
        "a4ab74475a498ed725f685421f67c09a4783fe76f67bd251e1e73db8eb1452dfad4df3c6453f7edecc7bb055dde561e2efd54d73a3d4f1f2f02eac90ba1e9b84ded66d43aee6393524db",
    )?;
    let hpt = hxv(
        "34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739",
    )?;
    let opened = open_base(&kp.private, &enc, &info, &aad, &hct)
        .map_err(|_| Error::SelfTest("hpke open"))?;
    check(opened.as_slice() == hpt.as_slice(), "hpke open")?;
    if let Some(b) = hct.last_mut() {
        *b ^= 1;
    }
    check(
        open_base(&kp.private, &enc, &info, &aad, &hct).is_err(),
        "hpke open tamper",
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
