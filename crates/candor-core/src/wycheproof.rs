// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Wycheproof / CCTV vectors (ST-023, AUD-RM1-CORE-05(b)). Test-only.
//!
//! Source: <https://github.com/C2SP/wycheproof> `testvectors_v1/` at commit
//! `3fa63dd0344abb611f1fb1d77e119938603ea230` (2026-09-02). Files are committed
//! byte-identical under `tests/vectors/wycheproof/` (the ML-KEM file is a documented
//! subset) and their SHA-256 is pinned below and checked before use.
//!
//! The vectors exercise this crate's own wrappers (`aead`, `kdf`, `sig`, `kem`) where
//! one exists, and the dependency directly otherwise (X25519 via `x25519-dalek`, the
//! same version `hpke` uses inside X-Wing).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use crate::aead::{chacha_open, chacha_seal, xchacha_open, xchacha_seal};
use crate::error::Error;
use crate::kdf::{hkdf, hmac_sha256};
use crate::kem::KemPublicKey;
use crate::secret::AeadKey;
use crate::sig::verify_strict;
use crate::suite::Suite;
use serde_json::Value;

const CHACHA: &str = include_str!("../tests/vectors/wycheproof/chacha20_poly1305_test.json");
const XCHACHA: &str = include_str!("../tests/vectors/wycheproof/xchacha20_poly1305_test.json");
const X25519: &str = include_str!("../tests/vectors/wycheproof/x25519_test.json");
const ED25519: &str = include_str!("../tests/vectors/wycheproof/ed25519_test.json");
const HKDF: &str = include_str!("../tests/vectors/wycheproof/hkdf_sha256_test.json");
const HMAC: &str = include_str!("../tests/vectors/wycheproof/hmac_sha256_test.json");
const MLKEM: &str = include_str!("../tests/vectors/wycheproof/mlkem_768_encaps_subset.json");

/// Pinned SHA-256 of each committed file (see SPEC-NOTES "Wycheproof").
fn pin(text: &str) -> &'static str {
    match text {
        t if t == CHACHA => "fe61d25f90e1bde4461d00eafe61049e5f29bd999f36b766df9cda90906ad53d",
        t if t == XCHACHA => "a79de072571b90eb40c3a63ce0c7f75dcb4b62323c8870228e1f61dcc61d63a9",
        t if t == X25519 => "35c3f5231cf25cc640b524d403461deee9e49441d5d915a3a25b2c8ff5adbe7d",
        t if t == ED25519 => "752d2ea7d7c6cf4736381b6cbacb61f8182b126ab7cd9b058f00c50084975536",
        t if t == HKDF => "bb2b462a38b251cb52a2aede706d6d4b62b26864f4e80c95497507ddb07c5f1e",
        t if t == HMAC => "2d201cfa61d1bf95e6f5d07d96634b4a348b31e8eaa277ad7c8d09677b7a743f",
        t if t == MLKEM => "63bb35573ab914918d704ce2ea4cfd47c950cc45e22b361a0d3ca6b332e63733",
        _ => panic!("unpinned Wycheproof file"),
    }
}

fn load(text: &str) -> Value {
    assert_eq!(
        hex::encode(crate::hash::sha256(&[text.as_bytes()])),
        pin(text),
        "Wycheproof file hash mismatch"
    );
    serde_json::from_str(text).unwrap()
}

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

/// Iterate `(group, test)` pairs; returns the number of tests visited.
fn each(v: &Value, mut f: impl FnMut(&Value, &Value)) -> usize {
    let mut n = 0;
    for g in v["testGroups"].as_array().unwrap() {
        for t in g["tests"].as_array().unwrap() {
            f(g, t);
            n += 1;
        }
    }
    assert_eq!(n as u64, v["numberOfTests"].as_u64().unwrap());
    n
}

fn result(t: &Value) -> &str {
    t["result"].as_str().unwrap()
}

fn aead_suite<const N: usize>(
    text: &str,
    seal: fn(&AeadKey, &[u8; N], &[u8], &[u8]) -> crate::Result<Vec<u8>>,
    open: fn(&AeadKey, &[u8; N], &[u8], &[u8]) -> crate::Result<zeroize::Zeroizing<Vec<u8>>>,
) -> (usize, usize) {
    let v = load(text);
    let mut unrepresentable = 0;
    let n = each(&v, |_, t| {
        let key = hx(&t["key"]);
        let iv = hx(&t["iv"]);
        let (Ok(key), Ok(iv)) = (
            AeadKey::from_slice(&key),
            <[u8; N]>::try_from(iv.as_slice()),
        ) else {
            // Wrong key/nonce sizes cannot be expressed through the typed API.
            assert_eq!(result(t), "invalid", "tc {}", t["tcId"]);
            unrepresentable += 1;
            return;
        };
        let (aad, msg) = (hx(&t["aad"]), hx(&t["msg"]));
        let mut ct = hx(&t["ct"]);
        ct.extend_from_slice(&hx(&t["tag"]));
        let opened = open(&key, &iv, &aad, &ct);
        match result(t) {
            "valid" => {
                assert_eq!(seal(&key, &iv, &aad, &msg).unwrap(), ct, "tc {}", t["tcId"]);
                assert_eq!(opened.unwrap().as_slice(), msg.as_slice());
            }
            _ => assert_eq!(
                opened.err(),
                Some(Error::Authentication),
                "tc {}",
                t["tcId"]
            ),
        }
    });
    (n, unrepresentable)
}

/// ST-023: ChaCha20-Poly1305 (STREAM chunks), incl. Poly1305/tag edge cases.
#[test]
fn wycheproof_chacha20_poly1305() {
    let (n, skipped) = aead_suite::<12>(CHACHA, chacha_seal, chacha_open);
    assert!(n >= 300 && skipped < n / 4, "{n} {skipped}");
}

/// ST-023: XChaCha20-Poly1305 (records, wraps).
#[test]
fn wycheproof_xchacha20_poly1305() {
    let (n, skipped) = aead_suite::<24>(XCHACHA, xchacha_seal, xchacha_open);
    assert!(n >= 300 && skipped < n / 4, "{n} {skipped}");
}

/// ST-023: HKDF-SHA256 (all §10 derivations), incl. empty salt and the output-length
/// limit (`SizeTooLarge` must fail closed).
#[test]
fn wycheproof_hkdf_sha256() {
    let v = load(HKDF);
    each(&v, |_, t| {
        let size = usize::try_from(t["size"].as_u64().unwrap()).unwrap();
        let mut out = vec![0u8; size];
        let r = hkdf(
            &hx(&t["ikm"]),
            &hx(&t["salt"]),
            &[&hx(&t["info"])],
            &mut out,
        );
        match result(t) {
            "valid" => {
                r.unwrap();
                assert_eq!(out, hx(&t["okm"]), "tc {}", t["tcId"]);
            }
            _ => assert_eq!(r.err(), Some(Error::Length), "tc {}", t["tcId"]),
        }
    });
}

/// ST-023: HMAC-SHA-256 (`header_mac`), incl. truncated-tag groups.
#[test]
fn wycheproof_hmac_sha256() {
    let v = load(HMAC);
    each(&v, |g, t| {
        let tag_len = usize::try_from(g["tagSize"].as_u64().unwrap() / 8).unwrap();
        let mac = hmac_sha256(&hx(&t["key"]), &[&hx(&t["msg"])]).unwrap();
        let ok = crate::kdf::ct_eq(&mac[..tag_len], &hx(&t["tag"]));
        assert_eq!(ok, result(t) == "valid", "tc {}", t["tcId"]);
    });
}

/// ST-023: Ed25519 with `verify_strict` (malleability, non-canonical encodings,
/// truncated/extended signatures).
#[test]
fn wycheproof_ed25519() {
    let v = load(ED25519);
    let mut valid = 0;
    each(&v, |g, t| {
        let pk: [u8; 32] = hx(&g["publicKey"]["pk"]).try_into().unwrap();
        let sig = hx(&t["sig"]);
        let verified = <[u8; 64]>::try_from(sig.as_slice())
            .is_ok_and(|s| verify_strict(&pk, &hx(&t["msg"]), &s).is_ok());
        assert_eq!(verified, result(t) == "valid", "tc {}", t["tcId"]);
        valid += usize::from(verified);
    });
    assert!(valid > 0);
}

/// ST-023: X25519 (the classical half of X-Wing) computes every Wycheproof vector,
/// and AUD-RM1-CORE-14: `KemPublicKey::from_bytes` refuses every X25519 component
/// that is non-canonical or yields an all-zero shared secret, and accepts the rest.
#[test]
fn wycheproof_x25519_and_xwing_pk_validation() {
    let v = load(X25519);
    let ek = valid_mlkem_ek();
    let (mut rejected, mut accepted) = (0, 0);
    each(&v, |_, t| {
        let public: [u8; 32] = hx(&t["public"]).try_into().unwrap();
        let private: [u8; 32] = hx(&t["private"]).try_into().unwrap();
        let shared = x25519_dalek::x25519(private, public);
        assert_eq!(shared.to_vec(), hx(&t["shared"]), "tc {}", t["tcId"]);
        let mut pk = ek.clone();
        pk.extend_from_slice(&public);
        let flags: Vec<&str> = t["flags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f.as_str().unwrap())
            .collect();
        let accepted_now = KemPublicKey::from_bytes(Suite::CandorStd1, &pk).is_ok();
        if flags.iter().any(|f| {
            matches!(
                *f,
                "ZeroSharedSecret" | "LowOrderPublic" | "NonCanonicalPublic"
            )
        }) {
            assert!(!accepted_now, "tc {} must be rejected", t["tcId"]);
        }
        if accepted_now {
            // An accepted key never produces the all-zero shared secret.
            assert_ne!(shared, [0u8; 32], "tc {}", t["tcId"]);
            accepted += 1;
        } else {
            rejected += 1;
        }
    });
    assert!(accepted > 100 && rejected > 10, "{accepted} {rejected}");
}

fn valid_mlkem_ek() -> Vec<u8> {
    let v = load(MLKEM);
    let t = v["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|g| g["tests"].as_array().unwrap())
        .find(|t| result(t) == "valid")
        .unwrap();
    hx(&t["ek"])
}

/// ST-023 / AUD-RM1-CORE-05(b): ML-KEM-768 encapsulation keys failing the FIPS 203
/// modulus check are refused inside an X-Wing public key; valid ones are accepted.
#[test]
fn wycheproof_mlkem768_invalid_ek() {
    let v = load(MLKEM);
    let mut x = [0u8; 32];
    x[0] = 9; // the X25519 base point: canonical, not of low order.
    let (mut bad, mut good) = (0, 0);
    each(&v, |_, t| {
        let mut pk = hx(&t["ek"]);
        pk.extend_from_slice(&x);
        let r = KemPublicKey::from_bytes(Suite::CandorStd1, &pk);
        if result(t) == "valid" {
            r.unwrap();
            good += 1;
        } else {
            assert!(r.is_err(), "tc {}", t["tcId"]);
            bad += 1;
        }
    });
    assert!(good > 0 && bad > 0);
}
