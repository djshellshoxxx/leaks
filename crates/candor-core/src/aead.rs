// SPDX-License-Identifier: Apache-2.0 OR MIT
//! AEAD primitives of CANDOR-STD-1: ChaCha20-Poly1305 (STREAM) and
//! XChaCha20-Poly1305 (records and symmetric wraps) (§4.1, §8).

use crate::error::{Error, Result};
use crate::secret::AeadKey;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, XChaCha20Poly1305};
use zeroize::Zeroizing;

pub(crate) fn chacha_seal(key: &AeadKey, nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    let c = ChaCha20Poly1305::new(&(*key.expose()).into());
    c.encrypt(&(*nonce).into(), Payload { msg: pt, aad }).map_err(|_| Error::Internal)
}

pub(crate) fn chacha_open(key: &AeadKey, nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let c = ChaCha20Poly1305::new(&(*key.expose()).into());
    c.decrypt(&(*nonce).into(), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Authentication)
}

pub(crate) fn xchacha_seal(key: &AeadKey, nonce: &[u8; 24], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    let c = XChaCha20Poly1305::new(&(*key.expose()).into());
    c.encrypt(&(*nonce).into(), Payload { msg: pt, aad }).map_err(|_| Error::Internal)
}

pub(crate) fn xchacha_open(key: &AeadKey, nonce: &[u8; 24], aad: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let c = XChaCha20Poly1305::new(&(*key.expose()).into());
    c.decrypt(&(*nonce).into(), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Authentication)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// ST-022: ChaCha20-Poly1305 RFC 8439 §2.8.2.
    #[test]
    fn rfc8439_aead() {
        let key = AeadKey::from_slice(&hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap()).unwrap();
        let nonce: [u8; 12] = hex::decode("070000004041424344454647").unwrap().try_into().unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ct = chacha_seal(&key, &nonce, &aad, pt).unwrap();
        // Exact RFC 8439 ciphertext prefix and tag.
        assert!(hex::encode(&ct).starts_with("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"));
        assert!(hex::encode(&ct).ends_with("1ae10b594f09e26a7e902ecbd0600691"));
        let back = chacha_open(&key, &nonce, &aad, &ct).unwrap();
        assert_eq!(back.as_slice(), pt);
        let mut bad = ct.clone();
        if let Some(b) = bad.last_mut() {
            *b ^= 1;
        }
        assert_eq!(chacha_open(&key, &nonce, &aad, &bad).err(), Some(Error::Authentication));
    }

    /// ST-022: XChaCha20-Poly1305 draft-irtf-cfrg-xchacha-03 §A.3.1.
    #[test]
    fn xchacha_draft_vector() {
        let key = AeadKey::from_slice(&hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap()).unwrap();
        let nonce: [u8; 24] = hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657").unwrap().try_into().unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ct = chacha_seal_x(&key, &nonce, &aad, pt);
        assert!(hex::encode(&ct).starts_with("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"));
        assert!(hex::encode(&ct).ends_with("c0875924c1c7987947deafd8780acf49"));
        assert_eq!(xchacha_open(&key, &nonce, &aad, &ct).unwrap().as_slice(), pt);
    }

    fn chacha_seal_x(key: &AeadKey, nonce: &[u8; 24], aad: &[u8], pt: &[u8]) -> Vec<u8> {
        xchacha_seal(key, nonce, aad, pt).unwrap()
    }
}
