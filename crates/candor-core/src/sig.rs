// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Ed25519 signatures (RFC 8032) with strict verification (§23.3, CA-3).

use crate::error::{Error, Result};
use ed25519_dalek::Signer as _;
use zeroize::Zeroizing;

/// An Ed25519 signing key. Zeroized on drop; `Debug` redacted.
pub struct SigningKey(ed25519_dalek::SigningKey);

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningKey(<redacted>)")
    }
}

impl SigningKey {
    /// From a 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// Generate from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        crate::rand::fill(seed.as_mut())?;
        Ok(Self::from_seed(&seed))
    }

    /// Public key bytes.
    #[must_use]
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Sign a message.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }
}

/// Sign `context ‖ parts…` (the spec's signature forms are all a registered label
/// followed by fixed fields).
#[must_use]
pub fn sign_with_context(key: &SigningKey, context: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut msg = Vec::with_capacity(256);
    msg.extend_from_slice(context);
    for p in parts {
        msg.extend_from_slice(p);
    }
    key.sign(&msg)
}

/// Strict RFC 8032 verification (canonical S, reject small-order keys).
pub fn verify_strict(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<()> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(pk).map_err(|_| Error::InvalidKey)?;
    let s = ed25519_dalek::Signature::from_bytes(sig);
    vk.verify_strict(msg, &s).map_err(|_| Error::Signature)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// ST-021: RFC 8032 §7.1 TEST 1 (empty message).
    #[test]
    fn rfc8032_test1() {
        let seed: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        let k = SigningKey::from_seed(&seed);
        assert_eq!(
            hex::encode(k.verifying_key_bytes()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig = k.sign(b"");
        assert_eq!(
            hex::encode(sig),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        assert!(verify_strict(&k.verifying_key_bytes(), b"", &sig).is_ok());
        assert_eq!(
            verify_strict(&k.verifying_key_bytes(), b"x", &sig).err(),
            Some(Error::Signature)
        );
    }

    /// Strictness: small-order public key (identity point) is rejected.
    #[test]
    fn rejects_small_order_key() {
        let mut id = [0u8; 32];
        id[0] = 1;
        let r = verify_strict(&id, b"", &[0u8; 64]);
        assert!(r.is_err());
    }
}
