// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Object identifiers: the only name type the store accepts (07 §10).

use crate::SafeFsError;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
/// Length of the canonical textual form.
pub(crate) const ID_LEN: usize = 26;

/// A 128-bit object identifier, rendered as 26 lowercase RFC 4648 base32
/// characters `[a-z2-7]{26}` (no padding; the final character carries the
/// last 3 bits followed by two zero bits, which parsing enforces).
///
/// Identifiers come only from [`ObjectId::random`] or from a keyed content
/// hash ([`ContentKey::object_id`]); never from caller-supplied names.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectId([u8; 16]);

impl ObjectId {
    /// A fresh random identifier from the OS CSPRNG.
    pub fn random() -> Result<Self, SafeFsError> {
        let mut b = [0u8; 16];
        getrandom::fill(&mut b).map_err(|_| SafeFsError::Io(std::io::ErrorKind::Other))?;
        Ok(Self(b))
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Builds an id from raw bytes (e.g. read back from an encrypted record).
    pub fn from_bytes(b: [u8; 16]) -> Self {
        Self(b)
    }

    /// Parses the canonical 26-character form. Anything else — upper case,
    /// padding, separators, dots, non-zero trailing bits — is rejected.
    pub fn parse(s: &str) -> Result<Self, SafeFsError> {
        let bytes = s.as_bytes();
        if bytes.len() != ID_LEN {
            return Err(SafeFsError::InvalidObjectId);
        }
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        let mut out = [0u8; 16];
        let mut n = 0usize;
        for &c in bytes {
            let v = ALPHABET
                .iter()
                .position(|&a| a == c)
                .ok_or(SafeFsError::InvalidObjectId)?;
            acc = (acc << 5) | u32::try_from(v).map_err(|_| SafeFsError::InvalidObjectId)?;
            bits = bits.wrapping_add(5);
            if bits >= 8 {
                bits = bits.wrapping_sub(8);
                let slot = out.get_mut(n).ok_or(SafeFsError::InvalidObjectId)?;
                *slot = ((acc >> bits) & 0xff) as u8;
                n = n.wrapping_add(1);
            }
            acc &= (1u32 << bits).wrapping_sub(1);
        }
        // 26*5 = 130 bits: exactly 16 bytes and 2 leftover bits that must be 0.
        if n != 16 || bits != 2 || acc != 0 {
            return Err(SafeFsError::InvalidObjectId);
        }
        Ok(Self(out))
    }

    /// Canonical 26-character lowercase base32 form.
    pub fn to_name(&self) -> String {
        let mut s = String::with_capacity(ID_LEN);
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        for &b in &self.0 {
            acc = (acc << 8) | u32::from(b);
            bits = bits.wrapping_add(8);
            while bits >= 5 {
                bits = bits.wrapping_sub(5);
                push_sym(&mut s, (acc >> bits) & 31);
            }
            acc &= (1u32 << bits).wrapping_sub(1);
        }
        if bits > 0 {
            push_sym(&mut s, (acc << 5u32.wrapping_sub(bits)) & 31);
        }
        s
    }

    /// Two-character shard directory name (first two characters).
    pub(crate) fn shard(&self) -> String {
        self.to_name().chars().take(2).collect()
    }
}

fn push_sym(s: &mut String, v: u32) {
    let c = ALPHABET
        .get(usize::try_from(v).unwrap_or(0))
        .copied()
        .unwrap_or(b'a');
    s.push(char::from(c));
}

impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectId({})", self.to_name())
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_name())
    }
}

/// A 256-bit secret key for content-addressed naming.
///
/// Content-addressed ids are `BLAKE3-keyed(key, content)` truncated to 128
/// bits. A *keyed* hash is mandatory: an unkeyed content hash in a blob name
/// would let anyone holding a document confirm it was stored (FILE-005,
/// THR-015 confirmation attack). Zeroized on drop; never printed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ContentKey([u8; 32]);

impl ContentKey {
    /// Wraps existing key bytes (e.g. unwrapped from a keystore).
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    /// Generates a fresh random key.
    pub fn generate() -> Result<Self, SafeFsError> {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).map_err(|_| SafeFsError::Io(std::io::ErrorKind::Other))?;
        Ok(Self(b))
    }

    /// Content-addressed id of `data` under this key.
    pub fn object_id(&self, data: &[u8]) -> ObjectId {
        let mut h = self.hasher();
        h.update(data);
        id_from_hasher(&h)
    }

    pub(crate) fn hasher(&self) -> blake3::Hasher {
        blake3::Hasher::new_keyed(&self.0)
    }
}

pub(crate) fn id_from_hasher(h: &blake3::Hasher) -> ObjectId {
    let mut out = [0u8; 16];
    let digest = h.finalize();
    for (o, d) in out.iter_mut().zip(digest.as_bytes().iter()) {
        *o = *d;
    }
    ObjectId(out)
}

impl fmt::Debug for ContentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContentKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn known_encoding() {
        // RFC 4648 base32 of 16 zero bytes, lowercase, unpadded.
        assert_eq!(ObjectId([0; 16]).to_name(), "aaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(ObjectId([0xff; 16]).to_name(), "77777777777777777777777774");
    }

    #[test]
    fn rejects_noncanonical() {
        for bad in [
            "",
            "AAAAAAAAAAAAAAAAAAAAAAAAAA",
            "aaaaaaaaaaaaaaaaaaaaaaaaab", // non-zero trailing bits
            "aaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "../aaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaa/a",
            "aaaaaaaaaaaaaaaaaaaaaaaa.a",
            "aaaaaaaaaaaaaaaaaaaaaaaa1a",
        ] {
            assert!(ObjectId::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn content_key_debug_redacted() {
        let k = ContentKey::from_bytes([7; 32]);
        assert!(!format!("{k:?}").contains('7'));
        // Keyed: different keys give different ids for the same content.
        let k2 = ContentKey::from_bytes([8; 32]);
        assert_ne!(k.object_id(b"x"), k2.object_id(b"x"));
    }

    proptest! {
        // ST-048 (name fuzzing, property form): round-trip and alphabet.
        #[test]
        fn roundtrip(b in any::<[u8; 16]>()) {
            let id = ObjectId(b);
            let n = id.to_name();
            prop_assert_eq!(n.len(), ID_LEN);
            prop_assert!(n.bytes().all(|c| ALPHABET.contains(&c)));
            prop_assert_eq!(ObjectId::parse(&n).ok(), Some(id));
        }

        #[test]
        fn parse_arbitrary_never_panics(s in ".{0,40}") {
            if let Ok(id) = ObjectId::parse(&s) {
                prop_assert_eq!(id.to_name(), s);
            }
        }
    }
}
