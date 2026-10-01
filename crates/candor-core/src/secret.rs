// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Secret key containers: zeroized on drop, no `Clone`, redacted `Debug`, no `Display`
//! (§23.2, CRYPTO-057).

use zeroize::{Zeroize, ZeroizeOnDrop};

macro_rules! secret_key_type {
    ($(#[$m:meta])* $name:ident, $len:expr) => {
        $(#[$m])*
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Key length in bytes.
            pub const LEN: usize = $len;

            /// Wrap raw key bytes. The caller's copy should be zeroized.
            #[must_use]
            pub fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Wrap key bytes from a slice of exactly `LEN` bytes.
            pub fn from_slice(bytes: &[u8]) -> $crate::error::Result<Self> {
                let arr: [u8; $len] =
                    bytes.try_into().map_err(|_| $crate::error::Error::Length)?;
                Ok(Self(arr))
            }

            /// Borrow the raw key bytes. Callers must not log or persist them in clear.
            #[must_use]
            pub fn expose(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

secret_key_type!(
    /// Per-object Content Key CK (K05, §9.2).
    ContentKey,
    32
);
secret_key_type!(
    /// Case Key version v (K06, §9.3).
    CaseKey,
    32
);
secret_key_type!(
    /// Per-case Erasure Key EK (K32, §9.10).
    ErasureKey,
    32
);
secret_key_type!(
    /// A derived 256-bit AEAD key (STREAM key, record key, wrap key).
    AeadKey,
    32
);
secret_key_type!(
    /// Header MAC key `K_mac` (§13.1).
    MacKey,
    32
);
secret_key_type!(
    /// Generic 32-byte secret (seeds, PRKs).
    Secret32,
    32
);

impl ContentKey {
    /// Generate a fresh random content key from the OS CSPRNG.
    pub fn generate() -> crate::error::Result<Self> {
        let mut k = [0u8; 32];
        crate::rand::fill(&mut k)?;
        let out = Self(k);
        k.zeroize();
        Ok(out)
    }

    pub(crate) fn generate_with(rng: &mut dyn crate::rand::RandomSource) -> crate::error::Result<Self> {
        let mut k = [0u8; 32];
        rng.fill(&mut k)?;
        let out = Self(k);
        k.zeroize();
        Ok(out)
    }
}

impl CaseKey {
    /// Generate a fresh random case key from the OS CSPRNG.
    pub fn generate() -> crate::error::Result<Self> {
        let mut k = [0u8; 32];
        crate::rand::fill(&mut k)?;
        let out = Self(k);
        k.zeroize();
        Ok(out)
    }
}

impl ErasureKey {
    /// Generate a fresh random erasure key from the OS CSPRNG.
    pub fn generate() -> crate::error::Result<Self> {
        let mut k = [0u8; 32];
        crate::rand::fill(&mut k)?;
        let out = Self(k);
        k.zeroize();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        // CRYPTO-057: secrets never appear in Debug output.
        let k = ContentKey::from_bytes([0xAB; 32]);
        let s = format!("{k:?}");
        assert_eq!(s, "ContentKey(<redacted>)");
        assert!(!s.contains("ab") && !s.contains("171"));
    }

    #[test]
    fn from_slice_checks_length() {
        assert!(ContentKey::from_slice(&[0u8; 31]).is_err());
        assert!(ContentKey::from_slice(&[0u8; 33]).is_err());
        assert!(ContentKey::from_slice(&[0u8; 32]).is_ok());
    }
}
