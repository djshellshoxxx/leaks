// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cipher suites (§4.1, ADR-006) and fixed sizes (§4.2).

use crate::error::{Error, Result};

/// A Candor cipher suite. Suites are never negotiated in-band (CRYPTO-003).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Suite {
    /// CANDOR-STD-1: X-Wing / HKDF-SHA256 / ChaCha20-Poly1305 HPKE, ChaCha20-Poly1305 STREAM,
    /// XChaCha20-Poly1305 records, HMAC-SHA-256, Ed25519, Argon2id.
    CandorStd1 = 0x0001,
    /// CANDOR-FIPS-1. Recognised on the wire but not implemented in this build:
    /// every operation returns [`Error::UnsupportedSuite`].
    CandorFips1 = 0x0002,
}

impl Suite {
    /// Wire identifier.
    #[must_use]
    pub const fn id(self) -> u16 {
        self as u16
    }

    /// Big-endian wire encoding (used in labels and AAD, §9.9).
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.id().to_be_bytes()
    }

    /// Parse a wire identifier. Unknown values (including the reserved CNSA `0x0003`)
    /// are rejected (§13.9, CRYPTO-056).
    pub fn from_id(id: u16) -> Result<Self> {
        match id {
            0x0001 => Ok(Suite::CandorStd1),
            0x0002 => Ok(Suite::CandorFips1),
            _ => Err(Error::UnknownSuite),
        }
    }

    /// Parse a wire identifier and require that this build implements it.
    pub fn from_id_supported(id: u16) -> Result<Self> {
        let s = Self::from_id(id)?;
        s.require_supported()?;
        Ok(s)
    }

    /// Fail with [`Error::UnsupportedSuite`] unless this build implements the suite.
    pub fn require_supported(self) -> Result<()> {
        match self {
            Suite::CandorStd1 => Ok(()),
            Suite::CandorFips1 => Err(Error::UnsupportedSuite),
        }
    }

    /// HPKE encapsulated key length `Nenc` (§4.2).
    #[must_use]
    pub const fn hpke_nenc(self) -> usize {
        match self {
            Suite::CandorStd1 => XWING_NENC,
            Suite::CandorFips1 => 1665,
        }
    }

    /// HPKE public key length `Npk` (§4.2).
    #[must_use]
    pub const fn hpke_npk(self) -> usize {
        match self {
            Suite::CandorStd1 => XWING_NPK,
            Suite::CandorFips1 => 1665,
        }
    }

    /// Header MAC length (§13.1).
    #[must_use]
    pub const fn mac_len(self) -> usize {
        match self {
            Suite::CandorStd1 => 32,
            Suite::CandorFips1 => 48,
        }
    }

    /// Record AEAD nonce length (§13.8).
    #[must_use]
    pub const fn record_nonce_len(self) -> usize {
        match self {
            Suite::CandorStd1 => 24,
            Suite::CandorFips1 => 12,
        }
    }
}

/// The default suite for every tenant (CRYPTO-001).
pub const DEFAULT_SUITE: Suite = Suite::CandorStd1;

/// X-Wing encapsulated key length.
pub const XWING_NENC: usize = 1120;
/// X-Wing public key length.
pub const XWING_NPK: usize = 1216;
/// X-Wing private key (seed) length.
pub const XWING_NSK: usize = 32;
/// AEAD key length.
pub const AEAD_KEY_LEN: usize = 32;
/// AEAD tag length.
pub const AEAD_TAG_LEN: usize = 16;
/// Content key length.
pub const CK_LEN: usize = 32;
/// Ed25519 public key length.
pub const ED25519_PK_LEN: usize = 32;
/// Ed25519 signature length.
pub const ED25519_SIG_LEN: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_roundtrip_and_reject_unknown() {
        assert_eq!(Suite::from_id(1), Ok(Suite::CandorStd1));
        assert_eq!(Suite::from_id(2), Ok(Suite::CandorFips1));
        // CRYPTO-056: CNSA-1 (0x0003) is reserved, not shipped.
        for id in [0u16, 3, 0xffff, 0x0100] {
            assert_eq!(Suite::from_id(id), Err(Error::UnknownSuite));
        }
    }

    #[test]
    fn fips_is_unsupported() {
        assert_eq!(Suite::from_id_supported(2), Err(Error::UnsupportedSuite));
        assert_eq!(Suite::CandorFips1.require_supported(), Err(Error::UnsupportedSuite));
        assert!(Suite::CandorStd1.require_supported().is_ok());
    }
}
