// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Hashes: SHA-256 content ids, `key_id`, bound hashes, evidence hashes (ADR-012).

use crate::labels;
use crate::suite::Suite;
use sha2::{Digest, Sha256};

/// SHA-256 over concatenated parts.
#[must_use]
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_slice());
    out
}

/// Key kinds for `key_id` (§13.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyKind {
    /// Member Epoch Key (K04).
    Mek = 1,
    /// User encryption key (K09).
    UserEnc = 2,
    /// Identity custodian group key (K13).
    Custodian = 3,
    /// Recovery quorum key (K14).
    Quorum = 4,
    /// Source X-Wing key.
    Source = 5,
    /// Viewer-job ephemeral key (K34).
    ViewerJob = 6,
}

/// `key_id(pk) = SHA-256("candor/v1/key-id" ‖ u16 suite ‖ u8 key_kind ‖ pk)` (§13.2).
#[must_use]
pub fn key_id(suite: Suite, kind: KeyKind, pk: &[u8]) -> [u8; 32] {
    sha256(&[labels::KEY_ID, &suite.to_be_bytes(), &[kind as u8], pk])
}

/// `lookup_tag = SHA-256("candor/v1/lookup-tag" ‖ lookup_id)` (§11.4).
#[must_use]
pub fn lookup_tag(lookup_id: &[u8; 32]) -> [u8; 32] {
    sha256(&[labels::LOOKUP_TAG, lookup_id])
}

/// Case-key stanza `bound_hash = H("candor/v1/casekey" ‖ case_id ‖ u32 v)` (§13.2).
#[must_use]
pub fn casekey_bound_hash(case_id: &[u8; 16], version: u32) -> [u8; 32] {
    sha256(&[labels::CASEKEY_BOUND, case_id, &version.to_be_bytes()])
}

/// Channel-key stanza `bound_hash = H("candor/v1/chankey" ‖ channel_id ‖ wrapped_key_id)` (§13.2).
#[must_use]
pub fn chankey_bound_hash(channel_id: &[u8; 16], wrapped_key_id: &[u8; 32]) -> [u8; 32] {
    sha256(&[labels::CHANKEY_BOUND, channel_id, wrapped_key_id])
}

/// Evidence hashes over decrypted file bytes (ADR-012, CRYPTO-050).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceHashes {
    /// SHA-256.
    pub sha256: [u8; 32],
    /// BLAKE3-256 (STD suite).
    pub blake3: [u8; 32],
}

/// Incremental SHA-256 + BLAKE3 hasher.
#[derive(Default)]
pub struct EvidenceHasher {
    sha: Sha256,
    b3: blake3::Hasher,
}

impl core::fmt::Debug for EvidenceHasher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EvidenceHasher")
    }
}

impl EvidenceHasher {
    /// New hasher.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Absorb bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.sha.update(data);
        self.b3.update(data);
    }

    /// Finish.
    #[must_use]
    pub fn finalize(self) -> EvidenceHashes {
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(self.sha.finalize().as_slice());
        EvidenceHashes { sha256, blake3: *self.b3.finalize().as_bytes() }
    }

    /// One-shot.
    #[must_use]
    pub fn digest(data: &[u8]) -> EvidenceHashes {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ST-022: SHA-256 ("abc", FIPS 180-4) and BLAKE3 (empty input, reference vector).
    #[test]
    fn evidence_kats() {
        let e = EvidenceHasher::digest(b"abc");
        assert_eq!(
            hex::encode(e.sha256),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let e = EvidenceHasher::digest(b"");
        assert_eq!(
            hex::encode(e.blake3),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        let mut h = EvidenceHasher::new();
        h.update(b"a");
        h.update(b"bc");
        assert_eq!(h.finalize(), EvidenceHasher::digest(b"abc"));
    }

    #[test]
    fn key_id_binds_suite_and_kind() {
        let pk = [9u8; 1216];
        let a = key_id(Suite::CandorStd1, KeyKind::Mek, &pk);
        assert_ne!(a, key_id(Suite::CandorStd1, KeyKind::UserEnc, &pk));
        assert_ne!(a, key_id(Suite::CandorFips1, KeyKind::Mek, &pk));
    }
}
