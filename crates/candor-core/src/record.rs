// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Encrypted record format (§13.8, CRYPTO-010/011/054) with the AAD forms of §9.9.
//!
//! `record = 0x01 ‖ u16 suite ‖ u32 key_version ‖ nonce (24 B) ‖ ciphertext ‖ tag`
//! (XChaCha20-Poly1305, random 192-bit nonce).

use crate::aead::{xchacha_open, xchacha_seal};
use crate::bytes::{Reader, concat};
use crate::error::{Error, Result};
use crate::labels;
use crate::rand::{OsRandom, RandomSource};
use crate::secret::AeadKey;
use crate::suite::{AEAD_TAG_LEN, Suite};
use zeroize::Zeroizing;

/// Record format version.
pub const RECORD_VERSION: u8 = 0x01;
/// Header length (version, suite, key_version, nonce) for STD.
pub const RECORD_HEADER_LEN: usize = 1 + 2 + 4 + 24;

/// Associated-data contexts. All ids are 16-byte UUIDs unless stated.
#[derive(Clone, PartialEq, Eq)]
pub enum RecordAad {
    /// Case field (§13.8): `"candor/v1/rec" ‖ tenant ‖ case_id ‖ u16 table ‖ u16 column ‖ record_id ‖ u32 key_version ‖ u64 row_version`.
    /// `key_version` is taken from the record header.
    Case {
        /// Tenant.
        tenant_id: [u8; 16],
        /// Case.
        case_id: [u8; 16],
        /// Table id.
        table_id: u16,
        /// Column id.
        column_id: u16,
        /// Record id.
        record_id: [u8; 16],
        /// Row version (replay detection, CRYPTO-054).
        row_version: u64,
    },
    /// `prefs_ct` (§9.9): `"candor/v1/source/prefs" ‖ tenant ‖ lookup_tag ‖ u32 prefs_version`.
    SourcePrefs {
        /// Tenant.
        tenant_id: [u8; 16],
        /// lookup_tag.
        lookup_tag: [u8; 32],
        /// prefs version.
        prefs_version: u32,
    },
    /// Desk keystore entry (§9.9): `"candor/v1/desk/keystore" ‖ user_id ‖ device_id ‖ key_id`.
    DeskKeystore {
        /// User.
        user_id: [u8; 16],
        /// Device.
        device_id: [u8; 16],
        /// Key id.
        key_id: [u8; 32],
    },
    /// K11 under authenticator slot i (§9.9): `"candor/v1/desk/keystore-slot" ‖ user_id ‖ device_id ‖ u8 i`.
    DeskKeystoreSlot {
        /// User.
        user_id: [u8; 16],
        /// Device.
        device_id: [u8; 16],
        /// Slot index.
        slot: u8,
    },
    /// Cached case key (§9.10): `"candor/v1/desk/case-key-cache" ‖ user_id ‖ device_id ‖ case_id ‖ u32 v`.
    DeskCaseKeyCache {
        /// User.
        user_id: [u8; 16],
        /// Device.
        device_id: [u8; 16],
        /// Case.
        case_id: [u8; 16],
        /// Case key version.
        version: u32,
    },
    /// Case metadata in the EKV (§9.10a): `"candor/v1/ek-meta" ‖ tenant ‖ case_id ‖ u16 column_id ‖ u64 row_version`.
    EkMeta {
        /// Tenant.
        tenant_id: [u8; 16],
        /// Case.
        case_id: [u8; 16],
        /// Column id.
        column_id: u16,
        /// Row version.
        row_version: u64,
    },
}

/// Redacted `Debug` (AUD-RM1-CORE-11): only the variant name; ids such as
/// `mailbox_id` and `lookup_tag` link a source and must never reach logs.
impl core::fmt::Debug for RecordAad {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            Self::Case { .. } => "Case",
            Self::SourcePrefs { .. } => "SourcePrefs",
            Self::DeskKeystore { .. } => "DeskKeystore",
            Self::DeskKeystoreSlot { .. } => "DeskKeystoreSlot",
            Self::DeskCaseKeyCache { .. } => "DeskCaseKeyCache",
            Self::EkMeta { .. } => "EkMeta",
        };
        write!(f, "RecordAad::{name}(<redacted>)")
    }
}

impl RecordAad {
    fn bytes(&self, key_version: u32) -> Vec<u8> {
        match self {
            Self::Case {
                tenant_id,
                case_id,
                table_id,
                column_id,
                record_id,
                row_version,
            } => concat(&[
                labels::RECORD_AAD,
                tenant_id,
                case_id,
                &table_id.to_be_bytes(),
                &column_id.to_be_bytes(),
                record_id,
                &key_version.to_be_bytes(),
                &row_version.to_be_bytes(),
            ]),
            Self::SourcePrefs {
                tenant_id,
                lookup_tag,
                prefs_version,
            } => concat(&[
                labels::SOURCE_PREFS,
                tenant_id,
                lookup_tag,
                &prefs_version.to_be_bytes(),
            ]),
            Self::DeskKeystore {
                user_id,
                device_id,
                key_id,
            } => concat(&[labels::DESK_KEYSTORE, user_id, device_id, key_id]),
            Self::DeskKeystoreSlot {
                user_id,
                device_id,
                slot,
            } => concat(&[labels::DESK_KEYSTORE_SLOT, user_id, device_id, &[*slot]]),
            Self::DeskCaseKeyCache {
                user_id,
                device_id,
                case_id,
                version,
            } => concat(&[
                labels::DESK_CASE_KEY_CACHE,
                user_id,
                device_id,
                case_id,
                &version.to_be_bytes(),
            ]),
            Self::EkMeta {
                tenant_id,
                case_id,
                column_id,
                row_version,
            } => concat(&[
                labels::EK_META,
                tenant_id,
                case_id,
                &column_id.to_be_bytes(),
                &row_version.to_be_bytes(),
            ]),
        }
    }
}

/// Encrypt a record under `key` (version `key_version`).
pub fn seal_record(
    key: &AeadKey,
    key_version: u32,
    aad: &RecordAad,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    seal_record_with(&mut OsRandom, key, key_version, aad, plaintext)
}

pub(crate) fn seal_record_with(
    rng: &mut dyn RandomSource,
    key: &AeadKey,
    key_version: u32,
    aad: &RecordAad,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 24];
    rng.fill(&mut nonce)?;
    let ct = xchacha_seal(key, &nonce, &aad.bytes(key_version), plaintext)?;
    Ok(concat(&[
        &[RECORD_VERSION],
        &Suite::CandorStd1.to_be_bytes(),
        &key_version.to_be_bytes(),
        &nonce,
        &ct,
    ]))
}

/// Parsed record header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    /// Suite.
    pub suite: Suite,
    /// Key version (selects the key; authenticated for `Case` records via AAD).
    pub key_version: u32,
}

fn parse(record: &[u8]) -> Result<(RecordHeader, [u8; 24], &[u8])> {
    let mut r = Reader::new(record);
    if r.u8()? != RECORD_VERSION {
        return Err(Error::Malformed("record version"));
    }
    let suite = Suite::from_id_supported(r.u16()?)?;
    let key_version = r.u32()?;
    let nonce = r.array::<24>()?;
    let ct = r.rest();
    if ct.len() < AEAD_TAG_LEN {
        return Err(Error::Length);
    }
    Ok((RecordHeader { suite, key_version }, nonce, ct))
}

/// Read the record header (to select the key version) without decrypting.
pub fn record_header(record: &[u8]) -> Result<RecordHeader> {
    parse(record).map(|(h, _, _)| h)
}

/// Decrypt a record. The caller supplies the expected context (including the
/// current `row_version` from the case event chain, CRYPTO-054).
pub fn open_record(key: &AeadKey, aad: &RecordAad, record: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let (h, nonce, ct) = parse(record)?;
    xchacha_open(key, &nonce, &aad.bytes(h.key_version), ct)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use crate::kdf::derive_case_record_key;
    use crate::rand::TestRng;
    use crate::secret::CaseKey;

    fn aad(row_version: u64) -> RecordAad {
        RecordAad::Case {
            tenant_id: [1; 16],
            case_id: [2; 16],
            table_id: 3,
            column_id: 4,
            record_id: [5; 16],
            row_version,
        }
    }

    #[test]
    fn roundtrip_and_binding() {
        let mut rng = TestRng::new(30);
        let k = derive_case_record_key(&CaseKey::from_bytes([9; 32]), 3).unwrap();
        let rec = seal_record_with(&mut rng, &k, 7, &aad(1), b"title").unwrap();
        assert_eq!(rec.len(), RECORD_HEADER_LEN + 5 + 16);
        assert_eq!(
            record_header(&rec).unwrap(),
            RecordHeader {
                suite: Suite::CandorStd1,
                key_version: 7
            }
        );
        assert_eq!(open_record(&k, &aad(1), &rec).unwrap().as_slice(), b"title");
        // CRYPTO-054: stale row replay (row_version mismatch) fails.
        assert!(open_record(&k, &aad(2), &rec).is_err());
        // CRYPTO-011: row moved to another case/tenant fails.
        let moved = RecordAad::Case {
            tenant_id: [1; 16],
            case_id: [9; 16],
            table_id: 3,
            column_id: 4,
            record_id: [5; 16],
            row_version: 1,
        };
        assert!(open_record(&k, &moved, &rec).is_err());
        // key_version is authenticated for case records.
        let mut b = rec.clone();
        b[6] ^= 1;
        assert!(open_record(&k, &aad(1), &b).is_err());
        // Malformed headers.
        let mut b = rec.clone();
        b[0] = 2;
        assert!(open_record(&k, &aad(1), &b).is_err());
        let mut b = rec.clone();
        b[2] = 2;
        assert_eq!(
            open_record(&k, &aad(1), &b).err(),
            Some(Error::UnsupportedSuite)
        );
        assert!(open_record(&k, &aad(1), &rec[..RECORD_HEADER_LEN + 15]).is_err());
    }

    #[test]
    fn other_aad_forms_are_distinct() {
        let mut rng = TestRng::new(31);
        let k = AeadKey::from_bytes([1; 32]);
        let a = RecordAad::DeskKeystoreSlot {
            user_id: [1; 16],
            device_id: [2; 16],
            slot: 0,
        };
        let b = RecordAad::DeskKeystoreSlot {
            user_id: [1; 16],
            device_id: [2; 16],
            slot: 1,
        };
        let rec = seal_record_with(&mut rng, &k, 0, &a, b"k11").unwrap();
        assert!(open_record(&k, &a, &rec).is_ok());
        assert!(open_record(&k, &b, &rec).is_err());
        let p = RecordAad::SourcePrefs {
            tenant_id: [1; 16],
            lookup_tag: [2; 32],
            prefs_version: 1,
        };
        let rec = seal_record_with(&mut rng, &k, 0, &p, b"prefs").unwrap();
        assert!(open_record(&k, &p, &rec).is_ok());
    }

    proptest::proptest! {
        #[test]
        fn open_arbitrary_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..100)) {
            proptest::prop_assert!(open_record(&AeadKey::from_bytes([0; 32]), &aad(0), &bytes).is_err());
        }
    }
}
