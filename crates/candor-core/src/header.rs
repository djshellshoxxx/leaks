// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Sealed Object CoreHeader (§13.1): 128-byte encode/decode/validate, `header_mac`,
//! `object_hash`.

use crate::bytes::Reader;
use crate::error::{Error, Result};
use crate::hash::sha256;
use crate::kdf::{ct_eq, derive_header_mac_key, hmac_sha256};
use crate::padding::is_legal_bucket;
use crate::secret::ContentKey;
use crate::stream;
use crate::suite::Suite;

/// CoreHeader length.
pub const HEADER_LEN: usize = 128;
/// Magic "CNDR".
pub const MAGIC: [u8; 4] = *b"CNDR";
/// Current format version.
pub const FORMAT_VERSION: u8 = 0x01;
/// STREAM chunk size log2 (64 KiB).
pub const CHUNK_SIZE_LOG2: u8 = 16;
/// `header_mac` length for CANDOR-STD-1.
pub const HEADER_MAC_LEN: usize = 32;

/// Object types (§13.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ObjectType {
    /// SUBMISSION.
    Submission = 0x01,
    /// ATTACHMENT_BUNDLE.
    AttachmentBundle = 0x02,
    /// IDENTITY.
    Identity = 0x03,
    /// REPLY.
    Reply = 0x04,
    /// SOURCE_MESSAGE.
    SourceMessage = 0x05,
    /// CASE_ATTACHMENT.
    CaseAttachment = 0x06,
    /// EXPORT_PACKAGE.
    ExportPackage = 0x07,
    /// CASE_DOCUMENT.
    CaseDocument = 0x08,
}

impl ObjectType {
    /// Parse; unknown values are rejected (§13.9).
    pub fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0x01 => Self::Submission,
            0x02 => Self::AttachmentBundle,
            0x03 => Self::Identity,
            0x04 => Self::Reply,
            0x05 => Self::SourceMessage,
            0x06 => Self::CaseAttachment,
            0x07 => Self::ExportPackage,
            0x08 => Self::CaseDocument,
            _ => return Err(Error::Malformed("object_type")),
        })
    }

    /// Intake-sealed objects carry a RecipientSlotBlock (§13.2). They are also exactly
    /// the source-originated objects (day_stamp = 0, ADR-010).
    #[must_use]
    pub fn is_intake_sealed(self) -> bool {
        matches!(
            self,
            Self::Submission | Self::AttachmentBundle | Self::Identity | Self::SourceMessage
        )
    }

    /// Types whose `channel_id` must be all-zero (§13.1, §13.5).
    #[must_use]
    pub fn requires_zero_channel(self) -> bool {
        matches!(
            self,
            Self::CaseAttachment | Self::CaseDocument | Self::ExportPackage | Self::Reply
        )
    }
}

/// Parsed and validated CoreHeader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreHeader {
    /// Object type.
    pub object_type: ObjectType,
    /// Suite.
    pub suite: Suite,
    /// Tenant id.
    pub tenant_id: [u8; 16],
    /// Channel id (zero for CASE_*, EXPORT_PACKAGE, REPLY).
    pub channel_id: [u8; 16],
    /// Member epoch id (0 unless sealed to Member Epoch Keys).
    pub epoch_id: u32,
    /// `H(RecipientSlotBlock)` for intake-sealed objects, else zero.
    pub slot_block_hash: [u8; 32],
    /// Random object id.
    pub object_id: [u8; 16],
    /// UTC day number for staff objects; 0 for source objects and REPLY.
    pub day_stamp: u32,
    /// Padded plaintext length (a legal bucket).
    pub padded_plaintext_len: u64,
    /// STREAM payload nonce.
    pub payload_nonce: [u8; 16],
}

impl CoreHeader {
    /// Semantic validation shared by encoder and decoder (§13.1, CRYPTO-016/018).
    ///
    /// Implementation decisions (SPEC-NOTES): `slot_block_hash` must be non-zero for
    /// intake-sealed types and zero otherwise; `epoch_id` must be 0 for every type
    /// that is not sealed to Member Epoch Keys (REPLY, IDENTITY, staff objects).
    pub fn validate(&self) -> Result<()> {
        self.suite.require_supported()?;
        let t = self.object_type;
        if !is_legal_bucket(t, self.padded_plaintext_len) {
            return Err(Error::IllegalBucket);
        }
        if t.requires_zero_channel() && self.channel_id != [0u8; 16] {
            return Err(Error::Malformed("channel_id must be zero"));
        }
        let zero_hash = self.slot_block_hash == [0u8; 32];
        if t.is_intake_sealed() == zero_hash {
            return Err(Error::Malformed("slot_block_hash"));
        }
        if (t.is_intake_sealed() || t == ObjectType::Reply) && self.day_stamp != 0 {
            return Err(Error::Malformed("day_stamp must be zero"));
        }
        let mek_sealed = matches!(
            t,
            ObjectType::Submission | ObjectType::AttachmentBundle | ObjectType::SourceMessage
        );
        if !mek_sealed && self.epoch_id != 0 {
            return Err(Error::Malformed("epoch_id must be zero"));
        }
        Ok(())
    }

    /// Encode to 128 bytes (validates first; never emits an invalid header).
    pub fn encode(&self) -> Result<[u8; HEADER_LEN]> {
        self.validate()?;
        let mut v = Vec::with_capacity(HEADER_LEN);
        v.extend_from_slice(&MAGIC);
        v.push(FORMAT_VERSION);
        v.push(self.object_type as u8);
        v.extend_from_slice(&self.suite.to_be_bytes());
        v.extend_from_slice(&[0, 0]); // flags
        v.extend_from_slice(&[0, 0]); // reserved
        v.extend_from_slice(&self.tenant_id);
        v.extend_from_slice(&self.channel_id);
        v.extend_from_slice(&self.epoch_id.to_be_bytes());
        v.extend_from_slice(&self.slot_block_hash);
        v.extend_from_slice(&self.object_id);
        v.extend_from_slice(&self.day_stamp.to_be_bytes());
        v.push(CHUNK_SIZE_LOG2);
        v.extend_from_slice(&[0, 0, 0]);
        v.extend_from_slice(&self.padded_plaintext_len.to_be_bytes());
        v.extend_from_slice(&self.payload_nonce);
        v.try_into().map_err(|_| Error::Internal)
    }

    /// Decode and validate exactly 128 bytes (CRYPTO-018, CRYPTO-047).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HEADER_LEN {
            return Err(Error::Length);
        }
        let mut r = Reader::new(bytes);
        if r.array::<4>()? != MAGIC {
            return Err(Error::Malformed("magic"));
        }
        if r.u8()? != FORMAT_VERSION {
            return Err(Error::Malformed("format_version"));
        }
        let object_type = ObjectType::from_u8(r.u8()?)?;
        let suite = Suite::from_id(r.u16()?)?;
        if r.u16()? != 0 {
            return Err(Error::Malformed("flags"));
        }
        if r.u16()? != 0 {
            return Err(Error::Malformed("reserved"));
        }
        let tenant_id = r.array()?;
        let channel_id = r.array()?;
        let epoch_id = r.u32()?;
        let slot_block_hash = r.array()?;
        let object_id = r.array()?;
        let day_stamp = r.u32()?;
        if r.u8()? != CHUNK_SIZE_LOG2 {
            return Err(Error::Malformed("chunk_size_log2"));
        }
        if r.array::<3>()? != [0, 0, 0] {
            return Err(Error::Malformed("reserved"));
        }
        let padded_plaintext_len = r.u64()?;
        let payload_nonce = r.array()?;
        r.finish()?;
        let h = Self {
            object_type,
            suite,
            tenant_id,
            channel_id,
            epoch_id,
            slot_block_hash,
            object_id,
            day_stamp,
            padded_plaintext_len,
            payload_nonce,
        };
        h.validate()?;
        Ok(h)
    }

    /// Exact STREAM payload length implied by the header (§13.3).
    pub fn expected_payload_len(&self) -> Result<u64> {
        stream::ciphertext_len(self.padded_plaintext_len)
    }

    /// `header_mac = HMAC(K_mac, CoreHeader)` (§13.1).
    pub fn header_mac(&self, ck: &ContentKey) -> Result<[u8; HEADER_MAC_LEN]> {
        let enc = self.encode()?;
        let k = derive_header_mac_key(self.suite, ck, &self.object_id)?;
        hmac_sha256(k.expose(), &[&enc])
    }

    /// Verify `header_mac` in constant time (CRYPTO-008).
    pub fn verify_header_mac(&self, ck: &ContentKey, mac: &[u8]) -> Result<()> {
        let expected = self.header_mac(ck)?;
        if ct_eq(&expected, mac) {
            Ok(())
        } else {
            Err(Error::Authentication)
        }
    }
}

/// `object_hash = H(CoreHeader ‖ header_mac)` (§13.1).
#[must_use]
pub fn object_hash(header: &[u8; HEADER_LEN], header_mac: &[u8; HEADER_MAC_LEN]) -> [u8; 32] {
    sha256(&[header, header_mac])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    pub(crate) fn sample() -> CoreHeader {
        CoreHeader {
            object_type: ObjectType::Submission,
            suite: Suite::CandorStd1,
            tenant_id: [1; 16],
            channel_id: [2; 16],
            epoch_id: 7,
            slot_block_hash: [3; 32],
            object_id: [4; 16],
            day_stamp: 0,
            padded_plaintext_len: 8192,
            payload_nonce: [5; 16],
        }
    }

    #[test]
    fn roundtrip() {
        let h = sample();
        let e = h.encode().unwrap();
        assert_eq!(&e[..4], b"CNDR");
        assert_eq!(e[100], 16);
        assert_eq!(CoreHeader::decode(&e).unwrap(), h);
    }

    /// CRYPTO-018 / CRYPTO-047 negative vectors per field.
    #[test]
    fn rejects_bad_fields() {
        let e = sample().encode().unwrap();
        let cases: &[(usize, u8)] = &[
            (0, b'X'),
            (4, 2),
            (4, 0),
            (5, 0),
            (5, 9),
            (7, 3),
            (8, 1),
            (9, 1),
            (10, 1),
            (11, 1),
            (100, 15),
            (101, 1),
            (103, 1),
        ];
        for (off, val) in cases {
            let mut b = e;
            b[*off] = *val;
            assert!(CoreHeader::decode(&b).is_err(), "offset {off}");
        }
        // FIPS suite id: recognised but unsupported.
        let mut b = e;
        b[7] = 2;
        assert_eq!(CoreHeader::decode(&b).err(), Some(Error::UnsupportedSuite));
        assert_eq!(CoreHeader::decode(&e[..127]).err(), Some(Error::Length));
        let mut long = e.to_vec();
        long.push(0);
        assert_eq!(CoreHeader::decode(&long).err(), Some(Error::Length));
    }

    #[test]
    fn semantic_rules() {
        let mut h = sample();
        h.padded_plaintext_len = 5000;
        assert_eq!(h.encode().err(), Some(Error::IllegalBucket));
        let mut h = sample();
        h.day_stamp = 1; // CRYPTO-016
        assert!(h.encode().is_err());
        let mut h = sample();
        h.slot_block_hash = [0; 32];
        assert!(h.encode().is_err());
        let mut h = sample();
        h.object_type = ObjectType::Reply;
        assert!(h.encode().is_err(), "REPLY needs zero channel/hash/epoch");
        h.channel_id = [0; 16];
        h.slot_block_hash = [0; 32];
        h.epoch_id = 0;
        assert!(h.encode().is_ok());
        h.day_stamp = 20_000;
        assert!(h.encode().is_err());
        let mut h = sample();
        h.object_type = ObjectType::CaseDocument;
        h.channel_id = [0; 16];
        h.slot_block_hash = [0; 32];
        h.epoch_id = 0;
        h.day_stamp = 20_000;
        h.padded_plaintext_len = 262_144;
        assert!(h.encode().is_ok());
    }

    #[test]
    fn mac_verifies_and_binds() {
        let h = sample();
        let ck = ContentKey::from_bytes([9; 32]);
        let mac = h.header_mac(&ck).unwrap();
        assert!(h.verify_header_mac(&ck, &mac).is_ok());
        let ck2 = ContentKey::from_bytes([8; 32]);
        assert_eq!(
            h.verify_header_mac(&ck2, &mac).err(),
            Some(Error::Authentication)
        );
        let mut h2 = h.clone();
        h2.slot_block_hash[0] ^= 1;
        assert_eq!(
            h2.verify_header_mac(&ck, &mac).err(),
            Some(Error::Authentication)
        );
        assert!(h.verify_header_mac(&ck, &mac[..31]).is_err());
    }

    proptest::proptest! {
        /// ST-040: decoder never panics on arbitrary input; encode∘decode = id on success.
        #[test]
        fn decode_arbitrary(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..200)) {
            if let Ok(h) = CoreHeader::decode(&bytes) {
                proptest::prop_assert_eq!(h.encode().unwrap().to_vec(), bytes);
            }
        }
    }
}
