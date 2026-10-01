// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Sealed Object assembly and opening (§13.1–§13.3):
//! `SealedObject = CoreHeader (128 B) ‖ header_mac (32 B) ‖ Payload (STREAM)`.
//!
//! Opening order (CRYPTO-008/018): validate header → check exact total length →
//! verify `header_mac` in constant time → only then decrypt the payload.

use crate::error::{Error, Result};
use crate::header::{CoreHeader, HEADER_LEN, HEADER_MAC_LEN, ObjectType, object_hash};
use crate::kdf::derive_payload_key;
use crate::kem::KemPublicKey;
use crate::rand::{OsRandom, RandomSource};
use crate::secret::ContentKey;
use crate::slots::{RecipientListEntry, RecipientSlotBlock, SlotBinding, SlotContext};
use crate::stream::{self, StreamDecryptor};
use crate::suite::Suite;
use zeroize::Zeroizing;

/// Parameters for sealing one object.
#[derive(Debug)]
pub struct SealRequest<'a> {
    /// Suite.
    pub suite: Suite,
    /// Object type.
    pub object_type: ObjectType,
    /// Tenant.
    pub tenant_id: [u8; 16],
    /// Channel (zero where §13.1 requires).
    pub channel_id: [u8; 16],
    /// Epoch (0 unless sealed to Member Epoch Keys).
    pub epoch_id: u32,
    /// Day stamp (0 for source objects and REPLY).
    pub day_stamp: u32,
    /// Slot context and recipients; required exactly for intake-sealed types.
    pub recipients: Option<(SlotContext, &'a [KemPublicKey])>,
    /// Padded plaintext length (a legal bucket for the type, §13.6).
    pub padded_len: u64,
}

/// What the payload builder sees: the final CoreHeader (for `H(CoreHeader)` in
/// `source_sig`/`sealer_sig`, §13.4) and the Recipient List entries (ADR-050(3)) that
/// must be embedded in the signed Recipient List inside the payload.
#[derive(Debug)]
pub struct PayloadContext<'a> {
    /// Final header.
    pub header: &'a CoreHeader,
    /// Encoded header (128 bytes).
    pub header_bytes: &'a [u8; HEADER_LEN],
    /// Recipient List entries, in the order of `SealRequest::recipients` (empty for
    /// non-intake objects).
    pub recipient_list: &'a [RecipientListEntry],
}

/// A sealed object.
#[derive(Debug, Clone)]
pub struct SealedObject {
    /// Header.
    pub header: CoreHeader,
    /// `header_mac`.
    pub header_mac: [u8; HEADER_MAC_LEN],
    /// `object_hash = H(CoreHeader ‖ header_mac)`.
    pub object_hash: [u8; 32],
    /// The slot block (intake-sealed objects only); stored alongside the blob.
    pub slot_block: Option<RecipientSlotBlock>,
    /// Recipient List entries that were handed to the payload builder.
    pub recipient_list: Vec<RecipientListEntry>,
    /// Blob bytes: `CoreHeader ‖ header_mac ‖ Payload`.
    pub bytes: Vec<u8>,
}

/// Seal with a fresh random CK. `build` returns the padded plaintext (exactly
/// `padded_len` bytes) once the header and Recipient List are known. Returns the CK
/// (for stanzas) and the object.
pub fn seal<F, P>(req: &SealRequest<'_>, build: F) -> Result<(ContentKey, SealedObject)>
where
    F: FnOnce(&PayloadContext<'_>) -> Result<P>,
    P: AsRef<[u8]>,
{
    let mut rng = OsRandom;
    let ck = ContentKey::generate_with(&mut rng)?;
    let obj = seal_with_ck_rng(&mut rng, &ck, req, build)?;
    Ok((ck, obj))
}

/// Seal with a caller-supplied CK (e.g. chaff CK derived per §12.7).
pub fn seal_with_ck<F, P>(ck: &ContentKey, req: &SealRequest<'_>, build: F) -> Result<SealedObject>
where
    F: FnOnce(&PayloadContext<'_>) -> Result<P>,
    P: AsRef<[u8]>,
{
    seal_with_ck_rng(&mut OsRandom, ck, req, build)
}

/// Convenience for objects without recipient slots (REPLY, CASE_*, EXPORT_PACKAGE):
/// seal a ready padded plaintext. Intake-sealed types are refused because their
/// payload must embed the Recipient List (use [`seal`]).
pub fn seal_bytes(req: &SealRequest<'_>, padded_plaintext: &[u8]) -> Result<(ContentKey, SealedObject)> {
    if req.object_type.is_intake_sealed() {
        return Err(Error::Malformed("intake objects must embed the Recipient List"));
    }
    seal(req, |_| Ok(padded_plaintext))
}

pub(crate) fn seal_with_ck_rng<F, P>(
    rng: &mut dyn RandomSource,
    ck: &ContentKey,
    req: &SealRequest<'_>,
    build: F,
) -> Result<SealedObject>
where
    F: FnOnce(&PayloadContext<'_>) -> Result<P>,
    P: AsRef<[u8]>,
{
    req.suite.require_supported()?;
    let mut object_id = [0u8; 16];
    rng.fill(&mut object_id)?;
    let mut payload_nonce = [0u8; 16];
    rng.fill(&mut payload_nonce)?;
    let (slot_block, recipient_list) = match (req.object_type.is_intake_sealed(), &req.recipients) {
        (true, Some((ctx, pks))) => {
            let b = SlotBinding {
                suite: req.suite,
                object_id,
                payload_nonce,
                context: ctx.clone(),
            };
            let (blk, list) = RecipientSlotBlock::build_with(rng, ck, &b, pks)?;
            (Some(blk), list)
        }
        (false, None) => (None, Vec::new()),
        _ => {
            return Err(Error::Malformed(
                "recipients required exactly for intake-sealed objects",
            ));
        }
    };
    let header = CoreHeader {
        object_type: req.object_type,
        suite: req.suite,
        tenant_id: req.tenant_id,
        channel_id: req.channel_id,
        epoch_id: req.epoch_id,
        slot_block_hash: slot_block
            .as_ref()
            .map_or([0u8; 32], RecipientSlotBlock::hash),
        object_id,
        day_stamp: req.day_stamp,
        padded_plaintext_len: req.padded_len,
        payload_nonce,
    };
    let header_bytes = header.encode()?;
    let padded = build(&PayloadContext {
        header: &header,
        header_bytes: &header_bytes,
        recipient_list: &recipient_list,
    })?;
    let padded = padded.as_ref();
    if u64::try_from(padded.len()).ok() != Some(req.padded_len) {
        return Err(Error::Length);
    }
    let header_mac = header.header_mac(ck)?;
    let k_pay = derive_payload_key(req.suite, ck, &payload_nonce)?;
    let payload = stream::encrypt(k_pay, padded)?;
    let mut bytes = Vec::with_capacity(
        HEADER_LEN
            .saturating_add(HEADER_MAC_LEN)
            .saturating_add(payload.len()),
    );
    bytes.extend_from_slice(&header_bytes);
    bytes.extend_from_slice(&header_mac);
    bytes.extend_from_slice(&payload);
    Ok(SealedObject {
        object_hash: object_hash(&header_bytes, &header_mac),
        header,
        header_mac,
        slot_block,
        recipient_list,
        bytes,
    })
}

/// A structurally validated (not yet authenticated) sealed object.
#[derive(Debug)]
pub struct ParsedObject<'a> {
    /// Header (validated, unauthenticated until `header_mac` is checked).
    pub header: CoreHeader,
    header_bytes: [u8; HEADER_LEN],
    header_mac: [u8; HEADER_MAC_LEN],
    payload: &'a [u8],
}

/// Parse a blob: header validation and exact length check before any decryption
/// (CRYPTO-018, CRYPTO-053).
pub fn parse(bytes: &[u8]) -> Result<ParsedObject<'_>> {
    let (hb, rest) = bytes.split_at_checked(HEADER_LEN).ok_or(Error::Length)?;
    let header = CoreHeader::decode(hb)?;
    let (mac, payload) = rest.split_at_checked(HEADER_MAC_LEN).ok_or(Error::Length)?;
    if u64::try_from(payload.len()).ok() != Some(header.expected_payload_len()?) {
        return Err(Error::Length);
    }
    Ok(ParsedObject {
        header_bytes: hb.try_into().map_err(|_| Error::Length)?,
        header_mac: mac.try_into().map_err(|_| Error::Length)?,
        header,
        payload,
    })
}

impl ParsedObject<'_> {
    /// `object_hash` (the value stanzas bind to).
    #[must_use]
    pub fn object_hash(&self) -> [u8; 32] {
        object_hash(&self.header_bytes, &self.header_mac)
    }

    /// The slot binding of this object for a given slot context.
    #[must_use]
    pub fn slot_binding(&self, context: SlotContext) -> SlotBinding {
        SlotBinding {
            suite: self.header.suite,
            object_id: self.header.object_id,
            payload_nonce: self.header.payload_nonce,
            context,
        }
    }

    /// Check that a slot block is the one committed in the header.
    pub fn check_slot_block(&self, block: &RecipientSlotBlock) -> Result<()> {
        if self.header.object_type.is_intake_sealed()
            && crate::kdf::ct_eq(&block.hash(), &self.header.slot_block_hash)
        {
            Ok(())
        } else {
            Err(Error::SlotVerification)
        }
    }

    /// Verify `header_mac` under `ck` (constant time).
    pub fn verify(&self, ck: &ContentKey) -> Result<()> {
        self.header.verify_header_mac(ck, &self.header_mac)
    }

    /// Verify the header MAC, then decrypt the whole payload (buffered: nothing is
    /// returned unless every chunk including the final one verifies).
    pub fn open(&self, ck: &ContentKey) -> Result<Zeroizing<Vec<u8>>> {
        self.verify(ck)?;
        let k = derive_payload_key(self.header.suite, ck, &self.header.payload_nonce)?;
        stream::decrypt(k, self.header.padded_plaintext_len, self.payload)
    }

    /// Verify the header MAC, then return a chunk decryptor and the payload bytes.
    pub fn open_stream(&self, ck: &ContentKey) -> Result<(StreamDecryptor, &[u8])> {
        self.verify(ck)?;
        let k = derive_payload_key(self.header.suite, ck, &self.header.payload_nonce)?;
        Ok((
            StreamDecryptor::new(k, self.header.padded_plaintext_len),
            self.payload,
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use crate::kem::KemKeyPair;
    use crate::padding::pad;
    use crate::rand::TestRng;

    #[test]
    fn submission_end_to_end() {
        let mut rng = TestRng::new(50);
        let m = KemKeyPair::generate_with(Suite::CandorStd1, &mut rng).unwrap();
        let ctx = SlotContext::MemberEpoch {
            tenant_id: [1; 16],
            channel_id: [2; 16],
            epoch_id: 3,
        };
        let pt = pad(ObjectType::Submission, b"hello").unwrap();
        let ck = ContentKey::generate_with(&mut rng).unwrap();
        let req = SealRequest {
            suite: Suite::CandorStd1,
            object_type: ObjectType::Submission,
            tenant_id: [1; 16],
            channel_id: [2; 16],
            epoch_id: 3,
            day_stamp: 0,
            recipients: Some((ctx.clone(), core::slice::from_ref(&m.public))),
            padded_len: pt.len() as u64,
        };
        let mut seen = Vec::new();
        let obj = seal_with_ck_rng(&mut rng, &ck, &req, |pc| {
            seen = pc.recipient_list.to_vec();
            assert_eq!(pc.header.padded_plaintext_len, pt.len() as u64);
            Ok(pt.clone())
        })
        .unwrap();
        assert_eq!(seen, obj.recipient_list);
        assert_eq!(seen.len(), 1);
        let p = parse(&obj.bytes).unwrap();
        assert_eq!(p.object_hash(), obj.object_hash);
        let blk = obj.slot_block.as_ref().unwrap();
        p.check_slot_block(blk).unwrap();
        let (ck2, pos) = blk
            .trial_open(&m.private, &p.slot_binding(ctx.clone()))
            .unwrap();
        assert_eq!(usize::from(obj.recipient_list[0].slot_index), pos);
        let dir = |kid: &[u8; 32]| {
            (crate::hash::key_id(Suite::CandorStd1, crate::hash::KeyKind::Mek, &m.public.to_bytes()) == *kid)
                .then(|| m.public.clone())
        };
        blk.verify_slot_block(&ck2, &p.slot_binding(ctx), &obj.recipient_list, dir)
            .unwrap();
        assert_eq!(p.open(&ck2).unwrap().as_slice(), pt.as_slice());

        // Salamander / wrong key: header commitment rejects before payload decryption.
        let other = ContentKey::from_bytes([0xEE; 32]);
        assert_eq!(p.open(&other).err(), Some(Error::Authentication));
        // Exact length enforced before decryption.
        assert_eq!(
            parse(&obj.bytes[..obj.bytes.len() - 1]).err(),
            Some(Error::Length)
        );
        let mut long = obj.bytes.clone();
        long.push(0);
        assert_eq!(parse(&long).err(), Some(Error::Length));
        // Header tamper ⇒ MAC failure (e.g. epoch changed).
        let mut t = obj.bytes.clone();
        t[47] ^= 1;
        assert_eq!(
            parse(&t).unwrap().open(&ck).err(),
            Some(Error::Authentication)
        );
        // Tampered slot_block_hash detected against the stored block.
        let mut t = obj.bytes.clone();
        t[48] ^= 1;
        assert!(parse(&t).unwrap().check_slot_block(blk).is_err());
        // Payload tamper ⇒ stream failure.
        let mut t = obj.bytes.clone();
        let l = t.len() - 1;
        t[l] ^= 1;
        assert!(parse(&t).unwrap().open(&ck).is_err());
    }

    #[test]
    fn reply_has_no_slots() {
        let pt = pad(ObjectType::Reply, b"r").unwrap();
        let req = SealRequest {
            suite: Suite::CandorStd1,
            object_type: ObjectType::Reply,
            tenant_id: [1; 16],
            channel_id: [0; 16],
            epoch_id: 0,
            day_stamp: 0,
            recipients: None,
            padded_len: pt.len() as u64,
        };
        let (ck, obj) = seal_bytes(&req, &pt).unwrap();
        assert!(obj.slot_block.is_none());
        assert_eq!(obj.bytes.len(), 128 + 32 + 4096 + 16);
        assert_eq!(parse(&obj.bytes).unwrap().open(&ck).unwrap().len(), 4096);
        let bad = SealRequest {
            padded_len: 100,
            ..req
        };
        assert_eq!(seal_bytes(&bad, &pt[..100]).err(), Some(Error::IllegalBucket));
        // Builder output must match the declared length.
        let req2 = SealRequest { padded_len: 4096, ..bad };
        assert_eq!(seal_bytes(&req2, &pt[..100]).err(), Some(Error::Length));
    }

    #[test]
    fn streaming_open() {
        let pt = pad(ObjectType::CaseDocument, &[7u8; 300_000]).unwrap();
        let req = SealRequest {
            suite: Suite::CandorStd1,
            object_type: ObjectType::CaseDocument,
            tenant_id: [1; 16],
            channel_id: [0; 16],
            epoch_id: 0,
            day_stamp: 20_000,
            recipients: None,
            padded_len: pt.len() as u64,
        };
        let (ck, obj) = seal_bytes(&req, &pt).unwrap();
        let p = parse(&obj.bytes).unwrap();
        let (dec, payload) = p.open_stream(&ck).unwrap();
        let mut rd = dec.reader(payload);
        let mut out = Vec::new();
        for c in rd.by_ref() {
            out.extend_from_slice(&c.unwrap());
        }
        rd.finish().unwrap();
        assert_eq!(out, pt.as_slice());
    }
}
