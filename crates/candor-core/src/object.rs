// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Sealed Object assembly and opening (§13.1–§13.3):
//! `SealedObject = CoreHeader (128 B) ‖ header_mac (32 B) ‖ Payload (STREAM)`.
//!
//! Opening order (CRYPTO-008/018): validate header → check exact total length →
//! verify `header_mac` in constant time → only then decrypt the payload.

use crate::error::{Error, Result};
use crate::header::{CoreHeader, HEADER_LEN, HEADER_MAC_LEN, ObjectType, object_hash};
use crate::kem::KemPublicKey;
use crate::rand::{OsRandom, RandomSource};
use crate::secret::ContentKey;
use crate::slots::{
    RecipientList, RecipientListEntry, RecipientSlotBlock, SlotBinding, SlotContext,
};
use crate::stream::{self, StreamDecryptor, StreamEncryptor};
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

/// A sealed object: public data only (AUD-RM1-CORE-01). The Recipient List entries,
/// which are CK-equivalent, are returned separately ([`SealSecrets`]) and are never
/// part of this value.
#[derive(Clone)]
pub struct SealedObject {
    /// Header.
    pub header: CoreHeader,
    /// `header_mac`.
    pub header_mac: [u8; HEADER_MAC_LEN],
    /// `object_hash = H(CoreHeader ‖ header_mac)`.
    pub object_hash: [u8; 32],
    /// The slot block (intake-sealed objects only); stored alongside the blob.
    pub slot_block: Option<RecipientSlotBlock>,
    /// Blob bytes: `CoreHeader ‖ header_mac ‖ Payload`.
    pub bytes: Vec<u8>,
}

impl core::fmt::Debug for SealedObject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // AUD-RM1-CORE-11: type and sizes only (no ids, hashes or ciphertext).
        f.debug_struct("SealedObject")
            .field("object_type", &self.header.object_type)
            .field("len", &self.bytes.len())
            .field("has_slot_block", &self.slot_block.is_some())
            .finish_non_exhaustive()
    }
}

/// The secrets produced by [`seal`]: the fresh CK and the Recipient List entries
/// (empty for non-intake objects). Not `Clone`; zeroized on drop; redacted `Debug`.
pub struct SealSecrets {
    ck: ContentKey,
    recipient_list: RecipientList,
}

impl core::fmt::Debug for SealSecrets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SealSecrets(<redacted>)")
    }
}

impl SealSecrets {
    /// The content key (for wrap stanzas).
    #[must_use]
    pub fn ck(&self) -> &ContentKey {
        &self.ck
    }

    /// The Recipient List entries (for embedding in another object's encrypted
    /// Recipient List, e.g. the IDENTITY entries inside a SUBMISSION).
    #[must_use]
    pub fn recipient_list(&self) -> &RecipientList {
        &self.recipient_list
    }

    /// Split into CK and entries.
    #[must_use]
    pub fn into_parts(self) -> (ContentKey, RecipientList) {
        (self.ck, self.recipient_list)
    }
}

/// Seal with a fresh random CK. `build` returns the padded plaintext (exactly
/// `padded_len` bytes) once the header and Recipient List are known. Returns the
/// secrets (CK for stanzas, Recipient List entries) and the public object.
pub fn seal<F, P>(req: &SealRequest<'_>, build: F) -> Result<(SealSecrets, SealedObject)>
where
    F: FnOnce(&PayloadContext<'_>) -> Result<P>,
    P: AsRef<[u8]>,
{
    let mut rng = OsRandom;
    let ck = ContentKey::generate_with(&mut rng)?;
    let (recipient_list, obj) = seal_with_ck_rng(&mut rng, &ck, req, build)?;
    Ok((SealSecrets { ck, recipient_list }, obj))
}

/// Seal with a caller-supplied CK (e.g. chaff CK derived per §12.7). Returns the
/// Recipient List entries (secret, see [`RecipientListEntry`]) and the object.
pub fn seal_with_ck<F, P>(
    ck: &ContentKey,
    req: &SealRequest<'_>,
    build: F,
) -> Result<(RecipientList, SealedObject)>
where
    F: FnOnce(&PayloadContext<'_>) -> Result<P>,
    P: AsRef<[u8]>,
{
    seal_with_ck_rng(&mut OsRandom, ck, req, build)
}

/// Convenience for objects without recipient slots (REPLY, CASE_*, EXPORT_PACKAGE):
/// seal a ready padded plaintext. Intake-sealed types are refused because their
/// payload must embed the Recipient List (use [`seal`]).
pub fn seal_bytes(
    req: &SealRequest<'_>,
    padded_plaintext: &[u8],
) -> Result<(ContentKey, SealedObject)> {
    if req.object_type.is_intake_sealed() {
        return Err(Error::Malformed(
            "intake objects must embed the Recipient List",
        ));
    }
    let (secrets, obj) = seal(req, |_| Ok(padded_plaintext))?;
    let (ck, _empty) = secrets.into_parts();
    Ok((ck, obj))
}

/// AUD-RM1-CORE-09(b): the slot context must match the object type
/// (IDENTITY ⇔ custodian) and the header fields it duplicates.
fn check_context(req: &SealRequest<'_>, ctx: &SlotContext) -> Result<()> {
    let ok = match ctx {
        SlotContext::Custodian { tenant_id } => {
            req.object_type == ObjectType::Identity && *tenant_id == req.tenant_id
        }
        SlotContext::MemberEpoch {
            tenant_id,
            channel_id,
            epoch_id,
        } => {
            req.object_type != ObjectType::Identity
                && *tenant_id == req.tenant_id
                && *channel_id == req.channel_id
                && *epoch_id == req.epoch_id
        }
    };
    if ok {
        Ok(())
    } else {
        Err(Error::Malformed("slot context does not match the header"))
    }
}

pub(crate) fn seal_with_ck_rng<F, P>(
    rng: &mut dyn RandomSource,
    ck: &ContentKey,
    req: &SealRequest<'_>,
    build: F,
) -> Result<(RecipientList, SealedObject)>
where
    F: FnOnce(&PayloadContext<'_>) -> Result<P>,
    P: AsRef<[u8]>,
{
    req.suite.require_supported()?;
    let mut object_id = [0u8; 16];
    rng.fill(&mut object_id)?;
    // AUD-RM1-CORE-04: the payload nonce is drawn inside the STREAM constructor.
    let (encryptor, payload_nonce) =
        StreamEncryptor::for_payload_with(rng, req.suite, ck, req.padded_len)?;
    let (slot_block, recipient_list) = match (req.object_type.is_intake_sealed(), &req.recipients) {
        (true, Some((ctx, pks))) => {
            check_context(req, ctx)?;
            let b = SlotBinding {
                suite: req.suite,
                object_id,
                payload_nonce,
                context: ctx.clone(),
            };
            let (blk, list) = RecipientSlotBlock::build_with(rng, ck, &b, pks)?;
            (Some(blk), list)
        }
        (false, None) => (None, RecipientList::default()),
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
        recipient_list: recipient_list.as_slice(),
    })?;
    let padded = padded.as_ref();
    if u64::try_from(padded.len()).ok() != Some(req.padded_len) {
        return Err(Error::Length);
    }
    let header_mac = header.header_mac(ck)?;
    let payload = encryptor.encrypt_all(padded)?;
    let mut bytes = Vec::with_capacity(
        HEADER_LEN
            .saturating_add(HEADER_MAC_LEN)
            .saturating_add(payload.len()),
    );
    bytes.extend_from_slice(&header_bytes);
    bytes.extend_from_slice(&header_mac);
    bytes.extend_from_slice(&payload);
    Ok((
        recipient_list,
        SealedObject {
            object_hash: object_hash(&header_bytes, &header_mac),
            header,
            header_mac,
            slot_block,
            bytes,
        },
    ))
}

/// A structurally validated (not yet authenticated) sealed object.
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

impl core::fmt::Debug for ParsedObject<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // AUD-RM1-CORE-11: type and lengths only, never the payload or ids.
        f.debug_struct("ParsedObject")
            .field("object_type", &self.header.object_type)
            .field("padded_plaintext_len", &self.header.padded_plaintext_len)
            .field("payload_len", &self.payload.len())
            .finish_non_exhaustive()
    }
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

    /// AUD-RM1-CORE-09(c): the slot binding derived from the header itself, so callers
    /// cannot pass a context that disagrees with it. IDENTITY → custodian context
    /// (tenant); other intake-sealed types → member-epoch context (tenant, channel,
    /// epoch). Fails for types without slots.
    pub fn slot_binding_from_header(&self) -> Result<SlotBinding> {
        let h = &self.header;
        let context = match h.object_type {
            ObjectType::Identity => SlotContext::Custodian {
                tenant_id: h.tenant_id,
            },
            t if t.is_intake_sealed() => SlotContext::MemberEpoch {
                tenant_id: h.tenant_id,
                channel_id: h.channel_id,
                epoch_id: h.epoch_id,
            },
            _ => return Err(Error::Malformed("object type has no recipient slots")),
        };
        Ok(self.slot_binding(context))
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
    ///
    /// The whole plaintext is held in memory (up to the largest file bucket, about
    /// 16 GiB); use [`ParsedObject::open_bounded`] or [`ParsedObject::open_stream`]
    /// where that is not acceptable (AUD-RM1-CORE-13).
    pub fn open(&self, ck: &ContentKey) -> Result<Zeroizing<Vec<u8>>> {
        self.verify(ck)?;
        let d = StreamDecryptor::for_payload(
            self.header.suite,
            ck,
            &self.header.payload_nonce,
            self.header.padded_plaintext_len,
        )?;
        stream::decrypt_with(d, self.payload)
    }

    /// [`ParsedObject::open`], refusing (before any decryption or allocation) objects
    /// whose padded plaintext is larger than `max_plaintext_len` bytes.
    pub fn open_bounded(
        &self,
        ck: &ContentKey,
        max_plaintext_len: u64,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if self.header.padded_plaintext_len > max_plaintext_len {
            return Err(Error::TooLarge);
        }
        self.open(ck)
    }

    /// Verify the header MAC, then return a chunk decryptor and the payload bytes.
    pub fn open_stream(&self, ck: &ContentKey) -> Result<(StreamDecryptor, &[u8])> {
        self.verify(ck)?;
        Ok((
            StreamDecryptor::for_payload(
                self.header.suite,
                ck,
                &self.header.payload_nonce,
                self.header.padded_plaintext_len,
            )?,
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
        let (list, obj) = seal_with_ck_rng(&mut rng, &ck, &req, |pc| {
            seen = pc.recipient_list.iter().map(|e| e.to_bytes()).collect();
            assert_eq!(pc.header.padded_plaintext_len, pt.len() as u64);
            Ok(pt.clone())
        })
        .unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0], list.as_slice()[0].to_bytes());
        // AUD-RM1-CORE-01: the public object carries no entry and prints nothing secret.
        let dbg = format!("{obj:?}");
        assert!(dbg.starts_with("SealedObject") && !dbg.contains("enc_rand"));
        let p = parse(&obj.bytes).unwrap();
        assert_eq!(p.object_hash(), obj.object_hash);
        let blk = obj.slot_block.as_ref().unwrap();
        p.check_slot_block(blk).unwrap();
        let (ck2, pos) = blk
            .trial_open(&m.private, &p.slot_binding(ctx.clone()))
            .unwrap();
        assert_eq!(usize::from(list.as_slice()[0].slot_index()), pos);
        let dir = |kid: &[u8; 32]| {
            (crate::hash::key_id(
                Suite::CandorStd1,
                crate::hash::KeyKind::Mek,
                &m.public.to_bytes(),
            ) == *kid)
                .then(|| m.public.clone())
        };
        blk.verify_slot_block(&ck2, &p.slot_binding(ctx.clone()), list.as_slice(), dir)
            .unwrap();
        // AUD-RM1-CORE-09(c): the header-derived binding equals the expected one.
        assert_eq!(
            p.slot_binding_from_header().unwrap(),
            p.slot_binding(ctx.clone())
        );
        let pd = format!("{p:?}");
        assert!(pd.starts_with("ParsedObject") && !pd.contains("payload:"));
        assert_eq!(
            p.open_bounded(&ck2, pt.len() as u64 - 1).err(),
            Some(Error::TooLarge)
        );
        assert_eq!(p.open(&ck2).unwrap().as_slice(), pt.as_slice());
        assert_eq!(
            p.open_bounded(&ck2, pt.len() as u64).unwrap().as_slice(),
            pt.as_slice()
        );

        // AUD-RM1-CORE-09(b): a slot context that disagrees with the header or the
        // object type is refused at sealing.
        let wrong_epoch = SlotContext::MemberEpoch {
            tenant_id: [1; 16],
            channel_id: [2; 16],
            epoch_id: 4,
        };
        let pks = [m.public.clone()];
        let bad = SealRequest {
            recipients: Some((wrong_epoch, &pks)),
            ..req
        };
        assert!(seal_with_ck_rng(&mut rng, &ck, &bad, |_| Ok(pt.clone())).is_err());
        let custodian = SealRequest {
            recipients: Some((SlotContext::Custodian { tenant_id: [1; 16] }, &pks)),
            ..req
        };
        assert!(seal_with_ck_rng(&mut rng, &ck, &custodian, |_| Ok(pt.clone())).is_err());

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
        assert_eq!(
            seal_bytes(&bad, &pt[..100]).err(),
            Some(Error::IllegalBucket)
        );
        // Builder output must match the declared length.
        let req2 = SealRequest {
            padded_len: 4096,
            ..bad
        };
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
