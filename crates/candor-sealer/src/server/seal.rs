// SPDX-License-Identifier: AGPL-3.0-or-later
//! Envelope construction (04 §12.3, §12.7, §13; ADR-034, ADR-047(3), ADR-050).
//!
//! Every object is built with the same C-11 (`candor-core`) functions for real
//! and chaff envelopes. The ATTACHMENT_BUNDLE is sealed in a streaming fashion
//! (staged parts are decrypted under `K_stage` chunk by chunk and re-encrypted
//! under the bundle CK) straight into a tmpfs staging file, so attachment
//! plaintext never exists in full, and never on disk.

use std::io::Write;

use super::directory::DirectorySnapshot;
use super::inner::{
    self, BUNDLE_MAGIC, ManifestFile, MessageKind, Prefs, RecipientListCbor, ReplyInner,
    ReportPrefs, SigSpec,
};
use super::select::Selection;
use super::session::StagedPart;
use super::sink::{Blob, EnvelopeGroup, EnvelopeObject};
use crate::proto::cbor::Value;
use crate::proto::{Mode, PendingReply, SecretText};
use candor_core::header::{CoreHeader, HEADER_LEN, HEADER_MAC_LEN, ObjectType, object_hash};
use candor_core::kdf::ct_eq;
use candor_core::kem::{self, KemPublicKey};
use candor_core::object::{self, SealRequest, SealedObject};
use candor_core::passphrase::SourceKeys;
use candor_core::secret::{ContentKey, Secret32, SessionKey};
use candor_core::sig::{SigningKey, verify_strict};
use candor_core::slots::{RecipientList, RecipientListEntry, RecipientSlotBlock, SlotBinding, SlotContext};
use candor_core::stanza::{HpkeWrapContext, WrapStanza};
use candor_core::stream::{self, CHUNK_SIZE, PartId, StreamDecryptor, StreamEncryptor};
use candor_core::{Error, Suite, fill_random, labels, padding};
use candor_safefs::{ObjectId, PendingObject, SafeRoot, SlotTime};
use zeroize::{Zeroize, Zeroizing};

/// Shared sealing context.
pub(crate) struct SealCtx<'a> {
    pub suite: Suite,
    pub tenant_id: [u8; 16],
    pub sealer_key: &'a SigningKey,
    pub staging: &'static SafeRoot,
    /// Day-start time stamped on staging files (no sub-day time, ADR-010).
    pub slot: SlotTime,
    pub custodian_pk: KemPublicKey,
    pub disposition_pk: KemPublicKey,
}

impl SealCtx<'_> {
    fn member_ctx(&self, channel_id: [u8; 16], epoch_id: u32) -> SlotContext {
        SlotContext::MemberEpoch {
            tenant_id: self.tenant_id,
            channel_id,
            epoch_id,
        }
    }
}

fn io_err<E>(_: E) -> Error {
    Error::Internal
}

// ---------------------------------------------------------------------------
// STREAM constructors (candor-core AUD-RM1-CORE-04 API): no raw keys or caller
// nonces; staged parts use single-use `PartId`s, payloads draw their nonce
// inside candor-core.

/// STREAM encryptor for a staged Tier W part under
/// `K_stage = HKDF(K36, part_id, "candor/v1/stage/part")` (§9.13). Each
/// [`PartId`] is accepted once.
pub(crate) fn staged_part_encryptor(
    k36: &SessionKey,
    part_id: &PartId,
    padded_len: u64,
) -> Result<StreamEncryptor, Error> {
    StreamEncryptor::for_staged_part(k36, part_id, padded_len)
}

/// STREAM decryptor for a staged Tier W part (§9.13).
pub(crate) fn staged_part_decryptor(
    k36: &SessionKey,
    part_id: &[u8; 16],
    padded_len: u64,
) -> Result<StreamDecryptor, Error> {
    StreamDecryptor::for_staged_part(k36, part_id, padded_len)
}

/// Start a staging file under a caller-known id, so a failed `commit` (which
/// may fail after the rename) can still be cleaned up (AUD-RM2-SEA-13).
pub(crate) fn stage_create(
    staging: &'static SafeRoot,
) -> Result<(ObjectId, PendingObject<'static>), Error> {
    let id = ObjectId::random().map_err(io_err)?;
    let w = staging.create_new(&id).map_err(io_err)?;
    Ok((id, w))
}

/// Commit a staging file; on failure remove whatever may have been renamed.
pub(crate) fn stage_commit(
    staging: &'static SafeRoot,
    w: PendingObject<'static>,
    id: &ObjectId,
    slot: SlotTime,
) -> Result<ObjectId, Error> {
    match w.commit(slot) {
        Ok(got) => Ok(got),
        Err(_) => {
            let _ = staging.remove(id, slot);
            Err(Error::Internal)
        }
    }
}

/// Encrypts a STREAM of known plaintext length chunk by chunk into `out`, with a
/// one-chunk plaintext buffer allocated once (it never grows; R7 SI-A-05).
pub(crate) struct StreamSink<W: Write> {
    buf: Zeroizing<Vec<u8>>,
    enc: StreamEncryptor,
    out: W,
    total: u64,
    consumed: u64,
}

impl<W: Write> StreamSink<W> {
    pub(crate) fn new(enc: StreamEncryptor, out: W, total: u64) -> Self {
        Self {
            buf: Zeroizing::new(Vec::with_capacity(CHUNK_SIZE)),
            enc,
            out,
            total,
            consumed: 0,
        }
    }

    /// Plaintext length of the chunk being assembled.
    fn target(&self) -> Result<usize, Error> {
        let start = self.consumed;
        let left = self.total.checked_sub(start).ok_or(Error::Internal)?;
        usize::try_from(left.min(CHUNK_SIZE as u64)).map_err(|_| Error::Internal)
    }

    fn flush_chunk(&mut self) -> Result<(), Error> {
        let ct = self.enc.encrypt_chunk(&self.buf)?;
        self.out.write_all(&ct).map_err(io_err)?;
        let n = u64::try_from(self.buf.len()).map_err(|_| Error::Internal)?;
        self.consumed = self.consumed.checked_add(n).ok_or(Error::Internal)?;
        self.buf.zeroize();
        Ok(())
    }

    /// Bytes accepted so far.
    pub(crate) fn accepted(&self) -> u64 {
        self.consumed
            .saturating_add(u64::try_from(self.buf.len()).unwrap_or(u64::MAX))
    }

    /// Append plaintext. Fails if it would exceed the declared total.
    pub(crate) fn push(&mut self, mut data: &[u8]) -> Result<(), Error> {
        let len = u64::try_from(data.len()).map_err(|_| Error::TooLarge)?;
        if self
            .accepted()
            .checked_add(len)
            .is_none_or(|t| t > self.total)
        {
            return Err(Error::TooLarge);
        }
        while !data.is_empty() {
            let room = self.target()?.saturating_sub(self.buf.len());
            let (now, rest) = data.split_at(room.min(data.len()));
            self.buf.extend_from_slice(now);
            data = rest;
            if self.buf.len() == self.target()? {
                self.flush_chunk()?;
            }
        }
        Ok(())
    }

    /// Zero-fill to the declared total, emit the final chunk and return the writer.
    pub(crate) fn finish(mut self) -> Result<W, Error> {
        let zeros = [0u8; 4096];
        while self.accepted() < self.total {
            let left = self.total.saturating_sub(self.accepted());
            let n = usize::try_from(left.min(4096)).map_err(|_| Error::Internal)?;
            self.push(zeros.get(..n).ok_or(Error::Internal)?)?;
        }
        if self.total == 0 {
            // A zero-length STREAM is one empty final chunk (§13.3).
            self.flush_chunk()?;
        }
        if !self.buf.is_empty() {
            return Err(Error::Internal);
        }
        self.enc.finish()?;
        Ok(self.out)
    }
}

/// `disposition_ct = HPKE.SealBase(K41, info = "candor/v1/wrap/disposition" ‖
/// suite ‖ tenant, aad = object_hash(first object), pt = kind ‖ 31 random)`
/// (04 §12.7). Returned as `enc ‖ ct` (Nenc + 48 bytes).
pub(crate) fn disposition_ct(
    suite: Suite,
    tenant_id: &[u8; 16],
    k41: &KemPublicKey,
    first_object_hash: &[u8; 32],
    chaff: bool,
) -> Result<Vec<u8>, Error> {
    let mut info = Vec::with_capacity(labels::WRAP_DISPOSITION.len().saturating_add(18));
    info.extend_from_slice(labels::WRAP_DISPOSITION);
    info.extend_from_slice(&suite.to_be_bytes());
    info.extend_from_slice(tenant_id);
    let mut pt = Zeroizing::new([0u8; 32]);
    fill_random(pt.get_mut(1..).ok_or(Error::Internal)?)?;
    if let Some(k) = pt.first_mut() {
        *k = u8::from(chaff);
    }
    let (enc, ct) = kem::seal_base(k41, &info, first_object_hash, pt.as_ref())?;
    let mut out = enc;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Chaff CK: `HKDF(IKM = chaff_seed, salt = u64 counter, info = "candor/v1/chaff/seed")`
/// (04 §10, §12.7).
pub(crate) fn chaff_ck(seed: &Secret32, counter: u64) -> Result<ContentKey, Error> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&counter.to_be_bytes()), seed.expose());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(labels::CHAFF_SEED, okm.as_mut())
        .map_err(|_| Error::Internal)?;
    Ok(ContentKey::from_bytes(*okm))
}

fn envelope_object(o: &SealedObject, blob: Blob) -> Result<EnvelopeObject, Error> {
    Ok(EnvelopeObject {
        object_type: o.header.object_type,
        object_hash: o.object_hash,
        slot_block: o
            .slot_block
            .as_ref()
            .map(RecipientSlotBlock::encode)
            .ok_or(Error::Internal)?,
        blob,
    })
}

/// The sealed ATTACHMENT_BUNDLE (staged) and what the SUBMISSION needs about it.
pub(crate) struct BundleOut {
    pub object: EnvelopeObject,
    pub entries: RecipientList,
    pub manifest: Vec<ManifestFile>,
    pub total_len: u64,
}

/// Seal staged parts into an ATTACHMENT_BUNDLE (§13.7) streamed into staging.
pub(crate) fn seal_bundle(
    ctx: &SealCtx<'_>,
    sel: &Selection,
    parts: &[StagedPart],
    k36: &SessionKey,
) -> Result<BundleOut, Error> {
    let count = u32::try_from(parts.len()).map_err(|_| Error::TooLarge)?;
    let mut total_len: u64 = 8;
    for p in parts {
        total_len = total_len.checked_add(p.real_len).ok_or(Error::TooLarge)?;
    }
    let padded = padding::bucket_for(ObjectType::AttachmentBundle, total_len)?;
    let ck = ContentKey::generate()?;
    let mut object_id = [0u8; 16];
    fill_random(&mut object_id)?;
    // The payload nonce is drawn inside candor-core with the encryptor.
    let (enc, payload_nonce) = StreamEncryptor::for_payload(ctx.suite, &ck, padded)?;
    let binding = SlotBinding {
        suite: ctx.suite,
        object_id,
        payload_nonce,
        context: ctx.member_ctx(sel.channel_id, sel.epoch_id),
    };
    let pks: Vec<KemPublicKey> = sel.recipients.iter().map(|r| r.pk.clone()).collect();
    let (block, entries) = RecipientSlotBlock::build(&ck, &binding, &pks)?;
    let header = CoreHeader {
        object_type: ObjectType::AttachmentBundle,
        suite: ctx.suite,
        tenant_id: ctx.tenant_id,
        channel_id: sel.channel_id,
        epoch_id: sel.epoch_id,
        slot_block_hash: block.hash(),
        object_id,
        day_stamp: 0,
        padded_plaintext_len: padded,
        payload_nonce,
    };
    let header_bytes = header.encode()?;
    let mac = header.header_mac(&ck)?;
    let (staged_id, mut w) = stage_create(ctx.staging)?;
    w.write_all(&header_bytes).map_err(io_err)?;
    w.write_all(&mac).map_err(io_err)?;
    let mut sink = StreamSink::new(enc, w, padded);
    sink.push(&BUNDLE_MAGIC)?;
    sink.push(&count.to_be_bytes())?;
    let mut manifest = Vec::with_capacity(parts.len());
    let mut offset: u64 = 8;
    for p in parts {
        let reader = ctx.staging.open_read(&p.object).map_err(io_err)?;
        let mut chunks = staged_part_decryptor(k36, &p.part_id, p.padded_len)?.reader(reader);
        let mut left = p.real_len;
        for chunk in chunks.by_ref() {
            let c = chunk?;
            let take = usize::try_from(left.min(c.len() as u64)).map_err(|_| Error::Internal)?;
            sink.push(c.get(..take).ok_or(Error::Internal)?)?;
            left = left.checked_sub(take as u64).ok_or(Error::Internal)?;
        }
        // Every chunk, including the padding and the final flag, must verify.
        chunks.finish()?;
        if left != 0 {
            return Err(Error::Stream("staged part shorter than recorded"));
        }
        manifest.push(ManifestFile {
            name: Zeroizing::new(p.name.expose().to_owned()),
            media_type: Zeroizing::new(p.media_type.expose().to_owned()),
            size: p.real_len,
            sha256: p.hashes.0.sha256,
            blake3: p.hashes.0.blake3,
            offset,
        });
        offset = offset.checked_add(p.real_len).ok_or(Error::Internal)?;
    }
    let w = sink.finish()?;
    let id = stage_commit(ctx.staging, w, &staged_id, ctx.slot)?;
    let len = stream::ciphertext_len(padded)?
        .checked_add((HEADER_LEN + HEADER_MAC_LEN) as u64)
        .ok_or(Error::Internal)?;
    Ok(BundleOut {
        object: EnvelopeObject {
            object_type: ObjectType::AttachmentBundle,
            object_hash: object_hash(&header_bytes, &mac),
            slot_block: block.encode(),
            blob: Blob::Staged { id, len },
        },
        entries,
        manifest,
        total_len,
    })
}

/// Seal the IDENTITY object to K13 (one real slot, 15 dummies; §13.2), padded
/// to the maximum IDENTITY bucket (ADR-052(1)).
fn seal_identity(
    ctx: &SealCtx<'_>,
    channel_id: [u8; 16],
    text: &str,
) -> Result<(RecipientList, SealedObject), Error> {
    let payload = inner::identity_payload(text)?;
    let pks = [ctx.custodian_pk.clone()];
    let req = SealRequest {
        suite: ctx.suite,
        object_type: ObjectType::Identity,
        tenant_id: ctx.tenant_id,
        channel_id,
        epoch_id: 0,
        day_stamp: 0,
        recipients: Some((
            SlotContext::Custodian {
                tenant_id: ctx.tenant_id,
            },
            &pks,
        )),
        padded_len: u64::try_from(payload.len()).map_err(|_| Error::Internal)?,
    };
    let (secrets, obj) = object::seal(&req, |_| Ok(payload.as_slice()))?;
    Ok((secrets.into_parts().1, obj))
}

fn nfc(s: &str) -> Zeroizing<String> {
    use unicode_normalization::UnicodeNormalization;
    // NFC expands at most 3× (UAX #15); size once so the buffer never reallocates.
    let mut out = Zeroizing::new(String::with_capacity(s.len().saturating_mul(3)));
    out.extend(s.nfc());
    out
}

/// The three sealed objects of one envelope group (ADR-052(1)).
pub(crate) struct SealedGroup {
    pub main: EnvelopeObject,
    pub bundle: EnvelopeObject,
    pub identity: EnvelopeObject,
}

impl SealedGroup {
    /// Delete the staged bundle (the group will not be handed to the sink).
    pub(crate) fn remove_staged(&self, ctx: &SealCtx<'_>) {
        remove_staged(ctx, &self.bundle);
    }

    pub(crate) fn into_group(self, channel_id: [u8; 16], disposition_ct: Vec<u8>) -> EnvelopeGroup {
        EnvelopeGroup {
            channel_id,
            main: self.main,
            bundle: self.bundle,
            identity: self.identity,
            disposition_ct,
        }
    }
}

/// What the source drafted, as used by the builders.
pub(crate) struct DraftInput<'a> {
    pub mode: Mode,
    pub message: &'a str,
    pub fields: &'a [(u16, SecretText)],
    pub identity: Option<&'a str>,
    pub flagged_labels: &'a [u16],
    pub categories: &'a [u16],
}

struct SubmissionParts<'a> {
    keys: &'a SourceKeys,
    report_index: u32,
    mailbox_id: [u8; 32],
    sel: &'a Selection,
    draft: &'a DraftInput<'a>,
    message_nfc: &'a str,
    bundle_hash: [u8; 32],
    identity_hash: [u8; 32],
    bundle: &'a BundleOut,
    identity_entries: &'a [RecipientListEntry],
}

fn submission_entries(
    p: &SubmissionParts<'_>,
    entries: &[RecipientListEntry],
) -> Vec<(u64, Value)> {
    let list = RecipientListCbor {
        epoch_id: p.sel.epoch_id,
        entries,
        skipped: p.sel.skipped,
        coi_policy_entry_hash: p.sel.coi_policy_entry_hash,
        tree_size: p.sel.tree_size,
        root_hash: p.sel.root_hash,
        bundle_entries: Some(p.bundle.entries.as_slice()),
        identity_entries: Some(p.identity_entries),
    };
    let mut concerns: Zeroizing<Vec<u16>> = Zeroizing::new(p.draft.flagged_labels.to_vec());
    concerns.sort_unstable();
    concerns.dedup();
    // Sized once: the map holds the mode and COI data, so it must not reallocate
    // and leave a stale copy behind (AUD-RM2-SEA-08).
    let mut m = Vec::with_capacity(24);
    m.extend([
        (1, Value::U(inner::SUBMISSION_FORMAT)),
        (2, Value::U(u64::from(p.report_index))),
        (3, Value::bytes(&p.mailbox_id)),
        (4, Value::bytes(&p.keys.kem_public_key().to_bytes())),
        (5, Value::bytes(&p.keys.sign_key().verifying_key_bytes())),
        (6, Value::bytes(&p.sel.roster_entry_hash)),
        (
            7,
            Value::A(vec![
                Value::U(p.sel.tree_size),
                Value::bytes(&p.sel.root_hash),
            ]),
        ),
        (8, Value::U(inner::TIER_W)),
        (9, Value::U(p.draft.mode as u64)),
        (10, Value::bytes(&p.bundle_hash)),
        (11, Value::bytes(&p.identity_hash)),
        (
            12,
            Value::A(
                p.draft
                    .fields
                    .iter()
                    .map(|(id, t)| {
                        Value::A(vec![Value::U(u64::from(*id)), Value::text(t.expose())])
                    })
                    .collect(),
            ),
        ),
        (13, Value::text(p.message_nfc)),
        (
            14,
            Value::A(concerns.iter().map(|l| Value::U(u64::from(*l))).collect()),
        ),
        (16, list.value()),
        (
            18,
            inner::manifest_value(&p.bundle.manifest, p.bundle.total_len),
        ),
    ]);
    if let Some(first) = p.draft.categories.first() {
        m.push((17, Value::U(u64::from(*first))));
    }
    if p.draft.categories.len() > 1 {
        m.push((
            1000,
            Value::A(
                p.draft
                    .categories
                    .iter()
                    .map(|c| Value::U(u64::from(*c)))
                    .collect(),
            ),
        ));
    }
    m
}

/// Initial Tier W submission: SUBMISSION + ATTACHMENT_BUNDLE (possibly empty)
/// + IDENTITY (empty in ANONYMOUS mode). Returns the group and the SUBMISSION hash.
pub(crate) fn seal_initial(
    ctx: &SealCtx<'_>,
    sel: &Selection,
    keys: &SourceKeys,
    report_index: u32,
    draft: &DraftInput<'_>,
    parts: &[StagedPart],
    k36: &SessionKey,
) -> Result<(SealedGroup, [u8; 32]), Error> {
    let mailbox_id = keys.mailbox_id(report_index)?;
    let bundle = seal_bundle(ctx, sel, parts, k36)?;
    let result = (|| {
        let identity_text = match draft.mode {
            Mode::Anonymous => "",
            _ => draft.identity.unwrap_or(""),
        };
        let (identity_list, identity) = seal_identity(ctx, sel.channel_id, identity_text)?;
        let message_nfc = nfc(draft.message);
        let sp = SubmissionParts {
            keys,
            report_index,
            mailbox_id,
            sel,
            draft,
            message_nfc: &message_nfc,
            bundle_hash: bundle.object.object_hash,
            identity_hash: identity.object_hash,
            bundle: &bundle,
            identity_entries: identity_list.as_slice(),
        };
        let sigs = [
            SigSpec {
                key: 15,
                label: labels::SIG_SUBMISSION,
                signer: keys.sign_key(),
            },
            SigSpec {
                key: 19,
                label: labels::SIG_SEALER,
                signer: ctx.sealer_key,
            },
        ];
        let pks: Vec<KemPublicKey> = sel.recipients.iter().map(|r| r.pk.clone()).collect();
        let req = SealRequest {
            suite: ctx.suite,
            object_type: ObjectType::Submission,
            tenant_id: ctx.tenant_id,
            channel_id: sel.channel_id,
            epoch_id: sel.epoch_id,
            day_stamp: 0,
            recipients: Some((ctx.member_ctx(sel.channel_id, sel.epoch_id), &pks)),
            // ADR-052(1): always the maximum bucket.
            padded_len: inner::max_bucket(ObjectType::Submission)?,
        };
        let (_ck, sub) = object::seal(&req, |pc| {
            inner::signed_payload(
                ObjectType::Submission,
                submission_entries(&sp, pc.recipient_list),
                pc.header_bytes,
                &sigs,
            )
        })?;
        let sub_hash = sub.object_hash;
        let group = SealedGroup {
            main: envelope_object(&sub, Blob::Inline(sub.bytes.clone()))?,
            bundle: bundle.object.clone(),
            identity: envelope_object(&identity, Blob::Inline(identity.bytes.clone()))?,
        };
        Ok((group, sub_hash))
    })();
    if result.is_err() {
        remove_staged(ctx, &bundle.object);
    }
    result
}

/// Delete a staged object that will not be handed to the sink.
pub(crate) fn remove_staged(ctx: &SealCtx<'_>, o: &EnvelopeObject) {
    if let Blob::Staged { id, .. } = &o.blob {
        let _ = ctx.staging.remove(id, ctx.slot);
    }
}

/// A follow-up or key-rotation SOURCE_MESSAGE (§13.4 v1.1) and optional bundle.
pub(crate) struct SourceMessageInput<'a> {
    pub keys: &'a SourceKeys,
    pub report: &'a ReportPrefs,
    pub kind: MessageKind,
    pub message: &'a str,
    /// KEY_ROTATION: the new keys (sign_pk', src_pk' and the signer for key 13).
    pub new_keys: Option<&'a SourceKeys>,
}

struct SourceMessageParts<'a> {
    sm: &'a SourceMessageInput<'a>,
    sel: &'a Selection,
    message_nfc: &'a str,
    bundle: &'a BundleOut,
    identity_hash: [u8; 32],
    identity_entries: &'a [RecipientListEntry],
}

fn source_message_entries(
    p: &SourceMessageParts<'_>,
    entries: &[RecipientListEntry],
) -> Vec<(u64, Value)> {
    let (sm, sel) = (p.sm, p.sel);
    let list = RecipientListCbor {
        epoch_id: sel.epoch_id,
        entries,
        skipped: sel.skipped,
        coi_policy_entry_hash: sel.coi_policy_entry_hash,
        tree_size: sel.tree_size,
        root_hash: sel.root_hash,
        bundle_entries: Some(p.bundle.entries.as_slice()),
        identity_entries: Some(p.identity_entries),
    };
    let mut m = Vec::with_capacity(16);
    m.extend([
        (1, Value::U(inner::SOURCE_MESSAGE_FORMAT)),
        (2, Value::U(u64::from(sm.report.report_index))),
        (3, Value::bytes(&sm.report.mailbox_id)),
        (4, Value::Null),
        (5, Value::text(p.message_nfc)),
        (7, Value::U(sm.kind as u64)),
        (8, list.value()),
        (9, Value::bytes(&sm.report.original_submission_hash)),
        // The bundle is always present (empty when no attachment, ADR-052(1)).
        (11, Value::bytes(&p.bundle.object.object_hash)),
        // Forward-compatible key: the group's (dummy) IDENTITY object.
        (1000, Value::bytes(&p.identity_hash)),
    ]);
    if let Some(nk) = sm.new_keys {
        m.push((
            10,
            Value::M(vec![
                (1, Value::bytes(&nk.sign_key().verifying_key_bytes())),
                (2, Value::bytes(&nk.kem_public_key().to_bytes())),
            ]),
        ));
    }
    m
}

/// Seal a SOURCE_MESSAGE envelope group (follow-up rule applied by the caller's
/// selection): SOURCE_MESSAGE + ATTACHMENT_BUNDLE (possibly empty) + a dummy
/// IDENTITY (empty, to K13), the same shape as every other group (ADR-052(1)).
pub(crate) fn seal_source_message(
    ctx: &SealCtx<'_>,
    sel: &Selection,
    sm: &SourceMessageInput<'_>,
    parts: &[StagedPart],
    k36: &SessionKey,
) -> Result<SealedGroup, Error> {
    let bundle = seal_bundle(ctx, sel, parts, k36)?;
    let result = (|| {
        let (identity_list, identity) = seal_identity(ctx, sel.channel_id, "")?;
        let message_nfc = nfc(sm.message);
        let mut sigs = vec![
            SigSpec {
                key: 6,
                label: labels::SIG_SOURCE_MESSAGE,
                signer: sm.keys.sign_key(),
            },
            SigSpec {
                key: 12,
                label: labels::SIG_SEALER,
                signer: ctx.sealer_key,
            },
        ];
        if let Some(nk) = sm.new_keys {
            sigs.push(SigSpec {
                key: 13,
                label: labels::SIG_SOURCE_MESSAGE,
                signer: nk.sign_key(),
            });
        }
        let parts_in = SourceMessageParts {
            sm,
            sel,
            message_nfc: &message_nfc,
            bundle: &bundle,
            identity_hash: identity.object_hash,
            identity_entries: identity_list.as_slice(),
        };
        let pks: Vec<KemPublicKey> = sel.recipients.iter().map(|r| r.pk.clone()).collect();
        let req = SealRequest {
            suite: ctx.suite,
            object_type: ObjectType::SourceMessage,
            tenant_id: ctx.tenant_id,
            channel_id: sel.channel_id,
            epoch_id: sel.epoch_id,
            day_stamp: 0,
            recipients: Some((ctx.member_ctx(sel.channel_id, sel.epoch_id), &pks)),
            padded_len: inner::max_bucket(ObjectType::SourceMessage)?,
        };
        let (_ck, msg) = object::seal(&req, |pc| {
            inner::signed_payload(
                ObjectType::SourceMessage,
                source_message_entries(&parts_in, pc.recipient_list),
                pc.header_bytes,
                &sigs,
            )
        })?;
        Ok(SealedGroup {
            main: envelope_object(&msg, Blob::Inline(msg.bytes.clone()))?,
            bundle: bundle.object.clone(),
            identity: envelope_object(&identity, Blob::Inline(identity.bytes.clone()))?,
        })
    })();
    if result.is_err() {
        remove_staged(ctx, &bundle.object);
    }
    result
}

/// Public chaff bundle-size distribution (04 §12.7; provisional values until
/// the 39 constants registry defines `CHAFF_BUCKETS_*`, see SPEC-NOTES). The
/// text-bearing objects need no distribution: real and chaff SUBMISSION,
/// SOURCE_MESSAGE and IDENTITY objects always use their maximum bucket
/// (ADR-052(1)). Configure it to approximate the real attachment distribution.
#[derive(Debug, Clone)]
pub struct ChaffBuckets {
    /// ATTACHMENT_BUNDLE padded lengths and weights (each ≤ 8 MiB). Must give
    /// the empty-bundle bucket (256 KiB) a positive weight, because every real
    /// group without attachments carries an empty bundle.
    pub bundle: Vec<(u64, u32)>,
}

impl Default for ChaffBuckets {
    fn default() -> Self {
        let b: Vec<u64> = padding::file_buckets()
            .take_while(|b| *b <= CHAFF_BUNDLE_MAX)
            .collect();
        let weights = [600u32, 120, 80, 60, 40, 30, 25, 20, 15, 10];
        Self {
            bundle: b
                .iter()
                .zip(weights.iter().chain(core::iter::repeat(&5)))
                .map(|(b, w)| (*b, *w))
                .collect(),
        }
    }
}

/// Largest chaff bundle bucket (8 MiB); larger real bundles are an honest limit
/// (04 §12.7, ADR-052(1)).
pub const CHAFF_BUNDLE_MAX: u64 = 8 << 20;

impl ChaffBuckets {
    /// All entries are legal bundle buckets ≤ 8 MiB, some weight is positive,
    /// and the empty-bundle bucket is in the support.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let t = ObjectType::AttachmentBundle;
        !self.bundle.is_empty()
            && self.bundle.iter().any(|(_, w)| *w > 0)
            && self
                .bundle
                .iter()
                .all(|(b, _)| padding::is_legal_bucket(t, *b) && *b <= CHAFF_BUNDLE_MAX)
            && self
                .bundle
                .iter()
                .any(|(b, w)| *b == padding::FILE_BUCKET_0 && *w > 0)
            && self
                .bundle
                .iter()
                .try_fold(0u32, |acc, (_, w)| acc.checked_add(*w))
                .is_some()
    }

    /// Whether `len` is in the support of the bundle distribution.
    #[must_use]
    pub fn supports(&self, len: u64) -> bool {
        self.bundle.iter().any(|(b, w)| *b == len && *w > 0)
    }
}

/// Seal one zero-plaintext chaff object with an all-dummy slot block.
fn chaff_object(
    ctx: &SealCtx<'_>,
    ck: &ContentKey,
    object_type: ObjectType,
    channel_id: [u8; 16],
    slot_ctx: SlotContext,
    epoch_id: u32,
    padded_len: u64,
) -> Result<SealedObject, Error> {
    let none: [KemPublicKey; 0] = [];
    let req = SealRequest {
        suite: ctx.suite,
        object_type,
        tenant_id: ctx.tenant_id,
        channel_id,
        epoch_id,
        day_stamp: 0,
        recipients: Some((slot_ctx, &none)),
        padded_len,
    };
    let n = usize::try_from(padded_len).map_err(|_| Error::TooLarge)?;
    let (_list, obj) = object::seal_with_ck(ck, &req, |_| Ok(vec![0u8; n]))?;
    Ok(obj)
}

/// Build one chaff envelope group (04 §12.7, ADR-052(1)): the same three-object
/// shape as a real group (main object and IDENTITY at their maximum bucket, a
/// bundle drawn from the configured distribution), the same functions, all 16
/// slots dummy, zero plaintext, CKs from the RAM chaff seed, chaff-kind
/// disposition marker.
pub(crate) fn build_chaff(
    ctx: &SealCtx<'_>,
    channel_id: [u8; 16],
    epoch_id: u32,
    seed: &Secret32,
    counter: &mut u64,
    followup: bool,
    buckets: &ChaffBuckets,
) -> Result<EnvelopeGroup, Error> {
    let mut next_ck = || -> Result<ContentKey, Error> {
        let ck = chaff_ck(seed, *counter)?;
        *counter = counter.checked_add(1).ok_or(Error::Internal)?;
        Ok(ck)
    };
    let member = ctx.member_ctx(channel_id, epoch_id);
    let main_type = if followup {
        ObjectType::SourceMessage
    } else {
        ObjectType::Submission
    };
    let bundle_len = super::rand::weighted(&buckets.bundle)?;
    let ck = next_ck()?;
    let main = chaff_object(
        ctx,
        &ck,
        main_type,
        channel_id,
        member.clone(),
        epoch_id,
        inner::max_bucket(main_type)?,
    )?;
    let ck = next_ck()?;
    let bundle = chaff_object(
        ctx,
        &ck,
        ObjectType::AttachmentBundle,
        channel_id,
        member,
        epoch_id,
        bundle_len,
    )?;
    let ck = next_ck()?;
    let identity = chaff_object(
        ctx,
        &ck,
        ObjectType::Identity,
        channel_id,
        SlotContext::Custodian {
            tenant_id: ctx.tenant_id,
        },
        0,
        inner::max_bucket(ObjectType::Identity)?,
    )?;
    let (staged_id, mut w) = stage_create(ctx.staging)?;
    w.write_all(&bundle.bytes).map_err(io_err)?;
    let id = stage_commit(ctx.staging, w, &staged_id, ctx.slot)?;
    let len = u64::try_from(bundle.bytes.len()).map_err(|_| Error::Internal)?;
    let group = SealedGroup {
        main: envelope_object(&main, Blob::Inline(main.bytes.clone()))?,
        bundle: envelope_object(&bundle, Blob::Staged { id, len })?,
        identity: envelope_object(&identity, Blob::Inline(identity.bytes.clone()))?,
    };
    match disposition_ct(
        ctx.suite,
        &ctx.tenant_id,
        &ctx.disposition_pk,
        &group.main.object_hash,
        true,
    ) {
        Ok(d) => Ok(group.into_group(channel_id, d)),
        Err(e) => {
            group.remove_staged(ctx);
            Err(e)
        }
    }
}

/// Re-wrap one pending reply's stanza (1) from the old to the new source key
/// (04 §11.7 step 3). `Err(Authentication)` if the stanza does not open for any
/// mailbox (the caller skips such entries, AUD-RM2-SEA-14).
pub(crate) fn rewrap_reply(
    suite: Suite,
    tenant_id: [u8; 16],
    old: &SourceKeys,
    new_pk: &KemPublicKey,
    prefs: &Prefs,
    r: &PendingReply,
) -> Result<Vec<u8>, Error> {
    let stanza = WrapStanza::decode(&r.stanza)?;
    for rep in &prefs.reports {
        let wctx = HpkeWrapContext::Reply {
            tenant_id,
            channel_id: rep.channel_id,
            mailbox_id: rep.mailbox_id,
        };
        if let Ok(ck) = stanza.open_hpke_ck(old.kem_private_key(), &wctx, &r.object_hash) {
            let fresh =
                WrapStanza::seal_hpke_ck(suite, new_pk, [0u8; 32], r.object_hash, &wctx, &ck)?;
            return fresh.encode();
        }
    }
    Err(Error::Authentication)
}

/// Open and verify one dead-drop entry (04 §13.5, §11.5): trial-decrypt stanza (1)
/// for each mailbox, open the REPLY, check the mailbox, verify the sender's
/// signature against the directory and the signer's roster membership. `None`
/// for anything that is not a verified reply to this source.
pub(crate) fn open_reply(
    snap: &DirectorySnapshot,
    tenant_id: [u8; 16],
    keys: &SourceKeys,
    prefs: &Prefs,
    entry: &[u8],
) -> Option<([u8; 32], ReplyInner)> {
    let (len, rest) = entry.split_first_chunk::<4>()?;
    if usize::try_from(u32::from_be_bytes(*len)).ok()? != rest.len() {
        return None;
    }
    let header = CoreHeader::decode(rest.get(..HEADER_LEN)?).ok()?;
    if header.object_type != ObjectType::Reply {
        return None;
    }
    let obj_len = usize::try_from(header.expected_payload_len().ok()?)
        .ok()?
        .checked_add(HEADER_LEN + HEADER_MAC_LEN)?;
    let parsed = object::parse(rest.get(..obj_len)?).ok()?;
    let stanza = WrapStanza::decode(rest.get(obj_len..)?).ok()?;
    let oh = parsed.object_hash();
    let header_bytes = rest.get(..HEADER_LEN)?;
    for rep in &prefs.reports {
        let wctx = HpkeWrapContext::Reply {
            tenant_id,
            channel_id: rep.channel_id,
            mailbox_id: rep.mailbox_id,
        };
        let Ok(ck) = stanza.open_hpke_ck(keys.kem_private_key(), &wctx, &oh) else {
            continue;
        };
        let pt = parsed.open(&ck).ok()?;
        let inner = inner::decode_reply(&pt).ok()?;
        if !ct_eq(&inner.mailbox_id, &rep.mailbox_id) {
            return None;
        }
        let signer = snap.user_key(&inner.sender_entry_hash)?;
        let in_roster = snap
            .channel(&rep.channel_id)?
            .members
            .iter()
            .any(|m| m.user_id == signer.user_id);
        if !in_roster {
            return None;
        }
        let h_hdr = candor_core::hash::sha256(&[header_bytes]);
        let mut msg = Vec::with_capacity(labels::SIG_REPLY.len().saturating_add(64));
        msg.extend_from_slice(labels::SIG_REPLY);
        msg.extend_from_slice(&h_hdr);
        msg.extend_from_slice(&inner.signed_hash);
        verify_strict(&signer.sig_pk, &msg, &inner.sender_sig).ok()?;
        return Some((rep.mailbox_id, inner));
    }
    None
}
