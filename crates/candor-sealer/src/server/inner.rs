// SPDX-License-Identifier: AGPL-3.0-or-later
//! Inner plaintext formats (04 §13.4, §13.5, §11.4, §13.7) in deterministic CBOR.
//! Builders take trusted data; parsers (prefs, reply) are strict and run only
//! after AEAD verification succeeded (04 §13: "No inner structure is parsed before
//! AEAD verification succeeds").

use crate::proto::cbor::{CborError, Dec, Value};
use candor_core::hash::sha256;
use candor_core::header::ObjectType;
use candor_core::sig::{SigningKey, sign_with_context};
use candor_core::slots::RecipientListEntry;
use candor_core::{Error, padding};
use zeroize::Zeroizing;

/// SUBMISSION `format` (§13.4).
pub(crate) const SUBMISSION_FORMAT: u64 = 1;
/// SOURCE_MESSAGE `format` (§13.4 v1.1).
pub(crate) const SOURCE_MESSAGE_FORMAT: u64 = 2;
/// Tier W (§13.4 key 8).
pub(crate) const TIER_W: u64 = 0;
/// `prefs_ct` plaintext format.
pub(crate) const PREFS_FORMAT: u64 = 1;
/// `kdf_version` of the current Argon2id parameters (ADR-046(7)).
pub(crate) const KDF_VERSION: u64 = 1;
/// IDENTITY inner format.
pub(crate) const IDENTITY_FORMAT: u64 = 1;
/// ATTACHMENT_BUNDLE magic (§13.7).
pub(crate) const BUNDLE_MAGIC: [u8; 4] = *b"CBDL";
/// Bundle manifest format (§13.4 key 18.1).
pub(crate) const MANIFEST_FORMAT: u64 = 1;
/// Maximum reports kept in `prefs_ct`.
pub(crate) const MAX_PREFS_REPORTS: usize = 16;
/// Maximum original eligible members per report (slot limit).
pub(crate) const MAX_ELIGIBLE: usize = 16;

/// SOURCE_MESSAGE kinds (§13.4 key 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageKind {
    Message = 0,
    KeyRotation = 1,
}

fn entries_value(entries: &[RecipientListEntry]) -> Value {
    let mut v: Vec<[u8; candor_core::slots::RECIPIENT_ENTRY_LEN]> =
        entries.iter().map(RecipientListEntry::to_bytes).collect();
    // §13.4 key 16.2: sorted (by key_id, which follows the 1-byte slot index).
    v.sort_by(|a, b| a.get(1..33).cmp(&b.get(1..33)));
    Value::A(v.iter().map(|e| Value::bytes(e)).collect())
}

/// The signed Recipient List (§13.4 key 16 / key 8; ADR-033(1), ADR-050(3)).
#[derive(Debug)]
pub(crate) struct RecipientListCbor<'a> {
    pub epoch_id: u32,
    /// Entries of this object's slot block.
    pub entries: &'a [RecipientListEntry],
    pub skipped: u32,
    pub coi_policy_entry_hash: [u8; 32],
    pub tree_size: u64,
    pub root_hash: [u8; 32],
    /// Entries of the ATTACHMENT_BUNDLE's slot block (key 1000).
    pub bundle_entries: Option<&'a [RecipientListEntry]>,
    /// Entries of the IDENTITY object's slot block (key 1001).
    pub identity_entries: Option<&'a [RecipientListEntry]>,
}

impl RecipientListCbor<'_> {
    pub(crate) fn value(&self) -> Value {
        let mut m = vec![
            (1, Value::U(u64::from(self.epoch_id))),
            (2, entries_value(self.entries)),
            (3, Value::U(u64::from(self.skipped))),
            (4, Value::bytes(&self.coi_policy_entry_hash)),
            (
                5,
                Value::A(vec![Value::U(self.tree_size), Value::bytes(&self.root_hash)]),
            ),
        ];
        if let Some(b) = self.bundle_entries {
            m.push((1000, entries_value(b)));
        }
        if let Some(i) = self.identity_entries {
            m.push((1001, entries_value(i)));
        }
        Value::M(m)
    }
}

/// One file of the bundle manifest (§13.4 key 18.2).
pub(crate) struct ManifestFile {
    pub name: Zeroizing<String>,
    pub media_type: Zeroizing<String>,
    pub size: u64,
    pub sha256: [u8; 32],
    pub blake3: [u8; 32],
    pub offset: u64,
}

pub(crate) fn manifest_value(files: &[ManifestFile], total_len: u64) -> Value {
    Value::M(vec![
        (1, Value::U(MANIFEST_FORMAT)),
        (
            2,
            Value::A(
                files
                    .iter()
                    .map(|f| {
                        Value::M(vec![
                            (1, Value::text(&f.name)),
                            (2, Value::text(&f.media_type)),
                            (3, Value::U(f.size)),
                            (4, Value::bytes(&f.sha256)),
                            (5, Value::bytes(&f.blake3)),
                            (6, Value::U(f.offset)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (3, Value::U(total_len)),
    ])
}

/// A signature to add over `label ‖ H(CoreHeader) ‖ H(cbor without the signature keys)`.
pub(crate) struct SigSpec<'a> {
    pub key: u64,
    pub label: &'static [u8],
    pub signer: &'a SigningKey,
}

fn cbor_err(_: CborError) -> Error {
    Error::Internal
}

/// Build `padded_plaintext = u32be(cbor_len) ‖ cbor ‖ 0x00…` (§13.4) with the
/// signatures of `sigs` added under their keys. `unsigned` must not contain any
/// signature key.
pub(crate) fn signed_payload(
    object_type: ObjectType,
    unsigned: Vec<(u64, Value)>,
    header_bytes: &[u8],
    sigs: &[SigSpec<'_>],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let body = Value::M(unsigned);
    let unsigned_cbor = body.encode().map_err(cbor_err)?;
    let h_body = sha256(&[&unsigned_cbor]);
    let h_hdr = sha256(&[header_bytes]);
    let Value::M(mut entries) = body else {
        return Err(Error::Internal);
    };
    for s in sigs {
        let sig = sign_with_context(s.signer, s.label, &[&h_hdr, &h_body]);
        entries.push((s.key, Value::bytes(&sig)));
    }
    let cbor = Value::M(entries).encode().map_err(cbor_err)?;
    length_prefixed_pad(object_type, &cbor)
}

/// `u32be(len) ‖ cbor`, zero-padded to the object type's bucket.
pub(crate) fn length_prefixed_pad(
    object_type: ObjectType,
    cbor: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let len = u32::try_from(cbor.len()).map_err(|_| Error::TooLarge)?;
    let total = cbor.len().checked_add(4).ok_or(Error::TooLarge)?;
    let mut pt = Zeroizing::new(Vec::with_capacity(total));
    pt.extend_from_slice(&len.to_be_bytes());
    pt.extend_from_slice(cbor);
    padding::pad(object_type, &pt)
}

/// IDENTITY inner plaintext: `{1: format, 2: identity text}` (empty text for the
/// ANONYMOUS-mode dummy, which lands in the most common bucket, §13.6).
pub(crate) fn identity_payload(text: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let v = Value::M(vec![(1, Value::U(IDENTITY_FORMAT)), (2, Value::text(text))]);
    let cbor = v.encode().map_err(cbor_err)?;
    length_prefixed_pad(ObjectType::Identity, &cbor)
}

/// One report in `prefs_ct` (§11.4 key 3).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ReportPrefs {
    pub report_index: u32,
    pub mailbox_id: [u8; 32],
    pub original_eligible: Vec<[u8; 16]>,
    pub roster_version: u64,
    /// Channel of the report (key 1000; needed to open replies, see SPEC-NOTES).
    pub channel_id: [u8; 16],
    /// `object_hash` of the initial SUBMISSION (key 1001; §13.4 SOURCE_MESSAGE key 9).
    pub original_submission_hash: [u8; 32],
}

impl core::fmt::Debug for ReportPrefs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ReportPrefs(<redacted>)")
    }
}

/// Decrypted `prefs_ct` (§11.4). No COI ticks, no wordlist language.
#[derive(Clone, PartialEq, Eq, Default)]
pub(crate) struct Prefs {
    pub reports: Vec<ReportPrefs>,
}

impl core::fmt::Debug for Prefs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Prefs(<redacted>)")
    }
}

pub(crate) fn encode_prefs(p: &Prefs) -> Result<Zeroizing<Vec<u8>>, Error> {
    let reports = p
        .reports
        .iter()
        .map(|r| {
            Value::M(vec![
                (1, Value::U(u64::from(r.report_index))),
                (2, Value::bytes(&r.mailbox_id)),
                (
                    3,
                    Value::A(r.original_eligible.iter().map(|u| Value::bytes(u)).collect()),
                ),
                (4, Value::U(r.roster_version)),
                (1000, Value::bytes(&r.channel_id)),
                (1001, Value::bytes(&r.original_submission_hash)),
            ])
        })
        .collect();
    Value::M(vec![
        (1, Value::U(PREFS_FORMAT)),
        (2, Value::U(KDF_VERSION)),
        (3, Value::A(reports)),
        (4, Value::M(Vec::new())),
    ])
    .encode()
    .map_err(cbor_err)
}

pub(crate) fn decode_prefs(b: &[u8]) -> Result<Prefs, CborError> {
    let mut d = Dec::new(b);
    let mut m = d.map(4)?;
    d.req(&mut m, 1)?;
    if d.uint()? != PREFS_FORMAT {
        return Err(CborError::Limit);
    }
    d.req(&mut m, 2)?;
    if d.uint()? != KDF_VERSION {
        return Err(CborError::Limit);
    }
    d.req(&mut m, 3)?;
    let n = d.array(MAX_PREFS_REPORTS)?;
    let mut reports = Vec::with_capacity(n);
    for _ in 0..n {
        let mut r = d.map(6)?;
        d.req(&mut r, 1)?;
        let report_index = d.u32()?;
        d.req(&mut r, 2)?;
        let mailbox_id = d.bytes_n()?;
        d.req(&mut r, 3)?;
        let k = d.array(MAX_ELIGIBLE)?;
        let mut original_eligible = Vec::with_capacity(k);
        for _ in 0..k {
            original_eligible.push(d.bytes_n()?);
        }
        d.req(&mut r, 4)?;
        let roster_version = d.uint()?;
        d.req(&mut r, 1000)?;
        let channel_id = d.bytes_n()?;
        d.req(&mut r, 1001)?;
        let original_submission_hash = d.bytes_n()?;
        d.end_map(r)?;
        reports.push(ReportPrefs {
            report_index,
            mailbox_id,
            original_eligible,
            roster_version,
            channel_id,
            original_submission_hash,
        });
    }
    d.req(&mut m, 4)?;
    let ui = d.map(0)?;
    d.end_map(ui)?;
    d.end_map(m)?;
    d.finish()?;
    Ok(Prefs { reports })
}

/// A decoded REPLY inner map (§13.5).
pub(crate) struct ReplyInner {
    pub mailbox_id: [u8; 32],
    pub reply_seq: u64,
    pub day: u32,
    pub body: Zeroizing<String>,
    pub sender_entry_hash: [u8; 32],
    pub role_label: Zeroizing<String>,
    pub sender_sig: [u8; 64],
    /// `H(cbor keys 1–7)`.
    pub signed_hash: [u8; 32],
}

/// REPLY inner `format`.
pub(crate) const REPLY_FORMAT: u64 = 1;

/// Parse a verified REPLY padded plaintext strictly (length prefix, canonical
/// CBOR, zero padding).
pub(crate) fn decode_reply(padded: &[u8]) -> Result<ReplyInner, CborError> {
    let (len, rest) = padded.split_first_chunk::<4>().ok_or(CborError::Truncated)?;
    let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| CborError::Limit)?;
    let cbor = rest.get(..len).ok_or(CborError::Truncated)?;
    if rest.get(len..).is_none_or(|pad| pad.iter().any(|b| *b != 0)) {
        return Err(CborError::Trailing);
    }
    let mut d = Dec::new(cbor);
    let mut m = d.map(8)?;
    d.req(&mut m, 1)?;
    if d.uint()? != REPLY_FORMAT {
        return Err(CborError::Limit);
    }
    d.req(&mut m, 2)?;
    let mailbox_id = d.bytes_n()?;
    d.req(&mut m, 3)?;
    let reply_seq = d.uint()?;
    d.req(&mut m, 4)?;
    let day = d.u32()?;
    d.req(&mut m, 5)?;
    let body = Zeroizing::new(d.text(crate::proto::MAX_REPLY_BODY_LEN)?.to_owned());
    d.req(&mut m, 6)?;
    let sender_entry_hash = d.bytes_n()?;
    d.req(&mut m, 7)?;
    let role_label = Zeroizing::new(d.text(crate::proto::MAX_ROLE_LABEL_LEN)?.to_owned());
    d.req(&mut m, 8)?;
    let sender_sig = d.bytes_n()?;
    d.end_map(m)?;
    d.finish()?;
    let signed = Value::M(vec![
        (1, Value::U(REPLY_FORMAT)),
        (2, Value::bytes(&mailbox_id)),
        (3, Value::U(reply_seq)),
        (4, Value::U(u64::from(day))),
        (5, Value::text(&body)),
        (6, Value::bytes(&sender_entry_hash)),
        (7, Value::text(&role_label)),
    ])
    .encode()?;
    Ok(ReplyInner {
        mailbox_id,
        reply_seq,
        day,
        body,
        sender_entry_hash,
        role_label,
        sender_sig,
        signed_hash: sha256(&[&signed]),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn prefs_round_trip_and_strictness() {
        let p = Prefs {
            reports: vec![ReportPrefs {
                report_index: 0,
                mailbox_id: [7; 32],
                original_eligible: vec![[1; 16], [2; 16]],
                roster_version: 5,
                channel_id: [3; 16],
                original_submission_hash: [4; 32],
            }],
        };
        let b = encode_prefs(&p).unwrap();
        assert!(decode_prefs(&b).unwrap() == p);
        let mut bad = b.to_vec();
        bad.push(0);
        assert!(decode_prefs(&bad).is_err());
    }

    #[test]
    fn identity_dummy_uses_first_bucket() {
        assert_eq!(identity_payload("").unwrap().len(), 4096);
    }
}
