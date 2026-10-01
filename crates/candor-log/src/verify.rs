// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline verification of one audit stream (`candorctl audit verify`, AUD-004).
//!
//! Detects: modified events (chain/Merkle mismatch), deleted events
//! (sequence gap / chain mismatch), reordering, non-canonical encodings,
//! forged or re-signed checkpoints, broken checkpoint chains, tail
//! truncation below the last checkpoint, and rollback/fork relative to a
//! witness-held checkpoint.

use core::fmt;

use ed25519_dalek::VerifyingKey;

use crate::cbor;
use crate::chain::{
    ChainRecord, SignedCheckpoint, StreamResume, chain_hash, checkpoint_genesis, genesis,
    leaf_hash, merkle_root,
};
use crate::codes::{StreamId, VerifyFailureCode};
use crate::envelope::ENVELOPE_VERSION;
use crate::ids::TenantRef;

/// Verification parameters.
#[derive(Clone, Copy, Debug)]
pub struct VerifyParams<'a> {
    /// Tenant the stream belongs to.
    pub tenant: TenantRef,
    /// Stream.
    pub stream: StreamId,
    /// Instance checkpoint key (from C-14).
    pub key: &'a VerifyingKey,
    /// Latest checkpoint held by the external witness, if any (rollback defence).
    pub trusted_latest: Option<&'a SignedCheckpoint>,
    /// Accept a store whose oldest whole checkpoint intervals were deleted by
    /// retention (the first record must then follow a checkpoint exactly).
    pub allow_pruned_prefix: bool,
}

/// Verification failure; `seq` is the first offending sequence number
/// (or checkpoint last-seq).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VerifyError {
    /// Failure code (also used for `audit.verification_failed`).
    pub code: VerifyFailureCode,
    /// Offending sequence number.
    pub seq: u64,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "audit verify: {} at seq {}", self.code.code(), self.seq)
    }
}

impl std::error::Error for VerifyError {}

fn err(code: VerifyFailureCode, seq: u64) -> VerifyError {
    VerifyError { code, seq }
}

/// Successful verification summary.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VerifyReport {
    /// First retained sequence number (None if no records).
    pub first_seq: Option<u64>,
    /// Next sequence number.
    pub next_seq: u64,
    /// Chain head.
    pub head: [u8; 32],
    /// Records verified (full + redacted).
    pub records: u64,
    /// Redacted stubs among them.
    pub redacted: u64,
    /// Checkpoints verified.
    pub checkpoints: u64,
    /// Records after the last checkpoint (not yet attested).
    pub unattested_tail: u64,
    /// Hash of the last checkpoint (or checkpoint genesis).
    pub last_checkpoint: [u8; 32],
    /// Leaves of the unattested tail (to resume writing).
    pub pending_leaves: Vec<[u8; 32]>,
}

impl VerifyReport {
    /// Resume point for [`crate::AuditLog::resume`].
    pub fn resume(&self) -> StreamResume {
        StreamResume {
            next_seq: self.next_seq,
            head: self.head,
            pending_leaves: self.pending_leaves.clone(),
            last_checkpoint: self.last_checkpoint,
        }
    }
}

struct Parsed {
    seq: u64,
    prev: [u8; 32],
    hash: [u8; 32],
    leaf: [u8; 32],
    redacted: bool,
    claimed: Option<[u8; 32]>,
}

fn record_seq(r: &ChainRecord) -> Result<u64, VerifyError> {
    match r {
        ChainRecord::Redacted { seq, .. } => Ok(*seq),
        ChainRecord::Full { bytes, .. } => cbor::decode(bytes)
            .ok()
            .and_then(|v| v.get("seq").and_then(cbor::Value::as_u64))
            .ok_or(err(VerifyFailureCode::NonCanonical, 0)),
    }
}

fn parse(
    r: &ChainRecord,
    head: &[u8; 32],
    p: &VerifyParams<'_>,
    expected: u64,
) -> Result<Parsed, VerifyError> {
    match r {
        ChainRecord::Redacted {
            seq,
            prev,
            leaf,
            hash,
        } => Ok(Parsed {
            seq: *seq,
            prev: *prev,
            hash: *hash,
            leaf: *leaf,
            redacted: true,
            claimed: None,
        }),
        ChainRecord::Full {
            bytes,
            claimed_hash,
        } => {
            let v =
                cbor::decode(bytes).map_err(|_| err(VerifyFailureCode::NonCanonical, expected))?;
            let mismatch = err(VerifyFailureCode::EnvelopeMismatch, expected);
            let seq = v.get("seq").and_then(cbor::Value::as_u64).ok_or(mismatch)?;
            if v.get("v").and_then(cbor::Value::as_u64) != Some(ENVELOPE_VERSION)
                || v.get("stream").and_then(cbor::Value::as_text) != Some(p.stream.code())
                || v.get("tenant").and_then(cbor::Value::as_bytes) != Some(p.tenant.as_bytes())
            {
                return Err(err(VerifyFailureCode::EnvelopeMismatch, seq));
            }
            let prev = v
                .get("prev")
                .and_then(cbor::Value::as_bytes32)
                .ok_or(err(VerifyFailureCode::EnvelopeMismatch, seq))?;
            let hash = chain_hash(head, bytes);
            Ok(Parsed {
                seq,
                prev,
                hash,
                leaf: leaf_hash(bytes),
                redacted: false,
                claimed: *claimed_hash,
            })
        }
    }
}

/// Verify one stream: records in stored order plus all retained checkpoints
/// (checkpoints are never deleted, 09 `audit_checkpoint`: permanent).
pub fn verify_stream(
    p: &VerifyParams<'_>,
    records: &[ChainRecord],
    checkpoints: &[SignedCheckpoint],
) -> Result<VerifyReport, VerifyError> {
    // 1. Checkpoint chain and signatures.
    let mut prev_cp = checkpoint_genesis(&p.tenant, p.stream);
    let mut expected_first: u64 = 0;
    for cp in checkpoints {
        let b = cp.body();
        if !cp.verify_signature(p.key) {
            return Err(err(VerifyFailureCode::BadSignature, b.last_seq));
        }
        if b.tenant != p.tenant
            || b.stream != p.stream
            || b.prev_checkpoint != prev_cp
            || b.first_seq != expected_first
            || b.last_seq < b.first_seq
        {
            return Err(err(VerifyFailureCode::CheckpointChain, b.last_seq));
        }
        prev_cp = cp.hash();
        expected_first = b
            .last_seq
            .checked_add(1)
            .ok_or(err(VerifyFailureCode::CheckpointChain, b.last_seq))?;
    }
    let attested_end = expected_first; // one past the last checkpointed seq

    // 2. Starting anchor.
    let (start, mut head) = match records.first() {
        None => {
            if attested_end == 0 {
                (0, genesis(&p.tenant, p.stream))
            } else if p.allow_pruned_prefix {
                let last = checkpoints
                    .last()
                    .map(|c| c.body().chain_head)
                    .ok_or(err(VerifyFailureCode::Truncated, 0))?;
                (attested_end, last)
            } else {
                return Err(err(VerifyFailureCode::Truncated, 0));
            }
        }
        Some(r) => {
            let s0 = record_seq(r)?;
            if s0 == 0 {
                (0, genesis(&p.tenant, p.stream))
            } else {
                let anchor = checkpoints
                    .iter()
                    .find(|c| c.body().last_seq.checked_add(1) == Some(s0))
                    .filter(|_| p.allow_pruned_prefix)
                    .ok_or(err(VerifyFailureCode::MissingPrefix, s0))?;
                (s0, anchor.body().chain_head)
            }
        }
    };

    // 3. Walk the chain.
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(records.len());
    let mut heads: Vec<[u8; 32]> = Vec::with_capacity(records.len());
    let mut expected = start;
    let mut redacted: u64 = 0;
    for (pos, r) in records.iter().enumerate() {
        let rec = parse(r, &head, p, expected)?;
        if rec.seq > expected {
            // Reordered if the expected record appears later; deleted otherwise.
            let later = records
                .get(pos.saturating_add(1)..)
                .unwrap_or_default()
                .iter()
                .any(|x| record_seq(x).ok() == Some(expected));
            let code = if later {
                VerifyFailureCode::SequenceOrder
            } else {
                VerifyFailureCode::SequenceGap
            };
            return Err(err(code, expected));
        }
        if rec.seq < expected {
            return Err(err(VerifyFailureCode::SequenceOrder, rec.seq));
        }
        if rec.prev != head || rec.claimed.is_some_and(|c| c != rec.hash) {
            return Err(err(VerifyFailureCode::ChainMismatch, rec.seq));
        }
        if rec.redacted {
            redacted = redacted.saturating_add(1);
        }
        head = rec.hash;
        leaves.push(rec.leaf);
        heads.push(rec.hash);
        expected = expected
            .checked_add(1)
            .ok_or(err(VerifyFailureCode::SequenceOrder, rec.seq))?;
    }
    let end = expected; // one past the last record

    // 4. Checkpoint contents.
    let mut verified_cps: u64 = 0;
    for cp in checkpoints {
        let b = cp.body();
        if b.last_seq < start {
            // Interval deleted by retention; signature and chain checked above.
            verified_cps = verified_cps.saturating_add(1);
            continue;
        }
        if b.first_seq < start {
            return Err(err(VerifyFailureCode::MissingPrefix, b.first_seq));
        }
        if b.last_seq >= end {
            return Err(err(VerifyFailureCode::Truncated, end));
        }
        let lo = usize::try_from(b.first_seq.saturating_sub(start))
            .map_err(|_| err(VerifyFailureCode::Truncated, b.first_seq))?;
        let hi = usize::try_from(b.last_seq.saturating_sub(start))
            .map_err(|_| err(VerifyFailureCode::Truncated, b.last_seq))?;
        let slice = leaves
            .get(lo..=hi)
            .ok_or(err(VerifyFailureCode::Truncated, b.last_seq))?;
        if merkle_root(slice) != b.merkle_root {
            return Err(err(VerifyFailureCode::MerkleMismatch, b.last_seq));
        }
        if heads.get(hi) != Some(&b.chain_head) {
            return Err(err(VerifyFailureCode::ChainMismatch, b.last_seq));
        }
        verified_cps = verified_cps.saturating_add(1);
    }
    if end < attested_end {
        return Err(err(VerifyFailureCode::Truncated, end));
    }

    // 5. Witness rollback / fork check.
    if let Some(w) = p.trusted_latest {
        let wb = w.body();
        if !w.verify_signature(p.key) || wb.tenant != p.tenant || wb.stream != p.stream {
            return Err(err(VerifyFailureCode::BadSignature, wb.last_seq));
        }
        let ours = checkpoints
            .iter()
            .find(|c| c.body().last_seq == wb.last_seq);
        match ours {
            Some(c) if c.hash() == w.hash() => {}
            _ => return Err(err(VerifyFailureCode::Rollback, wb.last_seq)),
        }
    }

    let tail_from = usize::try_from(attested_end.saturating_sub(start)).unwrap_or(usize::MAX);
    let pending_leaves = leaves
        .get(tail_from..)
        .map(<[_]>::to_vec)
        .unwrap_or_default();
    Ok(VerifyReport {
        first_seq: (!records.is_empty()).then_some(start),
        next_seq: end,
        head,
        records: u64::try_from(records.len()).unwrap_or(u64::MAX),
        redacted,
        checkpoints: verified_cps,
        unattested_tail: end.saturating_sub(attested_end.max(start)),
        last_checkpoint: prev_cp,
        pending_leaves,
    })
}
