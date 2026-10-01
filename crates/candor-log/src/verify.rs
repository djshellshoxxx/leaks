// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline verification of one audit stream (`candorctl audit verify`, AUD-004).
//!
//! Detects: modified events (chain/Merkle mismatch), deleted events
//! (sequence gap / chain mismatch), reordering, non-canonical encodings,
//! forged or re-signed checkpoints, broken checkpoint chains, tail
//! truncation below the last checkpoint, and rollback/fork relative to a
//! witness-held checkpoint.

use core::fmt;
use std::collections::BTreeMap;

use ed25519_dalek::VerifyingKey;

use crate::cbor;
use crate::chain::{
    ChainRecord, SignedCheckpoint, StreamResume, chain_hash, checkpoint_genesis, genesis,
    leaf_hash, merkle_root, record_commit, redaction_set_hash,
};
use crate::codes::{StreamId, VerifyFailureCode};
use crate::envelope::ENVELOPE_VERSION;
use crate::ids::{MS_PER_DAY, TenantRef};
use crate::retention::RetentionPolicy;

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
    /// retention. Even then a pruned prefix is accepted only when a
    /// checkpointed retention tombstone in the same stream lists exactly the
    /// deleted range and the root of the last deleted checkpoint, and that
    /// checkpoint is older than the stream's minimum retention
    /// (AUD-RM1-LOG-01).
    pub allow_pruned_prefix: bool,
}

/// Verification failure; `seq` is the first offending sequence number
/// (or checkpoint end). Only [`verify_stream`] creates one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
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

/// Successful verification summary. Only [`verify_stream`] creates one.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct VerifyReport {
    /// First retained sequence number (None if no records).
    pub first_seq: Option<u64>,
    /// Next sequence number.
    pub next_seq: u64,
    /// Chain head.
    pub head: [u8; 32],
    /// Records verified (full + redacted).
    pub records: u64,
    /// Redacted stubs among them (each bound to a checkpointed tombstone).
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

/// What a full record is, as far as the verifier cares.
enum Kind {
    Other,
    /// `case.disposed`: (removed count, redaction-set commitment).
    Disposed(u64, [u8; 32]),
    /// Retention tombstone: (stream code, last deleted seq, root, ts).
    Retention(String, u64, [u8; 32], u64),
}

struct Parsed {
    seq: u64,
    prev: Option<[u8; 32]>,
    commit: [u8; 32],
    redacted_by: Option<u64>,
    claimed: Option<[u8; 32]>,
    kind: Kind,
}

fn record_seq(r: &ChainRecord) -> Option<u64> {
    match r {
        ChainRecord::Redacted { seq, .. } => Some(*seq),
        ChainRecord::Full { bytes, .. } => cbor::decode(bytes)
            .ok()
            .and_then(|v| v.get("seq").and_then(cbor::Value::as_u64)),
    }
}

fn kind_of(v: &cbor::Value, stream: StreamId) -> Kind {
    let ty = v.get("type").and_then(cbor::Value::as_text);
    let pl = v.get("payload");
    let field = |k: &str| pl.and_then(|p| p.get(k));
    match (stream, ty) {
        (StreamId::Case, Some("case.disposed")) => {
            match (
                field("removed_event_count").and_then(cbor::Value::as_u64),
                field("redacted_set").and_then(cbor::Value::as_bytes32),
            ) {
                (Some(n), Some(h)) => Kind::Disposed(n, h),
                _ => Kind::Other,
            }
        }
        (StreamId::Sec, Some("audit.retention_tombstone"))
        | (StreamId::Sys, Some("sys.retention_tombstone")) => {
            let last = match field("seq_range") {
                Some(cbor::Value::Array(a)) => match a.as_slice() {
                    [_, l] => l.as_u64(),
                    _ => None,
                },
                _ => None,
            };
            match (
                field("stream").and_then(cbor::Value::as_text),
                last,
                field("last_deleted_checkpoint_root").and_then(cbor::Value::as_bytes32),
                v.get("ts").and_then(cbor::Value::as_u64),
            ) {
                (Some(s), Some(l), Some(r), Some(ts)) => Kind::Retention(s.to_owned(), l, r, ts),
                _ => Kind::Other,
            }
        }
        _ => Kind::Other,
    }
}

fn parse(r: &ChainRecord, p: &VerifyParams<'_>, expected: u64) -> Result<Parsed, VerifyError> {
    match r {
        ChainRecord::Redacted {
            seq,
            commit,
            tombstone_seq,
        } => {
            // Redaction exists only for per-case disposal (AUD-012).
            if p.stream != StreamId::Case {
                return Err(err(VerifyFailureCode::UnboundRedaction, *seq));
            }
            Ok(Parsed {
                seq: *seq,
                prev: None,
                commit: *commit,
                redacted_by: Some(*tombstone_seq),
                claimed: None,
                kind: Kind::Other,
            })
        }
        ChainRecord::Full {
            bytes,
            salt,
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
            Ok(Parsed {
                seq,
                prev: Some(prev),
                commit: record_commit(salt, bytes),
                redacted_by: None,
                claimed: *claimed_hash,
                kind: kind_of(&v, p.stream),
            })
        }
    }
}

/// Minimum age of deleted intervals at pruning: the lower retention bound
/// of the stream (20 §12).
fn min_retention_ms(s: StreamId) -> Option<u64> {
    let days = match s {
        StreamId::Sec => RetentionPolicy::SECURITY_BOUNDS.0,
        StreamId::Sys => RetentionPolicy::SYSTEM_BOUNDS.0,
        StreamId::Case => return None,
    };
    Some(u64::from(days).saturating_mul(MS_PER_DAY))
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
            return Err(err(VerifyFailureCode::BadSignature, b.end_seq));
        }
        if b.tenant != p.tenant
            || b.stream != p.stream
            || b.prev_checkpoint != prev_cp
            || b.first_seq != expected_first
            || b.end_seq < b.first_seq
        {
            return Err(err(VerifyFailureCode::CheckpointChain, b.end_seq));
        }
        prev_cp = cp.hash();
        expected_first = b.end_seq;
    }
    let attested_end = expected_first; // one past the last checkpointed seq

    // 2. Starting anchor. A pruned prefix needs an anchor checkpoint here
    //    and a tombstone, checked in step 5.
    let mut anchor: Option<&SignedCheckpoint> = None;
    let (start, mut head) = match records.first() {
        None if attested_end == 0 => (0, genesis(&p.tenant, p.stream)),
        // Every retention deletion leaves its (later) tombstone behind, so
        // an empty store with attested records is always a truncation.
        None => return Err(err(VerifyFailureCode::Truncated, 0)),
        Some(r) => {
            let s0 = record_seq(r).ok_or(err(VerifyFailureCode::NonCanonical, 0))?;
            if s0 == 0 {
                (0, genesis(&p.tenant, p.stream))
            } else {
                let a = checkpoints
                    .iter()
                    .find(|c| c.body().end_seq == s0 && !c.body().is_empty())
                    .filter(|_| p.allow_pruned_prefix && p.stream != StreamId::Case)
                    .ok_or(err(VerifyFailureCode::MissingPrefix, s0))?;
                anchor = Some(a);
                (s0, a.body().chain_head)
            }
        }
    };

    let initial_head = head;

    // 3. Walk the chain.
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(records.len().min(1 << 16));
    let mut heads: Vec<[u8; 32]> = Vec::with_capacity(records.len().min(1 << 16));
    let mut expected = start;
    let mut redacted: u64 = 0;
    let mut stubs: BTreeMap<u64, Vec<(u64, [u8; 32])>> = BTreeMap::new();
    let mut disposals: BTreeMap<u64, (u64, [u8; 32])> = BTreeMap::new();
    let mut retention: Vec<(u64, String, u64, [u8; 32], u64)> = Vec::new();
    for (pos, r) in records.iter().enumerate() {
        let rec = parse(r, p, expected)?;
        if rec.seq > expected {
            // Reordered if the expected record appears later; deleted otherwise.
            let later = records
                .get(pos.saturating_add(1)..)
                .unwrap_or_default()
                .iter()
                .any(|x| record_seq(x) == Some(expected));
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
        let hash = chain_hash(&head, &rec.commit);
        if rec.prev.is_some_and(|pv| pv != head) || rec.claimed.is_some_and(|c| c != hash) {
            return Err(err(VerifyFailureCode::ChainMismatch, rec.seq));
        }
        if let Some(t) = rec.redacted_by {
            if t <= rec.seq {
                return Err(err(VerifyFailureCode::UnboundRedaction, rec.seq));
            }
            stubs.entry(t).or_default().push((rec.seq, rec.commit));
            redacted = redacted.saturating_add(1);
        }
        match rec.kind {
            Kind::Disposed(n, h) => {
                disposals.insert(rec.seq, (n, h));
            }
            Kind::Retention(s, last, root, ts) => retention.push((rec.seq, s, last, root, ts)),
            Kind::Other => {}
        }
        head = hash;
        leaves.push(leaf_hash(&rec.commit));
        heads.push(hash);
        expected = expected
            .checked_add(1)
            .ok_or(err(VerifyFailureCode::SequenceOrder, rec.seq))?;
    }
    let end = expected; // one past the last record

    // 4. Checkpoint contents.
    let mut verified_cps: u64 = 0;
    for cp in checkpoints {
        let b = cp.body();
        if start > 0 && b.end_seq <= start {
            // Interval deleted by retention (bound by the tombstone check
            // below); signature and chain checked above.
            verified_cps = verified_cps.saturating_add(1);
            continue;
        }
        if b.first_seq < start {
            return Err(err(VerifyFailureCode::MissingPrefix, b.first_seq));
        }
        if b.end_seq > end {
            return Err(err(VerifyFailureCode::Truncated, end));
        }
        let lo = usize::try_from(b.first_seq.saturating_sub(start))
            .map_err(|_| err(VerifyFailureCode::Truncated, b.first_seq))?;
        let hi = usize::try_from(b.end_seq.saturating_sub(start))
            .map_err(|_| err(VerifyFailureCode::Truncated, b.end_seq))?;
        let slice = leaves
            .get(lo..hi)
            .ok_or(err(VerifyFailureCode::Truncated, b.end_seq))?;
        if merkle_root(slice) != b.merkle_root {
            return Err(err(VerifyFailureCode::MerkleMismatch, b.end_seq));
        }
        let expected_head = match hi.checked_sub(1) {
            Some(i) => heads.get(i).copied(),
            None => Some(initial_head),
        };
        if expected_head != Some(b.chain_head) {
            return Err(err(VerifyFailureCode::ChainMismatch, b.end_seq));
        }
        verified_cps = verified_cps.saturating_add(1);
    }
    if end < attested_end {
        return Err(err(VerifyFailureCode::Truncated, end));
    }

    // 5a. Every redacted stub is listed by a later, checkpointed
    //     `case.disposed` tombstone that commits to exactly the stubs bound
    //     to it (count and (seq, commitment) set).
    for (tseq, set) in &stubs {
        let (n, h) = disposals
            .get(tseq)
            .ok_or(err(VerifyFailureCode::UnboundRedaction, *tseq))?;
        if *tseq >= attested_end
            || u64::try_from(set.len()).ok() != Some(*n)
            || redaction_set_hash(set) != *h
        {
            return Err(err(VerifyFailureCode::UnboundRedaction, *tseq));
        }
    }
    // 5b. A pruned prefix needs a checkpointed retention tombstone in this
    //     stream naming exactly the deleted range end and the root of the
    //     anchor (last deleted) checkpoint, which must be older than the
    //     stream's minimum retention.
    if let Some(a) = anchor {
        let ab = a.body();
        let min_age =
            min_retention_ms(p.stream).ok_or(err(VerifyFailureCode::UnboundPrune, start))?;
        let bound = retention.iter().any(|(tseq, s, last, root, ts)| {
            *tseq < attested_end
                && s.as_str() == p.stream.code()
                && last.checked_add(1) == Some(start)
                && *root == ab.merkle_root
                && ts.saturating_sub(ab.signed_at.0) >= min_age
        });
        if !bound {
            return Err(err(VerifyFailureCode::UnboundPrune, start));
        }
    }

    // 6. Witness rollback / fork check.
    if let Some(w) = p.trusted_latest {
        let wb = w.body();
        if !w.verify_signature(p.key) || wb.tenant != p.tenant || wb.stream != p.stream {
            return Err(err(VerifyFailureCode::BadSignature, wb.end_seq));
        }
        if !checkpoints.iter().any(|c| c.hash() == w.hash()) {
            return Err(err(VerifyFailureCode::Rollback, wb.end_seq));
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
