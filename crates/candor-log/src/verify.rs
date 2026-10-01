// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline verification of one audit stream (`candorctl audit verify`, AUD-004).
//!
//! Detects: modified events (chain/Merkle mismatch), deleted events
//! (sequence gap / chain mismatch), reordering, non-canonical encodings,
//! forged or re-signed checkpoints, broken checkpoint chains, tail
//! truncation below the last checkpoint, rollback/fork relative to a
//! witness-held checkpoint (so truncation beyond the witnessed head,
//! AUD-RM1-LOG-19), and tombstones (disposal or retention) that do not carry
//! two valid signatures by distinct **pinned** disposal-approver keys
//! (AUD-RM1-LOG-16) or prune earlier than the configured retention
//! (AUD-RM1-LOG-20).

use core::fmt;
use std::collections::BTreeMap;

use ed25519_dalek::VerifyingKey;

use crate::cbor;
use crate::chain::{
    ChainRecord, SignedCheckpoint, StreamResume, case_tag_of_value, chain_hash, checkpoint_genesis,
    genesis, leaf_hash, merkle_root, record_commit, record_inner, redaction_set_hash,
    stream_of_code,
};
use crate::codes::{StreamId, VerifyFailureCode};
use crate::disposal::{Approval, ApproverKeys, RequestKind, SetCommit, request_bytes};
use crate::envelope::ENVELOPE_VERSION;
use crate::ids::{CaseRef, MS_PER_DAY, ReceiptId, TenantRef};
use crate::retention::RetentionPolicy;

/// Verification parameters.
#[derive(Clone, Copy, Debug)]
pub struct VerifyParams<'a> {
    /// Tenant the stream belongs to.
    pub tenant: TenantRef,
    /// Stream.
    pub stream: StreamId,
    /// Pinned instance checkpoint key (from C-14). Every checkpoint must
    /// verify under it.
    pub key: &'a VerifyingKey,
    /// Pinned disposal-approver keys: every tombstone must carry two valid
    /// signatures by distinct keys of this set (AUD-RM1-LOG-16).
    pub approver_keys: &'a ApproverKeys,
    /// Latest checkpoint held by the external witness, if any (rollback and
    /// truncation defence, AUD-RM1-LOG-19).
    pub trusted_latest: Option<&'a SignedCheckpoint>,
    /// Accept a store whose oldest whole checkpoint intervals were deleted by
    /// retention. Even then a pruned prefix is accepted only when a
    /// checkpointed retention tombstone in the same stream lists exactly the
    /// deleted range and the root of the last deleted checkpoint, and that
    /// checkpoint is older than the stream's minimum retention
    /// (AUD-RM1-LOG-01).
    pub allow_pruned_prefix: bool,
    /// The deployment's configured retention (days) for this stream, from
    /// the signed configuration: a prune younger than this fails even if
    /// it meets the 20 §12 minimum (AUD-RM1-LOG-20).
    pub min_retention_days: Option<u32>,
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
    /// Checkpoint key the stream was verified under (binds
    /// [`crate::field::Seq::of_failure`], AUD-RM1-LOG-17).
    pub(crate) origin: [u8; 32],
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "audit verify: {} at seq {}", self.code.code(), self.seq)
    }
}

impl std::error::Error for VerifyError {}

/// Failure before the key binding is attached.
#[derive(Clone, Copy)]
struct Fail(VerifyFailureCode, u64);

fn err(code: VerifyFailureCode, seq: u64) -> Fail {
    Fail(code, seq)
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
    /// Checkpoint key the stream was verified under (binds
    /// [`crate::field::SeqRange::within`]).
    pub(crate) origin: [u8; 32],
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
    /// Approved disposal tombstone: (case, this stream's set commitment).
    Disposed([u8; 16], SetCommit),
    /// Approved retention tombstone.
    Retention(Prune),
}

struct Prune {
    last: u64,
    root: [u8; 32],
    days: u32,
    ts: u64,
}

struct Parsed {
    seq: u64,
    prev: Option<[u8; 32]>,
    commit: [u8; 32],
    /// Redacted stub: (tombstone seq, case).
    redacted_by: Option<(u64, [u8; 16])>,
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

fn approvals_of(v: &cbor::Value) -> Option<[Approval; 2]> {
    match v {
        cbor::Value::Array(a) => match a.as_slice() {
            [x, y] => Some([Approval::from_value(x)?, Approval::from_value(y)?]),
            _ => None,
        },
        _ => None,
    }
}

/// `(tombstone type, set index)` of the disposal tombstone a stream's stubs
/// bind to.
fn disposal_type(stream: StreamId) -> Option<(&'static str, usize)> {
    match stream {
        StreamId::Case => Some(("case.disposed", 0)),
        StreamId::CaseSlot => Some(("case.slot_disposed", 1)),
        _ => None,
    }
}

fn retention_type(stream: StreamId) -> Option<&'static str> {
    match stream {
        StreamId::Sec => Some("audit.retention_tombstone"),
        StreamId::Sys => Some("sys.retention_tombstone"),
        StreamId::SysSlot => Some("sys.slot_retention_tombstone"),
        StreamId::Case | StreamId::CaseSlot => None,
    }
}

/// Decode and authenticate a tombstone; any defect is a failure (a
/// tombstone the writer would never have produced is evidence of forgery).
fn kind_of(v: &cbor::Value, p: &VerifyParams<'_>, seq: u64) -> Result<Kind, Fail> {
    let ty = v.get("type").and_then(cbor::Value::as_text);
    if let Some((name, i)) = disposal_type(p.stream)
        && ty == Some(name)
    {
        let bad = err(VerifyFailureCode::UnboundRedaction, seq);
        let d = v
            .get("payload")
            .and_then(|pl| pl.get("disposal"))
            .ok_or(bad)?;
        let case: [u8; 16] = d
            .get("case")
            .and_then(cbor::Value::as_bytes)
            .and_then(|b| b.try_into().ok())
            .ok_or(bad)?;
        let receipt: [u8; 16] = d
            .get("receipt_id")
            .and_then(cbor::Value::as_bytes)
            .and_then(|b| b.try_into().ok())
            .ok_or(bad)?;
        let sets = [
            d.get("case_set")
                .and_then(SetCommit::from_value)
                .ok_or(bad)?,
            d.get("slot_set")
                .and_then(SetCommit::from_value)
                .ok_or(bad)?,
        ];
        let total = u64::from(sets[0].count).saturating_add(u64::from(sets[1].count));
        if d.get("removed_event_count").and_then(cbor::Value::as_u64) != Some(total) {
            return Err(bad);
        }
        let approvals = d.get("approvals").and_then(approvals_of).ok_or(bad)?;
        let req = request_bytes(
            &p.tenant,
            &RequestKind::Case {
                case: CaseRef::from_bytes(case),
                receipt: ReceiptId::from_bytes(receipt),
                sets,
            },
        )
        .ok_or(bad)?;
        if !p.approver_keys.verify(&req, &approvals) {
            return Err(bad);
        }
        let set = *sets.get(i).ok_or(bad)?;
        return Ok(Kind::Disposed(case, set));
    }
    if let Some(name) = retention_type(p.stream)
        && ty == Some(name)
    {
        let bad = err(VerifyFailureCode::UnboundPrune, seq);
        let d = v.get("payload").and_then(|pl| pl.get("prune")).ok_or(bad)?;
        let stream = d
            .get("stream")
            .and_then(cbor::Value::as_text)
            .and_then(stream_of_code)
            .ok_or(bad)?;
        let last = match d.get("seq_range") {
            Some(cbor::Value::Array(a)) => match a.as_slice() {
                [_, l] => l.as_u64(),
                _ => None,
            },
            _ => None,
        }
        .ok_or(bad)?;
        let root = d
            .get("last_deleted_checkpoint_root")
            .and_then(cbor::Value::as_bytes32)
            .ok_or(bad)?;
        let days = d
            .get("retention_days")
            .and_then(cbor::Value::as_u64)
            .and_then(|x| u32::try_from(x).ok())
            .ok_or(bad)?;
        let approvals = d.get("approvals").and_then(approvals_of).ok_or(bad)?;
        let req = request_bytes(&p.tenant, &RequestKind::Retention { stream, days }).ok_or(bad)?;
        if stream != p.stream || !p.approver_keys.verify(&req, &approvals) {
            return Err(bad);
        }
        let ts = v.get("ts").and_then(cbor::Value::as_u64).ok_or(bad)?;
        return Ok(Kind::Retention(Prune {
            last,
            root,
            days,
            ts,
        }));
    }
    Ok(Kind::Other)
}

fn parse(r: &ChainRecord, p: &VerifyParams<'_>, expected: u64) -> Result<Parsed, Fail> {
    match r {
        ChainRecord::Redacted {
            seq,
            case,
            inner,
            tombstone_seq,
        } => {
            // Redaction exists only for per-case disposal (AUD-012).
            if disposal_type(p.stream).is_none() {
                return Err(err(VerifyFailureCode::UnboundRedaction, *seq));
            }
            Ok(Parsed {
                seq: *seq,
                prev: None,
                commit: record_commit(Some(case), inner),
                redacted_by: Some((*tombstone_seq, *case.as_bytes())),
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
            let tag = case_tag_of_value(p.stream, &v).map(CaseRef::from_bytes);
            Ok(Parsed {
                seq,
                prev: Some(prev),
                commit: record_commit(tag.as_ref(), &record_inner(salt, bytes)),
                redacted_by: None,
                claimed: *claimed_hash,
                kind: kind_of(&v, p, seq)?,
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
    let origin = p.key.to_bytes();
    verify_inner(p, records, checkpoints, origin).map_err(|Fail(code, seq)| VerifyError {
        code,
        seq,
        origin,
    })
}

fn verify_inner(
    p: &VerifyParams<'_>,
    records: &[ChainRecord],
    checkpoints: &[SignedCheckpoint],
    origin: [u8; 32],
) -> Result<VerifyReport, Fail> {
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
                    .filter(|_| p.allow_pruned_prefix && retention_type(p.stream).is_some())
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
    let mut stub_cases: BTreeMap<u64, Vec<[u8; 16]>> = BTreeMap::new();
    let mut disposals: BTreeMap<u64, ([u8; 16], SetCommit)> = BTreeMap::new();
    let mut retention: Vec<(u64, Prune)> = Vec::new();
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
        if let Some((t, case)) = rec.redacted_by {
            if t <= rec.seq {
                return Err(err(VerifyFailureCode::UnboundRedaction, rec.seq));
            }
            stubs.entry(t).or_default().push((rec.seq, rec.commit));
            stub_cases.entry(t).or_default().push(case);
            redacted = redacted.saturating_add(1);
        }
        match rec.kind {
            Kind::Disposed(case, set) => {
                disposals.insert(rec.seq, (case, set));
            }
            Kind::Retention(pr) => retention.push((rec.seq, pr)),
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

    // 5a. Every redacted stub is listed by a later, checkpointed,
    //     dual-approved disposal tombstone of this stream that names the
    //     stub's case and commits to exactly the stubs bound to it (count
    //     and (seq, commitment) set).
    for (tseq, set) in &stubs {
        let (case, commit) = disposals
            .get(tseq)
            .ok_or(err(VerifyFailureCode::UnboundRedaction, *tseq))?;
        let same_case = stub_cases
            .get(tseq)
            .is_some_and(|cs| cs.iter().all(|c| c == case));
        if *tseq >= attested_end
            || !same_case
            || u64::try_from(set.len()).ok() != Some(u64::from(commit.count))
            || redaction_set_hash(set) != commit.hash
        {
            return Err(err(VerifyFailureCode::UnboundRedaction, *tseq));
        }
    }
    // 5b. A pruned prefix needs a checkpointed, dual-approved retention
    //     tombstone in this stream naming exactly the deleted range end and
    //     the root of the anchor (last deleted) checkpoint, which must be
    //     older than the authorized retention, itself no shorter than the
    //     20 §12 minimum and the configured retention.
    if let Some(a) = anchor {
        let ab = a.body();
        let (spec_min, _) =
            RetentionPolicy::bounds(p.stream).ok_or(err(VerifyFailureCode::UnboundPrune, start))?;
        let floor = spec_min.max(p.min_retention_days.unwrap_or(0));
        let bound = retention.iter().any(|(tseq, pr)| {
            *tseq < attested_end
                && pr.last.checked_add(1) == Some(start)
                && pr.root == ab.merkle_root
                && pr.days >= floor
                && pr.ts.saturating_sub(ab.signed_at.0)
                    >= u64::from(pr.days).saturating_mul(MS_PER_DAY)
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
        origin,
    })
}
