// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sinks. A sink only ever receives [`CommittedRecord`]s and
//! [`SignedCheckpoint`]s, which only [`crate::AuditLog`] can create, so
//! every byte a sink writes went through the typed API.

use std::collections::BTreeMap;
use std::io::BufRead;
use std::sync::{Arc, Mutex};

use serde::Deserialize;

use crate::chain::{ChainRecord, CommittedRecord, SignedCheckpoint, redaction_set_hash};
use crate::codes::StreamId;
use crate::disposal::{DisposalRequest, RequestKind, SetCommit};
use crate::event::AuditEvent;
use crate::ids::{CaseRef, ReceiptId, TenantRef, hex, unhex};

/// Sink failure (no data echoed).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SinkError {
    /// I/O error.
    Io,
    /// Lock poisoned.
    Poisoned,
}

/// Destination for committed records and checkpoints.
///
/// A sink used as the **primary** must make each write atomic and durable
/// before returning `Ok` (all or nothing; on `Err` nothing may become
/// visible), because the primary is the commit point of the chain.
pub trait AuditSink {
    /// Persist one record (including [`CommittedRecord::salt`]).
    fn write_record(&mut self, r: &CommittedRecord) -> Result<(), SinkError>;
    /// Persist one checkpoint.
    fn write_checkpoint(&mut self, cp: &SignedCheckpoint) -> Result<(), SinkError>;
}

/// An in-memory store entry.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StoredEntry {
    /// The typed record, `None` once redacted.
    pub record: Option<CommittedRecord>,
    /// Verification form.
    pub chain: ChainRecord,
}

impl StoredEntry {
    fn seq(&self) -> Option<u64> {
        match (&self.record, &self.chain) {
            (Some(r), _) => Some(r.header().seq),
            (None, ChainRecord::Redacted { seq, .. }) => Some(*seq),
            (None, ChainRecord::Full { .. }) => None,
        }
    }
}

/// Read access to a store's redactable records, so any C-24 store (not
/// only [`MemoryStore`]) can plan a disposal (AUD-RM1-LOG-23).
pub trait CaseRecordSource {
    /// `(seq, c_i)` of every full record of `stream` bound to `case`
    /// ([`CommittedRecord::case_tag`]), in sequence order.
    fn case_records(&self, stream: StreamId, case: CaseRef) -> Vec<(u64, [u8; 32])>;
}

/// The exact set of CASE and CASE-SLOT records to redact for one case at
/// disposal, and the commitments its dual-approved tombstones carry
/// (AUD-012, AUD-RM1-LOG-01/16). A plan from a misbehaving source cannot
/// redact another case's records: each stub must name the tombstone's case,
/// which its record commitment binds.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RedactionPlan {
    case: CaseRef,
    /// `[CASE, CASE-SLOT]`.
    entries: [Vec<(u64, [u8; 32])>; 2],
}

fn plan_index(stream: StreamId) -> Option<usize> {
    match stream {
        StreamId::Case => Some(0),
        StreamId::CaseSlot => Some(1),
        _ => None,
    }
}

impl RedactionPlan {
    /// Plan the disposal of `case` from `source`.
    pub fn build(source: &impl CaseRecordSource, case: CaseRef) -> Self {
        Self {
            case,
            entries: [
                source.case_records(StreamId::Case, case),
                source.case_records(StreamId::CaseSlot, case),
            ],
        }
    }
    /// The case.
    pub fn case(&self) -> CaseRef {
        self.case
    }
    /// Number of records to redact (both streams).
    pub fn len(&self) -> usize {
        self.entries.iter().map(Vec::len).sum()
    }
    /// Whether nothing is to be redacted.
    pub fn is_empty(&self) -> bool {
        self.entries.iter().all(Vec::is_empty)
    }
    pub(crate) fn set_commits(&self) -> [SetCommit; 2] {
        self.entries.each_ref().map(|e| SetCommit {
            count: u32::try_from(e.len()).unwrap_or(u32::MAX),
            hash: redaction_set_hash(e),
        })
    }
    /// The request the disposal approvers sign.
    pub fn request(&self, tenant: TenantRef, receipt_id: ReceiptId) -> Option<DisposalRequest> {
        DisposalRequest::new(
            tenant,
            RequestKind::Case {
                case: self.case,
                receipt: receipt_id,
                sets: self.set_commits(),
            },
        )
    }
}

/// Redaction errors.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RedactionError {
    /// No tombstone for this plan in the stream.
    TombstoneMismatch,
    /// The tombstone does not follow every planned record.
    TombstoneOrder,
    /// A planned record is no longer present in full.
    StoreChanged,
    /// Redaction exists only in the CASE and CASE-SLOT streams.
    WrongStream,
}

/// In-memory class-separated store (tests, C-24 cache, SIEM gateway feed).
#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    entries: BTreeMap<StreamId, Vec<StoredEntry>>,
    checkpoints: BTreeMap<StreamId, Vec<SignedCheckpoint>>,
}

impl MemoryStore {
    /// Stored chain records of a stream.
    pub fn chain(&self, s: StreamId) -> Vec<ChainRecord> {
        self.entries
            .get(&s)
            .map(|v| v.iter().map(|e| e.chain.clone()).collect())
            .unwrap_or_default()
    }
    /// Typed records of a stream (redacted ones skipped).
    pub fn records(&self, s: StreamId) -> Vec<CommittedRecord> {
        self.entries
            .get(&s)
            .map(|v| v.iter().filter_map(|e| e.record.clone()).collect())
            .unwrap_or_default()
    }
    /// Checkpoints of a stream.
    pub fn checkpoints(&self, s: StreamId) -> Vec<SignedCheckpoint> {
        self.checkpoints.get(&s).cloned().unwrap_or_default()
    }

    /// Plan per-case redaction (AUD-012) of every full CASE / CASE-SLOT
    /// record bound to `case`.
    pub fn plan_case_redaction(&self, case: CaseRef) -> RedactionPlan {
        RedactionPlan::build(self, case)
    }

    /// Apply the `stream` part of a plan after that stream's tombstone
    /// (written by [`crate::AuditLog::emit_case_disposal`]) is stored: each
    /// planned record becomes a stub `{seq, case, inner, tombstone_seq}`;
    /// content and salt are dropped (all or nothing). Apply to CASE and,
    /// after its slot boundary, CASE-SLOT; then destroy the case key.
    /// Returns the number redacted.
    pub fn apply_case_redaction(
        &mut self,
        plan: &RedactionPlan,
        stream: StreamId,
    ) -> Result<u32, RedactionError> {
        let i = plan_index(stream).ok_or(RedactionError::WrongStream)?;
        let entries = plan.entries.get(i).ok_or(RedactionError::WrongStream)?;
        let sets = plan.set_commits();
        let v = self.entries.entry(stream).or_default();
        let tseq = v
            .iter()
            .filter_map(|e| e.record.as_ref())
            .find(|r| match r.event() {
                AuditEvent::CaseDisposed { disposal }
                | AuditEvent::CaseSlotDisposed { disposal } => {
                    disposal.case == plan.case && disposal.sets == sets
                }
                _ => false,
            })
            .map(|r| r.header().seq)
            .ok_or(RedactionError::TombstoneMismatch)?;
        if entries.iter().any(|(s, _)| *s >= tseq) {
            return Err(RedactionError::TombstoneOrder);
        }
        // Check first, then mutate (all or nothing).
        for (seq, commit) in entries {
            let ok = v.iter().any(|e| {
                e.record.as_ref().is_some_and(|r| {
                    r.header().seq == *seq
                        && r.commit() == commit
                        && r.case_tag() == Some(plan.case)
                })
            });
            if !ok {
                return Err(RedactionError::StoreChanged);
            }
        }
        let mut n: u32 = 0;
        for e in v.iter_mut() {
            let hit = e.record.as_ref().is_some_and(|r| {
                entries
                    .iter()
                    .any(|(s, c)| r.header().seq == *s && r.commit() == c)
            });
            if !hit {
                continue;
            }
            let stub = e.record.as_ref().and_then(|r| r.to_stub(tseq));
            if let Some(stub) = stub {
                e.record = None;
                e.chain = stub;
                n = n.saturating_add(1);
            }
        }
        Ok(n)
    }

    /// Delete records with `seq <= through_seq` (retention). Callers must use
    /// [`crate::retention::apply_interval_deletion`], which enforces whole
    /// intervals and a preceding, checkpointed tombstone.
    pub(crate) fn drop_through(&mut self, s: StreamId, through_seq: u64) {
        if let Some(v) = self.entries.get_mut(&s) {
            v.retain(|e| e.seq().is_none_or(|q| q > through_seq));
        }
    }

    /// Replace the stored chain form of record `seq` (tamper tests only).
    #[doc(hidden)]
    pub fn tamper_replace(&mut self, s: StreamId, seq: u64, c: ChainRecord) -> bool {
        let Some(e) = self
            .entries
            .get_mut(&s)
            .and_then(|v| v.iter_mut().find(|e| e.seq() == Some(seq)))
        else {
            return false;
        };
        e.record = None;
        e.chain = c;
        true
    }
}

impl CaseRecordSource for MemoryStore {
    fn case_records(&self, stream: StreamId, case: CaseRef) -> Vec<(u64, [u8; 32])> {
        self.entries
            .get(&stream)
            .map(|v| {
                v.iter()
                    .filter_map(|e| e.record.as_ref())
                    .filter(|r| r.case_tag() == Some(case))
                    .map(|r| (r.header().seq, *r.commit()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Shared handle to a [`MemoryStore`] usable as a sink.
#[derive(Clone, Debug, Default)]
pub struct MemorySink(pub Arc<Mutex<MemoryStore>>);

impl MemorySink {
    /// New empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl AuditSink for MemorySink {
    fn write_record(&mut self, r: &CommittedRecord) -> Result<(), SinkError> {
        let mut g = self.0.lock().map_err(|_| SinkError::Poisoned)?;
        g.entries
            .entry(r.header().stream)
            .or_default()
            .push(StoredEntry {
                record: Some(r.clone()),
                chain: r.to_chain_record(),
            });
        Ok(())
    }
    fn write_checkpoint(&mut self, cp: &SignedCheckpoint) -> Result<(), SinkError> {
        let mut g = self.0.lock().map_err(|_| SinkError::Poisoned)?;
        g.checkpoints
            .entry(cp.body().stream)
            .or_default()
            .push(cp.clone());
        Ok(())
    }
}

/// One JSON-lines file of the audit store.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum JsonlFile {
    /// `audit-<stream>.jsonl`.
    Records(StreamId),
    /// `checkpoints-<stream>.jsonl`.
    Checkpoints(StreamId),
}

impl JsonlFile {
    /// Conventional file name (static, no caller data).
    pub fn file_name(self) -> &'static str {
        match self {
            Self::Records(StreamId::Sec) => "audit-sec.jsonl",
            Self::Records(StreamId::Case) => "audit-case.jsonl",
            Self::Records(StreamId::Sys) => "audit-sys.jsonl",
            Self::Records(StreamId::CaseSlot) => "audit-case-slot.jsonl",
            Self::Records(StreamId::SysSlot) => "audit-sys-slot.jsonl",
            Self::Checkpoints(StreamId::Sec) => "checkpoints-sec.jsonl",
            Self::Checkpoints(StreamId::Case) => "checkpoints-case.jsonl",
            Self::Checkpoints(StreamId::Sys) => "checkpoints-sys.jsonl",
            Self::Checkpoints(StreamId::CaseSlot) => "checkpoints-case-slot.jsonl",
            Self::Checkpoints(StreamId::SysSlot) => "checkpoints-sys-slot.jsonl",
        }
    }
}

/// Append-only storage behind [`JsonlFileSink`]. The C-24 service
/// implements it over files it opened through the single audited safe-path
/// API (`candor-safefs`, ADR-027) with mode 0600, append-only flags and
/// `fsync` per line; this crate performs no path handling itself.
pub trait JsonlTarget {
    /// Durably append one line (without the newline) to `file`.
    fn append_line(&mut self, file: JsonlFile, line: &[u8]) -> std::io::Result<()>;
}

/// In-memory [`JsonlTarget`] (tests, support tooling).
#[derive(Clone, Debug, Default)]
pub struct MemoryJsonl {
    files: BTreeMap<JsonlFile, Vec<u8>>,
}

impl MemoryJsonl {
    /// Contents of one file.
    pub fn contents(&self, f: JsonlFile) -> &[u8] {
        self.files.get(&f).map(Vec::as_slice).unwrap_or_default()
    }
    /// Mutable contents (tamper tests).
    pub fn contents_mut(&mut self, f: JsonlFile) -> &mut Vec<u8> {
        self.files.entry(f).or_default()
    }
}

impl JsonlTarget for MemoryJsonl {
    fn append_line(&mut self, file: JsonlFile, line: &[u8]) -> std::io::Result<()> {
        let v = self.files.entry(file).or_default();
        v.extend_from_slice(line);
        v.push(b'\n');
        Ok(())
    }
}

/// Append-only JSON-lines sink, one file per stream plus one checkpoint
/// file per stream (class-separated). Lines contain only static type names,
/// integers and hex; the payload is the canonical CBOR in hex.
#[derive(Debug)]
pub struct JsonlFileSink<T: JsonlTarget> {
    target: T,
}

impl<T: JsonlTarget> JsonlFileSink<T> {
    /// Sink over `target`.
    pub fn new(target: T) -> Self {
        Self { target }
    }
    /// Borrow the target.
    pub fn target(&self) -> &T {
        &self.target
    }
    /// Recover the target.
    pub fn into_target(self) -> T {
        self.target
    }
}

/// Record line (the salt is stored next to the record so a verifier can
/// recompute the commitment; it is deleted with the record at redaction).
pub fn record_line(r: &CommittedRecord) -> String {
    format!(
        "{{\"k\":\"rec\",\"stream\":\"{}\",\"seq\":{},\"type\":\"{}\",\"hash\":\"{}\",\"salt\":\"{}\",\"cbor\":\"{}\"}}",
        r.header().stream.code(),
        r.header().seq,
        r.event().type_name(),
        hex(r.hash()),
        hex(r.salt()),
        hex(r.bytes())
    )
}

/// Redacted-stub line.
pub fn redacted_line(stream: StreamId, c: &ChainRecord) -> Option<String> {
    match c {
        ChainRecord::Redacted {
            seq,
            case,
            inner,
            tombstone_seq,
        } => Some(format!(
            "{{\"k\":\"red\",\"stream\":\"{}\",\"seq\":{},\"case\":\"{}\",\"inner\":\"{}\",\"tomb\":{}}}",
            stream.code(),
            seq,
            hex(case.as_bytes()),
            hex(inner),
            tombstone_seq
        )),
        ChainRecord::Full { .. } => None,
    }
}

/// Checkpoint line.
pub fn checkpoint_line(cp: &SignedCheckpoint) -> String {
    format!(
        "{{\"k\":\"cp\",\"stream\":\"{}\",\"end_seq\":{},\"cbor\":\"{}\",\"sig\":\"{}\"}}",
        cp.body().stream.code(),
        cp.body().end_seq,
        hex(cp.bytes()),
        hex(cp.signature())
    )
}

impl<T: JsonlTarget> AuditSink for JsonlFileSink<T> {
    fn write_record(&mut self, r: &CommittedRecord) -> Result<(), SinkError> {
        self.target
            .append_line(
                JsonlFile::Records(r.header().stream),
                record_line(r).as_bytes(),
            )
            .map_err(|_| SinkError::Io)
    }
    fn write_checkpoint(&mut self, cp: &SignedCheckpoint) -> Result<(), SinkError> {
        self.target
            .append_line(
                JsonlFile::Checkpoints(cp.body().stream),
                checkpoint_line(cp).as_bytes(),
            )
            .map_err(|_| SinkError::Io)
    }
}

/// A [`JsonlFileSink`] shared between the log and a reader.
#[derive(Clone, Debug, Default)]
pub struct SharedJsonl(pub Arc<Mutex<MemoryJsonl>>);

impl AuditSink for SharedJsonl {
    fn write_record(&mut self, r: &CommittedRecord) -> Result<(), SinkError> {
        let mut g = self.0.lock().map_err(|_| SinkError::Poisoned)?;
        g.append_line(
            JsonlFile::Records(r.header().stream),
            record_line(r).as_bytes(),
        )
        .map_err(|_| SinkError::Io)
    }
    fn write_checkpoint(&mut self, cp: &SignedCheckpoint) -> Result<(), SinkError> {
        let mut g = self.0.lock().map_err(|_| SinkError::Poisoned)?;
        g.append_line(
            JsonlFile::Checkpoints(cp.body().stream),
            checkpoint_line(cp).as_bytes(),
        )
        .map_err(|_| SinkError::Io)
    }
}

/// JSONL read errors (no input echoed).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReadError {
    /// I/O error.
    Io,
    /// Line too long.
    LineTooLong,
    /// Too many lines.
    TooManyLines,
    /// Malformed line.
    Malformed,
    /// Line metadata (`type`, `seq`, `end_seq`) disagrees with its CBOR.
    MetadataMismatch,
    /// Line belongs to another stream.
    WrongStream,
}

/// Maximum accepted JSONL line length.
pub const MAX_LINE: usize = 1 << 20;
/// Maximum number of lines read from one file in one call (AUD-RM1-LOG-13).
pub const MAX_LINES: usize = 1 << 22;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Line {
    k: String,
    stream: String,
    seq: Option<u64>,
    end_seq: Option<u64>,
    #[serde(rename = "type")]
    ty: Option<String>,
    hash: Option<String>,
    salt: Option<String>,
    cbor: Option<String>,
    case: Option<String>,
    inner: Option<String>,
    tomb: Option<u64>,
    sig: Option<String>,
}

fn h32(s: Option<&String>) -> Result<[u8; 32], ReadError> {
    s.and_then(|s| unhex(s))
        .and_then(|b| b.try_into().ok())
        .ok_or(ReadError::Malformed)
}

fn read_lines(r: impl BufRead, max_lines: usize) -> Result<Vec<Line>, ReadError> {
    let mut out = Vec::new();
    let mut r = r;
    loop {
        let mut buf = Vec::new();
        // Bounded read: never buffer more than MAX_LINE + 1 bytes per line.
        let n = std::io::Read::take(
            &mut r,
            u64::try_from(MAX_LINE)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_until(b'\n', &mut buf)
        .map_err(|_| ReadError::Io)?;
        if n == 0 {
            break;
        }
        if buf.last() == Some(&b'\n') {
            buf.pop();
        } else if buf.len() > MAX_LINE {
            return Err(ReadError::LineTooLong);
        }
        let line = String::from_utf8(buf).map_err(|_| ReadError::Malformed)?;
        if line.is_empty() {
            continue;
        }
        if out.len() >= max_lines {
            return Err(ReadError::TooManyLines);
        }
        out.push(serde_json::from_str::<Line>(&line).map_err(|_| ReadError::Malformed)?);
    }
    Ok(out)
}

/// Read a stream written by [`JsonlFileSink`] back for verification, from
/// the record file and the checkpoint file of `stream`. Every line's
/// metadata is cross-checked against its CBOR (AUD-RM1-LOG-13).
pub fn read_stream(
    stream: StreamId,
    records: impl BufRead,
    checkpoints: impl BufRead,
) -> Result<(Vec<ChainRecord>, Vec<SignedCheckpoint>), ReadError> {
    let mut recs = Vec::new();
    for l in read_lines(records, MAX_LINES)? {
        if l.stream != stream.code() {
            return Err(ReadError::WrongStream);
        }
        match l.k.as_str() {
            "rec" => {
                if l.case.is_some()
                    || l.inner.is_some()
                    || l.tomb.is_some()
                    || l.sig.is_some()
                    || l.end_seq.is_some()
                {
                    return Err(ReadError::Malformed);
                }
                let bytes = l
                    .cbor
                    .as_deref()
                    .and_then(unhex)
                    .ok_or(ReadError::Malformed)?;
                let v = crate::cbor::decode(&bytes).map_err(|_| ReadError::Malformed)?;
                if v.get("seq").and_then(crate::cbor::Value::as_u64) != l.seq
                    || v.get("type").and_then(crate::cbor::Value::as_text) != l.ty.as_deref()
                    || l.seq.is_none()
                {
                    return Err(ReadError::MetadataMismatch);
                }
                recs.push(ChainRecord::Full {
                    bytes,
                    salt: h32(l.salt.as_ref())?,
                    claimed_hash: Some(h32(l.hash.as_ref())?),
                });
            }
            "red" => {
                if l.cbor.is_some()
                    || l.salt.is_some()
                    || l.hash.is_some()
                    || l.ty.is_some()
                    || l.sig.is_some()
                    || l.end_seq.is_some()
                {
                    return Err(ReadError::Malformed);
                }
                let case: [u8; 16] = l
                    .case
                    .as_deref()
                    .and_then(unhex)
                    .and_then(|b| b.try_into().ok())
                    .ok_or(ReadError::Malformed)?;
                recs.push(ChainRecord::Redacted {
                    seq: l.seq.ok_or(ReadError::Malformed)?,
                    case: CaseRef::from_bytes(case),
                    inner: h32(l.inner.as_ref())?,
                    tombstone_seq: l.tomb.ok_or(ReadError::Malformed)?,
                });
            }
            _ => return Err(ReadError::Malformed),
        }
    }
    let mut cps = Vec::new();
    for l in read_lines(checkpoints, MAX_LINES)? {
        if l.stream != stream.code()
            || l.k != "cp"
            || l.case.is_some()
            || l.inner.is_some()
            || l.tomb.is_some()
            || l.salt.is_some()
            || l.hash.is_some()
            || l.ty.is_some()
            || l.seq.is_some()
        {
            return Err(ReadError::Malformed);
        }
        let bytes = l
            .cbor
            .as_deref()
            .and_then(unhex)
            .ok_or(ReadError::Malformed)?;
        let sig: [u8; 64] = l
            .sig
            .as_deref()
            .and_then(unhex)
            .and_then(|b| b.try_into().ok())
            .ok_or(ReadError::Malformed)?;
        let cp = SignedCheckpoint::from_parts(bytes, sig).map_err(|_| ReadError::Malformed)?;
        if l.end_seq != Some(cp.body().end_seq) {
            return Err(ReadError::MetadataMismatch);
        }
        cps.push(cp);
    }
    Ok((recs, cps))
}
