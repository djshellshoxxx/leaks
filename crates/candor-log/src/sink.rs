// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sinks. A sink only ever receives [`CommittedRecord`]s and
//! [`SignedCheckpoint`]s, which only [`crate::AuditLog`] can create, so
//! every byte a sink writes went through the typed API.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Deserialize;

use crate::chain::{ChainRecord, CommittedRecord, SignedCheckpoint};
use crate::codes::StreamId;
use crate::event::AuditEvent;
use crate::ids::{CaseRef, hex, unhex};

/// Sink failure (no data echoed).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SinkError {
    /// I/O error.
    Io,
    /// Lock poisoned.
    Poisoned,
}

/// Destination for committed records and checkpoints.
pub trait AuditSink {
    /// Persist one record (must be durable before returning for the primary sink).
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

    /// Per-case redaction at disposal (AUD-012): every CASE event of `case`
    /// becomes a hash-only stub. Returns the number of events removed; the
    /// caller then emits `case.disposed` with that count.
    pub fn redact_case(&mut self, case: CaseRef) -> u32 {
        let mut n: u32 = 0;
        if let Some(v) = self.entries.get_mut(&StreamId::Case) {
            for e in v.iter_mut() {
                let hit = e.record.as_ref().is_some_and(|r| {
                    r.event().case_ref() == Some(case)
                        && !matches!(r.event(), AuditEvent::CaseDisposed { .. })
                });
                if hit {
                    if let Some(r) = e.record.take() {
                        e.chain = r.to_redacted();
                        n = n.saturating_add(1);
                    }
                }
            }
        }
        n
    }

    /// Delete records with `seq <= through_seq` (retention). Callers must use
    /// [`crate::retention::apply_interval_deletion`], which enforces whole
    /// intervals and a preceding tombstone.
    pub(crate) fn drop_through(&mut self, s: StreamId, through_seq: u64) {
        if let Some(v) = self.entries.get_mut(&s) {
            v.retain(|e| match &e.record {
                Some(r) => r.header().seq > through_seq,
                None => match e.chain {
                    ChainRecord::Redacted { seq, .. } => seq > through_seq,
                    ChainRecord::Full { .. } => true,
                },
            });
        }
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

/// Append-only JSON-lines file sink, one file per stream
/// (`audit-<stream>.jsonl`) plus `checkpoints-<stream>.jsonl`.
///
/// Lines contain only static type names, integers and hex; the payload is
/// the canonical CBOR in hex. Files are created mode 0600 on Unix.
#[derive(Debug)]
pub struct JsonlFileSink {
    dir: PathBuf,
    durable: bool,
    files: BTreeMap<String, File>,
}

impl JsonlFileSink {
    /// Sink writing under `dir`; `durable` fsyncs after every line.
    pub fn new(dir: impl Into<PathBuf>, durable: bool) -> Self {
        Self {
            dir: dir.into(),
            durable,
            files: BTreeMap::new(),
        }
    }

    fn append(&mut self, name: String, line: &str) -> Result<(), SinkError> {
        let f = match self.files.get_mut(&name) {
            Some(f) => f,
            None => {
                let path = self.dir.join(&name);
                let mut oo = OpenOptions::new();
                oo.create(true).append(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    oo.mode(0o600);
                }
                let f = oo.open(path).map_err(|_| SinkError::Io)?;
                self.files.entry(name).or_insert(f)
            }
        };
        f.write_all(line.as_bytes()).map_err(|_| SinkError::Io)?;
        f.write_all(b"\n").map_err(|_| SinkError::Io)?;
        if self.durable {
            f.sync_data().map_err(|_| SinkError::Io)?;
        }
        Ok(())
    }
}

/// Record line.
pub fn record_line(r: &CommittedRecord) -> String {
    format!(
        "{{\"k\":\"rec\",\"stream\":\"{}\",\"seq\":{},\"type\":\"{}\",\"hash\":\"{}\",\"cbor\":\"{}\"}}",
        r.header().stream.code(),
        r.header().seq,
        r.event().type_name(),
        hex(r.hash()),
        hex(r.bytes())
    )
}

/// Redacted-stub line.
pub fn redacted_line(stream: StreamId, c: &ChainRecord) -> Option<String> {
    match c {
        ChainRecord::Redacted {
            seq,
            prev,
            leaf,
            hash,
        } => Some(format!(
            "{{\"k\":\"red\",\"stream\":\"{}\",\"seq\":{},\"prev\":\"{}\",\"leaf\":\"{}\",\"hash\":\"{}\"}}",
            stream.code(),
            seq,
            hex(prev),
            hex(leaf),
            hex(hash)
        )),
        ChainRecord::Full { .. } => None,
    }
}

/// Checkpoint line.
pub fn checkpoint_line(cp: &SignedCheckpoint) -> String {
    format!(
        "{{\"k\":\"cp\",\"stream\":\"{}\",\"last_seq\":{},\"cbor\":\"{}\",\"sig\":\"{}\"}}",
        cp.body().stream.code(),
        cp.body().last_seq,
        hex(cp.bytes()),
        hex(cp.signature())
    )
}

impl AuditSink for JsonlFileSink {
    fn write_record(&mut self, r: &CommittedRecord) -> Result<(), SinkError> {
        let name = format!("audit-{}.jsonl", r.header().stream.code());
        self.append(name, &record_line(r))
    }
    fn write_checkpoint(&mut self, cp: &SignedCheckpoint) -> Result<(), SinkError> {
        let name = format!("checkpoints-{}.jsonl", cp.body().stream.code());
        self.append(name, &checkpoint_line(cp))
    }
}

/// JSONL read errors (no input echoed).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReadError {
    /// I/O error.
    Io,
    /// Line too long.
    LineTooLong,
    /// Malformed line.
    Malformed,
    /// Line belongs to another stream.
    WrongStream,
}

/// Maximum accepted JSONL line length.
pub const MAX_LINE: usize = 1 << 20;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Line {
    k: String,
    stream: String,
    seq: Option<u64>,
    last_seq: Option<u64>,
    #[serde(rename = "type")]
    _type: Option<String>,
    hash: Option<String>,
    cbor: Option<String>,
    prev: Option<String>,
    leaf: Option<String>,
    sig: Option<String>,
}

fn h32(s: Option<&String>) -> Result<[u8; 32], ReadError> {
    s.and_then(|s| unhex(s))
        .and_then(|b| b.try_into().ok())
        .ok_or(ReadError::Malformed)
}

fn read_lines(path: &Path) -> Result<Vec<Line>, ReadError> {
    let f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(ReadError::Io),
    };
    let mut out = Vec::new();
    for line in BufReader::new(f).lines() {
        let line = line.map_err(|_| ReadError::Io)?;
        if line.len() > MAX_LINE {
            return Err(ReadError::LineTooLong);
        }
        if line.is_empty() {
            continue;
        }
        out.push(serde_json::from_str::<Line>(&line).map_err(|_| ReadError::Malformed)?);
    }
    Ok(out)
}

/// Read a stream written by [`JsonlFileSink`] back for verification.
pub fn read_stream(
    dir: &Path,
    stream: StreamId,
) -> Result<(Vec<ChainRecord>, Vec<SignedCheckpoint>), ReadError> {
    let mut recs = Vec::new();
    for l in read_lines(&dir.join(format!("audit-{}.jsonl", stream.code())))? {
        if l.stream != stream.code() {
            return Err(ReadError::WrongStream);
        }
        match l.k.as_str() {
            "rec" => {
                let bytes = l.cbor.as_deref().and_then(unhex).ok_or(ReadError::Malformed)?;
                recs.push(ChainRecord::Full {
                    bytes,
                    claimed_hash: Some(h32(l.hash.as_ref())?),
                });
            }
            "red" => recs.push(ChainRecord::Redacted {
                seq: l.seq.ok_or(ReadError::Malformed)?,
                prev: h32(l.prev.as_ref())?,
                leaf: h32(l.leaf.as_ref())?,
                hash: h32(l.hash.as_ref())?,
            }),
            _ => return Err(ReadError::Malformed),
        }
    }
    let mut cps = Vec::new();
    for l in read_lines(&dir.join(format!("checkpoints-{}.jsonl", stream.code())))? {
        if l.stream != stream.code() || l.k != "cp" || l.last_seq.is_none() {
            return Err(ReadError::Malformed);
        }
        let bytes = l.cbor.as_deref().and_then(unhex).ok_or(ReadError::Malformed)?;
        let sig: [u8; 64] = l
            .sig
            .as_deref()
            .and_then(unhex)
            .and_then(|b| b.try_into().ok())
            .ok_or(ReadError::Malformed)?;
        cps.push(SignedCheckpoint::from_parts(bytes, sig).map_err(|_| ReadError::Malformed)?);
    }
    Ok((recs, cps))
}
