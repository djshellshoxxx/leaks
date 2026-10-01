// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hash chain, RFC 6962 Merkle checkpoints, Ed25519 checkpoint signing and
//! the [`AuditLog`] writer (20 §8, AUD-001, AUD-002).
//!
//! * Chain: `h_i = SHA-256("candor/v1/audit/chain" ‖ h_{i-1} ‖ canonical_bytes(event_i))`
//!   with `h_{-1} = SHA-256("candor/v1/audit/genesis" ‖ tenant ‖ stream)`.
//!   Each envelope also carries `prev = h_{i-1}`.
//! * Merkle: RFC 6962 §2.1 (`leaf = SHA-256(0x00 ‖ canonical_bytes)`,
//!   `node = SHA-256(0x01 ‖ left ‖ right)`) over each checkpoint interval.
//! * Checkpoint: every `max_events` (≤ 1000) events or `max_interval`
//!   (≤ 5 min), whichever first; signed with Ed25519 over
//!   `"candor/v1/audit/checkpoint-sig" ‖ canonical_bytes(checkpoint)`.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cbor::{self, MapBuilder, Value};
use crate::codes::{HostRole, StreamId};
use crate::envelope::{
    EnvelopeError, EnvelopeHeader, EventContext, envelope_value, truncate, ts_precision,
};
use crate::event::AuditEvent;
use crate::field::AuditField;
use crate::ids::{TenantRef, UtcMillis};
use crate::sink::{AuditSink, SinkError};

/// Chain domain separator.
pub const CHAIN_DOMAIN: &[u8] = b"candor/v1/audit/chain";
/// Genesis domain separator.
pub const GENESIS_DOMAIN: &[u8] = b"candor/v1/audit/genesis";
/// Checkpoint hash domain separator.
pub const CHECKPOINT_DOMAIN: &[u8] = b"candor/v1/audit/checkpoint";
/// Checkpoint-chain genesis domain separator.
pub const CHECKPOINT_GENESIS_DOMAIN: &[u8] = b"candor/v1/audit/checkpoint-genesis";
/// Signature context prefix.
pub const CHECKPOINT_SIG_DOMAIN: &[u8] = b"candor/v1/audit/checkpoint-sig";
/// Witness cosignature context prefix.
pub const WITNESS_SIG_DOMAIN: &[u8] = b"candor/v1/audit/witness-cosign";

/// Spec maximum events per checkpoint (20 §8).
pub const MAX_EVENTS_PER_CHECKPOINT: u64 = 1000;
/// Spec maximum checkpoint interval: 5 minutes (20 §8).
pub const MAX_CHECKPOINT_INTERVAL_MS: u64 = 5 * 60 * 1000;

fn stream_byte(s: StreamId) -> u8 {
    match s {
        StreamId::Sec => 1,
        StreamId::Case => 2,
        StreamId::Sys => 3,
    }
}

/// `h_{-1}` for a stream.
pub fn genesis(tenant: &TenantRef, stream: StreamId) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(GENESIS_DOMAIN);
    h.update(tenant.as_bytes());
    h.update([stream_byte(stream)]);
    h.finalize().into()
}

/// Previous-checkpoint value of a stream's first checkpoint.
pub fn checkpoint_genesis(tenant: &TenantRef, stream: StreamId) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CHECKPOINT_GENESIS_DOMAIN);
    h.update(tenant.as_bytes());
    h.update([stream_byte(stream)]);
    h.finalize().into()
}

/// `h_i` from `h_{i-1}` and the canonical event bytes.
pub fn chain_hash(prev: &[u8; 32], canonical: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CHAIN_DOMAIN);
    h.update(prev);
    h.update(canonical);
    h.finalize().into()
}

/// RFC 6962 leaf hash of canonical event bytes.
pub fn leaf_hash(canonical: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(canonical);
    h.finalize().into()
}

fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// RFC 6962 Merkle Tree Hash over already-hashed leaves.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves {
        [] => Sha256::digest([]).into(),
        [one] => *one,
        _ => {
            // k = largest power of two strictly less than n (n >= 2).
            let n = leaves.len();
            let mut k: usize = 1;
            while k.checked_mul(2).is_some_and(|d| d < n) {
                k = k.saturating_mul(2);
            }
            let (l, r) = leaves.split_at(k.min(n));
            node_hash(&merkle_root(l), &merkle_root(r))
        }
    }
}

/// Reading of the audit clock (AUD-015).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ClockReading {
    /// Current UTC time.
    pub now: UtcMillis,
    /// Drift beyond 5 min detected by the time-sync monitor; flagged in checkpoints.
    pub drift_exceeded: bool,
}

/// Authenticated UTC clock (≥ 2 sources, AUD-015).
pub trait AuditClock {
    /// Current reading.
    fn read(&self) -> ClockReading;
}

/// System clock (no drift detection; use only where time sync is external).
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl AuditClock for SystemClock {
    fn read(&self) -> ClockReading {
        let ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        ClockReading {
            now: UtcMillis(ms),
            drift_exceeded: false,
        }
    }
}

/// Checkpoint signer. Production: non-exportable key in TPM 2.0 (CE) or
/// HSM (EE, C-29); [`SoftwareSigner`] is for tests and development.
pub trait CheckpointSigner {
    /// Public key (published in C-14).
    fn verifying_key(&self) -> VerifyingKey;
    /// Sign `msg` (already domain-prefixed).
    fn sign(&self, msg: &[u8]) -> Result<Signature, SignerError>;
}

/// Signer failure (HSM/TPM unavailable). No fallback key exists (ADR-046(2)).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SignerError;

/// In-memory Ed25519 signer. The secret is zeroized on drop and never
/// printed.
pub struct SoftwareSigner(SigningKey);

impl SoftwareSigner {
    /// From a 32-byte seed (consumed and zeroized by the caller's `Zeroizing`).
    pub fn from_seed(seed: &Zeroizing<[u8; 32]>) -> Self {
        Self(SigningKey::from_bytes(seed))
    }
}

impl fmt::Debug for SoftwareSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SoftwareSigner(pub={})",
            crate::ids::hex(self.0.verifying_key().as_bytes())
        )
    }
}

impl CheckpointSigner for SoftwareSigner {
    fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
    fn sign(&self, msg: &[u8]) -> Result<Signature, SignerError> {
        Ok(self.0.sign(msg))
    }
}

/// Checkpoint contents (20 §8: stream, first/last seq, Merkle root,
/// previous checkpoint hash, time; plus chain head and drift flag).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CheckpointBody {
    /// Tenant.
    pub tenant: TenantRef,
    /// Stream.
    pub stream: StreamId,
    /// First sequence number covered.
    pub first_seq: u64,
    /// Last sequence number covered.
    pub last_seq: u64,
    /// Chain hash `h_last`.
    pub chain_head: [u8; 32],
    /// RFC 6962 root over the interval's leaves.
    pub merkle_root: [u8; 32],
    /// Hash of the previous checkpoint (or the checkpoint genesis).
    pub prev_checkpoint: [u8; 32],
    /// Signing time (allow-listed exact system timestamp, 09 §8 L3 (e)).
    pub signed_at: UtcMillis,
    /// Clock drift > 5 min observed (AUD-015).
    pub clock_flagged: bool,
}

impl CheckpointBody {
    fn to_value(self) -> Value {
        let mut m = MapBuilder::new();
        m.put("v", Value::Uint(1))
            .put("kind", Value::text("checkpoint"))
            .put("tenant", self.tenant.to_value())
            .put("stream", self.stream.to_value())
            .put("first_seq", Value::Uint(self.first_seq))
            .put("last_seq", Value::Uint(self.last_seq))
            .put("chain_head", Value::Bytes(self.chain_head.to_vec()))
            .put("merkle_root", Value::Bytes(self.merkle_root.to_vec()))
            .put("prev_checkpoint", Value::Bytes(self.prev_checkpoint.to_vec()))
            .put("signed_at", Value::Uint(self.signed_at.0))
            .put("clock_flagged", Value::Bool(self.clock_flagged));
        m.build()
    }

    fn from_value(v: &Value) -> Option<Self> {
        if v.get("v")?.as_u64()? != 1 || v.get("kind")?.as_text()? != "checkpoint" {
            return None;
        }
        if matches!(v, Value::Map(m) if m.len() != 11) {
            return None;
        }
        let tenant: [u8; 16] = v.get("tenant")?.as_bytes()?.try_into().ok()?;
        let stream = match v.get("stream")?.as_text()? {
            "sec" => StreamId::Sec,
            "case" => StreamId::Case,
            "sys" => StreamId::Sys,
            _ => return None,
        };
        Some(Self {
            tenant: TenantRef::from_bytes(tenant),
            stream,
            first_seq: v.get("first_seq")?.as_u64()?,
            last_seq: v.get("last_seq")?.as_u64()?,
            chain_head: v.get("chain_head")?.as_bytes32()?,
            merkle_root: v.get("merkle_root")?.as_bytes32()?,
            prev_checkpoint: v.get("prev_checkpoint")?.as_bytes32()?,
            signed_at: UtcMillis(v.get("signed_at")?.as_u64()?),
            clock_flagged: v.get("clock_flagged")?.as_bool()?,
        })
    }
}

/// A signed checkpoint.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignedCheckpoint {
    body: CheckpointBody,
    bytes: Vec<u8>,
    signature: [u8; 64],
}

/// Checkpoint parse errors.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CheckpointParseError {
    /// Not canonical CBOR.
    NonCanonical,
    /// Wrong schema.
    Schema,
}

impl SignedCheckpoint {
    /// Parse from stored canonical bytes and signature.
    pub fn from_parts(bytes: Vec<u8>, signature: [u8; 64]) -> Result<Self, CheckpointParseError> {
        let v = cbor::decode(&bytes).map_err(|_| CheckpointParseError::NonCanonical)?;
        let body = CheckpointBody::from_value(&v).ok_or(CheckpointParseError::Schema)?;
        Ok(Self {
            body,
            bytes,
            signature,
        })
    }
    /// Body.
    pub fn body(&self) -> &CheckpointBody {
        &self.body
    }
    /// Canonical bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Signature bytes.
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
    /// `SHA-256("candor/v1/audit/checkpoint" ‖ bytes)`.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(CHECKPOINT_DOMAIN);
        h.update(&self.bytes);
        h.finalize().into()
    }
    fn signing_message(bytes: &[u8]) -> Vec<u8> {
        let mut m = CHECKPOINT_SIG_DOMAIN.to_vec();
        m.extend_from_slice(bytes);
        m
    }
    /// Verify the instance signature (strict Ed25519).
    pub fn verify_signature(&self, key: &VerifyingKey) -> bool {
        let sig = Signature::from_bytes(&self.signature);
        key.verify_strict(&Self::signing_message(&self.bytes), &sig)
            .is_ok()
    }
    /// Message a witness cosigns: `"candor/v1/audit/witness-cosign" ‖ checkpoint hash`.
    pub fn witness_message(&self) -> Vec<u8> {
        let mut m = WITNESS_SIG_DOMAIN.to_vec();
        m.extend_from_slice(&self.hash());
        m
    }
    /// Verify a witness cosignature (AUD-003).
    pub fn verify_cosignature(&self, witness_key: &VerifyingKey, sig: &[u8; 64]) -> bool {
        witness_key
            .verify_strict(&self.witness_message(), &Signature::from_bytes(sig))
            .is_ok()
    }
}

/// Checkpoint cadence. Values may only be stricter than the spec maxima.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CheckpointPolicy {
    max_events: u64,
    max_interval_ms: u64,
}

impl CheckpointPolicy {
    /// Spec default: 1000 events or 5 minutes.
    pub const DEFAULT: Self = Self {
        max_events: MAX_EVENTS_PER_CHECKPOINT,
        max_interval_ms: MAX_CHECKPOINT_INTERVAL_MS,
    };
    /// `None` if either value is zero or exceeds the spec maximum.
    pub fn new(max_events: u64, max_interval_ms: u64) -> Option<Self> {
        ((1..=MAX_EVENTS_PER_CHECKPOINT).contains(&max_events)
            && (1..=MAX_CHECKPOINT_INTERVAL_MS).contains(&max_interval_ms))
        .then_some(Self {
            max_events,
            max_interval_ms,
        })
    }
}

impl Default for CheckpointPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A record committed by [`AuditLog`]. Only the log can construct one, so
/// sinks can only ever receive typed, allow-listed events.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CommittedRecord {
    header: EnvelopeHeader,
    event: AuditEvent,
    bytes: Vec<u8>,
    hash: [u8; 32],
    leaf: [u8; 32],
}

impl CommittedRecord {
    /// Envelope header.
    pub fn header(&self) -> &EnvelopeHeader {
        &self.header
    }
    /// Typed event.
    pub fn event(&self) -> &AuditEvent {
        &self.event
    }
    /// Canonical CBOR bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Chain hash `h_i`.
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
    /// RFC 6962 leaf hash.
    pub fn leaf(&self) -> &[u8; 32] {
        &self.leaf
    }
    /// Verification form.
    pub fn to_chain_record(&self) -> ChainRecord {
        ChainRecord::Full {
            bytes: self.bytes.clone(),
            claimed_hash: Some(self.hash),
        }
    }
    /// Redacted stub (AUD-012): keeps only seq, prev, leaf and chain hash.
    pub fn to_redacted(&self) -> ChainRecord {
        ChainRecord::Redacted {
            seq: self.header.seq,
            prev: self.header.prev,
            leaf: self.leaf,
            hash: self.hash,
        }
    }
}

/// A stored record as presented to the verifier.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ChainRecord {
    /// Full canonical event.
    Full {
        /// Canonical CBOR.
        bytes: Vec<u8>,
        /// Stored chain hash, if the store keeps one (checked when present).
        claimed_hash: Option<[u8; 32]>,
    },
    /// Redacted event (per-case disposal, AUD-012): content removed.
    Redacted {
        /// Sequence number.
        seq: u64,
        /// `h_{i-1}`.
        prev: [u8; 32],
        /// Leaf hash (for Merkle recomputation).
        leaf: [u8; 32],
        /// `h_i`.
        hash: [u8; 32],
    },
}

/// Errors from [`AuditLog`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LogError {
    /// Envelope rule violated.
    Envelope(EnvelopeError),
    /// Encoding failed.
    Encoding,
    /// Sequence space exhausted.
    SeqOverflow,
    /// A sink failed; the stream state was not advanced.
    Sink(SinkError),
    /// Checkpoint signing failed (no fallback key, ADR-046(2)).
    Signer,
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Envelope(_) => "audit: envelope rule violated",
            Self::Encoding => "audit: encoding failed",
            Self::SeqOverflow => "audit: sequence overflow",
            Self::Sink(_) => "audit: sink failure",
            Self::Signer => "audit: checkpoint signing failed",
        };
        f.write_str(s)
    }
}

impl std::error::Error for LogError {}

/// Resume point for a stream (e.g., from a [`crate::verify::VerifyReport`]).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StreamResume {
    /// Next sequence number.
    pub next_seq: u64,
    /// Current chain head.
    pub head: [u8; 32],
    /// Leaves after the last checkpoint.
    pub pending_leaves: Vec<[u8; 32]>,
    /// Hash of the last checkpoint (or checkpoint genesis).
    pub last_checkpoint: [u8; 32],
}

#[derive(Debug)]
struct StreamState {
    stream: StreamId,
    next_seq: u64,
    head: [u8; 32],
    pending: Vec<[u8; 32]>,
    last_cp_hash: [u8; 32],
    last_cp_time: UtcMillis,
}

/// Result of [`AuditLog::emit`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Emitted {
    /// The committed record.
    pub record: CommittedRecord,
    /// A checkpoint produced because the event threshold was reached.
    pub checkpoint: Option<SignedCheckpoint>,
}

/// Class-separated, hash-chained audit writer (C-24).
pub struct AuditLog<S: CheckpointSigner, C: AuditClock> {
    tenant: TenantRef,
    host_role: HostRole,
    signer: S,
    clock: C,
    policy: CheckpointPolicy,
    streams: [StreamState; 3],
    sinks: Vec<Box<dyn AuditSink + Send>>,
}

impl<S: CheckpointSigner, C: AuditClock> fmt::Debug for AuditLog<S, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditLog")
            .field("tenant", &self.tenant)
            .field("host_role", &self.host_role)
            .field("streams", &self.streams)
            .finish_non_exhaustive()
    }
}

fn idx(s: StreamId) -> usize {
    match s {
        StreamId::Sec => 0,
        StreamId::Case => 1,
        StreamId::Sys => 2,
    }
}

impl<S: CheckpointSigner, C: AuditClock> AuditLog<S, C> {
    /// New log with empty streams.
    pub fn new(
        tenant: TenantRef,
        host_role: HostRole,
        signer: S,
        clock: C,
        policy: CheckpointPolicy,
    ) -> Self {
        let now = clock.read().now;
        let mk = |stream| StreamState {
            stream,
            next_seq: 0,
            head: genesis(&tenant, stream),
            pending: Vec::new(),
            last_cp_hash: checkpoint_genesis(&tenant, stream),
            last_cp_time: now,
        };
        Self {
            tenant,
            host_role,
            signer,
            clock,
            policy,
            streams: [mk(StreamId::Sec), mk(StreamId::Case), mk(StreamId::Sys)],
            sinks: Vec::new(),
        }
    }

    /// Resume a stream from verified state.
    pub fn resume(&mut self, stream: StreamId, r: StreamResume) {
        let now = self.clock.read().now;
        if let Some(st) = self.streams.get_mut(idx(stream)) {
            st.next_seq = r.next_seq;
            st.head = r.head;
            st.pending = r.pending_leaves;
            st.last_cp_hash = r.last_checkpoint;
            st.last_cp_time = now;
        }
    }

    /// Attach a sink. Records and checkpoints are written to every sink.
    pub fn add_sink(&mut self, sink: Box<dyn AuditSink + Send>) {
        self.sinks.push(sink);
    }

    /// Tenant.
    pub fn tenant(&self) -> TenantRef {
        self.tenant
    }

    /// Checkpoint verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }

    /// Emit one typed event (the only way to write an audit record).
    pub fn emit(&mut self, ctx: EventContext, event: AuditEvent) -> Result<Emitted, LogError> {
        ctx.validate().map_err(LogError::Envelope)?;
        if self.host_role == HostRole::Intake && !event.allowed_on_intake() {
            return Err(LogError::Envelope(EnvelopeError::NotAllowedOnHost));
        }
        let reading = self.clock.read();
        let stream = event.class().stream();
        let st = self
            .streams
            .get(idx(stream))
            .ok_or(LogError::Encoding)?;
        let precision = ts_precision(&event, &ctx.actor, self.host_role);
        let header = EnvelopeHeader {
            stream,
            seq: st.next_seq,
            ts: truncate(reading.now, precision),
            precision,
            tenant: self.tenant,
            host_role: self.host_role,
            ctx,
            prev: st.head,
        };
        let next_seq = st.next_seq.checked_add(1).ok_or(LogError::SeqOverflow)?;
        let bytes = cbor::encode(&envelope_value(&header, &event)).map_err(|_| LogError::Encoding)?;
        let hash = chain_hash(&st.head, &bytes);
        let leaf = leaf_hash(&bytes);
        let record = CommittedRecord {
            header,
            event,
            bytes,
            hash,
            leaf,
        };
        for s in &mut self.sinks {
            s.write_record(&record).map_err(LogError::Sink)?;
        }
        let pending_len = {
            let st = self
                .streams
                .get_mut(idx(stream))
                .ok_or(LogError::Encoding)?;
            st.next_seq = next_seq;
            st.head = hash;
            st.pending.push(leaf);
            u64::try_from(st.pending.len()).unwrap_or(u64::MAX)
        };
        let checkpoint = if pending_len >= self.policy.max_events {
            Some(self.checkpoint_stream(stream, reading)?)
        } else {
            None
        };
        Ok(Emitted { record, checkpoint })
    }

    /// Produce time-triggered checkpoints for streams whose interval elapsed
    /// and that have unattested events.
    pub fn tick(&mut self) -> Result<Vec<SignedCheckpoint>, LogError> {
        let reading = self.clock.read();
        let mut out = Vec::new();
        for stream in [StreamId::Sec, StreamId::Case, StreamId::Sys] {
            let due = self.streams.get(idx(stream)).is_some_and(|st| {
                !st.pending.is_empty()
                    && reading.now.0.saturating_sub(st.last_cp_time.0) >= self.policy.max_interval_ms
            });
            if due {
                out.push(self.checkpoint_stream(stream, reading)?);
            }
        }
        Ok(out)
    }

    /// Force a checkpoint of `stream` now (`None` if nothing is pending).
    pub fn checkpoint_now(&mut self, stream: StreamId) -> Result<Option<SignedCheckpoint>, LogError> {
        let reading = self.clock.read();
        if self
            .streams
            .get(idx(stream))
            .is_none_or(|st| st.pending.is_empty())
        {
            return Ok(None);
        }
        self.checkpoint_stream(stream, reading).map(Some)
    }

    fn checkpoint_stream(
        &mut self,
        stream: StreamId,
        reading: ClockReading,
    ) -> Result<SignedCheckpoint, LogError> {
        let st = self.streams.get(idx(stream)).ok_or(LogError::Encoding)?;
        let n = u64::try_from(st.pending.len()).map_err(|_| LogError::Encoding)?;
        let last_seq = st.next_seq.checked_sub(1).ok_or(LogError::Encoding)?;
        let first_seq = st.next_seq.checked_sub(n).ok_or(LogError::Encoding)?;
        let body = CheckpointBody {
            tenant: self.tenant,
            stream: st.stream,
            first_seq,
            last_seq,
            chain_head: st.head,
            merkle_root: merkle_root(&st.pending),
            prev_checkpoint: st.last_cp_hash,
            signed_at: reading.now,
            clock_flagged: reading.drift_exceeded,
        };
        let bytes = cbor::encode(&body.to_value()).map_err(|_| LogError::Encoding)?;
        let sig = self
            .signer
            .sign(&SignedCheckpoint::signing_message(&bytes))
            .map_err(|_| LogError::Signer)?;
        let cp = SignedCheckpoint {
            body,
            bytes,
            signature: sig.to_bytes(),
        };
        for s in &mut self.sinks {
            s.write_checkpoint(&cp).map_err(LogError::Sink)?;
        }
        let st = self
            .streams
            .get_mut(idx(stream))
            .ok_or(LogError::Encoding)?;
        st.pending.clear();
        st.last_cp_hash = cp.hash();
        st.last_cp_time = reading.now;
        Ok(cp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn merkle_shapes() {
        // RFC 6962: MTH of one leaf is the leaf hash itself.
        assert_eq!(merkle_root(&[h(1)]), h(1));
        assert_eq!(merkle_root(&[h(1), h(2)]), node_hash(&h(1), &h(2)));
        // n = 3: k = 2 → node(node(1,2), 3)
        assert_eq!(
            merkle_root(&[h(1), h(2), h(3)]),
            node_hash(&node_hash(&h(1), &h(2)), &h(3))
        );
        // n = 5: k = 4
        let l4 = node_hash(&node_hash(&h(1), &h(2)), &node_hash(&h(3), &h(4)));
        assert_eq!(merkle_root(&[h(1), h(2), h(3), h(4), h(5)]), node_hash(&l4, &h(5)));
        // empty tree = SHA-256("")
        assert_eq!(
            crate::ids::hex(&merkle_root(&[])),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn genesis_is_stream_separated() {
        let t = TenantRef::from_bytes([0; 16]);
        assert_ne!(genesis(&t, StreamId::Sec), genesis(&t, StreamId::Case));
        assert_ne!(genesis(&t, StreamId::Sec), checkpoint_genesis(&t, StreamId::Sec));
    }

    #[test]
    fn policy_bounds() {
        assert!(CheckpointPolicy::new(1001, 1000).is_none());
        assert!(CheckpointPolicy::new(10, MAX_CHECKPOINT_INTERVAL_MS + 1).is_none());
        assert!(CheckpointPolicy::new(0, 1).is_none());
        assert!(CheckpointPolicy::new(10, 1000).is_some());
    }
}
