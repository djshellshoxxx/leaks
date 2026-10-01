// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hash chain, RFC 6962 Merkle checkpoints, Ed25519 checkpoint signing and
//! the [`AuditLog`] writer (20 §8, AUD-001, AUD-002).
//!
//! * Record commitment: `c_i = SHA-256("candor/v1/audit/record-commit\0" ‖
//!   salt_i ‖ canonical_bytes(event_i))`. `salt_i` is all-zero except for
//!   redactable CASE records, where it is
//!   `HMAC-SHA-256(K_case, "candor/v1/audit/redaction-salt" ‖ 0 ‖ tenant ‖
//!   stream ‖ seq)` with a per-case key that is destroyed at disposal, so a
//!   redacted stub cannot be brute-forced back to its (low-entropy) record
//!   (AUD-RM1-LOG-08).
//! * Chain: `h_i = SHA-256("candor/v1/audit/chain\0" ‖ h_{i-1} ‖ c_i)` with
//!   `h_{-1} = SHA-256("candor/v1/audit/genesis\0" ‖ tenant ‖ stream)`.
//!   Each envelope also carries `prev = h_{i-1}`.
//! * Merkle: RFC 6962 §2.1 (`leaf = SHA-256(0x00 ‖ c_i)`,
//!   `node = SHA-256(0x01 ‖ left ‖ right)`) over each checkpoint interval.
//! * Checkpoints follow a **fixed, data-independent schedule** per stream
//!   (AUD-RM1-LOG-02): one checkpoint per slot boundary whether or not
//!   anything happened (empty intervals allowed), `signed_at` = the slot
//!   boundary. SECURITY: every 5 min (hourly on Z-INTAKE); CASE and SYSTEM,
//!   which carry date-only events, once per UTC day at 00:00. Signed with
//!   Ed25519 over `"candor/v1/audit/checkpoint-sig\0" ‖ canonical_bytes`.
//! * Sinks: one primary durable sink is the commit point; secondaries are
//!   fed from an outbox after the primary accepted, so a secondary failure
//!   can never fork the chain (AUD-RM1-LOG-07).
//!
//! All domain labels are NUL-terminated and therefore prefix-free
//! (AUD-RM1-LOG-12).

use core::fmt;
use std::collections::{BTreeMap, VecDeque};

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
use crate::ids::{CaseRef, MS_PER_DAY, MS_PER_HOUR, TenantRef, UtcMillis, keyed32};
use crate::sink::{AuditSink, SinkError};

/// Chain domain separator.
pub const CHAIN_DOMAIN: &[u8] = b"candor/v1/audit/chain\0";
/// Genesis domain separator.
pub const GENESIS_DOMAIN: &[u8] = b"candor/v1/audit/genesis\0";
/// Checkpoint hash domain separator.
pub const CHECKPOINT_DOMAIN: &[u8] = b"candor/v1/audit/checkpoint\0";
/// Checkpoint-chain genesis domain separator.
pub const CHECKPOINT_GENESIS_DOMAIN: &[u8] = b"candor/v1/audit/checkpoint-genesis\0";
/// Signature context prefix.
pub const CHECKPOINT_SIG_DOMAIN: &[u8] = b"candor/v1/audit/checkpoint-sig\0";
/// Witness cosignature context prefix.
pub const WITNESS_SIG_DOMAIN: &[u8] = b"candor/v1/audit/witness-cosign\0";
/// Record commitment domain separator.
pub const COMMIT_DOMAIN: &[u8] = b"candor/v1/audit/record-commit\0";
/// Redaction-set commitment domain separator (`case.disposed.redacted_set`).
pub const REDACTION_SET_DOMAIN: &[u8] = b"candor/v1/audit/redaction-set\0";
/// Per-case redaction salt label (HMAC input, NUL-terminated by `keyed32`).
const SALT_LABEL: &[u8] = b"candor/v1/audit/redaction-salt";

/// Default (and maximum) SECURITY checkpoint interval: 5 minutes (20 §8).
pub const MAX_CHECKPOINT_INTERVAL_MS: u64 = 5 * 60 * 1000;
/// Checkpoint interval of streams that carry date-only events (CASE,
/// SYSTEM): one UTC day.
pub const DAILY_CHECKPOINT_INTERVAL_MS: u64 = MS_PER_DAY;

pub(crate) fn stream_byte(s: StreamId) -> u8 {
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

/// Record commitment `c_i` over the salt and the canonical event bytes.
pub fn record_commit(salt: &[u8; 32], canonical: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(COMMIT_DOMAIN);
    h.update(salt);
    h.update(canonical);
    h.finalize().into()
}

/// `h_i` from `h_{i-1}` and the record commitment.
pub fn chain_hash(prev: &[u8; 32], commit: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CHAIN_DOMAIN);
    h.update(prev);
    h.update(commit);
    h.finalize().into()
}

/// RFC 6962 leaf hash of a record commitment.
pub fn leaf_hash(commit: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(commit);
    h.finalize().into()
}

/// Commitment to an ordered set of redacted records `(seq, c_i)`, carried
/// by the `case.disposed` tombstone (AUD-RM1-LOG-01).
pub fn redaction_set_hash(entries: &[(u64, [u8; 32])]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(REDACTION_SET_DOMAIN);
    h.update(
        u64::try_from(entries.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for (seq, c) in entries {
        h.update(seq.to_be_bytes());
        h.update(c);
    }
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

/// Per-case redaction-commitment key (AUD-RM1-LOG-08). Destroying it at
/// disposal makes the salts of the case's redacted records unrecoverable.
/// Secret: zeroized, never printed, not `Clone`.
pub struct CaseCommitKey(Zeroizing<[u8; 32]>);

impl CaseCommitKey {
    /// Wrap a random 32-byte key (minted by the case service at case
    /// creation, held in its key store).
    pub fn new(k: [u8; 32]) -> Self {
        Self(Zeroizing::new(k))
    }
    fn salt(&self, tenant: &TenantRef, stream: StreamId, seq: u64) -> [u8; 32] {
        let mut data = [0u8; 25];
        for (o, i) in data.iter_mut().zip(
            tenant
                .as_bytes()
                .iter()
                .chain([stream_byte(stream)].iter())
                .chain(seq.to_be_bytes().iter()),
        ) {
            *o = *i;
        }
        keyed32(&self.0, SALT_LABEL, &data)
    }
}

impl fmt::Debug for CaseCommitKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CaseCommitKey(<redacted>)")
    }
}

/// The key store has no key for a case (fail closed: the event is not
/// written).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyUnavailable;

/// Source of per-case commitment keys. A store must hand out a key for every
/// live case and must mint a fresh key for a case whose previous key was
/// destroyed by disposal.
pub trait CaseKeyStore {
    /// Key of `case`.
    fn commit_key(&mut self, case: CaseRef) -> Result<CaseCommitKey, KeyUnavailable>;
}

/// In-memory [`CaseKeyStore`] (tests, single-process deployments whose key
/// material comes from elsewhere). Keys are zeroized on destruction.
#[derive(Default)]
pub struct MemoryCaseKeys {
    keys: BTreeMap<CaseRef, Zeroizing<[u8; 32]>>,
}

impl fmt::Debug for MemoryCaseKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryCaseKeys")
            .field("cases", &self.keys.len())
            .finish_non_exhaustive()
    }
}

impl MemoryCaseKeys {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }
    /// Install the key of `case`.
    pub fn insert(&mut self, case: CaseRef, key: [u8; 32]) {
        self.keys.insert(case, Zeroizing::new(key));
    }
    /// Destroy the key of `case` (disposal); `true` if one existed.
    pub fn destroy(&mut self, case: CaseRef) -> bool {
        self.keys.remove(&case).is_some()
    }
}

impl CaseKeyStore for MemoryCaseKeys {
    fn commit_key(&mut self, case: CaseRef) -> Result<CaseCommitKey, KeyUnavailable> {
        self.keys
            .get(&case)
            .map(|k| CaseCommitKey::new(**k))
            .ok_or(KeyUnavailable)
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

/// The exact message a checkpoint signature covers:
/// `"candor/v1/audit/checkpoint-sig\0" ‖ checkpoint_bytes`.
pub fn checkpoint_signing_message(checkpoint_bytes: &[u8]) -> Vec<u8> {
    let mut m = CHECKPOINT_SIG_DOMAIN.to_vec();
    m.extend_from_slice(checkpoint_bytes);
    m
}

/// Checkpoint signer. Production: non-exportable key in TPM 2.0 (CE) or
/// HSM (EE, C-29); [`SoftwareSigner`] is for tests and development.
///
/// The signer is given the canonical checkpoint bytes and adds the signing
/// context itself ([`checkpoint_signing_message`]); it is never asked to
/// sign an arbitrary message, so a key shared with another purpose cannot
/// be used as a cross-protocol oracle through this trait (AUD-RM1-LOG-12).
pub trait CheckpointSigner {
    /// Public key (published in C-14).
    fn verifying_key(&self) -> VerifyingKey;
    /// Sign `checkpoint_signing_message(checkpoint_bytes)`.
    fn sign_checkpoint(&self, checkpoint_bytes: &[u8]) -> Result<Signature, SignerError>;
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
    fn sign_checkpoint(&self, checkpoint_bytes: &[u8]) -> Result<Signature, SignerError> {
        Ok(self.0.sign(&checkpoint_signing_message(checkpoint_bytes)))
    }
}

/// Checkpoint contents (20 §8: stream, seq range, Merkle root, previous
/// checkpoint hash, time; plus chain head and drift flag). The interval is
/// `[first_seq, end_seq)`; it is empty when `first_seq == end_seq`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CheckpointBody {
    /// Tenant.
    pub tenant: TenantRef,
    /// Stream.
    pub stream: StreamId,
    /// First sequence number covered.
    pub first_seq: u64,
    /// One past the last sequence number covered.
    pub end_seq: u64,
    /// Chain hash after the interval (`h_{end_seq-1}`, or the previous head
    /// for an empty interval).
    pub chain_head: [u8; 32],
    /// RFC 6962 root over the interval's leaves (`SHA-256("")` if empty).
    pub merkle_root: [u8; 32],
    /// Hash of the previous checkpoint (or the checkpoint genesis).
    pub prev_checkpoint: [u8; 32],
    /// Schedule slot boundary the checkpoint closes (never a clock reading).
    pub signed_at: UtcMillis,
    /// Clock drift > 5 min observed (AUD-015).
    pub clock_flagged: bool,
}

impl CheckpointBody {
    fn to_value(self) -> Value {
        let mut m = MapBuilder::new();
        m.put("v", Value::Uint(2))
            .put("kind", Value::text("checkpoint"))
            .put("tenant", self.tenant.to_value())
            .put("stream", self.stream.to_value())
            .put("first_seq", Value::Uint(self.first_seq))
            .put("end_seq", Value::Uint(self.end_seq))
            .put("chain_head", Value::Bytes(self.chain_head.to_vec()))
            .put("merkle_root", Value::Bytes(self.merkle_root.to_vec()))
            .put(
                "prev_checkpoint",
                Value::Bytes(self.prev_checkpoint.to_vec()),
            )
            .put("signed_at", Value::Uint(self.signed_at.0))
            .put("clock_flagged", Value::Bool(self.clock_flagged));
        m.build()
    }

    fn from_value(v: &Value) -> Option<Self> {
        if v.get("v")?.as_u64()? != 2 || v.get("kind")?.as_text()? != "checkpoint" {
            return None;
        }
        if !matches!(v, Value::Map(m) if m.len() == 11) {
            return None;
        }
        let tenant: [u8; 16] = v.get("tenant")?.as_bytes()?.try_into().ok()?;
        let stream = match v.get("stream")?.as_text()? {
            "sec" => StreamId::Sec,
            "case" => StreamId::Case,
            "sys" => StreamId::Sys,
            _ => return None,
        };
        let first_seq = v.get("first_seq")?.as_u64()?;
        let end_seq = v.get("end_seq")?.as_u64()?;
        if end_seq < first_seq {
            return None;
        }
        Some(Self {
            tenant: TenantRef::from_bytes(tenant),
            stream,
            first_seq,
            end_seq,
            chain_head: v.get("chain_head")?.as_bytes32()?,
            merkle_root: v.get("merkle_root")?.as_bytes32()?,
            prev_checkpoint: v.get("prev_checkpoint")?.as_bytes32()?,
            signed_at: UtcMillis(v.get("signed_at")?.as_u64()?),
            clock_flagged: v.get("clock_flagged")?.as_bool()?,
        })
    }

    /// Whether the interval is empty.
    pub fn is_empty(&self) -> bool {
        self.end_seq == self.first_seq
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
    /// `SHA-256("candor/v1/audit/checkpoint\0" ‖ bytes)`.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(CHECKPOINT_DOMAIN);
        h.update(&self.bytes);
        h.finalize().into()
    }
    /// Verify the instance signature (strict Ed25519).
    pub fn verify_signature(&self, key: &VerifyingKey) -> bool {
        let sig = Signature::from_bytes(&self.signature);
        key.verify_strict(&checkpoint_signing_message(&self.bytes), &sig)
            .is_ok()
    }
    /// Message a witness cosigns: `"candor/v1/audit/witness-cosign\0" ‖ checkpoint hash`.
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

/// Checkpoint schedule (AUD-RM1-LOG-02). Only the SECURITY interval is
/// configurable, and only stricter (shorter) than 5 minutes; it must divide
/// an hour so slots are aligned to wall-clock boundaries. CASE and SYSTEM
/// always checkpoint daily; Z-INTAKE SECURITY hourly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CheckpointPolicy {
    sec_interval_ms: u64,
}

impl CheckpointPolicy {
    /// Spec default: SECURITY every 5 minutes.
    pub const DEFAULT: Self = Self {
        sec_interval_ms: MAX_CHECKPOINT_INTERVAL_MS,
    };
    /// `None` unless `1 s ≤ sec_interval_ms ≤ 5 min`, a whole number of
    /// seconds, and a divisor of one hour.
    pub fn new(sec_interval_ms: u64) -> Option<Self> {
        ((1000..=MAX_CHECKPOINT_INTERVAL_MS).contains(&sec_interval_ms)
            && sec_interval_ms.is_multiple_of(1000)
            && MS_PER_HOUR.is_multiple_of(sec_interval_ms))
        .then_some(Self { sec_interval_ms })
    }
    /// Slot length of `stream` on a host of role `host`.
    pub fn slot_ms(&self, stream: StreamId, host: HostRole) -> u64 {
        match stream {
            // Both carry date-only events (imports, relay, source-load
            // health): a checkpoint more often than daily would time them.
            StreamId::Case | StreamId::Sys => DAILY_CHECKPOINT_INTERVAL_MS,
            // Z-INTAKE timestamps are hour-truncated (LOG-004).
            StreamId::Sec if host == HostRole::Intake => MS_PER_HOUR,
            StreamId::Sec => self.sec_interval_ms,
        }
    }
}

impl Default for CheckpointPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

fn slot_floor(now: UtcMillis, slot: u64) -> u64 {
    now.0.saturating_sub(now.0.checked_rem(slot).unwrap_or(0))
}

/// A record committed by [`AuditLog`]. Only the log can construct one, so
/// sinks can only ever receive typed, allow-listed events.
#[derive(Clone, PartialEq, Eq)]
pub struct CommittedRecord {
    header: EnvelopeHeader,
    event: AuditEvent,
    bytes: Vec<u8>,
    salt: [u8; 32],
    commit: [u8; 32],
    hash: [u8; 32],
    leaf: [u8; 32],
}

impl fmt::Debug for CommittedRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The salt is omitted: it is what keeps a redacted stub opaque.
        f.debug_struct("CommittedRecord")
            .field("header", &self.header)
            .field("event", &self.event)
            .finish_non_exhaustive()
    }
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
    /// Redaction salt (all-zero unless the record is redactable). Sinks
    /// store it next to the record and delete it with the record content
    /// at redaction.
    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }
    /// Record commitment `c_i`.
    pub fn commit(&self) -> &[u8; 32] {
        &self.commit
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
            salt: self.salt,
            claimed_hash: Some(self.hash),
        }
    }
}

/// A stored record as presented to the verifier.
#[derive(Clone, PartialEq, Eq)]
pub enum ChainRecord {
    /// Full canonical event.
    Full {
        /// Canonical CBOR.
        bytes: Vec<u8>,
        /// Redaction salt (all-zero for non-redactable records).
        salt: [u8; 32],
        /// Stored chain hash, if the store keeps one (checked when present).
        claimed_hash: Option<[u8; 32]>,
    },
    /// Redacted event (per-case disposal, AUD-012): content and salt
    /// removed. Valid only in the CASE stream and only when the
    /// `case.disposed` record at `tombstone_seq` commits to it.
    Redacted {
        /// Sequence number.
        seq: u64,
        /// Record commitment `c_i`.
        commit: [u8; 32],
        /// Sequence number of the covering `case.disposed` tombstone.
        tombstone_seq: u64,
    },
}

impl fmt::Debug for ChainRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full { bytes, .. } => write!(f, "ChainRecord::Full(<{} bytes>)", bytes.len()),
            Self::Redacted {
                seq, tombstone_seq, ..
            } => write!(
                f,
                "ChainRecord::Redacted(seq={seq}, tombstone={tombstone_seq})"
            ),
        }
    }
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
    /// The primary sink failed; nothing was committed.
    Sink(SinkError),
    /// No primary sink is attached (fail closed).
    NoPrimarySink,
    /// Checkpoint signing failed (no fallback key, ADR-046(2)); nothing was
    /// committed.
    Signer,
    /// No commitment key for the event's case (fail closed).
    CaseKeyUnavailable,
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Envelope(_) => "audit: envelope rule violated",
            Self::Encoding => "audit: encoding failed",
            Self::SeqOverflow => "audit: sequence overflow",
            Self::Sink(_) => "audit: primary sink failure",
            Self::NoPrimarySink => "audit: no primary sink",
            Self::Signer => "audit: checkpoint signing failed",
            Self::CaseKeyUnavailable => "audit: case commitment key unavailable",
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
    /// Start of the currently open schedule slot.
    open_slot: u64,
}

/// Result of [`AuditLog::emit`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Emitted {
    /// The committed record.
    pub record: CommittedRecord,
    /// The scheduled checkpoint that closed the previous slot of this
    /// stream before the record was appended, if one was due.
    pub checkpoint: Option<SignedCheckpoint>,
    /// At least one secondary sink has not yet received everything
    /// (outbox non-empty or desynchronised).
    pub secondary_lag: bool,
}

/// Maximum items queued for one secondary sink before it is declared
/// desynchronised (and must be rebuilt from the primary store).
pub const MAX_SECONDARY_OUTBOX: usize = 65_536;

#[derive(Clone)]
enum Outgoing {
    Record(Box<CommittedRecord>),
    Checkpoint(Box<SignedCheckpoint>),
}

struct Secondary {
    sink: Box<dyn AuditSink + Send>,
    outbox: VecDeque<Outgoing>,
    desynced: bool,
}

impl Secondary {
    /// Queue `item` and drain as far as the sink accepts. Returns whether
    /// the sink is lagging afterwards.
    fn deliver(&mut self, item: Option<Outgoing>) -> bool {
        if self.desynced {
            return true;
        }
        if let Some(item) = item {
            if self.outbox.len() >= MAX_SECONDARY_OUTBOX {
                self.desynced = true;
                self.outbox.clear();
                return true;
            }
            self.outbox.push_back(item);
        }
        while let Some(front) = self.outbox.front() {
            let ok = match front {
                Outgoing::Record(r) => self.sink.write_record(r).is_ok(),
                Outgoing::Checkpoint(c) => self.sink.write_checkpoint(c).is_ok(),
            };
            if !ok {
                break;
            }
            self.outbox.pop_front();
        }
        !self.outbox.is_empty()
    }
}

/// Delivery state of one secondary sink.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SecondaryStatus {
    /// Items waiting in the outbox.
    pub queued: usize,
    /// The outbox overflowed; the sink receives nothing more until it is
    /// rebuilt from the primary store and re-attached.
    pub desynced: bool,
}

/// Class-separated, hash-chained audit writer (C-24).
///
/// Sink semantics (AUD-RM1-LOG-07): the record (and its chain hash) is
/// computed once; the **primary** sink is the commit point. If the primary
/// write fails, nothing is committed and the stream state is unchanged, so
/// the next event reuses the same `seq` without forking any store. After
/// the primary accepted, secondaries receive the identical record through a
/// per-sink outbox, retried in order on every later emission and
/// [`AuditLog::tick`]; a secondary failure never reaches the caller as an
/// error and never re-issues a `seq`.
pub struct AuditLog<S: CheckpointSigner, C: AuditClock> {
    tenant: TenantRef,
    host_role: HostRole,
    signer: S,
    clock: C,
    policy: CheckpointPolicy,
    streams: [StreamState; 3],
    primary: Option<Box<dyn AuditSink + Send>>,
    secondaries: Vec<Secondary>,
    case_keys: Option<Box<dyn CaseKeyStore + Send>>,
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
            open_slot: slot_floor(now, policy.slot_ms(stream, host_role)),
        };
        Self {
            tenant,
            host_role,
            signer,
            clock,
            policy,
            streams: [mk(StreamId::Sec), mk(StreamId::Case), mk(StreamId::Sys)],
            primary: None,
            secondaries: Vec::new(),
            case_keys: None,
        }
    }

    /// Resume a stream from verified state.
    pub fn resume(&mut self, stream: StreamId, r: StreamResume) {
        let now = self.clock.read().now;
        let slot = self.policy.slot_ms(stream, self.host_role);
        if let Some(st) = self.streams.get_mut(idx(stream)) {
            st.next_seq = r.next_seq;
            st.head = r.head;
            st.pending = r.pending_leaves;
            st.last_cp_hash = r.last_checkpoint;
            st.open_slot = slot_floor(now, slot);
        }
    }

    /// Set the primary (durable, commit-point) sink.
    pub fn set_primary_sink(&mut self, sink: Box<dyn AuditSink + Send>) {
        self.primary = Some(sink);
    }

    /// Attach a secondary sink, fed from the outbox after the primary.
    pub fn add_secondary_sink(&mut self, sink: Box<dyn AuditSink + Send>) {
        self.secondaries.push(Secondary {
            sink,
            outbox: VecDeque::new(),
            desynced: false,
        });
    }

    /// Delivery state of each secondary sink, in attachment order.
    pub fn secondary_status(&self) -> Vec<SecondaryStatus> {
        self.secondaries
            .iter()
            .map(|s| SecondaryStatus {
                queued: s.outbox.len(),
                desynced: s.desynced,
            })
            .collect()
    }

    /// Install the per-case commitment key store (required for CASE events
    /// that refer to a case).
    pub fn set_case_keys(&mut self, keys: Box<dyn CaseKeyStore + Send>) {
        self.case_keys = Some(keys);
    }

    /// Tenant.
    pub fn tenant(&self) -> TenantRef {
        self.tenant
    }

    /// Checkpoint verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }

    fn to_secondaries(&mut self, item: Option<Outgoing>) -> bool {
        let mut lag = false;
        for s in &mut self.secondaries {
            lag |= s.deliver(item.clone());
        }
        lag
    }

    fn salt_for(
        &mut self,
        stream: StreamId,
        seq: u64,
        event: &AuditEvent,
    ) -> Result<[u8; 32], LogError> {
        if stream != StreamId::Case || matches!(event, AuditEvent::CaseDisposed { .. }) {
            return Ok([0; 32]);
        }
        let Some(case) = event.case_ref() else {
            return Ok([0; 32]);
        };
        let keys = self
            .case_keys
            .as_mut()
            .ok_or(LogError::CaseKeyUnavailable)?;
        let key = keys
            .commit_key(case)
            .map_err(|_| LogError::CaseKeyUnavailable)?;
        Ok(key.salt(&self.tenant, stream, seq))
    }

    /// Emit one typed event (the only way to write an audit record).
    ///
    /// A checkpoint due for this stream's previous slot is produced first
    /// (so a record is never covered by a checkpoint dated before it); if
    /// that fails, nothing is written.
    pub fn emit(&mut self, ctx: EventContext, event: AuditEvent) -> Result<Emitted, LogError> {
        ctx.validate().map_err(LogError::Envelope)?;
        if self.host_role == HostRole::Intake && !event.allowed_on_intake() {
            return Err(LogError::Envelope(EnvelopeError::NotAllowedOnHost));
        }
        if self.primary.is_none() {
            return Err(LogError::NoPrimarySink);
        }
        let reading = self.clock.read();
        let stream = event.class().stream();
        let checkpoint = self.close_due(stream, reading)?;
        let st = self.streams.get(idx(stream)).ok_or(LogError::Encoding)?;
        let (seq, head) = (st.next_seq, st.head);
        let precision = ts_precision(&event, &ctx.actor, self.host_role);
        let header = EnvelopeHeader {
            stream,
            seq,
            ts: truncate(reading.now, precision),
            precision,
            tenant: self.tenant,
            host_role: self.host_role,
            ctx,
            prev: head,
        };
        let next_seq = seq.checked_add(1).ok_or(LogError::SeqOverflow)?;
        let bytes =
            cbor::encode(&envelope_value(&header, &event)).map_err(|_| LogError::Encoding)?;
        let salt = self.salt_for(stream, seq, &event)?;
        let commit = record_commit(&salt, &bytes);
        let hash = chain_hash(&head, &commit);
        let leaf = leaf_hash(&commit);
        let record = CommittedRecord {
            header,
            event,
            bytes,
            salt,
            commit,
            hash,
            leaf,
        };
        self.primary
            .as_mut()
            .ok_or(LogError::NoPrimarySink)?
            .write_record(&record)
            .map_err(LogError::Sink)?;
        let st = self
            .streams
            .get_mut(idx(stream))
            .ok_or(LogError::Encoding)?;
        st.next_seq = next_seq;
        st.head = hash;
        st.pending.push(leaf);
        let secondary_lag = self.to_secondaries(Some(Outgoing::Record(Box::new(record.clone()))));
        Ok(Emitted {
            record,
            checkpoint,
            secondary_lag,
        })
    }

    /// Close every stream slot that has ended (one checkpoint per stream
    /// whose slot boundary passed, empty or not) and retry lagging
    /// secondaries. Call at least once per SECURITY slot.
    pub fn tick(&mut self) -> Result<Vec<SignedCheckpoint>, LogError> {
        let reading = self.clock.read();
        let mut out = Vec::new();
        for stream in [StreamId::Sec, StreamId::Case, StreamId::Sys] {
            if let Some(cp) = self.close_due(stream, reading)? {
                out.push(cp);
            }
        }
        self.to_secondaries(None);
        Ok(out)
    }

    /// If the slot that was open for `stream` has ended at `reading`, sign
    /// the checkpoint for it, dated at the latest passed boundary. One
    /// checkpoint is produced even if several boundaries passed (downtime).
    fn close_due(
        &mut self,
        stream: StreamId,
        reading: ClockReading,
    ) -> Result<Option<SignedCheckpoint>, LogError> {
        let slot = self.policy.slot_ms(stream, self.host_role);
        let boundary = slot_floor(reading.now, slot);
        let open = self
            .streams
            .get(idx(stream))
            .ok_or(LogError::Encoding)?
            .open_slot;
        if boundary <= open {
            return Ok(None);
        }
        self.checkpoint_stream(stream, boundary, reading.drift_exceeded)
            .map(Some)
    }

    fn checkpoint_stream(
        &mut self,
        stream: StreamId,
        boundary: u64,
        drift: bool,
    ) -> Result<SignedCheckpoint, LogError> {
        let st = self.streams.get(idx(stream)).ok_or(LogError::Encoding)?;
        let n = u64::try_from(st.pending.len()).map_err(|_| LogError::Encoding)?;
        let first_seq = st.next_seq.checked_sub(n).ok_or(LogError::Encoding)?;
        let body = CheckpointBody {
            tenant: self.tenant,
            stream: st.stream,
            first_seq,
            end_seq: st.next_seq,
            chain_head: st.head,
            merkle_root: merkle_root(&st.pending),
            prev_checkpoint: st.last_cp_hash,
            signed_at: UtcMillis(boundary),
            clock_flagged: drift,
        };
        let bytes = cbor::encode(&body.to_value()).map_err(|_| LogError::Encoding)?;
        let sig = self
            .signer
            .sign_checkpoint(&bytes)
            .map_err(|_| LogError::Signer)?;
        let cp = SignedCheckpoint {
            body,
            bytes,
            signature: sig.to_bytes(),
        };
        self.primary
            .as_mut()
            .ok_or(LogError::NoPrimarySink)?
            .write_checkpoint(&cp)
            .map_err(LogError::Sink)?;
        let st = self
            .streams
            .get_mut(idx(stream))
            .ok_or(LogError::Encoding)?;
        st.pending.clear();
        st.last_cp_hash = cp.hash();
        st.open_slot = boundary;
        self.to_secondaries(Some(Outgoing::Checkpoint(Box::new(cp.clone()))));
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
        assert_eq!(
            merkle_root(&[h(1), h(2), h(3), h(4), h(5)]),
            node_hash(&l4, &h(5))
        );
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
        assert_ne!(
            genesis(&t, StreamId::Sec),
            checkpoint_genesis(&t, StreamId::Sec)
        );
    }

    #[test]
    fn policy_bounds() {
        assert!(CheckpointPolicy::new(MAX_CHECKPOINT_INTERVAL_MS + 60_000).is_none());
        assert!(CheckpointPolicy::new(0).is_none());
        assert!(CheckpointPolicy::new(1500).is_none());
        assert!(CheckpointPolicy::new(7000).is_none()); // does not divide an hour
        assert!(CheckpointPolicy::new(60_000).is_some());
        let p = CheckpointPolicy::DEFAULT;
        assert_eq!(p.slot_ms(StreamId::Case, HostRole::Core), MS_PER_DAY);
        assert_eq!(p.slot_ms(StreamId::Sys, HostRole::Core), MS_PER_DAY);
        assert_eq!(p.slot_ms(StreamId::Sec, HostRole::Intake), MS_PER_HOUR);
        assert_eq!(p.slot_ms(StreamId::Sec, HostRole::Core), 300_000);
    }

    #[test]
    fn labels_are_prefix_free() {
        let labels = [
            CHAIN_DOMAIN,
            GENESIS_DOMAIN,
            CHECKPOINT_DOMAIN,
            CHECKPOINT_GENESIS_DOMAIN,
            CHECKPOINT_SIG_DOMAIN,
            WITNESS_SIG_DOMAIN,
            COMMIT_DOMAIN,
            REDACTION_SET_DOMAIN,
        ];
        for a in labels {
            assert_eq!(a.iter().filter(|b| **b == 0).count(), 1);
            assert_eq!(a.last(), Some(&0));
            for b in labels {
                if a != b {
                    assert!(!b.starts_with(a), "label is a prefix of another");
                }
            }
        }
    }
}
