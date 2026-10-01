// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hash chain, RFC 6962 Merkle checkpoints, Ed25519 checkpoint signing and
//! the [`AuditLog`] writer (20 §8, AUD-001, AUD-002).
//!
//! * Record commitment: `inner_i = SHA-256("candor/v1/audit/record-inner\0"
//!   ‖ salt_i ‖ canonical_bytes(event_i))` and `c_i =
//!   SHA-256("candor/v1/audit/record-commit\0" ‖ tag_i ‖ inner_i)`, where
//!   `tag_i = 0x01 ‖ CaseRef` for redactable (case-bearing CASE/CASE-SLOT)
//!   records and `0x00 ‖ 0^16` otherwise. A redacted stub keeps `(case,
//!   inner)`, so the verifier can check that it belongs to the case its
//!   tombstone names (AUD-RM1-LOG-16). `salt_i` is all-zero except for
//!   redactable records, where it is `HMAC-SHA-256(K_case,
//!   "candor/v1/audit/redaction-salt" ‖ 0 ‖ tenant ‖ stream ‖ seq)` with a
//!   per-case key that is destroyed at disposal, so a redacted stub cannot
//!   be brute-forced back to its (low-entropy) record (AUD-RM1-LOG-08).
//! * Chain: `h_i = SHA-256("candor/v1/audit/chain\0" ‖ h_{i-1} ‖ c_i)` with
//!   `h_{-1} = SHA-256("candor/v1/audit/genesis\0" ‖ tenant ‖ stream)`.
//!   Each envelope also carries `prev = h_{i-1}`.
//! * Merkle: RFC 6962 §2.1 (`leaf = SHA-256(0x00 ‖ c_i)`,
//!   `node = SHA-256(0x01 ‖ left ‖ right)`) over each checkpoint interval.
//! * **Date-only events never share a stream with exact-time events**
//!   (AUD-RM1-LOG-02): an event whose envelope `ts` is date-only (imports,
//!   envelope rejections, canary, relay, source-load health, CASE events by
//!   a system actor, `case.coi_tags_updated`) is routed to `case-slot` /
//!   `sys-slot`, held in memory and written only at the next import-slot
//!   boundary, the slot's records in uniformly shuffled order (OS CSPRNG).
//! * Checkpoints follow a **fixed, data-independent schedule** per stream:
//!   one checkpoint per slot boundary whether or not anything happened
//!   (empty intervals allowed), `signed_at` = the slot boundary. SECURITY,
//!   CASE and SYSTEM: every 5 min (hourly on Z-INTAKE); `case-slot` and
//!   `sys-slot`: at each import-slot boundary (00:00 UTC always is one).
//!   Signed with Ed25519 over `"candor/v1/audit/checkpoint-sig\0" ‖
//!   canonical_bytes`.
//! * Every stream publishes its head checkpoint to the external
//!   [`WitnessSink`] at each witness tick — hourly for SECURITY/CASE/SYSTEM,
//!   every slot for the slot streams, empty ticks included — so tail
//!   truncation beyond the witnessed head is detectable; residual ≤ one
//!   tick (AUD-RM1-LOG-19).
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
use crate::disposal::{
    ApproverKeys, CaseDisposal, DisposalAuthorization, DisposalError, RequestKind, RetentionPrune,
};
use crate::envelope::{
    Actor, EnvelopeError, EnvelopeHeader, EventContext, TsPrecision, envelope_value, truncate,
    ts_precision,
};
use crate::event::AuditEvent;
use crate::field::{AuditField, CheckpointRoot, Seq, SeqRange};
use crate::ids::{
    CaseRef, MS_PER_DAY, MS_PER_HOUR, RandomError, TenantRef, UtcMillis, keyed32, random_bytes,
};
use crate::retention::DeletionPlan;
use crate::sink::{AuditSink, RedactionPlan, SinkError};

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
/// Inner record commitment domain separator.
pub const INNER_DOMAIN: &[u8] = b"candor/v1/audit/record-inner\0";
/// Redaction-set commitment domain separator (`case.disposed.redacted_set`).
pub const REDACTION_SET_DOMAIN: &[u8] = b"candor/v1/audit/redaction-set\0";
/// Per-case redaction salt label (HMAC input, NUL-terminated by `keyed32`).
const SALT_LABEL: &[u8] = b"candor/v1/audit/redaction-salt";

/// Default (and maximum) checkpoint interval of the exact-time streams:
/// 5 minutes (20 §8).
pub const MAX_CHECKPOINT_INTERVAL_MS: u64 = 5 * 60 * 1000;
/// Import-slot granularity (ADR-038(1)): 15 minutes.
pub const IMPORT_SLOT_GRANULARITY_MS: u64 = 15 * 60 * 1000;
/// Witness tick of the exact-time streams: one hour (AUD-RM1-LOG-19).
pub const WITNESS_TICK_MS: u64 = MS_PER_HOUR;

/// All streams, in index order.
pub const STREAMS: [StreamId; 5] = [
    StreamId::Sec,
    StreamId::Case,
    StreamId::Sys,
    StreamId::CaseSlot,
    StreamId::SysSlot,
];

pub(crate) fn stream_byte(s: StreamId) -> u8 {
    match s {
        StreamId::Sec => 1,
        StreamId::Case => 2,
        StreamId::Sys => 3,
        StreamId::CaseSlot => 4,
        StreamId::SysSlot => 5,
    }
}

/// Whether `s` is a date-only slot stream.
pub const fn is_slot_stream(s: StreamId) -> bool {
    matches!(s, StreamId::CaseSlot | StreamId::SysSlot)
}

pub(crate) fn stream_of_code(c: &str) -> Option<StreamId> {
    STREAMS.into_iter().find(|s| s.code() == c)
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

/// Inner record commitment over the salt and the canonical event bytes.
pub fn record_inner(salt: &[u8; 32], canonical: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(INNER_DOMAIN);
    h.update(salt);
    h.update(canonical);
    h.finalize().into()
}

/// Record commitment `c_i` binding the case tag (`Some(case)` for a
/// redactable record) and the inner commitment.
pub fn record_commit(case: Option<&CaseRef>, inner: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(COMMIT_DOMAIN);
    match case {
        Some(c) => {
            h.update([1]);
            h.update(c.as_bytes());
        }
        None => {
            h.update([0]);
            h.update([0u8; 16]);
        }
    }
    h.update(inner);
    h.finalize().into()
}

/// The case a record is bound to: case-bearing CASE / CASE-SLOT records
/// except tombstones (they are the redactable ones).
pub(crate) fn case_tag(stream: StreamId, event: &AuditEvent) -> Option<CaseRef> {
    if !matches!(stream, StreamId::Case | StreamId::CaseSlot) || event.is_tombstone() {
        return None;
    }
    event.case_ref()
}

/// The verifier's view of [`case_tag`], from a decoded record: payload
/// `case` (16 bytes) or `subject` (16 bytes, or `["case", 16 bytes]`).
pub(crate) fn case_tag_of_value(stream: StreamId, v: &Value) -> Option<[u8; 16]> {
    if !matches!(stream, StreamId::Case | StreamId::CaseSlot) {
        return None;
    }
    if matches!(
        v.get("type").and_then(Value::as_text),
        Some("case.disposed" | "case.slot_disposed")
    ) {
        return None;
    }
    let pl = v.get("payload")?;
    let b16 = |x: &Value| -> Option<[u8; 16]> { x.as_bytes()?.try_into().ok() };
    if let Some(c) = pl.get("case") {
        return b16(c);
    }
    match pl.get("subject")? {
        Value::Bytes(_) => b16(pl.get("subject")?),
        Value::Array(a) => match a.as_slice() {
            [t, c] if t.as_text() == Some("case") => b16(c),
            _ => None,
        },
        _ => None,
    }
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
/// by the `case.disposed` tombstone (AUD-RM1-LOG-01). Crate-private
/// (AUD-RM1-LOG-16).
pub(crate) fn redaction_set_hash(entries: &[(u64, [u8; 32])]) -> [u8; 32] {
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
        let stream = stream_of_code(v.get("stream")?.as_text()?)?;
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

/// Checkpoint schedule (AUD-RM1-LOG-02). The exact-time interval is
/// configurable only stricter (shorter) than 5 minutes and must divide an
/// hour; Z-INTAKE checkpoints its streams hourly. The slot streams close at
/// the import-slot boundaries (15-minute multiples of the UTC day; 00:00 is
/// always one, so a slot never spans two dates). Default import schedule:
/// 4×/day at 00:00, 06:00, 12:00, 18:00 (ADR-038(1)).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CheckpointPolicy {
    sec_interval_ms: u64,
    /// Bit `i` set: a slot boundary at `i × 15 min` after 00:00 UTC.
    import_slots: u128,
}

const DEFAULT_IMPORT_SLOTS: u128 = 1 | (1 << 24) | (1 << 48) | (1 << 72);

impl CheckpointPolicy {
    /// Spec default: exact-time streams every 5 minutes, import slots at
    /// 00:00, 06:00, 12:00 and 18:00 UTC.
    pub const DEFAULT: Self = Self {
        sec_interval_ms: MAX_CHECKPOINT_INTERVAL_MS,
        import_slots: DEFAULT_IMPORT_SLOTS,
    };
    /// `None` unless `1 s ≤ sec_interval_ms ≤ 5 min`, a whole number of
    /// seconds, and a divisor of one hour.
    pub fn new(sec_interval_ms: u64) -> Option<Self> {
        ((1000..=MAX_CHECKPOINT_INTERVAL_MS).contains(&sec_interval_ms)
            && sec_interval_ms.is_multiple_of(1000)
            && MS_PER_HOUR.is_multiple_of(sec_interval_ms))
        .then_some(Self {
            sec_interval_ms,
            import_slots: DEFAULT_IMPORT_SLOTS,
        })
    }
    /// Set the import-slot schedule (minutes after 00:00 UTC, each a
    /// multiple of 15 and < 1440; 00:00 is always added). `None` on an
    /// invalid minute. HIGH/GOV (1×/day): e.g. `&[180]`.
    pub fn with_import_slots(mut self, minutes: &[u16]) -> Option<Self> {
        let mut mask: u128 = 1;
        for m in minutes {
            if !m.is_multiple_of(15) || *m >= 1440 {
                return None;
            }
            mask |= 1u128.checked_shl(u32::from(*m / 15))?;
        }
        self.import_slots = mask;
        Some(self)
    }
    /// Checkpoint interval of an exact-time stream on a host of role `host`.
    pub fn slot_ms(&self, stream: StreamId, host: HostRole) -> u64 {
        match stream {
            // Slot streams are not fixed-interval; see `boundary_floor`.
            StreamId::CaseSlot | StreamId::SysSlot => MS_PER_DAY,
            // Z-INTAKE timestamps are hour-truncated (LOG-004).
            _ if host == HostRole::Intake => MS_PER_HOUR,
            _ => self.sec_interval_ms,
        }
    }
    /// The latest schedule boundary of `stream` at or before `now`.
    pub fn boundary_floor(&self, stream: StreamId, host: HostRole, now: UtcMillis) -> u64 {
        if !is_slot_stream(stream) {
            return slot_floor(now, self.slot_ms(stream, host));
        }
        let day = slot_floor(now, MS_PER_DAY);
        let into = now.0.saturating_sub(day) / IMPORT_SLOT_GRANULARITY_MS;
        let mut best = 0u64;
        for i in 0..96u64 {
            if i > into {
                break;
            }
            if self.import_slots & (1u128 << i) != 0 {
                best = i;
            }
        }
        day.saturating_add(best.saturating_mul(IMPORT_SLOT_GRANULARITY_MS))
    }
    /// Whether a checkpoint closing `boundary` is a witness tick, given the
    /// boundary of the last published head (AUD-RM1-LOG-19): every slot
    /// boundary for the slot streams; the first boundary of each new hour
    /// for the others.
    pub fn witness_due(&self, stream: StreamId, last_published: u64, boundary: u64) -> bool {
        is_slot_stream(stream) || boundary / WITNESS_TICK_MS > last_published / WITNESS_TICK_MS
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

/// External witness that receives every stream's head checkpoint at each
/// witness tick (AUD-RM1-LOG-19). The witness must alarm when a tick is
/// missed (empty ticks are published too, so silence is meaningful).
pub trait WitnessSink {
    /// Publish `head`, the newest checkpoint of its stream.
    fn publish(&mut self, head: &SignedCheckpoint) -> Result<(), WitnessError>;
}

/// The witness could not be reached; the head stays queued and is retried
/// on every emission and tick.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WitnessError;

/// A record committed by [`AuditLog`]. Only the log can construct one, so
/// sinks can only ever receive typed, allow-listed events.
#[derive(Clone, PartialEq, Eq)]
pub struct CommittedRecord {
    header: EnvelopeHeader,
    event: AuditEvent,
    bytes: Vec<u8>,
    salt: [u8; 32],
    inner: [u8; 32],
    case: Option<CaseRef>,
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
    /// Inner commitment (kept in a redacted stub).
    pub fn inner(&self) -> &[u8; 32] {
        &self.inner
    }
    /// The case a redactable record is bound to.
    pub fn case_tag(&self) -> Option<CaseRef> {
        self.case
    }
    /// The redacted stub of this record, bound to the tombstone at
    /// `tombstone_seq`; `None` if the record is not redactable.
    pub fn to_stub(&self, tombstone_seq: u64) -> Option<ChainRecord> {
        self.case.map(|case| ChainRecord::Redacted {
            seq: self.header.seq,
            case,
            inner: self.inner,
            tombstone_seq,
        })
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
    /// removed. Valid only in the CASE / CASE-SLOT streams and only when
    /// the tombstone at `tombstone_seq` names the same `case` and commits
    /// to it.
    Redacted {
        /// Sequence number.
        seq: u64,
        /// The case the record was bound to (committed in `c_i`).
        case: CaseRef,
        /// Inner commitment; `c_i = record_commit(Some(case), inner)`.
        inner: [u8; 32],
        /// Sequence number of the covering tombstone.
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
    /// The OS random number generator failed (slot shuffle; fail closed).
    Random,
    /// An artefact-derived field (seq, range, checkpoint root) was not
    /// derived under this log's checkpoint key (AUD-RM1-LOG-17).
    ForeignArtefact,
    /// Tombstones are written only through the disposal API
    /// (AUD-RM1-LOG-16).
    TombstoneViaApi,
    /// Disposal authorization refused.
    Disposal(DisposalError),
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
            Self::Random => "audit: random number generator failed",
            Self::ForeignArtefact => "audit: artefact not derived under this log's key",
            Self::TombstoneViaApi => "audit: tombstones only through the disposal API",
            Self::Disposal(_) => "audit: disposal authorization refused",
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

/// A date-only event waiting for its slot boundary. Holds the case key
/// (fetched at emission, so a missing key fails the emission, not the
/// flush); zeroized on drop.
struct Staged {
    ctx: EventContext,
    event: AuditEvent,
    ts: UtcMillis,
    key: Option<CaseCommitKey>,
}

struct StreamState {
    stream: StreamId,
    next_seq: u64,
    head: [u8; 32],
    pending: Vec<[u8; 32]>,
    last_cp_hash: [u8; 32],
    /// Start of the currently open schedule slot.
    open_slot: u64,
    /// Slot streams: events of the open slot, in arrival order.
    staged: Vec<Staged>,
    /// Slot streams: the shuffled batch of a closing slot that is being
    /// written (non-empty only after a primary-sink failure mid-batch).
    flushing: VecDeque<Staged>,
    /// Boundary of the last head published to the witness.
    witnessed_at: u64,
    /// Head waiting to be published to the witness.
    witness_pending: Option<SignedCheckpoint>,
}

impl fmt::Debug for StreamState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamState")
            .field("stream", &self.stream)
            .field("next_seq", &self.next_seq)
            .finish_non_exhaustive()
    }
}

/// Result of [`AuditLog::emit`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Emitted {
    /// The committed record; `None` when the event is date-only and was
    /// staged for the next slot boundary of its slot stream (written then,
    /// in shuffled order, AUD-RM1-LOG-02).
    pub record: Option<CommittedRecord>,
    /// The scheduled checkpoint that closed the previous slot of this
    /// stream before the record was appended or staged, if one was due.
    pub checkpoint: Option<SignedCheckpoint>,
    /// At least one secondary sink has not yet received everything
    /// (outbox non-empty or desynchronised).
    pub secondary_lag: bool,
}

/// Maximum items queued for one secondary sink before it is declared
/// desynchronised (and must be rebuilt from the primary store).
pub const MAX_SECONDARY_OUTBOX: usize = 65_536;

/// Maximum date-only events staged per slot (fail closed beyond).
pub const MAX_STAGED_PER_SLOT: usize = 1 << 20;

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

/// Uniform integer in `0..bound` (rejection sampling over the OS CSPRNG).
fn uniform_below(bound: u64) -> Result<u64, RandomError> {
    if bound <= 1 {
        return Ok(0);
    }
    // Largest multiple of `bound` (bound ≥ 2, so no underflow/zero divisor).
    let zone = u64::MAX.saturating_sub(u64::MAX.checked_rem(bound).unwrap_or(0));
    loop {
        let v = u64::from_le_bytes(random_bytes::<8>()?);
        if v < zone {
            return v.checked_rem(bound).ok_or(RandomError);
        }
    }
}

/// Uniform Fisher–Yates shuffle (AUD-RM1-LOG-02).
fn shuffle<T>(v: &mut [T]) -> Result<(), RandomError> {
    let mut i = v.len();
    while i > 1 {
        let j = usize::try_from(uniform_below(u64::try_from(i).map_err(|_| RandomError)?)?)
            .map_err(|_| RandomError)?;
        i = i.saturating_sub(1);
        v.swap(i, j);
    }
    Ok(())
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
///
/// Date-only events are staged in memory until their slot boundary
/// (AUD-RM1-LOG-02). **Residual:** a process crash loses the staged events
/// of the open slot (at most one import slot of date-only events); the
/// restart itself is visible in `sys.service_started`.
pub struct AuditLog<S: CheckpointSigner, C: AuditClock> {
    tenant: TenantRef,
    host_role: HostRole,
    signer: S,
    clock: C,
    policy: CheckpointPolicy,
    streams: [StreamState; 5],
    primary: Option<Box<dyn AuditSink + Send>>,
    secondaries: Vec<Secondary>,
    case_keys: Option<Box<dyn CaseKeyStore + Send>>,
    approvers: Option<ApproverKeys>,
    witness: Option<Box<dyn WitnessSink + Send>>,
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
        StreamId::CaseSlot => 3,
        StreamId::SysSlot => 4,
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
        let mk = |stream| {
            let open = policy.boundary_floor(stream, host_role, now);
            StreamState {
                stream,
                next_seq: 0,
                head: genesis(&tenant, stream),
                pending: Vec::new(),
                last_cp_hash: checkpoint_genesis(&tenant, stream),
                open_slot: open,
                staged: Vec::new(),
                flushing: VecDeque::new(),
                witnessed_at: open,
                witness_pending: None,
            }
        };
        Self {
            tenant,
            host_role,
            signer,
            clock,
            policy,
            streams: STREAMS.map(mk),
            primary: None,
            secondaries: Vec::new(),
            case_keys: None,
            approvers: None,
            witness: None,
        }
    }

    /// Resume a stream from verified state.
    pub fn resume(&mut self, stream: StreamId, r: StreamResume) {
        let now = self.clock.read().now;
        let open = self.policy.boundary_floor(stream, self.host_role, now);
        if let Some(st) = self.streams.get_mut(idx(stream)) {
            st.next_seq = r.next_seq;
            st.head = r.head;
            st.pending = r.pending_leaves;
            st.last_cp_hash = r.last_checkpoint;
            st.open_slot = open;
            st.witnessed_at = open;
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

    /// Pin the disposal-approver keys (required for any tombstone,
    /// AUD-RM1-LOG-16).
    pub fn set_approver_keys(&mut self, keys: ApproverKeys) {
        self.approvers = Some(keys);
    }

    /// Attach the external witness (AUD-RM1-LOG-19).
    pub fn set_witness(&mut self, witness: Box<dyn WitnessSink + Send>) {
        self.witness = Some(witness);
    }

    /// Whether any stream's head is still waiting to reach the witness.
    pub fn witness_lag(&self) -> bool {
        self.streams.iter().any(|s| s.witness_pending.is_some())
    }

    /// Tenant.
    pub fn tenant(&self) -> TenantRef {
        self.tenant
    }

    /// Checkpoint verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }

    fn own(&self, cp: &SignedCheckpoint) -> Option<[u8; 32]> {
        let key = self.signer.verifying_key();
        (cp.verify_signature(&key) && cp.body().tenant == self.tenant).then(|| key.to_bytes())
    }

    /// One past the last sequence number of one of **this log's**
    /// checkpoints (for `audit.witness_*`); `None` for a checkpoint not
    /// signed by this log's key for its tenant (AUD-RM1-LOG-17).
    pub fn checkpoint_seq(&self, cp: &SignedCheckpoint) -> Option<Seq> {
        Some(Seq::bound(cp.body().end_seq, self.own(cp)?))
    }

    /// The (non-empty) interval of one of this log's checkpoints.
    pub fn checkpoint_range(&self, cp: &SignedCheckpoint) -> Option<SeqRange> {
        let origin = self.own(cp)?;
        let b = cp.body();
        (b.end_seq > b.first_seq).then(|| SeqRange {
            first: b.first_seq,
            last: b.end_seq.saturating_sub(1),
            origin,
        })
    }

    /// The Merkle root of one of this log's checkpoints
    /// (`audit.checkpoint_signed.root`).
    pub fn checkpoint_root(&self, cp: &SignedCheckpoint) -> Option<CheckpointRoot> {
        Some(CheckpointRoot {
            root: cp.body().merkle_root,
            origin: self.own(cp)?,
        })
    }

    fn feed_secondaries(&mut self, item: Option<Outgoing>) -> bool {
        let mut lag = false;
        for s in &mut self.secondaries {
            lag |= s.deliver(item.clone());
        }
        lag
    }

    fn feed_witness(&mut self) {
        let Some(w) = self.witness.as_mut() else {
            return;
        };
        for st in &mut self.streams {
            if let Some(cp) = st.witness_pending.as_ref()
                && w.publish(cp).is_ok()
            {
                st.witnessed_at = cp.body().signed_at.0;
                st.witness_pending = None;
            }
        }
    }

    fn case_key(&mut self, case: Option<CaseRef>) -> Result<Option<CaseCommitKey>, LogError> {
        let Some(case) = case else {
            return Ok(None);
        };
        let keys = self
            .case_keys
            .as_mut()
            .ok_or(LogError::CaseKeyUnavailable)?;
        keys.commit_key(case)
            .map(Some)
            .map_err(|_| LogError::CaseKeyUnavailable)
    }

    /// Emit one typed event (the only way to write an audit record).
    ///
    /// A checkpoint due for the event's stream is produced first (so a
    /// record is never covered by a checkpoint dated before it); if that
    /// fails, nothing is written. Date-only events are staged and written
    /// at the next slot boundary of their slot stream ([`Emitted::record`]
    /// is then `None`). Tombstones are refused here: use
    /// [`AuditLog::emit_case_disposal`] / [`AuditLog::emit_retention_tombstone`].
    pub fn emit(&mut self, ctx: EventContext, event: AuditEvent) -> Result<Emitted, LogError> {
        if event.is_tombstone() {
            return Err(LogError::TombstoneViaApi);
        }
        self.emit_checked(ctx, event)
    }

    fn emit_checked(&mut self, ctx: EventContext, event: AuditEvent) -> Result<Emitted, LogError> {
        ctx.validate().map_err(LogError::Envelope)?;
        if self.host_role == HostRole::Intake && !event.allowed_on_intake() {
            return Err(LogError::Envelope(EnvelopeError::NotAllowedOnHost));
        }
        if !event.origins_ok(self.signer.verifying_key().as_bytes()) {
            return Err(LogError::ForeignArtefact);
        }
        if self.primary.is_none() {
            return Err(LogError::NoPrimarySink);
        }
        let reading = self.clock.read();
        let precision = ts_precision(&event, &ctx.actor, self.host_role);
        let stream = if precision == TsPrecision::Day {
            event.class().slot_stream()
        } else {
            event.class().stream()
        };
        let checkpoint = self.close_due(stream, reading)?;
        let ts = truncate(reading.now, precision);
        let key = self.case_key(case_tag(stream, &event))?;
        let staged = Staged {
            ctx,
            event,
            ts,
            key,
        };
        if is_slot_stream(stream) {
            let st = self
                .streams
                .get_mut(idx(stream))
                .ok_or(LogError::Encoding)?;
            if st.staged.len() >= MAX_STAGED_PER_SLOT {
                return Err(LogError::SeqOverflow);
            }
            st.staged.push(staged);
            let secondary_lag = self.feed_secondaries(None);
            self.feed_witness();
            return Ok(Emitted {
                record: None,
                checkpoint,
                secondary_lag,
            });
        }
        let record = self.commit_now(stream, &staged, precision)?;
        let secondary_lag = self.feed_secondaries(Some(Outgoing::Record(Box::new(record.clone()))));
        self.feed_witness();
        Ok(Emitted {
            record: Some(record),
            checkpoint,
            secondary_lag,
        })
    }

    /// Build, write (primary) and chain one record at the stream's next
    /// sequence number.
    fn commit_now(
        &mut self,
        stream: StreamId,
        s: &Staged,
        precision: TsPrecision,
    ) -> Result<CommittedRecord, LogError> {
        let st = self.streams.get(idx(stream)).ok_or(LogError::Encoding)?;
        let (seq, head) = (st.next_seq, st.head);
        let header = EnvelopeHeader {
            stream,
            seq,
            ts: s.ts,
            precision,
            tenant: self.tenant,
            host_role: self.host_role,
            ctx: s.ctx,
            prev: head,
        };
        let next_seq = seq.checked_add(1).ok_or(LogError::SeqOverflow)?;
        let bytes =
            cbor::encode(&envelope_value(&header, &s.event)).map_err(|_| LogError::Encoding)?;
        let case = case_tag(stream, &s.event);
        let salt = match (&s.key, case) {
            (Some(k), Some(_)) => k.salt(&self.tenant, stream, seq),
            (None, Some(_)) => return Err(LogError::CaseKeyUnavailable),
            _ => [0; 32],
        };
        let inner = record_inner(&salt, &bytes);
        let commit = record_commit(case.as_ref(), &inner);
        let hash = chain_hash(&head, &commit);
        let leaf = leaf_hash(&commit);
        let record = CommittedRecord {
            header,
            event: s.event.clone(),
            bytes,
            salt,
            inner,
            case,
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
        Ok(record)
    }

    /// Close every stream slot that has ended (one checkpoint per stream
    /// whose slot boundary passed, empty or not; slot streams first write
    /// their shuffled batch), publish due heads to the witness and retry
    /// lagging secondaries. Call at least once per exact-time checkpoint
    /// interval.
    pub fn tick(&mut self) -> Result<Vec<SignedCheckpoint>, LogError> {
        let reading = self.clock.read();
        let mut out = Vec::new();
        for stream in STREAMS {
            if let Some(cp) = self.close_due(stream, reading)? {
                out.push(cp);
            }
        }
        self.feed_secondaries(None);
        self.feed_witness();
        Ok(out)
    }

    /// If the slot that was open for `stream` has ended at `reading`, write
    /// a slot stream's staged batch (uniformly shuffled) and sign the
    /// checkpoint for the slot, dated at the latest passed boundary. One
    /// checkpoint is produced even if several boundaries passed (downtime).
    fn close_due(
        &mut self,
        stream: StreamId,
        reading: ClockReading,
    ) -> Result<Option<SignedCheckpoint>, LogError> {
        let boundary = self
            .policy
            .boundary_floor(stream, self.host_role, reading.now);
        let open = self
            .streams
            .get(idx(stream))
            .ok_or(LogError::Encoding)?
            .open_slot;
        if boundary <= open {
            return Ok(None);
        }
        if is_slot_stream(stream) {
            self.flush_slot(stream)?;
        }
        self.checkpoint_stream(stream, boundary, reading.drift_exceeded)
            .map(Some)
    }

    /// Write the staged batch of a closing slot in shuffled order. On a
    /// primary failure the rest of the (already shuffled) batch stays queued
    /// and the slot stays open; the next call resumes it.
    fn flush_slot(&mut self, stream: StreamId) -> Result<(), LogError> {
        let st = self
            .streams
            .get_mut(idx(stream))
            .ok_or(LogError::Encoding)?;
        if st.flushing.is_empty() && !st.staged.is_empty() {
            let mut batch = core::mem::take(&mut st.staged);
            if let Err(e) = shuffle(&mut batch) {
                st.staged = batch;
                return Err(LogError::from(e));
            }
            st.flushing = batch.into();
        }
        loop {
            let st = self
                .streams
                .get_mut(idx(stream))
                .ok_or(LogError::Encoding)?;
            let Some(next) = st.flushing.pop_front() else {
                break;
            };
            match self.commit_now(stream, &next, TsPrecision::Day) {
                Ok(record) => {
                    self.feed_secondaries(Some(Outgoing::Record(Box::new(record))));
                }
                Err(e) => {
                    if let Some(st) = self.streams.get_mut(idx(stream)) {
                        st.flushing.push_front(next);
                    }
                    return Err(e);
                }
            }
        }
        Ok(())
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
        let witness = self.witness.is_some();
        let policy = self.policy;
        let st = self
            .streams
            .get_mut(idx(stream))
            .ok_or(LogError::Encoding)?;
        st.pending.clear();
        st.last_cp_hash = cp.hash();
        st.open_slot = boundary;
        if witness
            && (st.witness_pending.is_some()
                || policy.witness_due(stream, st.witnessed_at, boundary))
        {
            // Only the newest head matters: it attests every earlier one
            // through the checkpoint chain.
            st.witness_pending = Some(cp.clone());
        }
        self.feed_secondaries(Some(Outgoing::Checkpoint(Box::new(cp.clone()))));
        Ok(cp)
    }

    fn require_approved(&self, auth: &DisposalAuthorization) -> Result<(), LogError> {
        let keys = self
            .approvers
            .as_ref()
            .ok_or(LogError::Disposal(DisposalError::NoApproverKeys))?;
        if auth.request.tenant() != self.tenant {
            return Err(LogError::Disposal(DisposalError::Mismatch));
        }
        if !keys.verify(auth.request.bytes(), &auth.approvals) {
            return Err(LogError::Disposal(DisposalError::BadApprovals));
        }
        Ok(())
    }

    /// Write the dual-approved disposal tombstones of `plan` (AUD-012,
    /// AUD-RM1-LOG-16): `case.disposed` into CASE now (returned), and
    /// `case.slot_disposed` into CASE-SLOT at its next slot boundary. The
    /// authorization must approve exactly this plan; the actor must be
    /// staff. Then apply the plan per stream
    /// ([`crate::sink::MemoryStore::apply_case_redaction`]) and destroy the
    /// case key.
    pub fn emit_case_disposal(
        &mut self,
        ctx: EventContext,
        plan: &RedactionPlan,
        auth: &DisposalAuthorization,
    ) -> Result<Emitted, LogError> {
        if !matches!(ctx.actor, Actor::Staff(_)) {
            return Err(LogError::Disposal(DisposalError::StaffActorRequired));
        }
        self.require_approved(auth)?;
        let RequestKind::Case {
            case,
            receipt,
            sets,
        } = auth.request.kind
        else {
            return Err(LogError::Disposal(DisposalError::Mismatch));
        };
        if case != plan.case() || sets != plan.set_commits() {
            return Err(LogError::Disposal(DisposalError::Mismatch));
        }
        // A record of the case still staged for the open slot would be
        // written after the tombstone and escape redaction.
        let slot = self
            .streams
            .get(idx(StreamId::CaseSlot))
            .ok_or(LogError::Encoding)?;
        if slot
            .staged
            .iter()
            .chain(slot.flushing.iter())
            .any(|s| case_tag(StreamId::CaseSlot, &s.event) == Some(case))
        {
            return Err(LogError::Disposal(DisposalError::StagedRecordsPending));
        }
        let disposal = CaseDisposal {
            case,
            receipt,
            sets,
            approvals: auth.approvals,
        };
        let out = self.emit_checked(ctx, AuditEvent::CaseDisposed { disposal })?;
        self.emit_checked(ctx, AuditEvent::CaseSlotDisposed { disposal })?;
        Ok(out)
    }

    /// Write the dual-approved retention tombstone of `plan` into the
    /// pruned stream (AUD-005, AUD-RM1-LOG-16/20). `auth` must be a standing
    /// retention authorization for the plan's stream and period; the
    /// deleted intervals must be at least that old. `sys-slot` tombstones
    /// are date-only and written at the next slot boundary.
    pub fn emit_retention_tombstone(
        &mut self,
        ctx: EventContext,
        plan: &DeletionPlan,
        auth: &DisposalAuthorization,
    ) -> Result<Emitted, LogError> {
        self.require_approved(auth)?;
        let RequestKind::Retention { stream, days } = auth.request.kind else {
            return Err(LogError::Disposal(DisposalError::Mismatch));
        };
        if stream != plan.stream || days != plan.days {
            return Err(LogError::Disposal(DisposalError::Mismatch));
        }
        let now = self.clock.read().now.0;
        let min_age = u64::from(days).saturating_mul(MS_PER_DAY);
        if now.saturating_sub(plan.anchor_signed_at) < min_age {
            return Err(LogError::Disposal(DisposalError::TooEarly));
        }
        let prune = RetentionPrune {
            stream,
            first: plan.range.first,
            last: plan.range.last,
            anchor_root: plan.anchor_root,
            days,
            approvals: auth.approvals,
        };
        let event = match stream {
            StreamId::Sec => AuditEvent::AuditRetentionTombstone { prune },
            StreamId::Sys => AuditEvent::SysRetentionTombstone { prune },
            StreamId::SysSlot => AuditEvent::SysSlotRetentionTombstone { prune },
            StreamId::Case | StreamId::CaseSlot => {
                return Err(LogError::Disposal(DisposalError::Mismatch));
            }
        };
        self.emit_checked(ctx, event)
    }
}

impl From<RandomError> for LogError {
    fn from(_: RandomError) -> Self {
        Self::Random
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
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
        assert_eq!(p.slot_ms(StreamId::Case, HostRole::Core), 300_000);
        assert_eq!(p.slot_ms(StreamId::Sys, HostRole::Core), 300_000);
        assert_eq!(p.slot_ms(StreamId::Sec, HostRole::Intake), MS_PER_HOUR);
        assert_eq!(p.slot_ms(StreamId::Sys, HostRole::Intake), MS_PER_HOUR);
        assert_eq!(p.slot_ms(StreamId::Sec, HostRole::Core), 300_000);
        // Import slots: 00:00, 06:00, 12:00, 18:00 by default.
        let day = 20_000 * MS_PER_DAY;
        let at = |h: u64, m: u64| UtcMillis(day + h * MS_PER_HOUR + m * 60_000);
        let b = |t| p.boundary_floor(StreamId::CaseSlot, HostRole::Core, t);
        assert_eq!(b(at(0, 0)), day);
        assert_eq!(b(at(5, 59)), day);
        assert_eq!(b(at(6, 0)), day + 6 * MS_PER_HOUR);
        assert_eq!(b(at(23, 59)), day + 18 * MS_PER_HOUR);
        let high = CheckpointPolicy::DEFAULT.with_import_slots(&[180]).unwrap();
        let b = |t| high.boundary_floor(StreamId::SysSlot, HostRole::Core, t);
        assert_eq!(b(at(2, 59)), day);
        assert_eq!(b(at(3, 0)), day + 3 * MS_PER_HOUR);
        assert_eq!(b(at(23, 0)), day + 3 * MS_PER_HOUR);
        assert!(CheckpointPolicy::DEFAULT.with_import_slots(&[7]).is_none());
        assert!(
            CheckpointPolicy::DEFAULT
                .with_import_slots(&[1440])
                .is_none()
        );
        // Witness ticks: hourly for exact-time streams, every slot otherwise.
        assert!(!p.witness_due(StreamId::Sec, day, day + 300_000));
        assert!(p.witness_due(StreamId::Sec, day + 3_300_000, day + MS_PER_HOUR));
        assert!(p.witness_due(StreamId::CaseSlot, day, day + 6 * MS_PER_HOUR));
    }

    // The writer's case binding (`case_tag`) and the verifier's view from
    // the encoded record (`case_tag_of_value`) agree for every catalog
    // type in every stream (AUD-RM1-LOG-16 defence in depth).
    #[test]
    fn case_tag_writer_and_verifier_agree() {
        let c = CaseRef::from_bytes([0x5a; 16]);
        for e in AuditEvent::samples() {
            for stream in STREAMS {
                let h = EnvelopeHeader {
                    stream,
                    seq: 1,
                    ts: UtcMillis(0),
                    precision: TsPrecision::Millis,
                    tenant: TenantRef::from_bytes([1; 16]),
                    host_role: HostRole::Core,
                    ctx: EventContext::system(crate::codes::Service::Upload),
                    prev: [0; 32],
                };
                let v = cbor::decode(&cbor::encode(&envelope_value(&h, &e)).unwrap()).unwrap();
                assert_eq!(
                    case_tag(stream, &e).map(|c| *c.as_bytes()),
                    case_tag_of_value(stream, &v),
                    "{} in {}",
                    e.type_name(),
                    stream.code()
                );
            }
        }
        assert!(case_tag(StreamId::Case, &AuditEvent::CaseOpened { case: c }).is_some());
    }

    #[test]
    fn shuffle_is_a_permutation_and_varies() {
        let base: Vec<u32> = (0..64).collect();
        let mut a = base.clone();
        shuffle(&mut a).unwrap();
        let mut sorted = a.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, base);
        let mut b = base.clone();
        shuffle(&mut b).unwrap();
        assert!(a != base || b != base);
        assert!(uniform_below(1).unwrap() == 0);
        for _ in 0..100 {
            assert!(uniform_below(3).unwrap() < 3);
        }
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
            INNER_DOMAIN,
            REDACTION_SET_DOMAIN,
            crate::disposal::DISPOSAL_SIG_DOMAIN,
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
