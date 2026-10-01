// SPDX-License-Identifier: AGPL-3.0-or-later
//! Dual-approved disposal authorizations for tombstones (AUD-RM1-LOG-16,
//! AUD-RM1-LOG-20; 20 §8, §12, AUD-004, AUD-005, AUD-012).
//!
//! Every tombstone that lets the verifier accept missing content — a
//! `case.disposed` / `case.slot_disposed` record that redacted stubs bind
//! to, or a retention tombstone that a pruned prefix binds to — carries
//! **two Ed25519 signatures by two distinct pinned disposal-approver keys**
//! over a canonical request:
//!
//! * case disposal: `{kind: "case-disposal", v: 1, tenant, case,
//!   receipt_id, case_set: [n, H], slot_set: [n, H]}` where `H` is the
//!   commitment to exactly the redacted `(seq, c_i)` of that stream;
//! * retention: `{kind: "retention", v: 1, tenant, stream,
//!   retention_days}` (a standing authorization of the configured policy;
//!   each prune must also be at least that old).
//!
//! The message signed is `"candor/v1/audit/disposal-auth\0" ‖ request`.
//! Approver keys are dedicated (never the checkpoint key) and are pinned
//! in both the writer ([`crate::AuditLog::set_approver_keys`]) and the
//! verifier ([`crate::verify::VerifyParams::approver_keys`]); a tombstone
//! that does not carry two valid approvals under distinct pinned keys fails
//! verification. Tombstone payloads have private fields, so they can only be
//! built here, from an authorization ([`crate::AuditLog::emit_case_disposal`],
//! [`crate::AuditLog::emit_retention_tombstone`]).

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::cbor::{self, MapBuilder, Value};
use crate::chain::SignerError;
use crate::codes::StreamId;
use crate::field::{AuditField, Sample, sealed};
use crate::ids::{CaseRef, ReceiptId, TenantRef};
use crate::retention::RetentionPolicy;

/// Signature context of a disposal approval.
pub const DISPOSAL_SIG_DOMAIN: &[u8] = b"candor/v1/audit/disposal-auth\0";

/// Maximum number of pinned approver keys.
pub const MAX_APPROVER_KEYS: usize = 16;

/// The pinned set of disposal-approver public keys (≥ 2 distinct, never the
/// checkpoint key).
#[derive(Clone, PartialEq, Eq)]
pub struct ApproverKeys(Vec<VerifyingKey>);

impl fmt::Debug for ApproverKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ApproverKeys({} keys)", self.0.len())
    }
}

impl ApproverKeys {
    /// `None` unless there are 2..=16 distinct keys and none equals the
    /// checkpoint key (a dedicated disposal key, AUD-RM1-LOG-16).
    pub fn new(keys: Vec<VerifyingKey>, checkpoint_key: &VerifyingKey) -> Option<Self> {
        if keys.len() < 2 || keys.len() > MAX_APPROVER_KEYS {
            return None;
        }
        for (i, k) in keys.iter().enumerate() {
            if k == checkpoint_key || keys.iter().skip(i.saturating_add(1)).any(|o| o == k) {
                return None;
            }
        }
        Some(Self(keys))
    }

    fn contains(&self, key: &[u8; 32]) -> Option<&VerifyingKey> {
        self.0.iter().find(|k| k.as_bytes() == key)
    }

    /// Whether `approvals` are two valid signatures over `request` by two
    /// distinct keys of this set (strict Ed25519).
    pub(crate) fn verify(&self, request: &[u8], approvals: &[Approval; 2]) -> bool {
        let [a, b] = approvals;
        if a.key == b.key {
            return false;
        }
        let msg = signing_message(request);
        approvals.iter().all(|ap| {
            self.contains(&ap.key).is_some_and(|k| {
                k.verify_strict(&msg, &Signature::from_bytes(&ap.sig))
                    .is_ok()
            })
        })
    }
}

fn signing_message(request: &[u8]) -> Vec<u8> {
    let mut m = DISPOSAL_SIG_DOMAIN.to_vec();
    m.extend_from_slice(request);
    m
}

/// One approval: approver public key and signature.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Approval {
    pub(crate) key: [u8; 32],
    pub(crate) sig: [u8; 64],
}

impl fmt::Debug for Approval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Approval(key={})", crate::ids::hex(&self.key))
    }
}

impl Approval {
    fn to_value(self) -> Value {
        Value::Array(vec![
            Value::Bytes(self.key.to_vec()),
            Value::Bytes(self.sig.to_vec()),
        ])
    }
    pub(crate) fn from_value(v: &Value) -> Option<Self> {
        match v {
            Value::Array(a) => match a.as_slice() {
                [k, s] => Some(Self {
                    key: k.as_bytes32()?,
                    sig: s.as_bytes()?.try_into().ok()?,
                }),
                _ => None,
            },
            _ => None,
        }
    }
}

/// Commitment to the redacted records of one stream: count and set hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct SetCommit {
    pub(crate) count: u32,
    pub(crate) hash: [u8; 32],
}

impl SetCommit {
    fn to_value(self) -> Value {
        Value::Array(vec![
            Value::Uint(u64::from(self.count)),
            Value::Bytes(self.hash.to_vec()),
        ])
    }
    pub(crate) fn from_value(v: &Value) -> Option<Self> {
        match v {
            Value::Array(a) => match a.as_slice() {
                [n, h] => Some(Self {
                    count: u32::try_from(n.as_u64()?).ok()?,
                    hash: h.as_bytes32()?,
                }),
                _ => None,
            },
            _ => None,
        }
    }
}

/// What is being authorized.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum RequestKind {
    Case {
        case: CaseRef,
        receipt: ReceiptId,
        /// `[CASE, CASE-SLOT]`.
        sets: [SetCommit; 2],
    },
    Retention {
        stream: StreamId,
        days: u32,
    },
}

/// Canonical request bytes. Shared by the writer and the verifier.
pub(crate) fn request_bytes(tenant: &TenantRef, kind: &RequestKind) -> Option<Vec<u8>> {
    let mut m = MapBuilder::new();
    m.put("v", Value::Uint(1)).put("tenant", tenant.to_value());
    match kind {
        RequestKind::Case {
            case,
            receipt,
            sets,
        } => {
            let [c, s] = sets;
            m.put("kind", Value::text("case-disposal"))
                .put("case", case.to_value())
                .put("receipt_id", receipt.to_value())
                .put("case_set", c.to_value())
                .put("slot_set", s.to_value());
        }
        RequestKind::Retention { stream, days } => {
            m.put("kind", Value::text("retention"))
                .put("stream", stream.to_value())
                .put("retention_days", Value::Uint(u64::from(*days)));
        }
    }
    cbor::encode(&m.build()).ok()
}

/// A disposal request to be approved (shown to approvers; signed by them).
#[derive(Clone, PartialEq, Eq)]
pub struct DisposalRequest {
    tenant: TenantRef,
    pub(crate) kind: RequestKind,
    bytes: Vec<u8>,
}

impl fmt::Debug for DisposalRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            RequestKind::Case { sets, .. } => write!(
                f,
                "DisposalRequest::Case(records={}+{})",
                sets[0].count, sets[1].count
            ),
            RequestKind::Retention { stream, days } => write!(
                f,
                "DisposalRequest::Retention({}, {days} days)",
                stream.code()
            ),
        }
    }
}

impl DisposalRequest {
    pub(crate) fn new(tenant: TenantRef, kind: RequestKind) -> Option<Self> {
        let bytes = request_bytes(&tenant, &kind)?;
        Some(Self {
            tenant,
            kind,
            bytes,
        })
    }

    /// Standing authorization of a retention period for an interval-pruned
    /// stream (`sec`, `sys`, `sys-slot`). `None` for other streams or a
    /// period outside the 20 §12 bounds.
    pub fn retention(tenant: TenantRef, stream: StreamId, days: u32) -> Option<Self> {
        let (lo, hi) = RetentionPolicy::bounds(stream)?;
        if !(lo..=hi).contains(&days) {
            return None;
        }
        Self::new(tenant, RequestKind::Retention { stream, days })
    }

    /// Canonical bytes the approvers sign (after the context prefix).
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Tenant.
    pub fn tenant(&self) -> TenantRef {
        self.tenant
    }

    /// The case of a case-disposal request.
    pub fn case(&self) -> Option<CaseRef> {
        match self.kind {
            RequestKind::Case { case, .. } => Some(case),
            RequestKind::Retention { .. } => None,
        }
    }

    /// Total number of records a case disposal redacts (for the approval UI).
    pub fn redacted_count(&self) -> Option<u64> {
        match self.kind {
            RequestKind::Case { sets, .. } => {
                Some(u64::from(sets[0].count).saturating_add(u64::from(sets[1].count)))
            }
            RequestKind::Retention { .. } => None,
        }
    }
}

/// A disposal approver (an approver's hardware key; [`SoftwareApprover`]
/// for tests and development).
pub trait DisposalApprover {
    /// Public key (pinned in [`ApproverKeys`]).
    fn verifying_key(&self) -> VerifyingKey;
    /// Sign `"candor/v1/audit/disposal-auth\0" ‖ request.bytes()`.
    fn approve(&self, request: &DisposalRequest) -> Result<Approval, SignerError>;
}

/// In-memory approver key (tests/dev). Zeroized, never printed.
pub struct SoftwareApprover(SigningKey);

impl SoftwareApprover {
    /// From a 32-byte seed.
    pub fn from_seed(seed: &Zeroizing<[u8; 32]>) -> Self {
        Self(SigningKey::from_bytes(seed))
    }
}

impl fmt::Debug for SoftwareApprover {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SoftwareApprover(pub={})",
            crate::ids::hex(self.0.verifying_key().as_bytes())
        )
    }
}

impl DisposalApprover for SoftwareApprover {
    fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
    fn approve(&self, request: &DisposalRequest) -> Result<Approval, SignerError> {
        Ok(Approval {
            key: self.0.verifying_key().to_bytes(),
            sig: self.0.sign(&signing_message(request.bytes())).to_bytes(),
        })
    }
}

/// Authorization errors.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DisposalError {
    /// The approvals are not two valid signatures by distinct pinned keys.
    BadApprovals,
    /// The authorization does not match the plan / tenant / stream.
    Mismatch,
    /// No pinned approver keys are configured (fail closed).
    NoApproverKeys,
    /// The actor of a disposal must be a staff user.
    StaffActorRequired,
    /// Records of the case are still staged for the open slot; retry after
    /// the next slot boundary.
    StagedRecordsPending,
    /// The prune is younger than the authorized retention period.
    TooEarly,
}

/// A request with two verified approvals.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DisposalAuthorization {
    pub(crate) request: DisposalRequest,
    pub(crate) approvals: [Approval; 2],
}

impl DisposalAuthorization {
    /// Check `a` and `b` against the pinned `keys`.
    pub fn new(
        request: DisposalRequest,
        a: Approval,
        b: Approval,
        keys: &ApproverKeys,
    ) -> Result<Self, DisposalError> {
        let approvals = [a, b];
        if !keys.verify(request.bytes(), &approvals) {
            return Err(DisposalError::BadApprovals);
        }
        Ok(Self { request, approvals })
    }
    /// The approved request.
    pub fn request(&self) -> &DisposalRequest {
        &self.request
    }
}

/// Payload of `case.disposed` / `case.slot_disposed`. Private fields:
/// built only by [`crate::AuditLog::emit_case_disposal`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct CaseDisposal {
    pub(crate) case: CaseRef,
    pub(crate) receipt: ReceiptId,
    pub(crate) sets: [SetCommit; 2],
    pub(crate) approvals: [Approval; 2],
}

impl CaseDisposal {
    /// The disposed case.
    pub fn case(&self) -> CaseRef {
        self.case
    }
    /// Disposal receipt.
    pub fn receipt_id(&self) -> ReceiptId {
        self.receipt
    }
    /// Total removed CASE + CASE-SLOT events (20 §12 / AUD-012).
    pub fn removed_event_count(&self) -> u64 {
        u64::from(self.sets[0].count).saturating_add(u64::from(self.sets[1].count))
    }
}

impl sealed::Sealed for CaseDisposal {}
impl AuditField for CaseDisposal {
    fn to_value(&self) -> Value {
        let [c, s] = self.sets;
        let [a, b] = self.approvals;
        let mut m = MapBuilder::new();
        m.put("case", self.case.to_value())
            .put("receipt_id", self.receipt.to_value())
            .put(
                "removed_event_count",
                Value::Uint(self.removed_event_count()),
            )
            .put("case_set", c.to_value())
            .put("slot_set", s.to_value())
            .put("approvals", Value::Array(vec![a.to_value(), b.to_value()]));
        m.build()
    }
}

impl Sample for CaseDisposal {
    fn sample() -> Self {
        let set = SetCommit {
            count: 1,
            hash: [0x11; 32],
        };
        let ap = Approval {
            key: [0x22; 32],
            sig: [0x33; 64],
        };
        Self {
            case: CaseRef::sample(),
            receipt: ReceiptId::sample(),
            sets: [set, set],
            approvals: [ap, ap],
        }
    }
}

/// Payload of a retention tombstone (`audit.retention_tombstone`,
/// `sys.retention_tombstone`, `sys.slot_retention_tombstone`). Private
/// fields: built only by [`crate::AuditLog::emit_retention_tombstone`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct RetentionPrune {
    pub(crate) stream: StreamId,
    pub(crate) first: u64,
    pub(crate) last: u64,
    pub(crate) anchor_root: [u8; 32],
    pub(crate) days: u32,
    pub(crate) approvals: [Approval; 2],
}

impl RetentionPrune {
    /// Pruned stream.
    pub fn stream(&self) -> StreamId {
        self.stream
    }
    /// Deleted range `(first, last)`.
    pub fn range(&self) -> (u64, u64) {
        (self.first, self.last)
    }
}

impl sealed::Sealed for RetentionPrune {}
impl AuditField for RetentionPrune {
    fn to_value(&self) -> Value {
        let [a, b] = self.approvals;
        let mut m = MapBuilder::new();
        m.put("stream", self.stream.to_value())
            .put(
                "seq_range",
                Value::Array(vec![Value::Uint(self.first), Value::Uint(self.last)]),
            )
            .put(
                "last_deleted_checkpoint_root",
                Value::Bytes(self.anchor_root.to_vec()),
            )
            .put("retention_days", Value::Uint(u64::from(self.days)))
            .put("approvals", Value::Array(vec![a.to_value(), b.to_value()]));
        m.build()
    }
}

impl Sample for RetentionPrune {
    fn sample() -> Self {
        let ap = Approval {
            key: [0x22; 32],
            sig: [0x33; 64],
        };
        Self {
            stream: StreamId::Sec,
            first: 0,
            last: 9,
            anchor_root: [0x44; 32],
            days: 400,
            approvals: [ap, ap],
        }
    }
}
