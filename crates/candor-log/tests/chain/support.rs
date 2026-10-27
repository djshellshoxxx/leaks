// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared fixtures and test doubles for the chain test modules.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::common::*;
use candor_log::cbor;
use candor_log::chain::{ChainRecord, CheckpointSigner, SignerError};
use candor_log::codes::*;
use candor_log::disposal::{DisposalApprover, DisposalAuthorization, DisposalRequest};
use candor_log::ids::*;
use candor_log::sink::{AuditSink, MemorySink, MemoryStore, RedactionPlan, SinkError};
use candor_log::verify::{VerifyParams, verify_stream};
use candor_log::{
    AuditEvent, AuditLog, CheckpointPolicy, CommittedRecord, EventContext, SignedCheckpoint,
    SoftwareSigner, WitnessError, WitnessSink,
};

pub(super) const SLOT6H: u64 = 6 * 3_600_000;

pub(super) fn rec(e: candor_log::Emitted) -> CommittedRecord {
    e.record.expect("committed immediately")
}

pub(super) fn imported(n: u8) -> AuditEvent {
    AuditEvent::CaseImported {
        case: case(n),
        channel_id: channel(1),
        received_day: UtcMillis(T0).day(),
        import_slot_date: UtcMillis(T0).day(),
    }
}

/// Advance to just after the next import-slot boundary and tick (flushes
/// the slot streams).
pub(super) fn next_slot(log: &mut AuditLog<SoftwareSigner, TestClock>, clock: &TestClock) {
    let now = clock.now();
    clock.advance(SLOT6H - now % SLOT6H + 1_000);
    log.tick().unwrap();
}

pub(super) fn approve(req: DisposalRequest) -> DisposalAuthorization {
    let (a, b) = approvers();
    let sa = a.approve(&req).unwrap();
    let sb = b.approve(&req).unwrap();
    DisposalAuthorization::new(req, sa, sb, approver_keys()).unwrap()
}

pub(super) fn dispose(
    log: &mut AuditLog<SoftwareSigner, TestClock>,
    store: &MemoryStore,
    target: CaseRef,
) -> RedactionPlan {
    let plan = store.plan_case_redaction(target);
    let auth = approve(
        plan.request(tenant(), ReceiptId::generate().unwrap())
            .unwrap(),
    );
    log.emit_case_disposal(EventContext::staff(user(1)), &plan, &auth)
        .unwrap();
    plan
}

pub(super) fn opened(n: u8) -> AuditEvent {
    AuditEvent::CaseOpened { case: case(n) }
}

pub(super) fn login() -> AuditEvent {
    AuditEvent::AuthLoginSucceeded {
        method: AuthMethod::Fido2,
        aal: Aal::Aal3,
        authenticator_aaguid_class: AaguidClass::Certified,
        audience: Audience::DeskApi,
    }
}

pub(super) fn params<'a>(
    key: &'a ed25519_dalek::VerifyingKey,
    stream: StreamId,
) -> VerifyParams<'a> {
    VerifyParams {
        tenant: tenant(),
        stream,
        key,
        approver_keys: approver_keys(),
        trusted_latest: None,
        allow_pruned_prefix: false,
        min_retention_days: None,
    }
}

pub(super) const ALL: [StreamId; 5] = [
    StreamId::Sec,
    StreamId::Case,
    StreamId::Sys,
    StreamId::CaseSlot,
    StreamId::SysSlot,
];

/// `n` CASE events, `per_day` per batch; every batch is followed by a
/// checkpoint (the last one by a final tick).
pub(super) fn setup(
    n: u8,
    per_day: u8,
) -> (
    Vec<ChainRecord>,
    Vec<candor_log::SignedCheckpoint>,
    ed25519_dalek::VerifyingKey,
) {
    let (mut log, sink, clock) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    for i in 0..n {
        log.emit(EventContext::staff(user(1)), opened(i)).unwrap();
        if (i + 1) % per_day == 0 || i + 1 == n {
            clock.advance(DAY);
        }
    }
    log.tick().unwrap();
    let st = sink.0.lock().unwrap();
    (
        st.chain(StreamId::Case),
        st.checkpoints(StreamId::Case),
        log.verifying_key(),
    )
}

pub(super) fn code_of(
    recs: &[ChainRecord],
    cps: &[candor_log::SignedCheckpoint],
    key: &ed25519_dalek::VerifyingKey,
) -> VerifyFailureCode {
    verify_stream(&params(key, StreamId::Case), recs, cps)
        .unwrap_err()
        .code
}

pub(super) trait VkForTest {
    fn verifying_key_for_test(&self) -> ed25519_dalek::VerifyingKey;
}
impl VkForTest for candor_log::SoftwareSigner {
    fn verifying_key_for_test(&self) -> ed25519_dalek::VerifyingKey {
        candor_log::CheckpointSigner::verifying_key(self)
    }
}

pub(super) type CpView = Vec<(StreamId, u64)>;

/// Tick every minute for two days; optionally emit `extra` at 10:17:23.
pub(super) fn schedule_trace(
    host: HostRole,
    extra: Option<(EventContext, AuditEvent)>,
) -> (CpView, Vec<SignedCheckpoint>) {
    // Start 2026-10-01T00:00:00Z + 30 s.
    let start = T0 - T0 % DAY + 30_000;
    let mut r = rig_at(host, CheckpointPolicy::DEFAULT, start);
    let mut extra = extra;
    let mut out = Vec::new();
    for minute in 0..(2 * 24 * 60) {
        r.clock.advance(60_000);
        if minute == 10 * 60 + 17
            && let Some((ctx, ev)) = extra.take()
        {
            r.clock.advance(23_000);
            if let Some(cp) = r.log.emit(ctx, ev).unwrap().checkpoint {
                out.push(cp);
            }
            r.clock.advance(60_000 - 23_000);
        }
        out.extend(r.log.tick().unwrap());
    }
    let view = out
        .iter()
        .map(|c| (c.body().stream, c.body().signed_at.0))
        .collect();
    (view, out)
}

pub(super) fn precision_of(r: &CommittedRecord) -> u64 {
    ts_of(r)
}

pub(super) fn ts_of(r: &candor_log::CommittedRecord) -> u64 {
    let v = cbor::decode(r.bytes()).unwrap();
    v.get("ts").unwrap().as_u64().unwrap()
}

pub(super) fn find(st: &MemoryStore, s: StreamId, ty: &str) -> CommittedRecord {
    st.records(s)
        .into_iter()
        .find(|r| r.event().type_name() == ty)
        .unwrap()
}

pub(super) fn forged_stub(r: &CommittedRecord, case: CaseRef, tombstone_seq: u64) -> ChainRecord {
    ChainRecord::Redacted {
        seq: r.header().seq,
        case,
        inner: *r.inner(),
        tombstone_seq,
    }
}

pub(super) fn retention_auth(stream: StreamId, days: u32) -> DisposalAuthorization {
    approve(DisposalRequest::retention(tenant(), stream, days).unwrap())
}

/// Sink that fails while `fail` is set.
#[derive(Clone, Default)]
pub(super) struct Flaky {
    pub(super) fail: Arc<AtomicBool>,
    pub(super) inner: MemorySink,
    pub(super) writes: Arc<AtomicUsize>,
}

impl AuditSink for Flaky {
    fn write_record(&mut self, r: &CommittedRecord) -> Result<(), SinkError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(SinkError::Io);
        }
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.write_record(r)
    }
    fn write_checkpoint(&mut self, cp: &SignedCheckpoint) -> Result<(), SinkError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(SinkError::Io);
        }
        self.inner.write_checkpoint(cp)
    }
}

pub(super) struct FlakySigner {
    pub(super) inner: candor_log::SoftwareSigner,
    pub(super) fail: Arc<AtomicBool>,
}

impl CheckpointSigner for FlakySigner {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.inner.verifying_key()
    }
    fn sign_checkpoint(&self, b: &[u8]) -> Result<ed25519_dalek::Signature, SignerError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(SignerError);
        }
        self.inner.sign_checkpoint(b)
    }
}

/// Test witness: records every published head per stream.
#[derive(Clone, Default)]
pub(super) struct Witness {
    pub(super) heads: Arc<std::sync::Mutex<Vec<SignedCheckpoint>>>,
    pub(super) down: Arc<AtomicBool>,
}

impl WitnessSink for Witness {
    fn publish(&mut self, head: &SignedCheckpoint) -> Result<(), WitnessError> {
        if self.down.load(Ordering::SeqCst) {
            return Err(WitnessError);
        }
        self.heads.lock().unwrap().push(head.clone());
        Ok(())
    }
}

impl Witness {
    pub(super) fn latest(&self, s: StreamId) -> Option<SignedCheckpoint> {
        self.heads
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|c| c.body().stream == s)
            .cloned()
    }
}
