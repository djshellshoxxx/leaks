// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hash chain, checkpoints, verification, timestamp policy, retention and
//! sinks (AUD-001..AUD-005, AUD-012, LOG-004, LOG-012, LOG-013, LOG-021),
//! plus the AUD-RM1-LOG-01/02/07/08/13 regressions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use candor_log::cbor;
use candor_log::chain::{
    ChainRecord, CheckpointSigner, SignerError, StreamResume, record_commit, record_inner,
};
use candor_log::codes::*;
use candor_log::disposal::{
    ApproverKeys, DisposalApprover, DisposalAuthorization, DisposalError, DisposalRequest,
    SoftwareApprover,
};
use candor_log::envelope::EnvelopeError;
use candor_log::field::{SlotIndex, SmallCount, StaffTimer};
use candor_log::ids::*;
use candor_log::retention::{self, RetentionError, RetentionPolicy};
use candor_log::sink::{
    AuditSink, JsonlFile, MemoryJsonl, MemorySink, MemoryStore, ReadError, RedactionPlan,
    SharedJsonl, SinkError, read_stream,
};
use candor_log::verify::{VerifyParams, verify_stream};
use candor_log::{
    AuditClock, AuditEvent, AuditLog, CheckpointPolicy, CommittedRecord, EventContext, LogError,
    SignedCheckpoint, SoftwareSigner, WitnessError, WitnessSink,
};
use common::*;

const SLOT6H: u64 = 6 * 3_600_000;

fn rec(e: candor_log::Emitted) -> CommittedRecord {
    e.record.expect("committed immediately")
}

fn imported(n: u8) -> AuditEvent {
    AuditEvent::CaseImported {
        case: case(n),
        channel_id: channel(1),
        received_day: UtcMillis(T0).day(),
        import_slot_date: UtcMillis(T0).day(),
    }
}

/// Advance to just after the next import-slot boundary and tick (flushes
/// the slot streams).
fn next_slot(log: &mut AuditLog<SoftwareSigner, TestClock>, clock: &TestClock) {
    let now = clock.now();
    clock.advance(SLOT6H - now % SLOT6H + 1_000);
    log.tick().unwrap();
}

fn approve(req: DisposalRequest) -> DisposalAuthorization {
    let (a, b) = approvers();
    let sa = a.approve(&req).unwrap();
    let sb = b.approve(&req).unwrap();
    DisposalAuthorization::new(req, sa, sb, approver_keys()).unwrap()
}

fn dispose(
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

fn opened(n: u8) -> AuditEvent {
    AuditEvent::CaseOpened { case: case(n) }
}

fn login() -> AuditEvent {
    AuditEvent::AuthLoginSucceeded {
        method: AuthMethod::Fido2,
        aal: Aal::Aal3,
        authenticator_aaguid_class: AaguidClass::Certified,
        audience: Audience::DeskApi,
    }
}

fn params<'a>(key: &'a ed25519_dalek::VerifyingKey, stream: StreamId) -> VerifyParams<'a> {
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

const ALL: [StreamId; 5] = [
    StreamId::Sec,
    StreamId::Case,
    StreamId::Sys,
    StreamId::CaseSlot,
    StreamId::SysSlot,
];

#[test]
fn class_separated_streams_verify() {
    let (mut log, sink, clock) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    for i in 0..10 {
        log.emit(EventContext::staff(user(1)), opened(i)).unwrap();
        log.emit(EventContext::staff(user(2)), login()).unwrap();
    }
    log.emit(
        EventContext::system(Service::Health),
        AuditEvent::SysHealth {
            service: Service::Core,
            status: HealthStatus::Ok,
            check_code: HealthCheck::Liveness,
        },
    )
    .unwrap();
    clock.advance(DAY);
    assert_eq!(log.tick().unwrap().len(), 5);
    for i in 0..2 {
        log.emit(EventContext::staff(user(1)), opened(i)).unwrap();
    }
    let key = log.verifying_key();
    let store = sink.0.lock().unwrap().clone();
    for s in ALL {
        let rep = verify_stream(&params(&key, s), &store.chain(s), &store.checkpoints(s)).unwrap();
        assert_eq!(rep.first_seq, if rep.records > 0 { Some(0) } else { None });
    }
    // 12 case events; one checkpoint (after the downtime) over the first
    // 10, 2 unattested.
    let rep = verify_stream(
        &params(&key, StreamId::Case),
        &store.chain(StreamId::Case),
        &store.checkpoints(StreamId::Case),
    )
    .unwrap();
    assert_eq!(rep.records, 12);
    assert_eq!(rep.checkpoints, 1);
    assert_eq!(rep.unattested_tail, 2);
    // The case stream contains only CASE events.
    assert!(
        store
            .records(StreamId::Case)
            .iter()
            .all(|r| r.event().class() == candor_log::EventClass::Case)
    );
}

/// `n` CASE events, `per_day` per batch; every batch is followed by a
/// checkpoint (the last one by a final tick).
fn setup(
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

fn code_of(
    recs: &[ChainRecord],
    cps: &[candor_log::SignedCheckpoint],
    key: &ed25519_dalek::VerifyingKey,
) -> VerifyFailureCode {
    verify_stream(&params(key, StreamId::Case), recs, cps)
        .unwrap_err()
        .code
}

// AUD-004 tamper fixtures: modified payload, reordered, deleted, truncated,
// forged signature.
#[test]
fn deletion_of_middle_event_detected() {
    let (mut recs, cps, key) = setup(12, 5);
    recs.remove(6);
    assert_eq!(code_of(&recs, &cps, &key), VerifyFailureCode::SequenceGap);
}

#[test]
fn reordering_detected() {
    let (mut recs, cps, key) = setup(12, 5);
    recs.swap(3, 4);
    assert_eq!(code_of(&recs, &cps, &key), VerifyFailureCode::SequenceOrder);
}

#[test]
fn modification_detected() {
    let (mut recs, cps, key) = setup(12, 5);
    // Re-encode record 3 with a different case ID but keep it canonical.
    let ChainRecord::Full { bytes, salt, .. } = &recs[3] else {
        panic!()
    };
    let mut b = bytes.clone();
    let pos = b.windows(16).position(|w| w == case(3).as_bytes()).unwrap();
    b[pos] ^= 0x99;
    recs[3] = ChainRecord::Full {
        bytes: b,
        salt: *salt,
        claimed_hash: None,
    };
    assert_eq!(code_of(&recs, &cps, &key), VerifyFailureCode::ChainMismatch);
}

#[test]
fn modification_of_last_record_detected_by_checkpoint() {
    let (mut recs, cps, key) = setup(10, 5);
    let ChainRecord::Full { bytes, salt, .. } = &recs[9] else {
        panic!()
    };
    let mut b = bytes.clone();
    let pos = b.windows(16).position(|w| w == case(9).as_bytes()).unwrap();
    b[pos] ^= 0x42;
    recs[9] = ChainRecord::Full {
        bytes: b,
        salt: *salt,
        claimed_hash: None,
    };
    assert_eq!(
        code_of(&recs, &cps, &key),
        VerifyFailureCode::MerkleMismatch
    );
}

#[test]
fn truncation_below_checkpoint_detected() {
    let (mut recs, cps, key) = setup(10, 5);
    recs.truncate(8);
    assert_eq!(code_of(&recs, &cps, &key), VerifyFailureCode::Truncated);
}

#[test]
fn deleting_head_detected() {
    let (recs, cps, key) = setup(10, 5);
    assert_eq!(
        code_of(&recs[1..], &cps, &key),
        VerifyFailureCode::MissingPrefix
    );
}

#[test]
fn forged_checkpoint_rejected() {
    let (recs, cps, _key) = setup(10, 5);
    let other = signer(99).verifying_key_for_test();
    assert_eq!(
        code_of(&recs, &cps, &other),
        VerifyFailureCode::BadSignature
    );
    // Tampered signature bytes.
    let mut sig = *cps[0].signature();
    sig[0] ^= 1;
    let bad = candor_log::SignedCheckpoint::from_parts(cps[0].bytes().to_vec(), sig).unwrap();
    let key = signer(7).verifying_key_for_test();
    let mut cps2 = cps.clone();
    cps2[0] = bad;
    assert_eq!(code_of(&recs, &cps2, &key), VerifyFailureCode::BadSignature);
    // Dropping a checkpoint breaks the checkpoint chain.
    let cps3 = vec![cps[1].clone()];
    assert_eq!(
        code_of(&recs, &cps3, &key),
        VerifyFailureCode::CheckpointChain
    );
}

trait VkForTest {
    fn verifying_key_for_test(&self) -> ed25519_dalek::VerifyingKey;
}
impl VkForTest for candor_log::SoftwareSigner {
    fn verifying_key_for_test(&self) -> ed25519_dalek::VerifyingKey {
        candor_log::CheckpointSigner::verifying_key(self)
    }
}

#[test]
fn rollback_detected_against_witness() {
    let (recs, cps, key) = setup(15, 5);
    let witness_latest = cps.last().unwrap().clone();
    // Instance presents an older state (rolled back to 10 events).
    let mut p = params(&key, StreamId::Case);
    p.trusted_latest = Some(&witness_latest);
    let err = verify_stream(&p, &recs[..10], &cps[..2]).unwrap_err();
    assert_eq!(err.code, VerifyFailureCode::Rollback);
    // Current state verifies against the witness.
    verify_stream(&p, &recs, &cps).unwrap();
    // Witness cosignature round trip.
    let w = signer(42);
    let sig = ed25519_dalek::Signer::sign(
        &ed25519_dalek::SigningKey::from_bytes(&[42; 32]),
        &witness_latest.witness_message(),
    );
    assert!(witness_latest.verify_cosignature(&w.verifying_key_for_test(), &sig.to_bytes()));
    assert!(!witness_latest.verify_cosignature(&key, &sig.to_bytes()));
}

#[test]
fn non_canonical_record_rejected() {
    let (mut recs, cps, key) = setup(3, 5);
    let ChainRecord::Full { bytes, salt, .. } = &recs[1] else {
        panic!()
    };
    let mut b = bytes.clone();
    b.push(0x00); // trailing byte
    recs[1] = ChainRecord::Full {
        bytes: b,
        salt: *salt,
        claimed_hash: None,
    };
    assert_eq!(code_of(&recs, &cps, &key), VerifyFailureCode::NonCanonical);
}

#[test]
fn cross_stream_or_tenant_splice_rejected() {
    let (mut log, sink, _c) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    log.emit(EventContext::staff(user(1)), login()).unwrap();
    let sec = sink.0.lock().unwrap().chain(StreamId::Sec);
    let key = log.verifying_key();
    let err = verify_stream(&params(&key, StreamId::Case), &sec, &[]).unwrap_err();
    assert_eq!(err.code, VerifyFailureCode::EnvelopeMismatch);
}

// AUD-002 / AUD-RM1-LOG-02: checkpoints follow a fixed slot schedule,
// empty or not, dated at the slot boundary.
#[test]
fn checkpoint_schedule() {
    let (mut log, sink, clock) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    for _ in 0..1500 {
        // No count trigger: 1500 events in one slot produce no checkpoint.
        assert!(
            log.emit(EventContext::staff(user(1)), login())
                .unwrap()
                .checkpoint
                .is_none()
        );
    }
    assert!(log.tick().unwrap().is_empty());
    clock.advance(5 * 60 * 1000);
    let sec = |v: Vec<SignedCheckpoint>| -> Vec<SignedCheckpoint> {
        v.into_iter()
            .filter(|c| c.body().stream == StreamId::Sec)
            .collect()
    };
    let all = log.tick().unwrap();
    // SECURITY, CASE and SYSTEM share the 5-minute cadence.
    assert_eq!(all.len(), 3);
    let cps = sec(all);
    assert_eq!(cps.len(), 1);
    let b = cps[0].body();
    assert_eq!((b.first_seq, b.end_seq), (0, 1500));
    assert_eq!(b.signed_at.0 % 300_000, 0, "dated at the slot boundary");
    assert!(b.signed_at.0 <= clock.now() && clock.now() - b.signed_at.0 < 300_000);
    // An empty slot still yields a checkpoint (data-independent cadence).
    clock.advance(5 * 60 * 1000);
    let cps = sec(log.tick().unwrap());
    assert_eq!(cps.len(), 1);
    assert!(cps[0].body().is_empty());
    let st = sink.0.lock().unwrap();
    let rep = verify_stream(
        &params(&log.verifying_key(), StreamId::Sec),
        &st.chain(StreamId::Sec),
        &st.checkpoints(StreamId::Sec),
    )
    .unwrap();
    assert_eq!(rep.unattested_tail, 0);
    assert_eq!(rep.checkpoints, 2);
}

type CpView = Vec<(StreamId, u64)>;

/// Tick every minute for two days; optionally emit `extra` at 10:17:23.
fn schedule_trace(
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

// AUD-RM1-LOG-02 regression: whether or not a date-only event happened, the
// witness sees the same checkpoints at the same times, and only the slot
// stream that holds it changes (CASE/SYSTEM checkpoints are byte-identical,
// so they reveal nothing about date-only events). Slot streams checkpoint
// only at import-slot boundaries.
#[test]
fn checkpoint_timing_independent_of_date_only_events() {
    let (with, cps_with) = schedule_trace(
        HostRole::Core,
        Some((EventContext::system(Service::Relay), imported(5))),
    );
    let (without, cps_without) = schedule_trace(HostRole::Core, None);
    assert_eq!(
        with, without,
        "checkpoint times/streams must not depend on events"
    );
    for (s, t) in &with {
        if matches!(s, StreamId::CaseSlot | StreamId::SysSlot) {
            assert_eq!(t % SLOT6H, 0, "slot streams only at import slots");
        } else {
            assert_eq!(t % 300_000, 0);
        }
    }
    let diff = |a: &[SignedCheckpoint], b: &[SignedCheckpoint]| -> Vec<StreamId> {
        a.iter()
            .zip(b)
            .filter(|(x, y)| x.bytes() != y.bytes())
            .map(|(x, _)| x.body().stream)
            .collect()
    };
    let d = diff(&cps_with, &cps_without);
    assert!(
        !d.is_empty() && d.iter().all(|s| *s == StreamId::CaseSlot),
        "{d:?}"
    );
    // Same for a source-load-derived (date-only) SYSTEM health event.
    let flood = AuditEvent::SysHealth {
        service: Service::Upload,
        status: HealthStatus::Degraded,
        check_code: HealthCheck::AbuseFlood,
    };
    let (with_sys, cps_sys) = schedule_trace(
        HostRole::Core,
        Some((EventContext::system(Service::Health), flood)),
    );
    assert_eq!(with_sys, without);
    let d = diff(&cps_sys, &cps_without);
    assert!(
        !d.is_empty() && d.iter().all(|s| *s == StreamId::SysSlot),
        "{d:?}"
    );
    // SECURITY: a staff event does not move SECURITY checkpoint times either.
    let (with_sec, _) = schedule_trace(
        HostRole::Core,
        Some((EventContext::staff(user(1)), login())),
    );
    assert_eq!(with_sec, without);
    // Z-INTAKE: every exact-time stream hourly, never finer than the hour
    // truncation.
    let (intake, _) = schedule_trace(HostRole::Intake, None);
    assert!(intake.iter().all(|(_, t)| t % 3_600_000 == 0));
}

fn precision_of(r: &CommittedRecord) -> u64 {
    ts_of(r)
}

// AUD-RM1-LOG-02 regression (record-order channel, the round-2 residual):
// date-only events never share a stream with exact-time events, are not
// written before their slot boundary, and are written in uniformly shuffled
// order, so neither neighbours nor order bound their time within the slot.
#[test]
fn date_only_events_never_neighbour_exact_time_events() {
    let r = rig(HostRole::Core, CheckpointPolicy::DEFAULT);
    let (mut log, sink, clock) = (r.log, r.sink, r.clock);
    // Interleave staff (ms) CASE events with imports, staff-performed
    // import-related events and system-actor CASE events.
    for i in 0..8u8 {
        log.emit(EventContext::staff(user(1)), opened(i)).unwrap();
        clock.advance(61_000);
        let e = log
            .emit(EventContext::system(Service::Relay), imported(i))
            .unwrap();
        assert!(e.record.is_none(), "staged, not written");
        clock.advance(61_000);
    }
    log.emit(
        EventContext::staff(user(2)),
        AuditEvent::EvidenceImported {
            case: case(1),
            evid: evid(1),
            manifest_match: true,
        },
    )
    .unwrap();
    // Nothing reaches the slot stream before the boundary.
    log.tick().unwrap();
    assert!(sink.0.lock().unwrap().chain(StreamId::CaseSlot).is_empty());
    next_slot(&mut log, &clock);
    let st = sink.0.lock().unwrap().clone();
    let case_recs = st.records(StreamId::Case);
    let slot_recs = st.records(StreamId::CaseSlot);
    assert_eq!(case_recs.len(), 8);
    assert_eq!(slot_recs.len(), 9);
    // No date-only record has a finer-precision neighbour in its stream.
    assert!(case_recs.iter().all(|r| !precision_of(r).is_multiple_of(DAY)));
    assert!(slot_recs.iter().all(|r| precision_of(r).is_multiple_of(DAY)));
    // Every record of the slot carries the same (date) ts.
    assert!(slot_recs.windows(2).all(|w| ts_of(&w[0]) == ts_of(&w[1])));
    // The slot stream's checkpoint is dated at the import-slot boundary.
    let cps = st.checkpoints(StreamId::CaseSlot);
    assert!(cps.iter().all(|c| c.body().signed_at.0 % SLOT6H == 0));
    let key = log.verifying_key();
    for s in [StreamId::Case, StreamId::CaseSlot] {
        verify_stream(&params(&key, s), &st.chain(s), &st.checkpoints(s)).unwrap();
    }
    // Order inside the slot is random: over repeated runs with the same
    // arrival order the stored order differs (P(identical 8!) ≈ 2.5e-5).
    let order = |recs: &[CommittedRecord]| -> Vec<CaseRef> {
        recs.iter()
            .filter_map(|r| match r.event() {
                AuditEvent::CaseImported { case, .. } => Some(*case),
                _ => None,
            })
            .collect()
    };
    let first = order(&slot_recs);
    let arrival: Vec<CaseRef> = (0..8u8).map(case).collect();
    let mut differs = first != arrival;
    for _ in 0..4 {
        let r = rig(HostRole::Core, CheckpointPolicy::DEFAULT);
        let (mut l, s, c) = (r.log, r.sink, r.clock);
        for i in 0..8u8 {
            l.emit(EventContext::system(Service::Relay), imported(i))
                .unwrap();
        }
        next_slot(&mut l, &c);
        let o = order(&s.0.lock().unwrap().records(StreamId::CaseSlot));
        let mut sorted = o.clone();
        sorted.sort();
        let mut a = arrival.clone();
        a.sort();
        assert_eq!(sorted, a, "a permutation of the slot's events");
        differs |= o != first;
    }
    assert!(differs, "slot order must not follow arrival order");
}

fn ts_of(r: &candor_log::CommittedRecord) -> u64 {
    let v = cbor::decode(r.bytes()).unwrap();
    v.get("ts").unwrap().as_u64().unwrap()
}

fn find(st: &MemoryStore, s: StreamId, ty: &str) -> CommittedRecord {
    st.records(s)
        .into_iter()
        .find(|r| r.event().type_name() == ty)
        .unwrap()
}

// LOG-013 / LOG-021 / ADR-046(11): timestamp policy (and routing of
// date-only events to the slot streams, AUD-RM1-LOG-02).
#[test]
fn timestamp_policy() {
    let (mut log, sink, clock) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let staff = rec(log.emit(EventContext::staff(user(1)), opened(1)).unwrap());
    assert_eq!(ts_of(&staff), T0, "staff actions exact to the ms");
    for (ctx, e) in [
        (EventContext::system(Service::Relay), imported(1)),
        // Even a staff-performed import-related event is date-only.
        (
            EventContext::staff(user(1)),
            AuditEvent::EvidenceImported {
                case: case(1),
                evid: evid(3),
                manifest_match: true,
            },
        ),
        // CASE event with a system actor: date only.
        (
            EventContext::system(Service::Scheduler),
            AuditEvent::CaseSlaReminder {
                case: case(1),
                timer_id: TimerId::generate().unwrap(),
                due_date: UtcMillis(T0).day(),
            },
        ),
        // Source-load-derived health: date only.
        (
            EventContext::system(Service::Health),
            AuditEvent::SysHealth {
                service: Service::Upload,
                status: HealthStatus::Degraded,
                check_code: HealthCheck::AbuseFlood,
            },
        ),
        // Relay daily summary: date only, no arrival counts.
        (
            EventContext::system(Service::Relay),
            AuditEvent::SysRelayDaily {
                date: UtcMillis(T0).day(),
                slots_ok: SmallCount::new(4).unwrap(),
                slots_failed: SmallCount::new(0).unwrap(),
                slots_overrun: SmallCount::new(0).unwrap(),
            },
        ),
    ] {
        assert!(log.emit(ctx, e).unwrap().record.is_none());
    }
    // SYSTEM: second.
    let sys = rec(log
        .emit(
            EventContext::system(Service::Health),
            AuditEvent::SysJob {
                job_kind: JobKind::Backup,
                outcome: Outcome::Ok,
            },
        )
        .unwrap());
    assert_eq!(ts_of(&sys), T0 - T0 % 1000);
    next_slot(&mut log, &clock);
    let st = sink.0.lock().unwrap();
    for (s, ty) in [
        (StreamId::CaseSlot, "case.imported"),
        (StreamId::CaseSlot, "evidence.imported"),
        (StreamId::CaseSlot, "case.sla_reminder"),
        (StreamId::SysSlot, "sys.health"),
        (StreamId::SysSlot, "sys.relay_daily"),
    ] {
        let r = find(&st, s, ty);
        assert_eq!(ts_of(&r), T0 - T0 % DAY, "{ty} date-only (emission day)");
    }
}

// LOG-004 / 20 §3: Z-INTAKE emits only SYSTEM + admin-access SECURITY
// events, all truncated to at least the hour.
#[test]
fn intake_host_rules() {
    let (mut log, _sink, _c) = log_with(HostRole::Intake, CheckpointPolicy::DEFAULT);
    assert_eq!(
        log.emit(EventContext::staff(user(1)), opened(1))
            .unwrap_err(),
        LogError::Envelope(EnvelopeError::NotAllowedOnHost)
    );
    let r = rec(log
        .emit(
            EventContext::system(Service::Tor),
            AuditEvent::SysTorStatus {
                bootstrap_percent: candor_log::field::Percent::new(100).unwrap(),
                onion_published: true,
                pow_enabled: false,
            },
        )
        .unwrap());
    assert_eq!(ts_of(&r) % MS_PER_HOUR, 0);
    let a = rec(log.emit(EventContext::staff(user(1)), login()).unwrap());
    assert_eq!(ts_of(&a) % MS_PER_HOUR, 0);
    assert!(
        log.emit(
            EventContext::system(Service::Relay),
            AuditEvent::SysRelaySlotOverrun {
                date: DayStamp::from_days(1).unwrap(),
                slot_index: SlotIndex::new(1).unwrap()
            }
        )
        .is_err()
    );
}

// LOG-012: session tag only for staff; envelope rules.
#[test]
fn envelope_rules() {
    let (mut log, _sink, _c) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let sid = StaffSessionId::generate().unwrap();
    let mut ctx = EventContext::system(Service::Core);
    ctx.session = Some(SessionTag::derive(&DaySalt::new([1; 32]), &sid));
    assert_eq!(
        log.emit(ctx, opened(1)).unwrap_err(),
        LogError::Envelope(EnvelopeError::StaffFieldsOnSystemActor)
    );
    let mut ctx = EventContext::staff(user(1));
    ctx.reason = Some(ErrorReason::Timeout);
    assert_eq!(
        log.emit(ctx, opened(1)).unwrap_err(),
        LogError::Envelope(EnvelopeError::ReasonWithoutError)
    );
    let mut ctx = EventContext::staff(user(1)).with_outcome(Outcome::Error);
    ctx.reason = Some(ErrorReason::Timeout);
    ctx.session = Some(SessionTag::derive(&DaySalt::new([1; 32]), &sid));
    let r = rec(log.emit(ctx, opened(1)).unwrap());
    let v = cbor::decode(r.bytes()).unwrap();
    assert_eq!(v.get("session").unwrap().as_bytes().unwrap().len(), 8);
    assert_eq!(v.get("reason").unwrap().as_text(), Some("TIMEOUT"));
}

// Every catalog type encodes canonically and verifies (LOG-001 schema test).
// Tombstones only through the disposal API (AUD-RM1-LOG-16) and
// artefact-derived sample values not derived under this log's key
// (AUD-RM1-LOG-17) are refused.
#[test]
fn full_catalog_round_trip() {
    let (mut log, sink, clock) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let samples = AuditEvent::samples();
    assert_eq!(samples.len(), candor_log::CATALOG.len());
    let (mut refused_tomb, mut refused_foreign) = (0, 0);
    for e in samples {
        let tomb = e.is_tombstone();
        match log.emit(EventContext::staff(user(1)), e) {
            Err(LogError::TombstoneViaApi) => {
                assert!(tomb);
                refused_tomb += 1;
            }
            Err(LogError::ForeignArtefact) => refused_foreign += 1,
            Err(e) => panic!("{e:?}"),
            Ok(_) => assert!(!tomb),
        }
    }
    assert_eq!((refused_tomb, refused_foreign), (5, 6));
    next_slot(&mut log, &clock);
    let st = sink.0.lock().unwrap();
    for s in ALL {
        for r in st.records(s) {
            let names = r.event().field_names();
            let v = cbor::decode(r.bytes()).unwrap();
            assert_eq!(cbor::encode(&v).unwrap(), r.bytes());
            let cbor::Value::Map(payload) = v.get("payload").unwrap() else {
                panic!()
            };
            // Payload keys ⊆ schema.
            for (k, _) in payload {
                assert!(names.contains(&k.as_text().unwrap()));
            }
        }
        verify_stream(
            &params(&log.verifying_key(), s),
            &st.chain(s),
            &st.checkpoints(s),
        )
        .unwrap();
    }
}

// AUD-012: per-case redaction of CASE and CASE-SLOT records keeps both
// chains verifiable once the dual-approved tombstones that commit to the
// redacted sets are checkpointed.
#[test]
fn case_disposal_redaction_verifies() {
    let r = rig(HostRole::Core, CheckpointPolicy::DEFAULT);
    let (mut log, sink, clock, keys) = (r.log, r.sink, r.clock, r.keys);
    for i in 0..9 {
        log.emit(EventContext::staff(user(1)), opened(i % 3))
            .unwrap();
    }
    for i in 0..3 {
        log.emit(EventContext::system(Service::Relay), imported(i))
            .unwrap();
    }
    let target = case(1);
    // Disposal waits while records of the case are still staged.
    let pending = sink.0.lock().unwrap().plan_case_redaction(target);
    let auth = approve(
        pending
            .request(tenant(), ReceiptId::generate().unwrap())
            .unwrap(),
    );
    assert_eq!(
        log.emit_case_disposal(EventContext::staff(user(1)), &pending, &auth)
            .unwrap_err(),
        LogError::Disposal(DisposalError::StagedRecordsPending)
    );
    next_slot(&mut log, &clock);
    let store = sink.0.lock().unwrap().clone();
    let plan = dispose(&mut log, &store, target);
    assert_eq!(plan.len(), 4);
    // A system actor cannot dispose (date-only tombstone in CASE).
    let auth2 = approve(
        plan.request(tenant(), ReceiptId::generate().unwrap())
            .unwrap(),
    );
    assert_eq!(
        log.emit_case_disposal(EventContext::system(Service::Core), &plan, &auth2)
            .unwrap_err(),
        LogError::Disposal(DisposalError::StaffActorRequired)
    );
    let n = sink
        .0
        .lock()
        .unwrap()
        .apply_case_redaction(&plan, StreamId::Case)
        .unwrap();
    assert_eq!(n, 3);
    // The CASE-SLOT tombstone is written at the next slot boundary.
    assert!(
        sink.0
            .lock()
            .unwrap()
            .apply_case_redaction(&plan, StreamId::CaseSlot)
            .is_err()
    );
    let key = log.verifying_key();
    // Not yet checkpointed: the stubs are not provably bound.
    {
        let st = sink.0.lock().unwrap();
        let err = verify_stream(
            &params(&key, StreamId::Case),
            &st.chain(StreamId::Case),
            &st.checkpoints(StreamId::Case),
        )
        .unwrap_err();
        assert_eq!(err.code, VerifyFailureCode::UnboundRedaction);
    }
    next_slot(&mut log, &clock);
    assert_eq!(
        sink.0
            .lock()
            .unwrap()
            .apply_case_redaction(&plan, StreamId::CaseSlot)
            .unwrap(),
        1
    );
    keys.destroy(target);
    clock.advance(5 * 60 * 1000);
    log.tick().unwrap();
    let st = sink.0.lock().unwrap();
    for s in [StreamId::Case, StreamId::CaseSlot] {
        assert!(st.records(s).iter().all(|r| r.case_tag() != Some(target)));
    }
    let rep = verify_stream(
        &params(&key, StreamId::Case),
        &st.chain(StreamId::Case),
        &st.checkpoints(StreamId::Case),
    )
    .unwrap();
    assert_eq!(rep.redacted, 3);
    let rep = verify_stream(
        &params(&key, StreamId::CaseSlot),
        &st.chain(StreamId::CaseSlot),
        &st.checkpoints(StreamId::CaseSlot),
    )
    .unwrap();
    assert_eq!(rep.redacted, 1);
    // Tampering with a stub is detected.
    let mut recs = st.chain(StreamId::Case);
    let pos = recs
        .iter()
        .position(|r| matches!(r, ChainRecord::Redacted { .. }))
        .unwrap();
    if let ChainRecord::Redacted { inner, .. } = &mut recs[pos] {
        inner[0] ^= 1;
    }
    assert!(
        verify_stream(
            &params(&key, StreamId::Case),
            &recs,
            &st.checkpoints(StreamId::Case),
        )
        .is_err()
    );
    // After disposal the destroyed key fails new events for the case closed.
    drop(st);
    assert_eq!(
        log.emit(EventContext::staff(user(1)), opened(1))
            .unwrap_err(),
        LogError::CaseKeyUnavailable
    );
}

fn forged_stub(r: &CommittedRecord, case: CaseRef, tombstone_seq: u64) -> ChainRecord {
    ChainRecord::Redacted {
        seq: r.header().seq,
        case,
        inner: *r.inner(),
        tombstone_seq,
    }
}

// AUD-RM1-LOG-01 regression (the audit PoC; passed on the old verifier):
// an insider replaces a SECURITY record by a stub computed from the
// original; verification against the witness checkpoint must fail.
#[test]
fn stub_in_security_stream_rejected() {
    let (mut log, sink, clock) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let danger = rec(log
        .emit(
            EventContext::staff(user(1)),
            AuditEvent::CfgDangerousEnabled {
                key: Code::of::<5>(),
                expiry: StaffTimer::after(&clock, 60).unwrap(),
            },
        )
        .unwrap());
    log.emit(
        EventContext::staff(user(1)),
        AuditEvent::AuthLogout {
            reason_code: SessionEndReason::UserLogout,
        },
    )
    .unwrap();
    clock.advance(5 * 60 * 1000);
    let cps = log.tick().unwrap();
    let witness = cps
        .iter()
        .rev()
        .find(|c| c.body().stream == StreamId::Sec)
        .unwrap()
        .clone();
    let key = log.verifying_key();
    let mut st = sink.0.lock().unwrap();
    assert!(
        danger.to_stub(1).is_none(),
        "SECURITY records are not redactable"
    );
    assert!(st.tamper_replace(StreamId::Sec, 0, forged_stub(&danger, case(9), 1)));
    let mut p = params(&key, StreamId::Sec);
    p.trusted_latest = Some(&witness);
    let err =
        verify_stream(&p, &st.chain(StreamId::Sec), &st.checkpoints(StreamId::Sec)).unwrap_err();
    assert_eq!(err.code, VerifyFailureCode::UnboundRedaction);
}

// AUD-RM1-LOG-01: CASE stubs without a tombstone, or not in the tombstone's
// committed set (count/set mismatch), are rejected.
#[test]
fn case_stub_without_matching_tombstone_rejected() {
    let r = rig(HostRole::Core, CheckpointPolicy::DEFAULT);
    let (mut log, sink, clock) = (r.log, r.sink, r.clock);
    let mut recs = Vec::new();
    for i in 0..6 {
        recs.push(rec(log
            .emit(EventContext::staff(user(1)), opened(i % 2))
            .unwrap()));
    }
    clock.advance(DAY);
    log.tick().unwrap();
    let key = log.verifying_key();
    // (a) stub pointing at an ordinary record.
    {
        let mut st = sink.0.lock().unwrap().clone();
        st.tamper_replace(StreamId::Case, 0, recs[0].to_stub(1).unwrap());
        let e = verify_stream(
            &params(&key, StreamId::Case),
            &st.chain(StreamId::Case),
            &st.checkpoints(StreamId::Case),
        )
        .unwrap_err();
        assert_eq!(e.code, VerifyFailureCode::UnboundRedaction);
    }
    // (b) legitimate disposal of case 0, plus one extra record of case 1
    // stubbed against the same tombstone: case/set/count mismatch.
    let store = sink.0.lock().unwrap().clone();
    let plan = dispose(&mut log, &store, case(0));
    sink.0
        .lock()
        .unwrap()
        .apply_case_redaction(&plan, StreamId::Case)
        .unwrap();
    clock.advance(DAY);
    log.tick().unwrap();
    let tseq = sink
        .0
        .lock()
        .unwrap()
        .records(StreamId::Case)
        .iter()
        .find(|r| r.event().is_tombstone())
        .unwrap()
        .header()
        .seq;
    let mut st = sink.0.lock().unwrap().clone();
    verify_stream(
        &params(&key, StreamId::Case),
        &st.chain(StreamId::Case),
        &st.checkpoints(StreamId::Case),
    )
    .unwrap();
    for stub in [
        recs[1].to_stub(tseq).unwrap(),
        // naming the disposed case instead breaks the record commitment
        forged_stub(&recs[1], case(0), tseq),
    ] {
        let mut st2 = st.clone();
        st2.tamper_replace(StreamId::Case, 1, stub);
        let e = verify_stream(
            &params(&key, StreamId::Case),
            &st2.chain(StreamId::Case),
            &st2.checkpoints(StreamId::Case),
        )
        .unwrap_err();
        assert!(matches!(
            e.code,
            VerifyFailureCode::UnboundRedaction | VerifyFailureCode::ChainMismatch
        ));
    }
    // A tombstone cannot cover a later record.
    let later = rec(log.emit(EventContext::staff(user(1)), opened(3)).unwrap());
    st = sink.0.lock().unwrap().clone();
    assert!(st.tamper_replace(
        StreamId::Case,
        later.header().seq,
        later.to_stub(tseq).unwrap()
    ));
    let e = verify_stream(
        &params(&key, StreamId::Case),
        &st.chain(StreamId::Case),
        &st.checkpoints(StreamId::Case),
    )
    .unwrap_err();
    assert_eq!(e.code, VerifyFailureCode::UnboundRedaction);
}

// AUD-RM1-LOG-16 regression (round-2 PoC `forge.rs`): an insider who can
// emit and edit the store forges a `case.disposed` for an unrelated case
// that commits to a victim record. Every path is closed:
// (a) the tombstone variant cannot be built (private payload; trybuild
//     `forge_tombstone.rs`) and `emit` refuses tombstones;
// (b) the insider's own approver keys (pinned in a writer they control) do
//     not verify under the pinned approver keys;
// (c) a genuine disposal of another case cannot cover the victim's record.
#[test]
fn forged_disposal_tombstone_rejected() {
    // (a)
    let (mut log, _sink, _c) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let sample = AuditEvent::samples()
        .into_iter()
        .find(|e| e.type_name() == "case.disposed")
        .unwrap();
    assert_eq!(
        log.emit(EventContext::staff(user(1)), sample).unwrap_err(),
        LogError::TombstoneViaApi
    );
    // (b) a writer whose pinned approvers are the insider's own keys.
    let r = rig(HostRole::Core, CheckpointPolicy::DEFAULT);
    let (mut log, sink, clock) = (r.log, r.sink, r.clock);
    let victim = rec(log.emit(EventContext::staff(user(1)), opened(7)).unwrap());
    log.emit(EventContext::staff(user(1)), opened(8)).unwrap();
    let mallory = (
        SoftwareApprover::from_seed(&zeroize::Zeroizing::new([66; 32])),
        SoftwareApprover::from_seed(&zeroize::Zeroizing::new([67; 32])),
    );
    let own = ApproverKeys::new(
        vec![mallory.0.verifying_key(), mallory.1.verifying_key()],
        &log.verifying_key(),
    )
    .unwrap();
    log.set_approver_keys(own.clone());
    let store = sink.0.lock().unwrap().clone();
    let plan = store.plan_case_redaction(case(7));
    let req = plan
        .request(tenant(), ReceiptId::generate().unwrap())
        .unwrap();
    let auth = DisposalAuthorization::new(
        req.clone(),
        mallory.0.approve(&req).unwrap(),
        mallory.1.approve(&req).unwrap(),
        &own,
    )
    .unwrap();
    // The real pinned set refuses this authorization outright.
    assert_eq!(
        DisposalAuthorization::new(
            req.clone(),
            mallory.0.approve(&req).unwrap(),
            mallory.1.approve(&req).unwrap(),
            approver_keys(),
        )
        .unwrap_err(),
        DisposalError::BadApprovals
    );
    log.emit_case_disposal(EventContext::staff(user(1)), &plan, &auth)
        .unwrap();
    sink.0
        .lock()
        .unwrap()
        .apply_case_redaction(&plan, StreamId::Case)
        .unwrap();
    clock.advance(DAY);
    log.tick().unwrap();
    let key = log.verifying_key();
    let st = sink.0.lock().unwrap().clone();
    let e = verify_stream(
        &params(&key, StreamId::Case),
        &st.chain(StreamId::Case),
        &st.checkpoints(StreamId::Case),
    )
    .unwrap_err();
    assert_eq!(e.code, VerifyFailureCode::UnboundRedaction);
    // (c) genuinely approved disposal of case 8; the insider stubs the
    // victim's (case 7) record against it.
    let r = rig(HostRole::Core, CheckpointPolicy::DEFAULT);
    let (mut log, sink, clock) = (r.log, r.sink, r.clock);
    let victim2 = rec(log.emit(EventContext::staff(user(1)), opened(7)).unwrap());
    log.emit(EventContext::staff(user(1)), opened(8)).unwrap();
    let store = sink.0.lock().unwrap().clone();
    dispose(&mut log, &store, case(8));
    clock.advance(DAY);
    log.tick().unwrap();
    let mut st = sink.0.lock().unwrap().clone();
    let tseq = st
        .records(StreamId::Case)
        .iter()
        .find(|r| r.event().is_tombstone())
        .unwrap()
        .header()
        .seq;
    for stub in [
        victim2.to_stub(tseq).unwrap(),
        forged_stub(&victim2, case(8), tseq),
    ] {
        st.tamper_replace(StreamId::Case, victim2.header().seq, stub);
        assert!(
            verify_stream(
                &params(&key, StreamId::Case),
                &st.chain(StreamId::Case),
                &st.checkpoints(StreamId::Case),
            )
            .is_err()
        );
    }
    let _ = victim;
}

// AUD-RM1-LOG-08: a stub cannot be confirmed against a guessed record
// without the destroyed per-case key.
#[test]
fn redacted_stub_reveals_nothing_without_case_key() {
    let (mut log, _sink, _c) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let a = rec(log.emit(EventContext::staff(user(1)), opened(1)).unwrap());
    let b = rec(log.emit(EventContext::staff(user(1)), opened(1)).unwrap());
    assert_ne!(a.salt(), &[0; 32], "CASE records are salted");
    assert_ne!(a.salt(), b.salt(), "salt is per record");
    // An attacker who guesses the exact canonical bytes but lacks the salt
    // cannot reproduce the commitment.
    let tag = a.case_tag();
    assert_eq!(tag, Some(case(1)));
    assert_ne!(
        record_commit(tag.as_ref(), &record_inner(&[0; 32], a.bytes())),
        *a.commit()
    );
    assert_eq!(
        record_commit(tag.as_ref(), &record_inner(a.salt(), a.bytes())),
        *a.commit()
    );
    // Non-redactable records carry no salt and no case tag.
    let s = rec(log.emit(EventContext::staff(user(1)), login()).unwrap());
    assert_eq!(s.salt(), &[0; 32]);
    assert_eq!(s.case_tag(), None);
    // Salts never appear in Debug output.
    assert!(!format!("{a:?}").contains(&format!("{:?}", a.salt())));
}

fn retention_auth(stream: StreamId, days: u32) -> DisposalAuthorization {
    approve(DisposalRequest::retention(tenant(), stream, days).unwrap())
}

// AUD-005 / AUD-RM1-LOG-01/16/20: whole-interval retention with a
// checkpointed, dual-approved tombstone in the same stream; the remaining
// chain verifies; a prefix pruned without (or with a too-young) tombstone
// does not; the configured retention binds the verifier.
#[test]
fn retention_interval_deletion() {
    let (mut log, sink, clock) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    for _ in 0..10 {
        log.emit(EventContext::staff(user(1)), login()).unwrap();
    }
    clock.advance(5 * 60 * 1000);
    log.tick().unwrap();
    clock.advance(31 * DAY);
    log.emit(EventContext::staff(user(1)), login()).unwrap();
    let policy = RetentionPolicy::new(90, 7, 365, 13).unwrap();
    let cps = sink.0.lock().unwrap().checkpoints(StreamId::Sec);
    // SECURITY: nothing older than 90 days yet.
    assert!(
        retention::plan_interval_deletion(&policy, StreamId::Sec, &cps, 0, UtcMillis(clock.now()))
            .unwrap()
            .is_none()
    );
    // An insider pruning the first interval without a tombstone is caught.
    {
        let mut st = sink.0.lock().unwrap().clone();
        for q in 0..10 {
            st.tamper_replace(
                StreamId::Sec,
                q,
                ChainRecord::Full {
                    bytes: vec![],
                    salt: [0; 32],
                    claimed_hash: None,
                },
            );
        }
        let recs: Vec<ChainRecord> = st
            .chain(StreamId::Sec)
            .into_iter()
            .filter(|r| !matches!(r, ChainRecord::Full { bytes, .. } if bytes.is_empty()))
            .collect();
        let key = log.verifying_key();
        let mut p = params(&key, StreamId::Sec);
        p.allow_pruned_prefix = true;
        let e = verify_stream(&p, &recs, &st.checkpoints(StreamId::Sec)).unwrap_err();
        assert_eq!(e.code, VerifyFailureCode::UnboundPrune);
    }
    clock.advance(60 * DAY);
    let cps = sink.0.lock().unwrap().checkpoints(StreamId::Sec);
    let now = UtcMillis(clock.now());
    let plan = retention::plan_interval_deletion(&policy, StreamId::Sec, &cps, 0, now)
        .unwrap()
        .unwrap();
    assert_eq!(plan.range(), (0, 9));
    // Without a tombstone, deletion is refused.
    assert_eq!(
        retention::apply_interval_deletion(&mut sink.0.lock().unwrap(), &plan),
        Err(RetentionError::MissingTombstone)
    );
    // The authorization must match the plan's period, and tombstones only
    // go through the API.
    assert_eq!(
        log.emit_retention_tombstone(
            EventContext::system(Service::Audit),
            &plan,
            &retention_auth(StreamId::Sec, 400)
        )
        .unwrap_err(),
        LogError::Disposal(DisposalError::Mismatch)
    );
    log.emit_retention_tombstone(
        EventContext::system(Service::Audit),
        &plan,
        &retention_auth(StreamId::Sec, 90),
    )
    .unwrap();
    assert_eq!(
        retention::apply_interval_deletion(&mut sink.0.lock().unwrap(), &plan),
        Err(RetentionError::TombstoneNotAttested)
    );
    clock.advance(5 * 60 * 1000);
    log.tick().unwrap();
    retention::apply_interval_deletion(&mut sink.0.lock().unwrap(), &plan).unwrap();
    let st = sink.0.lock().unwrap();
    let recs = st.chain(StreamId::Sec);
    let cps = st.checkpoints(StreamId::Sec);
    let key = log.verifying_key();
    // Strict verification refuses a pruned store; retention-aware accepts it.
    assert!(verify_stream(&params(&key, StreamId::Sec), &recs, &cps).is_err());
    let mut p = params(&key, StreamId::Sec);
    p.allow_pruned_prefix = true;
    let rep = verify_stream(&p, &recs, &cps).unwrap();
    assert_eq!(rep.first_seq, Some(10));
    // AUD-RM1-LOG-20 regression: with the deployment's configured 400-day
    // SECURITY retention, a 90-day prune no longer verifies.
    p.min_retention_days = Some(400);
    assert_eq!(
        verify_stream(&p, &recs, &cps).unwrap_err().code,
        VerifyFailureCode::UnboundPrune
    );
    p.min_retention_days = Some(90);
    verify_stream(&p, &recs, &cps).unwrap();
    // CASE streams are never interval-deleted.
    for s in [StreamId::Case, StreamId::CaseSlot] {
        assert!(retention::plan_interval_deletion(&policy, s, &cps, 0, now).is_err());
        assert!(DisposalRequest::retention(tenant(), s, 90).is_none());
    }
}

// AUD-RM1-LOG-01/20: a tombstone for intervals younger than the authorized
// retention (planned with a falsified "now") is refused by the writer; an
// authorization below the 20 §12 minimum cannot be made.
#[test]
fn premature_prune_rejected() {
    let (mut log, sink, clock) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    for _ in 0..4 {
        log.emit(EventContext::staff(user(1)), login()).unwrap();
    }
    clock.advance(5 * 60 * 1000);
    log.tick().unwrap();
    let policy = RetentionPolicy::new(90, 7, 365, 13).unwrap();
    let cps = sink.0.lock().unwrap().checkpoints(StreamId::Sec);
    let fake_now = UtcMillis(clock.now() + 100 * DAY);
    let plan = retention::plan_interval_deletion(&policy, StreamId::Sec, &cps, 0, fake_now)
        .unwrap()
        .unwrap();
    assert_eq!(
        log.emit_retention_tombstone(
            EventContext::system(Service::Audit),
            &plan,
            &retention_auth(StreamId::Sec, 90)
        )
        .unwrap_err(),
        LogError::Disposal(DisposalError::TooEarly)
    );
    assert!(DisposalRequest::retention(tenant(), StreamId::Sec, 30).is_none());
    assert!(DisposalRequest::retention(tenant(), StreamId::Sys, 6).is_none());
}

// JSONL sink round trip and tamper detection through the file format
// (the JSONL sink is a secondary here; AUD-RM1-LOG-13 metadata checks).
#[test]
fn jsonl_round_trip() {
    let (mut log, _sink, clock) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let jsonl = SharedJsonl::default();
    log.add_secondary_sink(Box::new(jsonl.clone()));
    for i in 0..7 {
        log.emit(EventContext::staff(user(1)), opened(i)).unwrap();
    }
    clock.advance(DAY);
    log.tick().unwrap();
    let mem: MemoryJsonl = jsonl.0.lock().unwrap().clone();
    let recs_txt = mem.contents(JsonlFile::Records(StreamId::Case)).to_vec();
    let cps_txt = mem
        .contents(JsonlFile::Checkpoints(StreamId::Case))
        .to_vec();
    let text = String::from_utf8(recs_txt.clone()).unwrap();
    assert!(text.lines().all(|l| l.starts_with("{\"k\":\"rec\"")));
    assert!(text.contains("\"type\":\"case.opened\""));
    let (recs, cps) = read_stream(StreamId::Case, recs_txt.as_slice(), cps_txt.as_slice()).unwrap();
    let key = log.verifying_key();
    let rep = verify_stream(&params(&key, StreamId::Case), &recs, &cps).unwrap();
    assert_eq!(rep.records, 7);
    // Resume from the verified state continues the same chain.
    let resume: StreamResume = rep.resume();
    assert_eq!(resume.next_seq, 7);
    // Flip one hex digit in the stored CBOR of line 2.
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let l = &mut lines[2];
    let i = l.rfind("\"}").unwrap() - 1;
    let c = if l.as_bytes()[i] == b'0' { "1" } else { "0" };
    l.replace_range(i..=i, c);
    let tampered = lines.join("\n");
    let res = read_stream(StreamId::Case, tampered.as_bytes(), cps_txt.as_slice());
    assert!(res.map_or(true, |(r, c)| {
        verify_stream(&params(&key, StreamId::Case), &r, &c).is_err()
    }));
    // Line metadata must agree with the CBOR (seq / type).
    let lied = text.replacen("\"seq\":0,", "\"seq\":5,", 1);
    assert_eq!(
        read_stream(StreamId::Case, lied.as_bytes(), cps_txt.as_slice()).unwrap_err(),
        ReadError::MetadataMismatch
    );
    let lied = text.replacen("\"type\":\"case.opened\"", "\"type\":\"case.listed\"", 1);
    assert_eq!(
        read_stream(StreamId::Case, lied.as_bytes(), cps_txt.as_slice()).unwrap_err(),
        ReadError::MetadataMismatch
    );
    // Unknown fields / garbage rejected.
    assert!(read_stream(StreamId::Case, &b"{\"k\":\"rec\",\"x\":1}\n"[..], &b""[..]).is_err());
    assert!(read_stream(StreamId::Case, &b"not json\n"[..], &b""[..]).is_err());
}

#[test]
fn resume_continues_chain() {
    let (mut log, sink, clock) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    for i in 0..6 {
        log.emit(EventContext::staff(user(1)), opened(i)).unwrap();
        if i == 3 {
            clock.advance(DAY);
        }
    }
    let (recs, cps) = {
        let st = sink.0.lock().unwrap();
        (st.chain(StreamId::Case), st.checkpoints(StreamId::Case))
    };
    let key = log.verifying_key();
    let rep = verify_stream(&params(&key, StreamId::Case), &recs, &cps).unwrap();
    assert_eq!(rep.unattested_tail, 2);
    // A fresh writer (restart) resumes from the verified state.
    let r2 = rig_at(HostRole::Core, CheckpointPolicy::DEFAULT, clock.now());
    let (mut log2, sink2, clock2) = (r2.log, r2.sink, r2.clock);
    log2.resume(StreamId::Case, rep.resume());
    for i in 6..10 {
        log2.emit(EventContext::staff(user(1)), opened(i)).unwrap();
    }
    clock2.advance(DAY);
    log2.tick().unwrap();
    let st2 = sink2.0.lock().unwrap();
    let mut all = recs;
    all.extend(st2.chain(StreamId::Case));
    let mut all_cps = cps;
    all_cps.extend(st2.checkpoints(StreamId::Case));
    let rep = verify_stream(&params(&key, StreamId::Case), &all, &all_cps).unwrap();
    assert_eq!(rep.records, 10);
    assert_eq!(rep.unattested_tail, 0);
}

/// Sink that fails while `fail` is set.
#[derive(Clone, Default)]
struct Flaky {
    fail: Arc<AtomicBool>,
    inner: MemorySink,
    writes: Arc<AtomicUsize>,
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

// AUD-RM1-LOG-07 regression: a failing secondary never forks the chain
// (the old code re-issued the seq to the sinks that had succeeded); it
// catches up from its outbox in order.
#[test]
fn failing_secondary_does_not_fork_chain() {
    let (mut log, primary, clock) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let sec = Flaky::default();
    log.add_secondary_sink(Box::new(sec.clone()));
    log.emit(EventContext::staff(user(1)), login()).unwrap();
    sec.fail.store(true, Ordering::SeqCst);
    for _ in 0..3 {
        let e = log.emit(EventContext::staff(user(1)), login()).unwrap();
        assert!(e.secondary_lag);
    }
    assert_eq!(log.secondary_status()[0].queued, 3);
    sec.fail.store(false, Ordering::SeqCst);
    clock.advance(5 * 60 * 1000);
    log.tick().unwrap();
    assert_eq!(log.secondary_status()[0].queued, 0);
    let key = log.verifying_key();
    for store in [
        primary.0.lock().unwrap().clone(),
        sec.inner.0.lock().unwrap().clone(),
    ] {
        let rep = verify_stream(
            &params(&key, StreamId::Sec),
            &store.chain(StreamId::Sec),
            &store.checkpoints(StreamId::Sec),
        )
        .unwrap();
        assert_eq!(rep.records, 4);
        assert_eq!(rep.unattested_tail, 0);
    }
}

// AUD-RM1-LOG-07: a failing primary commits nothing; the next event takes
// the same seq and the store still verifies.
#[test]
fn failing_primary_commits_nothing() {
    let clock = TestClock::new(T0);
    let mut log = AuditLog::new(
        tenant(),
        HostRole::Core,
        signer(7),
        clock.clone(),
        CheckpointPolicy::DEFAULT,
    );
    let prim = Flaky::default();
    log.set_primary_sink(Box::new(prim.clone()));
    log.emit(EventContext::staff(user(1)), login()).unwrap();
    prim.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        log.emit(EventContext::staff(user(1)), login()).unwrap_err(),
        LogError::Sink(SinkError::Io)
    );
    prim.fail.store(false, Ordering::SeqCst);
    let e = log.emit(EventContext::staff(user(1)), login()).unwrap();
    assert_eq!(e.record.unwrap().header().seq, 1);
    let st = prim.inner.0.lock().unwrap();
    verify_stream(
        &params(&log.verifying_key(), StreamId::Sec),
        &st.chain(StreamId::Sec),
        &st.checkpoints(StreamId::Sec),
    )
    .unwrap();
    // Without a primary sink nothing can be emitted (fail closed).
    let mut bare = AuditLog::new(
        tenant(),
        HostRole::Core,
        signer(7),
        clock,
        CheckpointPolicy::DEFAULT,
    );
    assert_eq!(
        bare.emit(EventContext::staff(user(1)), login())
            .unwrap_err(),
        LogError::NoPrimarySink
    );
}

struct FlakySigner {
    inner: candor_log::SoftwareSigner,
    fail: Arc<AtomicBool>,
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

// AUD-RM1-LOG-07: a signer failure when a slot must be closed writes
// nothing (no committed-but-reported-failed record), so a retry does not
// log the event twice.
#[test]
fn signer_failure_writes_nothing() {
    let clock = TestClock::new(T0);
    let fail = Arc::new(AtomicBool::new(false));
    let signer = FlakySigner {
        inner: signer(7),
        fail: fail.clone(),
    };
    let mut log = AuditLog::new(
        tenant(),
        HostRole::Core,
        signer,
        clock.clone(),
        CheckpointPolicy::DEFAULT,
    );
    let sink = MemorySink::new();
    log.set_primary_sink(Box::new(sink.clone()));
    log.emit(EventContext::staff(user(1)), login()).unwrap();
    clock.advance(5 * 60 * 1000);
    fail.store(true, Ordering::SeqCst);
    assert_eq!(
        log.emit(EventContext::staff(user(1)), login()).unwrap_err(),
        LogError::Signer
    );
    assert_eq!(sink.0.lock().unwrap().chain(StreamId::Sec).len(), 1);
    fail.store(false, Ordering::SeqCst);
    let e = log.emit(EventContext::staff(user(1)), login()).unwrap();
    assert!(e.checkpoint.is_some());
    assert_eq!(e.record.unwrap().header().seq, 1);
    let st = sink.0.lock().unwrap();
    verify_stream(
        &params(&log.verifying_key(), StreamId::Sec),
        &st.chain(StreamId::Sec),
        &st.checkpoints(StreamId::Sec),
    )
    .unwrap();
}

/// Test witness: records every published head per stream.
#[derive(Clone, Default)]
struct Witness {
    heads: Arc<std::sync::Mutex<Vec<SignedCheckpoint>>>,
    down: Arc<AtomicBool>,
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
    fn latest(&self, s: StreamId) -> Option<SignedCheckpoint> {
        self.heads
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|c| c.body().stream == s)
            .cloned()
    }
}

// AUD-RM1-LOG-19 regression: every stream publishes its head to the
// witness at each tick — hourly for SECURITY/CASE/SYSTEM, every import slot
// for the slot streams, empty ticks included — and the verifier given the
// latest witnessed head detects truncation beyond it (records and/or
// checkpoints removed). Residual: records after the last witnessed head
// (≤ one tick).
#[test]
fn witness_ticks_and_truncation_beyond_witnessed_head() {
    let start = T0 - T0 % DAY + 30_000;
    let r = rig_at(HostRole::Core, CheckpointPolicy::DEFAULT, start);
    let (mut log, sink, clock) = (r.log, r.sink, r.clock);
    let w = Witness::default();
    log.set_witness(Box::new(w.clone()));
    // A day of minute ticks; CASE events in the first two hours only.
    for minute in 0..(24 * 60) {
        clock.advance(60_000);
        if minute < 120 && minute % 7 == 0 {
            log.emit(EventContext::staff(user(1)), opened(1)).unwrap();
        }
        log.tick().unwrap();
    }
    let heads = w.heads.lock().unwrap().clone();
    for s in [StreamId::Sec, StreamId::Case, StreamId::Sys] {
        let times: Vec<u64> = heads
            .iter()
            .filter(|c| c.body().stream == s)
            .map(|c| c.body().signed_at.0)
            .collect();
        assert_eq!(times.len(), 24, "{s:?}: one head per hour, empty included");
        assert!(times.iter().all(|t| t % 3_600_000 == 0));
    }
    for s in [StreamId::CaseSlot, StreamId::SysSlot] {
        let n = heads.iter().filter(|c| c.body().stream == s).count();
        assert_eq!(n, 4, "{s:?}: one head per import slot");
    }
    assert!(!log.witness_lag());
    let key = log.verifying_key();
    let witnessed = w.latest(StreamId::Case).unwrap();
    let st = sink.0.lock().unwrap().clone();
    let recs = st.chain(StreamId::Case);
    let cps = st.checkpoints(StreamId::Case);
    let mut p = params(&key, StreamId::Case);
    p.trusted_latest = Some(&witnessed);
    verify_stream(&p, &recs, &cps).unwrap();
    // Truncating records covered by the witnessed head is detected even when
    // the insider also drops every checkpoint after the last surviving one.
    let keep = recs.len() - 3;
    let cut_cps: Vec<SignedCheckpoint> = cps
        .iter()
        .take_while(|c| c.body().end_seq as usize <= keep)
        .cloned()
        .collect();
    let e = verify_stream(&p, &recs[..keep], &cut_cps).unwrap_err();
    assert_eq!(e.code, VerifyFailureCode::Rollback);
    let e = verify_stream(&p, &recs[..keep], &cps).unwrap_err();
    assert_eq!(e.code, VerifyFailureCode::Truncated);
    // Without the witness the same truncation is indistinguishable from
    // an honest older state (why the witness ticks exist).
    verify_stream(&params(&key, StreamId::Case), &recs[..keep], &cut_cps).unwrap();
    // A head that could not be published stays queued and goes out later.
    w.down.store(true, Ordering::SeqCst);
    clock.advance(3_600_000);
    log.tick().unwrap();
    assert!(log.witness_lag());
    w.down.store(false, Ordering::SeqCst);
    log.tick().unwrap();
    assert!(!log.witness_lag());
}

// AUD-RM1-LOG-17 regression (round-2 PoC `main.rs`): checkpoint-derived
// values come only from the writer's own checkpoints and are bound to its
// key; a self-signed checkpoint or a second log with the insider's key
// cannot launder chosen bits into `seq`/`seq_range`/`root` fields.
#[test]
fn checkpoint_values_cannot_be_laundered() {
    let (mut log, _sink, clock) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    log.emit(EventContext::staff(user(1)), login()).unwrap();
    clock.advance(5 * 60 * 1000);
    let real = log
        .tick()
        .unwrap()
        .into_iter()
        .find(|c| c.body().stream == StreamId::Sec)
        .unwrap();
    // Self-signed checkpoint with an IPv6 address as root and an IPv4:port
    // as end_seq.
    let mut v = cbor::decode(real.bytes()).unwrap();
    if let cbor::Value::Map(m) = &mut v {
        for (k, val) in m.iter_mut() {
            match k.as_text() {
                Some("merkle_root") => *val = cbor::Value::Bytes(vec![0x20; 32]),
                Some("end_seq") => *val = cbor::Value::Uint(0xCB00_7107_0000_01BB),
                _ => {}
            }
        }
    }
    let bytes = cbor::encode(&v).unwrap();
    let mine = signer(9);
    let sig = mine.sign_checkpoint(&bytes).unwrap();
    let forged = SignedCheckpoint::from_parts(bytes, sig.to_bytes()).unwrap();
    assert!(log.checkpoint_root(&forged).is_none());
    assert!(log.checkpoint_seq(&forged).is_none());
    assert!(log.checkpoint_range(&forged).is_none());
    // Values from the insider's own writer are refused by the real one.
    let mut other = AuditLog::new(
        tenant(),
        HostRole::Core,
        signer(9),
        clock.clone(),
        CheckpointPolicy::DEFAULT,
    );
    other.set_primary_sink(Box::new(MemorySink::new()));
    let root = other.checkpoint_root(&forged).unwrap();
    let range = other.checkpoint_range(&forged).unwrap();
    let seq = other.checkpoint_seq(&forged).unwrap();
    for ev in [
        AuditEvent::AuditCheckpointSigned {
            stream: StreamId::Sec,
            seq_range: range,
            root,
        },
        AuditEvent::AuditWitnessFailed {
            witness_id: WitnessId::generate().unwrap(),
            checkpoint_seq: seq,
        },
    ] {
        assert_eq!(
            log.emit(EventContext::staff(user(1)), ev).unwrap_err(),
            LogError::ForeignArtefact
        );
    }
    // The writer's own artefacts are accepted.
    let ok = AuditEvent::AuditCheckpointSigned {
        stream: StreamId::Sec,
        seq_range: log.checkpoint_range(&real).unwrap(),
        root: log.checkpoint_root(&real).unwrap(),
    };
    log.emit(EventContext::staff(user(1)), ok).unwrap();
    // A verification failure under another key does not bind either.
    let other_key = signer(9).verifying_key();
    let e = verify_stream(&params(&other_key, StreamId::Sec), &[], std::slice::from_ref(&real)).unwrap_err();
    assert_eq!(
        log.emit(
            EventContext::staff(user(1)),
            AuditEvent::AuditVerificationFailed {
                stream: StreamId::Sec,
                seq: candor_log::field::Seq::of_failure(&e),
                failure_code: e.code,
            }
        )
        .unwrap_err(),
        LogError::ForeignArtefact
    );
    let e = verify_stream(&params(&log.verifying_key(), StreamId::Case), &[], &[real]).unwrap_err();
    log.emit(
        EventContext::staff(user(1)),
        AuditEvent::AuditVerificationFailed {
            stream: StreamId::Case,
            seq: candor_log::field::Seq::of_failure(&e),
            failure_code: e.code,
        },
    )
    .unwrap();
    let _ = (clock.read(), seq);
}
