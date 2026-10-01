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
use candor_log::chain::{ChainRecord, CheckpointSigner, SignerError, StreamResume, record_commit};
use candor_log::codes::*;
use candor_log::envelope::EnvelopeError;
use candor_log::field::{SlotIndex, SmallCount, StaffTimer};
use candor_log::ids::*;
use candor_log::retention::{self, RetentionError, RetentionPolicy};
use candor_log::sink::{
    AuditSink, JsonlFile, MemoryJsonl, MemorySink, ReadError, SharedJsonl, SinkError, read_stream,
};
use candor_log::verify::{VerifyParams, verify_stream};
use candor_log::{
    AuditEvent, AuditLog, CheckpointPolicy, CommittedRecord, EventContext, LogError,
    SignedCheckpoint,
};
use common::*;

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
        trusted_latest: None,
        allow_pruned_prefix: false,
    }
}

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
    assert_eq!(log.tick().unwrap().len(), 3);
    for i in 0..2 {
        log.emit(EventContext::staff(user(1)), opened(i)).unwrap();
    }
    let key = log.verifying_key();
    let store = sink.0.lock().unwrap().clone();
    for s in [StreamId::Sec, StreamId::Case, StreamId::Sys] {
        let rep = verify_stream(&params(&key, s), &store.chain(s), &store.checkpoints(s)).unwrap();
        assert_eq!(rep.first_seq, if rep.records > 0 { Some(0) } else { None });
    }
    // 12 case events; one daily checkpoint over the first 10, 2 unattested.
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

/// `n` CASE events, `per_day` per UTC day; every completed day is
/// checkpointed (the last one by a final tick).
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
    let cps = log.tick().unwrap();
    assert_eq!(cps.len(), 1);
    let b = cps[0].body();
    assert_eq!((b.first_seq, b.end_seq), (0, 1500));
    assert_eq!(b.signed_at.0 % 300_000, 0, "dated at the slot boundary");
    assert!(b.signed_at.0 <= clock.now() && clock.now() - b.signed_at.0 < 300_000);
    // An empty slot still yields a checkpoint (data-independent cadence).
    clock.advance(5 * 60 * 1000);
    let cps = log.tick().unwrap();
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

// AUD-RM1-LOG-02 regression (failed on the old cadence, which emitted a
// checkpoint one tick after the import with an exact `signed_at` and
// `seq 0..0`): whether or not a date-only import happened, the witness sees
// the same checkpoints at the same times. CASE/SYSTEM checkpoint only at
// 00:00 UTC; only their (daily) seq range and roots can differ.
#[test]
fn checkpoint_timing_independent_of_date_only_events() {
    let import = AuditEvent::CaseImported {
        case: case(5),
        channel_id: ChannelId::derive(&idk(), b"ch"),
        received_day: UtcMillis(T0).day(),
        import_slot_date: UtcMillis(T0).day(),
    };
    let (with, cps_with) = schedule_trace(
        HostRole::Core,
        Some((EventContext::system(Service::Relay), import)),
    );
    let (without, cps_without) = schedule_trace(HostRole::Core, None);
    assert_eq!(
        with, without,
        "checkpoint times/streams must not depend on events"
    );
    for (s, t) in &with {
        if *s != StreamId::Sec {
            assert_eq!(t % DAY, 0, "CASE/SYSTEM checkpoints only at midnight");
        }
    }
    // Same for a source-load-derived (date-only) SYSTEM health event.
    let flood = AuditEvent::SysHealth {
        service: Service::Upload,
        status: HealthStatus::Degraded,
        check_code: HealthCheck::AbuseFlood,
    };
    let (with_sys, _) = schedule_trace(
        HostRole::Core,
        Some((EventContext::system(Service::Health), flood)),
    );
    assert_eq!(with_sys, without);
    // Only the CASE checkpoint closing the import day differs, and only in
    // its seq range / roots (counts per day are not hidden; documented).
    let diff: Vec<_> = cps_with
        .iter()
        .zip(&cps_without)
        .filter(|(a, b)| a.bytes() != b.bytes() && a.body().stream == b.body().stream)
        .map(|(a, _)| a.body().stream)
        .collect();
    assert!(diff.iter().all(|s| *s == StreamId::Case));
    // SECURITY: a staff event does not move SECURITY checkpoint times either.
    let (with_sec, _) = schedule_trace(
        HostRole::Core,
        Some((EventContext::staff(user(1)), login())),
    );
    assert_eq!(with_sec, without);
    // Z-INTAKE: SECURITY hourly, never finer than the hour truncation.
    let (intake, _) = schedule_trace(HostRole::Intake, None);
    assert!(intake.iter().all(|(_, t)| t % 3_600_000 == 0));
}

fn ts_of(r: &candor_log::CommittedRecord) -> u64 {
    let v = cbor::decode(r.bytes()).unwrap();
    v.get("ts").unwrap().as_u64().unwrap()
}

// LOG-013 / LOG-021 / ADR-046(11): timestamp policy.
#[test]
fn timestamp_policy() {
    let (mut log, _sink, _c) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let staff = log
        .emit(EventContext::staff(user(1)), opened(1))
        .unwrap()
        .record;
    assert_eq!(ts_of(&staff), T0, "staff actions exact to the ms");
    let imp = log
        .emit(
            EventContext::system(Service::Relay),
            AuditEvent::CaseImported {
                case: case(1),
                channel_id: ChannelId::derive(&idk(), b"ch"),
                received_day: UtcMillis(T0).day(),
                import_slot_date: UtcMillis(T0).day(),
            },
        )
        .unwrap()
        .record;
    assert_eq!(ts_of(&imp) % MS_PER_DAY, 0, "import events date-only");
    // Even a staff-performed import-related event is date-only.
    let ev = log
        .emit(
            EventContext::staff(user(1)),
            AuditEvent::EvidenceImported {
                case: case(1),
                evid: EvidRef::derive(&idk(), b"e3"),
                manifest_match: true,
            },
        )
        .unwrap()
        .record;
    assert_eq!(ts_of(&ev) % MS_PER_DAY, 0);
    // CASE event with a system actor: date only.
    let sla = log
        .emit(
            EventContext::system(Service::Scheduler),
            AuditEvent::CaseSlaReminder {
                case: case(1),
                timer_id: TimerId::derive(&idk(), b"t4"),
                due_date: UtcMillis(T0).day(),
            },
        )
        .unwrap()
        .record;
    assert_eq!(ts_of(&sla) % MS_PER_DAY, 0);
    // SYSTEM: second.
    let sys = log
        .emit(
            EventContext::system(Service::Health),
            AuditEvent::SysJob {
                job_kind: JobKind::Backup,
                outcome: Outcome::Ok,
            },
        )
        .unwrap()
        .record;
    assert_eq!(ts_of(&sys), T0 - T0 % 1000);
    // Source-load-derived health: date only.
    let flood = log
        .emit(
            EventContext::system(Service::Health),
            AuditEvent::SysHealth {
                service: Service::Upload,
                status: HealthStatus::Degraded,
                check_code: HealthCheck::AbuseFlood,
            },
        )
        .unwrap()
        .record;
    assert_eq!(ts_of(&flood) % MS_PER_DAY, 0);
    // Relay daily summary and slot overrun: date only, no arrival counts.
    let relay = log
        .emit(
            EventContext::system(Service::Relay),
            AuditEvent::SysRelayDaily {
                date: UtcMillis(T0).day(),
                slots_ok: SmallCount::new(4).unwrap(),
                slots_failed: SmallCount::new(0).unwrap(),
                slots_overrun: SmallCount::new(0).unwrap(),
            },
        )
        .unwrap()
        .record;
    assert_eq!(ts_of(&relay) % MS_PER_DAY, 0);
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
    let r = log
        .emit(
            EventContext::system(Service::Tor),
            AuditEvent::SysTorStatus {
                bootstrap_percent: candor_log::field::Percent::new(100).unwrap(),
                onion_published: true,
                pow_enabled: false,
            },
        )
        .unwrap()
        .record;
    assert_eq!(ts_of(&r) % MS_PER_HOUR, 0);
    let a = log
        .emit(EventContext::staff(user(1)), login())
        .unwrap()
        .record;
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
    let mut ctx = EventContext::system(Service::Core);
    ctx.session = Some(SessionTag::derive(&DaySalt::new([1; 32]), b"sid"));
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
    ctx.session = Some(SessionTag::derive(&DaySalt::new([1; 32]), b"sid"));
    let r = log.emit(ctx, opened(1)).unwrap().record;
    let v = cbor::decode(r.bytes()).unwrap();
    assert_eq!(v.get("session").unwrap().as_bytes().unwrap().len(), 8);
    assert_eq!(v.get("reason").unwrap().as_text(), Some("TIMEOUT"));
}

// Every catalog type encodes canonically and verifies (LOG-001 schema test).
#[test]
fn full_catalog_round_trip() {
    let (mut log, sink, _c) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let samples = AuditEvent::samples();
    assert_eq!(samples.len(), candor_log::CATALOG.len());
    for e in samples {
        let names = e.field_names();
        let r = log.emit(EventContext::staff(user(1)), e).unwrap().record;
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
    let st = sink.0.lock().unwrap();
    for s in [StreamId::Sec, StreamId::Case, StreamId::Sys] {
        verify_stream(
            &params(&log.verifying_key(), s),
            &st.chain(s),
            &st.checkpoints(s),
        )
        .unwrap();
    }
}

// AUD-012: per-case redaction keeps the chain verifiable once the
// tombstone that commits to the redacted set is checkpointed.
#[test]
fn case_disposal_redaction_verifies() {
    let r = rig(HostRole::Core, CheckpointPolicy::DEFAULT);
    let (mut log, sink, clock, keys) = (r.log, r.sink, r.clock, r.keys);
    for i in 0..9 {
        log.emit(EventContext::staff(user(1)), opened(i % 3))
            .unwrap();
    }
    let target = case(1);
    let plan = sink.0.lock().unwrap().plan_case_redaction(target);
    assert_eq!(plan.len(), 3);
    let tomb = log
        .emit(
            EventContext::staff(user(1)),
            plan.tombstone(ReceiptId::derive(&idk(), b"r5")),
        )
        .unwrap()
        .record;
    let n = sink
        .0
        .lock()
        .unwrap()
        .apply_case_redaction(&plan, &tomb)
        .unwrap();
    assert_eq!(n, 3);
    keys.destroy(target);
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
    clock.advance(DAY);
    log.tick().unwrap();
    let st = sink.0.lock().unwrap();
    assert!(
        st.records(StreamId::Case)
            .iter()
            .filter(|r| !matches!(r.event(), AuditEvent::CaseDisposed { .. }))
            .all(|r| r.event().case_ref() != Some(target))
    );
    let rep = verify_stream(
        &params(&key, StreamId::Case),
        &st.chain(StreamId::Case),
        &st.checkpoints(StreamId::Case),
    )
    .unwrap();
    assert_eq!(rep.redacted, 3);
    // Tampering with a stub is detected.
    let mut recs = st.chain(StreamId::Case);
    let pos = recs
        .iter()
        .position(|r| matches!(r, ChainRecord::Redacted { .. }))
        .unwrap();
    if let ChainRecord::Redacted { commit, .. } = &mut recs[pos] {
        commit[0] ^= 1;
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

fn stub_of(r: &CommittedRecord, tombstone_seq: u64) -> ChainRecord {
    ChainRecord::Redacted {
        seq: r.header().seq,
        commit: *r.commit(),
        tombstone_seq,
    }
}

// AUD-RM1-LOG-01 regression (the audit PoC; passed on the old verifier):
// an insider replaces a SECURITY record by a stub computed from the
// original; verification against the witness checkpoint must fail.
#[test]
fn stub_in_security_stream_rejected() {
    let (mut log, sink, clock) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let danger = log
        .emit(
            EventContext::staff(user(1)),
            AuditEvent::CfgDangerousEnabled {
                key: Code::of::<5>(),
                expiry: StaffTimer::after(&clock, 60).unwrap(),
            },
        )
        .unwrap()
        .record;
    log.emit(
        EventContext::staff(user(1)),
        AuditEvent::AuthLogout {
            reason_code: SessionEndReason::UserLogout,
        },
    )
    .unwrap();
    clock.advance(5 * 60 * 1000);
    let cps = log.tick().unwrap();
    let witness = cps.last().unwrap().clone();
    let key = log.verifying_key();
    let mut st = sink.0.lock().unwrap();
    assert!(st.tamper_replace(StreamId::Sec, 0, stub_of(&danger, 1)));
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
        recs.push(
            log.emit(EventContext::staff(user(1)), opened(i % 2))
                .unwrap()
                .record,
        );
    }
    clock.advance(DAY);
    log.tick().unwrap();
    let key = log.verifying_key();
    // (a) stub pointing at an ordinary record.
    {
        let mut st = sink.0.lock().unwrap().clone();
        st.tamper_replace(StreamId::Case, 0, stub_of(&recs[0], 1));
        let e = verify_stream(
            &params(&key, StreamId::Case),
            &st.chain(StreamId::Case),
            &st.checkpoints(StreamId::Case),
        )
        .unwrap_err();
        assert_eq!(e.code, VerifyFailureCode::UnboundRedaction);
    }
    // (b) legitimate disposal of case 0, plus one extra record of case 1
    // stubbed against the same tombstone: set/count mismatch.
    let plan = sink.0.lock().unwrap().plan_case_redaction(case(0));
    let tomb = log
        .emit(
            EventContext::staff(user(1)),
            plan.tombstone(ReceiptId::derive(&idk(), b"r")),
        )
        .unwrap()
        .record;
    sink.0
        .lock()
        .unwrap()
        .apply_case_redaction(&plan, &tomb)
        .unwrap();
    clock.advance(DAY);
    log.tick().unwrap();
    let tseq = tomb.header().seq;
    let mut st = sink.0.lock().unwrap().clone();
    verify_stream(
        &params(&key, StreamId::Case),
        &st.chain(StreamId::Case),
        &st.checkpoints(StreamId::Case),
    )
    .unwrap();
    st.tamper_replace(StreamId::Case, 1, stub_of(&recs[1], tseq));
    let e = verify_stream(
        &params(&key, StreamId::Case),
        &st.chain(StreamId::Case),
        &st.checkpoints(StreamId::Case),
    )
    .unwrap_err();
    assert_eq!(e.code, VerifyFailureCode::UnboundRedaction);
    // A tombstone cannot cover a later record.
    let later = log
        .emit(EventContext::staff(user(1)), opened(3))
        .unwrap()
        .record;
    let mut st = sink.0.lock().unwrap().clone();
    assert!(st.tamper_replace(StreamId::Case, later.header().seq, stub_of(&later, tseq)));
    let e = verify_stream(
        &params(&key, StreamId::Case),
        &st.chain(StreamId::Case),
        &st.checkpoints(StreamId::Case),
    )
    .unwrap_err();
    assert_eq!(e.code, VerifyFailureCode::UnboundRedaction);
}

// AUD-RM1-LOG-08: a stub cannot be confirmed against a guessed record
// without the destroyed per-case key.
#[test]
fn redacted_stub_reveals_nothing_without_case_key() {
    let (mut log, _sink, _c) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let a = log
        .emit(EventContext::staff(user(1)), opened(1))
        .unwrap()
        .record;
    let b = log
        .emit(EventContext::staff(user(1)), opened(1))
        .unwrap()
        .record;
    assert_ne!(a.salt(), &[0; 32], "CASE records are salted");
    assert_ne!(a.salt(), b.salt(), "salt is per record");
    // An attacker who guesses the exact canonical bytes but lacks the salt
    // cannot reproduce the commitment.
    assert_ne!(record_commit(&[0; 32], a.bytes()), *a.commit());
    assert_eq!(record_commit(a.salt(), a.bytes()), *a.commit());
    // Non-redactable records carry no salt.
    let s = log
        .emit(EventContext::staff(user(1)), login())
        .unwrap()
        .record;
    assert_eq!(s.salt(), &[0; 32]);
    // Salts never appear in Debug output.
    assert!(!format!("{a:?}").contains(&format!("{:?}", a.salt())));
}

// AUD-005 / AUD-RM1-LOG-01: whole-interval retention with a checkpointed
// tombstone in the same stream; the remaining chain verifies; a prefix
// pruned without (or with a too-young) tombstone does not.
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
    assert_eq!(plan.range.last(), 9);
    // Without a tombstone, deletion is refused.
    let unrelated = log
        .emit(EventContext::staff(user(1)), login())
        .unwrap()
        .record;
    assert!(
        retention::apply_interval_deletion(&mut sink.0.lock().unwrap(), &plan, &unrelated).is_err()
    );
    let tomb = log
        .emit(EventContext::system(Service::Audit), plan.tombstone())
        .unwrap()
        .record;
    assert_eq!(
        retention::apply_interval_deletion(&mut sink.0.lock().unwrap(), &plan, &tomb),
        Err(RetentionError::TombstoneNotAttested)
    );
    clock.advance(5 * 60 * 1000);
    log.tick().unwrap();
    retention::apply_interval_deletion(&mut sink.0.lock().unwrap(), &plan, &tomb).unwrap();
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
    // CASE stream is never interval-deleted.
    assert!(retention::plan_interval_deletion(&policy, StreamId::Case, &cps, 0, now).is_err());
}

// AUD-RM1-LOG-01: a tombstone for intervals younger than the minimum
// retention (planned with a falsified "now") does not bind the prune.
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
    let tomb = log
        .emit(EventContext::system(Service::Audit), plan.tombstone())
        .unwrap()
        .record;
    clock.advance(5 * 60 * 1000);
    log.tick().unwrap();
    retention::apply_interval_deletion(&mut sink.0.lock().unwrap(), &plan, &tomb).unwrap();
    let st = sink.0.lock().unwrap();
    let key = log.verifying_key();
    let mut p = params(&key, StreamId::Sec);
    p.allow_pruned_prefix = true;
    let e =
        verify_stream(&p, &st.chain(StreamId::Sec), &st.checkpoints(StreamId::Sec)).unwrap_err();
    assert_eq!(e.code, VerifyFailureCode::UnboundPrune);
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
    assert_eq!(e.record.header().seq, 1);
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
    assert_eq!(e.record.header().seq, 1);
    let st = sink.0.lock().unwrap();
    verify_stream(
        &params(&log.verifying_key(), StreamId::Sec),
        &st.chain(StreamId::Sec),
        &st.checkpoints(StreamId::Sec),
    )
    .unwrap();
}
