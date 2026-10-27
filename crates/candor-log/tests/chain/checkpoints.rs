// SPDX-License-Identifier: AGPL-3.0-or-later
//! Checkpoint schedule and timing, date-only events, witness ticks and
//! checkpoint-value laundering (AUD-002, AUD-RM1-LOG-02/17/19).

use super::support::*;

use std::sync::atomic::Ordering;

use crate::common::*;
use candor_log::cbor;
use candor_log::chain::CheckpointSigner;
use candor_log::codes::*;
use candor_log::ids::*;
use candor_log::sink::MemorySink;
use candor_log::verify::verify_stream;
use candor_log::{
    AuditClock, AuditEvent, AuditLog, CheckpointPolicy, EventContext, LogError, SignedCheckpoint,
};

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
    let e = verify_stream(
        &params(&other_key, StreamId::Sec),
        &[],
        std::slice::from_ref(&real),
    )
    .unwrap_err();
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
    let e = verify_stream(&params(&log.verifying_key(), StreamId::Sec), &[], &[real]).unwrap_err();
    log.emit(
        EventContext::staff(user(1)),
        AuditEvent::AuditVerificationFailed {
            stream: StreamId::Sec,
            seq: candor_log::field::Seq::of_failure(&e),
            failure_code: e.code,
        },
    )
    .unwrap();
    let _ = (clock.read(), seq);
}
