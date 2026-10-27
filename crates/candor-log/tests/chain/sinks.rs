// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sink behaviour: JSONL round trip, resume, failing secondary and primary
//! sinks, signer failure, restart stage loss and failure sequence bounds
//! (AUD-RM1-LOG-07/24/25/26).

use super::support::*;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::common::*;
use candor_log::chain::{ChainRecord, StreamResume};
use candor_log::codes::*;
use candor_log::sink::{
    JsonlFile, MemoryJsonl, MemorySink, ReadError, SharedJsonl, SinkError, read_stream,
};
use candor_log::verify::verify_stream;
use candor_log::{AuditEvent, AuditLog, CheckpointPolicy, EventContext, LogError};

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

// AUD-RM1-LOG-24 regression (round-3 PoC `r3seq.rs`): a crafted record
// verified under the writer's *public* key fails with a caller-chosen seq
// (IPv4 203.0.113.7:443 packed in 64 bits); the resulting `Seq` is outside
// the writer's sequence space and `emit` refuses it.
#[test]
fn crafted_failure_seq_cannot_be_logged() {
    let (mut log, _sink, _c) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    log.emit(EventContext::staff(user(1)), login()).unwrap();
    let key = log.verifying_key();
    let x: u64 = 0xcb00_7107_0000_01bb;
    let stub = ChainRecord::Redacted {
        seq: x,
        case: case(1),
        inner: [0; 32],
        tombstone_seq: x + 1,
    };
    let e = verify_stream(&params(&key, StreamId::Sec), &[stub], &[]).unwrap_err();
    let seq = candor_log::field::Seq::of_failure(&e);
    assert_eq!(seq.get(), x, "the verifier reports the crafted value");
    assert_eq!(
        log.emit(
            EventContext::staff(user(1)),
            AuditEvent::AuditVerificationFailed {
                stream: StreamId::Sec,
                seq,
                failure_code: e.code,
            }
        )
        .unwrap_err(),
        LogError::ForeignArtefact
    );
    // A failure inside the writer's own sequence space is still loggable.
    let ok = verify_stream(&params(&key, StreamId::Case), &[], &[]).map(|_| ());
    assert!(ok.is_ok());
    let bad = ChainRecord::Full {
        bytes: vec![0xff],
        salt: [0; 32],
        claimed_hash: None,
    };
    let e = verify_stream(&params(&key, StreamId::Sec), &[bad], &[]).unwrap_err();
    log.emit(
        EventContext::staff(user(1)),
        AuditEvent::AuditVerificationFailed {
            stream: StreamId::Sec,
            seq: candor_log::field::Seq::of_failure(&e),
            failure_code: e.code,
        },
    )
    .unwrap();
}

// AUD-RM1-LOG-25: after a restart the log records, in `sys-slot` at the
// next slot boundary, that staged date-only events may have been lost.
#[test]
fn restart_marks_possible_stage_loss() {
    let r = rig(HostRole::Core, CheckpointPolicy::DEFAULT);
    let (mut log, sink, clock) = (r.log, r.sink, r.clock);
    log.emit(EventContext::system(Service::Relay), imported(1))
        .unwrap();
    // Crash: the staged import is gone with the process.
    drop(log);
    let r2 = rig_at(HostRole::Core, CheckpointPolicy::DEFAULT, clock.now());
    let (mut log2, sink2, clock2) = (r2.log, r2.sink, r2.clock);
    log2.note_restart().unwrap();
    assert!(sink2.0.lock().unwrap().chain(StreamId::SysSlot).is_empty());
    next_slot(&mut log2, &clock2);
    let st = sink2.0.lock().unwrap();
    let lost: Vec<StreamId> = st
        .records(StreamId::SysSlot)
        .iter()
        .filter_map(|r| match r.event() {
            AuditEvent::SysStageLost { stream } => Some(*stream),
            _ => None,
        })
        .collect();
    assert_eq!(lost.len(), 2);
    assert!(lost.contains(&StreamId::CaseSlot) && lost.contains(&StreamId::SysSlot));
    assert!(
        st.records(StreamId::SysSlot)
            .iter()
            .all(|r| ts_of(r).is_multiple_of(DAY))
    );
    verify_stream(
        &params(&log2.verifying_key(), StreamId::SysSlot),
        &st.chain(StreamId::SysSlot),
        &st.checkpoints(StreamId::SysSlot),
    )
    .unwrap();
    assert!(sink.0.lock().unwrap().chain(StreamId::CaseSlot).is_empty());
}

// AUD-RM1-LOG-26: a failure seq is bounded by the counter of the stream it
// was verified for, not by the largest stream of the writer.
#[test]
fn failure_seq_bounded_by_its_own_stream() {
    let (mut log, _sink, _c) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    for i in 0..6 {
        log.emit(EventContext::staff(user(1)), opened(i)).unwrap();
    }
    log.emit(EventContext::staff(user(1)), login()).unwrap();
    let key = log.verifying_key();
    let stub = |s| ChainRecord::Redacted {
        seq: 5,
        case: case(1),
        inner: [0; 32],
        tombstone_seq: s,
    };
    let fail = |stream| {
        let e = verify_stream(&params(&key, stream), &[stub(9)], &[]).unwrap_err();
        assert_eq!(e.seq, 5);
        AuditEvent::AuditVerificationFailed {
            stream,
            seq: candor_log::field::Seq::of_failure(&e),
            failure_code: e.code,
        }
    };
    // SEC holds 1 record: seq 5 is outside it (CASE holds 6).
    assert_eq!(
        log.emit(EventContext::staff(user(1)), fail(StreamId::Sec))
            .unwrap_err(),
        LogError::ForeignArtefact
    );
    log.emit(EventContext::staff(user(1)), fail(StreamId::Case))
        .unwrap();
}
