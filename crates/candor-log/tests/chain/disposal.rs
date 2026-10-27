// SPDX-License-Identifier: AGPL-3.0-or-later
//! Case disposal and redaction, redacted stubs, forged tombstones and
//! retention-interval deletion (AUD-005, AUD-012, AUD-RM1-LOG-01/08/16/20).

use super::support::*;

use crate::common::*;
use candor_log::chain::{ChainRecord, record_commit, record_inner};
use candor_log::codes::*;
use candor_log::disposal::{
    ApproverKeys, DisposalApprover, DisposalAuthorization, DisposalError, DisposalRequest,
    SoftwareApprover,
};
use candor_log::field::StaffTimer;
use candor_log::ids::*;
use candor_log::retention::{self, RetentionError, RetentionPolicy};
use candor_log::verify::verify_stream;
use candor_log::{AuditEvent, CheckpointPolicy, EventContext, LogError};

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
