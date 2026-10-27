// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tamper detection and record/stream integrity: deletion, reordering,
//! modification, truncation, forged checkpoints, rollback against a witness,
//! non-canonical records, cross-stream splices, envelope rules and the
//! catalog round trip (AUD-001..AUD-004, LOG-001, LOG-012).

use super::support::*;

use crate::common::*;
use candor_log::cbor;
use candor_log::chain::ChainRecord;
use candor_log::codes::*;
use candor_log::envelope::EnvelopeError;
use candor_log::ids::*;
use candor_log::verify::verify_stream;
use candor_log::{AuditEvent, CheckpointPolicy, EventContext, LogError};

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
