// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hash chain, checkpoints, verification, timestamp policy, retention and
//! sinks (AUD-001..AUD-005, AUD-012, LOG-004, LOG-012, LOG-013, LOG-021).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use candor_log::cbor;
use candor_log::chain::{ChainRecord, StreamResume};
use candor_log::codes::*;
use candor_log::envelope::EnvelopeError;
use candor_log::field::{Count, SmallCount};
use candor_log::ids::*;
use candor_log::retention::{self, RetentionPolicy};
use candor_log::sink::{JsonlFile, MemoryJsonl, SharedJsonl, read_stream};
use candor_log::verify::{VerifyParams, verify_stream};
use candor_log::{AuditEvent, CheckpointPolicy, EventContext, LogError};
use common::*;

fn opened(n: u8) -> AuditEvent {
    AuditEvent::CaseOpened {
        case: CaseRef::from_bytes([n; 16]),
    }
}

fn login() -> AuditEvent {
    AuditEvent::AuthLoginSucceeded {
        method: AuthMethod::Fido2,
        aal: Aal::Aal3,
        authenticator_aaguid_class: AaguidClass::Certified,
        audience: Audience::DeskApi,
    }
}

fn params<'a>(
    key: &'a ed25519_dalek::VerifyingKey,
    stream: StreamId,
) -> VerifyParams<'a> {
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
    let (mut log, sink, _clock) = log_with(HostRole::Core, CheckpointPolicy::new(4, 300_000).unwrap());
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
    let key = log.verifying_key();
    let store = sink.0.lock().unwrap().clone();
    for s in [StreamId::Sec, StreamId::Case, StreamId::Sys] {
        let rep = verify_stream(&params(&key, s), &store.chain(s), &store.checkpoints(s)).unwrap();
        assert_eq!(rep.first_seq, if rep.records > 0 { Some(0) } else { None });
    }
    // 10 case events, checkpoint every 4 → 2 checkpoints, 2 unattested.
    let rep = verify_stream(
        &params(&key, StreamId::Case),
        &store.chain(StreamId::Case),
        &store.checkpoints(StreamId::Case),
    )
    .unwrap();
    assert_eq!(rep.records, 10);
    assert_eq!(rep.checkpoints, 2);
    assert_eq!(rep.unattested_tail, 2);
    // The case stream contains only CASE events.
    assert!(store
        .records(StreamId::Case)
        .iter()
        .all(|r| r.event().class() == candor_log::EventClass::Case));
}

fn setup(n: u8, every: u64) -> (Vec<ChainRecord>, Vec<candor_log::SignedCheckpoint>, ed25519_dalek::VerifyingKey) {
    let (mut log, sink, _c) = log_with(HostRole::Core, CheckpointPolicy::new(every, 300_000).unwrap());
    for i in 0..n {
        log.emit(EventContext::staff(user(1)), opened(i)).unwrap();
    }
    let st = sink.0.lock().unwrap();
    (st.chain(StreamId::Case), st.checkpoints(StreamId::Case), log.verifying_key())
}

fn code_of(
    recs: &[ChainRecord],
    cps: &[candor_log::SignedCheckpoint],
    key: &ed25519_dalek::VerifyingKey,
) -> VerifyFailureCode {
    verify_stream(&params(key, StreamId::Case), recs, cps).unwrap_err().code
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
    let ChainRecord::Full { bytes, .. } = &recs[3] else { panic!() };
    let mut b = bytes.clone();
    let pos = b.windows(16).position(|w| w == [3u8; 16]).unwrap();
    b[pos] = 0x99;
    recs[3] = ChainRecord::Full { bytes: b, claimed_hash: None };
    assert_eq!(code_of(&recs, &cps, &key), VerifyFailureCode::ChainMismatch);
}

#[test]
fn modification_of_last_record_detected_by_checkpoint() {
    let (mut recs, cps, key) = setup(10, 5);
    let ChainRecord::Full { bytes, .. } = &recs[9] else { panic!() };
    let mut b = bytes.clone();
    let pos = b.windows(16).position(|w| w == [9u8; 16]).unwrap();
    b[pos] = 0x42;
    recs[9] = ChainRecord::Full { bytes: b, claimed_hash: None };
    assert_eq!(code_of(&recs, &cps, &key), VerifyFailureCode::MerkleMismatch);
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
    assert_eq!(code_of(&recs[1..], &cps, &key), VerifyFailureCode::MissingPrefix);
}

#[test]
fn forged_checkpoint_rejected() {
    let (recs, cps, _key) = setup(10, 5);
    let other = signer(99).verifying_key_for_test();
    assert_eq!(code_of(&recs, &cps, &other), VerifyFailureCode::BadSignature);
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
    assert_eq!(code_of(&recs, &cps3, &key), VerifyFailureCode::CheckpointChain);
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
    let ChainRecord::Full { bytes, .. } = &recs[1] else { panic!() };
    let mut b = bytes.clone();
    b.push(0x00); // trailing byte
    recs[1] = ChainRecord::Full { bytes: b, claimed_hash: None };
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

// AUD-002: checkpoint cadence by count and by time.
#[test]
fn checkpoint_cadence() {
    let (mut log, sink, clock) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let mut produced = 0;
    for _ in 0..1000 {
        if log.emit(EventContext::staff(user(1)), login()).unwrap().checkpoint.is_some() {
            produced += 1;
        }
    }
    assert_eq!(produced, 1);
    log.emit(EventContext::staff(user(1)), login()).unwrap();
    assert!(log.tick().unwrap().is_empty());
    clock.advance(5 * 60 * 1000);
    let cps = log.tick().unwrap();
    assert_eq!(cps.len(), 1);
    assert_eq!(cps[0].body().first_seq, 1000);
    assert_eq!(cps[0].body().last_seq, 1000);
    // No events pending → no checkpoint.
    clock.advance(5 * 60 * 1000);
    assert!(log.tick().unwrap().is_empty());
    let st = sink.0.lock().unwrap();
    let rep = verify_stream(
        &params(&log.verifying_key(), StreamId::Sec),
        &st.chain(StreamId::Sec),
        &st.checkpoints(StreamId::Sec),
    )
    .unwrap();
    assert_eq!(rep.unattested_tail, 0);
}

fn ts_of(r: &candor_log::CommittedRecord) -> u64 {
    let v = cbor::decode(r.bytes()).unwrap();
    v.get("ts").unwrap().as_u64().unwrap()
}

// LOG-013 / LOG-021 / ADR-046(11): timestamp policy.
#[test]
fn timestamp_policy() {
    let (mut log, _sink, _c) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let staff = log.emit(EventContext::staff(user(1)), opened(1)).unwrap().record;
    assert_eq!(ts_of(&staff), T0, "staff actions exact to the ms");
    let imp = log
        .emit(
            EventContext::system(Service::Relay),
            AuditEvent::CaseImported {
                case: CaseRef::from_bytes([1; 16]),
                channel_id: ChannelId::from_bytes([2; 16]),
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
                case: CaseRef::from_bytes([1; 16]),
                evid: EvidRef::from_bytes([3; 16]),
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
                case: CaseRef::from_bytes([1; 16]),
                timer_id: TimerId::from_bytes([4; 16]),
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
                slots_ok: SmallCount(4),
                slots_failed: SmallCount(0),
                slots_overrun: SmallCount(0),
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
        log.emit(EventContext::staff(user(1)), opened(1)).unwrap_err(),
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
    let a = log.emit(EventContext::staff(user(1)), login()).unwrap().record;
    assert_eq!(ts_of(&a) % MS_PER_HOUR, 0);
    assert!(log
        .emit(
            EventContext::system(Service::Relay),
            AuditEvent::SysRelaySlotOverrun {
                date: DayStamp(1),
                slot_index: candor_log::field::SlotIndex(1)
            }
        )
        .is_err());
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
    let (mut log, sink, _c) = log_with(HostRole::Core, CheckpointPolicy::new(7, 300_000).unwrap());
    let samples = AuditEvent::samples();
    assert_eq!(samples.len(), candor_log::CATALOG.len());
    for e in samples {
        let names = e.field_names();
        let r = log.emit(EventContext::staff(user(1)), e).unwrap().record;
        let v = cbor::decode(r.bytes()).unwrap();
        assert_eq!(cbor::encode(&v).unwrap(), r.bytes());
        let cbor::Value::Map(payload) = v.get("payload").unwrap() else { panic!() };
        // Payload keys ⊆ schema.
        for (k, _) in payload {
            assert!(names.contains(&k.as_text().unwrap()));
        }
    }
    let st = sink.0.lock().unwrap();
    for s in [StreamId::Sec, StreamId::Case, StreamId::Sys] {
        verify_stream(&params(&log.verifying_key(), s), &st.chain(s), &st.checkpoints(s)).unwrap();
    }
}

// AUD-012: per-case redaction keeps the chain verifiable.
#[test]
fn case_disposal_redaction_verifies() {
    let (mut log, sink, _c) = log_with(HostRole::Core, CheckpointPolicy::new(4, 300_000).unwrap());
    for i in 0..9 {
        log.emit(EventContext::staff(user(1)), opened(i % 3)).unwrap();
    }
    let target = CaseRef::from_bytes([1; 16]);
    let removed = sink.0.lock().unwrap().redact_case(target);
    assert_eq!(removed, 3);
    log.emit(
        EventContext::staff(user(1)),
        AuditEvent::CaseDisposed {
            case: target,
            receipt_id: ReceiptId::from_bytes([5; 16]),
            removed_event_count: Count(removed),
        },
    )
    .unwrap();
    let st = sink.0.lock().unwrap();
    assert!(st
        .records(StreamId::Case)
        .iter()
        .filter(|r| !matches!(r.event(), AuditEvent::CaseDisposed { .. }))
        .all(|r| r.event().case_ref() != Some(target)));
    let rep = verify_stream(
        &params(&log.verifying_key(), StreamId::Case),
        &st.chain(StreamId::Case),
        &st.checkpoints(StreamId::Case),
    )
    .unwrap();
    assert_eq!(rep.redacted, 3);
    // Tampering with a stub is detected.
    let mut recs = st.chain(StreamId::Case);
    let pos = recs.iter().position(|r| matches!(r, ChainRecord::Redacted { .. })).unwrap();
    if let ChainRecord::Redacted { leaf, .. } = &mut recs[pos] {
        leaf[0] ^= 1;
    }
    let err = verify_stream(
        &params(&log.verifying_key(), StreamId::Case),
        &recs,
        &st.checkpoints(StreamId::Case),
    )
    .unwrap_err();
    assert_eq!(err.code, VerifyFailureCode::MerkleMismatch);
}

// AUD-005: whole-interval retention with tombstone; remaining chain verifies.
#[test]
fn retention_interval_deletion() {
    let (mut log, sink, clock) = log_with(HostRole::Core, CheckpointPolicy::new(5, 300_000).unwrap());
    for _ in 0..10 {
        log.emit(EventContext::staff(user(1)), login()).unwrap();
    }
    clock.advance(31 * MS_PER_DAY);
    for _ in 0..3 {
        log.emit(
            EventContext::system(Service::Health),
            AuditEvent::SysJob {
                job_kind: JobKind::Retention,
                outcome: Outcome::Ok,
            },
        )
        .unwrap();
    }
    let policy = RetentionPolicy::new(90, 7, 365, 13).unwrap();
    // SECURITY: nothing older than 90 days yet.
    let cps = sink.0.lock().unwrap().checkpoints(StreamId::Sec);
    assert!(retention::plan_interval_deletion(&policy, StreamId::Sec, &cps, 0, UtcMillis(T0 + 31 * MS_PER_DAY))
        .unwrap()
        .is_none());
    clock.advance(60 * MS_PER_DAY);
    let now = UtcMillis(T0 + 91 * MS_PER_DAY);
    let plan = retention::plan_interval_deletion(&policy, StreamId::Sec, &cps, 0, now)
        .unwrap()
        .unwrap();
    assert_eq!(plan.range.last, 9);
    // Without a tombstone, deletion is refused.
    let unrelated = log.emit(EventContext::staff(user(1)), login()).unwrap().record;
    assert!(retention::apply_interval_deletion(&mut sink.0.lock().unwrap(), &plan, &unrelated).is_err());
    let tomb = log
        .emit(EventContext::system(Service::Audit), plan.tombstone())
        .unwrap()
        .record;
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

// JSONL sink round trip and tamper detection through the file format.
#[test]
fn jsonl_round_trip() {
    let (mut log, _sink, _c) = log_with(HostRole::Core, CheckpointPolicy::new(3, 300_000).unwrap());
    let jsonl = SharedJsonl::default();
    log.add_sink(Box::new(jsonl.clone()));
    for i in 0..7 {
        log.emit(EventContext::staff(user(1)), opened(i)).unwrap();
    }
    let mem: MemoryJsonl = jsonl.0.lock().unwrap().clone();
    let recs_txt = mem.contents(JsonlFile::Records(StreamId::Case)).to_vec();
    let cps_txt = mem.contents(JsonlFile::Checkpoints(StreamId::Case)).to_vec();
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
    let (recs, cps) = read_stream(StreamId::Case, tampered.as_bytes(), cps_txt.as_slice()).unwrap();
    assert!(verify_stream(&params(&key, StreamId::Case), &recs, &cps).is_err());
    // Unknown fields / garbage rejected.
    assert!(read_stream(StreamId::Case, &b"{\"k\":\"rec\",\"x\":1}\n"[..], &b""[..]).is_err());
    assert!(read_stream(StreamId::Case, &b"not json\n"[..], &b""[..]).is_err());
}

#[test]
fn resume_continues_chain() {
    let (mut log, sink, _c) = log_with(HostRole::Core, CheckpointPolicy::new(4, 300_000).unwrap());
    for i in 0..6 {
        log.emit(EventContext::staff(user(1)), opened(i)).unwrap();
    }
    let (recs, cps) = {
        let st = sink.0.lock().unwrap();
        (st.chain(StreamId::Case), st.checkpoints(StreamId::Case))
    };
    let key = log.verifying_key();
    let rep = verify_stream(&params(&key, StreamId::Case), &recs, &cps).unwrap();
    // A fresh writer (restart) resumes from the verified state.
    let (mut log2, sink2, _c2) = log_with(HostRole::Core, CheckpointPolicy::new(4, 300_000).unwrap());
    log2.resume(StreamId::Case, rep.resume());
    for i in 6..10 {
        log2.emit(EventContext::staff(user(1)), opened(i)).unwrap();
    }
    let st2 = sink2.0.lock().unwrap();
    let mut all = recs;
    all.extend(st2.chain(StreamId::Case));
    let mut all_cps = cps;
    all_cps.extend(st2.checkpoints(StreamId::Case));
    let rep = verify_stream(&params(&key, StreamId::Case), &all, &all_cps).unwrap();
    assert_eq!(rep.records, 10);
}
