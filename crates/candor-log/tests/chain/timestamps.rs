// SPDX-License-Identifier: AGPL-3.0-or-later
//! Timestamp policy, date-only neighbour rules and Z-INTAKE host truncation
//! (LOG-013, LOG-021, ADR-046(11), AUD-RM1-LOG-02).

use super::support::*;

use crate::common::*;
use candor_log::codes::*;
use candor_log::envelope::EnvelopeError;
use candor_log::field::{SlotIndex, SmallCount};
use candor_log::ids::*;
use candor_log::verify::verify_stream;
use candor_log::{AuditEvent, CheckpointPolicy, CommittedRecord, EventContext, LogError};

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
    assert!(
        case_recs
            .iter()
            .all(|r| !precision_of(r).is_multiple_of(DAY))
    );
    assert!(
        slot_recs
            .iter()
            .all(|r| precision_of(r).is_multiple_of(DAY))
    );
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
