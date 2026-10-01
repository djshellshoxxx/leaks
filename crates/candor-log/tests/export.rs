// SPDX-License-Identifier: AGPL-3.0-or-later
//! C-26 SIEM allow-list replay (AUD-010, LOG-020, LOG-022, TEL-018).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::collections::BTreeSet;

use candor_log::codes::*;
use candor_log::export::*;
use candor_log::ids::UtcMillis;
use candor_log::verify::{VerifyParams, verify_stream};
use candor_log::{AuditEvent, AuditLog, CheckpointPolicy, EventContext, LogError, SoftwareSigner};
use common::*;

/// A real `audit.verification_failed` (its `seq` must come from a
/// verification under the log's own key, AUD-RM1-LOG-17).
fn verification_failed(log: &AuditLog<SoftwareSigner, TestClock>) -> AuditEvent {
    let key = log.verifying_key();
    let p = VerifyParams {
        tenant: tenant(),
        stream: StreamId::Sec,
        key: &key,
        approver_keys: approver_keys(),
        trusted_latest: None,
        allow_pruned_prefix: false,
        min_retention_days: None,
    };
    let bogus = candor_log::chain::ChainRecord::Full {
        bytes: vec![0xff],
        salt: [0; 32],
        claimed_hash: None,
    };
    let e = verify_stream(&p, &[bogus], &[]).unwrap_err();
    AuditEvent::AuditVerificationFailed {
        stream: StreamId::Sec,
        seq: candor_log::field::Seq::of_failure(&e),
        failure_code: e.code,
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn allowed_keys(ty: &str) -> &'static [&'static str] {
    match ty {
        "auth.login_succeeded" => &[
            "type", "date", "tenant", "actor", "method", "aal", "outcome",
        ],
        "auth.login_failed" => &[
            "type",
            "date",
            "tenant",
            "actor",
            "method",
            "outcome",
            "failure_code",
        ],
        "auth.stepup_failed" => &["type", "date", "actor"],
        t if t.starts_with("user.") => &["type", "date", "actor", "target"],
        t if t.starts_with("role.") => &["type", "date", "actor", "target", "role"],
        "authz.denied" => &["type", "date", "actor", "action", "reason_code"],
        t if t.starts_with("cfg.") => &["type", "ts", "actor", "key", "class"],
        "audit.verification_failed" | "audit.witness_failed" => {
            &["type", "ts", "stream", "failure_code"]
        }
        "selftest.logging_violation" | "secret.placement_violation" => {
            &["type", "ts", "host_role", "check_code"]
        }
        t if t.starts_with("update.") => &["type", "date", "component", "outcome"],
        t if t.starts_with("backup.") => &["type", "date", "backup_id", "outcome"],
        "sys.health_band" => &["type", "date", "service", "band"],
        t if t.starts_with("breakglass.") => &["type", "date", "reason_code", "count"],
        _ => &[],
    }
}

#[test]
fn full_catalog_replay_respects_allow_list() {
    let (mut log, sink, clock) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let mut exp = ScrubbedExport::new(
        SiemKey::new([9; 32]),
        ExportPrecision::Date,
        ExportProfile::Standard,
    )
    .unwrap();
    let mut out = Vec::new();
    let mut case_events = 0;
    let mut day = None;
    let mut samples = AuditEvent::samples();
    samples.push(verification_failed(&log));
    for e in samples {
        match log.emit(EventContext::staff(user(0x5a)), e) {
            Ok(_) | Err(LogError::TombstoneViaApi | LogError::ForeignArtefact) => {}
            Err(e) => panic!("{e:?}"),
        }
    }
    // Flush the date-only slot streams, then replay every stored record.
    clock.advance(6 * 3_600_000);
    log.tick().unwrap();
    let st = sink.0.lock().unwrap().clone();
    for s in [
        StreamId::Sec,
        StreamId::Case,
        StreamId::Sys,
        StreamId::CaseSlot,
        StreamId::SysSlot,
    ] {
        for rec in st.records(s) {
            day.get_or_insert(rec.header().ts.day());
            let is_case = matches!(rec.header().stream, StreamId::Case | StreamId::CaseSlot);
            match exp.ingest(&rec) {
                Disposition::Immediate(l) => out.push(l),
                Disposition::Batched => assert!(!is_case),
                Disposition::Dropped => {
                    if is_case {
                        case_events += 1;
                    }
                }
            }
        }
    }
    out.extend(exp.close_day(day.unwrap()));
    assert!(case_events > 40, "all CASE events dropped");
    let user_hex = hex(user(0x5a).as_bytes());
    let case_hex = "5a".repeat(16);
    for l in &out {
        let v: serde_json::Value = serde_json::from_str(&l.0).unwrap();
        let obj = v.as_object().unwrap();
        let ty = obj["type"].as_str().unwrap();
        let allowed: BTreeSet<&str> = allowed_keys(ty).iter().copied().collect();
        assert!(!allowed.is_empty(), "unexpected exported type {ty}");
        for k in obj.keys() {
            assert!(
                allowed.contains(k.as_str()),
                "{ty}: field {k} not allow-listed"
            );
        }
        // No raw UserRef/CaseRef, no COI code, date-only staff times.
        // (backup_id is an allow-listed opaque ID that shares the sample bytes.)
        if !ty.starts_with("backup.") {
            assert!(
                !l.0.contains(&user_hex) && !l.0.contains(&case_hex),
                "{l:?}"
            );
        }
        assert!(!l.0.contains("COI"));
        if let Some(d) = obj.get("date") {
            assert_eq!(d.as_str().unwrap().len(), 10);
        }
        if let Some(t) = obj.get("ts") {
            assert!(
                t.as_str().unwrap().ends_with(":00Z"),
                "ts coarsened to the hour"
            );
        }
        assert!(!ty.starts_with("sys.") || ty == "sys.health_band");
    }
    // Integrity alarms are among the immediate lines.
    assert!(
        out.iter()
            .any(|l| l.0.contains("audit.verification_failed"))
    );
}

#[test]
fn pseudonyms_are_per_destination_and_stable() {
    let (mut log, _sink, _c) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let rec = log
        .emit(
            EventContext::staff(user(3)),
            AuditEvent::AuthzDenied {
                action: Code::of::<4>(),
                resource_kind: Code::of::<1>(),
                reason_code: AuthzDenyReason::NoRelation,
            },
        )
        .unwrap()
        .record
        .unwrap();
    let line = |key: u8| {
        let mut e = ScrubbedExport::new(
            SiemKey::new([key; 32]),
            ExportPrecision::Date,
            ExportProfile::Standard,
        )
        .unwrap();
        assert_eq!(e.ingest(&rec), Disposition::Batched);
        e.close_day(rec.header().ts.day()).remove(0).0
    };
    assert_eq!(line(1), line(1));
    assert_ne!(line(1), line(2));
    let v: serde_json::Value = serde_json::from_str(&line(1)).unwrap();
    assert_eq!(v["actor"].as_str().unwrap().len(), 16, "64-bit pseudonym");
    assert_eq!(v["reason_code"], "NO_RELATION");
    assert!(
        v.get("resource_kind").is_none(),
        "no resource in SIEM export"
    );
}

#[test]
fn breakglass_and_health_aggregated_daily() {
    let (mut log, sink, clock) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let mut e = ScrubbedExport::new(
        SiemKey::new([1; 32]),
        ExportPrecision::Date,
        ExportProfile::Standard,
    )
    .unwrap();
    for _ in 0..3 {
        let r = log
            .emit(
                EventContext::staff(user(1)),
                AuditEvent::BreakglassRequested {
                    case: case(7),
                    reason_code: Code::of::<2>(),
                    duration_min: candor_log::field::DurationMin::new(60).unwrap(),
                    review_outcome: None,
                },
            )
            .unwrap()
            .record
            .unwrap();
        assert_eq!(e.ingest(&r), Disposition::Batched);
    }
    for st in [HealthStatus::Ok, HealthStatus::Degraded, HealthStatus::Ok] {
        let r = log
            .emit(
                EventContext::system(Service::Health),
                AuditEvent::SysHealth {
                    service: Service::Web,
                    status: st,
                    check_code: HealthCheck::Liveness,
                },
            )
            .unwrap()
            .record
            .unwrap();
        e.ingest(&r);
        clock.advance(1000);
    }
    // Source-load-derived detectors and relay/capacity events never export
    // (and are staged for the date-only `sys-slot` stream, AUD-RM1-LOG-02).
    let staged = log
        .emit(
            EventContext::system(Service::Health),
            AuditEvent::SysHealth {
                service: Service::Upload,
                status: HealthStatus::Down,
                check_code: HealthCheck::AbuseFlood,
            },
        )
        .unwrap();
    assert!(staged.record.is_none());
    clock.advance(6 * 3_600_000);
    log.tick().unwrap();
    let r = sink.0.lock().unwrap().records(StreamId::SysSlot).remove(0);
    assert_eq!(e.ingest(&r), Disposition::Dropped);
    let lines = e.close_day(UtcMillis(T0).day());
    assert_eq!(lines.len(), 2);
    assert!(
        lines
            .iter()
            .any(|l| l.0.contains("\"band\":\"DEGRADED\"") && l.0.contains("\"service\":\"web\""))
    );
    assert!(
        lines
            .iter()
            .any(|l| l.0.contains("\"count\":3") && !l.0.contains(&hex(case(7).as_bytes())))
    );
    assert!(!lines.iter().any(|l| l.0.contains("upload")));
}

#[test]
fn precision_and_profiles() {
    assert!(
        ScrubbedExport::new(
            SiemKey::new([1; 32]),
            ExportPrecision::Exact,
            ExportProfile::HighOrGov
        )
        .is_err()
    );
    let (mut log, _sink, _c) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let failed = verification_failed(&log);
    let rec = log
        .emit(EventContext::system(Service::Audit), failed)
        .unwrap()
        .record
        .unwrap();
    // HIGH/GOV: even alarms are batched daily.
    let mut e = ScrubbedExport::new(
        SiemKey::new([1; 32]),
        ExportPrecision::Hour,
        ExportProfile::HighOrGov,
    )
    .unwrap();
    assert_eq!(e.ingest(&rec), Disposition::Batched);
    let mut e = ScrubbedExport::new(
        SiemKey::new([1; 32]),
        ExportPrecision::Date,
        ExportProfile::Standard,
    )
    .unwrap();
    assert!(matches!(e.ingest(&rec), Disposition::Immediate(_)));
    // Exact (DANGEROUS) keeps milliseconds for staff dates.
    let login = log
        .emit(
            EventContext::staff(user(1)),
            AuditEvent::AuthLoginFailed {
                method: AuthMethod::Totp,
                failure_code: LoginFailure::UvMissing,
                audience: Audience::AdminApi,
            },
        )
        .unwrap()
        .record
        .unwrap();
    let mut e = ScrubbedExport::new(
        SiemKey::new([1; 32]),
        ExportPrecision::Exact,
        ExportProfile::Standard,
    )
    .unwrap();
    e.ingest(&login);
    let l = e.close_day(login.header().ts.day()).remove(0).0;
    assert!(l.contains("T13:37:42.123Z"), "{l}");
}
