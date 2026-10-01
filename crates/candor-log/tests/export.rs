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
use candor_log::ids::{CaseRef, UtcMillis};
use candor_log::{AuditEvent, CheckpointPolicy, EventContext};
use common::*;

fn allowed_keys(ty: &str) -> &'static [&'static str] {
    match ty {
        "auth.login_succeeded" => &["type", "date", "tenant", "actor", "method", "aal", "outcome"],
        "auth.login_failed" => &["type", "date", "tenant", "actor", "method", "outcome", "failure_code"],
        "auth.stepup_failed" => &["type", "date", "actor"],
        t if t.starts_with("user.") => &["type", "date", "actor", "target"],
        t if t.starts_with("role.") => &["type", "date", "actor", "target", "role"],
        "authz.denied" => &["type", "date", "actor", "action", "reason_code"],
        t if t.starts_with("cfg.") => &["type", "ts", "actor", "key", "class"],
        "audit.verification_failed" | "audit.witness_failed" => &["type", "ts", "stream", "failure_code"],
        "selftest.logging_violation" | "secret.placement_violation" => &["type", "ts", "host_role", "check_code"],
        t if t.starts_with("update.") => &["type", "date", "component", "outcome"],
        t if t.starts_with("backup.") => &["type", "date", "backup_id", "outcome"],
        "sys.health_band" => &["type", "date", "service", "band"],
        t if t.starts_with("breakglass.") => &["type", "date", "reason_code", "count"],
        _ => &[],
    }
}

#[test]
fn full_catalog_replay_respects_allow_list() {
    let (mut log, _sink, _c) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let mut exp = ScrubbedExport::new(SiemKey::new([9; 32]), ExportPrecision::Date, ExportProfile::Standard).unwrap();
    let mut out = Vec::new();
    let mut case_events = 0;
    let mut day = None;
    for e in AuditEvent::samples() {
        let rec = log.emit(EventContext::staff(user(0x5a)), e).unwrap().record;
        day = Some(rec.header().ts.day());
        let is_case = rec.header().stream == StreamId::Case;
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
    out.extend(exp.close_day(day.unwrap()));
    assert!(case_events > 40, "all CASE events dropped");
    let user_hex = "5a".repeat(16);
    let case_hex = "5a".repeat(16);
    for l in &out {
        let v: serde_json::Value = serde_json::from_str(&l.0).unwrap();
        let obj = v.as_object().unwrap();
        let ty = obj["type"].as_str().unwrap();
        let allowed: BTreeSet<&str> = allowed_keys(ty).iter().copied().collect();
        assert!(!allowed.is_empty(), "unexpected exported type {ty}");
        for k in obj.keys() {
            assert!(allowed.contains(k.as_str()), "{ty}: field {k} not allow-listed");
        }
        // No raw UserRef/CaseRef, no COI code, date-only staff times.
        assert!(!l.0.contains(&user_hex) && !l.0.contains(&case_hex));
        assert!(!l.0.contains("COI"));
        if let Some(d) = obj.get("date") {
            assert_eq!(d.as_str().unwrap().len(), 10);
        }
        if let Some(t) = obj.get("ts") {
            assert!(t.as_str().unwrap().ends_with(":00Z"), "ts coarsened to the hour");
        }
        assert!(!ty.starts_with("sys.") || ty == "sys.health_band");
    }
    // Integrity alarms are among the immediate lines.
    assert!(out.iter().any(|l| l.0.contains("audit.verification_failed")));
}

#[test]
fn pseudonyms_are_per_destination_and_stable() {
    let (mut log, _sink, _c) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let rec = log
        .emit(
            EventContext::staff(user(3)),
            AuditEvent::AuthzDenied {
                action: Code::new(4),
                resource_kind: Code::new(1),
                reason_code: AuthzDenyReason::NoRelation,
            },
        )
        .unwrap()
        .record;
    let line = |key: u8| {
        let mut e = ScrubbedExport::new(SiemKey::new([key; 32]), ExportPrecision::Date, ExportProfile::Standard).unwrap();
        assert_eq!(e.ingest(&rec), Disposition::Batched);
        e.close_day(rec.header().ts.day()).remove(0).0
    };
    assert_eq!(line(1), line(1));
    assert_ne!(line(1), line(2));
    let v: serde_json::Value = serde_json::from_str(&line(1)).unwrap();
    assert_eq!(v["actor"].as_str().unwrap().len(), 16, "64-bit pseudonym");
    assert_eq!(v["reason_code"], "NO_RELATION");
    assert!(v.get("resource_kind").is_none(), "no resource in SIEM export");
}

#[test]
fn breakglass_and_health_aggregated_daily() {
    let (mut log, _sink, clock) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let mut e = ScrubbedExport::new(SiemKey::new([1; 32]), ExportPrecision::Date, ExportProfile::Standard).unwrap();
    for _ in 0..3 {
        let r = log
            .emit(
                EventContext::staff(user(1)),
                AuditEvent::BreakglassRequested {
                    case: CaseRef::from_bytes([7; 16]),
                    reason_code: Code::new(2),
                    duration_min: candor_log::field::DurationMin(60),
                    review_outcome: None,
                },
            )
            .unwrap()
            .record;
        assert_eq!(e.ingest(&r), Disposition::Batched);
    }
    for st in [HealthStatus::Ok, HealthStatus::Degraded, HealthStatus::Ok] {
        let r = log
            .emit(
                EventContext::system(Service::Health),
                AuditEvent::SysHealth { service: Service::Web, status: st, check_code: HealthCheck::Liveness },
            )
            .unwrap()
            .record;
        e.ingest(&r);
        clock.advance(1000);
    }
    // Source-load-derived detectors and relay/capacity events never export.
    let r = log
        .emit(
            EventContext::system(Service::Health),
            AuditEvent::SysHealth { service: Service::Upload, status: HealthStatus::Down, check_code: HealthCheck::AbuseFlood },
        )
        .unwrap()
        .record;
    assert_eq!(e.ingest(&r), Disposition::Dropped);
    let lines = e.close_day(UtcMillis(T0).day());
    assert_eq!(lines.len(), 2);
    assert!(lines.iter().any(|l| l.0.contains("\"band\":\"DEGRADED\"") && l.0.contains("\"service\":\"web\"")));
    assert!(lines.iter().any(|l| l.0.contains("\"count\":3") && !l.0.contains(&"07".repeat(16))));
    assert!(!lines.iter().any(|l| l.0.contains("upload")));
}

#[test]
fn precision_and_profiles() {
    assert!(ScrubbedExport::new(SiemKey::new([1; 32]), ExportPrecision::Exact, ExportProfile::HighOrGov).is_err());
    let (mut log, _sink, _c) = log_with(HostRole::Core, CheckpointPolicy::DEFAULT);
    let rec = log
        .emit(
            EventContext::system(Service::Audit),
            AuditEvent::AuditVerificationFailed {
                stream: StreamId::Case,
                seq: candor_log::field::Seq(4),
                failure_code: VerifyFailureCode::ChainMismatch,
            },
        )
        .unwrap()
        .record;
    // HIGH/GOV: even alarms are batched daily.
    let mut e = ScrubbedExport::new(SiemKey::new([1; 32]), ExportPrecision::Hour, ExportProfile::HighOrGov).unwrap();
    assert_eq!(e.ingest(&rec), Disposition::Batched);
    let mut e = ScrubbedExport::new(SiemKey::new([1; 32]), ExportPrecision::Date, ExportProfile::Standard).unwrap();
    assert!(matches!(e.ingest(&rec), Disposition::Immediate(_)));
    // Exact (DANGEROUS) keeps milliseconds for staff dates.
    let login = log
        .emit(
            EventContext::staff(user(1)),
            AuditEvent::AuthLoginFailed { method: AuthMethod::Totp, failure_code: LoginFailure::UvMissing, audience: Audience::AdminApi },
        )
        .unwrap()
        .record;
    let mut e = ScrubbedExport::new(SiemKey::new([1; 32]), ExportPrecision::Exact, ExportProfile::Standard).unwrap();
    e.ingest(&login);
    let l = e.close_day(login.header().ts.day()).remove(0).0;
    assert!(l.contains("T13:37:42.123Z"), "{l}");
}
