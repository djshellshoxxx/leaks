// SPDX-License-Identifier: AGPL-3.0-or-later
//! `ScrubbedExport`: the C-26 SIEM allow-list (20 §13, AUD-010, LOG-022).
//!
//! * Only SECURITY and SYSTEM events; CASE events are always dropped.
//! * Per-type field allow-list; everything else dropped.
//! * Actors/targets as `HMAC-SHA-256(K_siem, "candor/v1/siem/actor" ‖ UserRef)`
//!   truncated to 64 bits (per destination key).
//! * Staff-event `date` fields are UTC dates by default (hour = ADVANCED,
//!   exact = DANGEROUS; HIGH/GOV never finer than one hour).
//! * SYSTEM only as one global daily health band per service; break-glass
//!   only as daily counts per reason code.
//! * Daily batches, except integrity alarms (sent on occurrence outside
//!   HIGH/GOV).

use std::collections::BTreeMap;

use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Map, Value as J};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::chain::CommittedRecord;
use crate::codes::{HealthCheck, HealthStatus, Service, StreamId};
use crate::envelope::Actor;
use crate::event::AuditEvent;
use crate::ids::{DayStamp, MS_PER_HOUR, UserRef, UtcMillis, hex};

/// Timestamp precision of exported staff events.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub enum ExportPrecision {
    /// UTC date (default, SAFE).
    #[default]
    Date,
    /// Hour (ADVANCED).
    Hour,
    /// Exact (DANGEROUS, dual control DC-09).
    Exact,
}

/// Deployment profile class relevant to export.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ExportProfile {
    /// Standard profiles.
    #[default]
    Standard,
    /// HIGH and GOV: never finer than one hour; always daily batches (03 META-035).
    HighOrGov,
}

/// Per-destination pseudonymisation key `K_siem` (rotated yearly). No `Debug`.
#[allow(missing_debug_implementations)] // deliberate: secret
pub struct SiemKey(Zeroizing<[u8; 32]>);

impl SiemKey {
    /// Wrap a key.
    pub fn new(k: [u8; 32]) -> Self {
        Self(Zeroizing::new(k))
    }
}

/// Configuration errors.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExportConfigError {
    /// Exact precision is not available in HIGH/GOV.
    PrecisionNotAvailable,
}

/// One exported JSON line.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SiemLine(pub String);

/// What happened to an ingested record.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Disposition {
    /// Sent now (integrity alarm).
    Immediate(SiemLine),
    /// Queued for the daily batch.
    Batched,
    /// Not exportable.
    Dropped,
}

#[derive(Default)]
struct DayBatch {
    lines: Vec<SiemLine>,
    health: BTreeMap<Service, HealthStatus>,
    breakglass: BTreeMap<(&'static str, u16), u32>,
}

/// The C-26 scrubbing exporter.
#[allow(missing_debug_implementations)] // holds SiemKey
pub struct ScrubbedExport {
    key: SiemKey,
    precision: ExportPrecision,
    profile: ExportProfile,
    pending: BTreeMap<DayStamp, DayBatch>,
}

fn severity(s: HealthStatus) -> u8 {
    match s {
        HealthStatus::Ok => 0,
        HealthStatus::Degraded => 1,
        HealthStatus::Down => 2,
    }
}

fn iso_hour(t: UtcMillis) -> String {
    let h = (t.0 % crate::ids::MS_PER_DAY) / MS_PER_HOUR;
    format!("{}T{:02}:00Z", t.day().iso(), h)
}

fn iso_exact(t: UtcMillis) -> String {
    let ms = t.0 % crate::ids::MS_PER_DAY;
    format!(
        "{}T{:02}:{:02}:{:02}.{:03}Z",
        t.day().iso(),
        ms / MS_PER_HOUR,
        (ms / 60_000) % 60,
        (ms / 1000) % 60,
        ms % 1000
    )
}

fn s(v: &'static str) -> J {
    J::String(v.to_owned())
}

impl ScrubbedExport {
    /// New exporter; rejects precision the profile does not allow.
    pub fn new(
        key: SiemKey,
        precision: ExportPrecision,
        profile: ExportProfile,
    ) -> Result<Self, ExportConfigError> {
        if profile == ExportProfile::HighOrGov && precision == ExportPrecision::Exact {
            return Err(ExportConfigError::PrecisionNotAvailable);
        }
        Ok(Self {
            key,
            precision,
            profile,
            pending: BTreeMap::new(),
        })
    }

    fn pseudonym(&self, u: &UserRef) -> String {
        let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(self.key.0.as_slice()) else {
            return String::from("0000000000000000");
        };
        mac.update(b"candor/v1/siem/actor");
        mac.update(u.as_bytes());
        let out = mac.finalize().into_bytes();
        hex(out.get(..8).unwrap_or_default())
    }

    fn actor(&self, a: &Actor) -> J {
        match a {
            Actor::Staff(u) => J::String(self.pseudonym(u)),
            Actor::System(svc) => J::String(format!("system:{}", svc.code())),
        }
    }

    /// Staff-event date field per configured precision.
    fn date_field(&self, t: UtcMillis) -> J {
        J::String(match self.precision {
            ExportPrecision::Date => t.day().iso(),
            ExportPrecision::Hour => iso_hour(t),
            ExportPrecision::Exact => iso_exact(t),
        })
    }

    /// `ts` field (cfg/integrity events): hour unless exact is configured.
    fn ts_field(&self, t: UtcMillis) -> J {
        J::String(match self.precision {
            ExportPrecision::Exact => iso_exact(t),
            _ => iso_hour(t),
        })
    }

    /// Ingest one committed record.
    pub fn ingest(&mut self, r: &CommittedRecord) -> Disposition {
        let h = r.header();
        // CASE content never leaves (20 §13); the date-only slot streams
        // never reach the SIEM either (imports, relay, source-load health).
        if matches!(
            h.stream,
            StreamId::Case | StreamId::CaseSlot | StreamId::SysSlot
        ) {
            return Disposition::Dropped;
        }
        let day = h.ts.day();
        let mut m = Map::new();
        m.insert("type".into(), s(r.event().type_name()));
        let mut alarm = false;
        use AuditEvent as E;
        match r.event() {
            E::AuthLoginSucceeded { method, aal, .. } => {
                m.insert("date".into(), self.date_field(h.ts));
                m.insert("tenant".into(), J::String(hex(h.tenant.as_bytes())));
                m.insert("actor".into(), self.actor(&h.ctx.actor));
                m.insert("method".into(), s(method.code()));
                m.insert("aal".into(), s(aal.code()));
                m.insert("outcome".into(), s(h.ctx.outcome.code()));
            }
            E::AuthLoginFailed {
                method,
                failure_code,
                ..
            } => {
                m.insert("date".into(), self.date_field(h.ts));
                m.insert("tenant".into(), J::String(hex(h.tenant.as_bytes())));
                m.insert("actor".into(), self.actor(&h.ctx.actor));
                m.insert("method".into(), s(method.code()));
                m.insert("outcome".into(), s(h.ctx.outcome.code()));
                m.insert("failure_code".into(), s(failure_code.code()));
            }
            E::AuthStepupFailed { .. } => {
                m.insert("date".into(), self.date_field(h.ts));
                m.insert("actor".into(), self.actor(&h.ctx.actor));
            }
            E::UserCreated { target, .. }
            | E::UserSuspended { target, .. }
            | E::UserReactivated { target, .. }
            | E::UserSuspendedDormant { target, .. }
            | E::UserAuthenticatorCountLow { target }
            | E::UserEnrollmentApproved { target, .. } => {
                m.insert("date".into(), self.date_field(h.ts));
                m.insert("actor".into(), self.actor(&h.ctx.actor));
                m.insert("target".into(), J::String(self.pseudonym(target)));
            }
            E::RoleAssigned { target, role }
            | E::RoleRevoked { target, role }
            | E::RoleExpired { target, role } => {
                m.insert("date".into(), self.date_field(h.ts));
                m.insert("actor".into(), self.actor(&h.ctx.actor));
                m.insert("target".into(), J::String(self.pseudonym(target)));
                m.insert("role".into(), s(role.code()));
            }
            E::AuthzDenied {
                action,
                reason_code,
                ..
            } => {
                m.insert("date".into(), self.date_field(h.ts));
                m.insert("actor".into(), self.actor(&h.ctx.actor));
                m.insert("action".into(), J::from(action.get()));
                m.insert("reason_code".into(), s(reason_code.code()));
            }
            E::CfgChanged { key, class, .. } => {
                m.insert("ts".into(), self.ts_field(h.ts));
                m.insert("actor".into(), self.actor(&h.ctx.actor));
                m.insert("key".into(), J::from(key.get()));
                m.insert("class".into(), s(class.code()));
            }
            E::CfgDangerousEnabled { key, .. }
            | E::CfgDangerousDisabled { key, .. }
            | E::CfgDangerousExpired { key, .. } => {
                m.insert("ts".into(), self.ts_field(h.ts));
                m.insert("actor".into(), self.actor(&h.ctx.actor));
                m.insert("key".into(), J::from(key.get()));
                m.insert("class".into(), s("DANGEROUS"));
                alarm = true;
            }
            E::AuditVerificationFailed {
                stream,
                failure_code,
                ..
            } => {
                m.insert("ts".into(), self.ts_field(h.ts));
                m.insert("stream".into(), s(stream.code()));
                m.insert("failure_code".into(), s(failure_code.code()));
                alarm = true;
            }
            E::AuditWitnessFailed { .. } => {
                m.insert("ts".into(), self.ts_field(h.ts));
                m.insert("stream".into(), s(StreamId::Sec.code()));
                alarm = true;
            }
            E::SelftestLoggingViolation {
                host_role,
                check_code,
            } => {
                m.insert("ts".into(), self.ts_field(h.ts));
                m.insert("host_role".into(), s(host_role.code()));
                m.insert("check_code".into(), s(check_code.code()));
                alarm = true;
            }
            E::SecretPlacementViolation {
                host_role,
                secret_kind,
            } => {
                m.insert("ts".into(), self.ts_field(h.ts));
                m.insert("host_role".into(), s(host_role.code()));
                m.insert("check_code".into(), J::from(secret_kind.get()));
                alarm = true;
            }
            E::UpdateApplied { component, .. } | E::UpdateRejected { component, .. } => {
                m.insert("date".into(), J::String(day.iso()));
                m.insert("component".into(), s(component.code()));
                m.insert("outcome".into(), s(h.ctx.outcome.code()));
            }
            E::BackupCompleted { backup_id, .. } | E::BackupRestorePerformed { backup_id, .. } => {
                m.insert("date".into(), J::String(day.iso()));
                m.insert("backup_id".into(), J::String(hex(backup_id.as_bytes())));
                m.insert("outcome".into(), s(h.ctx.outcome.code()));
            }
            E::BreakglassRequested { reason_code, .. }
            | E::BreakglassApproved { reason_code, .. }
            | E::BreakglassExpired { reason_code, .. }
            | E::BreakglassReviewed { reason_code, .. }
            | E::BreakglassWrapRefused { reason_code, .. } => {
                let b = self.pending.entry(day).or_default();
                let c = b
                    .breakglass
                    .entry((r.event().type_name(), reason_code.get()))
                    .or_insert(0);
                *c = c.saturating_add(1);
                return Disposition::Batched;
            }
            E::SysHealth {
                service,
                status,
                check_code,
            } => {
                if check_code.is_source_load_derived() {
                    return Disposition::Dropped;
                }
                self.note_health(day, *service, *status);
                if *check_code != HealthCheck::InsecureDevOverride {
                    return Disposition::Batched;
                }
                // Insecure developer override: an integrity alarm of its
                // own (sealer C-2), besides the daily band.
                m.insert("ts".into(), self.ts_field(h.ts));
                m.insert("service".into(), s(service.code()));
                m.insert("check_code".into(), s(check_code.code()));
                alarm = true;
            }
            E::SysServiceCrashed { service, .. } => {
                self.note_health(day, *service, HealthStatus::Degraded);
                return Disposition::Batched;
            }
            _ => return Disposition::Dropped,
        }
        let line = SiemLine(J::Object(m).to_string());
        if alarm && self.profile == ExportProfile::Standard {
            Disposition::Immediate(line)
        } else {
            self.pending.entry(day).or_default().lines.push(line);
            Disposition::Batched
        }
    }

    fn note_health(&mut self, day: DayStamp, svc: Service, st: HealthStatus) {
        let b = self.pending.entry(day).or_default();
        let cur = b.health.entry(svc).or_insert(HealthStatus::Ok);
        if severity(st) > severity(*cur) {
            *cur = st;
        }
    }

    /// Close a UTC day: returns the daily batch (sent at a fixed tenant time).
    pub fn close_day(&mut self, day: DayStamp) -> Vec<SiemLine> {
        let Some(b) = self.pending.remove(&day) else {
            return Vec::new();
        };
        let mut out = b.lines;
        for (svc, st) in b.health {
            let mut m = Map::new();
            m.insert("type".into(), s("sys.health_band"));
            m.insert("date".into(), J::String(day.iso()));
            m.insert("service".into(), s(svc.code()));
            m.insert("band".into(), s(st.code()));
            out.push(SiemLine(J::Object(m).to_string()));
        }
        for ((ty, reason), n) in b.breakglass {
            let mut m = Map::new();
            m.insert("type".into(), s(ty));
            m.insert("date".into(), J::String(day.iso()));
            m.insert("reason_code".into(), J::from(reason));
            m.insert("count".into(), J::from(n));
            out.push(SiemLine(J::Object(m).to_string()));
        }
        out
    }
}
