// SPDX-License-Identifier: AGPL-3.0-or-later
//! The common event envelope (20 §4) and timestamp policy.

use crate::cbor::{MapBuilder, Value};
use crate::codes::{ErrorReason, HostRole, Outcome, Service, StreamId};
use crate::event::{AuditEvent, EventClass, TimePolicy};
use crate::field::AuditField;
use crate::ids::{DeviceKeyId, PersonRef, SessionTag, TenantRef, UserRef, UtcMillis};

/// Envelope version.
pub const ENVELOPE_VERSION: u64 = 1;

/// Who performed the action. There is no source variant: sources are never
/// actors (20 §4 "never a source identifier").
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Actor {
    /// A staff user.
    Staff(UserRef),
    /// A service (`system:<service>`).
    System(Service),
}

impl Actor {
    /// Envelope value: staff → 16-byte ID; system → text `system:<service>`.
    pub fn to_value(&self) -> Value {
        match self {
            Self::Staff(u) => u.to_value(),
            Self::System(s) => Value::Text(format!("system:{}", s.code())),
        }
    }
}

/// Caller-supplied envelope context. `ts`, `seq`, `prev`, `stream`,
/// `tenant` and `host_role` are set by the log, never by the caller.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EventContext {
    /// Actor.
    pub actor: Actor,
    /// Person reference (dual-control/COI accountability), staff only.
    pub actor_person: Option<PersonRef>,
    /// Salted truncated session hash, staff only (LOG-012).
    pub session: Option<SessionTag>,
    /// Desk device key ID, staff only.
    pub device: Option<DeviceKeyId>,
    /// Outcome.
    pub outcome: Outcome,
    /// Error reason, only with `Outcome::Error`.
    pub reason: Option<ErrorReason>,
}

impl EventContext {
    /// Successful staff action.
    pub fn staff(user: UserRef) -> Self {
        Self {
            actor: Actor::Staff(user),
            actor_person: None,
            session: None,
            device: None,
            outcome: Outcome::Ok,
            reason: None,
        }
    }

    /// Successful system action.
    pub fn system(service: Service) -> Self {
        Self {
            actor: Actor::System(service),
            actor_person: None,
            session: None,
            device: None,
            outcome: Outcome::Ok,
            reason: None,
        }
    }

    /// Builder: outcome.
    pub fn with_outcome(mut self, outcome: Outcome) -> Self {
        self.outcome = outcome;
        self
    }
}

/// Envelope validation errors.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EnvelopeError {
    /// Staff-only fields set on a system actor.
    StaffFieldsOnSystemActor,
    /// `reason` set without `outcome = ERROR`.
    ReasonWithoutError,
    /// Event not permitted on this host role (Z-INTAKE: no CASE events, 20 §3).
    NotAllowedOnHost,
}

impl EventContext {
    pub(crate) fn validate(&self) -> Result<(), EnvelopeError> {
        if matches!(self.actor, Actor::System(_))
            && (self.actor_person.is_some() || self.session.is_some() || self.device.is_some())
        {
            return Err(EnvelopeError::StaffFieldsOnSystemActor);
        }
        if self.reason.is_some() && self.outcome != Outcome::Error {
            return Err(EnvelopeError::ReasonWithoutError);
        }
        Ok(())
    }
}

/// Timestamp precision actually applied to an envelope.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TsPrecision {
    /// Millisecond (staff actions).
    Millis,
    /// Second.
    Second,
    /// Hour (Z-INTAKE).
    Hour,
    /// UTC date only (`DayDate`).
    Day,
}

/// Apply 20 §4 / §6.2 timestamp rules.
pub fn ts_precision(event: &AuditEvent, actor: &Actor, host: HostRole) -> TsPrecision {
    let p = match (event.time_policy(), actor) {
        (TimePolicy::DateOnly, _) => TsPrecision::Day,
        (TimePolicy::Staff, Actor::Staff(_)) => TsPrecision::Millis,
        (TimePolicy::Staff, Actor::System(_)) => match event.class() {
            EventClass::Case => TsPrecision::Day,
            _ => TsPrecision::Second,
        },
        (TimePolicy::System, _) => TsPrecision::Second,
    };
    if host == HostRole::Intake && p != TsPrecision::Day {
        // Z-INTAKE: truncated to the hour (20 §6.2, LOG-004).
        TsPrecision::Hour
    } else {
        p
    }
}

/// Truncate `now` to `p`.
pub fn truncate(now: UtcMillis, p: TsPrecision) -> UtcMillis {
    match p {
        TsPrecision::Millis => now,
        TsPrecision::Second => now.to_second(),
        TsPrecision::Hour => now.to_hour(),
        TsPrecision::Day => now.day().start(),
    }
}

/// Fully-resolved envelope header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EnvelopeHeader {
    /// Stream.
    pub stream: StreamId,
    /// Sequence number.
    pub seq: u64,
    /// Truncated timestamp.
    pub ts: UtcMillis,
    /// Precision applied.
    pub precision: TsPrecision,
    /// Tenant.
    pub tenant: TenantRef,
    /// Host role.
    pub host_role: HostRole,
    /// Caller context.
    pub ctx: EventContext,
    /// Previous chain hash `h_{i-1}`.
    pub prev: [u8; 32],
}

/// Build the canonical envelope value.
pub fn envelope_value(h: &EnvelopeHeader, event: &AuditEvent) -> Value {
    let mut m = MapBuilder::new();
    m.put("v", Value::Uint(ENVELOPE_VERSION))
        .put("stream", h.stream.to_value())
        .put("seq", Value::Uint(h.seq))
        .put("type", Value::text(event.type_name()))
        .put("ts", Value::Uint(h.ts.0))
        .put("tenant", h.tenant.to_value())
        .put("host_role", h.host_role.to_value())
        .put("actor", h.ctx.actor.to_value())
        .put_opt("actor_person", h.ctx.actor_person.map(|p| p.to_value()))
        .put_opt("session", h.ctx.session.map(|s| s.to_value()))
        .put_opt("device", h.ctx.device.map(|d| d.to_value()))
        .put("outcome", h.ctx.outcome.to_value())
        .put_opt("reason", h.ctx.reason.map(|r| r.to_value()))
        .put("payload", event.payload())
        .put("prev", Value::Bytes(h.prev.to_vec()));
    m.build()
}
