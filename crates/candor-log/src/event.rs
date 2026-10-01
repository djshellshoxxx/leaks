// SPDX-License-Identifier: AGPL-3.0-or-later
//! The audit event catalog (20 §5.1–§5.3 and the §5.5 canonical types).
//!
//! One enum variant per catalog type, each with an explicit allow-listed
//! field schema built only from [`AuditField`] types. Payload keys are the
//! Rust field names; fields not listed here cannot be emitted (20 §5:
//! "Payload fields not listed are forbidden").

use core::any::Any;

use crate::cbor::{MapBuilder, Value};
use crate::codes::*;
use crate::field::*;
use crate::ids::*;

/// Event class (ADR-016). SOURCE-SENSITIVE has no events (see [`crate::metrics`]).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum EventClass {
    /// SECURITY → stream `sec`.
    Security,
    /// CASE → stream `case`.
    Case,
    /// SYSTEM → stream `sys`.
    System,
}

impl EventClass {
    /// The C-24 stream for this class.
    pub const fn stream(self) -> StreamId {
        match self {
            Self::Security => StreamId::Sec,
            Self::Case => StreamId::Case,
            Self::System => StreamId::Sys,
        }
    }
}

/// How the envelope `ts` of an event is derived from the audit clock
/// (20 §4, ADR-010, ADR-038(1), ADR-046(11)).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimePolicy {
    /// Staff action: millisecond for a staff actor; for a system actor,
    /// date-only in CASE and second in SECURITY.
    Staff,
    /// Always UTC date only (import-related, source- or schedule-caused).
    DateOnly,
    /// SYSTEM: second (hour on Z-INTAKE).
    System,
}

fn case_of(name: &str, v: &dyn Any) -> Option<CaseRef> {
    if name != "case" && name != "subject" {
        return None;
    }
    if let Some(c) = v.downcast_ref::<CaseRef>() {
        return Some(*c);
    }
    match v.downcast_ref::<CaseOrBucket>() {
        Some(CaseOrBucket::Case(c)) => Some(*c),
        _ => match v.downcast_ref::<CaseOrChannel>() {
            Some(CaseOrChannel::Case(c)) => Some(*c),
            _ => None,
        },
    }
}

macro_rules! catalog {
    ($( $(#[$m:meta])* $v:ident = $name:literal [$class:ident, $tp:ident] { $( $f:ident : $t:ty ),* $(,)? } )*) => {
        /// A catalog audit event. Construct a variant and pass it to
        /// [`crate::AuditLog::emit`].
        #[derive(Clone, PartialEq, Eq, Debug)]
        #[non_exhaustive]
        pub enum AuditEvent {
            $( $(#[$m])* #[allow(missing_docs)] $v { $( $f: $t ),* } ),*
        }

        /// `(type name, class)` for every catalog type, in declaration order.
        pub const CATALOG: &[(&str, EventClass)] = &[ $( ($name, EventClass::$class) ),* ];

        impl AuditEvent {
            /// Canonical type name (20 §5).
            pub const fn type_name(&self) -> &'static str {
                match self { $( Self::$v { .. } => $name ),* }
            }
            /// Event class.
            pub const fn class(&self) -> EventClass {
                match self { $( Self::$v { .. } => EventClass::$class ),* }
            }
            const fn base_time_policy(&self) -> TimePolicy {
                match self { $( Self::$v { .. } => TimePolicy::$tp ),* }
            }
            /// Allow-listed payload map.
            pub fn payload(&self) -> Value {
                match self {
                    $( Self::$v { $( $f ),* } => {
                        #[allow(unused_mut)]
                        let mut m = MapBuilder::new();
                        $( m.put_opt(stringify!($f), AuditField::payload_value($f)); )*
                        m.build()
                    } ),*
                }
            }
            /// Payload field names of this event's schema.
            pub fn field_names(&self) -> &'static [&'static str] {
                match self { $( Self::$v { .. } => &[ $( stringify!($f) ),* ] ),* }
            }
            /// The case this event refers to, if any (for per-case redaction, AUD-012).
            pub fn case_ref(&self) -> Option<CaseRef> {
                match self {
                    $( Self::$v { $( $f ),* } => {
                        let found: Option<CaseRef> = None;
                        $( let found = found.or_else(|| case_of(stringify!($f), $f as &dyn Any)); )*
                        found
                    } ),*
                }
            }
        }
    };
}

catalog! {
    // ---------------- 20 §5.1 SECURITY ----------------
    AuthLoginSucceeded = "auth.login_succeeded" [Security, Staff] { method: AuthMethod, aal: Aal, authenticator_aaguid_class: AaguidClass, audience: Audience }
    AuthLoginFailed = "auth.login_failed" [Security, Staff] { method: AuthMethod, failure_code: LoginFailure, audience: Audience }
    AuthStepupSucceeded = "auth.stepup_succeeded" [Security, Staff] { operation_class: Code<OperationClass>, descriptor_hash_prefix: HashPrefix8 }
    AuthStepupFailed = "auth.stepup_failed" [Security, Staff] { operation_class: Code<OperationClass>, descriptor_hash_prefix: HashPrefix8 }
    AuthLogout = "auth.logout" [Security, Staff] { reason_code: SessionEndReason }
    AuthSessionExpired = "auth.session_expired" [Security, Staff] { reason_code: SessionEndReason }
    AuthSessionRevoked = "auth.session_revoked" [Security, Staff] { reason_code: SessionEndReason }
    AuthTokenRefreshed = "auth.token_refreshed" [Security, Staff] {}
    AuthAuthenticatorEnrolled = "auth.authenticator_enrolled" [Security, Staff] { aaguid_class: AaguidClass, count_after: SmallCount }
    AuthAuthenticatorRemoved = "auth.authenticator_removed" [Security, Staff] { aaguid_class: AaguidClass, count_after: SmallCount }
    AuthTotpFallbackUsed = "auth.totp_fallback_used" [Security, Staff] {}
    UserCreated = "user.created" [Security, Staff] { target: UserRef, source: DirectorySource }
    UserSuspended = "user.suspended" [Security, Staff] { target: UserRef, source: DirectorySource }
    UserReactivated = "user.reactivated" [Security, Staff] { target: UserRef, source: DirectorySource }
    UserSuspendedDormant = "user.suspended_dormant" [Security, Staff] { target: UserRef, source: DirectorySource }
    UserAuthenticatorCountLow = "user.authenticator_count_low" [Security, Staff] { target: UserRef }
    UserEnrollmentApproved = "user.enrollment_approved" [Security, Staff] { target: UserRef, approver: UserRef }
    UserListed = "user.listed" [Security, Staff] { scope: Code<ListScope> }
    DeviceCustodyRecorded = "device.custody_recorded" [Security, Staff] { target: UserRef, device: DeviceKeyId, custody_class: CustodyClass }
    DeviceCustodyRevoked = "device.custody_revoked" [Security, Staff] { target: UserRef, device: DeviceKeyId, custody_class: CustodyClass }
    DeviceEnrollRequested = "device.enroll_requested" [Security, Staff] {}
    DeviceEnrolled = "device.enrolled" [Security, Staff] {}
    DeviceRevoked = "device.revoked" [Security, Staff] {}
    RoleAssigned = "role.assigned" [Security, Staff] { target: UserRef, role: Role }
    RoleRevoked = "role.revoked" [Security, Staff] { target: UserRef, role: Role }
    RoleExpired = "role.expired" [Security, Staff] { target: UserRef, role: Role }
    AuthzDenied = "authz.denied" [Security, Staff] { action: Code<Action>, resource_kind: Code<ResourceKind>, reason_code: AuthzDenyReason }
    ApprovalCreated = "approval.created" [Security, Staff] { dc_code: DcCode, approver: Option<UserRef>, effective_date: Option<DayStamp> }
    ApprovalGranted = "approval.granted" [Security, Staff] { dc_code: DcCode, approver: Option<UserRef>, effective_date: Option<DayStamp> }
    ApprovalConsumed = "approval.consumed" [Security, Staff] { dc_code: DcCode, approver: Option<UserRef>, effective_date: Option<DayStamp> }
    ApprovalExpired = "approval.expired" [Security, Staff] { dc_code: DcCode, approver: Option<UserRef>, effective_date: Option<DayStamp> }
    BreakglassRequested = "breakglass.requested" [Security, Staff] { case: CaseRef, reason_code: Code<BreakglassReason>, duration_min: DurationMin, review_outcome: Option<ReviewOutcome> }
    BreakglassApproved = "breakglass.approved" [Security, Staff] { case: CaseRef, reason_code: Code<BreakglassReason>, duration_min: DurationMin, review_outcome: Option<ReviewOutcome> }
    BreakglassExpired = "breakglass.expired" [Security, Staff] { case: CaseRef, reason_code: Code<BreakglassReason>, duration_min: DurationMin, review_outcome: Option<ReviewOutcome> }
    BreakglassReviewed = "breakglass.reviewed" [Security, Staff] { case: CaseRef, reason_code: Code<BreakglassReason>, duration_min: DurationMin, review_outcome: Option<ReviewOutcome> }
    BreakglassWrapRefused = "breakglass.wrap_refused" [Security, Staff] { case: CaseRef, reason_code: Code<BreakglassReason>, duration_min: DurationMin, review_outcome: Option<ReviewOutcome> }
    FleetAction = "fleet.action" [Security, Staff] { action_code: Code<crate::codes::FleetAction>, outcome: Outcome }
    FleetDenied = "fleet.denied" [Security, Staff] { action_code: Code<crate::codes::FleetAction>, outcome: Outcome }
    CfgChanged = "cfg.changed" [Security, Staff] { key: Code<ConfigKey>, class: ConfigClass, old_value_hash: Hash32, new_value: ConfigValue }
    CfgDangerousEnabled = "cfg.dangerous_enabled" [Security, Staff] { key: Code<ConfigKey>, expiry: StaffTimer }
    CfgDangerousDisabled = "cfg.dangerous_disabled" [Security, Staff] { key: Code<ConfigKey>, expiry: StaffTimer }
    CfgDangerousExpired = "cfg.dangerous_expired" [Security, Staff] { key: Code<ConfigKey>, expiry: StaffTimer }
    CfgAttestationRecorded = "cfg.attestation_recorded" [Security, Staff] { attestation_kind: AttestationKind, attester: UserRef }
    CfgChangeCancelled = "cfg.change_cancelled" [Security, Staff] {}
    CfgWorkflowPublished = "cfg.workflow_published" [Security, Staff] {}
    ChannelConfigChanged = "channel.config_changed" [Security, Staff] {}
    KeydirEntryPublished = "keydir.entry_published" [Security, Staff] { entry_kind: KeydirEntryKind, entry_hash: Hash32, publication_slot_date: DayStamp }
    KeydirConsistencyFailure = "keydir.consistency_failure" [Security, Staff] { observer: Observer, detail_code: Code<KeydirDetail> }
    KeydirSnapshotRejected = "keydir.snapshot_rejected" [Security, Staff] {}
    KeydirEpochDestroyed = "keydir.epoch_destroyed" [Security, Staff] {}
    AuditCheckpointSigned = "audit.checkpoint_signed" [Security, Staff] { stream: StreamId, seq_range: SeqRange, root: Hash32 }
    AuditWitnessCosigned = "audit.witness_cosigned" [Security, Staff] { witness_id: WitnessId, checkpoint_seq: Seq }
    AuditWitnessFailed = "audit.witness_failed" [Security, Staff] { witness_id: WitnessId, checkpoint_seq: Seq }
    AuditVerificationFailed = "audit.verification_failed" [Security, Staff] { stream: StreamId, seq: Seq, failure_code: VerifyFailureCode }
    AuditExported = "audit.exported" [Security, Staff] { stream: StreamId, seq_range: SeqRange, destination_class: DestinationClass, approvers: Approvers, recipient_key_fingerprint: Hash32 }
    AuditViewed = "audit.viewed" [Security, Staff] { stream: StreamId, seq_range: SeqRange }
    AuditRead = "audit.read" [Security, Staff] { stream: StreamId, filter_kind: Code<FilterKind>, result_count_bucket: CountBucket }
    /// Retention tombstone written before whole checkpoint intervals are
    /// deleted (20 §12, AUD-005). Implementation-defined name; see SPEC-NOTES.
    AuditRetentionTombstone = "audit.retention_tombstone" [Security, Staff] { stream: StreamId, seq_range: SeqRange, last_deleted_checkpoint_root: Hash32 }
    SecretPlacementViolation = "secret.placement_violation" [Security, Staff] { host_role: HostRole, secret_kind: Code<SecretKind> }
    SelftestLoggingViolation = "selftest.logging_violation" [Security, Staff] { host_role: HostRole, check_code: LoggingCheck }
    UpdateApplied = "update.applied" [Security, Staff] { component: Component, version: Version, reason_code: Option<UpdateReason> }
    UpdateRejected = "update.rejected" [Security, Staff] { component: Component, version: Version, reason_code: Option<UpdateReason> }
    BackupCompleted = "backup.completed" [Security, Staff] { backup_id: BackupId, scope: BackupScope, erasure_log_applied: bool, intake_deletion_list_applied: bool }
    BackupRestorePerformed = "backup.restore_performed" [Security, Staff] { backup_id: BackupId, scope: BackupScope, erasure_log_applied: bool, intake_deletion_list_applied: bool }
    PlatformMismatch = "platform.mismatch" [Security, Staff] { component: Component, expected_manifest_hash_prefix: HashPrefix8, reason_code: PlatformReason }
    EkvRewrapOpened = "ekv.rewrap_opened" [Security, Staff] { affected_case_bucket: CountBucket, approvers: Approvers }
    EkvRewrapClosed = "ekv.rewrap_closed" [Security, Staff] { affected_case_bucket: CountBucket, approvers: Approvers }
    TenantCreated = "tenant.created" [Security, Staff] { tenant: TenantRef }
    TenantDeleted = "tenant.deleted" [Security, Staff] { tenant: TenantRef }
    OnionRotated = "onion.rotated" [Security, Staff] {}
    MetricsAggregateViewed = "metrics.aggregate_viewed" [Security, Staff] { report_id: ReportId }
    SupportBundleCreated = "support.bundle_created" [Security, Staff] {}

    // ---------------- 20 §5.2 CASE ----------------
    CaseImported = "case.imported" [Case, DateOnly] { case: CaseRef, channel_id: ChannelId, received_day: DayStamp, import_slot_date: DayStamp }
    CaseEnvelopeRejected = "case.envelope_rejected" [Case, DateOnly] { pending_envelope_bucket: CountBucket, approvers: Approvers }
    CaseStateChanged = "case.state_changed" [Case, Staff] { case: CaseRef, from_state: CaseState, to_state: CaseState }
    CaseAssigned = "case.assigned" [Case, Staff] { case: CaseRef, target: UserRef, relation: Relation, reason_code: Option<MembershipReason> }
    CaseMemberAdded = "case.member_added" [Case, Staff] { case: CaseRef, target: UserRef, relation: Relation, reason_code: Option<MembershipReason> }
    CaseMemberRemoved = "case.member_removed" [Case, Staff] { case: CaseRef, target: UserRef, relation: Relation, reason_code: MembershipReason }
    CaseMemberSuspended = "case.member_suspended" [Case, Staff] { case: CaseRef, target: UserRef, relation: Relation, reason_code: MembershipReason }
    CaseWrapDeletionRequested = "case.wrap_deletion_requested" [Case, Staff] { case: CaseRef, target: UserRef, approvers: Option<Approvers>, not_before_day: DayStamp }
    CaseWrapDeletionApproved = "case.wrap_deletion_approved" [Case, Staff] { case: CaseRef, target: UserRef, approvers: Option<Approvers>, not_before_day: DayStamp }
    CaseWrapDeletionExecuted = "case.wrap_deletion_executed" [Case, Staff] { case: CaseRef, target: UserRef, approvers: Option<Approvers>, not_before_day: DayStamp }
    CaseRekeyed = "case.rekeyed" [Case, Staff] { case: CaseRef, key_generation: KeyGeneration }
    CaseCoiAttested = "case.coi_attested" [Case, Staff] { case: CaseRef, attester: UserRef }
    CaseCoiTagsUpdated = "case.coi_tags_updated" [Case, Staff] { case: CaseRef }
    CaseCoiWrapViolation = "case.coi_wrap_violation" [Case, Staff] { case: CaseRef, detail_code: CoiWrapDetail }
    CaseSlaReminder = "case.sla_reminder" [Case, Staff] { case: CaseRef, timer_id: TimerId, due_date: DayStamp }
    CaseSlaBreached = "case.sla_breached" [Case, Staff] { case: CaseRef, timer_id: TimerId, due_date: DayStamp }
    CaseSlaExtended = "case.sla_extended" [Case, Staff] { case: CaseRef, timer_id: TimerId, due_date: DayStamp }
    CaseSlaPaused = "case.sla_paused" [Case, Staff] { case: CaseRef, timer_id: TimerId, due_date: DayStamp }
    CaseSlaResumed = "case.sla_resumed" [Case, Staff] { case: CaseRef, timer_id: TimerId, due_date: DayStamp }
    CaseCanaryEscalated = "case.canary_escalated" [Case, DateOnly] { subject: CaseOrBucket, trigger_code: CanaryTrigger }
    CaseDismissRequested = "case.dismiss_requested" [Case, Staff] { case: CaseRef, reason_code: Code<CaseDecisionReason>, approver: Option<UserRef> }
    CaseDismissApproved = "case.dismiss_approved" [Case, Staff] { case: CaseRef, reason_code: Code<CaseDecisionReason>, approver: Option<UserRef> }
    CaseClosureApproved = "case.closure_approved" [Case, Staff] { case: CaseRef, reason_code: Code<CaseDecisionReason>, approver: Option<UserRef> }
    CaseReopened = "case.reopened" [Case, Staff] { case: CaseRef, reason_code: Code<CaseDecisionReason>, approver: Option<UserRef> }
    CaseReferred = "case.referred" [Case, Staff] { case: CaseRef, reason_code: Code<CaseDecisionReason>, approver: Option<UserRef> }
    CaseMessageSent = "case.message_sent" [Case, Staff] { case: CaseRef, template_code: TemplateCode }
    CaseMessageRead = "case.message_read" [Case, Staff] { case: CaseRef }
    CaseOpened = "case.opened" [Case, Staff] { case: CaseRef }
    CaseListed = "case.listed" [Case, Staff] { scope: Code<ListScope> }
    CaseEligibilityComputed = "case.eligibility_computed" [Case, Staff] { subject: CaseOrChannel }
    IntakeListed = "intake.listed" [Case, Staff] { channel_id: ChannelId }
    IntakeEnvelopeRead = "intake.envelope_read" [Case, Staff] { channel_id: ChannelId }
    EvidenceImported = "evidence.imported" [Case, DateOnly] { case: CaseRef, evid: EvidRef, manifest_match: bool }
    EvidenceOpened = "evidence.opened" [Case, Staff] { case: CaseRef, evid: EvidRef, level: Level }
    EvidenceTransformed = "evidence.transformed" [Case, Staff] { case: CaseRef, xform_id: XformId, operation: Code<XformOp>, input_count: Count, output_count: Count }
    EvidenceExportApproved = "evidence.export_approved" [Case, Staff] {}
    EvidenceExported = "evidence.exported" [Case, Staff] { case: CaseRef, package_id: PackageId, evid_count: Count, destination_class: DestinationClass, original: bool, approvers: Approvers, psr_id: Option<PsrId> }
    EvidenceExportFetched = "evidence.export_fetched" [Case, Staff] {}
    EvidenceDeleted = "evidence.deleted" [Case, Staff] { case: CaseRef, evid: EvidRef, method: DeletionMethod }
    EvidenceListed = "evidence.listed" [Case, Staff] { scope: Code<ListScope> }
    CustodyHead = "custody.head" [Case, Staff] { case: CaseRef, custody_mac: Hash32 }
    IdentityUnsealRequested = "identity.unseal_requested" [Case, Staff] { case: CaseRef, legal_basis_code: Code<LegalBasis>, approvers: Option<Approvers>, notice_state: NoticeState }
    IdentityUnsealApproved = "identity.unseal_approved" [Case, Staff] { case: CaseRef, legal_basis_code: Code<LegalBasis>, approvers: Option<Approvers>, notice_state: NoticeState }
    IdentityUnsealDenied = "identity.unseal_denied" [Case, Staff] { case: CaseRef, legal_basis_code: Code<LegalBasis>, approvers: Option<Approvers>, notice_state: NoticeState }
    IdentityUnsealed = "identity.unsealed" [Case, Staff] {}
    LegalholdSet = "legalhold.set" [Case, Staff] { case: CaseRef, hold_ref: HoldRef }
    LegalholdReleased = "legalhold.released" [Case, Staff] { case: CaseRef, hold_ref: HoldRef }
    CaseDisposalRequested = "case.disposal_requested" [Case, Staff] {}
    CaseDisposalApproved = "case.disposal_approved" [Case, Staff] {}
    /// Disposal tombstone (AUD-012): CaseRef, receipt, and the count of
    /// removed CASE events (20 §12); disposal date = envelope `ts`.
    CaseDisposed = "case.disposed" [Case, Staff] { case: CaseRef, receipt_id: ReceiptId, removed_event_count: Count }
    CaseDataPurged = "case.data_purged" [Case, Staff] { case: CaseRef, reason_code: PurgeReason }
    OversightOpened = "oversight.opened" [Case, Staff] { case: CaseRef, mode: OversightMode }
    CaseRewrappedAfterVaultLoss = "case.rewrapped_after_vault_loss" [Case, Staff] { case: CaseRef, approvers: Approvers }
    CaseIdentityRequestRefused = "case.identity_request_refused" [Case, Staff] { case: CaseRef, requester: UserRef, refusal_code: IdentityRefusal }
    RecordsSearchPerformed = "records.search_performed" [Case, Staff] { query_hash: Hash32, legal_basis_code: Code<LegalBasis>, case_count_bucket: CountBucket }
    RecordsCaseRead = "records.case_read" [Case, Staff] { case: CaseRef }
    BreakglassKeyWrapped = "breakglass.key_wrapped" [Case, Staff] {}
    ChannelMembershipChanged = "channel.membership_changed" [Case, Staff] { channel_id: ChannelId, approvers: Approvers, policy_hash: Hash32, effective_date: DayStamp }
    CoiMapChanged = "coi_map.changed" [Case, Staff] { channel_id: ChannelId, approvers: Approvers, policy_hash: Hash32, effective_date: DayStamp }
    SlaPackChanged = "sla_pack.changed" [Case, Staff] { channel_id: ChannelId, approvers: Approvers, policy_hash: Hash32, effective_date: DayStamp }

    // ---------------- 20 §5.3 SYSTEM ----------------
    SysServiceStarted = "sys.service_started" [System, System] { service: Service, version: Version, exit_code: Option<ExitCode> }
    SysServiceStopped = "sys.service_stopped" [System, System] { service: Service, version: Version, exit_code: Option<ExitCode> }
    SysServiceCrashed = "sys.service_crashed" [System, System] { service: Service, version: Version, exit_code: Option<ExitCode> }
    SysHealth = "sys.health" [System, System] { service: Service, status: HealthStatus, check_code: HealthCheck }
    SysCapacity = "sys.capacity" [System, System] { resource: CapacityResource, percent_bucket: PercentBucket }
    SysRelayDaily = "sys.relay_daily" [System, DateOnly] { date: DayStamp, slots_ok: SmallCount, slots_failed: SmallCount, slots_overrun: SmallCount }
    SysRelaySlotOverrun = "sys.relay_slot_overrun" [System, DateOnly] { date: DayStamp, slot_index: SlotIndex }
    SysTorStatus = "sys.tor_status" [System, System] { bootstrap_percent: Percent, onion_published: bool, pow_enabled: bool }
    SysJob = "sys.job" [System, System] { job_kind: JobKind, outcome: Outcome }
    SysClock = "sys.clock" [System, System] { drift_ms_bucket: DriftBucket, source_count: SmallCount }
    SysSandboxImage = "sys.sandbox_image" [System, System] { image_name: Code<SandboxImage>, age_days: AgeDays }
}

impl AuditEvent {
    /// Effective timestamp policy (adds the 24 §9.4 rule that
    /// source-load-derived health events are date-only).
    pub fn time_policy(&self) -> TimePolicy {
        match self {
            Self::SysHealth { check_code, .. } if check_code.is_source_load_derived() => {
                TimePolicy::DateOnly
            }
            _ => self.base_time_policy(),
        }
    }

    /// Whether a Z-INTAKE host may emit this event (20 §3: only SYSTEM
    /// events and SECURITY events about administrative access to the host).
    pub fn allowed_on_intake(&self) -> bool {
        match self.class() {
            EventClass::System => !matches!(
                self,
                Self::SysRelayDaily { .. } | Self::SysRelaySlotOverrun { .. }
            ),
            EventClass::Case => false,
            EventClass::Security => matches!(
                self,
                Self::AuthLoginSucceeded { .. }
                    | Self::AuthLoginFailed { .. }
                    | Self::AuthLogout { .. }
                    | Self::AuthSessionExpired { .. }
                    | Self::AuthSessionRevoked { .. }
                    | Self::AuthzDenied { .. }
                    | Self::SecretPlacementViolation { .. }
                    | Self::SelftestLoggingViolation { .. }
                    | Self::UpdateApplied { .. }
                    | Self::UpdateRejected { .. }
                    | Self::PlatformMismatch { .. }
            ),
        }
    }

    /// Whether this is an import-related event (always date-only, LOG-013/LOG-021).
    pub fn is_import_related(&self) -> bool {
        matches!(
            self,
            Self::CaseImported { .. } | Self::EvidenceImported { .. } | Self::CaseEnvelopeRejected { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn catalog_names_unique_and_well_formed() {
        let mut seen = BTreeSet::new();
        for (n, _) in CATALOG {
            assert!(seen.insert(*n), "duplicate {n}");
            assert!(n.bytes().all(|b| b.is_ascii_lowercase() || b == b'.' || b == b'_'));
            assert!(n.contains('.'));
        }
    }

    // LOG-020 / ADR-037(3): no COI-distinguishing codes anywhere.
    #[test]
    fn no_coi_reason_codes() {
        for c in AuthzDenyReason::ALL {
            assert!(!c.code().contains("COI"));
        }
        for c in MembershipReason::ALL {
            assert!(!c.code().contains("COI"));
        }
        for c in IdentityRefusal::ALL {
            assert!(!c.code().contains("COI"));
        }
    }

    #[test]
    fn case_ref_extraction() {
        let c = CaseRef::from_bytes([7; 16]);
        assert_eq!(AuditEvent::CaseOpened { case: c }.case_ref(), Some(c));
        assert_eq!(
            AuditEvent::CaseCanaryEscalated {
                subject: CaseOrBucket::Case(c),
                trigger_code: CanaryTrigger::C1
            }
            .case_ref(),
            Some(c)
        );
        assert_eq!(AuditEvent::AuthTotpFallbackUsed {}.case_ref(), None);
    }

    #[test]
    fn payload_keys_match_schema_and_omit_none() {
        let e = AuditEvent::ApprovalCreated {
            dc_code: DcCode::new(9).unwrap(),
            approver: None,
            effective_date: None,
        };
        let Value::Map(m) = e.payload() else { panic!() };
        assert_eq!(m.len(), 1);
        assert_eq!(e.field_names(), &["dc_code", "approver", "effective_date"]);
    }

    #[test]
    fn import_events_are_date_only() {
        let c = CaseRef::from_bytes([1; 16]);
        let e = AuditEvent::CaseImported {
            case: c,
            channel_id: ChannelId::from_bytes([2; 16]),
            received_day: DayStamp(1),
            import_slot_date: DayStamp(1),
        };
        assert!(e.is_import_related());
        assert_eq!(e.time_policy(), TimePolicy::DateOnly);
        let h = AuditEvent::SysHealth {
            service: Service::Upload,
            status: HealthStatus::Degraded,
            check_code: HealthCheck::AbuseFlood,
        };
        assert_eq!(h.time_policy(), TimePolicy::DateOnly);
    }
}
