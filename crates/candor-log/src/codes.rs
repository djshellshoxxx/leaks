// SPDX-License-Identifier: AGPL-3.0-or-later
//! Enumerated codes. Every code is a closed Rust enum encoded as a fixed
//! upper-case text constant, or a [`Code`] from a numeric registry
//! (`Code<T>` in 20 §5) for spaces the specification does not enumerate.
//!
//! ADR-037(3) / P-16 / LOG-020: no code here distinguishes a COI removal or
//! a COI denial. `AuthzDenyReason` has no `COI_EXCLUDED`, `MembershipReason`
//! has only `REMOVED`/`EXPIRED`, and `IdentityRefusal` has no `COI`.

use core::marker::PhantomData;

use crate::cbor::Value;
use crate::field::{AuditField, Sample, sealed::Sealed};

macro_rules! code_enum {
    ($(#[$m:meta])* $name:ident { $( $(#[$vm:meta])* $v:ident => $s:literal ),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
        pub enum $name { $( $(#[$vm])* $v ),+ }

        impl $name {
            /// All variants.
            pub const ALL: &'static [Self] = &[ $( Self::$v ),+ ];
            /// Canonical code string.
            pub const fn code(self) -> &'static str {
                match self { $( Self::$v => $s ),+ }
            }
        }

        impl Sealed for $name {}
        impl AuditField for $name {
            fn to_value(&self) -> Value {
                Value::text(self.code())
            }
        }
        impl Sample for $name {
            fn sample() -> Self {
                Self::ALL.first().copied().unwrap_or_else(|| unreachable_first())
            }
        }
    };
}

#[allow(clippy::panic)]
#[cold]
fn unreachable_first<T>() -> T {
    // code_enum! requires at least one variant, so ALL is never empty.
    panic!("empty code enum")
}

/// Marker for a numeric code registry (`Code<T>`).
pub trait CodeSpace: 'static {
    /// Registry name (for documentation and the schema registry).
    const NAME: &'static str;
}

/// A code from a numeric registry. Numeric codes cannot carry request data.
pub struct Code<S: CodeSpace>(u16, PhantomData<S>);

impl<S: CodeSpace> Code<S> {
    /// Registry code `n`.
    pub const fn new(n: u16) -> Self {
        Self(n, PhantomData)
    }
    /// Numeric value.
    pub const fn get(&self) -> u16 {
        self.0
    }
}

impl<S: CodeSpace> Clone for Code<S> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<S: CodeSpace> Copy for Code<S> {}
impl<S: CodeSpace> PartialEq for Code<S> {
    fn eq(&self, o: &Self) -> bool {
        self.0 == o.0
    }
}
impl<S: CodeSpace> Eq for Code<S> {}
impl<S: CodeSpace> core::hash::Hash for Code<S> {
    fn hash<H: core::hash::Hasher>(&self, h: &mut H) {
        self.0.hash(h);
    }
}
impl<S: CodeSpace> core::fmt::Debug for Code<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}#{}", S::NAME, self.0)
    }
}
impl<S: CodeSpace> Sample for Code<S> {
    fn sample() -> Self {
        Self::new(3)
    }
}
impl<S: CodeSpace> Sealed for Code<S> {}
impl<S: CodeSpace> AuditField for Code<S> {
    fn to_value(&self) -> Value {
        Value::Uint(u64::from(self.0))
    }
}

macro_rules! code_space {
    ($( $(#[$m:meta])* $name:ident = $s:literal ;)+) => {
        $(
            $(#[$m])*
            #[derive(Debug)]
            pub enum $name {}
            impl CodeSpace for $name { const NAME: &'static str = $s; }
        )+
    };
}

code_space! {
    /// Step-up operation classes.
    OperationClass = "operation_class";
    /// Authorization actions (C-22 action registry).
    Action = "action";
    /// Resource kinds (C-22).
    ResourceKind = "resource_kind";
    /// Break-glass reason codes.
    BreakglassReason = "breakglass_reason";
    /// Fleet action codes (ADR-045).
    FleetAction = "fleet_action";
    /// Configuration keys (32 CFG registry).
    ConfigKey = "config_key";
    /// Key-directory consistency detail codes.
    KeydirDetail = "keydir_detail";
    /// Secret kinds (ADR-028).
    SecretKind = "secret_kind";
    /// Case decision reason codes (dismiss/closure/reopen/referral).
    CaseDecisionReason = "case_decision_reason";
    /// Evidence transform operations.
    XformOp = "xform_op";
    /// Legal basis codes.
    LegalBasis = "legal_basis";
    /// List scopes (`case.listed`, `evidence.listed`, `user.listed`).
    ListScope = "list_scope";
    /// Audit read filter kinds.
    FilterKind = "filter_kind";
    /// Sandbox image identifiers (`sys.sandbox_image`).
    SandboxImage = "sandbox_image";
}

code_enum!(
    /// Authentication method.
    AuthMethod { Fido2 => "FIDO2", Piv => "PIV", Totp => "TOTP", SsoFido2 => "SSO+FIDO2" });
code_enum!(
    /// Authenticator assurance level.
    Aal { Aal1 => "AAL1", Aal2 => "AAL2", Aal3 => "AAL3" });
code_enum!(
    /// Authenticator AAGUID class.
    AaguidClass { Certified => "CERTIFIED", Uncertified => "UNCERTIFIED" });
code_enum!(
    /// Token audience (09 `session.audience`).
    Audience { DeskApi => "DESK_API", AdminApi => "ADMIN_API" });
code_enum!(
    /// `auth.login_failed` failure codes (20 §5.1).
    LoginFailure {
        BadAssertion => "BAD_ASSERTION",
        UvMissing => "UV_MISSING",
        UnknownCredential => "UNKNOWN_CREDENTIAL",
        Suspended => "SUSPENDED",
        IdpRejected => "IDP_REJECTED",
    });
code_enum!(
    /// Session end reasons (`auth.logout`/`session_expired`/`session_revoked`).
    SessionEndReason {
        UserLogout => "USER_LOGOUT",
        IdleTimeout => "IDLE_TIMEOUT",
        AbsoluteTimeout => "ABSOLUTE_TIMEOUT",
        Revoked => "REVOKED",
        Suspended => "SUSPENDED",
        DeviceRevoked => "DEVICE_REVOKED",
    });
code_enum!(
    /// Origin of a user lifecycle action (ADR-044(1)).
    DirectorySource { Manual => "MANUAL", Scim => "SCIM", Idp => "IDP" });
code_enum!(
    /// Device custody class (ADR-043).
    CustodyClass { Independent => "INDEPENDENT", Org => "ORG" });
code_enum!(
    /// Roles (15 §role catalog).
    Role {
        IntakeTriager => "INTAKE_TRIAGER",
        Investigator => "INVESTIGATOR",
        CaseLead => "CASE_LEAD",
        Reviewer => "REVIEWER",
        ChannelOwner => "CHANNEL_OWNER",
        IdentityCustodian => "IDENTITY_CUSTODIAN",
        LegalCounsel => "LEGAL_COUNSEL",
        Oversight => "OVERSIGHT",
        RecordsOfficer => "RECORDS_OFFICER",
        RecordsCustodian => "RECORDS_CUSTODIAN",
        Auditor => "AUDITOR",
        MetricsViewer => "METRICS_VIEWER",
        SecurityOfficer => "SECURITY_OFFICER",
        SysAdmin => "SYS_ADMIN",
        UserAdmin => "USER_ADMIN",
        RecoveryTrustee => "RECOVERY_TRUSTEE",
        IndependentApprover => "INDEPENDENT_APPROVER",
        EmergencyAdmin => "EMERGENCY_ADMIN",
    });
code_enum!(
    /// `authz.denied` reason codes. COI denials are `NO_RELATION`; no
    /// `COI_EXCLUDED` code exists (ADR-037(3), RVW-B-01, LOG-020).
    AuthzDenyReason {
        NoRelation => "NO_RELATION",
        TenantMismatch => "TENANT_MISMATCH",
        StepUpRequired => "STEP_UP_REQUIRED",
        DualControlRequired => "DUAL_CONTROL_REQUIRED",
        StateInvalid => "STATE_INVALID",
        Suspended => "SUSPENDED",
    });
code_enum!(
    /// Break-glass review outcome.
    ReviewOutcome { Pending => "PENDING", Justified => "JUSTIFIED", NotJustified => "NOT_JUSTIFIED" });
code_enum!(
    /// Outcome (envelope and `fleet.*`/`sys.job`).
    Outcome { Ok => "OK", Denied => "DENIED", Error => "ERROR" });
code_enum!(
    /// Envelope-level error reason (only with `outcome = ERROR`).
    ErrorReason {
        Internal => "INTERNAL",
        Timeout => "TIMEOUT",
        DependencyUnavailable => "DEPENDENCY_UNAVAILABLE",
        InvalidState => "INVALID_STATE",
        PolicyRejected => "POLICY_REJECTED",
    });
code_enum!(
    /// Configuration class (ADR-046(6)).
    ConfigClass { Safe => "SAFE", Advanced => "ADVANCED", Dangerous => "DANGEROUS" });
code_enum!(
    /// Attestation kinds (ADR-044(4)).
    AttestationKind { InfraBackupExcludesVault => "INFRA_BACKUP_EXCLUDES_VAULT" });
code_enum!(
    /// Key Directory entry kinds.
    KeydirEntryKind {
        UserKey => "USER_KEY",
        MemberEpochKey => "MEMBER_EPOCH_KEY",
        ChannelDescriptor => "CHANNEL_DESCRIPTOR",
        ChannelRoster => "CHANNEL_ROSTER",
        OperatorStatement => "OPERATOR_STATEMENT",
        Release => "RELEASE",
    });
code_enum!(
    /// Who observed a Key Directory inconsistency.
    Observer { Desk => "DESK", Witness => "WITNESS", Monitor => "MONITOR", Core => "CORE" });
code_enum!(
    /// Audit stream identifier (20 §4 `stream`).
    StreamId { Sec => "sec", Case => "case", Sys => "sys" });
code_enum!(
    /// Audit verification failure codes (`audit.verification_failed`).
    VerifyFailureCode {
        ChainMismatch => "CHAIN_MISMATCH",
        SequenceGap => "SEQUENCE_GAP",
        SequenceOrder => "SEQUENCE_ORDER",
        NonCanonical => "NON_CANONICAL",
        EnvelopeMismatch => "ENVELOPE_MISMATCH",
        MerkleMismatch => "MERKLE_MISMATCH",
        BadSignature => "BAD_SIGNATURE",
        CheckpointChain => "CHECKPOINT_CHAIN",
        Truncated => "TRUNCATED",
        Rollback => "ROLLBACK",
        MissingPrefix => "MISSING_PREFIX",
    });
code_enum!(
    /// Audit export destination classes.
    DestinationClass {
        AuditorFile => "AUDITOR_FILE",
        Regulator => "REGULATOR",
        LawEnforcement => "LAW_ENFORCEMENT",
        Counsel => "COUNSEL",
        Integration => "INTEGRATION",
        Internal => "INTERNAL",
    });
code_enum!(
    /// Host role (20 §4 `host_role`). Not a hostname or address.
    HostRole { Intake => "intake", Core => "core", Monitor => "monitor", Desk => "desk" });
code_enum!(
    /// Logging self-test check codes (LOG-018).
    LoggingCheck {
        TorLogEnabled => "TOR_LOG_ENABLED",
        TorSafeLoggingOff => "TOR_SAFELOGGING_OFF",
        AccessLogPresent => "ACCESS_LOG_PRESENT",
        JournalPersistent => "JOURNAL_PERSISTENT",
        NftLogRule => "NFT_LOG_RULE",
        CoredumpEnabled => "COREDUMP_ENABLED",
        UnexpectedLogFile => "UNEXPECTED_LOG_FILE",
        CaptureToolRunning => "CAPTURE_TOOL_RUNNING",
    });
code_enum!(
    /// Software components (updates, platform floors).
    Component {
        Candor => "CANDOR",
        Tor => "TOR",
        Postgres => "POSTGRES",
        Os => "OS",
        Desk => "DESK",
        SandboxImage => "SANDBOX_IMAGE",
    });
code_enum!(
    /// Update rejection reasons.
    UpdateReason {
        SignatureInvalid => "SIGNATURE_INVALID",
        Rollback => "ROLLBACK",
        Freeze => "FREEZE",
        BelowFloor => "BELOW_FLOOR",
        NotInLog => "NOT_IN_LOG",
    });
code_enum!(
    /// Backup scope.
    BackupScope { Core => "CORE", Intake => "INTAKE", Vault => "VAULT", Audit => "AUDIT" });
code_enum!(
    /// `platform.mismatch` reasons (ADR-040).
    PlatformReason { BelowFloor => "BELOW_FLOOR", ManifestMismatch => "MANIFEST_MISMATCH" });
code_enum!(
    /// Count bucket {1, 2–9, 10–99, ≥100} (ADR-047(7) and pending-envelope buckets).
    CountBucket { One => "1", TwoToNine => "2-9", TenTo99 => "10-99", HundredPlus => ">=100" });
code_enum!(
    /// Case states (14 §4.1).
    CaseState {
        PendingImport => "PENDING_IMPORT",
        New => "NEW",
        Triage => "TRIAGE",
        Assessment => "ASSESSMENT",
        Investigation => "INVESTIGATION",
        OnHold => "ON_HOLD",
        Decision => "DECISION",
        Remediation => "REMEDIATION",
        Closed => "CLOSED",
        Referred => "REFERRED",
        Dismissed => "DISMISSED",
        Retained => "RETAINED",
        Disposed => "DISPOSED",
    });
code_enum!(
    /// Case membership relations.
    Relation {
        Triage => "TRIAGE",
        Lead => "LEAD",
        Investigator => "INVESTIGATOR",
        Reviewer => "REVIEWER",
        Counsel => "COUNSEL",
        Records => "RECORDS",
        Oversight => "OVERSIGHT",
    });
code_enum!(
    /// Membership removal reason: `REMOVED` for every cause (COI, revocation,
    /// request), `EXPIRED` for temporary-grant expiry (ADR-037(3)).
    MembershipReason { Removed => "REMOVED", Expired => "EXPIRED" });
code_enum!(
    /// `case.coi_wrap_violation` detail codes.
    CoiWrapDetail { WrapForExcludedTag => "WRAP_FOR_EXCLUDED_TAG", WrapSetNotAcl => "WRAP_SET_NOT_ACL" });
code_enum!(
    /// Canary trigger codes C1–C5.
    CanaryTrigger { C1 => "C1", C2 => "C2", C3 => "C3", C4 => "C4", C5 => "C5" });
code_enum!(
    /// Message template codes (no content, no length).
    TemplateCode {
        Ack => "ACK",
        Rfi => "RFI",
        Feedback => "FEEDBACK",
        Extension => "EXTENSION",
        Closure => "CLOSURE",
        UnsealNotice => "UNSEAL_NOTICE",
        Custom => "CUSTOM",
    });
code_enum!(
    /// Containment level L0–L4.
    Level { L0 => "L0", L1 => "L1", L2 => "L2", L3 => "L3", L4 => "L4" });
code_enum!(
    /// Evidence deletion method.
    DeletionMethod { CryptoErase => "CRYPTO_ERASE", Purge => "PURGE" });
code_enum!(
    /// Identity-unseal notice state.
    NoticeState { Queued => "QUEUED", Deferred => "DEFERRED" });
code_enum!(
    /// `case.data_purged` reasons.
    PurgeReason { EuArt17Irrelevant => "EU_ART17_IRRELEVANT" });
code_enum!(
    /// Oversight access mode.
    OversightMode { Standard => "STANDARD", Restricted => "RESTRICTED" });
code_enum!(
    /// `case.identity_request_refused` codes. The 20 §5.2 `COI` value is
    /// intentionally absent (P-16, ADR-037(3)); see SPEC-NOTES.md.
    IdentityRefusal { NoLegalBasis => "NO_LEGAL_BASIS", NotNecessary => "NOT_NECESSARY", Scope => "SCOPE" });
code_enum!(
    /// Services (`sys.*`; `actor = system:<service>`).
    Service {
        Tor => "tor",
        Web => "web",
        Upload => "upload",
        IntakeStore => "intake_store",
        Relay => "relay",
        Core => "core",
        Authz => "authz",
        Auth => "auth",
        Audit => "audit",
        Health => "health",
        KeyDirectory => "keydir",
        Admin => "admin",
        Viewer => "viewer",
        Backup => "backup",
        Scheduler => "scheduler",
        Siem => "siem",
    });
code_enum!(
    /// Health status.
    HealthStatus { Ok => "OK", Degraded => "DEGRADED", Down => "DOWN" });
code_enum!(
    /// Health check codes. Source-load-derived detectors are date-only (24 §9.4).
    HealthCheck {
        Liveness => "LIVENESS",
        Readiness => "READINESS",
        Database => "DATABASE",
        Disk => "DISK",
        TorBootstrap => "TOR_BOOTSTRAP",
        RelaySchedule => "RELAY_SCHEDULE",
        AbuseFlood => "ABUSE_FLOOD",
        PowPressure => "POW_PRESSURE",
        QueueBacklog => "QUEUE_BACKLOG",
    });

impl HealthCheck {
    /// Whether the check is derived from source load (abuse/flood detectors);
    /// such events carry a date-only `ts` (24 §9.4 "Abuse alerting").
    pub const fn is_source_load_derived(self) -> bool {
        matches!(self, Self::AbuseFlood | Self::PowPressure | Self::QueueBacklog)
    }
}

code_enum!(
    /// Capacity resources.
    CapacityResource { Disk => "DISK", Mem => "MEM", Queue => "QUEUE" });
code_enum!(
    /// Job kinds (`sys.job`).
    JobKind { Retention => "RETENTION", EpochRotate => "EPOCH_ROTATE", Checkpoint => "CHECKPOINT", Backup => "BACKUP" });
code_enum!(
    /// Clock drift bucket.
    DriftBucket {
        Under100ms => "<100ms",
        Under1s => "<1s",
        Under10s => "<10s",
        Under1min => "<1min",
        Under5min => "<5min",
        AtLeast5min => ">=5min",
    });

/// Either a case or a pending-envelope bucket (`case.canary_escalated`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CaseOrBucket {
    /// A case.
    Case(crate::ids::CaseRef),
    /// A pending-envelope count bucket.
    PendingBucket(CountBucket),
}

impl Sample for CaseOrBucket {
    fn sample() -> Self {
        Self::Case(crate::ids::CaseRef::sample())
    }
}
impl Sealed for CaseOrBucket {}
impl AuditField for CaseOrBucket {
    fn to_value(&self) -> Value {
        match self {
            Self::Case(c) => c.to_value(),
            Self::PendingBucket(b) => b.to_value(),
        }
    }
}

/// Either a case or a channel (`case.eligibility_computed`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CaseOrChannel {
    /// A case.
    Case(crate::ids::CaseRef),
    /// A channel.
    Channel(crate::ids::ChannelId),
}

impl Sample for CaseOrChannel {
    fn sample() -> Self {
        Self::Case(crate::ids::CaseRef::sample())
    }
}
impl Sealed for CaseOrChannel {}
impl AuditField for CaseOrChannel {
    fn to_value(&self) -> Value {
        let (tag, v) = match self {
            Self::Case(c) => ("case", c.to_value()),
            Self::Channel(c) => ("channel", c.to_value()),
        };
        Value::Array(vec![Value::text(tag), v])
    }
}

/// New value of a configuration key: only enumerated/boolean values are
/// recorded in clear; anything else as a hash (20 §5.1 `cfg.changed`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ConfigValue {
    /// Boolean key.
    Bool(bool),
    /// Enumerated key (registry ordinal).
    Enum(u16),
    /// Any other value, hashed.
    Hash(crate::ids::Hash32),
}

impl Sample for ConfigValue {
    fn sample() -> Self {
        Self::Bool(true)
    }
}
impl Sealed for ConfigValue {}
impl AuditField for ConfigValue {
    fn to_value(&self) -> Value {
        match self {
            Self::Bool(b) => Value::Bool(*b),
            Self::Enum(e) => Value::Uint(u64::from(*e)),
            Self::Hash(h) => h.to_value(),
        }
    }
}
