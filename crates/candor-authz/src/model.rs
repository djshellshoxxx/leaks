// SPDX-License-Identifier: AGPL-3.0-or-later
//! The policy model as data: roles (15 §5.1), permissions (08 §8–§9 route
//! permissions), relations (15 §5.4), case states and flags (14 §4.1),
//! subject/object facts (15 §5.3) and the request context (step-up proofs,
//! dual-control approvals, trusted time). Everything here is plain data the
//! caller loads inside the same DB transaction as the data access (15 §5.9
//! PIP); the engine performs no I/O.

use crate::ids::{
    CaseId, ChannelId, DepartmentId, Day, EnvelopeId, ExclTag, KeyId, OpDigest, PersonRef,
    Seconds, TenantId, UserId,
};

macro_rules! str_enum {
    ($(#[$m:meta])* $name:ident { $($(#[$vm:meta])* $v:ident = $s:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name { $($(#[$vm])* $v),+ }

        impl $name {
            /// Every variant, in declaration order (drives exhaustive tests).
            pub const ALL: &'static [$name] = &[$($name::$v),+];

            /// The wire / policy-file spelling.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $($name::$v => $s),+ }
            }

            /// Strict parse of the policy-file spelling.
            #[must_use]
            pub fn parse(s: &str) -> Option<Self> {
                match s { $($s => Some($name::$v),)+ _ => None }
            }
        }
    };
}

str_enum!(
    /// Staff roles (15 §5.1). `CASE_LEAD` is a relation-derived role: it is
    /// effective only for a subject holding the `lead` relation on the case.
    Role {
        IntakeTriager = "INTAKE_TRIAGER",
        Investigator = "INVESTIGATOR",
        CaseLead = "CASE_LEAD",
        Reviewer = "REVIEWER",
        ChannelOwner = "CHANNEL_OWNER",
        IdentityCustodian = "IDENTITY_CUSTODIAN",
        LegalCounsel = "LEGAL_COUNSEL",
        Oversight = "OVERSIGHT",
        RecordsOfficer = "RECORDS_OFFICER",
        RecordsCustodian = "RECORDS_CUSTODIAN",
        Auditor = "AUDITOR",
        MetricsViewer = "METRICS_VIEWER",
        SecurityOfficer = "SECURITY_OFFICER",
        SysAdmin = "SYS_ADMIN",
        UserAdmin = "USER_ADMIN",
        TenantAdmin = "TENANT_ADMIN",
        RecoveryTrustee = "RECOVERY_TRUSTEE",
        EmergencyAdmin = "EMERGENCY_ADMIN",
    }
);

impl Role {
    /// Roles with zero case-content capability (15 §5.7, ADR-015). A policy
    /// bundle can never grant them a content permission (baseline invariant).
    #[must_use]
    pub const fn is_admin(self) -> bool {
        matches!(
            self,
            Role::SysAdmin
                | Role::UserAdmin
                | Role::SecurityOfficer
                | Role::TenantAdmin
                | Role::EmergencyAdmin
        )
    }

    /// Roles that only ever act on the `admin-api` audience (ADR-029).
    #[must_use]
    pub const fn admin_audience_only(self) -> bool {
        matches!(
            self,
            Role::SysAdmin | Role::UserAdmin | Role::SecurityOfficer | Role::TenantAdmin
        )
    }
}

str_enum!(
    /// Permissions named by the 08 §8 (desk) and §9 (admin) route tables and the
    /// 15 §5.2 matrix rows.
    Permission {
        MeRead = "me.read",
        NotificationSettings = "me.notification_settings",
        SyncRead = "sync.read",
        DeviceRevoke = "device.revoke",
        EpochKeysRead = "epoch_keys.read",
        EpochKeysPublish = "epoch_keys.publish",
        EpochKeysDestroyAck = "epoch_keys.destroy_ack",
        IntakeList = "intake.list",
        IntakeRead = "intake.read",
        IntakeTriage = "intake.triage",
        IntakeReject = "intake.reject",
        CaseCreate = "case.create",
        CaseList = "case.list",
        CaseRead = "case.read",
        CaseUpdate = "case.update",
        CaseTransition = "case.transition",
        CaseCloseApprove = "case.close_approve",
        CaseMembersRead = "case.members.read",
        CaseShare = "case.share",
        CaseRekey = "case.rekey",
        CaseNote = "case.note",
        CaseReply = "case.reply",
        CaseCoiDeclare = "case.coi_declare",
        LegalHoldPlace = "legal_hold.place",
        LegalHoldRelease = "legal_hold.release",
        CaseDelete = "case.delete",
        CaseDeleteApprove = "case.delete.approve",
        CaseAuditRead = "case.audit.read",
        SlaRead = "sla.read",
        WrapDeleteRequest = "wrap_delete.request",
        WrapDeleteApprove = "wrap_delete.approve",
        EvidenceList = "evidence.list",
        EvidenceRead = "evidence.read",
        EvidenceReadOriginal = "evidence.read_original",
        EvidenceAdd = "evidence.add",
        EvidenceUploadChunk = "evidence.upload_chunk",
        EvidenceRemove = "evidence.remove",
        IdentityRequest = "identity.request",
        IdentityApprove = "identity.approve",
        IdentityReadSealed = "identity.read_sealed",
        BreakGlassRequest = "breakglass.request",
        BreakGlassApprove = "breakglass.approve",
        BreakGlassWrap = "breakglass.wrap",
        BreakGlassRead = "breakglass.read",
        BreakGlassReview = "breakglass.review",
        ExportCreate = "export.create",
        ExportCreateOriginal = "export.create_original",
        ExportRead = "export.read",
        ExportApprove = "export.approve",
        ExportDownload = "export.download",
        UpdatesRead = "updates.read",
        UserList = "user.list",
        UserInvite = "user.invite",
        UserUpdate = "user.update",
        UserDisable = "user.disable",
        DeviceApprove = "device.approve",
        RoleList = "role.list",
        RoleAssign = "role.assign",
        ChannelManage = "channel.manage",
        ChannelRosterManage = "channel.roster.manage",
        CoiManage = "coi.manage",
        WorkflowManage = "workflow.manage",
        RetentionManage = "retention.manage",
        ConfigRead = "config.read",
        ConfigPropose = "config.propose",
        ConfigApprove = "config.approve",
        ConfigCancel = "config.cancel",
        AuditSecurityRead = "audit.security.read",
        AuditVerify = "audit.verify",
        AuditExport = "audit.export",
        HealthRead = "health.read",
        ReportsRead = "reports.read",
        RecoveryQuorumEnable = "recovery_quorum.enable",
        OnionRotate = "onion.rotate",
        BackupOperate = "backup.operate",
        UpdateOperate = "update.operate",
        SupportBundle = "support.bundle",
    }
);

impl Permission {
    /// Case-content permissions: anything that reads, writes or shares the
    /// content or membership of a case or an intake envelope. Admin roles can
    /// never hold one (15 §5.7). Exported so the lint and the engine agree.
    #[must_use]
    pub const fn is_content(self) -> bool {
        use Permission as P;
        matches!(
            self,
            P::IntakeList
                | P::IntakeRead
                | P::IntakeTriage
                | P::IntakeReject
                | P::CaseCreate
                | P::CaseList
                | P::CaseRead
                | P::CaseUpdate
                | P::CaseTransition
                | P::CaseCloseApprove
                | P::CaseMembersRead
                | P::CaseShare
                | P::CaseRekey
                | P::CaseNote
                | P::CaseReply
                | P::CaseCoiDeclare
                | P::LegalHoldPlace
                | P::LegalHoldRelease
                | P::CaseDelete
                | P::CaseDeleteApprove
                | P::WrapDeleteRequest
                | P::WrapDeleteApprove
                | P::EvidenceList
                | P::EvidenceRead
                | P::EvidenceReadOriginal
                | P::EvidenceAdd
                | P::EvidenceUploadChunk
                | P::EvidenceRemove
                | P::IdentityRequest
                | P::IdentityApprove
                | P::IdentityReadSealed
                | P::BreakGlassWrap
                | P::ExportCreate
                | P::ExportCreateOriginal
                | P::ExportRead
                | P::ExportApprove
                | P::ExportDownload
                | P::SlaRead
        )
    }

    /// Permissions that change case content; denied on read-only states
    /// (`CLOSED`, `DISMISSED`, `RETAINED`; 14 §4.1).
    #[must_use]
    pub const fn mutates_content(self) -> bool {
        use Permission as P;
        matches!(
            self,
            P::CaseUpdate
                | P::CaseNote
                | P::CaseReply
                | P::EvidenceAdd
                | P::EvidenceUploadChunk
                | P::EvidenceRemove
        )
    }

    /// Permissions reachable only through the `admin-api` audience (08 §9).
    #[must_use]
    pub const fn is_admin_api(self) -> bool {
        use Permission as P;
        matches!(
            self,
            P::UserList
                | P::UserInvite
                | P::UserUpdate
                | P::UserDisable
                | P::DeviceApprove
                | P::RoleList
                | P::RoleAssign
                | P::ChannelManage
                | P::ChannelRosterManage
                | P::CoiManage
                | P::WorkflowManage
                | P::RetentionManage
                | P::ConfigRead
                | P::ConfigPropose
                | P::ConfigApprove
                | P::ConfigCancel
                | P::AuditSecurityRead
                | P::AuditVerify
                | P::AuditExport
                | P::HealthRead
                | P::ReportsRead
                | P::RecoveryQuorumEnable
                | P::OnionRotate
                | P::BackupOperate
                | P::UpdateOperate
                | P::SupportBundle
        )
    }

    /// Audit stream class for an allowed action (20 §3; ADR-016).
    #[must_use]
    pub const fn audit_class(self) -> AuditClass {
        use Permission as P;
        if self.is_admin_api()
            || matches!(
                self,
                P::BreakGlassRequest
                    | P::BreakGlassApprove
                    | P::BreakGlassReview
                    | P::DeviceRevoke
                    | P::NotificationSettings
                    | P::EpochKeysPublish
                    | P::EpochKeysDestroyAck
            )
        {
            AuditClass::Security
        } else {
            AuditClass::Case
        }
    }
}

str_enum!(
    /// Token audience (ADR-029). Sources never reach C-22.
    Audience {
        DeskApi = "desk-api",
        AdminApi = "admin-api",
    }
);

str_enum!(
    /// Case ACL relations (15 §5.4) plus the engine-derived `break_glass`.
    Relation {
        Member = "member",
        Lead = "lead",
        Reviewer = "reviewer",
        Counsel = "counsel",
        OversightSilent = "oversight",
        RecordsGrant = "records",
        BreakGlass = "break_glass",
    }
);

str_enum!(
    /// Case states (14 §4.1).
    CaseState {
        PendingImport = "PENDING_IMPORT",
        New = "NEW",
        Triage = "TRIAGE",
        Assessment = "ASSESSMENT",
        Investigation = "INVESTIGATION",
        OnHold = "ON_HOLD",
        Decision = "DECISION",
        Remediation = "REMEDIATION",
        Closed = "CLOSED",
        Referred = "REFERRED",
        Dismissed = "DISMISSED",
        Retained = "RETAINED",
        Disposed = "DISPOSED",
    }
);

impl CaseState {
    /// Content visible only to the Triage Set (ADR-037(2)).
    #[must_use]
    pub const fn triage_only(self) -> bool {
        matches!(self, CaseState::New | CaseState::Triage)
    }

    /// Members read only (14 §4.1).
    #[must_use]
    pub const fn read_only(self) -> bool {
        matches!(
            self,
            CaseState::Closed | CaseState::Dismissed | CaseState::Retained
        )
    }
}

str_enum!(
    /// Dual-control operation ids (15 §5.8, normative list).
    DcId {
        Dc01 = "DC-01",
        Dc02 = "DC-02",
        Dc03 = "DC-03",
        Dc04 = "DC-04",
        Dc05 = "DC-05",
        Dc06 = "DC-06",
        Dc07 = "DC-07",
        Dc08 = "DC-08",
        Dc09 = "DC-09",
        Dc10 = "DC-10",
        Dc11 = "DC-11",
        Dc12 = "DC-12",
        Dc13 = "DC-13",
        Dc14 = "DC-14",
        Dc15 = "DC-15",
        Dc16 = "DC-16",
        Dc17 = "DC-17",
        Dc18 = "DC-18",
        Dc19 = "DC-19",
    }
);

str_enum!(
    /// Break-glass reason codes (15 §5.6). A request without one is invalid.
    BreakGlassReason {
        ImminentDanger = "IMMINENT_DANGER",
        LegalDeadline = "LEGAL_DEADLINE",
        MemberIncapacitated = "MEMBER_INCAPACITATED",
    }
);

str_enum!(
    /// Audit stream class of an obligation (20 §3).
    AuditClass {
        Case = "CASE",
        Security = "SECURITY",
    }
);

/// Case overlay flags (14 §4.1). A bit set, not an enum, because several
/// apply at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Flags(u32);

impl Flags {
    pub const NONE: Flags = Flags(0);
    pub const LEGAL_HOLD: Flags = Flags(1 << 0);
    pub const SEALED_MATTER: Flags = Flags(1 << 1);
    pub const IDENTITY_SEALED: Flags = Flags(1 << 2);
    pub const BREAK_GLASS_ACTIVE: Flags = Flags(1 << 3);
    pub const RESTRICTED_OVERSIGHT: Flags = Flags(1 << 4);
    pub const HOLDER_SUSPENDED: Flags = Flags(1 << 5);
    pub const HIGH_DETRIMENT_RISK: Flags = Flags(1 << 6);
    /// All defined bits; anything else is rejected by [`Flags::from_bits`].
    pub const ALL: Flags = Flags((1 << 7) - 1);

    /// Strict construction: unknown bits are refused (fail closed).
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Flags> {
        if bits & !Self::ALL.0 == 0 {
            Some(Flags(bits))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, other: Flags) -> bool {
        self.0 & other.0 == other.0
    }

    #[must_use]
    pub const fn union(self, other: Flags) -> Flags {
        Flags(self.0 | other.0)
    }
}

/// Authenticator assurance level of the current session (15 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthnLevel {
    Aal2,
    Aal3,
}

/// Account state (15 §5.3). Only `Active` can be authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountState {
    Active,
    Suspended,
    NeedsAuthenticator,
}

/// Desk device custody (ADR-043).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Custody {
    Independent,
    OrgManaged,
    Unknown,
}

/// Channel type (14 §8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelType {
    Standard,
    Independent,
}

/// `LEGAL_COUNSEL` tag (15 §5.1): only `External` is an independent role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CounselKind {
    Internal,
    External,
}

/// Scope of a role assignment (AP-08 `scope_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    Tenant,
    Channel(ChannelId),
    Department(DepartmentId),
}

/// One role assignment with its validity (15 §5.5: ≤ 365 days).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleAssignment {
    pub role: Role,
    pub scope: Scope,
    /// Last valid day, inclusive. `None` only for built-in standing roles.
    pub valid_until: Option<Day>,
}

/// Membership in a channel roster (C-14 entry; 14 §8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelMembership {
    pub channel: ChannelId,
    /// Triage Set member (ADR-037(1)).
    pub triage_set: bool,
    pub department: Option<DepartmentId>,
    /// Current `DEVICE_CUSTODY` record of the acting device (ADR-043).
    pub custody: Custody,
}

/// The authenticated principal and its attributes (15 §5.3 subject
/// attributes). Built by C-10 from the verified session only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject<'a> {
    pub tenant: TenantId,
    pub user: UserId,
    pub person: PersonRef,
    pub roles: &'a [RoleAssignment],
    pub channels: &'a [ChannelMembership],
    pub audience: Audience,
    pub authn_level: AuthnLevel,
    pub account_state: AccountState,
    /// The DPoP-style device binding verified for this request (15 §4.6).
    pub device_binding_valid: bool,
    /// Whether this account holds an approved step-up accommodation (RVW-C-16).
    pub step_up_accommodation: bool,
    pub counsel_kind: Option<CounselKind>,
}

impl Subject<'_> {
    /// Role active today in a scope covering the object (tenant-wide, or the
    /// object's channel / department).
    #[must_use]
    pub fn has_role(&self, role: Role, today: Day, channel: Option<ChannelId>) -> bool {
        self.roles.iter().any(|r| {
            r.role == role
                && r.valid_until.is_none_or(|d| d >= today)
                && match r.scope {
                    Scope::Tenant => true,
                    Scope::Channel(c) => channel == Some(c),
                    Scope::Department(d) => self
                        .channels
                        .iter()
                        .any(|m| Some(m.channel) == channel && m.department == Some(d)),
                }
        })
    }

    /// Independent role for approver constraints (15 §5.1, ADR-045).
    #[must_use]
    pub fn is_independent(&self, today: Day) -> bool {
        self.has_role(Role::Oversight, today, None)
            || (self.has_role(Role::LegalCounsel, today, None)
                && self.counsel_kind == Some(CounselKind::External))
    }

    #[must_use]
    pub fn membership(&self, channel: ChannelId) -> Option<&ChannelMembership> {
        self.channels.iter().find(|m| m.channel == channel)
    }
}

/// Why an ACL entry exists (DA-35 `via`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GrantVia {
    Standard,
    BreakGlass,
    Records,
}

/// One case ACL row (15 §5.4; DA-36 stores the grantee's blinded tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AclEntry {
    pub user: UserId,
    pub relation: Relation,
    pub via: GrantVia,
    /// Last valid day, inclusive; mandatory for temporary relations.
    pub valid_until: Option<Day>,
    /// Exact expiry for break-glass grants (≤ 4 h; 15 §5.6(5)). Mandatory
    /// when `via == BreakGlass`; an entry without it grants nothing.
    pub expires_at: Option<Seconds>,
    /// Server-side suspension (14 §8.5(1); ADR-044(1)).
    pub suspended: bool,
    /// The grantee's blinded exclusion tag, supplied by the granting Desk.
    pub excl_tag: ExclTag,
}

/// Case facts (15 §5.3 object attributes). The tenant and the case are part
/// of the type: there is no way to ask for a case-level decision without them
/// (IDOR rule, 15 §5.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseFacts<'a> {
    pub tenant: TenantId,
    pub case: CaseId,
    pub channel: ChannelId,
    pub department: Option<DepartmentId>,
    pub state: CaseState,
    pub flags: Flags,
    pub acl: &'a [AclEntry],
    /// Blinded exclusion tags, padded to a multiple of 8 (04 §9.11).
    pub coi_tags: &'a crate::coi::CoiTagSet,
    pub channel_type: ChannelType,
}

/// Channel facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelFacts {
    pub tenant: TenantId,
    pub channel: ChannelId,
    pub department: Option<DepartmentId>,
    pub channel_type: ChannelType,
    /// DC-16 waiver in force (ADR-043).
    pub custody_waiver: bool,
}

/// Import envelope facts (DA-20..DA-25).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeFacts {
    pub tenant: TenantId,
    pub envelope: EnvelopeId,
    pub channel: ChannelId,
    pub department: Option<DepartmentId>,
}

/// Kinds of objects owned by a case (08 §8.5–§8.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChildKind {
    Record,
    Evidence,
    EvidenceUpload,
    Export,
    DeletionRequest,
    UnsealRequest,
    BreakGlassRequest,
    WrapDeletionRequest,
    LegalHold,
}

/// A case-owned object. It carries its owning case by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildFacts {
    pub kind: ChildKind,
    /// Creator / uploader / requester, when the route binds to it.
    pub author: Option<UserId>,
    /// Evidence `kind == original` (DA-55: never removable).
    pub original: bool,
    /// Approvers recorded on the child (DA-73/DA-81 read access).
    pub approvers: [Option<UserId>; 2],
}

/// Admin-API objects (08 §9). They are tenant-bound; the tenant is explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdminKind {
    User,
    Device,
    RoleAssignment,
    Channel,
    Roster,
    CoiMap,
    Workflow,
    RetentionPolicy,
    Config,
    ConfigChange,
    Audit,
    Health,
    Reports,
    Backup,
    Update,
    SupportBundle,
    RecoveryQuorum,
    Onion,
}

/// The object of a decision. Every variant carries its tenant; case-level
/// variants carry their owning case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Object<'a> {
    /// Tenant-level desk action (lists, `me`, sync, SLA summary).
    Tenant(TenantId),
    Channel(&'a ChannelFacts),
    Envelope(&'a EnvelopeFacts),
    Case(&'a CaseFacts<'a>),
    CaseChild(&'a CaseFacts<'a>, ChildFacts),
    Admin(TenantId, AdminKind),
}

impl Object<'_> {
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        match self {
            Object::Tenant(t) | Object::Admin(t, _) => *t,
            Object::Channel(c) => c.tenant,
            Object::Envelope(e) => e.tenant,
            Object::Case(c) | Object::CaseChild(c, _) => c.tenant,
        }
    }

    #[must_use]
    pub const fn case(&self) -> Option<&CaseFacts<'_>> {
        match self {
            Object::Case(c) | Object::CaseChild(c, _) => Some(c),
            _ => None,
        }
    }

    #[must_use]
    pub const fn channel(&self) -> Option<ChannelId> {
        match self {
            Object::Channel(c) => Some(c.channel),
            Object::Envelope(e) => Some(e.channel),
            Object::Case(c) | Object::CaseChild(c, _) => Some(c.channel),
            Object::Tenant(_) | Object::Admin(..) => None,
        }
    }

    /// Resource-bound objects answer deny with a uniform 404 (08 §3.3).
    #[must_use]
    pub const fn is_resource(&self) -> bool {
        !matches!(self, Object::Tenant(_) | Object::Admin(..))
    }
}

/// A fresh step-up assertion already verified by C-21 (15 §4.7; DA-06).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepUpProof {
    pub action: Permission,
    pub op: OpDigest,
    pub issued_at: Seconds,
    /// Single use: a consumed proof satisfies nothing.
    pub consumed: bool,
}

/// One approver of a dual-control approval, with facts verified by C-10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Approver {
    pub user: UserId,
    pub person: PersonRef,
    pub roles: &'static [Role],
    pub independent: bool,
    /// WebAuthn transaction confirmation present and bound to the operation.
    pub step_up: bool,
    /// Approver's blinded tag for the object's case (blind COI check).
    pub excl_tag: Option<ExclTag>,
}

/// `Approval` object (15 §5.8): single-use, 24 h expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval<'a> {
    pub op: OpDigest,
    pub proposer: PersonRef,
    pub approvers: &'a [Approver],
    pub expires_at: Seconds,
    pub consumed: bool,
}

/// Request context (15 §5.3 environment attributes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context<'a> {
    pub today: Day,
    pub now: Seconds,
    /// Digest of the operation descriptor for this request.
    pub op: OpDigest,
    pub step_up: Option<StepUpProof>,
    pub approval: Option<&'a Approval<'a>>,
    /// The requesting Desk's own blinded tag for the target case, when the
    /// route supplies one (DA-70). Tested blindly like an ACL tag.
    pub subject_excl_tag: Option<ExclTag>,
}

/// Candidate recipient for key-wrap verification (07 §5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrapCandidate {
    pub user: UserId,
    pub key: KeyId,
    pub excl_tag: ExclTag,
}
