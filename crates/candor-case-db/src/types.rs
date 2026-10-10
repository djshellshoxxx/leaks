// SPDX-License-Identifier: AGPL-3.0-or-later
//! Opaque identifiers, days, principals, pagination. Every id is a random
//! 128-bit value (UUID v4 layout); parsing is strict (36-char lowercase
//! hyphenated form only) and never panics.

use core::fmt;

use uuid::Uuid;

use crate::error::{DbError, Result};

/// Fill `b` from the OS CSPRNG (fail closed).
pub(crate) fn fill_random(b: &mut [u8]) -> Result<()> {
    getrandom::fill(b).map_err(|_| DbError::Rng)
}

fn random_uuid() -> Result<Uuid> {
    let mut b = [0u8; 16];
    fill_random(&mut b)?;
    Ok(uuid::Builder::from_random_bytes(b).into_uuid())
}

/// Strict UUID parse: exactly the hyphenated lowercase form.
fn parse_strict(s: &str) -> Result<Uuid> {
    if s.len() != 36 || s.bytes().any(|c| c.is_ascii_uppercase()) {
        return Err(DbError::InvalidInput("id format"));
    }
    Uuid::try_parse(s).map_err(|_| DbError::InvalidInput("id format"))
}

macro_rules! id_type {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Uuid);

        impl $name {
            /// New random id.
            pub fn random() -> Result<Self> {
                random_uuid().map(Self)
            }
            /// Wrap raw bytes (e.g. from a verified token).
            #[must_use]
            pub const fn from_bytes(b: [u8; 16]) -> Self {
                Self(Uuid::from_bytes(b))
            }
            /// Raw bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }
            /// Strict parse of the hyphenated lowercase form.
            pub fn parse(s: &str) -> Result<Self> {
                parse_strict(s).map(Self)
            }
            pub(crate) const fn uuid(&self) -> Uuid {
                self.0
            }
            /// The all-zero id (system principals, 09 §6.1).
            #[must_use]
            pub const fn nil() -> Self {
                Self(Uuid::nil())
            }
            /// Whether this is the all-zero id.
            #[must_use]
            pub fn is_nil(&self) -> bool {
                self.0.is_nil()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0.as_hyphenated())
            }
        }

        // Ids are opaque, never source-linked content; Debug shows the type only.
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

id_type!(
    /// Tenant.
    TenantId
);
id_type!(
    /// Staff user (`core.app_user`).
    UserId
);
id_type!(
    /// Channel.
    ChannelId
);
id_type!(
    /// Case.
    CaseId
);
id_type!(
    /// Imported envelope (new random id, never the intake ref).
    ImportEnvelopeId
);
id_type!(
    /// Message.
    MessageId
);
id_type!(
    /// Evidence object.
    EvidenceId
);
id_type!(
    /// Blob.
    BlobId
);
id_type!(
    /// Job.
    JobId
);
id_type!(
    /// Legal hold.
    HoldId
);
id_type!(
    /// A request row (break-glass, wrap deletion, deletion).
    RequestId
);
id_type!(
    /// Retention policy.
    RetentionPolicyId
);
id_type!(
    /// Workflow definition.
    WorkflowDefId
);
id_type!(
    /// SLA timer.
    TimerId
);
id_type!(
    /// Notification queue row.
    NotifId
);
id_type!(
    /// Device.
    DeviceId
);

/// A UTC calendar day as days since 1970-01-01 (bound as `DATE '1970-01-01' + n`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Day(pub u32);

impl Day {
    /// Largest supported day number (year 9999).
    pub const MAX: u32 = 2_932_896;

    /// Validate the range.
    pub fn new(n: u32) -> Result<Self> {
        if n > Self::MAX {
            return Err(DbError::InvalidInput("day out of range"));
        }
        Ok(Self(n))
    }
    pub(crate) fn i32(self) -> Result<i32> {
        i32::try_from(self.0).map_err(|_| DbError::InvalidInput("day out of range"))
    }
    pub(crate) fn from_i32(d: i32) -> Result<Self> {
        u32::try_from(d)
            .ok()
            .filter(|n| *n <= Self::MAX)
            .map(Self)
            .ok_or(DbError::Integrity("day"))
    }
    /// Days after this day (checked).
    pub fn plus(self, n: u32) -> Result<Self> {
        self.0
            .checked_add(n)
            .ok_or(DbError::InvalidInput("day out of range"))
            .and_then(Self::new)
    }
}

/// Registered job kinds (07 §6.2); the only values `core.job.kind` accepts.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum JobKind {
    NotifyDailyDigest,
    SlaEvaluate,
    RetentionEvaluate,
    CryptoEraseCase,
    ImportEscalate,
    EkvBackup,
    EpochRunwayCheck,
    EpochKeyDestroy,
    BlobGc,
    ChaffDiscard,
    EkRewrapPending,
    DeletionListPrune,
    EkvReplicate,
    KdTimelockActivate,
    KdWeeklyPublish,
    WrapDeletionExecute,
    RecordsGrantExpire,
    TimestampRetention,
    AuditCheckpoint,
    AuditAnchor,
    AuditReconcile,
    KdCheckpointPublish,
    KdWitnessCosign,
    BackupRun,
    BackupVerify,
    SessionGc,
    BreakglassExpire,
    BreakglassReviewDue,
    ExportDelivery,
    ExportExpire,
    LegalHoldReview,
    CountersRollup,
    UpdateCheck,
    IdempotencyGc,
}

impl JobKind {
    /// Every registered kind.
    pub const ALL: [JobKind; 34] = [
        Self::NotifyDailyDigest,
        Self::SlaEvaluate,
        Self::RetentionEvaluate,
        Self::CryptoEraseCase,
        Self::ImportEscalate,
        Self::EkvBackup,
        Self::EpochRunwayCheck,
        Self::EpochKeyDestroy,
        Self::BlobGc,
        Self::ChaffDiscard,
        Self::EkRewrapPending,
        Self::DeletionListPrune,
        Self::EkvReplicate,
        Self::KdTimelockActivate,
        Self::KdWeeklyPublish,
        Self::WrapDeletionExecute,
        Self::RecordsGrantExpire,
        Self::TimestampRetention,
        Self::AuditCheckpoint,
        Self::AuditAnchor,
        Self::AuditReconcile,
        Self::KdCheckpointPublish,
        Self::KdWitnessCosign,
        Self::BackupRun,
        Self::BackupVerify,
        Self::SessionGc,
        Self::BreakglassExpire,
        Self::BreakglassReviewDue,
        Self::ExportDelivery,
        Self::ExportExpire,
        Self::LegalHoldReview,
        Self::CountersRollup,
        Self::UpdateCheck,
        Self::IdempotencyGc,
    ];

    /// The `core.job.kind` text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotifyDailyDigest => "notify_daily_digest",
            Self::SlaEvaluate => "sla_evaluate",
            Self::RetentionEvaluate => "retention_evaluate",
            Self::CryptoEraseCase => "crypto_erase_case",
            Self::ImportEscalate => "import_escalate",
            Self::EkvBackup => "ekv_backup",
            Self::EpochRunwayCheck => "epoch_runway_check",
            Self::EpochKeyDestroy => "epoch_key_destroy",
            Self::BlobGc => "blob_gc",
            Self::ChaffDiscard => "chaff_discard",
            Self::EkRewrapPending => "ek_rewrap_pending",
            Self::DeletionListPrune => "deletion_list_prune",
            Self::EkvReplicate => "ekv_replicate",
            Self::KdTimelockActivate => "kd_timelock_activate",
            Self::KdWeeklyPublish => "kd_weekly_publish",
            Self::WrapDeletionExecute => "wrap_deletion_execute",
            Self::RecordsGrantExpire => "records_grant_expire",
            Self::TimestampRetention => "timestamp_retention",
            Self::AuditCheckpoint => "audit_checkpoint",
            Self::AuditAnchor => "audit_anchor",
            Self::AuditReconcile => "audit_reconcile",
            Self::KdCheckpointPublish => "kd_checkpoint_publish",
            Self::KdWitnessCosign => "kd_witness_cosign",
            Self::BackupRun => "backup_run",
            Self::BackupVerify => "backup_verify",
            Self::SessionGc => "session_gc",
            Self::BreakglassExpire => "breakglass_expire",
            Self::BreakglassReviewDue => "breakglass_review_due",
            Self::ExportDelivery => "export_delivery",
            Self::ExportExpire => "export_expire",
            Self::LegalHoldReview => "legal_hold_review",
            Self::CountersRollup => "counters_rollup",
            Self::UpdateCheck => "update_check",
            Self::IdempotencyGc => "idempotency_gc",
        }
    }

    /// Parse the `core.job.kind` text.
    pub fn parse(s: &str) -> Result<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|k| k.as_str() == s)
            .ok_or(DbError::InvalidInput("job kind"))
    }
}

/// Kind of the authenticated principal (09 §6.1 `candor.principal_kind`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum PrincipalKind {
    Desk,
    Admin,
    Relay,
    Worker(JobKind),
    Notify,
    Kd,
    Auth,
    AuditWriter,
    AuditReader,
    Monitor,
}

impl PrincipalKind {
    /// The GUC text (`worker:<job_kind>` for workers).
    #[must_use]
    pub fn guc_value(self) -> String {
        match self {
            Self::Desk => "desk".into(),
            Self::Admin => "admin".into(),
            Self::Relay => "relay".into(),
            Self::Worker(k) => format!("worker:{}", k.as_str()),
            Self::Notify => "notify".into(),
            Self::Kd => "kd".into(),
            Self::Auth => "auth".into(),
            Self::AuditWriter => "audit_w".into(),
            Self::AuditReader => "audit_r".into(),
            Self::Monitor => "monitor".into(),
        }
    }

    /// Whether a suspended tenant still serves this principal (operators and
    /// maintenance only; staff, relay and notifications are refused).
    #[must_use]
    pub const fn serves_suspended(self) -> bool {
        matches!(
            self,
            Self::Admin | Self::Worker(_) | Self::AuditWriter | Self::AuditReader | Self::Monitor
        )
    }

    /// Whether this is a system principal (nil user id, 09 §6.1).
    #[must_use]
    pub const fn is_system(self) -> bool {
        !matches!(self, Self::Desk | Self::Admin)
    }
}

/// The authenticated principal a transaction runs as. Built by the service
/// from a verified token (08 §3.1), never from request input.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Principal {
    tenant: TenantId,
    user: UserId,
    kind: PrincipalKind,
}

impl Principal {
    /// A staff principal (Desk or Admin) with a real user id.
    pub fn staff(tenant: TenantId, user: UserId, kind: PrincipalKind) -> Result<Self> {
        if tenant.is_nil() || user.is_nil() || kind.is_system() {
            return Err(DbError::InvalidInput("principal"));
        }
        Ok(Self { tenant, user, kind })
    }
    /// A system principal (nil user id).
    pub fn system(tenant: TenantId, kind: PrincipalKind) -> Result<Self> {
        if tenant.is_nil() || !kind.is_system() {
            return Err(DbError::InvalidInput("principal"));
        }
        Ok(Self {
            tenant,
            user: UserId::nil(),
            kind,
        })
    }
    /// A system principal of the admin service (nil user; bootstrap only).
    pub(crate) fn admin_system(tenant: TenantId) -> Result<Self> {
        if tenant.is_nil() {
            return Err(DbError::InvalidInput("principal"));
        }
        Ok(Self {
            tenant,
            user: UserId::nil(),
            kind: PrincipalKind::Admin,
        })
    }
    /// Tenant.
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// User (nil for system principals).
    #[must_use]
    pub const fn user(&self) -> UserId {
        self.user
    }
    /// Kind.
    #[must_use]
    pub const fn kind(&self) -> PrincipalKind {
        self.kind
    }
}

/// Bounded page size for keyset pagination.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PageSize(u16);

impl PageSize {
    /// Largest page any list method returns.
    pub const MAX: u16 = 200;
    /// Default page.
    pub const DEFAULT: PageSize = PageSize(50);

    /// `1..=MAX`.
    pub fn new(n: u16) -> Result<Self> {
        if n == 0 || n > Self::MAX {
            return Err(DbError::InvalidInput("page size"));
        }
        Ok(Self(n))
    }
    /// Value.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
    pub(crate) const fn limit(self) -> i64 {
        self.0 as i64
    }
}

impl Default for PageSize {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Keyset cursor: the last id of the previous page (opaque to callers).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cursor(pub [u8; 16]);

impl Cursor {
    pub(crate) const fn uuid(&self) -> Uuid {
        Uuid::from_bytes(self.0)
    }
}

/// A page of rows plus the cursor for the next page (None at the end).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Page<T> {
    /// Rows, at most `PageSize` of them.
    pub items: Vec<T>,
    /// Cursor to pass as `after` for the next page.
    pub next: Option<Cursor>,
}

impl<T> Page<T> {
    pub(crate) fn new(items: Vec<T>, size: PageSize, key: impl Fn(&T) -> [u8; 16]) -> Self {
        let next = if items.len() >= usize::from(size.get()) {
            items.last().map(|t| Cursor(key(t)))
        } else {
            None
        };
        Self { items, next }
    }
}

/// Bound a byte slice to `1..=max` bytes before binding (hostile-input rule).
pub(crate) fn bounded<'a>(b: &'a [u8], max: usize, what: &'static str) -> Result<&'a [u8]> {
    if b.is_empty() || b.len() > max {
        return Err(DbError::InvalidInput(what));
    }
    Ok(b)
}

/// Bound a text field to `1..=max` characters, no control characters.
pub(crate) fn bounded_text<'a>(s: &'a str, max: usize, what: &'static str) -> Result<&'a str> {
    let n = s.chars().count();
    if n == 0 || n > max || s.chars().any(char::is_control) {
        return Err(DbError::InvalidInput(what));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_parse_strict() {
        let id = CaseId::random().unwrap();
        let s = id.to_string();
        assert_eq!(CaseId::parse(&s).unwrap(), id);
        assert!(CaseId::parse(&s.to_uppercase()).is_err());
        assert!(CaseId::parse(&s.replace('-', "")).is_err());
        assert!(CaseId::parse("").is_err());
        assert_eq!(format!("{id:?}"), "CaseId(..)");
    }

    #[test]
    fn page_size_bounds() {
        assert!(PageSize::new(0).is_err());
        assert!(PageSize::new(201).is_err());
        assert_eq!(PageSize::new(200).unwrap().get(), 200);
    }

    #[test]
    fn principal_rules() {
        let t = TenantId::random().unwrap();
        let u = UserId::random().unwrap();
        assert!(Principal::staff(t, u, PrincipalKind::Desk).is_ok());
        assert!(Principal::staff(t, UserId::nil(), PrincipalKind::Desk).is_err());
        assert!(Principal::staff(t, u, PrincipalKind::Relay).is_err());
        assert!(Principal::system(t, PrincipalKind::Desk).is_err());
        assert!(Principal::system(TenantId::nil(), PrincipalKind::Relay).is_err());
        let p = Principal::system(t, PrincipalKind::Worker(JobKind::BlobGc)).unwrap();
        assert_eq!(p.kind().guc_value(), "worker:blob_gc");
        assert!(p.user().is_nil());
    }

    #[test]
    fn job_kind_round_trip() {
        for k in JobKind::ALL {
            assert_eq!(JobKind::parse(k.as_str()).unwrap(), k);
        }
        assert!(JobKind::parse("rm_rf").is_err());
    }

    #[test]
    fn day_bounds() {
        assert!(Day::new(Day::MAX + 1).is_err());
        assert!(Day::from_i32(-1).is_err());
        assert_eq!(Day::new(10).unwrap().plus(5).unwrap(), Day(15));
        assert!(Day(Day::MAX).plus(1).is_err());
    }
}
