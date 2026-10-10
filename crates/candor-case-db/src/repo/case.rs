// SPDX-License-Identifier: AGPL-3.0-or-later
//! `core.case`, `core.case_member`, `core.case_key_wrap`, `core.coi_excl_tag`,
//! `core.case_state_history` (09 §5.2.4, §5.2.5; ADR-033 §3, ADR-037(3)).

use crate::error::{DbError, Result, db};
use crate::repo::{
    get_bool, get_bytes, get_day, get_opt_day, get_string, get_u16, get_u32, get_u64, get_uuid,
    i32_of, i64_of, one,
};
use crate::tx::TenantTx;
use crate::types::{
    CaseId, ChannelId, Cursor, Day, Page, PageSize, RetentionPolicyId, UserId, WorkflowDefId,
    bounded, bounded_text, fill_random,
};

/// `record_ct` bound (09 §5.2.4).
pub const MAX_RECORD_CT: usize = 256 * 1024;
/// `wrap_ct` bound.
pub const MAX_WRAP_CT: usize = 2048;
/// Tags per case are a multiple of this (ADR-037(3)).
pub const COI_TAG_GROUP: usize = 8;
/// Largest tag set accepted per case.
pub const MAX_COI_TAGS: usize = 64;

/// ACL access level.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AccessLevel {
    Read,
    Contribute,
    Lead,
    Records,
}

impl AccessLevel {
    /// Enum text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Contribute => "contribute",
            Self::Lead => "lead",
            Self::Records => "records",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "read" => Self::Read,
            "contribute" => Self::Contribute,
            "lead" => Self::Lead,
            "records" => Self::Records,
            _ => return Err(DbError::Integrity("enum")),
        })
    }
}

/// ACL membership state (ADR-044(1)).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CaseMemberState {
    Active,
    Suspended,
    Revoked,
}

impl CaseMemberState {
    /// Enum text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "active" => Self::Active,
            "suspended" => Self::Suspended,
            "revoked" => Self::Revoked,
            _ => return Err(DbError::Integrity("enum")),
        })
    }
}

/// A case-key wrap to store (already sealed under the Erasure Key by
/// `candor-ekv`, ADR-033 §3).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NewWrap {
    pub recipient_key_id: [u8; 16],
    /// None for the Recovery Quorum wrap (ADR-013).
    pub recipient_user_id: Option<UserId>,
    pub wrap_ct: Vec<u8>,
}

/// Case creation input. The creator becomes the first `lead` member.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NewCase {
    pub case_id: CaseId,
    pub channel_id: ChannelId,
    pub workflow_def_id: WorkflowDefId,
    pub workflow_version: u32,
    pub initial_state: String,
    pub priority: u8,
    /// `import_date` of the initial envelope (fixed-slot date, ADR-038).
    pub received_date: Day,
    pub opened_day: Day,
    pub record_ct: Vec<u8>,
    pub retention_policy_id: RetentionPolicyId,
    pub wraps: Vec<NewWrap>,
    /// Blinded COI tags, a multiple of 8 (padding tags included).
    pub coi_tags: Vec<[u8; 32]>,
}

/// Case row (workflow view; `record_ct` fetched separately).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Case {
    pub case_id: CaseId,
    pub display_ref: String,
    pub channel_id: ChannelId,
    pub workflow_def_id: WorkflowDefId,
    pub workflow_version: u32,
    pub state: String,
    pub priority: u8,
    pub received_date: Day,
    pub last_import_month: Day,
    pub opened_day: Day,
    pub closed_day: Option<Day>,
    pub key_epoch: u32,
    pub retention_policy_id: RetentionPolicyId,
    pub deletion_due_day: Option<Day>,
    pub legal_hold: bool,
    pub ek_missing: bool,
    pub version: u64,
}

/// ACL row.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CaseMember {
    pub user_id: UserId,
    pub access_level: AccessLevel,
    pub breakglass: bool,
    pub valid_until_day: Option<Day>,
    pub state: CaseMemberState,
    pub version: u64,
}

const SQL_INSERT: &str = "INSERT INTO core.\"case\" (tenant_id, case_id, display_ref, channel_id, workflow_def_id, workflow_version, state, \
     priority, received_date, last_import_month, opened_day, record_ct, key_epoch, retention_policy_id) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, DATE '1970-01-01' + $9::int4, \
     pg_catalog.date_trunc('month', DATE '1970-01-01' + $9::int4)::date, DATE '1970-01-01' + $10::int4, $11, 0, $12) \
     ON CONFLICT DO NOTHING";
const SQL_GET: &str = "SELECT case_id, display_ref, channel_id, workflow_def_id, workflow_version, state, priority, \
     (received_date - DATE '1970-01-01')::int4, (last_import_month - DATE '1970-01-01')::int4, \
     (opened_day - DATE '1970-01-01')::int4, (closed_day - DATE '1970-01-01')::int4, key_epoch, retention_policy_id, \
     (deletion_due_day - DATE '1970-01-01')::int4, legal_hold, ek_missing, version \
     FROM core.\"case\" WHERE tenant_id = $1 AND case_id = $2";
const SQL_LIST: &str = "SELECT case_id, display_ref, channel_id, workflow_def_id, workflow_version, state, priority, \
     (received_date - DATE '1970-01-01')::int4, (last_import_month - DATE '1970-01-01')::int4, \
     (opened_day - DATE '1970-01-01')::int4, (closed_day - DATE '1970-01-01')::int4, key_epoch, retention_policy_id, \
     (deletion_due_day - DATE '1970-01-01')::int4, legal_hold, ek_missing, version \
     FROM core.\"case\" WHERE tenant_id = $1 AND case_id > $2 ORDER BY case_id LIMIT $3";
const SQL_RECORD: &str =
    "SELECT record_ct FROM core.\"case\" WHERE tenant_id = $1 AND case_id = $2";
const SQL_SET_RECORD: &str = "UPDATE core.\"case\" SET record_ct = $4, version = $3 + 1 \
     WHERE tenant_id = $1 AND case_id = $2 AND version = $3";
const SQL_TRANSITION: &str = "UPDATE core.\"case\" SET state = $4, version = $3 + 1 \
     WHERE tenant_id = $1 AND case_id = $2 AND version = $3 AND state = $5";
const SQL_HISTORY: &str = "INSERT INTO core.case_state_history (tenant_id, case_id, seq, from_state, to_state, transition_id, actor_user_id, day) \
     SELECT $1, $2, COALESCE(max(seq) + 1, 0), $3, $4, $5, $6, DATE '1970-01-01' + $7::int4 \
     FROM core.case_state_history WHERE tenant_id = $1 AND case_id = $2";
const SQL_CLOSE: &str = "UPDATE core.\"case\" SET closed_day = DATE '1970-01-01' + $4::int4, deletion_due_day = DATE '1970-01-01' + $5::int4, \
     version = $3 + 1 WHERE tenant_id = $1 AND case_id = $2 AND version = $3 AND closed_day IS NULL";
const SQL_SET_EK_MISSING: &str = "UPDATE core.\"case\" SET ek_missing = $4, version = $3 + 1 \
     WHERE tenant_id = $1 AND case_id = $2 AND version = $3";
const SQL_DUE: &str = "SELECT case_id FROM core.\"case\" WHERE tenant_id = $1 AND deletion_due_day <= DATE '1970-01-01' + $2::int4 \
     AND NOT legal_hold AND case_id > $3 ORDER BY case_id LIMIT $4";
const SQL_DELETE: &str =
    "DELETE FROM core.\"case\" WHERE tenant_id = $1 AND case_id = $2 AND NOT legal_hold";
const SQL_MEMBER_INSERT: &str = "INSERT INTO core.case_member (tenant_id, case_id, user_id, access_level, via, grant_ref, valid_until_day, state) \
     VALUES ($1, $2, $3, $4::text::core.access_level, $5::text::core.member_via, $6, DATE '1970-01-01' + $7::int4, 'active') \
     ON CONFLICT DO NOTHING";
const SQL_MEMBERS: &str = "SELECT user_id, access_level::text, via = 'breakglass', (valid_until_day - DATE '1970-01-01')::int4, \
     state::text, version FROM core.case_member WHERE tenant_id = $1 AND case_id = $2 ORDER BY user_id";
const SQL_MEMBER_STATE: &str = "UPDATE core.case_member SET state = $5::text::core.case_member_state, version = $4 + 1 \
     WHERE tenant_id = $1 AND case_id = $2 AND user_id = $3 AND version = $4";
const SQL_WRAP_INSERT: &str = "INSERT INTO core.case_key_wrap (tenant_id, case_id, key_epoch, recipient_key_id, recipient_user_id, wrap_ct, wrapped_by) \
     VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING";
const SQL_WRAP_OWN: &str = "SELECT key_epoch, recipient_key_id, wrap_ct FROM core.case_key_wrap \
     WHERE tenant_id = $1 AND case_id = $2 AND recipient_user_id = $3 ORDER BY key_epoch DESC, recipient_key_id";
const SQL_WRAP_HOLDERS: &str = "SELECT count(DISTINCT recipient_user_id) FROM core.case_key_wrap \
     WHERE tenant_id = $1 AND case_id = $2 AND key_epoch = $3 AND recipient_user_id IS NOT NULL";
const SQL_WRAP_DELETE_ALL: &str =
    "DELETE FROM core.case_key_wrap WHERE tenant_id = $1 AND case_id = $2";
const SQL_WRAP_DELETE_USER: &str = "DELETE FROM core.case_key_wrap WHERE tenant_id = $1 AND case_id = $2 AND recipient_user_id = $3";
const SQL_TAG_INSERT: &str = "INSERT INTO core.coi_excl_tag (tenant_id, case_id, tag) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING";
const SQL_TAG_PRESENT: &str = "SELECT acl.coi_tag_present($1, $2)";

fn case_row(r: &sqlx::postgres::PgRow) -> Result<Case> {
    Ok(Case {
        case_id: CaseId::from_bytes(get_uuid(r, 0)?),
        display_ref: get_string(r, 1)?,
        channel_id: ChannelId::from_bytes(get_uuid(r, 2)?),
        workflow_def_id: WorkflowDefId::from_bytes(get_uuid(r, 3)?),
        workflow_version: get_u32(r, 4)?,
        state: get_string(r, 5)?,
        priority: u8::try_from(get_u16(r, 6)?).map_err(|_| DbError::Integrity("range"))?,
        received_date: get_day(r, 7)?,
        last_import_month: get_day(r, 8)?,
        opened_day: get_day(r, 9)?,
        closed_day: get_opt_day(r, 10)?,
        key_epoch: get_u32(r, 11)?,
        retention_policy_id: RetentionPolicyId::from_bytes(get_uuid(r, 12)?),
        deletion_due_day: get_opt_day(r, 13)?,
        legal_hold: get_bool(r, 14)?,
        ek_missing: get_bool(r, 15)?,
        version: get_u64(r, 16)?,
    })
}

/// Random 40-bit display reference, 8 base32 characters (A–Z, 2–7).
pub fn random_display_ref() -> Result<String> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut b = [0u8; 8];
    fill_random(&mut b)?;
    Ok(b.iter()
        .map(|x| char::from(ALPHABET.get(usize::from(x & 31)).copied().unwrap_or(b'A')))
        .collect())
}

fn check_tags(tags: &[[u8; 32]]) -> Result<()> {
    if tags.is_empty() || tags.len() > MAX_COI_TAGS || !tags.len().is_multiple_of(COI_TAG_GROUP) {
        return Err(DbError::InvalidInput("coi tag count"));
    }
    Ok(())
}

/// Create a case: row, creator as `lead` member, wraps (≥ 1, verified by the
/// service against the candidate set, 07 §5.5) and the blinded tag set.
/// Retries the random `display_ref` on collision.
pub async fn create(tx: &mut TenantTx, c: &NewCase) -> Result<()> {
    let creator = tx.principal().user();
    if creator.is_nil() {
        return Err(DbError::InvalidInput("case creator"));
    }
    bounded(&c.record_ct, MAX_RECORD_CT, "record_ct")?;
    bounded_text(&c.initial_state, 64, "state")?;
    if c.priority > 9 || c.wraps.is_empty() || c.wraps.len() > 64 {
        return Err(DbError::InvalidInput("case shape"));
    }
    check_tags(&c.coi_tags)?;
    for w in &c.wraps {
        bounded(&w.wrap_ct, MAX_WRAP_CT, "wrap_ct")?;
    }
    let mut inserted = false;
    for _ in 0..4 {
        let n = sqlx::query(SQL_INSERT)
            .bind(tx.tenant().uuid())
            .bind(c.case_id.uuid())
            .bind(random_display_ref()?)
            .bind(c.channel_id.uuid())
            .bind(c.workflow_def_id.uuid())
            .bind(i32_of(c.workflow_version)?)
            .bind(c.initial_state.as_str())
            .bind(i16::from(c.priority))
            .bind(c.received_date.i32()?)
            .bind(c.opened_day.i32()?)
            .bind(c.record_ct.as_slice())
            .bind(c.retention_policy_id.uuid())
            .execute(tx.conn())
            .await;
        match n.map(|r| r.rows_affected()) {
            Ok(1) => {
                inserted = true;
                break;
            }
            Ok(_) => return Err(DbError::AlreadyExists),
            Err(e) => match db(e) {
                DbError::AlreadyExists => continue,
                other => return Err(other),
            },
        }
    }
    if !inserted {
        return Err(DbError::AlreadyExists);
    }
    let n = sqlx::query(SQL_MEMBER_INSERT)
        .bind(tx.tenant().uuid())
        .bind(c.case_id.uuid())
        .bind(creator.uuid())
        .bind(AccessLevel::Lead.as_str())
        .bind("normal")
        .bind(Option::<uuid::Uuid>::None)
        .bind(Option::<i32>::None)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::Integrity("creator membership"))?;
    for w in &c.wraps {
        insert_wrap(tx, c.case_id, 0, w).await?;
    }
    for t in &c.coi_tags {
        sqlx::query(SQL_TAG_INSERT)
            .bind(tx.tenant().uuid())
            .bind(c.case_id.uuid())
            .bind(t.as_slice())
            .execute(tx.conn())
            .await
            .map_err(db)?;
    }
    Ok(())
}

/// IDOR-safe lookup (RLS additionally restricts to ACL members).
pub async fn get(tx: &mut TenantTx, id: CaseId) -> Result<Case> {
    let r = sqlx::query(SQL_GET)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
        .ok_or(DbError::NotFound)?;
    case_row(&r)
}

/// Keyset page of the caller's visible cases.
pub async fn list(tx: &mut TenantTx, after: Option<Cursor>, size: PageSize) -> Result<Page<Case>> {
    let rows = sqlx::query(SQL_LIST)
        .bind(tx.tenant().uuid())
        .bind(after.unwrap_or(Cursor([0; 16])).uuid())
        .bind(size.limit())
        .fetch_all(tx.conn())
        .await
        .map_err(db)?;
    let items = rows.iter().map(case_row).collect::<Result<Vec<_>>>()?;
    Ok(Page::new(items, size, |c| *c.case_id.as_bytes()))
}

/// The encrypted case record.
pub async fn record_ct(tx: &mut TenantTx, id: CaseId) -> Result<Vec<u8>> {
    let r = sqlx::query(SQL_RECORD)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
        .ok_or(DbError::NotFound)?;
    get_bytes(&r, 0)
}

/// Replace the encrypted case record, optimistic on `version`.
pub async fn set_record_ct(
    tx: &mut TenantTx,
    id: CaseId,
    version: u64,
    record_ct: &[u8],
) -> Result<()> {
    bounded(record_ct, MAX_RECORD_CT, "record_ct")?;
    let n = sqlx::query(SQL_SET_RECORD)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(i64_of(version)?)
        .bind(record_ct)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::VersionConflict)
}

/// Workflow transition with history row (14; exact time only in audit).
pub async fn transition(
    tx: &mut TenantTx,
    id: CaseId,
    version: u64,
    from_state: &str,
    to_state: &str,
    transition_id: &str,
    day: Day,
) -> Result<()> {
    bounded_text(from_state, 64, "state")?;
    bounded_text(to_state, 64, "state")?;
    bounded_text(transition_id, 64, "transition")?;
    let actor = tx.principal().user();
    if actor.is_nil() {
        return Err(DbError::InvalidInput("transition actor"));
    }
    let n = sqlx::query(SQL_TRANSITION)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(i64_of(version)?)
        .bind(to_state)
        .bind(from_state)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::VersionConflict)?;
    let n = sqlx::query(SQL_HISTORY)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(from_state)
        .bind(to_state)
        .bind(transition_id)
        .bind(actor.uuid())
        .bind(day.i32()?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::Integrity("history"))
}

/// Close the case and schedule deletion per its retention policy.
pub async fn close(tx: &mut TenantTx, id: CaseId, version: u64, closed_day: Day) -> Result<Day> {
    let c = get(tx, id).await?;
    let (days, _) = super::channel::get_retention_policy(tx, c.retention_policy_id).await?;
    let due = closed_day.plus(u32::from(days))?;
    let n = sqlx::query(SQL_CLOSE)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(i64_of(version)?)
        .bind(closed_day.i32()?)
        .bind(due.i32()?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::VersionConflict)?;
    Ok(due)
}

/// Mark the Erasure Key missing/restored after a vault incident (ADR-047(7)).
pub async fn set_ek_missing(
    tx: &mut TenantTx,
    id: CaseId,
    version: u64,
    missing: bool,
) -> Result<()> {
    let n = sqlx::query(SQL_SET_EK_MISSING)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(i64_of(version)?)
        .bind(missing)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::VersionConflict)
}

/// Cases whose deletion is due on or before `today` and not on legal hold
/// (worker `retention_evaluate`).
pub async fn deletion_due(
    tx: &mut TenantTx,
    today: Day,
    after: Option<Cursor>,
    size: PageSize,
) -> Result<Page<CaseId>> {
    let rows = sqlx::query(SQL_DUE)
        .bind(tx.tenant().uuid())
        .bind(today.i32()?)
        .bind(after.unwrap_or(Cursor([0; 16])).uuid())
        .bind(size.limit())
        .fetch_all(tx.conn())
        .await
        .map_err(db)?;
    let items = rows
        .iter()
        .map(|r| get_uuid(r, 0).map(CaseId::from_bytes))
        .collect::<Result<Vec<_>>>()?;
    Ok(Page::new(items, size, |c| *c.as_bytes()))
}

/// Delete the case row and everything cascading from it (worker
/// `crypto_erase_case`, after the vault DESTROY). Refused under legal hold.
pub async fn erase(tx: &mut TenantTx, id: CaseId) -> Result<()> {
    let n = sqlx::query(SQL_DELETE)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::NotFound)
}

/// Add an ACL member (normal or records grant; break-glass via `breakglass`).
pub async fn add_member(
    tx: &mut TenantTx,
    id: CaseId,
    user: UserId,
    level: AccessLevel,
    valid_until_day: Option<Day>,
) -> Result<()> {
    let via = if level == AccessLevel::Records {
        "records_grant"
    } else {
        "normal"
    };
    let n = sqlx::query(SQL_MEMBER_INSERT)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(user.uuid())
        .bind(level.as_str())
        .bind(via)
        .bind(Option::<uuid::Uuid>::None)
        .bind(valid_until_day.map(Day::i32).transpose()?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// ACL of a case.
pub async fn members(tx: &mut TenantTx, id: CaseId) -> Result<Vec<CaseMember>> {
    let rows = sqlx::query(SQL_MEMBERS)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .fetch_all(tx.conn())
        .await
        .map_err(db)?;
    rows.iter()
        .map(|r| {
            Ok(CaseMember {
                user_id: UserId::from_bytes(get_uuid(r, 0)?),
                access_level: AccessLevel::parse(&get_string(r, 1)?)?,
                breakglass: get_bool(r, 2)?,
                valid_until_day: get_opt_day(r, 3)?,
                state: CaseMemberState::parse(&get_string(r, 4)?)?,
                version: get_u64(r, 5)?,
            })
        })
        .collect()
}

/// Suspend/revoke/reactivate a member (server-side authorization only;
/// wraps stay until a `wrap_deletion_request` executes, ADR-044(1)).
pub async fn set_member_state(
    tx: &mut TenantTx,
    id: CaseId,
    user: UserId,
    version: u64,
    state: CaseMemberState,
) -> Result<()> {
    let n = sqlx::query(SQL_MEMBER_STATE)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(user.uuid())
        .bind(i64_of(version)?)
        .bind(state.as_str())
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::VersionConflict)
}

/// Store one EK-sealed wrap for `key_epoch`.
pub async fn insert_wrap(tx: &mut TenantTx, id: CaseId, key_epoch: u32, w: &NewWrap) -> Result<()> {
    bounded(&w.wrap_ct, MAX_WRAP_CT, "wrap_ct")?;
    let by = tx.principal().user();
    let n = sqlx::query(SQL_WRAP_INSERT)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(i32_of(key_epoch)?)
        .bind(w.recipient_key_id.as_slice())
        .bind(w.recipient_user_id.map(|u| u.uuid()))
        .bind(w.wrap_ct.as_slice())
        .bind(by.uuid())
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// The caller's own wraps `(key_epoch, recipient_key_id, wrap_ct)` (RLS
/// hides every other row).
pub async fn own_wraps(tx: &mut TenantTx, id: CaseId) -> Result<Vec<(u32, [u8; 16], Vec<u8>)>> {
    let me = tx.principal().user();
    let rows = sqlx::query(SQL_WRAP_OWN)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(me.uuid())
        .fetch_all(tx.conn())
        .await
        .map_err(db)?;
    rows.iter()
        .map(|r| {
            let kid: Vec<u8> = get_bytes(r, 1)?;
            let kid: [u8; 16] = kid
                .try_into()
                .map_err(|_| DbError::Integrity("column length"))?;
            Ok((get_u32(r, 0)?, kid, get_bytes(r, 2)?))
        })
        .collect()
}

/// Distinct member holders of a wrap at `key_epoch` (`min_recipients`
/// checks, ADR-044(1)/(2)). Not ACL-filtered for the worker.
pub async fn wrap_holders(tx: &mut TenantTx, id: CaseId, key_epoch: u32) -> Result<u64> {
    let r = sqlx::query(SQL_WRAP_HOLDERS)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(i32_of(key_epoch)?)
        .fetch_one(tx.conn())
        .await
        .map_err(db)?;
    get_u64(&r, 0)
}

/// Delete every wrap of the case (worker `crypto_erase_case`).
pub async fn delete_all_wraps(tx: &mut TenantTx, id: CaseId) -> Result<u64> {
    Ok(sqlx::query(SQL_WRAP_DELETE_ALL)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected())
}

/// Delete one member's wraps (worker, executed `wrap_deletion_request`).
pub async fn delete_user_wraps(tx: &mut TenantTx, id: CaseId, user: UserId) -> Result<u64> {
    Ok(sqlx::query(SQL_WRAP_DELETE_USER)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(user.uuid())
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected())
}

/// Blind membership check through the definer function (C-22 only; the
/// caller must be an active member, else the answer is false).
pub async fn coi_tag_present(tx: &mut TenantTx, id: CaseId, tag: &[u8; 32]) -> Result<bool> {
    let r = sqlx::query(SQL_TAG_PRESENT)
        .bind(id.uuid())
        .bind(tag.as_slice())
        .fetch_one(tx.conn())
        .await
        .map_err(db)?;
    get_bool(&r, 0)
}

/// Add a further group of 8 tags (member add with new exclusions).
pub async fn add_coi_tags(tx: &mut TenantTx, id: CaseId, tags: &[[u8; 32]]) -> Result<()> {
    check_tags(tags)?;
    for t in tags {
        sqlx::query(SQL_TAG_INSERT)
            .bind(tx.tenant().uuid())
            .bind(id.uuid())
            .bind(t.as_slice())
            .execute(tx.conn())
            .await
            .map_err(db)?;
    }
    Ok(())
}
