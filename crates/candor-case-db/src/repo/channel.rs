// SPDX-License-Identifier: AGPL-3.0-or-later
//! `core.retention_policy`, `core.workflow_definition`, `core.channel`,
//! `core.channel_member` (09 §5.2.1, §5.2.5).

use crate::error::{DbError, Result, db};
use sqlx::Row;

use crate::repo::{
    get_bool, get_day, get_opt_uuid, get_string, get_u16, get_u32, get_u64, get_uuid, i32_of,
    i64_of, one,
};
use crate::tx::TenantTx;
use crate::types::{
    ChannelId, Cursor, Day, Page, PageSize, RetentionPolicyId, UserId, WorkflowDefId, bounded,
};

/// Largest JSON document (i18n labels) accepted.
const MAX_LABEL_JSON: usize = 16 * 1024;
/// Largest workflow definition.
const MAX_WORKFLOW_JSON: usize = 256 * 1024;

/// ADR-002 channel mode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChannelMode {
    Anonymous,
    Confidential,
    Identified,
}

impl ChannelMode {
    /// Enum text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::Confidential => "confidential",
            Self::Identified => "identified",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "anonymous" => Self::Anonymous,
            "confidential" => Self::Confidential,
            "identified" => Self::Identified,
            _ => return Err(DbError::Integrity("enum")),
        })
    }
}

/// `channel_member.state`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemberState {
    PendingTimelock,
    PendingKeys,
    Active,
    Suspended,
    Removed,
}

impl MemberState {
    /// Enum text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PendingTimelock => "pending_timelock",
            Self::PendingKeys => "pending_keys",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Removed => "removed",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "pending_timelock" => Self::PendingTimelock,
            "pending_keys" => Self::PendingKeys,
            "active" => Self::Active,
            "suspended" => Self::Suspended,
            "removed" => Self::Removed,
            _ => return Err(DbError::Integrity("enum")),
        })
    }
}

/// Retention policy input.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NewRetentionPolicy {
    pub id: RetentionPolicyId,
    /// 30..=3650.
    pub retain_days_after_close: u16,
    pub crypto_erase: bool,
}

/// Channel input.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NewChannel {
    pub id: ChannelId,
    /// UTF-8 JSON object of i18n labels (validated by the service).
    pub public_label_json: String,
    pub mode: ChannelMode,
    pub workflow_def_id: WorkflowDefId,
    pub retention_policy_id: RetentionPolicyId,
    pub reply_enabled: bool,
    /// 2..=16 normally; 1 only as a DANGEROUS config (ADR-044(2)).
    pub min_recipients: u8,
    pub alternative_channel_id: Option<ChannelId>,
    pub independent: bool,
}

/// Channel row.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Channel {
    pub channel_id: ChannelId,
    pub mode: ChannelMode,
    pub workflow_def_id: WorkflowDefId,
    pub retention_policy_id: RetentionPolicyId,
    pub reply_enabled: bool,
    pub min_recipients: u8,
    pub alternative_channel_id: Option<ChannelId>,
    pub independent: bool,
    pub disabled: bool,
    pub version: u64,
}

/// Channel member row (roster, ADR-030).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChannelMember {
    pub channel_id: ChannelId,
    pub user_id: UserId,
    pub show_name: bool,
    pub label_index: u16,
    pub triage: bool,
    pub label_cert_leaf: Option<u64>,
    pub effective_day: Day,
    pub state: MemberState,
    pub version: u64,
}

/// Member input.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NewChannelMember {
    pub channel_id: ChannelId,
    pub user_id: UserId,
    pub role_label_json: String,
    pub show_name: bool,
    pub label_index: u8,
    pub triage: bool,
    pub effective_day: Day,
}

const SQL_RP_INSERT: &str = "INSERT INTO core.retention_policy (tenant_id, retention_policy_id, retain_days_after_close, action, legal_basis_code) \
     VALUES ($1, $2, $3, $4::text::core.retention_action, 'legal_obligation') ON CONFLICT DO NOTHING";
const SQL_RP_GET: &str = "SELECT retain_days_after_close, action = 'crypto_erase' FROM core.retention_policy \
     WHERE tenant_id = $1 AND retention_policy_id = $2";
const SQL_WF_INSERT: &str = "INSERT INTO core.workflow_definition (tenant_id, workflow_def_id, version, definition, state, published_by) \
     VALUES ($1, $2, $3, $4::jsonb, 'published', $5) ON CONFLICT DO NOTHING";
const SQL_WF_GET: &str = "SELECT definition::text FROM core.workflow_definition \
     WHERE tenant_id = $1 AND workflow_def_id = $2 AND version = $3 AND state = 'published'";
const SQL_CH_INSERT: &str = "INSERT INTO core.channel (tenant_id, channel_id, public_label_i18n, mode, workflow_def_id, retention_policy_id, \
     reply_enabled, min_recipients, alternative_channel_id, channel_type) \
     VALUES ($1, $2, $3::jsonb, $4::text::core.channel_mode, $5, $6, $7, $8, $9, $10::text::core.channel_type) ON CONFLICT DO NOTHING";
const SQL_CH_GET: &str = "SELECT channel_id, mode::text, workflow_def_id, retention_policy_id, reply_enabled, min_recipients, \
     alternative_channel_id, channel_type = 'independent', state = 'disabled', version \
     FROM core.channel WHERE tenant_id = $1 AND channel_id = $2";
const SQL_CH_LIST: &str = "SELECT channel_id, mode::text, workflow_def_id, retention_policy_id, reply_enabled, min_recipients, \
     alternative_channel_id, channel_type = 'independent', state = 'disabled', version \
     FROM core.channel WHERE tenant_id = $1 AND channel_id > $2 ORDER BY channel_id LIMIT $3";
const SQL_CH_DISABLE: &str = "UPDATE core.channel SET state = 'disabled', version = $3 + 1 \
     WHERE tenant_id = $1 AND channel_id = $2 AND version = $3";
const SQL_CM_INSERT: &str = "INSERT INTO core.channel_member (tenant_id, channel_id, user_id, role_label_i18n, show_name, label_index, triage, \
     effective_day, state) VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, DATE '1970-01-01' + $8::int4, 'pending_timelock') ON CONFLICT DO NOTHING";
const SQL_CM_LIST: &str = "SELECT channel_id, user_id, show_name, label_index, triage, label_cert_leaf, \
     (effective_day - DATE '1970-01-01')::int4, state::text, version FROM core.channel_member \
     WHERE tenant_id = $1 AND channel_id = $2 ORDER BY label_index";
const SQL_CM_SET_STATE: &str = "UPDATE core.channel_member SET state = $5::text::core.channel_member_state, version = $4 + 1 \
     WHERE tenant_id = $1 AND channel_id = $2 AND user_id = $3 AND version = $4";

fn ch_row(r: &sqlx::postgres::PgRow) -> Result<Channel> {
    Ok(Channel {
        channel_id: ChannelId::from_bytes(get_uuid(r, 0)?),
        mode: ChannelMode::parse(&get_string(r, 1)?)?,
        workflow_def_id: WorkflowDefId::from_bytes(get_uuid(r, 2)?),
        retention_policy_id: RetentionPolicyId::from_bytes(get_uuid(r, 3)?),
        reply_enabled: get_bool(r, 4)?,
        min_recipients: u8::try_from(get_u16(r, 5)?).map_err(|_| DbError::Integrity("range"))?,
        alternative_channel_id: get_opt_uuid(r, 6)?.map(ChannelId::from_bytes),
        independent: get_bool(r, 7)?,
        disabled: get_bool(r, 8)?,
        version: get_u64(r, 9)?,
    })
}

/// Create a retention policy (admin).
pub async fn create_retention_policy(tx: &mut TenantTx, p: &NewRetentionPolicy) -> Result<()> {
    if !(30..=3650).contains(&p.retain_days_after_close) {
        return Err(DbError::InvalidInput("retention days"));
    }
    let n = sqlx::query(SQL_RP_INSERT)
        .bind(tx.tenant().uuid())
        .bind(p.id.uuid())
        .bind(i32::from(p.retain_days_after_close))
        .bind(if p.crypto_erase {
            "crypto_erase"
        } else {
            "review"
        })
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// `(retain_days_after_close, crypto_erase)`.
pub async fn get_retention_policy(tx: &mut TenantTx, id: RetentionPolicyId) -> Result<(u16, bool)> {
    let r = sqlx::query(SQL_RP_GET)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
        .ok_or(DbError::NotFound)?;
    let days = u16::try_from(get_u32(&r, 0)?).map_err(|_| DbError::Integrity("range"))?;
    Ok((days, get_bool(&r, 1)?))
}

/// Publish a workflow definition version (admin). `definition_json` is a
/// UTF-8 JSON document the service has validated against 14's schema.
pub async fn publish_workflow(
    tx: &mut TenantTx,
    id: WorkflowDefId,
    version: u32,
    definition_json: &str,
    published_by: UserId,
) -> Result<()> {
    bounded(
        definition_json.as_bytes(),
        MAX_WORKFLOW_JSON,
        "workflow definition",
    )?;
    if version == 0 {
        return Err(DbError::InvalidInput("workflow version"));
    }
    let n = sqlx::query(SQL_WF_INSERT)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(i32_of(version)?)
        .bind(definition_json)
        .bind(published_by.uuid())
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// The published definition text.
pub async fn get_workflow(tx: &mut TenantTx, id: WorkflowDefId, version: u32) -> Result<String> {
    let r = sqlx::query(SQL_WF_GET)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(i32_of(version)?)
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
        .ok_or(DbError::NotFound)?;
    get_string(&r, 0)
}

/// Create a channel (admin).
pub async fn create(tx: &mut TenantTx, c: &NewChannel) -> Result<()> {
    bounded(
        c.public_label_json.as_bytes(),
        MAX_LABEL_JSON,
        "channel label",
    )?;
    if !(1..=16).contains(&c.min_recipients) {
        return Err(DbError::InvalidInput("min_recipients"));
    }
    if c.mode == ChannelMode::Anonymous && c.alternative_channel_id.is_none() {
        return Err(DbError::InvalidInput(
            "anonymous channel needs an alternative",
        ));
    }
    let n = sqlx::query(SQL_CH_INSERT)
        .bind(tx.tenant().uuid())
        .bind(c.id.uuid())
        .bind(c.public_label_json.as_str())
        .bind(c.mode.as_str())
        .bind(c.workflow_def_id.uuid())
        .bind(c.retention_policy_id.uuid())
        .bind(c.reply_enabled)
        .bind(i16::from(c.min_recipients))
        .bind(c.alternative_channel_id.map(|a| a.uuid()))
        .bind(if c.independent {
            "independent"
        } else {
            "standard"
        })
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// IDOR-safe lookup.
pub async fn get(tx: &mut TenantTx, id: ChannelId) -> Result<Channel> {
    let r = sqlx::query(SQL_CH_GET)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
        .ok_or(DbError::NotFound)?;
    ch_row(&r)
}

/// Keyset page of channels.
pub async fn list(
    tx: &mut TenantTx,
    after: Option<Cursor>,
    size: PageSize,
) -> Result<Page<Channel>> {
    let rows = sqlx::query(SQL_CH_LIST)
        .bind(tx.tenant().uuid())
        .bind(after.unwrap_or(Cursor([0; 16])).uuid())
        .bind(size.limit())
        .fetch_all(tx.conn())
        .await
        .map_err(db)?;
    let items = rows.iter().map(ch_row).collect::<Result<Vec<_>>>()?;
    Ok(Page::new(items, size, |c| *c.channel_id.as_bytes()))
}

/// Soft-disable (never reused), optimistic on `version`.
pub async fn disable(tx: &mut TenantTx, id: ChannelId, version: u64) -> Result<()> {
    let n = sqlx::query(SQL_CH_DISABLE)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(i64_of(version)?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::VersionConflict)
}

/// Add a roster member in `pending_timelock` (admin, after the roster_change
/// approval; ADR-036(2)).
pub async fn add_member(tx: &mut TenantTx, m: &NewChannelMember) -> Result<()> {
    bounded(m.role_label_json.as_bytes(), MAX_LABEL_JSON, "role label")?;
    let n = sqlx::query(SQL_CM_INSERT)
        .bind(tx.tenant().uuid())
        .bind(m.channel_id.uuid())
        .bind(m.user_id.uuid())
        .bind(m.role_label_json.as_str())
        .bind(m.show_name)
        .bind(i16::from(m.label_index))
        .bind(m.triage)
        .bind(m.effective_day.i32()?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// The roster of a channel (≤ 256 rows by construction).
pub async fn members(tx: &mut TenantTx, channel: ChannelId) -> Result<Vec<ChannelMember>> {
    let rows = sqlx::query(SQL_CM_LIST)
        .bind(tx.tenant().uuid())
        .bind(channel.uuid())
        .fetch_all(tx.conn())
        .await
        .map_err(db)?;
    rows.iter()
        .map(|r| {
            Ok(ChannelMember {
                channel_id: ChannelId::from_bytes(get_uuid(r, 0)?),
                user_id: UserId::from_bytes(get_uuid(r, 1)?),
                show_name: get_bool(r, 2)?,
                label_index: get_u16(r, 3)?,
                triage: get_bool(r, 4)?,
                label_cert_leaf: r
                    .try_get::<Option<i64>, _>(5)
                    .map_err(db)?
                    .map(|v| u64::try_from(v).map_err(|_| DbError::Integrity("range")))
                    .transpose()?,
                effective_day: get_day(r, 6)?,
                state: MemberState::parse(&get_string(r, 7)?)?,
                version: get_u64(r, 8)?,
            })
        })
        .collect()
}

/// Move a member to a new state (kd/admin), optimistic on `version`.
pub async fn set_member_state(
    tx: &mut TenantTx,
    channel: ChannelId,
    user: UserId,
    version: u64,
    state: MemberState,
) -> Result<()> {
    let n = sqlx::query(SQL_CM_SET_STATE)
        .bind(tx.tenant().uuid())
        .bind(channel.uuid())
        .bind(user.uuid())
        .bind(i64_of(version)?)
        .bind(state.as_str())
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::VersionConflict)
}
