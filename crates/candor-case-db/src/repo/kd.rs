// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kd.kd_entry`, `kd.kd_checkpoint`, `kd.member_epoch_key` (09 §5.4;
//! ADR-036). Entries are append-only; the trigger refuses UPDATE/DELETE and
//! enforces a dense per-tenant leaf index.

use crate::error::{DbError, Result, db};
use crate::repo::{get_bytes, get_day, get_string, get_u64, get_uuid, i64_of, one};
use crate::tx::TenantTx;
use crate::types::{ChannelId, Day, DeviceId, Page, PageSize, UserId, bounded};

/// Largest entry body.
pub const MAX_BODY: usize = 256 * 1024;
/// Largest checkpoint note.
pub const MAX_NOTE: usize = 16 * 1024;

/// Entry types (07 §5.10; 04 §14.2 names).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum EntryType {
    UserKey,
    UserKeyRevoke,
    ChannelIdentity,
    ChannelRoster,
    RoleLabelCert,
    MemberEpochKey,
    CoiMap,
    RoutingKey,
    ConnectorKey,
    RecoveryQuorumState,
    ProtectionStatement,
    OperatorStatement,
    IncidentNotice,
    ServerRelease,
    ClientRelease,
    ConfigSigner,
    GovernanceRoles,
    Objection,
    SealerAttestation,
    ServerState,
    DispositionKey,
    AuditExportKey,
}

impl EntryType {
    const TABLE: [(EntryType, &'static str); 22] = [
        (Self::UserKey, "user_key"),
        (Self::UserKeyRevoke, "user_key_revoke"),
        (Self::ChannelIdentity, "channel_identity"),
        (Self::ChannelRoster, "channel_roster"),
        (Self::RoleLabelCert, "role_label_cert"),
        (Self::MemberEpochKey, "member_epoch_key"),
        (Self::CoiMap, "coi_map"),
        (Self::RoutingKey, "routing_key"),
        (Self::ConnectorKey, "connector_key"),
        (Self::RecoveryQuorumState, "recovery_quorum_state"),
        (Self::ProtectionStatement, "protection_statement"),
        (Self::OperatorStatement, "operator_statement"),
        (Self::IncidentNotice, "incident_notice"),
        (Self::ServerRelease, "server_release"),
        (Self::ClientRelease, "client_release"),
        (Self::ConfigSigner, "config_signer"),
        (Self::GovernanceRoles, "governance_roles"),
        (Self::Objection, "objection"),
        (Self::SealerAttestation, "sealer_attestation"),
        (Self::ServerState, "server_state"),
        (Self::DispositionKey, "disposition_key"),
        (Self::AuditExportKey, "audit_export_key"),
    ];
    /// Enum text.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        Self::TABLE
            .iter()
            .find(|(k, _)| *k == self)
            .map_or("user_key", |(_, s)| s)
    }
    /// Parse the enum text.
    pub fn parse(s: &str) -> Result<Self> {
        Self::TABLE
            .iter()
            .find(|(_, t)| *t == s)
            .map(|(k, _)| *k)
            .ok_or(DbError::Integrity("enum"))
    }
}

/// A log entry.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Entry {
    pub leaf_index: u64,
    pub entry_type: EntryType,
    pub subject_id: [u8; 16],
    pub body: Vec<u8>,
    pub leaf_hash: [u8; 32],
    pub signer_key_id: [u8; 32],
    pub sig: [u8; 64],
    pub appended_day: Day,
    pub effective_day: Day,
}

/// Member Epoch Key index row (ADR-030, ADR-033 §2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MemberEpochKey {
    pub key_id: [u8; 16],
    pub channel_id: ChannelId,
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub valid_from_day: Day,
    pub valid_until_day: Day,
    pub decrypt_until_day: Day,
    pub leaf_index: u64,
    pub state: String,
}

const SQL_NEXT: &str =
    "SELECT COALESCE(max(leaf_index) + 1, 0) FROM kd.kd_entry WHERE tenant_id = $1";
const SQL_APPEND: &str = "INSERT INTO kd.kd_entry (tenant_id, leaf_index, entry_type, subject_id, body, leaf_hash, signer_key_id, sig, appended_day, effective_day) \
     VALUES ($1, $2, $3::text::kd.entry_type, $4, $5, $6, $7, $8, DATE '1970-01-01' + $9::int4, DATE '1970-01-01' + $10::int4)";
const SQL_GET: &str = "SELECT leaf_index, entry_type::text, subject_id, body, leaf_hash, signer_key_id, sig, \
     (appended_day - DATE '1970-01-01')::int4, (effective_day - DATE '1970-01-01')::int4 FROM kd.kd_entry WHERE tenant_id = $1 AND leaf_index = $2";
const SQL_LIST: &str = "SELECT leaf_index, entry_type::text, subject_id, body, leaf_hash, signer_key_id, sig, \
     (appended_day - DATE '1970-01-01')::int4, (effective_day - DATE '1970-01-01')::int4 FROM kd.kd_entry \
     WHERE tenant_id = $1 AND leaf_index >= $2 ORDER BY leaf_index LIMIT $3";
const SQL_CP_INSERT: &str = "INSERT INTO kd.kd_checkpoint (tenant_id, tree_size, root_hash, note, created_day, slot) \
     VALUES ($1, $2, $3, $4, DATE '1970-01-01' + $5::int4, $6::text::kd.checkpoint_slot) ON CONFLICT DO NOTHING";
const SQL_CP_LATEST: &str = "SELECT tree_size, root_hash, note FROM kd.kd_checkpoint WHERE tenant_id = $1 ORDER BY tree_size DESC LIMIT 1";
const SQL_MEK_INSERT: &str = "INSERT INTO kd.member_epoch_key (tenant_id, key_id, channel_id, user_id, device_id, valid_from_day, valid_until_day, \
     decrypt_until_day, leaf_index, state) VALUES ($1, $2, $3, $4, $5, DATE '1970-01-01' + $6::int4, DATE '1970-01-01' + $7::int4, \
     DATE '1970-01-01' + $8::int4, $9, 'active') ON CONFLICT DO NOTHING";
const SQL_MEK_LIST: &str = "SELECT key_id, channel_id, user_id, device_id, (valid_from_day - DATE '1970-01-01')::int4, \
     (valid_until_day - DATE '1970-01-01')::int4, (decrypt_until_day - DATE '1970-01-01')::int4, leaf_index, state::text \
     FROM kd.member_epoch_key WHERE tenant_id = $1 AND channel_id = $2 AND state <> 'destroyed' ORDER BY key_id";
/// Forward-only state change; `destroy_due` only when no pending envelope of
/// the channel still carries an epoch whose decrypt window covers the key.
const SQL_MEK_STATE: &str = "UPDATE kd.member_epoch_key k SET state = $3::text::kd.mek_state WHERE k.tenant_id = $1 AND k.key_id = $2 \
     AND ($3 <> 'destroy_due' OR (k.decrypt_until_day < DATE '1970-01-01' + $4::int4 AND NOT EXISTS (SELECT 1 FROM core.import_envelope e \
     WHERE e.tenant_id = k.tenant_id AND e.channel_id = k.channel_id AND e.state = 'pending')))";

fn arr<const N: usize>(v: Vec<u8>) -> Result<[u8; N]> {
    v.try_into()
        .map_err(|_| DbError::Integrity("column length"))
}

fn row(r: &sqlx::postgres::PgRow) -> Result<Entry> {
    Ok(Entry {
        leaf_index: get_u64(r, 0)?,
        entry_type: EntryType::parse(&get_string(r, 1)?)?,
        subject_id: get_uuid(r, 2)?,
        body: get_bytes(r, 3)?,
        leaf_hash: arr(get_bytes(r, 4)?)?,
        signer_key_id: arr(get_bytes(r, 5)?)?,
        sig: arr(get_bytes(r, 6)?)?,
        appended_day: get_day(r, 7)?,
        effective_day: get_day(r, 8)?,
    })
}

/// Next leaf index of the tenant's log.
pub async fn next_leaf_index(tx: &mut TenantTx) -> Result<u64> {
    let r = sqlx::query(SQL_NEXT)
        .bind(tx.tenant().uuid())
        .fetch_one(tx.conn())
        .await
        .map_err(db)?;
    get_u64(&r, 0)
}

/// Append an entry at `leaf_index` (must be the next index: the trigger
/// refuses gaps and forks). Returns the stored entry's index.
pub async fn append(tx: &mut TenantTx, e: &Entry) -> Result<u64> {
    bounded(&e.body, MAX_BODY, "entry body")?;
    if e.effective_day < e.appended_day {
        return Err(DbError::InvalidInput("effective day"));
    }
    sqlx::query(SQL_APPEND)
        .bind(tx.tenant().uuid())
        .bind(i64_of(e.leaf_index)?)
        .bind(e.entry_type.as_str())
        .bind(uuid::Uuid::from_bytes(e.subject_id))
        .bind(e.body.as_slice())
        .bind(e.leaf_hash.as_slice())
        .bind(e.signer_key_id.as_slice())
        .bind(e.sig.as_slice())
        .bind(e.appended_day.i32()?)
        .bind(e.effective_day.i32()?)
        .execute(tx.conn())
        .await
        .map_err(db)?;
    Ok(e.leaf_index)
}

/// One entry.
pub async fn get(tx: &mut TenantTx, leaf_index: u64) -> Result<Entry> {
    let r = sqlx::query(SQL_GET)
        .bind(tx.tenant().uuid())
        .bind(i64_of(leaf_index)?)
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
        .ok_or(DbError::NotFound)?;
    row(&r)
}

/// Entries from `from_leaf` upwards (dense), one page.
pub async fn list_from(tx: &mut TenantTx, from_leaf: u64, size: PageSize) -> Result<Page<Entry>> {
    let rows = sqlx::query(SQL_LIST)
        .bind(tx.tenant().uuid())
        .bind(i64_of(from_leaf)?)
        .bind(size.limit())
        .fetch_all(tx.conn())
        .await
        .map_err(db)?;
    let items = rows.iter().map(row).collect::<Result<Vec<_>>>()?;
    let next = if items.len() >= usize::from(size.get()) {
        items.last().map(|e| {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&e.leaf_index.saturating_add(1).to_be_bytes());
            crate::types::Cursor(b)
        })
    } else {
        None
    };
    Ok(Page { items, next })
}

/// Store a checkpoint at `tree_size` (fixed cadence, 07 §5.10).
pub async fn append_checkpoint(
    tx: &mut TenantTx,
    tree_size: u64,
    root_hash: &[u8; 32],
    note: &[u8],
    day: Day,
    slot: &str,
) -> Result<()> {
    bounded(note, MAX_NOTE, "checkpoint note")?;
    if !["daily", "weekly_publication", "removal", "hourly"].contains(&slot) {
        return Err(DbError::InvalidInput("checkpoint slot"));
    }
    let n = sqlx::query(SQL_CP_INSERT)
        .bind(tx.tenant().uuid())
        .bind(i64_of(tree_size)?)
        .bind(root_hash.as_slice())
        .bind(note)
        .bind(day.i32()?)
        .bind(slot)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// Latest checkpoint `(tree_size, root_hash, note)`.
pub async fn latest_checkpoint(tx: &mut TenantTx) -> Result<Option<(u64, [u8; 32], Vec<u8>)>> {
    let r = sqlx::query(SQL_CP_LATEST)
        .bind(tx.tenant().uuid())
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?;
    r.map(|r| Ok((get_u64(&r, 0)?, arr(get_bytes(&r, 1)?)?, get_bytes(&r, 2)?)))
        .transpose()
}

/// Index a published `MEMBER_EPOCH_KEY` entry.
pub async fn insert_member_epoch_key(tx: &mut TenantTx, k: &MemberEpochKey) -> Result<()> {
    if k.valid_until_day < k.valid_from_day || k.decrypt_until_day < k.valid_until_day {
        return Err(DbError::InvalidInput("epoch window"));
    }
    let n = sqlx::query(SQL_MEK_INSERT)
        .bind(tx.tenant().uuid())
        .bind(k.key_id.as_slice())
        .bind(k.channel_id.uuid())
        .bind(k.user_id.uuid())
        .bind(k.device_id.uuid())
        .bind(k.valid_from_day.i32()?)
        .bind(k.valid_until_day.i32()?)
        .bind(k.decrypt_until_day.i32()?)
        .bind(i64_of(k.leaf_index)?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// Non-destroyed epoch keys of a channel.
pub async fn member_epoch_keys(
    tx: &mut TenantTx,
    channel: ChannelId,
) -> Result<Vec<MemberEpochKey>> {
    let rows = sqlx::query(SQL_MEK_LIST)
        .bind(tx.tenant().uuid())
        .bind(channel.uuid())
        .fetch_all(tx.conn())
        .await
        .map_err(db)?;
    rows.iter()
        .map(|r| {
            Ok(MemberEpochKey {
                key_id: arr(get_bytes(r, 0)?)?,
                channel_id: ChannelId::from_bytes(get_uuid(r, 1)?),
                user_id: UserId::from_bytes(get_uuid(r, 2)?),
                device_id: DeviceId::from_bytes(get_uuid(r, 3)?),
                valid_from_day: get_day(r, 4)?,
                valid_until_day: get_day(r, 5)?,
                decrypt_until_day: get_day(r, 6)?,
                leaf_index: get_u64(r, 7)?,
                state: get_string(r, 8)?,
            })
        })
        .collect()
}

/// Move an epoch key forward (`decrypt_only`, `destroy_due`, `destroyed`).
/// `destroy_due` additionally requires the decrypt window to have passed
/// before `today` and no pending envelope on the channel (ADR-033 §2).
pub async fn set_member_epoch_key_state(
    tx: &mut TenantTx,
    key_id: &[u8; 16],
    state: &str,
    today: Day,
) -> Result<bool> {
    if !["decrypt_only", "destroy_due", "destroyed"].contains(&state) {
        return Err(DbError::InvalidInput("epoch key state"));
    }
    Ok(sqlx::query(SQL_MEK_STATE)
        .bind(tx.tenant().uuid())
        .bind(key_id.as_slice())
        .bind(state)
        .bind(today.i32()?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected()
        == 1)
}
