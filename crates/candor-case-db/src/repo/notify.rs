// SPDX-License-Identifier: AGPL-3.0-or-later
//! `core.notification_target`, `core.notification_queue` (09 §5.2.7;
//! ADR-017, ADR-038(2)): one content-free T1 row per `daily_constant` target
//! per day, created for every target regardless of activity.

use crate::error::{DbError, Result, db};
use crate::repo::{get_bool, get_string, get_u64, get_uuid, one};
use crate::tx::TenantTx;
use crate::types::{Day, NotifId, UserId, bounded_text};

/// Notification target `(channel_type, contact_uri, daily, version)`.
pub type Target = (String, String, bool, u64);

const SQL_T_UPSERT: &str = "INSERT INTO core.notification_target AS t (tenant_id, user_id, channel_type, contact_uri, mode) \
     VALUES ($1, $2, $3::text::core.notify_channel, $4, $5::text::core.notify_mode) \
     ON CONFLICT (tenant_id, user_id) DO UPDATE SET channel_type = EXCLUDED.channel_type, contact_uri = EXCLUDED.contact_uri, \
     mode = EXCLUDED.mode, version = t.version + 1";
const SQL_T_GET: &str = "SELECT channel_type::text, contact_uri, mode = 'daily_constant', version FROM core.notification_target \
     WHERE tenant_id = $1 AND user_id = $2";
/// The daily job: one queued row per daily target for `due_day`, idempotent.
const SQL_Q_DAILY: &str = "INSERT INTO core.notification_queue (tenant_id, notif_id, user_id, template, due_day, state) \
     SELECT $1, pg_catalog.gen_random_uuid(), t.user_id, 'T1', DATE '1970-01-01' + $2::int4, 'queued' \
     FROM core.notification_target t WHERE t.tenant_id = $1 AND t.mode = 'daily_constant' ON CONFLICT DO NOTHING";
const SQL_Q_DUE: &str = "SELECT notif_id, user_id FROM core.notification_queue WHERE tenant_id = $1 AND state = 'queued' \
     AND due_day <= DATE '1970-01-01' + $2::int4 ORDER BY notif_id LIMIT 1000";
const SQL_Q_SET: &str = "UPDATE core.notification_queue SET state = $3::text::core.notif_state \
     WHERE tenant_id = $1 AND notif_id = $2 AND state = 'queued'";
const SQL_Q_PURGE: &str = "DELETE FROM core.notification_queue WHERE tenant_id = $1 AND state <> 'queued' AND due_day < DATE '1970-01-01' + $2::int4";

/// Set the caller's (Desk) or a user's (notify) target.
pub async fn set_target(
    tx: &mut TenantTx,
    user: UserId,
    channel_type: &str,
    contact_uri: &str,
    daily: bool,
) -> Result<()> {
    if !["smtp", "matrix", "webhook"].contains(&channel_type) {
        return Err(DbError::InvalidInput("notification channel"));
    }
    let contact_uri = bounded_text(contact_uri, 320, "contact uri")?;
    let n = sqlx::query(SQL_T_UPSERT)
        .bind(tx.tenant().uuid())
        .bind(user.uuid())
        .bind(channel_type)
        .bind(contact_uri)
        .bind(if daily { "daily_constant" } else { "off" })
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::NotFound)
}

/// A user's target.
pub async fn get_target(tx: &mut TenantTx, user: UserId) -> Result<Target> {
    let r = sqlx::query(SQL_T_GET)
        .bind(tx.tenant().uuid())
        .bind(user.uuid())
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
        .ok_or(DbError::NotFound)?;
    Ok((
        get_string(&r, 0)?,
        get_string(&r, 1)?,
        get_bool(&r, 2)?,
        get_u64(&r, 3)?,
    ))
}

/// Queue the day's constant digest rows (`notify_daily_digest`). Returns
/// the number of rows added (0 when already queued).
pub async fn queue_daily(tx: &mut TenantTx, due_day: Day) -> Result<u64> {
    Ok(sqlx::query(SQL_Q_DAILY)
        .bind(tx.tenant().uuid())
        .bind(due_day.i32()?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected())
}

/// Queued rows due by `day`: `(notif_id, user_id)`.
pub async fn due(tx: &mut TenantTx, day: Day) -> Result<Vec<(NotifId, UserId)>> {
    let rows = sqlx::query(SQL_Q_DUE)
        .bind(tx.tenant().uuid())
        .bind(day.i32()?)
        .fetch_all(tx.conn())
        .await
        .map_err(db)?;
    rows.iter()
        .map(|r| {
            Ok((
                NotifId::from_bytes(get_uuid(r, 0)?),
                UserId::from_bytes(get_uuid(r, 1)?),
            ))
        })
        .collect()
}

/// Mark sent or dropped.
pub async fn mark(tx: &mut TenantTx, id: NotifId, sent: bool) -> Result<()> {
    let n = sqlx::query(SQL_Q_SET)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(if sent { "sent" } else { "dropped" })
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::NotFound)
}

/// Purge finished rows older than `before_day` (7-day retention).
pub async fn purge(tx: &mut TenantTx, before_day: Day) -> Result<u64> {
    Ok(sqlx::query(SQL_Q_PURGE)
        .bind(tx.tenant().uuid())
        .bind(before_day.i32()?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected())
}
