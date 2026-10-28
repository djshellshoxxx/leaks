// SPDX-License-Identifier: AGPL-3.0-or-later
//! `audit.audit_event`, `audit.audit_checkpoint` (09 §5.5; 07 §5.9). The
//! hash chain is computed by C-24; the database enforces dense sequence,
//! prev-hash linkage, pending-first insertion, immutability and no deletion.
//! `occurred_at` is set only for staff actions; system and import events are
//! date-only (ADR-033(4), ADR-038(1)).

use crate::error::{DbError, Result, db};
use crate::repo::{get_bytes, get_u64, i64_of, one};
use crate::tx::TenantTx;
use crate::types::{Day, bounded};

/// Payload bound (canonical CBOR of allow-listed fields).
pub const MAX_PAYLOAD: usize = 16 * 1024;

/// Event class (one chain per class per tenant).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    Security,
    Case,
    System,
}

impl Class {
    /// Enum text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Case => "case",
            Self::System => "system",
        }
    }
}

/// An event to append (hashes computed by the audit service).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NewEvent {
    pub class: Class,
    pub seq: u64,
    pub event_type: u16,
    pub actor_pseudonym: [u8; 16],
    pub object_pseudonym: Option<[u8; 16]>,
    pub payload: Vec<u8>,
    pub occurred_date: Day,
    /// Staff actions only: seconds since the Unix epoch.
    pub occurred_at_unix: Option<i64>,
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
}

const SQL_INSERT: &str = "INSERT INTO audit.audit_event (tenant_id, class, seq, event_type, actor_pseudonym, object_pseudonym, payload, occurred_date, \
     occurred_at, prev_hash, hash, state) VALUES ($1, $2::text::audit.event_class, $3, $4, $5, $6, $7, DATE '1970-01-01' + $8::int4, \
     pg_catalog.to_timestamp($9), $10, $11, 'pending')";
const SQL_SET_STATE: &str = "UPDATE audit.audit_event SET state = $4::text::audit.event_state \
     WHERE tenant_id = $1 AND class = $2::text::audit.event_class AND seq = $3 AND state = 'pending'";
const SQL_HEAD: &str = "SELECT seq, hash FROM audit.audit_event WHERE tenant_id = $1 AND class = $2::text::audit.event_class \
     ORDER BY seq DESC LIMIT 1";
const SQL_PENDING: &str = "SELECT seq FROM audit.audit_event WHERE tenant_id = $1 AND class = $2::text::audit.event_class AND state = 'pending' \
     ORDER BY seq LIMIT 1000";
const SQL_CP_INSERT: &str = "INSERT INTO audit.audit_checkpoint (tenant_id, class, seq, hash, sig, signed_at, witness_ref) \
     VALUES ($1, $2::text::audit.event_class, $3, $4, $5, pg_catalog.to_timestamp($6), $7) ON CONFLICT DO NOTHING";
const SQL_CP_LATEST: &str = "SELECT seq, hash, sig FROM audit.audit_checkpoint WHERE tenant_id = $1 AND class = $2::text::audit.event_class \
     ORDER BY seq DESC LIMIT 1";

/// Append a pending event (two-phase: commit the business transaction, then
/// `set_committed`). The trigger refuses gaps, forks and non-pending inserts.
pub async fn append(tx: &mut TenantTx, e: &NewEvent) -> Result<()> {
    bounded(&e.payload, MAX_PAYLOAD, "audit payload")?;
    if e.seq == 0 {
        return Err(DbError::InvalidInput("audit seq"));
    }
    if let Some(t) = e.occurred_at_unix
        && !(0..=253_402_300_799).contains(&t)
    {
        return Err(DbError::InvalidInput("audit time"));
    }
    sqlx::query(SQL_INSERT)
        .bind(tx.tenant().uuid())
        .bind(e.class.as_str())
        .bind(i64_of(e.seq)?)
        .bind(i16::try_from(e.event_type).map_err(|_| DbError::InvalidInput("event type"))?)
        .bind(e.actor_pseudonym.as_slice())
        .bind(e.object_pseudonym.as_ref().map(<[u8; 16]>::as_slice))
        .bind(e.payload.as_slice())
        .bind(e.occurred_date.i32()?)
        .bind(e.occurred_at_unix.map(|t| t as f64))
        .bind(e.prev_hash.as_slice())
        .bind(e.hash.as_slice())
        .execute(tx.conn())
        .await
        .map_err(db)?;
    Ok(())
}

/// Move a pending event to `committed` (true) or `aborted` (false).
pub async fn set_state(tx: &mut TenantTx, class: Class, seq: u64, committed: bool) -> Result<()> {
    let n = sqlx::query(SQL_SET_STATE)
        .bind(tx.tenant().uuid())
        .bind(class.as_str())
        .bind(i64_of(seq)?)
        .bind(if committed { "committed" } else { "aborted" })
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::NotFound)
}

/// Chain head `(seq, hash)` of a class, None for an empty chain.
pub async fn head(tx: &mut TenantTx, class: Class) -> Result<Option<(u64, [u8; 32])>> {
    let r = sqlx::query(SQL_HEAD)
        .bind(tx.tenant().uuid())
        .bind(class.as_str())
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?;
    r.map(|r| {
        let h: [u8; 32] = get_bytes(&r, 1)?
            .try_into()
            .map_err(|_| DbError::Integrity("column length"))?;
        Ok((get_u64(&r, 0)?, h))
    })
    .transpose()
}

/// Pending sequence numbers (the reconciliation job, 07 §5.9).
pub async fn pending(tx: &mut TenantTx, class: Class) -> Result<Vec<u64>> {
    let rows = sqlx::query(SQL_PENDING)
        .bind(tx.tenant().uuid())
        .bind(class.as_str())
        .fetch_all(tx.conn())
        .await
        .map_err(db)?;
    rows.iter().map(|r| get_u64(r, 0)).collect()
}

/// Store a signed checkpoint at `seq` (must reference an existing event).
pub async fn checkpoint(
    tx: &mut TenantTx,
    class: Class,
    seq: u64,
    hash: &[u8; 32],
    sig: &[u8; 64],
    signed_at_unix: i64,
    witness_ref: Option<&[u8]>,
) -> Result<()> {
    if !(0..=253_402_300_799).contains(&signed_at_unix) {
        return Err(DbError::InvalidInput("checkpoint time"));
    }
    if let Some(w) = witness_ref
        && w.len() > 256
    {
        return Err(DbError::InvalidInput("witness ref"));
    }
    let n = sqlx::query(SQL_CP_INSERT)
        .bind(tx.tenant().uuid())
        .bind(class.as_str())
        .bind(i64_of(seq)?)
        .bind(hash.as_slice())
        .bind(sig.as_slice())
        .bind(signed_at_unix as f64)
        .bind(witness_ref)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// Latest checkpoint `(seq, hash, sig)`.
pub async fn latest_checkpoint(
    tx: &mut TenantTx,
    class: Class,
) -> Result<Option<(u64, [u8; 32], [u8; 64])>> {
    let r = sqlx::query(SQL_CP_LATEST)
        .bind(tx.tenant().uuid())
        .bind(class.as_str())
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?;
    r.map(|r| {
        let h: [u8; 32] = get_bytes(&r, 1)?
            .try_into()
            .map_err(|_| DbError::Integrity("column length"))?;
        let s: [u8; 64] = get_bytes(&r, 2)?
            .try_into()
            .map_err(|_| DbError::Integrity("column length"))?;
        Ok((get_u64(&r, 0)?, h, s))
    })
    .transpose()
}
