// SPDX-License-Identifier: AGPL-3.0-or-later
//! `core.import_envelope`, `core.import_envelope_part`, `core.submission`
//! (09 §5.2.3; ADR-038, ADR-047(2)). The relay stages rows with a new random
//! id and the fixed-slot date; no intake reference or arrival time is stored.

use crate::error::{DbError, Result, db};
use crate::repo::{get_bytes, get_opt_bytes, get_opt_day, get_string, get_u16, get_u32, get_u64, get_uuid, i32_of, i64_of, one};
use crate::tx::TenantTx;
use crate::types::{BlobId, CaseId, ChannelId, Cursor, Day, ImportEnvelopeId, Page, PageSize, UserId, bounded};

/// `header_ct` bound (07 §5.4).
pub const MAX_HEADER_CT: usize = 8 * 1024;
/// `manifest_ct` bound.
pub const MAX_MANIFEST_CT: usize = 64 * 1024;
/// `disposition_ct` bound.
pub const MAX_DISPOSITION_CT: usize = 4096;
/// Parts per envelope.
pub const MAX_PARTS: usize = 32;
/// Largest padded part (4 GiB).
pub const MAX_PADDED: u64 = 4 * 1024 * 1024 * 1024;

/// Envelope state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ImportState {
    Pending,
    Imported,
    Duplicate,
    Rejected,
}

impl ImportState {
    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "pending" => Self::Pending,
            "imported" => Self::Imported,
            "duplicate" => Self::Duplicate,
            "rejected" => Self::Rejected,
            _ => return Err(DbError::Integrity("enum")),
        })
    }
}

/// Part input `(blob_id, padded_size)` in part order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NewPart {
    pub blob_id: BlobId,
    pub padded_size: u64,
}

/// Relay staging input (validated by the relay against the intake, 07 §5.4).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NewImportEnvelope {
    pub id: ImportEnvelopeId,
    pub channel_id: ChannelId,
    pub header_ct: Vec<u8>,
    pub manifest_ct: Vec<u8>,
    /// SHA-256 of `header_ct` (idempotency; nulled ≤ 24 h later).
    pub header_digest: [u8; 32],
    pub import_date: Day,
    pub disposition_ct: Vec<u8>,
    pub epoch_index: u32,
    pub import_batch_no: u64,
    pub parts: Vec<NewPart>,
}

/// Envelope row (ciphertexts fetched separately).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ImportEnvelope {
    pub id: ImportEnvelopeId,
    pub channel_id: ChannelId,
    pub import_date: Option<Day>,
    pub epoch_index: u32,
    pub import_batch_no: u64,
    pub state: ImportState,
    pub escalated_date: Option<Day>,
}

const SQL_INSERT: &str = "INSERT INTO core.import_envelope (tenant_id, import_envelope_id, channel_id, header_ct, manifest_ct, header_digest, \
     import_date, disposition_ct, epoch_index, import_batch_no, state) \
     VALUES ($1, $2, $3, $4, $5, $6, DATE '1970-01-01' + $7::int4, $8, $9, $10, 'pending') ON CONFLICT DO NOTHING";
const SQL_PART_INSERT: &str = "INSERT INTO core.import_envelope_part (tenant_id, import_envelope_id, part_no, blob_id, padded_size) \
     VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING";
const SQL_DIGEST_EXISTS: &str =
    "SELECT EXISTS (SELECT 1 FROM core.import_envelope WHERE tenant_id = $1 AND header_digest = $2)";
const SQL_GET: &str = "SELECT import_envelope_id, channel_id, (import_date - DATE '1970-01-01')::int4, epoch_index, import_batch_no, state::text, \
     (escalated_date - DATE '1970-01-01')::int4 FROM core.import_envelope WHERE tenant_id = $1 AND import_envelope_id = $2";
const SQL_LIST_PENDING: &str = "SELECT import_envelope_id, channel_id, (import_date - DATE '1970-01-01')::int4, epoch_index, import_batch_no, state::text, \
     (escalated_date - DATE '1970-01-01')::int4 FROM core.import_envelope \
     WHERE tenant_id = $1 AND channel_id = $2 AND state = 'pending' AND import_envelope_id > $3 ORDER BY import_envelope_id LIMIT $4";
const SQL_CT: &str = "SELECT header_ct, manifest_ct, disposition_ct FROM core.import_envelope WHERE tenant_id = $1 AND import_envelope_id = $2";
const SQL_PARTS: &str = "SELECT part_no, blob_id, padded_size FROM core.import_envelope_part \
     WHERE tenant_id = $1 AND import_envelope_id = $2 ORDER BY part_no";
/// Link: state → imported, import_date and disposition nulled in the same
/// transaction (ADR-047(2); L17), submission row, case month bumped.
const SQL_LINK: &str = "UPDATE core.import_envelope SET state = 'imported', import_date = NULL, disposition_ct = NULL \
     WHERE tenant_id = $1 AND import_envelope_id = $2 AND state = 'pending' RETURNING (pg_catalog.date_trunc('month', \
     DATE '1970-01-01' + $3::int4)::date - DATE '1970-01-01')::int4";
const SQL_SUBMISSION: &str = "INSERT INTO core.submission (tenant_id, case_id, import_envelope_id, seq) \
     SELECT $1, $2, $3, COALESCE(max(seq) + 1, 0) FROM core.submission WHERE tenant_id = $1 AND case_id = $2";
const SQL_CASE_MONTH: &str = "UPDATE core.\"case\" SET last_import_month = GREATEST(last_import_month, DATE '1970-01-01' + $4::int4), \
     version = $3 + 1 WHERE tenant_id = $1 AND case_id = $2 AND version = $3";
const SQL_REJECT: &str = "UPDATE core.import_envelope SET state = 'rejected', rejected_by = ARRAY[$3::uuid, $4::uuid], import_date = NULL, \
     disposition_ct = NULL WHERE tenant_id = $1 AND import_envelope_id = $2 AND state = 'pending'";
const SQL_ESCALATE: &str = "UPDATE core.import_envelope SET escalated_date = DATE '1970-01-01' + $3::int4 \
     WHERE tenant_id = $1 AND import_envelope_id = $2 AND state = 'pending' AND escalated_date IS NULL";
const SQL_NULL_DIGESTS: &str = "UPDATE core.import_envelope SET header_digest = NULL \
     WHERE tenant_id = $1 AND header_digest IS NOT NULL AND import_batch_no < $2";
const SQL_DELETE: &str = "DELETE FROM core.import_envelope WHERE tenant_id = $1 AND import_envelope_id = $2";
const SQL_PENDING_COUNT: &str = "SELECT count(*) FROM core.import_envelope WHERE tenant_id = $1 AND state = 'pending'";

fn row(r: &sqlx::postgres::PgRow) -> Result<ImportEnvelope> {
    Ok(ImportEnvelope {
        id: ImportEnvelopeId::from_bytes(get_uuid(r, 0)?),
        channel_id: ChannelId::from_bytes(get_uuid(r, 1)?),
        import_date: get_opt_day(r, 2)?,
        epoch_index: get_u32(r, 3)?,
        import_batch_no: get_u64(r, 4)?,
        state: ImportState::parse(&get_string(r, 5)?)?,
        escalated_date: get_opt_day(r, 6)?,
    })
}

/// Stage one envelope with its parts (relay, inside the slot transaction).
/// Returns false when the digest is already known (idempotent re-import).
pub async fn stage(tx: &mut TenantTx, e: &NewImportEnvelope) -> Result<bool> {
    bounded(&e.header_ct, MAX_HEADER_CT, "header_ct")?;
    bounded(&e.manifest_ct, MAX_MANIFEST_CT, "manifest_ct")?;
    bounded(&e.disposition_ct, MAX_DISPOSITION_CT, "disposition_ct")?;
    if e.parts.is_empty() || e.parts.len() > MAX_PARTS || e.import_batch_no == 0 {
        return Err(DbError::InvalidInput("envelope shape"));
    }
    if e.parts.iter().any(|p| p.padded_size == 0 || p.padded_size > MAX_PADDED) {
        return Err(DbError::InvalidInput("padded size"));
    }
    let dup = sqlx::query(SQL_DIGEST_EXISTS)
        .bind(tx.tenant().uuid())
        .bind(e.header_digest.as_slice())
        .fetch_one(tx.conn())
        .await
        .map_err(db)?;
    if crate::repo::get_bool(&dup, 0)? {
        return Ok(false);
    }
    let n = sqlx::query(SQL_INSERT)
        .bind(tx.tenant().uuid())
        .bind(e.id.uuid())
        .bind(e.channel_id.uuid())
        .bind(e.header_ct.as_slice())
        .bind(e.manifest_ct.as_slice())
        .bind(e.header_digest.as_slice())
        .bind(e.import_date.i32()?)
        .bind(e.disposition_ct.as_slice())
        .bind(i32_of(e.epoch_index)?)
        .bind(i64_of(e.import_batch_no)?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)?;
    for (i, p) in e.parts.iter().enumerate() {
        let part_no = i16::try_from(i).map_err(|_| DbError::InvalidInput("part"))?;
        let n = sqlx::query(SQL_PART_INSERT)
            .bind(tx.tenant().uuid())
            .bind(e.id.uuid())
            .bind(part_no)
            .bind(p.blob_id.uuid())
            .bind(i64_of(p.padded_size)?)
            .execute(tx.conn())
            .await
            .map_err(db)?
            .rows_affected();
        one(n, DbError::AlreadyExists)?;
    }
    Ok(true)
}

/// IDOR-safe lookup (Triage Set RLS for the Desk).
pub async fn get(tx: &mut TenantTx, id: ImportEnvelopeId) -> Result<ImportEnvelope> {
    let r = sqlx::query(SQL_GET)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
        .ok_or(DbError::NotFound)?;
    row(&r)
}

/// Pending envelopes of a channel, keyset by id.
pub async fn list_pending(tx: &mut TenantTx, channel: ChannelId, after: Option<Cursor>, size: PageSize) -> Result<Page<ImportEnvelope>> {
    let rows = sqlx::query(SQL_LIST_PENDING)
        .bind(tx.tenant().uuid())
        .bind(channel.uuid())
        .bind(after.unwrap_or(Cursor([0; 16])).uuid())
        .bind(size.limit())
        .fetch_all(tx.conn())
        .await
        .map_err(db)?;
    let items = rows.iter().map(row).collect::<Result<Vec<_>>>()?;
    Ok(Page::new(items, size, |e| *e.id.as_bytes()))
}

/// `(header_ct, manifest_ct, disposition_ct)` of an envelope.
pub async fn ciphertexts(tx: &mut TenantTx, id: ImportEnvelopeId) -> Result<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)> {
    let r = sqlx::query(SQL_CT)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
        .ok_or(DbError::NotFound)?;
    Ok((get_bytes(&r, 0)?, get_bytes(&r, 1)?, get_opt_bytes(&r, 2)?))
}

/// Parts `(part_no, blob_id, padded_size)`.
pub async fn parts(tx: &mut TenantTx, id: ImportEnvelopeId) -> Result<Vec<(u16, BlobId, u64)>> {
    let rows = sqlx::query(SQL_PARTS)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .fetch_all(tx.conn())
        .await
        .map_err(db)?;
    rows.iter()
        .map(|r| Ok((get_u16(r, 0)?, BlobId::from_bytes(get_uuid(r, 1)?), get_u64(r, 2)?)))
        .collect()
}

/// Link a pending envelope to a case: nulls `import_date` and
/// `disposition_ct`, adds the submission row and bumps the case's
/// `last_import_month` (optimistic on the case version).
pub async fn link_to_case(tx: &mut TenantTx, id: ImportEnvelopeId, case: CaseId, case_version: u64) -> Result<()> {
    let e = get(tx, id).await?;
    let slot = e.import_date.ok_or(DbError::Guard("envelope not pending"))?;
    let r = sqlx::query(SQL_LINK)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(slot.i32()?)
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
        .ok_or(DbError::Guard("envelope not pending"))?;
    let month: i32 = sqlx::Row::try_get(&r, 0).map_err(db)?;
    let n = sqlx::query(SQL_SUBMISSION)
        .bind(tx.tenant().uuid())
        .bind(case.uuid())
        .bind(id.uuid())
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::Integrity("submission"))?;
    let n = sqlx::query(SQL_CASE_MONTH)
        .bind(tx.tenant().uuid())
        .bind(case.uuid())
        .bind(i64_of(case_version)?)
        .bind(month)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::VersionConflict)
}

/// Dual-approved rejection (DA-23): two distinct approvers.
pub async fn reject(tx: &mut TenantTx, id: ImportEnvelopeId, approvers: [UserId; 2]) -> Result<()> {
    if approvers[0] == approvers[1] || approvers.iter().any(UserId::is_nil) {
        return Err(DbError::InvalidInput("two distinct approvers"));
    }
    let n = sqlx::query(SQL_REJECT)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(approvers[0].uuid())
        .bind(approvers[1].uuid())
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::NotFound)
}

/// Record the escalation day once (`import_escalate` job).
pub async fn escalate(tx: &mut TenantTx, id: ImportEnvelopeId, day: Day) -> Result<bool> {
    Ok(sqlx::query(SQL_ESCALATE)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(day.i32()?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected()
        == 1)
}

/// Null `header_digest` of every envelope of a batch older than
/// `before_batch_no` (the relay runs this at the slot ≥ 24 h later).
pub async fn null_old_digests(tx: &mut TenantTx, before_batch_no: u64) -> Result<u64> {
    Ok(sqlx::query(SQL_NULL_DIGESTS)
        .bind(tx.tenant().uuid())
        .bind(i64_of(before_batch_no)?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected())
}

/// Delete an envelope and its parts (chaff discard, rejection, re-wrap done).
pub async fn delete(tx: &mut TenantTx, id: ImportEnvelopeId) -> Result<()> {
    let n = sqlx::query(SQL_DELETE)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::NotFound)
}

/// Pending count (relay backpressure, 07 §5.4).
pub async fn pending_count(tx: &mut TenantTx) -> Result<u64> {
    let r = sqlx::query(SQL_PENDING_COUNT)
        .bind(tx.tenant().uuid())
        .fetch_one(tx.conn())
        .await
        .map_err(db)?;
    get_u64(&r, 0)
}
