// SPDX-License-Identifier: AGPL-3.0-or-later
//! `core.message`, `core.attachment`, `core.evidence_object`,
//! `core.blob_object` (09 §5.2.4, §5.2.8; ADR-012, ADR-047(2)).

use crate::error::{DbError, Result, db};
use crate::repo::{get_bool, get_bytes, get_opt_bytes, get_opt_uuid, get_u16, get_u32, get_u64, get_uuid, i32_of, i64_of, one};
use crate::tx::TenantTx;
use crate::types::{BlobId, CaseId, Cursor, Day, EvidenceId, ImportEnvelopeId, MessageId, Page, PageSize, bounded};

/// `body_ct` bound.
pub const MAX_BODY_CT: usize = 256 * 1024;
/// `dek_wrap_ct` bound.
pub const MAX_DEK_WRAP_CT: usize = 2048;
/// `meta_ct` bound.
pub const MAX_META_CT: usize = 64 * 1024;

/// Message row.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Message {
    pub message_id: MessageId,
    pub case_id: CaseId,
    pub from_source: bool,
    pub import_envelope_id: Option<ImportEnvelopeId>,
    /// Staff reply day for `to_source`; always None for `from_source` (L17).
    pub day: Option<Day>,
    pub blob_id: Option<BlobId>,
    pub dek_wrap_ct: Option<Vec<u8>>,
    pub body_ct: Option<Vec<u8>>,
    pub key_epoch: u32,
    pub size_bucket: u8,
}

/// Evidence row (ciphertexts included: ≤ 66 KiB).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Evidence {
    pub evidence_id: EvidenceId,
    pub case_id: CaseId,
    pub staff_upload: bool,
    pub blob_id: BlobId,
    pub dek_wrap_ct: Vec<u8>,
    pub meta_ct: Vec<u8>,
    pub padded_size: u64,
    pub key_epoch: u32,
    pub erased: bool,
}

const SQL_MSG_FROM_SOURCE: &str = "INSERT INTO core.message (tenant_id, message_id, case_id, direction, import_envelope_id, day, blob_id, dek_wrap_ct, \
     body_ct, key_epoch, size_bucket) VALUES ($1, $2, $3, 'from_source', $4, NULL, $5, $6, NULL, $7, $8) ON CONFLICT DO NOTHING";
const SQL_MSG_TO_SOURCE: &str = "INSERT INTO core.message (tenant_id, message_id, case_id, direction, import_envelope_id, day, blob_id, dek_wrap_ct, \
     body_ct, key_epoch, size_bucket) VALUES ($1, $2, $3, 'to_source', NULL, DATE '1970-01-01' + $4::int4, NULL, NULL, $5, $6, $7) ON CONFLICT DO NOTHING";
const SQL_MSG_GET: &str = "SELECT message_id, case_id, direction = 'from_source', import_envelope_id, (day - DATE '1970-01-01')::int4, blob_id, \
     dek_wrap_ct, body_ct, key_epoch, size_bucket FROM core.message WHERE tenant_id = $1 AND message_id = $2";
const SQL_MSG_LIST: &str = "SELECT message_id, case_id, direction = 'from_source', import_envelope_id, (day - DATE '1970-01-01')::int4, blob_id, \
     dek_wrap_ct, body_ct, key_epoch, size_bucket FROM core.message WHERE tenant_id = $1 AND case_id = $2 AND message_id > $3 \
     ORDER BY message_id LIMIT $4";
const SQL_ATT_INSERT: &str = "INSERT INTO core.attachment (tenant_id, message_id, evidence_id, position) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING";
const SQL_ATT_LIST: &str = "SELECT evidence_id, position FROM core.attachment WHERE tenant_id = $1 AND message_id = $2 ORDER BY position";
const SQL_EV_INSERT: &str = "INSERT INTO core.evidence_object (tenant_id, evidence_id, case_id, origin, blob_id, dek_wrap_ct, meta_ct, padded_size, key_epoch) \
     VALUES ($1, $2, $3, $4::text::core.evidence_origin, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING";
const SQL_EV_GET: &str = "SELECT evidence_id, case_id, origin = 'staff_upload', blob_id, dek_wrap_ct, meta_ct, padded_size, key_epoch, state = 'erased' \
     FROM core.evidence_object WHERE tenant_id = $1 AND evidence_id = $2";
const SQL_EV_LIST: &str = "SELECT evidence_id, case_id, origin = 'staff_upload', blob_id, dek_wrap_ct, meta_ct, padded_size, key_epoch, state = 'erased' \
     FROM core.evidence_object WHERE tenant_id = $1 AND case_id = $2 AND evidence_id > $3 ORDER BY evidence_id LIMIT $4";
const SQL_EV_ERASE: &str = "UPDATE core.evidence_object SET state = 'erased' WHERE tenant_id = $1 AND evidence_id = $2 AND state = 'active'";
const SQL_BLOB_INSERT: &str = "INSERT INTO core.blob_object (tenant_id, blob_id, store, padded_size, ct_sha256, refcount) \
     VALUES ($1, $2, $3::text::core.blob_store, $4, $5, 1) ON CONFLICT DO NOTHING";
const SQL_BLOB_GET: &str = "SELECT store = 's3', padded_size, ct_sha256, refcount FROM core.blob_object WHERE tenant_id = $1 AND blob_id = $2";
const SQL_BLOB_REF: &str = "UPDATE core.blob_object SET refcount = refcount + $3 WHERE tenant_id = $1 AND blob_id = $2 AND refcount + $3 >= 0";
const SQL_BLOB_UNREFERENCED: &str = "SELECT blob_id FROM core.blob_object WHERE tenant_id = $1 AND refcount = 0 AND blob_id > $2 ORDER BY blob_id LIMIT $3";
const SQL_BLOB_DELETE: &str = "DELETE FROM core.blob_object WHERE tenant_id = $1 AND blob_id = $2 AND refcount = 0";

fn msg_row(r: &sqlx::postgres::PgRow) -> Result<Message> {
    Ok(Message {
        message_id: MessageId::from_bytes(get_uuid(r, 0)?),
        case_id: CaseId::from_bytes(get_uuid(r, 1)?),
        from_source: get_bool(r, 2)?,
        import_envelope_id: get_opt_uuid(r, 3)?.map(ImportEnvelopeId::from_bytes),
        day: crate::repo::get_opt_day(r, 4)?,
        blob_id: get_opt_uuid(r, 5)?.map(BlobId::from_bytes),
        dek_wrap_ct: get_opt_bytes(r, 6)?,
        body_ct: get_opt_bytes(r, 7)?,
        key_epoch: get_u32(r, 8)?,
        size_bucket: u8::try_from(get_u16(r, 9)?).map_err(|_| DbError::Integrity("range"))?,
    })
}

fn ev_row(r: &sqlx::postgres::PgRow) -> Result<Evidence> {
    Ok(Evidence {
        evidence_id: EvidenceId::from_bytes(get_uuid(r, 0)?),
        case_id: CaseId::from_bytes(get_uuid(r, 1)?),
        staff_upload: get_bool(r, 2)?,
        blob_id: BlobId::from_bytes(get_uuid(r, 3)?),
        dek_wrap_ct: get_bytes(r, 4)?,
        meta_ct: get_bytes(r, 5)?,
        padded_size: get_u64(r, 6)?,
        key_epoch: get_u32(r, 7)?,
        erased: get_bool(r, 8)?,
    })
}

fn bucket(b: u8) -> Result<i16> {
    if !(1..=16).contains(&b) {
        return Err(DbError::InvalidInput("size bucket"));
    }
    Ok(i16::from(b))
}

/// An imported source message: no day (ADR-047(2)); the envelope DEK is
/// re-wrapped under the case key.
pub async fn create_from_source(
    tx: &mut TenantTx,
    id: MessageId,
    case: CaseId,
    envelope: ImportEnvelopeId,
    blob: BlobId,
    dek_wrap_ct: &[u8],
    key_epoch: u32,
    size_bucket: u8,
) -> Result<()> {
    bounded(dek_wrap_ct, MAX_DEK_WRAP_CT, "dek_wrap_ct")?;
    let n = sqlx::query(SQL_MSG_FROM_SOURCE)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(case.uuid())
        .bind(envelope.uuid())
        .bind(blob.uuid())
        .bind(dek_wrap_ct)
        .bind(i32_of(key_epoch)?)
        .bind(bucket(size_bucket)?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// A staff reply copy for the case history (the sealed reply itself goes to
/// `reply_outbox`).
pub async fn create_to_source(
    tx: &mut TenantTx,
    id: MessageId,
    case: CaseId,
    day: Day,
    body_ct: &[u8],
    key_epoch: u32,
    size_bucket: u8,
) -> Result<()> {
    bounded(body_ct, MAX_BODY_CT, "body_ct")?;
    let n = sqlx::query(SQL_MSG_TO_SOURCE)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(case.uuid())
        .bind(day.i32()?)
        .bind(body_ct)
        .bind(i32_of(key_epoch)?)
        .bind(bucket(size_bucket)?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// IDOR-safe lookup.
pub async fn get(tx: &mut TenantTx, id: MessageId) -> Result<Message> {
    let r = sqlx::query(SQL_MSG_GET)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
        .ok_or(DbError::NotFound)?;
    msg_row(&r)
}

/// Messages of a case, keyset by id.
pub async fn list(tx: &mut TenantTx, case: CaseId, after: Option<Cursor>, size: PageSize) -> Result<Page<Message>> {
    let rows = sqlx::query(SQL_MSG_LIST)
        .bind(tx.tenant().uuid())
        .bind(case.uuid())
        .bind(after.unwrap_or(Cursor([0; 16])).uuid())
        .bind(size.limit())
        .fetch_all(tx.conn())
        .await
        .map_err(db)?;
    let items = rows.iter().map(msg_row).collect::<Result<Vec<_>>>()?;
    Ok(Page::new(items, size, |m| *m.message_id.as_bytes()))
}

/// Attach evidence to a message at `position`.
pub async fn attach(tx: &mut TenantTx, message: MessageId, evidence: EvidenceId, position: u8) -> Result<()> {
    let n = sqlx::query(SQL_ATT_INSERT)
        .bind(tx.tenant().uuid())
        .bind(message.uuid())
        .bind(evidence.uuid())
        .bind(i16::from(position))
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// Attachments `(evidence_id, position)` of a message.
pub async fn attachments(tx: &mut TenantTx, message: MessageId) -> Result<Vec<(EvidenceId, u16)>> {
    let rows = sqlx::query(SQL_ATT_LIST)
        .bind(tx.tenant().uuid())
        .bind(message.uuid())
        .fetch_all(tx.conn())
        .await
        .map_err(db)?;
    rows.iter()
        .map(|r| Ok((EvidenceId::from_bytes(get_uuid(r, 0)?), get_u16(r, 1)?)))
        .collect()
}

/// Create an ORIGINAL evidence object (immutable afterwards, ADR-012).
#[allow(clippy::too_many_arguments)]
pub async fn create_evidence(
    tx: &mut TenantTx,
    id: EvidenceId,
    case: CaseId,
    staff_upload: bool,
    blob: BlobId,
    dek_wrap_ct: &[u8],
    meta_ct: &[u8],
    padded_size: u64,
    key_epoch: u32,
) -> Result<()> {
    bounded(dek_wrap_ct, MAX_DEK_WRAP_CT, "dek_wrap_ct")?;
    bounded(meta_ct, MAX_META_CT, "meta_ct")?;
    if padded_size == 0 || padded_size > super::import::MAX_PADDED {
        return Err(DbError::InvalidInput("padded size"));
    }
    let n = sqlx::query(SQL_EV_INSERT)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(case.uuid())
        .bind(if staff_upload { "staff_upload" } else { "source_attachment" })
        .bind(blob.uuid())
        .bind(dek_wrap_ct)
        .bind(meta_ct)
        .bind(i64_of(padded_size)?)
        .bind(i32_of(key_epoch)?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// IDOR-safe lookup.
pub async fn get_evidence(tx: &mut TenantTx, id: EvidenceId) -> Result<Evidence> {
    let r = sqlx::query(SQL_EV_GET)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
        .ok_or(DbError::NotFound)?;
    ev_row(&r)
}

/// Evidence of a case, keyset by id.
pub async fn list_evidence(tx: &mut TenantTx, case: CaseId, after: Option<Cursor>, size: PageSize) -> Result<Page<Evidence>> {
    let rows = sqlx::query(SQL_EV_LIST)
        .bind(tx.tenant().uuid())
        .bind(case.uuid())
        .bind(after.unwrap_or(Cursor([0; 16])).uuid())
        .bind(size.limit())
        .fetch_all(tx.conn())
        .await
        .map_err(db)?;
    let items = rows.iter().map(ev_row).collect::<Result<Vec<_>>>()?;
    Ok(Page::new(items, size, |e| *e.evidence_id.as_bytes()))
}

/// Mark evidence erased (the only permitted change).
pub async fn erase_evidence(tx: &mut TenantTx, id: EvidenceId) -> Result<()> {
    let n = sqlx::query(SQL_EV_ERASE)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::NotFound)
}

/// Register a stored ciphertext blob with refcount 1.
pub async fn create_blob(tx: &mut TenantTx, id: BlobId, s3: bool, padded_size: u64, ct_sha256: &[u8; 32]) -> Result<()> {
    if padded_size == 0 || padded_size > super::import::MAX_PADDED {
        return Err(DbError::InvalidInput("padded size"));
    }
    let n = sqlx::query(SQL_BLOB_INSERT)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(if s3 { "s3" } else { "fs" })
        .bind(i64_of(padded_size)?)
        .bind(ct_sha256.as_slice())
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// `(s3, padded_size, ct_sha256, refcount)`.
pub async fn get_blob(tx: &mut TenantTx, id: BlobId) -> Result<(bool, u64, [u8; 32], u32)> {
    let r = sqlx::query(SQL_BLOB_GET)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
        .ok_or(DbError::NotFound)?;
    let h: [u8; 32] = get_bytes(&r, 2)?
        .try_into()
        .map_err(|_| DbError::Integrity("column length"))?;
    Ok((get_bool(&r, 0)?, get_u64(&r, 1)?, h, get_u32(&r, 3)?))
}

/// Adjust the reference count by `delta` (never below zero).
pub async fn blob_ref(tx: &mut TenantTx, id: BlobId, delta: i32) -> Result<()> {
    if !(-64..=64).contains(&delta) {
        return Err(DbError::InvalidInput("refcount delta"));
    }
    let n = sqlx::query(SQL_BLOB_REF)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(delta)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::NotFound)
}

/// Unreferenced blobs (worker `blob_gc`; the 24 h age is the job's, kept
/// outside the database so no per-blob time exists).
pub async fn unreferenced_blobs(tx: &mut TenantTx, after: Option<Cursor>, size: PageSize) -> Result<Page<BlobId>> {
    let rows = sqlx::query(SQL_BLOB_UNREFERENCED)
        .bind(tx.tenant().uuid())
        .bind(after.unwrap_or(Cursor([0; 16])).uuid())
        .bind(size.limit())
        .fetch_all(tx.conn())
        .await
        .map_err(db)?;
    let items = rows
        .iter()
        .map(|r| get_uuid(r, 0).map(BlobId::from_bytes))
        .collect::<Result<Vec<_>>>()?;
    Ok(Page::new(items, size, |b| *b.as_bytes()))
}

/// Delete an unreferenced blob row (after the object store deletion).
pub async fn delete_blob(tx: &mut TenantTx, id: BlobId) -> Result<()> {
    let n = sqlx::query(SQL_BLOB_DELETE)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::NotFound)
}
