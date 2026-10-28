// SPDX-License-Identifier: AGPL-3.0-or-later
//! `core.job` (09 §5.2.8; 07 §6.1). Leases use the server clock (allow-listed
//! L3); no job is ever enqueued as a consequence of an import (ADR-038).

use crate::error::{DbError, Result, db};
use crate::repo::{get_bytes, get_string, get_u16, get_uuid, one};
use crate::tx::TenantTx;
use crate::types::{JobId, JobKind, PageSize, bounded};

/// CBOR payload bound (opaque ids, enums, days only; BE-020).
pub const MAX_PAYLOAD: usize = 4096;
/// Lease length in seconds (07 §6.1).
pub const LEASE_SECONDS: i32 = 300;

/// A claimed job.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Job {
    pub job_id: JobId,
    pub kind: JobKind,
    pub payload: Vec<u8>,
    pub attempts: u16,
    pub max_attempts: u16,
}

const SQL_ENQUEUE: &str = "INSERT INTO core.job (tenant_id, job_id, kind, payload, priority, run_after, max_attempts) \
     VALUES ($1, $2, $3, $4, $5, pg_catalog.now() + pg_catalog.make_interval(secs => $6), $7) ON CONFLICT DO NOTHING";
const SQL_CLAIM: &str = "WITH c AS (SELECT job_id FROM core.job WHERE tenant_id = $1 AND state = 'ready' AND run_after <= pg_catalog.now() \
     AND kind = ANY($2) ORDER BY priority DESC, run_after FOR UPDATE SKIP LOCKED LIMIT $3) \
     UPDATE core.job j SET state = 'running', locked_by = $4, lease_until = pg_catalog.now() + pg_catalog.make_interval(secs => $5), \
     attempts = j.attempts + 1 FROM c WHERE j.tenant_id = $1 AND j.job_id = c.job_id \
     RETURNING j.job_id, j.kind, j.payload, j.attempts, j.max_attempts";
const SQL_RECLAIM: &str = "UPDATE core.job SET state = 'ready', locked_by = NULL, lease_until = NULL \
     WHERE tenant_id = $1 AND state = 'running' AND lease_until < pg_catalog.now()";
const SQL_RENEW: &str = "UPDATE core.job SET lease_until = pg_catalog.now() + pg_catalog.make_interval(secs => $4) \
     WHERE tenant_id = $1 AND job_id = $2 AND state = 'running' AND locked_by = $3";
const SQL_DONE: &str = "UPDATE core.job SET state = 'done', locked_by = NULL, lease_until = NULL \
     WHERE tenant_id = $1 AND job_id = $2 AND state = 'running' AND locked_by = $3";
/// Failure: back off `min(2^attempts × 30 s, 6 h)` or die at max_attempts.
const SQL_FAIL: &str = "UPDATE core.job SET state = CASE WHEN attempts >= max_attempts THEN 'dead'::core.job_state ELSE 'ready'::core.job_state END, \
     locked_by = NULL, lease_until = NULL, \
     run_after = pg_catalog.now() + pg_catalog.make_interval(secs => LEAST(pg_catalog.power(2, attempts) * 30, 21600)) \
     WHERE tenant_id = $1 AND job_id = $2 AND state = 'running' AND locked_by = $3 RETURNING state = 'dead'";
const SQL_PURGE_DONE: &str =
    "DELETE FROM core.job WHERE tenant_id = $1 AND state = 'done' AND job_id = ANY($2)";

fn worker_name(s: &str) -> Result<&str> {
    crate::types::bounded_text(s, 64, "worker name")
}

/// Enqueue a job to run after `delay_seconds` (0 = now).
pub async fn enqueue(
    tx: &mut TenantTx,
    id: JobId,
    kind: JobKind,
    payload: &[u8],
    priority: i8,
    delay_seconds: u32,
    max_attempts: u8,
) -> Result<()> {
    bounded(payload, MAX_PAYLOAD, "job payload")?;
    if !(-10..=10).contains(&priority)
        || !(1..=64).contains(&max_attempts)
        || delay_seconds > 86_400 * 31
    {
        return Err(DbError::InvalidInput("job parameters"));
    }
    let n = sqlx::query(SQL_ENQUEUE)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(kind.as_str())
        .bind(payload)
        .bind(i16::from(priority))
        .bind(f64::from(delay_seconds))
        .bind(i16::from(max_attempts))
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::AlreadyExists)
}

/// Reclaim expired leases, then claim up to `size` ready jobs of `kinds`.
pub async fn claim(
    tx: &mut TenantTx,
    kinds: &[JobKind],
    worker: &str,
    size: PageSize,
) -> Result<Vec<Job>> {
    let worker = worker_name(worker)?;
    if kinds.is_empty() || kinds.len() > JobKind::ALL.len() {
        return Err(DbError::InvalidInput("job kinds"));
    }
    sqlx::query(SQL_RECLAIM)
        .bind(tx.tenant().uuid())
        .execute(tx.conn())
        .await
        .map_err(db)?;
    let names: Vec<&str> = kinds.iter().map(|k| k.as_str()).collect();
    let rows = sqlx::query(SQL_CLAIM)
        .bind(tx.tenant().uuid())
        .bind(&names)
        .bind(size.limit())
        .bind(worker)
        .bind(f64::from(LEASE_SECONDS))
        .fetch_all(tx.conn())
        .await
        .map_err(db)?;
    rows.iter()
        .map(|r| {
            Ok(Job {
                job_id: JobId::from_bytes(get_uuid(r, 0)?),
                kind: JobKind::parse(&get_string(r, 1)?)
                    .map_err(|_| DbError::Integrity("job kind"))?,
                payload: get_bytes(r, 2)?,
                attempts: get_u16(r, 3)?,
                max_attempts: get_u16(r, 4)?,
            })
        })
        .collect()
}

/// Extend the lease of a running job held by `worker`.
pub async fn renew(tx: &mut TenantTx, id: JobId, worker: &str) -> Result<()> {
    let n = sqlx::query(SQL_RENEW)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(worker_name(worker)?)
        .bind(f64::from(LEASE_SECONDS))
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::NotFound)
}

/// Mark done.
pub async fn complete(tx: &mut TenantTx, id: JobId, worker: &str) -> Result<()> {
    let n = sqlx::query(SQL_DONE)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(worker_name(worker)?)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected();
    one(n, DbError::NotFound)
}

/// Record a failure; returns true when the job is now dead.
pub async fn fail(tx: &mut TenantTx, id: JobId, worker: &str) -> Result<bool> {
    let r = sqlx::query(SQL_FAIL)
        .bind(tx.tenant().uuid())
        .bind(id.uuid())
        .bind(worker_name(worker)?)
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
        .ok_or(DbError::NotFound)?;
    crate::repo::get_bool(&r, 0)
}

/// Purge finished jobs by id (the retention of 7 days is the worker's; no
/// completion time is stored).
pub async fn purge_done(tx: &mut TenantTx, ids: &[JobId]) -> Result<u64> {
    if ids.is_empty() || ids.len() > 1000 {
        return Err(DbError::InvalidInput("job ids"));
    }
    let u: Vec<uuid::Uuid> = ids.iter().map(|i| i.uuid()).collect();
    Ok(sqlx::query(SQL_PURGE_DONE)
        .bind(tx.tenant().uuid())
        .bind(&u)
        .execute(tx.conn())
        .await
        .map_err(db)?
        .rows_affected())
}
