// SPDX-License-Identifier: AGPL-3.0-or-later
//! Embedded, checksummed, forward-only migrations (09 §11; BE-050). One
//! initial migration while the schema is pre-release (ADR-057 lesson); the
//! upgrade mechanism is an RM-5 item. Run by `candorctl migrate` as the
//! database owner / superuser of a fresh cluster; never at service start.

use sha2::{Digest, Sha256};
use sqlx::postgres::PgConnectOptions;
use sqlx::{ConnectOptions, Connection, PgConnection, Row};

use crate::classification::{CLASSIFICATION_TSV, ClassRow, parse_classification};
use crate::error::{DbError, Result, db};

/// Embedded forward-only migrations `(version, sql)`.
pub const MIGRATIONS: &[(i32, &str)] = &[(1, include_str!("../migrations/0001_case_schema.sql"))];

/// Expected `candor.schema_meta.schema_hash` of this build:
/// `SHA-256("candor/v1/case/schema" ‖ Σ (u32be version ‖ SHA-256(sql)) ‖ SHA-256(classification))`.
#[must_use]
pub fn schema_hash() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"candor/v1/case/schema");
    for (v, sql) in MIGRATIONS {
        h.update(v.to_be_bytes());
        h.update(Sha256::digest(sql.as_bytes()));
    }
    h.update(Sha256::digest(CLASSIFICATION_TSV.as_bytes()));
    h.finalize().into()
}

pub(crate) const SQL_LEDGER_EXISTS: &str =
    "SELECT pg_catalog.to_regclass('candor.schema_migration') IS NOT NULL";
const SQL_LEDGER_GET: &str = "SELECT sha256 FROM candor.schema_migration WHERE version = $1";
pub(crate) const SQL_LEDGER_ALL: &str =
    "SELECT version, sha256 FROM candor.schema_migration ORDER BY version";
const SQL_LEDGER_PUT: &str = "INSERT INTO candor.schema_migration (version, sha256) VALUES ($1, $2)";
const SQL_MIGRATE_TIMEOUTS: &str = "SELECT pg_catalog.set_config('lock_timeout', '10s', true), \
     pg_catalog.set_config('statement_timeout', '10min', true)";
const SQL_META_PUT: &str = "INSERT INTO candor.schema_meta (singleton, schema_hash) VALUES (true, $1)";
pub(crate) const SQL_META_GET: &str = "SELECT schema_hash FROM candor.schema_meta";
const SQL_CLASS_PUT: &str = "INSERT INTO candor.column_class (table_schema, table_name, column_name, class, ciphertext) \
     VALUES ($1, $2, $3, $4::text::candor.data_class, $5)";

pub(crate) fn get_arr<const N: usize>(row: &sqlx::postgres::PgRow, i: usize) -> Result<[u8; N]> {
    let v: Vec<u8> = row.try_get(i).map_err(db)?;
    v.try_into()
        .map_err(|_| DbError::Integrity("column length"))
}

/// Verify the applied ledger against the build (every version, every digest)
/// and the stored schema hash. Used by the migrator (second run) and at
/// every service open (schema drift refusal).
pub(crate) async fn verify_ledger(conn: &mut PgConnection) -> Result<()> {
    let applied = sqlx::query(SQL_LEDGER_ALL)
        .fetch_all(&mut *conn)
        .await
        .map_err(db)?;
    if applied.len() != MIGRATIONS.len() {
        return Err(DbError::Integrity("schema version mismatch"));
    }
    for (row, (v, sql)) in applied.iter().zip(MIGRATIONS) {
        let got_v: i32 = row.try_get(0).map_err(db)?;
        let digest: [u8; 32] = Sha256::digest(sql.as_bytes()).into();
        if got_v != *v || get_arr::<32>(row, 1)? != digest {
            return Err(DbError::Integrity("schema version mismatch"));
        }
    }
    let meta = sqlx::query(SQL_META_GET)
        .fetch_one(&mut *conn)
        .await
        .map_err(db)?;
    if get_arr::<32>(&meta, 0)? != schema_hash() {
        return Err(DbError::Integrity("schema hash mismatch"));
    }
    Ok(())
}

/// Run all pending embedded migrations, each in its own transaction with lock
/// and statement timeouts (SI-E-06); load the column classification; record
/// the build's schema hash. An already-applied migration must match its
/// recorded SHA-256 and the stored schema hash must match the build
/// (tamper/drift detection); otherwise the run refuses.
pub async fn migrate(opts: &PgConnectOptions) -> Result<()> {
    let rows: Vec<ClassRow> = parse_classification(CLASSIFICATION_TSV)?;
    let mut conn = PgConnection::connect_with(&opts.clone().disable_statement_logging())
        .await
        .map_err(db)?;
    let mut applied_any = false;
    for (version, sql) in MIGRATIONS {
        let digest: [u8; 32] = Sha256::digest(sql.as_bytes()).into();
        let mut tx = conn.begin().await.map_err(db)?;
        sqlx::query(SQL_MIGRATE_TIMEOUTS)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let ledger: bool = sqlx::query(SQL_LEDGER_EXISTS)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?
            .try_get(0)
            .map_err(db)?;
        if ledger {
            let got = sqlx::query(SQL_LEDGER_GET)
                .bind(*version)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;
            if let Some(row) = got {
                if get_arr::<32>(&row, 0)? != digest {
                    return Err(DbError::Integrity("applied migration differs from build"));
                }
                tx.rollback().await.map_err(db)?;
                continue;
            }
        }
        sqlx::raw_sql(*sql).execute(&mut *tx).await.map_err(db)?;
        if *version == 1 {
            for r in &rows {
                sqlx::query(SQL_CLASS_PUT)
                    .bind(&r.schema)
                    .bind(&r.table)
                    .bind(&r.column)
                    .bind(r.class.as_str())
                    .bind(r.ciphertext)
                    .execute(&mut *tx)
                    .await
                    .map_err(db)?;
            }
            sqlx::query(SQL_META_PUT)
                .bind(schema_hash().as_slice())
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        sqlx::query(SQL_LEDGER_PUT)
            .bind(*version)
            .bind(digest.as_slice())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        applied_any = true;
    }
    if !applied_any {
        verify_ledger(&mut conn).await?;
    }
    conn.close().await.map_err(db)
}
