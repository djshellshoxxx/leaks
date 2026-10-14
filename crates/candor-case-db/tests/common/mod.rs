// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared PostgreSQL test helpers.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use candor_case_db::*;
use sqlx::postgres::PgConnectOptions;
use sqlx::{AssertSqlSafe, Connection, PgConnection};

pub fn base() -> Option<PgConnectOptions> {
    // Unset: the test returns early and passes trivially (no free-text output,
    // LOG-001; run scripts/pg-test.sh to enable the suite).
    let dir = std::env::var("CANDOR_TEST_PG").ok()?;
    let port = std::env::var("CANDOR_TEST_PG_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5433);
    Some(
        PgConnectOptions::new_without_pgpass()
            .socket(dir)
            .port(port),
    )
}

pub fn superuser() -> String {
    std::env::var("CANDOR_TEST_PG_SUPERUSER").unwrap_or_else(|_| "pgcase".into())
}

/// Cluster-wide role DDL in concurrent migrations can race; serialise.
static MIGRATE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub fn rand_u64() -> u64 {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).unwrap();
    u64::from_le_bytes(b)
}

pub async fn su(base: &PgConnectOptions, db: &str) -> PgConnection {
    PgConnection::connect_with(&base.clone().username(&superuser()).database(db))
        .await
        .unwrap()
}

/// Create and migrate a fresh database; returns its name.
pub async fn fresh_db(base: &PgConnectOptions) -> String {
    let _g = MIGRATE_LOCK.lock().await;
    let name = format!("candor_case_t{:016x}", rand_u64());
    let mut c = su(base, "postgres").await;
    // Name is generated hex only: safe to splice for this DDL in tests.
    sqlx::raw_sql(AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&mut c)
        .await
        .unwrap();
    c.close().await.unwrap();
    let mig = base.clone().username(&superuser()).database(&name);
    migrate(&mig).await.unwrap();
    // Idempotent: a second run applies nothing and verifies the ledger.
    migrate(&mig).await.unwrap();
    name
}

pub async fn open(base: &PgConnectOptions, db: &str, role: Role) -> CaseDb {
    CaseDb::open(base.clone().username(role.pg_name()).database(db), role, 2)
        .await
        .unwrap()
}

pub async fn try_open(base: &PgConnectOptions, db: &str, role: Role) -> Result<CaseDb> {
    CaseDb::open(base.clone().username(role.pg_name()).database(db), role, 2).await
}

/// A plain connection as `role` (for raw probes in tests).
pub async fn conn(base: &PgConnectOptions, db: &str, role: &str) -> PgConnection {
    PgConnection::connect_with(&base.clone().username(role).database(db))
        .await
        .unwrap()
}

pub mod fixtures;
pub mod grants;

use sqlx::Row;
use uuid::Uuid;

pub fn uuid_of(id: &[u8; 16]) -> Uuid {
    Uuid::from_bytes(*id)
}

/// Begin a transaction on a raw connection with the three context settings
/// (what `TenantTx` does; used for raw probes).
pub async fn ctx<'c>(
    c: &'c mut PgConnection,
    tenant: Uuid,
    user: Uuid,
    kind: &str,
) -> sqlx::Transaction<'c, sqlx::Postgres> {
    let mut tx = c.begin().await.unwrap();
    sqlx::query(
        "SELECT pg_catalog.set_config('candor.tenant_id', $1::uuid::text, true), \
         pg_catalog.set_config('candor.user_id', $2::uuid::text, true), \
         pg_catalog.set_config('candor.principal_kind', $3::text, true)",
    )
    .bind(tenant)
    .bind(user)
    .bind(kind)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx
}

/// SQLSTATE of an error, if any.
pub fn sqlstate(e: &sqlx::Error) -> String {
    e.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned())
        .unwrap_or_default()
}

/// Count rows of a table under the current transaction's context.
pub async fn count(tx: &mut PgConnection, table: &str, filter: &str) -> i64 {
    sqlx::query(AssertSqlSafe(format!(
        "SELECT count(*) FROM {table} {filter}"
    )))
    .fetch_one(tx)
    .await
    .unwrap()
    .try_get(0)
    .unwrap()
}

/// Insert every fixture row for `tenant` as the superuser (RLS bypassed).
pub async fn load_fixtures(c: &mut PgConnection, tenant: Uuid, user: Uuid) {
    for (_, _, sql) in fixtures::FIXTURES {
        sqlx::query(AssertSqlSafe((*sql).to_string()))
            .bind(tenant)
            .bind(user)
            .execute(&mut *c)
            .await
            .unwrap_or_else(|e| panic!("fixture {sql}: {e}"));
    }
}

/// Principal kind text for a reader role.
pub fn kind_of(role: &str) -> &'static str {
    match role {
        "candor_case" => "desk",
        "candor_admin" => "admin",
        "candor_relay" => "relay",
        "candor_worker" => "worker:blob_gc",
        "candor_notify" => "notify",
        "candor_kd" => "kd",
        "candor_auth" => "auth",
        "candor_audit_w" => "audit_w",
        "candor_audit_r" => "audit_r",
        _ => "monitor",
    }
}
