// SPDX-License-Identifier: AGPL-3.0-or-later
//! PostgreSQL integration tests. Run via `scripts/pg-test.sh`; skipped (with a
//! message) when `CANDOR_TEST_PG` is unset. Each test uses a fresh database in the
//! throwaway cluster. Covers the conformance suite plus PG-only checks: live
//! schema lint (09 §8 L1–L4, L11–L13), intake settings (L11 `SHOW`), roles and
//! grants (DB-002, R7 SI-E-02), RLS tenant isolation (R7 SI-E-03), refusal of
//! privileged connections, durability across reconnects, no exact times stored.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use candor_intake_store::lint::check_columns;
use candor_intake_store::*;
use sqlx::postgres::PgConnectOptions;
use sqlx::{AssertSqlSafe, Connection, PgConnection, Row};

fn base() -> Option<PgConnectOptions> {
    let Ok(dir) = std::env::var("CANDOR_TEST_PG") else {
        eprintln!("skipping PostgreSQL test: CANDOR_TEST_PG unset (run scripts/pg-test.sh)");
        return None;
    };
    let port = std::env::var("CANDOR_TEST_PG_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5432);
    Some(
        PgConnectOptions::new_without_pgpass()
            .socket(dir)
            .port(port),
    )
}

fn superuser() -> String {
    std::env::var("CANDOR_TEST_PG_SUPERUSER").unwrap_or_else(|_| "pgtest".into())
}

/// Cluster-wide role DDL in concurrent migrations can race ("tuple concurrently
/// updated"); production runs one `candorctl migrate` at a time, tests serialise.
static MIGRATE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Create and migrate a fresh database; returns its name.
async fn fresh_db(base: &PgConnectOptions) -> String {
    let _g = MIGRATE_LOCK.lock().await;
    let name = format!("candor_intake_t{:016x}", rand_u64());
    let mut c =
        PgConnection::connect_with(&base.clone().username(&superuser()).database("postgres"))
            .await
            .unwrap();
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

fn rand_u64() -> u64 {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).unwrap();
    u64::from_le_bytes(b)
}

async fn open(base: &PgConnectOptions, db: &str, tenant: TenantId) -> PgIntakeStore {
    PgIntakeStore::open(
        base.clone().username("candor_istore").database(db),
        tenant,
        4,
    )
    .await
    .unwrap()
}

fn factory() -> Option<
    impl Fn(TenantId) -> std::pin::Pin<Box<dyn std::future::Future<Output = PgIntakeStore> + Send>>,
> {
    let b = base()?;
    Some(move |t: TenantId| {
        let b = b.clone();
        Box::pin(async move {
            let db = fresh_db(&b).await;
            open(&b, &db, t).await
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = PgIntakeStore> + Send>>
    })
}

conformance_tests!(factory());

async fn su(base: &PgConnectOptions, db: &str) -> PgConnection {
    PgConnection::connect_with(&base.clone().username(&superuser()).database(db))
        .await
        .unwrap()
}

/// 09 §8 L1–L4, L11–L13 against the live migrated catalog; DB-007, DB-008.
#[tokio::test]
async fn pg_schema_lint_live() {
    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let mut c = su(&b, &db).await;
    let rows = sqlx::query(
        "SELECT table_name::text, column_name::text, data_type::text, column_default::text \
         FROM information_schema.columns WHERE table_schema = 'candor' ORDER BY 1, 2",
    )
    .fetch_all(&mut c)
    .await
    .unwrap();
    let cols: Vec<(String, String, String, Option<String>)> = rows
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
        .collect();
    assert!(!cols.is_empty());
    let v = check_columns(&cols);
    assert!(v.is_empty(), "{v:?}");
    // No time-typed or network-typed column in ANY schema of the intake database
    // except PostgreSQL's own catalogs (L1, L3: intake allow-list is empty).
    let n: i64 = sqlx::query(
        "SELECT count(*) FROM information_schema.columns WHERE table_schema NOT IN ('pg_catalog', 'information_schema') \
         AND data_type IN ('timestamp without time zone', 'timestamp with time zone', 'time without time zone', \
         'time with time zone', 'interval', 'inet', 'cidr', 'macaddr', 'macaddr8')",
    )
    .fetch_one(&mut c)
    .await
    .unwrap()
    .get(0);
    assert_eq!(n, 0);
    // No views, sequences, publications or extensions beyond plpgsql.
    let extra: i64 = sqlx::query(
        "SELECT (SELECT count(*) FROM pg_catalog.pg_class k JOIN pg_catalog.pg_namespace n ON n.oid = k.relnamespace \
                 WHERE n.nspname = 'candor' AND k.relkind IN ('v', 'm', 'S')) \
              + (SELECT count(*) FROM pg_catalog.pg_publication) \
              + (SELECT count(*) FROM pg_catalog.pg_extension WHERE extname <> 'plpgsql')",
    )
    .fetch_one(&mut c)
    .await
    .unwrap()
    .get(0);
    assert_eq!(extra, 0);
}

/// L11 `SHOW` checks and logging hygiene (09 §10, ADR-046(1), R7 SI-E-04).
#[tokio::test]
async fn pg_settings() {
    let Some(b) = base() else { return };
    let mut c = PgConnection::connect_with(&b.clone().username(&superuser()).database("postgres"))
        .await
        .unwrap();
    for (name, want) in [
        ("wal_level", "minimal"),
        ("max_wal_senders", "0"),
        ("archive_mode", "off"),
        ("track_commit_timestamp", "off"),
        ("listen_addresses", ""),
        ("log_statement", "none"),
        ("log_parameter_max_length", "0"),
        ("log_parameter_max_length_on_error", "0"),
        ("log_min_error_statement", "panic"),
        ("fsync", "on"),
    ] {
        let got: String = sqlx::query("SELECT pg_catalog.current_setting($1)")
            .bind(name)
            .fetch_one(&mut c)
            .await
            .unwrap()
            .get(0);
        assert_eq!(got, want, "{name}");
    }
}

/// DB-002, R7 SI-E-02: app roles unprivileged, own nothing; backup role is
/// read-only on exactly the snapshot tables; nothing granted to PUBLIC.
#[tokio::test]
async fn pg_roles_and_grants() {
    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let mut c = su(&b, &db).await;
    let rows = sqlx::query(
        "SELECT rolname::text, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication, rolcanlogin \
         FROM pg_catalog.pg_roles WHERE rolname IN ('candor_istore', 'candor_intake_backup', 'candor_intake_migrator') ORDER BY 1",
    )
    .fetch_all(&mut c)
    .await
    .unwrap();
    assert_eq!(rows.len(), 3);
    for r in &rows {
        let name: String = r.get(0);
        for i in 1..6 {
            assert!(!r.get::<bool, _>(i), "{name} attribute {i}");
        }
        assert_eq!(
            r.get::<bool, _>(6),
            name != "candor_intake_migrator",
            "{name} login"
        );
    }
    let owners: Vec<String> = sqlx::query(
        "SELECT DISTINCT tableowner::text FROM pg_catalog.pg_tables WHERE schemaname = 'candor'",
    )
    .fetch_all(&mut c)
    .await
    .unwrap()
    .iter()
    .map(|r| r.get(0))
    .collect();
    assert_eq!(owners, vec!["candor_intake_migrator".to_string()]);
    let grants: Vec<(String, String, String)> = sqlx::query(
        "SELECT grantee::text, table_name::text, privilege_type::text FROM information_schema.role_table_grants \
         WHERE table_schema = 'candor' AND grantee <> 'candor_intake_migrator' ORDER BY 1, 2, 3",
    )
    .fetch_all(&mut c)
    .await
    .unwrap()
    .iter()
    .map(|r| (r.get(0), r.get(1), r.get(2)))
    .collect();
    assert!(
        grants.iter().all(|(g, _, p)| g != "PUBLIC"
            && p != "TRUNCATE"
            && p != "REFERENCES"
            && p != "TRIGGER"),
        "{grants:?}"
    );
    let backup: Vec<(String, String)> = grants
        .iter()
        .filter(|(g, _, _)| g == "candor_intake_backup")
        .map(|(_, t, p)| (t.clone(), p.clone()))
        .collect();
    assert_eq!(
        backup,
        vec![
            ("deletion_list".into(), "SELECT".into()),
            ("intake_meta".into(), "SELECT".into()),
            ("source_account".into(), "SELECT".into())
        ]
    );
    // deletion_list: no table-wide UPDATE for the app (column `relayed` only).
    assert!(!grants.contains(&(
        "candor_istore".into(),
        "deletion_list".into(),
        "UPDATE".into()
    )));
    // RLS enabled and forced on every data table.
    let unforced: i64 = sqlx::query(
        "SELECT count(*) FROM pg_catalog.pg_class k JOIN pg_catalog.pg_namespace n ON n.oid = k.relnamespace \
         WHERE n.nspname = 'candor' AND k.relkind = 'r' AND k.relname <> 'schema_migration' \
         AND NOT (k.relrowsecurity AND k.relforcerowsecurity)",
    )
    .fetch_one(&mut c)
    .await
    .unwrap()
    .get(0);
    assert_eq!(unforced, 0);
}

/// The store refuses a superuser (or owner) connection.
#[tokio::test]
async fn pg_refuses_privileged_role() {
    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let r = PgIntakeStore::open(
        b.clone().username(&superuser()).database(&db),
        common::TENANT,
        1,
    )
    .await;
    assert!(matches!(r, Err(StoreError::Integrity(_))));
}

/// R7 SI-E-03: a connection configured for another tenant sees nothing and can
/// write nothing; raw SQL without or with a wrong tenant setting sees zero rows.
#[tokio::test]
async fn pg_rls_tenant_isolation() {
    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let a = open(&b, &db, common::TENANT).await;
    a.init(common::TENANT, common::SALT).await.unwrap();
    a.commit_envelope(common::envelope(
        AccountLink::New(common::new_account(1)),
        0,
        1,
    ))
    .await
    .unwrap();
    a.apply_replies(common::TODAY, vec![common::reply(None, 1, 100)])
        .await
        .unwrap();

    let other = open(&b, &db, common::OTHER_TENANT).await;
    assert_eq!(
        other.init(common::OTHER_TENANT, common::SALT).await,
        Err(StoreError::TenantMismatch)
    );
    assert_eq!(other.pending_count().await, Err(StoreError::NotInitialized));
    assert_eq!(
        other.lookup_account(&LookupTag([1; 32])).await,
        Err(StoreError::NotInitialized)
    );
    assert_eq!(
        other
            .commit_envelope(common::envelope(AccountLink::None, 0, 0))
            .await,
        Err(StoreError::NotInitialized)
    );

    let mut c = PgConnection::connect_with(&b.clone().username("candor_istore").database(&db))
        .await
        .unwrap();
    for setting in [None, Some("22222222-2222-2222-2222-222222222222")] {
        let mut tx = c.begin().await.unwrap();
        if let Some(t) = setting {
            sqlx::query("SELECT pg_catalog.set_config('candor.tenant_id', $1, true)")
                .bind(t)
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        for q in [
            "SELECT count(*) FROM candor.intake_meta",
            "SELECT count(*) FROM candor.source_account",
            "SELECT count(*) FROM candor.envelope",
            "SELECT count(*) FROM candor.envelope_part",
            "SELECT count(*) FROM candor.reply",
            "SELECT count(*) FROM candor.deletion_list",
        ] {
            let n: i64 = sqlx::query(q).fetch_one(&mut *tx).await.unwrap().get(0);
            assert_eq!(n, 0, "{q} with {setting:?}");
        }
        let ins = sqlx::query(
            "INSERT INTO candor.counter_month (month, channel_id, name, value) VALUES (DATE '2026-10-01', \
             '33333333-3333-3333-3333-333333333333', 'accounts_created', 1)",
        )
        .execute(&mut *tx)
        .await;
        assert!(ins.is_err(), "insert must violate the RLS policy");
        tx.rollback().await.unwrap();
    }
    // The app role cannot bypass the guards: no TRUNCATE, no DDL.
    let mut tx = c.begin().await.unwrap();
    assert!(
        sqlx::query("TRUNCATE candor.reply")
            .execute(&mut *tx)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let mut tx = c.begin().await.unwrap();
    assert!(
        sqlx::query("ALTER TABLE candor.reply DISABLE ROW LEVEL SECURITY")
            .execute(&mut *tx)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
}

/// Durability: committed state survives a new pool (BE-071 via COMMIT; BE-074
/// deletion list durability); database guards reject tampering by the app role.
#[tokio::test]
async fn pg_durability_and_guards() {
    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let sg = common::signer();
    {
        let s = open(&b, &db, common::TENANT).await;
        s.init(common::TENANT, common::SALT).await.unwrap();
        s.commit_envelope(common::envelope(
            AccountLink::New(common::new_account(2)),
            0,
            0,
        ))
        .await
        .unwrap();
        let a = s
            .lookup_account(&LookupTag([2; 32]))
            .await
            .unwrap()
            .unwrap()
            .account_id;
        s.delete_account(a, common::TODAY, &sg).await.unwrap();
        s.install_directory_snapshot(common::snap(1, 10, 20700, 0), common::TODAY)
            .await
            .unwrap();
        s.close().await;
    }
    let s = open(&b, &db, common::TENANT).await;
    let list = s.deletion_list_after(0, 10).await.unwrap();
    assert_eq!(list.len(), 1);
    deletion::verify_chain(&list, &sg.verifying_key(), None).unwrap();
    assert_eq!(s.kd_high_water().await.unwrap().tree_size, 10);
    assert_eq!(s.pending_count().await.unwrap(), 1);

    // Direct tampering by the app role is refused by triggers.
    let mut c = PgConnection::connect_with(&b.clone().username("candor_istore").database(&db))
        .await
        .unwrap();
    for q in [
        "UPDATE candor.intake_meta SET kd_tree_size_hwm = 1",
        "UPDATE candor.intake_meta SET relay_req_counter = 0 WHERE relay_req_counter > 0 OR true",
        "UPDATE candor.deletion_list SET relayed = true",
        "DELETE FROM candor.intake_meta",
    ] {
        let mut tx = c.begin().await.unwrap();
        sqlx::query("SELECT pg_catalog.set_config('candor.tenant_id', $1, true)")
            .bind("11111111-1111-1111-1111-111111111111")
            .execute(&mut *tx)
            .await
            .unwrap();
        let r = sqlx::query(q).execute(&mut *tx).await;
        tx.rollback().await.unwrap();
        if q.starts_with("UPDATE candor.deletion_list") {
            // relayed false -> true is the one permitted update.
            assert!(r.is_ok(), "{q}");
        } else if q.contains("relay_req_counter = 0") {
            // counter is 0 already in this test: setting 0 is not a decrease.
            assert!(r.is_ok(), "{q}");
        } else {
            assert!(r.is_err(), "{q}");
        }
    }
    let mut tx = c.begin().await.unwrap();
    sqlx::query("SELECT pg_catalog.set_config('candor.tenant_id', $1, true)")
        .bind("11111111-1111-1111-1111-111111111111")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(
        sqlx::query("UPDATE candor.deletion_list SET del_day = del_day + 1")
            .execute(&mut *tx)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
}

/// Schema drift is refused at open (BE-050).
#[tokio::test]
async fn pg_schema_drift_refused() {
    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let mut c = su(&b, &db).await;
    sqlx::query("UPDATE candor.schema_migration SET sha256 = '\\x00000000000000000000000000000000000000000000000000000000000000ff'")
        .execute(&mut c)
        .await
        .unwrap();
    let r = PgIntakeStore::open(
        b.clone().username("candor_istore").database(&db),
        common::TENANT,
        1,
    )
    .await;
    assert!(matches!(r, Err(StoreError::Integrity(_))));
    assert!(matches!(
        migrate(&b.clone().username(&superuser()).database(&db)).await,
        Err(StoreError::Integrity(_))
    ));
}

/// ADR-010 / DB-008: after a full workload, every date-typed value in the intake
/// database is a whole day, and no relation stores a time-typed value.
#[tokio::test]
async fn pg_no_exact_times_stored() {
    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let s = open(&b, &db, common::TENANT).await;
    s.init(common::TENANT, common::SALT).await.unwrap();
    s.commit_envelope(common::envelope(
        AccountLink::New(common::new_account(3)),
        1,
        2,
    ))
    .await
    .unwrap();
    let a = s
        .lookup_account(&LookupTag([3; 32]))
        .await
        .unwrap()
        .unwrap()
        .account_id;
    s.apply_replies(common::TODAY, vec![common::reply(Some(a), 3, 100)])
        .await
        .unwrap();
    s.install_directory_snapshot(common::snap(1, 10, 20700, 0), common::TODAY)
        .await
        .unwrap();
    s.counter_add(
        common::TODAY.month_start(),
        ChannelId([1; 16]),
        CounterName::SubmissionsReceived,
        1,
    )
    .await
    .unwrap();
    s.delete_mailbox(
        a,
        &MailboxId([3; 32]),
        &[],
        common::TODAY,
        &common::signer(),
    )
    .await
    .unwrap();
    let mut c = su(&b, &db).await;
    // Every date column holds only the days we supplied (day granularity by type).
    let days: Vec<i32> = sqlx::query(
        "SELECT (received_date - DATE '1970-01-01')::int4 FROM candor.envelope \
         UNION ALL SELECT (release_day - DATE '1970-01-01')::int4 FROM candor.envelope \
         UNION ALL SELECT (available_day - DATE '1970-01-01')::int4 FROM candor.reply \
         UNION ALL SELECT (del_day - DATE '1970-01-01')::int4 FROM candor.deletion_list \
         UNION ALL SELECT (applied_day - DATE '1970-01-01')::int4 FROM candor.directory_snapshot",
    )
    .fetch_all(&mut c)
    .await
    .unwrap()
    .iter()
    .map(|r| r.get(0))
    .collect();
    let today = common::TODAY.0 as i32;
    assert!(
        days.iter().all(|d| *d == today || *d == today + 1),
        "{days:?}"
    );
    // track_commit_timestamp is off, so no commit time is retrievable for rows.
    let r = sqlx::query("SELECT pg_catalog.pg_xact_commit_timestamp(xmin) FROM candor.envelope")
        .fetch_all(&mut c)
        .await;
    assert!(r.is_err(), "commit timestamps must be unavailable");
}
