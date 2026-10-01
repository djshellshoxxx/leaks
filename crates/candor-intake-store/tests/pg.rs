// SPDX-License-Identifier: AGPL-3.0-or-later
//! PostgreSQL integration tests. Run via `scripts/pg-test.sh`; skipped (with a
//! message) when `CANDOR_TEST_PG` is unset. Each test uses a fresh database in the
//! throwaway cluster. Covers the conformance suite plus PG-only checks: live
//! schema lint (09 §8 L1–L4, L11–L13), intake settings (L11 `SHOW`), roles and
//! grants (DB-002, R7 SI-E-02), RLS tenant isolation (R7 SI-E-03), refusal of
//! privileged connections, durability across reconnects, no exact times stored,
//! and the AUD-RM2-STO regressions that need a live server (row `xmin`, server
//! log, database guards, restart into restore-pending).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    // Test fixture only: a private 0700 temp root for candor-safefs
    // (pg_staged_ack_after_commit).
    clippy::disallowed_methods
)]

mod common;

use candor_intake_store::lint::check_columns;
use candor_intake_store::*;
use sqlx::postgres::PgConnectOptions;
use std::collections::HashSet;

use sqlx::{AssertSqlSafe, Connection, PgConnection, Row};

fn base() -> Option<PgConnectOptions> {
    // Unset: the test returns early and passes trivially (no free-text output
    // is allowed, LOG-001; run scripts/pg-test.sh to enable the suite).
    let dir = std::env::var("CANDOR_TEST_PG").ok()?;
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

/// Create and migrate a fresh database; returns its name. With `log_errors`,
/// the database logs WARNING and above (the cluster default is `panic`), so a
/// test can prove that no server error is written (AUD-RM2-STO-02).
async fn fresh_db_with(base: &PgConnectOptions, log_errors: bool) -> String {
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
    if log_errors {
        sqlx::raw_sql(AssertSqlSafe(format!(
            "ALTER DATABASE {name} SET log_min_messages = 'warning'"
        )))
        .execute(&mut c)
        .await
        .unwrap();
    }
    c.close().await.unwrap();
    let mig = base.clone().username(&superuser()).database(&name);
    migrate(&mig).await.unwrap();
    // Idempotent: a second run applies nothing and verifies the ledger.
    migrate(&mig).await.unwrap();
    name
}

async fn fresh_db(base: &PgConnectOptions) -> String {
    fresh_db_with(base, false).await
}

fn rand_u64() -> u64 {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).unwrap();
    u64::from_le_bytes(b)
}

async fn open_plain(base: &PgConnectOptions, db: &str, tenant: TenantId) -> PgIntakeStore {
    PgIntakeStore::open(
        base.clone().username("candor_istore").database(db),
        tenant,
        4,
        common::TEST_DEADDROP,
        Box::new(RandomDummyReplies),
    )
    .await
    .unwrap()
}

async fn maint(base: &PgConnectOptions, db: &str, tenant: TenantId) -> PgIntakeMaintenance {
    PgIntakeMaintenance::open(
        base.clone().username("candor_intake_maint").database(db),
        tenant,
        common::core_pk(),
    )
    .await
    .unwrap()
}

async fn open(base: &PgConnectOptions, db: &str, tenant: TenantId) -> PgIntakeStore {
    open_plain(base, db, tenant)
        .await
        .with_maintenance(maint(base, db, tenant).await)
}

/// The VACUUM connection: the maintenance role (database owner, no table;
/// AUD-RM2-STO-24(a)).
fn vac(base: &PgConnectOptions, db: &str) -> PgConnectOptions {
    base.clone().username("candor_intake_maint").database(db)
}

type ChunkRow = (Vec<u8>, Option<Vec<u8>>, u32);

type Fut = std::pin::Pin<Box<dyn std::future::Future<Output = PgIntakeStore> + Send>>;

fn factory_with(log_errors: bool) -> Option<impl Fn(TenantId) -> Fut> {
    let b = base()?;
    Some(move |t: TenantId| {
        let b = b.clone();
        Box::pin(async move {
            let db = fresh_db_with(&b, log_errors).await;
            open(&b, &db, t).await
        }) as Fut
    })
}

fn factory() -> Option<impl Fn(TenantId) -> Fut> {
    factory_with(false)
}

conformance_tests!(factory());

async fn su(base: &PgConnectOptions, db: &str) -> PgConnection {
    PgConnection::connect_with(&base.clone().username(&superuser()).database(db))
        .await
        .unwrap()
}

/// Run `q` as `role` in a tenant-scoped transaction that is rolled back.
async fn try_as(base: &PgConnectOptions, db: &str, role: &str, q: &str) -> bool {
    let mut c = PgConnection::connect_with(&base.clone().username(role).database(db))
        .await
        .unwrap();
    let mut tx = c.begin().await.unwrap();
    sqlx::query("SELECT pg_catalog.set_config('candor.tenant_id', $1, true)")
        .bind("11111111-1111-1111-1111-111111111111")
        .execute(&mut *tx)
        .await
        .unwrap();
    let r = sqlx::raw_sql(AssertSqlSafe(q.to_string()))
        .execute(&mut *tx)
        .await;
    tx.rollback().await.unwrap();
    r.is_ok()
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
    // ADR-052(2): no envelope table references an account.
    let fk: i64 = sqlx::query(
        "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'candor' \
         AND table_name IN ('envelope', 'envelope_part') AND column_name LIKE '%account%'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap()
    .get(0);
    assert_eq!(fk, 0);
}

/// L11 `SHOW` checks and logging hygiene (09 §10, ADR-046(1), ADR-052(14),
/// R7 SI-E-04, AUD-RM2-STO-02).
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
        ("log_min_messages", "panic"),
        ("logging_collector", "off"),
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
    // AUD-RM2-STO-11: the intake profile runs without cumulative statistics or
    // autovacuum (scripts/pg-test.sh; the "stock" profile keeps both on to
    // show the store does not depend on either).
    let stats = if std::env::var("CANDOR_TEST_PG_PROFILE").as_deref() == Ok("stock") {
        "on"
    } else {
        "off"
    };
    for (name, want) in [("track_counts", stats), ("autovacuum", stats)] {
        let got: String = sqlx::query("SELECT pg_catalog.current_setting($1)")
            .bind(name)
            .fetch_one(&mut c)
            .await
            .unwrap()
            .get(0);
        assert_eq!(got, want, "{name}");
    }
}

/// DB-002, R7 SI-E-02, AUD-RM2-STO-03/08: app roles unprivileged, own nothing;
/// the backup role is read-only on exactly the snapshot tables; the app role
/// cannot delete deletion-list entries or rewrite salt/schema hash; the
/// maintenance role holds only the prune privileges; temp_file_limit is set.
#[tokio::test]
async fn pg_roles_and_grants() {
    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let mut c = su(&b, &db).await;
    let rows = sqlx::query(
        "SELECT rolname::text, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication, rolcanlogin \
         FROM pg_catalog.pg_roles WHERE rolname IN ('candor_istore', 'candor_intake_backup', \
         'candor_intake_migrator', 'candor_intake_maint') ORDER BY 1",
    )
    .fetch_all(&mut c)
    .await
    .unwrap();
    assert_eq!(rows.len(), 4);
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
    // AUD-RM2-STO-24(a): the database is owned by the maintenance role, which
    // owns no table or schema and is in no other role except pg_checkpoint
    // (no membership in the schema owner).
    let dba: String = sqlx::query(
        "SELECT pg_catalog.pg_get_userbyid(datdba)::text FROM pg_catalog.pg_database \
         WHERE datname = pg_catalog.current_database()",
    )
    .fetch_one(&mut c)
    .await
    .unwrap()
    .get(0);
    assert_eq!(dba, "candor_intake_maint");
    let memberships: Vec<String> = sqlx::query(
        "SELECT pg_catalog.pg_get_userbyid(m.roleid)::text FROM pg_catalog.pg_auth_members m \
         JOIN pg_catalog.pg_roles r ON r.oid = m.member WHERE r.rolname = 'candor_intake_maint'",
    )
    .fetch_all(&mut c)
    .await
    .unwrap()
    .iter()
    .map(|r| r.get(0))
    .collect();
    assert_eq!(memberships, vec!["pg_checkpoint".to_string()]);
    // AUD-RM2-STO-11: autovacuum disabled on every intake table and its TOAST.
    let autovac: i64 = sqlx::query(
        "SELECT count(*) FROM pg_catalog.pg_class k JOIN pg_catalog.pg_namespace n ON n.oid = k.relnamespace \
         WHERE n.nspname = 'candor' AND k.relkind = 'r' AND k.relname <> 'schema_migration' \
         AND 'autovacuum_enabled=false' = ANY (k.reloptions) \
         AND (k.reltoastrelid = 0 OR (SELECT 'autovacuum_enabled=false' = ANY (t.reloptions) \
              FROM pg_catalog.pg_class t WHERE t.oid = k.reltoastrelid))",
    )
    .fetch_one(&mut c)
    .await
    .unwrap()
    .get(0);
    assert_eq!(autovac, 8);
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
    let of = |role: &str| -> Vec<(String, String)> {
        grants
            .iter()
            .filter(|(g, _, _)| g == role)
            .map(|(_, t, p)| (t.clone(), p.clone()))
            .collect()
    };
    assert_eq!(
        of("candor_intake_backup"),
        vec![
            ("deletion_list".into(), "SELECT".into()),
            ("intake_meta".into(), "SELECT".into()),
            ("source_account".into(), "SELECT".into())
        ]
    );
    assert_eq!(
        of("candor_intake_maint"),
        vec![
            ("deletion_list".into(), "DELETE".into()),
            ("deletion_list".into(), "SELECT".into()),
            ("intake_meta".into(), "SELECT".into()),
            ("schema_migration".into(), "SELECT".into())
        ]
    );
    let app = of("candor_istore");
    for (t, p) in [
        ("deletion_list", "DELETE"),
        ("deletion_list", "UPDATE"),
        ("intake_meta", "UPDATE"),
        ("intake_meta", "DELETE"),
    ] {
        assert!(!app.contains(&(t.into(), p.into())), "app has {p} on {t}");
    }
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
    // 09 §10: temp_file_limit for the app role (set by a superuser migration).
    let settings: Vec<String> = sqlx::query(
        "SELECT unnest(s.setconfig) FROM pg_catalog.pg_db_role_setting s \
         JOIN pg_catalog.pg_roles r ON r.oid = s.setrole \
         JOIN pg_catalog.pg_database d ON d.oid = s.setdatabase \
         WHERE r.rolname = 'candor_istore' AND d.datname = current_database()",
    )
    .fetch_all(&mut c)
    .await
    .unwrap()
    .iter()
    .map(|r| r.get(0))
    .collect();
    assert!(
        settings.contains(&"temp_file_limit=1GB".to_string()),
        "{settings:?}"
    );
    // Column-level: the app may not change identity columns of intake_meta.
    for q in [
        "UPDATE candor.intake_meta SET kdf_salt = kdf_salt",
        "UPDATE candor.intake_meta SET schema_hash = schema_hash",
    ] {
        assert!(!try_as(&b, &db, "candor_istore", q).await, "{q}");
    }
}

/// The store refuses a superuser, a member of an owning role, and a schema whose
/// guard trigger was disabled (AUD-RM2-STO-08).
#[tokio::test]
async fn pg_refuses_privileged_role() {
    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let open_as = |role: String| {
        let b = b.clone();
        let db = db.clone();
        async move {
            PgIntakeStore::open(
                b.username(&role).database(&db),
                common::TENANT,
                1,
                common::TEST_DEADDROP,
                Box::new(RandomDummyReplies),
            )
            .await
        }
    };
    assert!(matches!(
        open_as(superuser()).await,
        Err(StoreError::Integrity(_))
    ));
    // A login role that is a member of the owning role (provisioning mistake).
    let mut c = su(&b, &db).await;
    sqlx::raw_sql(
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'candor_probe') THEN \
         CREATE ROLE candor_probe LOGIN NOINHERIT; END IF; END $$",
    )
    .execute(&mut c)
    .await
    .unwrap();
    sqlx::raw_sql(AssertSqlSafe(format!(
        "GRANT CONNECT ON DATABASE {db} TO candor_probe; GRANT candor_intake_migrator TO candor_probe"
    )))
    .execute(&mut c)
    .await
    .unwrap();
    assert!(matches!(
        open_as("candor_probe".into()).await,
        Err(StoreError::Integrity(_))
    ));
    // The app role itself opens; after a guard trigger is disabled it refuses.
    assert!(open_as("candor_istore".into()).await.is_ok());
    sqlx::query("ALTER TABLE candor.deletion_list DISABLE TRIGGER deletion_list_guard")
        .execute(&mut c)
        .await
        .unwrap();
    assert!(matches!(
        open_as("candor_istore".into()).await,
        Err(StoreError::Integrity(_))
    ));
}

/// R7 SI-E-03: a connection configured for another tenant sees nothing and can
/// write nothing; raw SQL without or with a wrong tenant setting sees zero rows.
#[tokio::test]
async fn pg_rls_tenant_isolation() {
    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let a = open(&b, &db, common::TENANT).await;
    a.init(common::TENANT, common::SALT).await.unwrap();
    common::account(&a, 1).await;
    a.commit_envelope(common::envelope(0)).await.unwrap();
    a.apply_replies(common::TODAY, vec![common::reply(None, 1, 100)])
        .await
        .unwrap();

    let other = open_plain(&b, &db, common::OTHER_TENANT).await;
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
        other.commit_envelope(common::envelope(0)).await,
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
    for q in [
        "TRUNCATE candor.reply",
        "ALTER TABLE candor.reply DISABLE ROW LEVEL SECURITY",
    ] {
        assert!(!try_as(&b, &db, "candor_istore", q).await, "{q}");
    }
}

/// Durability across reconnects (BE-071, BE-074), restart into restore-pending
/// (AUD-RM2-STO-05) and the database guards against a compromised app role,
/// including the two-statement bypass of AUD-RM2-STO-03.
#[tokio::test]
async fn pg_durability_and_guards() {
    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let sg = common::signer();
    let pk = sg.verifying_key();
    {
        let s = open(&b, &db, common::TENANT).await;
        s.init(common::TENANT, common::SALT).await.unwrap();
        s.commit_envelope(common::envelope(0)).await.unwrap();
        for t in [2u8, 3, 4] {
            let a = common::account(&s, t).await;
            s.delete_account(a, common::TODAY, &sg).await.unwrap();
        }
        s.install_directory_snapshot(common::snap(1, 10, 20700, 0), common::TODAY)
            .await
            .unwrap();
        assert!(s.serving_allowed().await.unwrap());
        s.close().await;
    }
    // Process restart: restore-pending until Z-CORE confirms the head.
    let s = open(&b, &db, common::TENANT).await;
    assert!(!s.serving_allowed().await.unwrap());
    assert_eq!(
        s.commit_envelope(common::envelope(0)).await,
        Err(StoreError::RestorePending)
    );
    let list = s.deletion_list_after(0, 10).await.unwrap();
    assert_eq!(list.len(), 3);
    deletion::verify_chain(&list, &pk, None).unwrap();
    assert_eq!(s.kd_high_water().await.unwrap().tree_size, 10);
    assert_eq!(s.pending_count().await.unwrap(), 1);
    // App role: no flagging, no deletion, not even after flipping relayed
    // (AUD-RM2-STO-03 two-statement bypass).
    for q in [
        "UPDATE candor.deletion_list SET relayed = true",
        "DELETE FROM candor.deletion_list",
        "DELETE FROM candor.deletion_list WHERE relayed",
        "UPDATE candor.deletion_list SET relayed = true; DELETE FROM candor.deletion_list;",
        "UPDATE candor.deletion_list SET del_day = del_day + 1",
        "UPDATE candor.intake_meta SET kd_tree_size_hwm = 1",
        "UPDATE candor.intake_meta SET deletion_acked_seq = 99",
        "DELETE FROM candor.intake_meta",
    ] {
        assert!(!try_as(&b, &db, "candor_istore", q).await, "app: {q}");
    }
    // The unchanged rewrite is allowed.
    assert!(
        try_as(
            &b,
            &db,
            "candor_istore",
            "UPDATE candor.deletion_list SET relayed = relayed"
        )
        .await
    );
    // Maintenance role: never unacknowledged entries, never the head.
    for q in [
        "UPDATE candor.deletion_list SET relayed = true",
        "DELETE FROM candor.deletion_list WHERE seq = 3",
        "UPDATE candor.deletion_list SET relayed = true WHERE seq = 1; DELETE FROM candor.deletion_list;",
    ] {
        assert!(
            !try_as(&b, &db, "candor_intake_maint", q).await,
            "maint: {q}"
        );
    }
    // Z-CORE's copy must end at its signed head: a truncated copy is refused.
    let h3 = common::zhead(list.last());
    assert!(
        s.apply_pushed_deletion_list(
            &list[..1],
            &h3,
            &common::core_pk(),
            &pk,
            &common::PrefixHasher,
            common::TODAY
        )
        .await
        .is_err()
    );
    assert!(!s.serving_allowed().await.unwrap());
    assert_eq!(
        s.apply_pushed_deletion_list(
            &list,
            &h3,
            &common::core_pk(),
            &pk,
            &common::PrefixHasher,
            common::TODAY,
        )
        .await
        .unwrap(),
        3
    );
    assert!(s.serving_allowed().await.unwrap());
    assert!(
        !try_as(
            &b,
            &db,
            "candor_intake_maint",
            "UPDATE candor.deletion_list SET relayed = true; \
             DELETE FROM candor.deletion_list WHERE seq = (SELECT max(seq) FROM candor.deletion_list);"
        )
        .await,
        "head is never deletable"
    );
    assert!(
        try_as(
            &b,
            &db,
            "candor_intake_maint",
            "UPDATE candor.deletion_list SET relayed = true; DELETE FROM candor.deletion_list WHERE seq < 3;"
        )
        .await
    );
    // Store-level prune keeps the head.
    assert_eq!(
        s.prune_deletion_list(common::TODAY.plus(100).unwrap())
            .await
            .unwrap(),
        2
    );
    assert_eq!(s.deletion_list_after(0, 10).await.unwrap().len(), 1);
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
        common::TEST_DEADDROP,
        Box::new(RandomDummyReplies),
    )
    .await;
    assert!(matches!(r, Err(StoreError::Integrity(_))));
    assert!(matches!(
        migrate(&b.clone().username(&superuser()).database(&db)).await,
        Err(StoreError::Integrity(_))
    ));
}

/// Mixed source and relay activity within one slot.
async fn workload(s: &PgIntakeStore) -> AccountId {
    let sg = common::signer();
    let a = common::account(s, 3).await;
    let gone = common::account(s, 4).await;
    s.commit_envelope(common::envelope(1)).await.unwrap();
    s.commit_envelope(common::envelope(0)).await.unwrap();
    s.apply_replies(
        common::TODAY,
        vec![
            common::reply(Some(a), 3, 100),
            common::reply(Some(a), 3, 120),
            common::reply(None, 9, 300),
        ],
    )
    .await
    .unwrap();
    let r = s.mailbox_list(a).await.unwrap()[0].clone();
    let oh: [u8; 32] = r.reply_ct[..32].try_into().unwrap();
    s.delete_replies(a, &[(r.reply_ref, oh)], common::TODAY, &sg)
        .await
        .unwrap();
    s.delete_mailbox(a, &MailboxId([3; 32]), &[], common::TODAY, &sg)
        .await
        .unwrap();
    s.delete_account(gone, common::TODAY, &sg).await.unwrap();
    s.install_directory_snapshot(common::snap(1, 10, 20700, 0), common::TODAY)
        .await
        .unwrap();
    s.rebuild_published_set(common::slot(common::TODAY))
        .await
        .unwrap();
    let lim = ClaimLimits {
        max_objects: 1,
        max_bytes: MAX_CLAIM_BYTES,
    };
    let bt = s.claim_batch(common::TODAY, lim).await.unwrap();
    s.ack_batch(bt.batch_no, &[bt.objects[0].sha256])
        .await
        .unwrap();
    s.deletion_list_after(1, 10).await.unwrap();
    a
}

const XMIN_UNION: &str = "SELECT xmin::text FROM candor.source_account \
     UNION ALL SELECT xmin::text FROM candor.envelope \
     UNION ALL SELECT xmin::text FROM candor.envelope_part \
     UNION ALL SELECT xmin::text FROM candor.reply \
     UNION ALL SELECT xmin::text FROM candor.deletion_list \
     UNION ALL SELECT xmin::text FROM candor.counter_month \
     UNION ALL SELECT xmin::text FROM candor.directory_snapshot \
     UNION ALL SELECT xmin::text FROM candor.intake_meta";

async fn acct_xmin(c: &mut PgConnection, a: AccountId) -> (String, String) {
    let r = sqlx::query(
        "SELECT xmin::text, ctid::text FROM candor.source_account WHERE account_id = $1",
    )
    .bind(uuid::Uuid::from_bytes(a.0))
    .fetch_one(c)
    .await
    .unwrap();
    (r.get(0), r.get(1))
}

async fn distinct_xmin(c: &mut PgConnection) -> (i64, i64) {
    let r = sqlx::query(AssertSqlSafe(format!(
        "SELECT count(*), count(DISTINCT x) FROM ({XMIN_UNION}) t(x)"
    )))
    .fetch_one(c)
    .await
    .unwrap();
    (r.get(0), r.get(1))
}

/// AUD-RM2-STO-01: after a mixture of actions within a slot, the import-slot
/// rewrite leaves every source-linkable row with the same `xmin` (and no lock
/// `xmax`), so row versions reveal only the slot; a source envelope commit never
/// writes an account row.
#[tokio::test]
async fn pg_uniform_rewrite_xmin() {
    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let s = open(&b, &db, common::TENANT).await;
    s.init(common::TENANT, common::SALT).await.unwrap();
    let a = workload(&s).await;
    let mut c = su(&b, &db).await;
    let before = acct_xmin(&mut c, a).await;
    s.commit_envelope(common::envelope(0)).await.unwrap();
    assert_eq!(
        acct_xmin(&mut c, a).await,
        before,
        "commit never writes accounts"
    );
    let (rows, distinct) = distinct_xmin(&mut c).await;
    assert!(rows > 10 && distinct > 1, "{rows} rows, {distinct} xmins");
    s.uniform_rewrite(
        common::slot(common::TODAY),
        &[CounterDelta {
            month: common::TODAY.month_start(),
            channel_id: ChannelId([1; 16]),
            name: CounterName::SubmissionsReceived,
            delta: 2,
        }],
        &[a],
    )
    .await
    .unwrap();
    let (rows2, distinct2) = distinct_xmin(&mut c).await;
    assert!(rows2 >= rows);
    assert_eq!(distinct2, 1, "all source-linkable rows share one xmin");
    // A row whose table has a BEFORE UPDATE trigger keeps the rewriting
    // transaction's own id as a lock-only xmax: it reveals nothing beyond xmin.
    let foreign: i64 = sqlx::query(AssertSqlSafe(format!(
        "SELECT count(*) FROM ({}) t(n, x) WHERE x <> '0' AND x <> n",
        XMIN_UNION.replace("xmin::text", "xmin::text, xmax::text")
    )))
    .fetch_one(&mut c)
    .await
    .unwrap()
    .get(0);
    assert_eq!(foreign, 0, "no row carries another transaction's xmax");
}

/// AUD-RM2-STO-02: the whole conformance suite runs without a single server-side
/// ERROR/WARNING/FATAL line (expected outcomes never raise errors). The suite's
/// databases log at `warning`; every other database logs nothing (`panic`).
#[tokio::test]
async fn pg_no_server_errors_on_expected_paths() {
    let Some(b) = base() else { return };
    let Ok(log) = std::env::var("CANDOR_TEST_PG_LOG") else {
        return;
    };
    let start = server_log(&b, &log).await.len();
    macro_rules! run {
        ($($f:ident),*) => { $( common::$f(factory_with(true).unwrap()).await; )* };
    }
    run!(
        init_and_meta,
        accounts,
        envelope_validation,
        claim_ack,
        claim_limits,
        claim_fairness,
        dead_drop,
        reply_backlog,
        reply_rules,
        deletion_list,
        kd_snapshots,
        counters,
        activity_fold,
        restore_pending_gate,
        backup_restore,
        dead_drop_sizes
    );
    let text = server_log(&b, &log).await;
    let new = String::from_utf8_lossy(text.get(start..).unwrap_or(&[]));
    let bad: Vec<&str> = new
        .lines()
        .filter(|l| l.contains("ERROR") || l.contains("WARNING") || l.contains("FATAL"))
        .collect();
    assert!(bad.is_empty(), "server log lines: {bad:?}");
    // Positive control: a real server error in such a database is captured
    // (with the pre-fix duplicate handling, every DuplicateEnvelope and
    // AccountExists produced a line like this).
    let db = fresh_db_with(&b, true).await;
    assert!(!try_as(&b, &db, "candor_istore", "SELECT 1 / 0").await);
    let text = server_log(&b, &log).await;
    let all = String::from_utf8_lossy(&text);
    assert!(all.contains("ERROR"), "log capture does not work");
}

/// The test cluster's server log, read through the server itself (superuser
/// `pg_read_binary_file`; the workspace bans direct filesystem reads, ADR-027).
async fn server_log(b: &PgConnectOptions, path: &str) -> Vec<u8> {
    let mut c = su(b, "postgres").await;
    sqlx::query("SELECT pg_catalog.pg_read_binary_file($1)")
        .bind(path)
        .fetch_one(&mut c)
        .await
        .unwrap()
        .get(0)
}

/// ADR-010 / DB-008: after a full workload, every date-typed value in the intake
/// database is a whole day (applied_day a month), and no relation stores a
/// time-typed value.
#[tokio::test]
async fn pg_no_exact_times_stored() {
    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let s = open(&b, &db, common::TENANT).await;
    s.init(common::TENANT, common::SALT).await.unwrap();
    workload(&s).await;
    let mut c = su(&b, &db).await;
    let days: Vec<i32> = sqlx::query(
        "SELECT (received_date - DATE '1970-01-01')::int4 FROM candor.envelope \
         UNION ALL SELECT (release_day - DATE '1970-01-01')::int4 FROM candor.envelope \
         UNION ALL SELECT (available_day - DATE '1970-01-01')::int4 FROM candor.reply WHERE pub_gen IS NULL \
         UNION ALL SELECT (del_day - DATE '1970-01-01')::int4 FROM candor.deletion_list",
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
    let applied: i32 = sqlx::query(
        "SELECT (applied_day - DATE '1970-01-01')::int4 FROM candor.directory_snapshot",
    )
    .fetch_one(&mut c)
    .await
    .unwrap()
    .get(0);
    assert_eq!(applied as u32, common::TODAY.month_start().0);
    let r = sqlx::query("SELECT pg_catalog.pg_xact_commit_timestamp(xmin) FROM candor.envelope")
        .fetch_all(&mut c)
        .await;
    assert!(r.is_err(), "commit timestamps must be unavailable");
}

/// AUD-RM2-STO-11: the maintenance role can reset the cumulative statistics.
#[tokio::test]
async fn pg_statistics_reset() {
    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let m = maint(&b, &db, common::TENANT).await;
    m.reset_statistics().await.unwrap();
}

/// Run `q` as `role` in a tenant-scoped transaction and commit it.
async fn commit_as(base: &PgConnectOptions, db: &str, role: &str, q: &str) -> bool {
    let mut c = PgConnection::connect_with(&base.clone().username(role).database(db))
        .await
        .unwrap();
    let mut tx = c.begin().await.unwrap();
    sqlx::query("SELECT pg_catalog.set_config('candor.tenant_id', $1, true)")
        .bind("11111111-1111-1111-1111-111111111111")
        .execute(&mut *tx)
        .await
        .unwrap();
    match sqlx::raw_sql(AssertSqlSafe(q.to_string()))
        .execute(&mut *tx)
        .await
    {
        Ok(_) => {
            tx.commit().await.unwrap();
            true
        }
        Err(_) => {
            tx.rollback().await.unwrap();
            false
        }
    }
}

/// AUD-RM2-STO-21 (the audit probe): the application role can neither insert
/// an out-of-sequence head nor pre-flag an entry, and cannot acknowledge a
/// head outside the local chain; a chained junk entry plus an acknowledgement
/// without Z-CORE's signature is accepted by the database but the maintenance
/// process re-verifies the signature and prunes nothing.
#[tokio::test]
async fn pg_deletion_list_append_guard() {
    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let s = open(&b, &db, common::TENANT).await;
    s.init(common::TENANT, common::SALT).await.unwrap();
    let sg = common::signer();
    for t in [2u8, 3, 4] {
        let a = common::account(&s, t).await;
        s.delete_account(a, common::TODAY, &sg).await.unwrap();
    }
    let app = "candor_istore";
    let zeros = |n: usize| format!("pg_catalog.decode(pg_catalog.repeat('00', {n}), 'hex')");
    // The audit probe: an arbitrary out-of-sequence head.
    assert!(
        !commit_as(
            &b,
            &db,
            app,
            &format!(
                "INSERT INTO candor.deletion_list VALUES (1000, 'account', {}, DATE '2026-01-01', {}, {}, false)",
                zeros(32),
                zeros(32),
                zeros(64)
            )
        )
        .await,
        "out-of-sequence insert"
    );
    // Correctly chained but pre-flagged relayed: refused.
    let chained = |relayed: bool| {
        format!(
            "INSERT INTO candor.deletion_list SELECT 4, 'account', d.del_hash, DATE '2026-01-01', \
             candor.deletion_chain_hash(d), d.sig, {relayed} FROM candor.deletion_list d WHERE d.seq = 3"
        )
    };
    assert!(
        !commit_as(&b, &db, app, &chained(true)).await,
        "pre-flagged"
    );
    // Below the oldest entry without a link: refused.
    assert!(
        !commit_as(
            &b,
            &db,
            app,
            &format!(
                "INSERT INTO candor.deletion_list VALUES (1, 'account', {}, DATE '2026-01-01', {}, {}, false)",
                zeros(32),
                zeros(32),
                zeros(64)
            )
        )
        .await,
        "duplicate/unlinked genesis"
    );
    // Acknowledgement beyond the chain, or with a wrong hash: refused.
    assert!(
        !commit_as(
            &b,
            &db,
            app,
            &format!(
                "UPDATE candor.intake_meta SET deletion_acked_seq = 1000, deletion_acked_hash = {}, deletion_acked_sig = {}, \
                 deletion_acked_day = DATE '2026-01-01', deletion_acked_counter = 1",
                zeros(32),
                zeros(64)
            )
        )
        .await
    );
    assert!(
        !commit_as(
            &b,
            &db,
            app,
            &format!(
                "UPDATE candor.intake_meta SET deletion_acked_seq = 3, deletion_acked_hash = {}, deletion_acked_sig = {}, \
                 deletion_acked_day = DATE '2026-01-01', deletion_acked_counter = 1",
                zeros(32),
                zeros(64)
            )
        )
        .await
    );
    // A chained junk entry and a chain-consistent acknowledgement with a junk
    // signature pass the database (it cannot verify Ed25519) ...
    assert!(commit_as(&b, &db, app, &chained(false)).await);
    assert!(
        commit_as(
            &b,
            &db,
            app,
            &format!(
                "UPDATE candor.intake_meta SET deletion_acked_seq = 4, deletion_acked_hash = \
                 (SELECT candor.deletion_chain_hash(d) FROM candor.deletion_list d WHERE d.seq = 4), \
                 deletion_acked_sig = {}, deletion_acked_day = DATE '2026-01-01', deletion_acked_counter = 1",
                zeros(64)
            )
        )
        .await
    );
    // AUD-RM2-STO-24: the stored head cannot change without a newer
    // attestation counter, and counter and day never decrease.
    for q in [
        "UPDATE candor.intake_meta SET deletion_acked_sig = pg_catalog.decode(pg_catalog.repeat('11', 64), 'hex')",
        "UPDATE candor.intake_meta SET deletion_acked_day = DATE '2026-01-02'",
        "UPDATE candor.intake_meta SET deletion_acked_counter = 0",
        "UPDATE candor.intake_meta SET deletion_acked_day = DATE '2025-12-31', deletion_acked_counter = 2",
    ] {
        assert!(!commit_as(&b, &db, app, q).await, "{q}");
    }
    // ... but the maintenance process verifies Z-CORE's signature and refuses.
    assert!(matches!(
        s.prune_deletion_list(common::TODAY.plus(400).unwrap())
            .await,
        Err(StoreError::DeletionList(_))
    ));
    let mut c = su(&b, &db).await;
    let left: Vec<(i64, bool)> =
        sqlx::query("SELECT seq, relayed FROM candor.deletion_list ORDER BY seq")
            .fetch_all(&mut c)
            .await
            .unwrap()
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect();
    assert_eq!(left, vec![(1, false), (2, false), (3, false), (4, false)]);
}

/// Kendall's tau between two rankings given as pairs (x, y).
fn kendall_tau(v: &[(usize, u32)]) -> f64 {
    let (mut c, mut d) = (0i64, 0i64);
    for i in 0..v.len() {
        for j in i + 1..v.len() {
            let s = (v[i].0 as i64 - v[j].0 as i64) * (i64::from(v[i].1) - i64::from(v[j].1));
            if s > 0 {
                c += 1;
            } else if s < 0 {
                d += 1;
            }
        }
    }
    (c - d) as f64 / (c + d).max(1) as f64
}

/// `(key attribute, toast chunk_id)` of every live tuple of `table`, read from
/// the raw heap pages (pageinspect): the attribute `toast_attr` must be an
/// on-disk TOAST pointer (`0x01`, tag 18, …, `va_valueid` at bytes 10..14).
async fn chunk_ids(
    c: &mut PgConnection,
    table: &str,
    key_attr: usize,
    toast_attr: usize,
) -> Vec<ChunkRow> {
    let rows = sqlx::query(AssertSqlSafe(format!(
        "SELECT a.t_attrs[{key_attr}], a.t_attrs[2], a.t_attrs[{toast_attr}] \
         FROM generate_series(0, (pg_relation_size('{table}') / 8192)::int - 1) p, \
         LATERAL heap_page_item_attrs(get_raw_page('{table}', p), '{table}'::regclass) a \
         WHERE a.lp_flags = 1"
    )))
    .fetch_all(c)
    .await
    .unwrap();
    rows.iter()
        .map(|r| {
            let key: Vec<u8> = r.get(0);
            let second: Option<Vec<u8>> = r.get(1);
            let ptr: Vec<u8> = r.get(2);
            assert_eq!(
                (ptr[0], ptr[1], ptr.len()),
                (0x01, 18, 18),
                "{table}: toast pointer"
            );
            (
                key,
                second,
                u32::from_le_bytes(ptr[10..14].try_into().unwrap()),
            )
        })
        .collect()
}

/// `(reply_ref bytes, first 12 bytes of reply_ct)` of every reply.
async fn reply_prefixes(c: &mut PgConnection) -> Vec<(Vec<u8>, Vec<u8>)> {
    sqlx::query("SELECT reply_ref, substring(reply_ct from 1 for 12) FROM candor.reply")
        .fetch_all(c)
        .await
        .unwrap()
        .iter()
        .map(|r| {
            let id: uuid::Uuid = r.get(0);
            (id.as_bytes().to_vec(), r.get::<Vec<u8>, _>(1))
        })
        .collect()
}

/// `t_xmin` of every live (LP_NORMAL) tuple in the raw pages of `rel`.
async fn raw_xmins(c: &mut PgConnection, rel: &str) -> Vec<String> {
    sqlx::query(AssertSqlSafe(format!(
        "SELECT t.t_xmin::text FROM generate_series(0, (pg_relation_size('{rel}') / 8192)::int - 1) p, \
         LATERAL heap_page_items(get_raw_page('{rel}', p)) t WHERE t.lp_flags = 1"
    )))
    .fetch_all(c)
    .await
    .unwrap()
    .iter()
    .map(|r| r.get(0))
    .collect()
}

/// AUD-RM2-STO-18: after a mixed workload, `uniform_rewrite` re-creates every
/// out-of-line value (new chunk_ids, the slot's `xmin`) in a shuffled order,
/// account and envelope rows stay in line, and after the post-rewrite VACUUM
/// the raw pages of every intake table and TOAST table hold only tuples with
/// the slot's `xmin`. Pre-fix, TOAST tuples kept their creation `xmin` and the
/// chunk_id order equalled the creation order (positive control below).
#[tokio::test]
async fn pg_uniform_rewrite_toast() {
    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let s = open(&b, &db, common::TENANT).await;
    s.init(common::TENANT, common::SALT).await.unwrap();
    let a = workload(&s).await;
    for t in 40u8..48 {
        let mut na = common::new_account(t);
        na.prefs_ct = vec![t; MAX_PREFS_CT];
        s.create_account(na, common::TODAY).await.unwrap();
    }
    let n = 40usize;
    let mut envs = Vec::new();
    let mut replies = Vec::new();
    for _ in 0..n {
        envs.push(s.commit_envelope(common::envelope(0)).await.unwrap());
        let r = common::reply(None, 0x71, 9000);
        replies.push(r.reply_ct[..12].to_vec());
        s.apply_replies(common::TODAY, vec![r]).await.unwrap();
    }
    let mut big = common::snap(2, 20, 20701, 10);
    big.body = vec![0; 200_000];
    getrandom::fill(&mut big.body).unwrap();
    s.install_directory_snapshot(big, common::TODAY)
        .await
        .unwrap();

    let mut c = su(&b, &db).await;
    sqlx::raw_sql("CREATE EXTENSION IF NOT EXISTS pageinspect")
        .execute(&mut c)
        .await
        .unwrap();
    let env_rank = |rows: &[ChunkRow]| -> Vec<(usize, u32)> {
        rows.iter()
            .filter(|(_, part, _)| part.as_deref() == Some(&[0u8, 0][..]))
            .filter_map(|(k, _, id)| {
                envs.iter()
                    .position(|e| e.0.as_slice() == k.as_slice())
                    .map(|i| (i, *id))
            })
            .collect()
    };
    let reply_rank = |rows: &[ChunkRow], cts: &[(Vec<u8>, Vec<u8>)]| -> Vec<(usize, u32)> {
        rows.iter()
            .filter_map(|(k, _, id)| {
                let ct = &cts.iter().find(|(r, _)| r == k)?.1;
                replies
                    .iter()
                    .position(|p| ct.starts_with(p))
                    .map(|i| (i, *id))
            })
            .collect()
    };
    // Positive control: before the rewrite chunk_ids follow creation order.
    let before = env_rank(&chunk_ids(&mut c, "candor.envelope_part", 1, 4).await);
    assert_eq!(before.len(), n);
    assert!(
        kendall_tau(&before) > 0.95,
        "control: {}",
        kendall_tau(&before)
    );
    let cts = reply_prefixes(&mut c).await;
    let rb = reply_rank(&chunk_ids(&mut c, "candor.reply", 1, 3).await, &cts);
    assert_eq!(rb.len(), n);
    assert!(kendall_tau(&rb) > 0.95);

    s.uniform_rewrite(common::slot(common::TODAY), &[], &[a])
        .await
        .unwrap();
    vacuum_after_rewrite(&vac(&b, &db)).await.unwrap();

    // One xmin over every heap row and every TOAST chunk (logical view).
    let rels: Vec<(String, Option<String>)> = sqlx::query(
        "SELECT k.oid::regclass::text, NULLIF(k.reltoastrelid, 0)::regclass::text \
         FROM pg_class k JOIN pg_namespace n ON n.oid = k.relnamespace \
         WHERE n.nspname = 'candor' AND k.relkind = 'r' AND k.relname <> 'schema_migration'",
    )
    .fetch_all(&mut c)
    .await
    .unwrap()
    .iter()
    .map(|r| (r.get(0), r.get(1)))
    .collect();
    assert_eq!(rels.len(), 8);
    let (_, distinct) = distinct_xmin(&mut c).await;
    assert_eq!(distinct, 1);
    let slot_xmin: String = sqlx::query("SELECT xmin::text FROM candor.intake_meta")
        .fetch_one(&mut c)
        .await
        .unwrap()
        .get(0);
    let mut toast_rows = 0usize;
    for (rel, toast) in &rels {
        let heap = raw_xmins(&mut c, rel).await;
        assert!(
            heap.iter().all(|x| *x == slot_xmin),
            "{rel}: raw heap xmins {heap:?}"
        );
        let Some(t) = toast else { continue };
        let logical: Vec<String> =
            sqlx::query(AssertSqlSafe(format!("SELECT xmin::text FROM {t}")))
                .fetch_all(&mut c)
                .await
                .unwrap()
                .iter()
                .map(|r| r.get(0))
                .collect();
        let raw = raw_xmins(&mut c, t).await;
        assert_eq!(
            raw.len(),
            logical.len(),
            "{rel}: dead TOAST tuples left after VACUUM"
        );
        assert!(logical.iter().all(|x| *x == slot_xmin), "{rel}: TOAST xmin");
        if rel.ends_with("source_account") || rel.ends_with("envelope") {
            assert!(logical.is_empty(), "{rel} must keep values in line");
        }
        toast_rows += logical.len();
    }
    assert!(toast_rows > 3 * n, "TOAST rows checked: {toast_rows}");
    // New chunk_ids carry no creation order.
    let after = env_rank(&chunk_ids(&mut c, "candor.envelope_part", 1, 4).await);
    assert_eq!(after.len(), n);
    let ids_before: Vec<u32> = before.iter().map(|x| x.1).collect();
    assert!(
        after.iter().all(|(_, id)| !ids_before.contains(id)),
        "all chunk_ids are new"
    );
    let cts = reply_prefixes(&mut c).await;
    let ra = reply_rank(&chunk_ids(&mut c, "candor.reply", 1, 3).await, &cts);
    assert_eq!(ra.len(), n);
    for (what, v) in [("envelope_part", &after), ("reply", &ra)] {
        let t = kendall_tau(v);
        // n = 40: sd ≈ 0.11, so |tau| < 0.5 fails a random order with p < 1e-5.
        assert!(
            t.abs() < 0.5,
            "{what}: chunk_id order correlates with creation (tau {t})"
        );
    }
}

/// AUD-RM2-STO-19/20: in a seized database, published dummies and real Tier V
/// replies cannot be told apart by any stored column: the same length→bucket
/// function for both, NULL account and slot, the generation's day, one `xmin`
/// after the rewrite, and statistically identical bucket distributions when
/// real replies follow the configured profile. Pre-fix, dummies stored
/// `⌈len/4096⌉` and reals the plaintext bucket.
#[tokio::test]
async fn pg_dummy_rows_indistinguishable() {
    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let s = open(&b, &db, common::TENANT).await;
    s.init(common::TENANT, common::SALT).await.unwrap();
    let mut day = common::TODAY;
    s.rebuild_published_set(common::slot(day)).await.unwrap();
    let mut reals: Vec<Vec<u8>> = Vec::new();
    for _ in 0..28 {
        day = day.plus(1).unwrap();
        // Real replies follow the configured profile (the calibration duty).
        let batch: Vec<IncomingReply> = (0..2)
            .map(|_| {
                let k = common::TEST_DEADDROP.draw_dummy_bucket().unwrap();
                common::reply_bucket(None, 0x33, k)
            })
            .collect();
        reals.extend(batch.iter().map(|r| r.reply_ct.clone()));
        s.apply_replies(day, batch).await.unwrap();
        s.rebuild_published_set(common::slot(day)).await.unwrap();
    }
    s.uniform_rewrite(common::slot(day), &[], &[])
        .await
        .unwrap();
    let mut c = su(&b, &db).await;
    let rows = sqlx::query(
        "SELECT reply_ct, size_bucket, (available_day - DATE '1970-01-01')::int4, slot IS NULL, \
         source_account_id IS NULL, pub_gen, xmin::text FROM candor.reply",
    )
    .fetch_all(&mut c)
    .await
    .unwrap();
    let (mut hr, mut hd) = ([0usize; 16], [0usize; 16]);
    let mut xmins = HashSet::new();
    let mut seen_real = 0;
    for r in &rows {
        let ct: Vec<u8> = r.get(0);
        let bucket: i16 = r.get(1);
        let avail: i32 = r.get(2);
        let gen_: Option<i64> = r.get(5);
        xmins.insert(r.get::<String, _>(6));
        assert_eq!(
            reply_bucket_of_len(ct.len()).map(i16::from),
            Some(bucket),
            "stored bucket is the length's bucket for every row"
        );
        assert!(
            r.get::<bool, _>(3) && r.get::<bool, _>(4),
            "no slot, no account"
        );
        let g = gen_.expect("everything published");
        if g > 0 {
            assert_eq!(
                i64::from(avail),
                g,
                "available_day = generation day (1 slot/day)"
            );
        }
        let real = reals.contains(&ct);
        seen_real += usize::from(real);
        let h = if real { &mut hr } else { &mut hd };
        h[usize::try_from(bucket).unwrap() - 1] += 1;
    }
    assert_eq!(seen_real, reals.len());
    assert_eq!(xmins.len(), 1);
    let chi = common::chi2_two_sample(&common::grouped(&hr), &common::grouped(&hd));
    assert!(
        chi < common::CHI2_4DOF_P1E4,
        "real vs dummy buckets separable: chi2 {chi} {hr:?} {hd:?}"
    );
}

/// AUD-RM2-STO-08: PostgreSQL lets a role `ALTER ROLE` its own defaults (not
/// revocable), so the store checks the stored defaults and the effective
/// session values of every connection and refuses any deviation; the startup
/// options override role defaults; `temp_file_limit` is superuser-only and set
/// (1 GB); `open` also refuses membership in the database owner (VACUUM
/// login), an extra (permissive) policy and a table without FORCE RLS.
#[tokio::test]
async fn pg_role_defaults_and_live_guards() {
    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let open_as = |role: &str| {
        PgIntakeStore::open(
            b.clone().username(role).database(&db),
            common::TENANT,
            2,
            common::TEST_DEADDROP,
            Box::new(RandomDummyReplies),
        )
    };
    let refused = |r: Result<PgIntakeStore>| matches!(r, Err(StoreError::Integrity(_)));
    let s = open_as("candor_istore").await.unwrap();
    s.init(common::TENANT, common::SALT).await.unwrap();
    // The effective values with the startup options in place.
    let mut app = PgConnection::connect_with(&b.clone().username("candor_istore").database(&db))
        .await
        .unwrap();
    let tfl: String = sqlx::query("SELECT pg_catalog.current_setting('temp_file_limit')")
        .fetch_one(&mut app)
        .await
        .unwrap()
        .get(0);
    assert_eq!(tfl, "1GB");
    // temp_file_limit cannot be changed by the role itself.
    for q in [
        format!("ALTER ROLE candor_istore IN DATABASE {db} SET temp_file_limit = -1"),
        format!("ALTER ROLE candor_istore IN DATABASE {db} RESET temp_file_limit"),
        "SET temp_file_limit = -1".to_string(),
    ] {
        assert!(
            sqlx::raw_sql(AssertSqlSafe(q.clone()))
                .execute(&mut app)
                .await
                .is_err(),
            "{q}"
        );
    }
    // The audit probe: the role rewrites its own default (accepted by
    // PostgreSQL) -> every later connection of the store is refused.
    for (q, restore) in [
        ("statement_timeout = 0", "SET statement_timeout = '30s'"),
        ("search_path = public, candor", "SET search_path = candor"),
        ("synchronous_commit = off", "RESET synchronous_commit"),
    ] {
        sqlx::raw_sql(AssertSqlSafe(format!(
            "ALTER ROLE candor_istore IN DATABASE {db} SET {q}"
        )))
        .execute(&mut app)
        .await
        .unwrap();
        assert!(refused(open_as("candor_istore").await), "{q}");
        // The startup options still win over the rewritten default.
        let mut c2 = PgConnection::connect_with(
            &b.clone().username("candor_istore").database(&db).options([
                ("statement_timeout", "30s"),
                ("search_path", "candor"),
                ("synchronous_commit", "on"),
            ]),
        )
        .await
        .unwrap();
        let got: (String, String, String) = {
            let r = sqlx::query(
                "SELECT pg_catalog.current_setting('statement_timeout'), \
                 pg_catalog.current_setting('search_path'), pg_catalog.current_setting('synchronous_commit')",
            )
            .fetch_one(&mut c2)
            .await
            .unwrap();
            (r.get(0), r.get(1), r.get(2))
        };
        assert_eq!(got, ("30s".into(), "candor".into(), "on".into()));
        sqlx::raw_sql(AssertSqlSafe(format!(
            "ALTER ROLE candor_istore IN DATABASE {db} {restore}"
        )))
        .execute(&mut app)
        .await
        .unwrap();
    }
    s.close().await;
    open_as("candor_istore").await.unwrap();
    // Provisioning mistake: an unlimited temp_file_limit is refused, a lower
    // one (deploy: 256MB) accepted.
    let mut c = su(&b, &db).await;
    for (v, ok) in [("-1", false), ("'256MB'", true), ("'1GB'", true)] {
        sqlx::raw_sql(AssertSqlSafe(format!(
            "ALTER ROLE candor_istore IN DATABASE {db} SET temp_file_limit = {v}"
        )))
        .execute(&mut c)
        .await
        .unwrap();
        assert_eq!(
            open_as("candor_istore").await.is_ok(),
            ok,
            "temp_file_limit {v}"
        );
    }

    // Live guards: membership in the database owner, an extra policy, and
    // NO FORCE ROW LEVEL SECURITY are refused.
    sqlx::raw_sql(
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'candor_probe2') THEN \
         CREATE ROLE candor_probe2 LOGIN NOINHERIT; END IF; END $$",
    )
    .execute(&mut c)
    .await
    .unwrap();
    sqlx::raw_sql(AssertSqlSafe(format!(
        "GRANT CONNECT ON DATABASE {db} TO candor_probe2; GRANT candor_intake_maint TO candor_probe2"
    )))
    .execute(&mut c)
    .await
    .unwrap();
    assert_eq!(
        open_as("candor_probe2").await.err(),
        Some(StoreError::Integrity(
            "intake role is privileged or a member of an owning role"
        )),
        "db owner member"
    );
    sqlx::raw_sql("CREATE POLICY p_open ON candor.reply USING (true)")
        .execute(&mut c)
        .await
        .unwrap();
    let extra: i64 =
        sqlx::query("SELECT count(*) FROM pg_catalog.pg_policy WHERE polname = 'p_open'")
            .fetch_one(&mut c)
            .await
            .unwrap()
            .get(0);
    assert_eq!(extra, 1);
    assert!(refused(open_as("candor_istore").await), "extra policy");
    sqlx::raw_sql("DROP POLICY p_open ON candor.reply")
        .execute(&mut c)
        .await
        .unwrap();
    assert!(open_as("candor_istore").await.is_ok());
    sqlx::raw_sql("ALTER TABLE candor.reply NO FORCE ROW LEVEL SECURITY")
        .execute(&mut c)
        .await
        .unwrap();
    assert!(refused(open_as("candor_istore").await), "NO FORCE RLS");
}

/// AUD-RM2-STO-24(a): the VACUUM jobs run only as the maintenance role,
/// which owns the database but no table or schema and is no member of the
/// schema owner (PostgreSQL 16 lets the database owner VACUUM): the
/// superuser, a member of the schema owner and the app role are refused
/// before any VACUUM. Neither the maintenance role nor the app role can
/// disable a guard, read source rows or `SET ROLE` to the schema owner, and
/// the app role cannot VACUUM (PostgreSQL skips the table: its file is
/// unchanged).
#[tokio::test]
async fn pg_vacuum_login_identity() {
    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let mut c = su(&b, &db).await;
    sqlx::raw_sql(
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'candor_probe') THEN \
         CREATE ROLE candor_probe LOGIN NOINHERIT; END IF; END $$",
    )
    .execute(&mut c)
    .await
    .unwrap();
    sqlx::raw_sql(AssertSqlSafe(format!(
        "GRANT CONNECT ON DATABASE {db} TO candor_probe; GRANT candor_intake_migrator TO candor_probe"
    )))
    .execute(&mut c)
    .await
    .unwrap();
    for role in [
        superuser(),
        "candor_probe".to_string(),
        "candor_istore".to_string(),
    ] {
        let o = b.clone().username(&role).database(&db);
        assert!(
            matches!(
                vacuum_after_rewrite(&o).await,
                Err(StoreError::Integrity(_))
            ),
            "{role}"
        );
        assert!(
            matches!(vacuum_full_daily(&o).await, Err(StoreError::Integrity(_))),
            "{role}"
        );
    }
    vacuum_after_rewrite(&vac(&b, &db)).await.unwrap();
    vacuum_full_daily(&vac(&b, &db)).await.unwrap();
    let mut v = PgConnection::connect_with(&vac(&b, &db)).await.unwrap();
    let mut app = PgConnection::connect_with(&b.clone().username("candor_istore").database(&db))
        .await
        .unwrap();
    for conn in [&mut v, &mut app] {
        for q in [
            "ALTER TABLE candor.deletion_list DISABLE TRIGGER deletion_list_guard",
            "ALTER TABLE candor.reply NO FORCE ROW LEVEL SECURITY",
            "SET ROLE candor_intake_migrator",
        ] {
            assert!(sqlx::raw_sql(q).execute(&mut *conn).await.is_err(), "{q}");
        }
    }
    assert!(
        sqlx::raw_sql("SELECT count(*) FROM candor.source_account")
            .execute(&mut v)
            .await
            .is_err()
    );
    assert!(
        sqlx::raw_sql("SET ROLE candor_intake_maint")
            .execute(&mut app)
            .await
            .is_err()
    );
    let before = reply_node(&mut c).await;
    // PostgreSQL skips (WARNING, no error) a table the role may not vacuum.
    let _ = sqlx::raw_sql("VACUUM (FULL) candor.reply")
        .execute(&mut app)
        .await;
    assert_eq!(
        reply_node(&mut c).await,
        before,
        "app role must not VACUUM FULL"
    );
    vacuum_full_daily(&vac(&b, &db)).await.unwrap();
    assert_ne!(reply_node(&mut c).await, before, "maintenance role does");
}

/// All pages (raw bytes) of `rel` (pageinspect).
async fn raw_pages(c: &mut PgConnection, rel: &str) -> Vec<Vec<u8>> {
    sqlx::query(
        "SELECT get_raw_page($1, p) FROM generate_series(0, \
         (pg_relation_size($1::regclass) / 8192)::int - 1) p",
    )
    .bind(rel)
    .fetch_all(c)
    .await
    .unwrap()
    .iter()
    .map(|r| r.get(0))
    .collect()
}

/// Every relation holding intake data: tables, their TOAST tables, and all
/// their indexes (`(name, relfilenode)`).
async fn intake_relations(c: &mut PgConnection) -> Vec<(String, i64)> {
    sqlx::query(
        "WITH t AS (SELECT k.oid, k.reltoastrelid FROM pg_class k JOIN pg_namespace n ON n.oid = k.relnamespace \
                    WHERE n.nspname = 'candor' AND k.relkind = 'r' AND k.relname <> 'schema_migration'), \
              r AS (SELECT oid FROM t UNION SELECT reltoastrelid FROM t WHERE reltoastrelid <> 0), \
              a AS (SELECT oid FROM r UNION SELECT i.indexrelid FROM pg_index i JOIN r ON r.oid = i.indrelid) \
         SELECT a.oid::regclass::text, k.relfilenode::int8 FROM a JOIN pg_class k ON k.oid = a.oid ORDER BY 1",
    )
    .fetch_all(c)
    .await
    .unwrap()
    .iter()
    .map(|r| (r.get(0), r.get(1)))
    .collect()
}

fn count_hits(pages: &[Vec<u8>], pats: &HashSet<[u8; 8]>) -> usize {
    pages
        .iter()
        .flat_map(|p| p.windows(8))
        .filter(|w| pats.contains(&<[u8; 8]>::try_from(*w).unwrap()))
        .count()
}

/// AUD-RM2-STO-23 (the audit's raw-page probe): after `uniform_rewrite` and
/// the slot VACUUM, pre-rewrite tuple images (`[old xmin][xmax = rewrite
/// xid]` headers) and old TOAST chunk ids (`[chunk_id][chunk_seq 0]` in TOAST
/// tuples and index entries, `[va_valueid][toastrelid]` in heap pointers)
/// still sit in page free space (positive control); after the daily
/// `VACUUM FULL` (maintenance role) no page of any intake table, TOAST table or
/// index holds any of them, every relation has a new file, and the store's
/// content is unchanged.
#[tokio::test]
async fn pg_vacuum_full_erases_old_images() {
    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let s = open(&b, &db, common::TENANT).await;
    s.init(common::TENANT, common::SALT).await.unwrap();
    let a = workload(&s).await;
    for t in 40u8..46 {
        let mut na = common::new_account(t);
        na.prefs_ct = vec![t; MAX_PREFS_CT];
        s.create_account(na, common::TODAY).await.unwrap();
    }
    for _ in 0..12 {
        s.commit_envelope(common::envelope(0)).await.unwrap();
        s.apply_replies(common::TODAY, vec![common::reply(None, 0x72, 9000)])
            .await
            .unwrap();
    }
    let mut c = su(&b, &db).await;
    sqlx::raw_sql("CREATE EXTENSION IF NOT EXISTS pageinspect")
        .execute(&mut c)
        .await
        .unwrap();
    let rels = intake_relations(&mut c).await;
    // Old xmins of every live heap and TOAST tuple, and every old chunk id.
    let mut old_xmins: HashSet<u32> = HashSet::new();
    let mut old_chunks: Vec<(u32, u32)> = Vec::new();
    let toasts: Vec<(String, u32)> = sqlx::query(
        "SELECT k.reltoastrelid::regclass::text, k.reltoastrelid::int8 FROM pg_class k \
         JOIN pg_namespace n ON n.oid = k.relnamespace \
         WHERE n.nspname = 'candor' AND k.relkind = 'r' AND k.reltoastrelid <> 0",
    )
    .fetch_all(&mut c)
    .await
    .unwrap()
    .iter()
    .map(|r| (r.get(0), u32::try_from(r.get::<i64, _>(1)).unwrap()))
    .collect();
    for (rel, _) in &rels {
        let kind: String =
            sqlx::query("SELECT relkind::text FROM pg_class WHERE oid = $1::regclass")
                .bind(rel)
                .fetch_one(&mut c)
                .await
                .unwrap()
                .get(0);
        if kind == "i" {
            continue;
        }
        for x in raw_xmins(&mut c, rel).await {
            old_xmins.insert(x.parse().unwrap());
        }
    }
    for (t, oid) in &toasts {
        for r in sqlx::query(AssertSqlSafe(format!(
            "SELECT DISTINCT chunk_id::int8 FROM {t}"
        )))
        .fetch_all(&mut c)
        .await
        .unwrap()
        {
            old_chunks.push((u32::try_from(r.get::<i64, _>(0)).unwrap(), *oid));
        }
    }
    assert!(old_xmins.len() > 5, "{old_xmins:?}");
    assert!(old_chunks.len() > 20, "{}", old_chunks.len());

    s.uniform_rewrite(common::slot(common::TODAY), &[], &[a])
        .await
        .unwrap();
    vacuum_after_rewrite(&vac(&b, &db)).await.unwrap();
    let slot: u32 = sqlx::query("SELECT xmin::text::int8 FROM candor.intake_meta")
        .fetch_one(&mut c)
        .await
        .unwrap()
        .get::<i64, _>(0)
        .try_into()
        .unwrap();
    assert!(!old_xmins.contains(&slot));
    let mut xmin_pats: HashSet<[u8; 8]> = HashSet::new();
    for x in &old_xmins {
        let mut p = [0u8; 8];
        p[..4].copy_from_slice(&x.to_le_bytes());
        p[4..].copy_from_slice(&slot.to_le_bytes());
        xmin_pats.insert(p);
    }
    // `[chunk_id][chunk_seq 0]` is searched only in TOAST relations and their
    // indexes (in a heap, an int8 such as a generation number could equal
    // it); `[va_valueid][toastrelid]` everywhere.
    let (mut seq_pats, mut ptr_pats) = (HashSet::new(), HashSet::new());
    for (id, toastrel) in &old_chunks {
        let mut p = [0u8; 8];
        p[..4].copy_from_slice(&id.to_le_bytes());
        seq_pats.insert(p);
        p[4..].copy_from_slice(&toastrel.to_le_bytes());
        ptr_pats.insert(p);
    }
    let chunk_hits = |rel: &str, pages: &[Vec<u8>]| {
        count_hits(pages, &ptr_pats)
            + if rel.starts_with("pg_toast.") {
                count_hits(pages, &seq_pats)
            } else {
                0
            }
    };
    let (mut hx, mut hc) = (0usize, 0usize);
    for (rel, _) in &rels {
        let pages = raw_pages(&mut c, rel).await;
        hx += count_hits(&pages, &xmin_pats);
        hc += chunk_hits(rel, &pages);
    }
    // Positive control (the audit's finding): plain VACUUM leaves them.
    assert!(
        hx > 0,
        "control: no old tuple header found after plain VACUUM"
    );
    assert!(hc > 0, "control: no old chunk id found after plain VACUUM");

    let before = s.export_backup().await.unwrap();
    let mailbox = s.mailbox_list(a).await.unwrap();
    vacuum_full_daily(&vac(&b, &db)).await.unwrap();
    let after_rels = intake_relations(&mut c).await;
    assert_eq!(after_rels.len(), rels.len());
    for ((r0, f0), (r1, f1)) in rels.iter().zip(&after_rels) {
        assert_eq!(r0, r1);
        assert_ne!(f0, f1, "{r0}: not rewritten");
    }
    let (mut hx, mut hc) = (0usize, 0usize);
    for (rel, _) in &after_rels {
        let pages = raw_pages(&mut c, rel).await;
        hx += count_hits(&pages, &xmin_pats);
        hc += chunk_hits(rel, &pages);
    }
    assert_eq!(hx, 0, "old tuple headers survive VACUUM FULL");
    assert_eq!(hc, 0, "old chunk ids survive VACUUM FULL");
    // Content and the single slot xmin are unchanged.
    assert_eq!(s.export_backup().await.unwrap(), before);
    assert_eq!(distinct_xmin(&mut c).await.1, 1);
    assert_eq!(s.mailbox_list(a).await.unwrap(), mailbox);
}

async fn reply_node(c: &mut PgConnection) -> i64 {
    sqlx::query("SELECT relfilenode::int8 FROM pg_class WHERE oid = 'candor.reply'::regclass")
        .fetch_one(c)
        .await
        .unwrap()
        .get(0)
}

/// AUD-RM2-STO-27 against PostgreSQL: the staged blob is acknowledged only
/// with the token of a committed `envelope_part` row naming it; a duplicate
/// group and a commit refused in restore-pending (both before any
/// transaction commits) leave orphans that the slot sweep removes, while the
/// committed blob stays.
#[tokio::test]
async fn pg_staged_ack_after_commit() {
    use candor_intake_store::staged::{
        STAGED_BUNDLE_INDEX, StagedHeader, StagedReceiver, send_staged_bundle,
    };
    use candor_safefs::{ObjectId, RootPolicy, SafeRoot, SlotTime};
    use sha2::Digest;
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::os::unix::fs::PermissionsExt;

    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let tmp = tempfile::Builder::new()
        .permissions(PermissionsExt::from_mode(0o700))
        .tempdir()
        .unwrap();
    let (sealer, store_sock) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::SEQPACKET,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    let uid = rustix::net::sockopt::socket_peercred(&store_sock)
        .unwrap()
        .uid
        .as_raw();
    let rx = StagedReceiver::new(
        SafeRoot::open(tmp.path(), RootPolicy::BlobStore).unwrap(),
        uid,
        1 << 20,
    )
    .unwrap();
    let slot = SlotTime::from_unix_secs(1_790_000_100).unwrap();
    let next = SlotTime::from_unix_secs(1_790_003_700).unwrap();
    let data = vec![0x42u8; 9000];
    let fd = rustix::fs::memfd_create(
        "staged",
        rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
    )
    .unwrap();
    let mut f = std::fs::File::from(fd);
    f.write_all(&data).unwrap();
    let fd: std::os::fd::OwnedFd = f.into();
    rustix::fs::fcntl_add_seals(
        &fd,
        rustix::fs::SealFlags::WRITE
            | rustix::fs::SealFlags::GROW
            | rustix::fs::SealFlags::SHRINK
            | rustix::fs::SealFlags::SEAL,
    )
    .unwrap();
    let h = StagedHeader {
        len: data.len() as u64,
        sha256: sha2::Sha256::digest(&data).into(),
    };
    let ack = |want: u8| {
        let mut x = [0u8; 2];
        let n = rustix::net::recv(&sealer, &mut x, rustix::net::RecvFlags::DONTWAIT).unwrap();
        assert_eq!((n.0, x[0]), (1, want));
    };
    let mut env0 = common::envelope(0);
    {
        let s = open(&b, &db, common::TENANT).await;
        s.init(common::TENANT, common::SALT).await.unwrap();
        send_staged_bundle(&sealer, &h, fd.as_fd()).unwrap();
        let blob = rx.receive(store_sock.as_fd(), slot).unwrap();
        let keep = blob.blob_id();
        env0.objects[STAGED_BUNDLE_INDEX].blob = PartRef {
            blob_id: keep,
            padded_size: blob.len(),
        };
        let c = rx.commit_staged(&s, env0.clone(), blob).await.unwrap();
        // The committed row names the blob before the ack is sent.
        let mut su = su(&b, &db).await;
        let n: i64 =
            sqlx::query_scalar("SELECT count(*) FROM candor.envelope_part WHERE blob_id = $1")
                .bind(uuid::Uuid::from_bytes(keep.0))
                .fetch_one(&mut su)
                .await
                .unwrap();
        assert_eq!(n, 1);
        rx.acknowledge(store_sock.as_fd(), c).unwrap();
        ack(0x01);
        // Same group again: DuplicateEnvelope, nothing committed.
        send_staged_bundle(&sealer, &h, fd.as_fd()).unwrap();
        let dup = rx.receive(store_sock.as_fd(), slot).unwrap();
        let mut env1 = env0.clone();
        env1.objects[STAGED_BUNDLE_INDEX].blob.blob_id = dup.blob_id();
        assert_eq!(
            rx.commit_staged(&s, env1, dup).await.unwrap_err(),
            StoreError::DuplicateEnvelope
        );
        rx.refuse(store_sock.as_fd()).unwrap();
        ack(0x00);
        assert_eq!(rx.sweep(&s, next).await.unwrap(), 1);
        assert_eq!(
            rx.blobs().list().unwrap(),
            vec![ObjectId::from_bytes(keep.0)]
        );
        s.close().await;
    }
    // Restart: restore-pending refuses the commit; the copy is swept.
    let s = open(&b, &db, common::TENANT).await;
    send_staged_bundle(&sealer, &h, fd.as_fd()).unwrap();
    let blob = rx.receive(store_sock.as_fd(), slot).unwrap();
    let mut env2 = common::envelope(0);
    env2.objects[STAGED_BUNDLE_INDEX].blob = PartRef {
        blob_id: blob.blob_id(),
        padded_size: blob.len(),
    };
    assert_eq!(
        rx.commit_staged(&s, env2, blob).await.unwrap_err(),
        StoreError::RestorePending
    );
    rx.refuse(store_sock.as_fd()).unwrap();
    ack(0x00);
    assert_eq!(rx.sweep(&s, next).await.unwrap(), 1);
    assert_eq!(rx.blobs().list().unwrap().len(), 1);
    assert_eq!(rx.in_flight(), 0);
}

/// AUD-RM2-STO-27(4) against PostgreSQL: a crash between the blob copy and
/// the envelope commit leaves a blob no restarted receiver knows; the
/// start-up sweep removes it (no `envelope_part` row names it) and keeps the
/// committed one. The check runs as the application role; the maintenance
/// role has no access to `envelope_part` and fails closed (nothing removed);
/// so does a wrong-tenant or uninitialised store (AUD-RM2-STO-28).
#[tokio::test]
async fn pg_staged_crash_between_copy_and_commit() {
    use candor_intake_store::staged::{
        STAGED_BUNDLE_INDEX, StagedHeader, StagedReceiver, send_staged_bundle,
    };
    use candor_safefs::{ObjectId, RootPolicy, SafeRoot, SlotTime};
    use sha2::Digest;
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::os::unix::fs::PermissionsExt;

    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let tmp = tempfile::Builder::new()
        .permissions(PermissionsExt::from_mode(0o700))
        .tempdir()
        .unwrap();
    let (sealer, store_sock) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::SEQPACKET,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    let uid = rustix::net::sockopt::socket_peercred(&store_sock)
        .unwrap()
        .uid
        .as_raw();
    let receiver = || {
        StagedReceiver::new(
            SafeRoot::open(tmp.path(), RootPolicy::BlobStore).unwrap(),
            uid,
            1 << 20,
        )
        .unwrap()
    };
    let slot = SlotTime::from_unix_secs(1_790_000_100).unwrap();
    let data = vec![0x17u8; 4000];
    let mut f = std::fs::File::from(
        rustix::fs::memfd_create(
            "staged",
            rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
        )
        .unwrap(),
    );
    f.write_all(&data).unwrap();
    let fd: std::os::fd::OwnedFd = f.into();
    rustix::fs::fcntl_add_seals(
        &fd,
        rustix::fs::SealFlags::WRITE
            | rustix::fs::SealFlags::GROW
            | rustix::fs::SealFlags::SHRINK
            | rustix::fs::SealFlags::SEAL,
    )
    .unwrap();
    let h = StagedHeader {
        len: data.len() as u64,
        sha256: sha2::Sha256::digest(&data).into(),
    };
    let s = open(&b, &db, common::TENANT).await;
    s.init(common::TENANT, common::SALT).await.unwrap();
    let rx = receiver();
    send_staged_bundle(&sealer, &h, fd.as_fd()).unwrap();
    let kept = rx.receive(store_sock.as_fd(), slot).unwrap();
    let keep = ObjectId::from_bytes(kept.blob_id().0);
    let mut env = common::envelope(0);
    env.objects[STAGED_BUNDLE_INDEX].blob = PartRef {
        blob_id: kept.blob_id(),
        padded_size: kept.len(),
    };
    let c = rx.commit_staged(&s, env, kept).await.unwrap();
    rx.acknowledge(store_sock.as_fd(), c).unwrap();
    // Copy done, then the process dies before the envelope commit.
    send_staged_bundle(&sealer, &h, fd.as_fd()).unwrap();
    std::mem::forget(rx.receive(store_sock.as_fd(), slot).unwrap());
    drop(rx);
    // Restart.
    let rx2 = receiver();
    assert_eq!(rx2.blobs().list().unwrap().len(), 2);
    let m = maint(&b, &db, common::TENANT).await;
    assert!(
        rx2.startup(&m, slot).await.is_err(),
        "maint role fails closed"
    );
    assert_eq!(rx2.blobs().list().unwrap().len(), 2);
    assert_eq!(rx2.startup(&s, slot).await.unwrap(), 1);
    assert_eq!(rx2.blobs().list().unwrap(), vec![keep]);
    // Idempotent.
    assert_eq!(rx2.sweep(&s, slot).await.unwrap(), 0);
    // AUD-RM2-STO-28: a store opened with the wrong tenant sees no rows
    // (RLS); the check must fail, not report "unreferenced", and the sweep
    // must delete nothing.
    let wrong = open(&b, &db, common::OTHER_TENANT).await;
    let keep_id = BlobId(*keep.as_bytes());
    assert_eq!(
        wrong.blob_referenced(keep_id).await,
        Err(StoreError::NotInitialized)
    );
    assert!(rx2.sweep(&wrong, slot).await.is_err());
    assert!(rx2.startup(&wrong, slot).await.is_err());
    assert_eq!(rx2.blobs().list().unwrap(), vec![keep]);
    // An uninitialised database fails the same way.
    let empty_db = fresh_db(&b).await;
    let empty = open(&b, &empty_db, common::TENANT).await;
    assert_eq!(
        empty.blob_referenced(keep_id).await,
        Err(StoreError::NotInitialized)
    );
    assert!(rx2.sweep(&empty, slot).await.is_err());
    assert_eq!(rx2.blobs().list().unwrap(), vec![keep]);
    assert_eq!(s.blob_referenced(keep_id).await, Ok(true));
}

/// Lead decision on AUD-RM2-STO-27: the envelope commit is capped inside the
/// transaction (`SET LOCAL statement_timeout` / `lock_timeout`, ≤ 20 s per
/// attempt). A commit stalled by a lock another session holds is refused
/// within the bound with `Timeout` (definite: no retry, nothing committed);
/// the copied blob is an orphan that the sweep removes once the lock is gone.
#[tokio::test]
async fn pg_staged_stalled_commit_refused() {
    use candor_intake_store::staged::{
        STAGED_BUNDLE_INDEX, StagedHeader, StagedReceiver, send_staged_bundle,
    };
    use candor_safefs::{RootPolicy, SafeRoot, SlotTime};
    use sha2::Digest;
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::os::unix::fs::PermissionsExt;

    let Some(b) = base() else { return };
    let db = fresh_db(&b).await;
    let tmp = tempfile::Builder::new()
        .permissions(PermissionsExt::from_mode(0o700))
        .tempdir()
        .unwrap();
    let (sealer, store_sock) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::SEQPACKET,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    let uid = rustix::net::sockopt::socket_peercred(&store_sock)
        .unwrap()
        .uid
        .as_raw();
    let rx = StagedReceiver::new(
        SafeRoot::open(tmp.path(), RootPolicy::BlobStore).unwrap(),
        uid,
        1 << 20,
    )
    .unwrap();
    let slot = SlotTime::from_unix_secs(1_790_000_100).unwrap();
    let data = vec![0x33u8; 3000];
    let mut f = std::fs::File::from(
        rustix::fs::memfd_create(
            "staged",
            rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
        )
        .unwrap(),
    );
    f.write_all(&data).unwrap();
    let fd: std::os::fd::OwnedFd = f.into();
    rustix::fs::fcntl_add_seals(
        &fd,
        rustix::fs::SealFlags::WRITE
            | rustix::fs::SealFlags::GROW
            | rustix::fs::SealFlags::SHRINK
            | rustix::fs::SealFlags::SEAL,
    )
    .unwrap();
    let h = StagedHeader {
        len: data.len() as u64,
        sha256: sha2::Sha256::digest(&data).into(),
    };
    let s = open(&b, &db, common::TENANT).await;
    s.init(common::TENANT, common::SALT).await.unwrap();
    send_staged_bundle(&sealer, &h, fd.as_fd()).unwrap();
    let blob = rx.receive(store_sock.as_fd(), slot).unwrap();
    let mut env = common::envelope(0);
    env.objects[STAGED_BUNDLE_INDEX].blob = PartRef {
        blob_id: blob.blob_id(),
        padded_size: blob.len(),
    };
    // Another session holds a conflicting lock for longer than the cap.
    let mut holder = su(&b, &db).await;
    sqlx::raw_sql("BEGIN; LOCK TABLE candor.envelope IN ACCESS EXCLUSIVE MODE")
        .execute(&mut holder)
        .await
        .unwrap();
    let t0 = std::time::Instant::now();
    let r = rx.commit_staged(&s, env.clone(), blob).await;
    let took = t0.elapsed();
    assert_eq!(r.unwrap_err(), StoreError::Timeout);
    assert!(
        took >= std::time::Duration::from_secs(2),
        "the lock stalled it"
    );
    assert!(
        took < std::time::Duration::from_secs(20),
        "refused within the per-attempt cap"
    );
    rx.refuse(store_sock.as_fd()).unwrap();
    let mut x = [0u8; 2];
    let n = rustix::net::recv(&sealer, &mut x, rustix::net::RecvFlags::DONTWAIT).unwrap();
    assert_eq!((n.0, x[0]), (1, 0x00));
    sqlx::raw_sql("ROLLBACK")
        .execute(&mut holder)
        .await
        .unwrap();
    // Nothing committed; the orphan is swept; the store still works.
    assert_eq!(s.pending_count().await.unwrap(), 0);
    assert_eq!(rx.sweep(&s, slot).await.unwrap(), 1);
    assert!(rx.blobs().list().unwrap().is_empty());
    s.commit_envelope(env).await.unwrap();
}
