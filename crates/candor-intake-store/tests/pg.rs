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
    )
    .await
    .unwrap()
}

async fn open(base: &PgConnectOptions, db: &str, tenant: TenantId) -> PgIntakeStore {
    open_plain(base, db, tenant)
        .await
        .with_maintenance(maint(base, db, tenant).await)
}

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
            ("intake_meta".into(), "SELECT".into())
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
    // Z-CORE's copy is behind (only seq 1): truncated relative to its claim,
    // or behind the local head without anchoring rule violations -> accepted
    // only when it ends at the asserted head.
    assert!(
        s.apply_pushed_deletion_list(&list[..1], 3, &pk, &common::PrefixHasher)
            .await
            .is_err()
    );
    assert!(!s.serving_allowed().await.unwrap());
    assert_eq!(
        s.apply_pushed_deletion_list(&list, 3, &pk, &common::PrefixHasher)
            .await
            .unwrap(),
        3
    );
    assert!(s.serving_allowed().await.unwrap());

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
    s.deletion_list_after(3, 10).await.unwrap();
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
    let locked: i64 = sqlx::query(AssertSqlSafe(format!(
        "SELECT count(*) FROM ({}) t(x) WHERE x <> '0'",
        XMIN_UNION.replace("xmin::text", "xmax::text")
    )))
    .fetch_one(&mut c)
    .await
    .unwrap()
    .get(0);
    assert_eq!(locked, 0, "no row carries a lock xmax after the rewrite");
}

/// AUD-RM2-STO-02: the whole conformance suite runs without a single server-side
/// ERROR/WARNING/FATAL line (expected outcomes never raise errors). The suite's
/// databases log at `warning`; every other database logs nothing (`panic`).
#[tokio::test]
async fn pg_no_server_errors_on_expected_paths() {
    let Some(_) = base() else { return };
    let Ok(log) = std::env::var("CANDOR_TEST_PG_LOG") else {
        eprintln!("skipping: CANDOR_TEST_PG_LOG unset (run scripts/pg-test.sh)");
        return;
    };
    let start = std::fs::metadata(&log).map(|m| m.len()).unwrap_or(0);
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
        backup_restore
    );
    let text = std::fs::read(&log).unwrap();
    let new = String::from_utf8_lossy(text.get(usize::try_from(start).unwrap()..).unwrap_or(&[]));
    let bad: Vec<&str> = new
        .lines()
        .filter(|l| l.contains("ERROR") || l.contains("WARNING") || l.contains("FATAL"))
        .collect();
    assert!(bad.is_empty(), "server log lines: {bad:?}");
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
