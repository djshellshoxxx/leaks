// SPDX-License-Identifier: AGPL-3.0-or-later
//! PostgreSQL integration tests. Run via `scripts/pg-test.sh`; skipped (with
//! no output) when `CANDOR_TEST_PG` is unset. Each test uses a fresh database
//! in the throwaway cluster.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use candor_case_db::*;
use common::*;
use sha2::Digest;
use sqlx::{AssertSqlSafe, Row};
use uuid::Uuid;


/// Migration: fresh apply, idempotent re-run, every role opens.
#[tokio::test]
async fn migrate_and_open_every_role() {
    let Some(b) = base() else { return };
    let name = fresh_db(&b).await;
    for r in ALL_ROLES {
        let d = open(&b, &name, r).await;
        assert_eq!(d.role(), r);
    }
}

/// 09 §8 live schema lint over the migrated catalog.
#[tokio::test]
async fn live_lint_passes() {
    let Some(b) = base() else { return };
    let name = fresh_db(&b).await;
    let mut c = su(&b, &name).await;
    let v = lint::live(&mut c).await.unwrap();
    assert!(v.is_empty(), "{v:?}");
    // The same result from the least-privileged role (pg_catalog, not
    // information_schema, which hides columns without privilege).
    let mut c = conn(&b, &name, "candor_monitor").await;
    let v = lint::live(&mut c).await.unwrap();
    assert!(v.is_empty(), "{v:?}");
}

// ---- RLS isolation, generated from the table list (ST-062/063; SI-E-03) -----

/// Every tenant table has a fixture; with tenant A bound, a reader sees only
/// A's row, cannot move it to B, and cannot insert a B row (WITH CHECK).
#[tokio::test]
async fn rls_isolation_every_table() {
    let Some(b) = base() else { return };
    let name = fresh_db(&b).await;
    for t in lint::TENANT_TABLES {
        assert!(
            fixtures::FIXTURES.iter().any(|(ft, _, _)| ft == t),
            "no fixture for {t}: add one to tests/common/fixtures.rs"
        );
    }
    let (ta, tb) = (Uuid::new_v4(), Uuid::new_v4());
    let (ua, ub) = (Uuid::new_v4(), Uuid::new_v4());
    let mut s = su(&b, &name).await;
    load_fixtures(&mut s, ta, ua).await;
    load_fixtures(&mut s, tb, ub).await;
    for (table, reader, sql) in fixtures::FIXTURES {
        if *reader == "-" {
            continue; // coi_excl_tag: probed through the definer function below
        }
        let mut c = conn(&b, &name, reader).await;
        let mut tx = ctx(&mut c, ta, ua, kind_of(reader)).await;
        assert_eq!(count(&mut tx, table, "").await, 1, "{table} as {reader}");
        assert_eq!(count(&mut tx, table, &format!("WHERE tenant_id = '{tb}'")).await, 0, "{table}");
        // Moving a row to another tenant: refused by WITH CHECK or by grants.
        let moved = sqlx::query(AssertSqlSafe(format!("UPDATE {table} SET tenant_id = $1 WHERE tenant_id = $2")))
            .bind(tb)
            .bind(ta)
            .execute(&mut *tx)
            .await;
        assert!(moved.is_err(), "{table}: row moved across tenants as {reader}");
        tx.rollback().await.unwrap();
        // Inserting a B row under A's context: refused (WITH CHECK or grants).
        let mut tx = ctx(&mut c, ta, ua, kind_of(reader)).await;
        let ins = sqlx::query(AssertSqlSafe((*sql).to_string()))
            .bind(tb)
            .bind(ua)
            .execute(&mut *tx)
            .await;
        assert!(ins.is_err(), "{table}: cross-tenant insert accepted as {reader}");
        tx.rollback().await.unwrap();
        // No context at all: an error, never an empty result (fail closed).
        let bare = sqlx::query(AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
            .fetch_one(&mut c)
            .await;
        assert_eq!(sqlstate(&bare.unwrap_err()), "42501", "{table}: no-context read did not fail closed");
    }
    // Superuser view: both tenants still hold exactly one row each.
    for (table, _, _) in fixtures::FIXTURES {
        assert_eq!(count(&mut s, table, &format!("WHERE tenant_id = '{ta}'")).await, 1);
        assert_eq!(count(&mut s, table, &format!("WHERE tenant_id = '{tb}'")).await, 1);
    }
    // coi_excl_tag: no SELECT for the Desk role; the definer function answers
    // only for the caller's own case.
    let mut c = conn(&b, &name, "candor_case").await;
    let mut tx = ctx(&mut c, ta, ua, "desk").await;
    let sel = sqlx::query("SELECT count(*) FROM core.coi_excl_tag").fetch_one(&mut *tx).await;
    assert_eq!(sqlstate(&sel.unwrap_err()), "42501");
    tx.rollback().await.unwrap();
    let mut tx = ctx(&mut c, ta, ua, "desk").await;
    let present: bool = sqlx::query("SELECT acl.coi_tag_present($1, pg_catalog.sha256($1::text::bytea))")
        .bind(ta)
        .fetch_one(&mut *tx)
        .await
        .unwrap()
        .try_get(0)
        .unwrap();
    assert!(present);
    let other: bool = sqlx::query("SELECT acl.coi_tag_present($1, pg_catalog.sha256($1::text::bytea))")
        .bind(tb)
        .fetch_one(&mut *tx)
        .await
        .unwrap()
        .try_get(0)
        .unwrap();
    assert!(!other, "a tag of another tenant's case was visible");
    // A non-member of the case (nil user) gets false even for a present tag.
    tx.rollback().await.unwrap();
    let mut tx = ctx(&mut c, ta, Uuid::nil(), "desk").await;
    let nm: bool = sqlx::query("SELECT acl.coi_tag_present($1, pg_catalog.sha256($1::text::bytea))")
        .bind(ta)
        .fetch_one(&mut *tx)
        .await
        .unwrap()
        .try_get(0)
        .unwrap();
    assert!(!nm);
}

/// ACL: a Desk user who is not a case member sees nothing of that case.
#[tokio::test]
async fn rls_case_acl_hides_non_member() {
    let Some(b) = base() else { return };
    let name = fresh_db(&b).await;
    let (ta, ua, stranger) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let mut s = su(&b, &name).await;
    load_fixtures(&mut s, ta, ua).await;
    let mut c = conn(&b, &name, "candor_case").await;
    let mut tx = ctx(&mut c, ta, stranger, "desk").await;
    for t in [
        "core.\"case\"", "core.case_record", "core.message", "core.attachment", "core.evidence_object",
        "core.submission", "core.sla_timer", "core.legal_hold", "core.case_key_wrap", "core.import_envelope",
        "core.import_envelope_part", "core.sealed_identity", "core.breakglass_request", "core.case_member",
        "core.notification_target",
    ] {
        assert_eq!(count(&mut tx, t, "").await, 0, "{t} visible to a non-member");
    }
    // A member sees them, but only their own wrap and target.
    tx.rollback().await.unwrap();
    let mut tx = ctx(&mut c, ta, ua, "desk").await;
    assert_eq!(count(&mut tx, "core.\"case\"", "").await, 1);
    assert_eq!(count(&mut tx, "core.case_key_wrap", "").await, 1);
    // Insert a wrap for another recipient as the member: allowed (case create
    // stores every wrap); reading it back is not.
    sqlx::query("INSERT INTO core.case_key_wrap (tenant_id, case_id, key_epoch, recipient_key_id, recipient_user_id, wrap_ct, wrapped_by) \
                 VALUES ($1, $1, 0, pg_catalog.decode(pg_catalog.repeat('22', 16), 'hex'), $2, '\\x01', $3)")
        .bind(ta)
        .bind(stranger)
        .bind(ua)
        .execute(&mut *tx)
        .await
        .unwrap();
    assert_eq!(count(&mut tx, "core.case_key_wrap", "").await, 1);
}

// ---- grant matrix (db-grant-audit; 09 §6.4, §7; ADR-015) ---------------------

#[tokio::test]
async fn grant_matrix() {
    let Some(b) = base() else { return };
    let name = fresh_db(&b).await;
    let mut s = su(&b, &name).await;
    let roles: Vec<&str> = ALL_ROLES.iter().map(|r| r.pg_name()).collect();
    let tables: Vec<String> = sqlx::query(
        "SELECT n.nspname || '.' || k.relname FROM pg_catalog.pg_class k JOIN pg_catalog.pg_namespace n ON n.oid = k.relnamespace \
         WHERE k.relkind = 'r' AND n.nspname IN ('candor', 'core', 'auth', 'kd', 'audit') ORDER BY 1",
    )
    .fetch_all(&mut s)
    .await
    .unwrap()
    .iter()
    .map(|r| r.try_get::<String, _>(0).unwrap())
    .collect();
    assert_eq!(tables.len(), grants::TABLE_GRANTS.len(), "grant matrix must list every table");
    let mut problems = Vec::new();
    for t in &tables {
        let (_, expected) = grants::TABLE_GRANTS
            .iter()
            .find(|(n, _)| n == t)
            .unwrap_or_else(|| panic!("{t} missing from the grant matrix"));
        let quoted = quote(t);
        for role in &roles {
            let want: String = expected
                .iter()
                .filter(|(r, _)| *r == "*" || r == role)
                .map(|(_, p)| *p)
                .collect();
            for (letter, priv_) in [("S", "SELECT"), ("I", "INSERT"), ("U", "UPDATE"), ("D", "DELETE"), ("T", "TRUNCATE"), ("R", "REFERENCES"), ("G", "TRIGGER")] {
                let has: bool = sqlx::query("SELECT pg_catalog.has_table_privilege($1, $2, $3)")
                    .bind(role)
                    .bind(&quoted)
                    .bind(priv_)
                    .fetch_one(&mut s)
                    .await
                    .unwrap()
                    .try_get(0)
                    .unwrap();
                if has != want.contains(letter) {
                    problems.push(format!("{t} {role} {priv_}: expected {}", want.contains(letter)));
                }
            }
        }
    }
    // Column-level grants: exactly the listed columns.
    for (t, role, letter, cols) in grants::COLUMN_GRANTS {
        let quoted = quote(t);
        let priv_ = if *letter == "S" { "SELECT" } else { "UPDATE" };
        let all: Vec<String> = sqlx::query(
            "SELECT a.attname::text FROM pg_catalog.pg_attribute a WHERE a.attrelid = $1::regclass AND a.attnum > 0 AND NOT a.attisdropped",
        )
        .bind(&quoted)
        .fetch_all(&mut s)
        .await
        .unwrap()
        .iter()
        .map(|r| r.try_get::<String, _>(0).unwrap())
        .collect();
        for c in &all {
            let has: bool = sqlx::query("SELECT pg_catalog.has_column_privilege($1, $2, $3, $4)")
                .bind(role)
                .bind(&quoted)
                .bind(c)
                .bind(priv_)
                .fetch_one(&mut s)
                .await
                .unwrap()
                .try_get(0)
                .unwrap();
            if has != cols.contains(&c.as_str()) {
                problems.push(format!("{t}.{c} {role} column {priv_}: expected {}", cols.contains(&c.as_str())));
            }
        }
    }
    // L10 / ADR-015: admin, monitor and notify never read a ciphertext column;
    // the worker reads none either, except blob references (uuid) where a job
    // must move or delete blobs (09 §6.5).
    let class = classification::parse_classification(classification::CLASSIFICATION_TSV).unwrap();
    for r in class.iter().filter(|r| r.ciphertext) {
        for role in ["candor_admin", "candor_worker", "candor_monitor", "candor_notify"] {
            if role == "candor_worker" && r.column == "blob_id" {
                continue;
            }
            let t = quote(&format!("{}.{}", r.schema, r.table));
            let has: bool = sqlx::query("SELECT pg_catalog.has_column_privilege($1, $2, $3, 'SELECT')")
                .bind(role)
                .bind(&t)
                .bind(&r.column)
                .fetch_one(&mut s)
                .await
                .unwrap()
                .try_get(0)
                .unwrap();
            if has {
                problems.push(format!("{role} can read ciphertext {}.{}.{}", r.schema, r.table, r.column));
            }
        }
    }
    // The definer owner holds exactly SELECT on two tables and nothing else.
    let acl: Vec<String> = sqlx::query(
        "SELECT table_schema || '.' || table_name || ':' || privilege_type FROM information_schema.role_table_grants \
         WHERE grantee = 'candor_acl' ORDER BY 1",
    )
    .fetch_all(&mut s)
    .await
    .unwrap()
    .iter()
    .map(|r| r.try_get::<String, _>(0).unwrap())
    .collect();
    assert_eq!(acl, ["core.case_member:SELECT", "core.coi_excl_tag:SELECT"]);
    assert!(problems.is_empty(), "{problems:#?}");
}

fn quote(t: &str) -> String {
    if t == "core.case" { "core.\"case\"".into() } else { t.into() }
}

// ---- guards and triggers -------------------------------------------------------

#[tokio::test]
async fn append_only_and_guard_triggers() {
    let Some(b) = base() else { return };
    let name = fresh_db(&b).await;
    let (ta, ua) = (Uuid::new_v4(), Uuid::new_v4());
    let mut s = su(&b, &name).await;
    load_fixtures(&mut s, ta, ua).await;
    let mut c = conn(&b, &name, "candor_kd").await;
    let mut tx = ctx(&mut c, ta, Uuid::nil(), "kd").await;
    // kd_entry: UPDATE and DELETE raise even for the owner-adjacent role;
    // a gap or a replayed leaf index is refused.
    let e = sqlx::query("UPDATE kd.kd_entry SET body = '\\x02' WHERE tenant_id = $1").bind(ta).execute(&mut *tx).await;
    assert!(matches!(sqlstate(&e.unwrap_err()).as_str(), "42501" | "P0003"));
    tx.rollback().await.unwrap();
    let mut tx = ctx(&mut c, ta, Uuid::nil(), "kd").await;
    let gap = sqlx::query("INSERT INTO kd.kd_entry (tenant_id, leaf_index, entry_type, subject_id, body, leaf_hash, signer_key_id, sig, appended_day, effective_day) \
        VALUES ($1, 5, 'user_key', $1, '\\x01', pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'), pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'), pg_catalog.decode(pg_catalog.repeat('00', 64), 'hex'), DATE '2026-01-01', DATE '2026-01-01')")
        .bind(ta).execute(&mut *tx).await;
    assert_eq!(sqlstate(&gap.unwrap_err()), "P0004");
    tx.rollback().await.unwrap();
    // Superuser (owner-like) cannot update or delete either: the trigger fires regardless.
    for sql in ["UPDATE kd.kd_entry SET body = '\\x02'", "DELETE FROM kd.kd_entry", "DELETE FROM kd.kd_checkpoint",
                "DELETE FROM audit.audit_event", "UPDATE audit.audit_event SET payload = '\\x02'",
                "UPDATE audit.audit_event SET state = 'committed'; UPDATE audit.audit_event SET state = 'aborted'",
                "DELETE FROM audit.audit_checkpoint", "DELETE FROM kd.member_epoch_key",
                "UPDATE kd.member_epoch_key SET state = 'destroyed'; UPDATE kd.member_epoch_key SET state = 'active'",
                "UPDATE core.evidence_object SET blob_id = pg_catalog.gen_random_uuid()",
                "UPDATE core.\"case\" SET state = 'x'",
                "UPDATE core.\"case\" SET state = 'x', version = version + 2",
                "UPDATE core.role SET name = 'z', built_in = true; UPDATE core.role SET name = 'y'"] {
        let r = sqlx::raw_sql(AssertSqlSafe(format!("BEGIN; {sql}; ROLLBACK;"))).execute(&mut s).await;
        assert!(r.is_err(), "guard missing for `{sql}`");
        let _ = sqlx::raw_sql("ROLLBACK").execute(&mut s).await;
    }
    // Audit chain: wrong prev_hash, wrong seq and non-pending inserts are refused.
    let mut c = conn(&b, &name, "candor_audit_w").await;
    let mut tx = ctx(&mut c, ta, Uuid::nil(), "audit_w").await;
    let bad_prev = sqlx::query("INSERT INTO audit.audit_event (tenant_id, class, seq, event_type, actor_pseudonym, payload, occurred_date, prev_hash, hash) \
        VALUES ($1, 'system', 2, 1, pg_catalog.decode(pg_catalog.repeat('00', 16), 'hex'), '\\x01', DATE '2026-01-01', pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'), pg_catalog.decode(pg_catalog.repeat('02', 32), 'hex'))")
        .bind(ta).execute(&mut *tx).await;
    assert_eq!(sqlstate(&bad_prev.unwrap_err()), "P0004");
    tx.rollback().await.unwrap();
    let mut tx = ctx(&mut c, ta, Uuid::nil(), "audit_w").await;
    let good = sqlx::query("INSERT INTO audit.audit_event (tenant_id, class, seq, event_type, actor_pseudonym, payload, occurred_date, prev_hash, hash) \
        VALUES ($1, 'system', 2, 1, pg_catalog.decode(pg_catalog.repeat('00', 16), 'hex'), '\\x01', DATE '2026-01-01', pg_catalog.decode(pg_catalog.repeat('01', 32), 'hex'), pg_catalog.decode(pg_catalog.repeat('02', 32), 'hex'))")
        .bind(ta).execute(&mut *tx).await;
    assert!(good.is_ok());
    // pending → committed once; a second change is refused.
    let n = sqlx::query("UPDATE audit.audit_event SET state = 'committed' WHERE tenant_id = $1 AND class = 'system' AND seq = 2").bind(ta).execute(&mut *tx).await.unwrap().rows_affected();
    assert_eq!(n, 1);
    let again = sqlx::query("UPDATE audit.audit_event SET state = 'aborted' WHERE tenant_id = $1 AND class = 'system' AND seq = 2").bind(ta).execute(&mut *tx).await;
    assert_eq!(sqlstate(&again.unwrap_err()), "P0003");
    tx.rollback().await.unwrap();
    // Dual control in SQL: same person as approver, reviewer or release approver.
    for sql in [
        "UPDATE core.breakglass_request SET approver_id = requester_id",
        "UPDATE core.wrap_deletion_request SET approved_by = requested_by",
        "UPDATE core.deletion_request SET approved_by = requested_by",
        "UPDATE core.legal_hold SET released_by = placed_by, release_approved_by = placed_by, released_day = placed_day",
        "UPDATE core.import_envelope SET state = 'rejected', rejected_by = ARRAY[tenant_id, tenant_id]",
        // L17: an imported envelope keeps no slot date; a source message no day.
        "UPDATE core.import_envelope SET state = 'imported'",
        "UPDATE core.message SET day = DATE '2026-01-01' WHERE direction = 'from_source'",
        // Export approval by the creator, or with the wrong digest.
        "INSERT INTO core.export_approval (tenant_id, export_id, approver_id, decision, digest_confirmed, day) SELECT tenant_id, export_id, created_by, 'approve', package_digest, DATE '2026-01-01' FROM core.export_package",
    ] {
        let r = sqlx::raw_sql(AssertSqlSafe(format!("BEGIN; {sql}; ROLLBACK;"))).execute(&mut s).await;
        assert!(r.is_err(), "constraint missing for `{sql}`");
        let _ = sqlx::raw_sql("ROLLBACK").execute(&mut s).await;
    }
    // Legal hold derivation: fixture hold is unreleased → case.legal_hold true;
    // releasing it (two people) clears the flag and bumps the version.
    let held: (bool, i64) = {
        let r = sqlx::query("SELECT legal_hold, version FROM core.\"case\" WHERE tenant_id = $1").bind(ta).fetch_one(&mut s).await.unwrap();
        (r.try_get(0).unwrap(), r.try_get(1).unwrap())
    };
    assert!(held.0);
    sqlx::query("UPDATE core.legal_hold SET released_by = $2, release_approved_by = $1, released_day = placed_day, version = version + 1 WHERE tenant_id = $1")
        .bind(ta).bind(ua).execute(&mut s).await.unwrap();
    let after: (bool, i64) = {
        let r = sqlx::query("SELECT legal_hold, version FROM core.\"case\" WHERE tenant_id = $1").bind(ta).fetch_one(&mut s).await.unwrap();
        (r.try_get(0).unwrap(), r.try_get(1).unwrap())
    };
    assert_eq!(after, (false, held.1 + 1));
    // Worker scoping: a worker job other than the erasure kinds cannot delete content.
    let mut c = conn(&b, &name, "candor_worker").await;
    let mut tx = ctx(&mut c, ta, Uuid::nil(), "worker:sla_evaluate").await;
    let n = sqlx::query("DELETE FROM core.case_record WHERE tenant_id = $1").bind(ta).execute(&mut *tx).await.unwrap().rows_affected();
    assert_eq!(n, 0, "worker deleted content outside an erasure job");
    tx.rollback().await.unwrap();
    let mut tx = ctx(&mut c, ta, Uuid::nil(), "worker:crypto_erase_case").await;
    let n = sqlx::query("DELETE FROM core.case_record WHERE tenant_id = $1").bind(ta).execute(&mut *tx).await.unwrap().rows_affected();
    assert_eq!(n, 1);
    tx.rollback().await.unwrap();
    // Job kinds: the notify role sees only its own job kinds.
    let mut c = conn(&b, &name, "candor_notify").await;
    let mut tx = ctx(&mut c, ta, Uuid::nil(), "notify").await;
    assert_eq!(count(&mut tx, "core.job", "").await, 0);
}

// ---- TenantTx fail-closed -----------------------------------------------------

#[tokio::test]
async fn tenant_tx_fail_closed() {
    let Some(b) = base() else { return };
    let name = fresh_db(&b).await;
    let admin = open(&b, &name, Role::Admin).await;
    let case = open(&b, &name, Role::Case).await;
    let t = TenantId::random().unwrap();
    let u = UserId::random().unwrap();
    // Unknown tenant: refused before any query.
    let desk = Principal::staff(t, u, PrincipalKind::Desk).unwrap();
    assert_eq!(case.begin(&desk).await.err(), Some(DbError::TenantUnknown));
    // Bootstrap through the admin pool only.
    assert_eq!(repo::tenant::bootstrap(&case, t, "Acme", repo::tenant::RiskClass::Low).await.err(), Some(DbError::PrincipalMismatch));
    assert!(repo::tenant::bootstrap(&admin, t, "Acme", repo::tenant::RiskClass::Low).await.unwrap());
    assert!(!repo::tenant::bootstrap(&admin, t, "Acme", repo::tenant::RiskClass::Low).await.unwrap());
    assert_eq!(repo::tenant::bootstrap(&admin, t, "", repo::tenant::RiskClass::Low).await.err(), Some(DbError::InvalidInput("tenant label")));
    // Principal kind must match the pool's role.
    assert_eq!(admin.begin(&desk).await.err(), Some(DbError::PrincipalMismatch));
    let mut tx = case.begin(&desk).await.unwrap();
    let row = repo::tenant::get(&mut tx).await.unwrap();
    assert_eq!((row.label.as_str(), row.suspended, row.version), ("Acme", false, 1));
    tx.commit().await.unwrap();
    // Suspension: Desk refused, Admin and Worker still served.
    let adm = Principal::staff(t, u, PrincipalKind::Admin).unwrap();
    let mut tx = admin.begin(&adm).await.unwrap();
    assert_eq!(repo::tenant::set_suspended(&mut tx, 7, true).await.err(), Some(DbError::VersionConflict));
    repo::tenant::set_suspended(&mut tx, 1, true).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(case.begin(&desk).await.err(), Some(DbError::TenantSuspended));
    assert!(admin.begin(&adm).await.is_ok());
    let worker = open(&b, &name, Role::Worker).await;
    let w = Principal::system(t, PrincipalKind::Worker(JobKind::BlobGc)).unwrap();
    assert!(worker.begin(&w).await.is_ok());
    // Context never leaks across transactions on a pooled connection.
    let mut c = conn(&b, &name, "candor_case").await;
    let tx = ctx(&mut c, uuid_of(t.as_bytes()), uuid_of(u.as_bytes()), "desk").await;
    tx.commit().await.unwrap();
    let after: String = sqlx::query("SELECT pg_catalog.current_setting('candor.tenant_id', true)")
        .fetch_one(&mut c)
        .await
        .unwrap()
        .try_get(0)
        .unwrap();
    assert!(after.is_empty(), "tenant context survived the transaction");
    // A session-level SET is harmless: the next TenantTx overrides it, and a
    // raw statement without the wrapper still fails on the other tables.
    let bare = sqlx::query("SELECT count(*) FROM core.\"case\"").fetch_one(&mut c).await;
    assert_eq!(sqlstate(&bare.unwrap_err()), "42501");
}

// ---- migration tamper, drift and privileged-login refusal --------------------

#[tokio::test]
async fn tamper_and_drift_refused() {
    let Some(b) = base() else { return };
    let name = fresh_db(&b).await;
    let mut s = su(&b, &name).await;
    let mig = b.clone().username(&superuser()).database(&name);
    // Ledger digest altered: migrate and open refuse.
    sqlx::raw_sql("UPDATE candor.schema_migration SET sha256 = pg_catalog.decode(pg_catalog.repeat('ab', 32), 'hex')").execute(&mut s).await.unwrap();
    assert_eq!(migrate(&mig).await.err(), Some(DbError::Integrity("applied migration differs from build")));
    assert_eq!(try_open(&b, &name, Role::Case).await.err(), Some(DbError::Integrity("schema version mismatch")));
    let digest = sha2::Sha256::digest(MIGRATIONS[0].1.as_bytes());
    sqlx::query("UPDATE candor.schema_migration SET sha256 = $1").bind(digest.as_slice()).execute(&mut s).await.unwrap();
    assert!(try_open(&b, &name, Role::Case).await.is_ok());
    // Schema hash altered.
    sqlx::raw_sql("UPDATE candor.schema_meta SET schema_hash = pg_catalog.decode(pg_catalog.repeat('ab', 32), 'hex')").execute(&mut s).await.unwrap();
    assert_eq!(try_open(&b, &name, Role::Case).await.err(), Some(DbError::Integrity("schema hash mismatch")));
    sqlx::query("UPDATE candor.schema_meta SET schema_hash = $1").bind(schema_hash().as_slice()).execute(&mut s).await.unwrap();
    // Classification row altered.
    sqlx::raw_sql("UPDATE candor.column_class SET class = 'SYS' WHERE column_name = 'record_ct'").execute(&mut s).await.unwrap();
    assert_eq!(try_open(&b, &name, Role::Case).await.err(), Some(DbError::Integrity("schema lint failed")));
    sqlx::raw_sql("UPDATE candor.column_class SET class = 'CT' WHERE column_name = 'record_ct'").execute(&mut s).await.unwrap();
    // Drift: an extra table, an extra (unclassified, time-typed) column.
    sqlx::raw_sql("CREATE TABLE core.extra (tenant_id uuid NOT NULL, x int)").execute(&mut s).await.unwrap();
    assert_eq!(try_open(&b, &name, Role::Case).await.err(), Some(DbError::Integrity("schema guards differ from build")));
    sqlx::raw_sql("DROP TABLE core.extra").execute(&mut s).await.unwrap();
    sqlx::raw_sql("ALTER TABLE core.\"case\" ADD COLUMN seen_at timestamptz").execute(&mut s).await.unwrap();
    assert_eq!(try_open(&b, &name, Role::Case).await.err(), Some(DbError::Integrity("schema lint failed")));
    let mut c = conn(&b, &name, "candor_monitor").await;
    let v = lint::live(&mut c).await.unwrap();
    assert!(v.iter().any(|m| m.starts_with("L3")) && v.iter().any(|m| m.starts_with("L5")), "{v:?}");
    sqlx::raw_sql("ALTER TABLE core.\"case\" DROP COLUMN seen_at").execute(&mut s).await.unwrap();
    // Guards disabled: RLS unforced, a trigger disabled, a policy dropped.
    for (break_, fix) in [
        ("ALTER TABLE core.message NO FORCE ROW LEVEL SECURITY", "ALTER TABLE core.message FORCE ROW LEVEL SECURITY"),
        ("ALTER TABLE kd.kd_entry DISABLE TRIGGER kd_entry_append_only", "ALTER TABLE kd.kd_entry ENABLE TRIGGER kd_entry_append_only"),
        ("DROP POLICY p_case_acl ON core.case_record", "CREATE POLICY p_case_acl ON core.case_record AS RESTRICTIVE FOR ALL TO candor_case USING (false)"),
        ("DROP POLICY p_tenant ON core.job", "CREATE POLICY p_tenant ON core.job AS PERMISSIVE FOR ALL USING (tenant_id = candor.tenant()) WITH CHECK (tenant_id = candor.tenant())"),
    ] {
        sqlx::raw_sql(AssertSqlSafe(break_.to_string())).execute(&mut s).await.unwrap();
        assert_eq!(try_open(&b, &name, Role::Case).await.err(), Some(DbError::Integrity("schema guards differ from build")), "{break_}");
        sqlx::raw_sql(AssertSqlSafe(fix.to_string())).execute(&mut s).await.unwrap();
    }
    // Privileged or cross-member logins.
    for (break_, fix, want) in [
        ("ALTER ROLE candor_case BYPASSRLS", "ALTER ROLE candor_case NOBYPASSRLS", "login is not the plain application role"),
        ("ALTER ROLE candor_case CREATEROLE", "ALTER ROLE candor_case NOCREATEROLE", "login is not the plain application role"),
        ("GRANT candor_admin TO candor_case", "REVOKE candor_admin FROM candor_case", "login is not the plain application role"),
        ("GRANT candor_migrator TO candor_case", "REVOKE candor_migrator FROM candor_case", "login is not the plain application role"),
        ("ALTER ROLE candor_case SET statement_timeout = '1h'", "ALTER ROLE candor_case RESET statement_timeout", "session settings differ"),
    ] {
        sqlx::raw_sql(AssertSqlSafe(break_.to_string())).execute(&mut s).await.unwrap();
        assert_eq!(try_open(&b, &name, Role::Case).await.err(), Some(DbError::Integrity(want)), "{break_}");
        sqlx::raw_sql(AssertSqlSafe(fix.to_string())).execute(&mut s).await.unwrap();
    }
    // Logging of SQL text or bind values on this database: refused (IMP-RM3-019).
    for (k, v) in [("log_statement", "all"), ("log_min_error_statement", "error"), ("log_parameter_max_length_on_error", "1024")] {
        sqlx::raw_sql(AssertSqlSafe(format!("ALTER DATABASE {name} SET {k} = '{v}'"))).execute(&mut s).await.unwrap();
        assert_eq!(try_open(&b, &name, Role::Case).await.err(), Some(DbError::Integrity("session settings differ")), "{k}");
        sqlx::raw_sql(AssertSqlSafe(format!("ALTER DATABASE {name} RESET {k}"))).execute(&mut s).await.unwrap();
    }
    // A superuser login under an app role name is refused.
    let r = CaseDb::open(b.clone().username(&superuser()).database(&name), Role::Case, 1).await;
    assert_eq!(r.err(), Some(DbError::Integrity("login is not the plain application role")));
    assert!(try_open(&b, &name, Role::Case).await.is_ok());
}
