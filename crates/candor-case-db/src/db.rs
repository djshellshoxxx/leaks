// SPDX-License-Identifier: AGPL-3.0-or-later
//! Role-bound connection pools. `CaseDb::open` verifies, before serving: the
//! login is exactly the expected application role with no privilege beyond
//! its grants (not superuser, not BYPASSRLS, no CREATEROLE/CREATEDB/
//! REPLICATION, no membership in another candor role or in the table
//! owner); RLS is enabled and forced on every tenant table with the expected
//! policies and guard triggers; the session settings are the pinned ones; the
//! migration ledger, schema hash and column classification match the build
//! (schema drift refusal); and the server records no SQL text, bind values or
//! commit timestamps (IMP-RM3-019). Any mismatch refuses to run.

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, Connection, PgConnection, PgPool, Row};

use crate::error::{DbError, Result, db};
use crate::lint;
use crate::migrate::verify_ledger;
use crate::tx::TenantTx;
use crate::types::{Principal, PrincipalKind};

/// Application database roles (09 §5.2 legend, §7).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum Role {
    /// `candor_case`: Desk router.
    Case,
    /// `candor_admin`: Admin router (no content grants, ADR-015).
    Admin,
    /// `candor_relay`: fixed-slot import.
    Relay,
    /// `candor_worker`: scheduled jobs, retention, erasure.
    Worker,
    /// `candor_notify`: content-free notifications.
    Notify,
    /// `candor_kd`: key directory.
    Kd,
    /// `candor_auth`: staff authentication state.
    Auth,
    /// `candor_audit_w`: audit chain writer.
    AuditWriter,
    /// `candor_audit_r`: audit reader (auditor tools).
    AuditReader,
    /// `candor_monitor`: read-only operational state.
    Monitor,
}

/// Every role, for provisioning and the grant audit.
pub const ALL_ROLES: [Role; 10] = [
    Role::Case,
    Role::Admin,
    Role::Relay,
    Role::Worker,
    Role::Notify,
    Role::Kd,
    Role::Auth,
    Role::AuditWriter,
    Role::AuditReader,
    Role::Monitor,
];

impl Role {
    /// PostgreSQL role name.
    #[must_use]
    pub const fn pg_name(self) -> &'static str {
        match self {
            Self::Case => "candor_case",
            Self::Admin => "candor_admin",
            Self::Relay => "candor_relay",
            Self::Worker => "candor_worker",
            Self::Notify => "candor_notify",
            Self::Kd => "candor_kd",
            Self::Auth => "candor_auth",
            Self::AuditWriter => "candor_audit_w",
            Self::AuditReader => "candor_audit_r",
            Self::Monitor => "candor_monitor",
        }
    }

    const fn statement_timeout(self) -> &'static str {
        match self {
            Self::Worker => "10min",
            _ => "30s",
        }
    }

    const fn read_only(self) -> bool {
        matches!(self, Self::Monitor | Self::AuditReader)
    }

    /// Whether this role serves transactions of the given principal kind.
    #[must_use]
    pub const fn serves(self, kind: PrincipalKind) -> bool {
        matches!(
            (self, kind),
            (Self::Case, PrincipalKind::Desk)
                | (Self::Admin, PrincipalKind::Admin)
                | (Self::Relay, PrincipalKind::Relay)
                | (Self::Worker, PrincipalKind::Worker(_))
                | (Self::Notify, PrincipalKind::Notify)
                | (Self::Kd, PrincipalKind::Kd)
                | (Self::Auth, PrincipalKind::Auth)
                | (Self::AuditWriter, PrincipalKind::AuditWriter)
                | (Self::AuditReader, PrincipalKind::AuditReader)
                | (Self::Monitor, PrincipalKind::Monitor)
        )
    }
}

/// Identity check of the login (see module doc). `$1` = expected role name.
const SQL_ROLE_CHECK: &str = "SELECT r.rolname = $1::name, r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication, \
     EXISTS (SELECT 1 FROM pg_catalog.pg_roles o WHERE o.rolname LIKE 'candor\\_%' AND o.rolname <> r.rolname \
             AND pg_catalog.pg_has_role(r.rolname, o.rolname, 'MEMBER')), \
     EXISTS (SELECT 1 FROM pg_catalog.pg_tables t WHERE t.schemaname IN ('candor', 'core', 'auth', 'kd', 'audit') \
             AND pg_catalog.pg_has_role(r.rolname, t.tableowner, 'MEMBER')), \
     pg_catalog.pg_has_role(r.rolname, (SELECT d.datdba FROM pg_catalog.pg_database d \
             WHERE d.datname = pg_catalog.current_database()), 'MEMBER') \
     FROM pg_catalog.pg_roles r WHERE r.rolname = current_user";
/// Live guards: tenant tables without forced RLS, p_tenant policies,
/// restrictive policies, enabled guard triggers, tenant-table count.
const SQL_GUARD_CHECK: &str = "WITH t AS (SELECT k.oid, n.nspname, k.relname, k.relrowsecurity, k.relforcerowsecurity \
       FROM pg_catalog.pg_class k JOIN pg_catalog.pg_namespace n ON n.oid = k.relnamespace \
       WHERE k.relkind = 'r' AND n.nspname IN ('core', 'auth', 'kd', 'audit') \
       AND NOT (n.nspname = 'core' AND k.relname = 'permission')) \
     SELECT (SELECT count(*) FROM t WHERE NOT (t.relrowsecurity AND t.relforcerowsecurity)), \
       (SELECT count(*) FROM pg_catalog.pg_policy p JOIN t ON t.oid = p.polrelid WHERE p.polname = 'p_tenant' \
        AND p.polpermissive AND p.polcmd = '*' AND p.polroles = '{0}'), \
       (SELECT count(*) FROM pg_catalog.pg_policy p JOIN t ON t.oid = p.polrelid WHERE NOT p.polpermissive), \
       (SELECT count(*) FROM pg_catalog.pg_trigger g JOIN t ON t.oid = g.tgrelid WHERE NOT g.tgisinternal AND g.tgenabled = 'O'), \
       (SELECT count(*) FROM pg_catalog.pg_trigger g JOIN t ON t.oid = g.tgrelid WHERE NOT g.tgisinternal AND g.tgenabled <> 'O'), \
       (SELECT count(*) FROM t), \
       (SELECT count(*) FROM pg_catalog.pg_proc f JOIN pg_catalog.pg_namespace n ON n.oid = f.pronamespace \
        WHERE n.nspname IN ('candor', 'core', 'auth', 'kd', 'audit', 'acl') AND f.prosecdef), \
       (SELECT count(*) FROM pg_catalog.pg_extension e WHERE e.extname <> 'plpgsql')";
/// Restrictive policies created by the migration (lint::EXPECTED_RESTRICTIVE).
pub(crate) const EXPECTED_RESTRICTIVE: i64 = 40;
/// Named guard triggers plus the version guards.
pub(crate) const EXPECTED_TRIGGERS: i64 = 27;
/// SECURITY DEFINER allow-list: `acl.is_case_member`, `acl.coi_tag_present`.
const EXPECTED_DEFINERS: i64 = 2;

/// Session hardening check, on every new connection. A role can `ALTER ROLE`
/// its own defaults, so stored defaults are restricted to the migration's
/// values and the effective values (after the startup options) are compared.
const SQL_SESSION_CHECK: &str = "SELECT COALESCE((SELECT pg_catalog.array_agg(x ORDER BY x) \
     FROM pg_catalog.pg_db_role_setting s, pg_catalog.unnest(s.setconfig) x \
     WHERE s.setrole = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = current_user) \
     AND s.setdatabase IN (0, (SELECT d.oid FROM pg_catalog.pg_database d \
     WHERE d.datname = pg_catalog.current_database()))), '{}'::text[]), \
     pg_catalog.current_setting('search_path'), pg_catalog.current_setting('statement_timeout'), \
     pg_catalog.current_setting('idle_in_transaction_session_timeout'), \
     pg_catalog.current_setting('lock_timeout'), \
     pg_catalog.current_setting('synchronous_commit'), pg_catalog.current_setting('row_security'), \
     pg_catalog.current_setting('default_transaction_read_only'), \
     pg_catalog.current_setting('session_replication_role'), \
     pg_catalog.current_setting('default_transaction_isolation'), \
     pg_catalog.current_setting('track_commit_timestamp'), \
     pg_catalog.current_setting('log_statement'), \
     pg_catalog.current_setting('log_min_error_statement'), \
     pg_catalog.current_setting('log_parameter_max_length_on_error')";
const ALLOWED_ROLE_SETTINGS: [&str; 5] = [
    "idle_in_transaction_session_timeout=60s",
    "search_path=candor, core",
    "statement_timeout=30s",
    "statement_timeout=10min",
    "default_transaction_read_only=on",
];

fn session_options(role: Role) -> [(&'static str, &'static str); 7] {
    [
        ("statement_timeout", role.statement_timeout()),
        ("idle_in_transaction_session_timeout", "60s"),
        ("lock_timeout", "10s"),
        ("search_path", "candor, core"),
        ("synchronous_commit", "on"),
        ("row_security", "on"),
        (
            "default_transaction_read_only",
            if role.read_only() { "on" } else { "off" },
        ),
    ]
}

async fn session_ok(conn: &mut PgConnection, role: Role) -> std::result::Result<bool, sqlx::Error> {
    let row = sqlx::query(SQL_SESSION_CHECK).fetch_one(conn).await?;
    let stored: Vec<String> = row.try_get(0)?;
    if !stored
        .iter()
        .all(|e| ALLOWED_ROLE_SETTINGS.contains(&e.as_str()) || e.starts_with("temp_file_limit="))
    {
        return Ok(false);
    }
    let expected: [&str; 13] = [
        "candor, core",
        role.statement_timeout(),
        "1min",
        "10s",
        "on",
        "on",
        if role.read_only() { "on" } else { "off" },
        "origin",
        "read committed",
        "off",
        "none",
        "panic",
        "0",
    ];
    for (i, want) in expected.iter().enumerate() {
        let got: String = row.try_get(i.saturating_add(1))?;
        if got != *want {
            return Ok(false);
        }
    }
    Ok(true)
}

/// A role-bound pool.
pub struct CaseDb {
    pool: PgPool,
    role: Role,
}

impl std::fmt::Debug for CaseDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaseDb").field("role", &self.role).finish()
    }
}

impl CaseDb {
    /// Open a pool for `role` and verify everything in the module doc. Every
    /// later pool connection re-runs the session check.
    pub async fn open(opts: PgConnectOptions, role: Role, max_connections: u32) -> Result<Self> {
        let opts = opts.options(session_options(role));
        let mut conn = PgConnection::connect_with(&opts.clone().disable_statement_logging())
            .await
            .map_err(db)?;
        let row = sqlx::query(SQL_ROLE_CHECK)
            .bind(role.pg_name())
            .fetch_one(&mut conn)
            .await
            .map_err(db)?;
        let is_role: bool = row.try_get(0).map_err(db)?;
        let privileged: bool = row.try_get(1).map_err(db)?;
        let other_member: bool = row.try_get(2).map_err(db)?;
        let owner_member: bool = row.try_get(3).map_err(db)?;
        let db_owner: bool = row.try_get(4).map_err(db)?;
        if !is_role || privileged || other_member || owner_member || db_owner {
            return Err(DbError::Integrity(
                "login is not the plain application role",
            ));
        }
        let g = sqlx::query(SQL_GUARD_CHECK)
            .fetch_one(&mut conn)
            .await
            .map_err(db)?;
        let unforced: i64 = g.try_get(0).map_err(db)?;
        let tenant_policies: i64 = g.try_get(1).map_err(db)?;
        let restrictive: i64 = g.try_get(2).map_err(db)?;
        let triggers_on: i64 = g.try_get(3).map_err(db)?;
        let triggers_off: i64 = g.try_get(4).map_err(db)?;
        let tables: i64 = g.try_get(5).map_err(db)?;
        let definers: i64 = g.try_get(6).map_err(db)?;
        let extensions: i64 = g.try_get(7).map_err(db)?;
        if unforced != 0
            || tables != lint::TENANT_TABLES.len() as i64
            || tenant_policies != tables
            || restrictive != EXPECTED_RESTRICTIVE
            || triggers_on != EXPECTED_TRIGGERS
            || triggers_off != 0
            || definers != EXPECTED_DEFINERS
            || extensions != 0
        {
            return Err(DbError::Integrity("schema guards differ from build"));
        }
        if !session_ok(&mut conn, role).await.map_err(db)? {
            return Err(DbError::Integrity("session settings differ"));
        }
        verify_ledger(&mut conn).await?;
        let violations = lint::live(&mut conn).await?;
        if !violations.is_empty() {
            return Err(DbError::Integrity("schema lint failed"));
        }
        conn.close().await.map_err(db)?;
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.clamp(1, 64))
            .acquire_timeout(std::time::Duration::from_secs(5))
            .after_connect(move |conn, _meta| {
                Box::pin(async move {
                    if session_ok(conn, role).await? {
                        Ok(())
                    } else {
                        Err(sqlx::Error::Protocol("session settings differ".into()))
                    }
                })
            })
            .connect_with(opts.disable_statement_logging())
            .await
            .map_err(db)?;
        Ok(Self { pool, role })
    }

    /// The role this pool is bound to.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Begin a tenant transaction for `principal` (the only way to query).
    pub async fn begin(&self, principal: &Principal) -> Result<TenantTx> {
        if !self.role.serves(principal.kind()) {
            return Err(DbError::PrincipalMismatch);
        }
        TenantTx::begin(&self.pool, principal).await
    }

    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
    }
}
