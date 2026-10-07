// SPDX-License-Identifier: AGPL-3.0-or-later
//! Schema lint (09 §8 L1–L6, L14, L16, L18; IMP-RM3-001/019). The static
//! lint runs over the migration SQL in a unit test; the live lint runs over
//! the migrated catalog at every service open (and in the PG test suite).
//! A violation is a human-readable string naming schema objects only.

use sqlx::{PgConnection, Row};

use crate::classification::{CLASSIFICATION_TSV, ClassRow, DataClass, parse_classification};
use crate::error::{Result, db};

/// Every tenant-scoped table (`schema.table`): RLS enabled + forced with the
/// `p_tenant` policy. Generated tests (RLS isolation, grant matrix) iterate
/// this list, so a new table without tests fails `tenant_tables_match_file`.
pub const TENANT_TABLES: &[&str] = &[
    "core.tenant",
    "core.department",
    "core.retention_policy",
    "core.workflow_definition",
    "core.channel",
    "core.app_user",
    "core.channel_member",
    "core.roster_change",
    "core.coi_category",
    "core.coi_registry",
    "core.role",
    "core.role_assignment",
    "core.import_envelope",
    "core.import_envelope_part",
    "core.case",
    "core.case_meta",
    "core.submission",
    "core.breakglass_request",
    "core.case_member",
    "core.case_key_wrap",
    "core.coi_excl_tag",
    "core.case_record",
    "core.message",
    "core.evidence_object",
    "core.attachment",
    "core.evidence_derivative",
    "core.sealed_identity",
    "core.identity_unseal_request",
    "core.case_state_history",
    "core.sla_timer",
    "core.legal_hold",
    "core.deletion_request",
    "core.wrap_deletion_request",
    "core.reply_outbox",
    "core.intake_deletion_list",
    "core.export_package",
    "core.export_approval",
    "core.notification_target",
    "core.notification_queue",
    "core.job",
    "core.config_change",
    "core.config_bundle",
    "core.idempotency_key",
    "core.blob_object",
    "core.aggregate_counter",
    "auth.webauthn_credential",
    "auth.device",
    "auth.enrollment_token",
    "auth.session",
    "auth.refresh_token",
    "auth.stepup_proof",
    "auth.pop_nonce",
    "kd.kd_entry",
    "kd.kd_checkpoint",
    "kd.witness_cosignature",
    "kd.member_epoch_key",
    "kd.user_key",
    "audit.audit_event",
    "audit.audit_checkpoint",
];

/// L3: the canonical exact-timestamp allow-list (`schema.table.column`).
pub const TIMESTAMP_ALLOW: &[&str] = &[
    "auth.session.issued_at",
    "auth.session.expires_at",
    "auth.refresh_token.expires_at",
    "auth.stepup_proof.expires_at",
    "auth.enrollment_token.expires_at",
    "auth.pop_nonce.seen_at",
    "core.idempotency_key.expires_at",
    "core.job.run_after",
    "core.job.lease_until",
    "core.config_change.effective_after",
    "core.breakglass_request.expires_at",
    "audit.audit_event.occurred_at",
    "audit.audit_checkpoint.signed_at",
];

/// L2 network-identity name tokens.
const L2_TOKENS: &[&str] = &[
    "ip", "ips", "ipaddr", "remote", "peer", "referer", "referrer", "geo", "geoip", "lat", "lng",
    "lon", "latitude", "longitude", "circuit", "asn", "hostname", "ua", "useragent",
];
const L2_PHRASES: &[&str] = &[
    "ip_address",
    "client_addr",
    "x_forwarded",
    "forwarded_for",
    "user_agent",
    "circuit_id",
    "onion_circ",
];

/// L2: `(?i)(^|_)(…)($|_)`.
#[must_use]
pub fn l2_violation(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    if n.split('_').any(|t| L2_TOKENS.contains(&t)) {
        return true;
    }
    L2_PHRASES.iter().any(|p| {
        n == *p
            || n.starts_with(&format!("{p}_"))
            || n.ends_with(&format!("_{p}"))
            || n.contains(&format!("_{p}_"))
    })
}

/// Time-typed PostgreSQL types (L3) and network types (L1).
const TIME_TYPES: &[&str] = &[
    "timestamp without time zone",
    "timestamp with time zone",
    "time without time zone",
    "time with time zone",
    "interval",
];
const NET_TYPES: &[&str] = &["inet", "cidr", "macaddr", "macaddr8"];
const TIME_DEFAULTS: &[&str] = &[
    "now(",
    "current_timestamp",
    "clock_timestamp",
    "localtimestamp",
    "transaction_timestamp",
    "statement_timestamp",
    "current_date",
    "current_time",
];

/// A live or statically parsed column: `(schema, table, column, data_type, default)`.
pub type ColumnRow = (String, String, String, String, Option<String>);

/// Lint column rows against the classification and the 09 §8 rules.
#[must_use]
pub fn check_columns(rows: &[ColumnRow], class: &[ClassRow]) -> Vec<String> {
    let mut v = Vec::new();
    let find = |s: &str, t: &str, c: &str| {
        class
            .iter()
            .find(|r| r.schema == s && r.table == t && r.column == c)
    };
    for (s, t, c, ty, def) in rows {
        let fq = format!("{s}.{t}.{c}");
        if NET_TYPES.contains(&ty.as_str()) {
            v.push(format!("L1: {fq} has network type {ty}"));
        }
        if l2_violation(c) {
            v.push(format!("L2: {fq} network-identity name"));
        }
        if TIME_TYPES.contains(&ty.as_str()) && !TIMESTAMP_ALLOW.contains(&fq.as_str()) {
            v.push(format!("L3: {fq} exact time outside the allow-list"));
        }
        let cls = find(s, t, c);
        match cls {
            None => v.push(format!("L5: {fq} unclassified")),
            Some(r) => {
                if c.ends_with("_ct") && !(r.ciphertext && ty == "bytea") {
                    v.push(format!("L5: {fq} *_ct must be ciphertext bytea"));
                }
                if r.ciphertext && ty != "uuid" && ty != "bytea" {
                    v.push(format!("L5: {fq} ciphertext column type {ty}"));
                }
                if r.class == DataClass::CT && !r.ciphertext {
                    v.push(format!("L5: {fq} CT class without ciphertext flag"));
                }
            }
        }
        if let Some(d) = def {
            let d = d.to_ascii_lowercase();
            if TIME_DEFAULTS.iter().any(|f| d.contains(f)) {
                v.push(format!("L4: {fq} time default"));
            }
        }
        // L14: no COI user/reason/source column outside the registry.
        let lc = c.to_ascii_lowercase();
        if s == "core"
            && t != "coi_registry"
            && lc.contains("coi")
            && (lc.contains("user") || lc.contains("reason") || lc.contains("source"))
        {
            v.push(format!("L14: {fq} COI identity column"));
        }
        // L16: metadata-erasure columns only as ciphertext.
        if s == "core"
            && !["coi_category", "workflow_definition", "tenant", "department", "channel", "channel_member", "role"]
                .contains(&t.as_str())
            && ["category", "routing_visible", "custom_field", "title", "label"]
                .iter()
                .any(|k| lc.contains(k))
            && ty != "bytea"
        {
            v.push(format!("L16: {fq} cleartext metadata column"));
        }
        // L18: chaff indistinguishability on import tables.
        if t.starts_with("import_envelope")
            && ["chaff", "decoy", "dummy"].iter().any(|k| lc.contains(k))
        {
            v.push(format!("L18: {fq} names chaff"));
        }
    }
    for r in class {
        if !rows
            .iter()
            .any(|(s, t, c, _, _)| *s == r.schema && *t == r.table && *c == r.column)
        {
            v.push(format!("L5: classified column {}.{}.{} missing", r.schema, r.table, r.column));
        }
    }
    v
}

/// Keywords that must not appear in the migration SQL (comments stripped),
/// with the number of allowed occurrences.
const SQL_KEYWORDS: &[(&str, usize)] = &[
    ("security definer", 1),
    ("unlogged", 0),
    ("publication", 0),
    ("replication slot", 0),
    ("pg_logical", 0),
    ("track_commit_timestamp", 0),
    ("create extension", 0),
    (" serial", 0),
    ("generated always as identity", 0),
    ("generated by default as identity", 0),
    ("leakproof", 0),
    (" inet", 0),
    (" cidr", 0),
    (" macaddr", 0),
    ("bypassrls ", 0),
    ("superuser ", 0),
];

/// Static lint over migration SQL text: keyword budget and the column rules
/// over every `CREATE TABLE` block (types and defaults as written).
#[must_use]
pub fn check_sql(sql: &str, class: &[ClassRow]) -> Vec<String> {
    let mut v = Vec::new();
    let lower: String = sql
        .lines()
        .map(|l| l.split("--").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    for (kw, allowed) in SQL_KEYWORDS {
        let n = lower
            .match_indices(kw)
            .filter(|(i, _)| {
                let prev = lower.get(i.saturating_sub(2)..*i).unwrap_or("");
                !(prev == "no" && (*kw == "bypassrls " || *kw == "superuser "))
            })
            .count();
        if n > *allowed {
            v.push(format!("keyword `{}` appears {n} times (allowed {allowed})", kw.trim()));
        }
    }
    let mut rows: Vec<ColumnRow> = Vec::new();
    let mut cur: Option<(String, String)> = None;
    for line in lower.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("create table ") {
            let name = rest.split([' ', '(']).next().unwrap_or("").replace('"', "");
            let (s, t) = name.split_once('.').unwrap_or(("", ""));
            cur = Some((s.to_string(), t.to_string()));
            continue;
        }
        if let Some((s, t)) = cur.as_ref() {
            if l.starts_with(");") {
                cur = None;
                continue;
            }
            let mut it = l.split_whitespace();
            let first = it.next().unwrap_or("");
            let ty = it.next().unwrap_or("").trim_end_matches(',');
            if first.is_empty()
                || !first.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                || ["check", "unique", "primary", "foreign", "constraint"].contains(&first)
            {
                continue;
            }
            let ty = match ty {
                "timestamptz" => "timestamp with time zone".to_string(),
                "timestamp" => "timestamp without time zone".to_string(),
                other => other.to_string(),
            };
            let def = l
                .find(" default ")
                .map(|i| l.get(i..).unwrap_or("").to_string());
            rows.push((s.clone(), t.clone(), first.to_string(), ty, def));
        }
    }
    v.extend(check_columns(&rows, class));
    v
}

const SQL_LIVE_COLUMNS: &str = "SELECT c.table_schema::text, c.table_name::text, c.column_name::text, c.data_type::text, c.column_default::text \
     FROM information_schema.columns c JOIN information_schema.tables t \
     ON t.table_schema = c.table_schema AND t.table_name = c.table_name \
     WHERE c.table_schema IN ('candor', 'core', 'auth', 'kd', 'audit') AND t.table_type = 'BASE TABLE' \
     ORDER BY 1, 2, c.ordinal_position";
const SQL_LIVE_CLASS: &str = "SELECT table_schema, table_name, column_name, class::text, ciphertext FROM candor.column_class";
const SQL_LIVE_RLS: &str = "SELECT n.nspname::text || '.' || k.relname::text FROM pg_catalog.pg_class k \
     JOIN pg_catalog.pg_namespace n ON n.oid = k.relnamespace \
     WHERE k.relkind = 'r' AND n.nspname IN ('core', 'auth', 'kd', 'audit') \
     AND NOT (n.nspname = 'core' AND k.relname = 'permission') \
     AND NOT (k.relrowsecurity AND k.relforcerowsecurity \
       AND EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = k.oid AND p.polname = 'p_tenant') \
       AND EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid = k.oid AND a.attname = 'tenant_id' \
                   AND a.attnotnull AND a.atttypid = 'uuid'::regtype)) ORDER BY 1";
const SQL_LIVE_TABLES: &str = "SELECT n.nspname::text || '.' || k.relname::text FROM pg_catalog.pg_class k \
     JOIN pg_catalog.pg_namespace n ON n.oid = k.relnamespace \
     WHERE k.relkind = 'r' AND n.nspname IN ('core', 'auth', 'kd', 'audit') \
     AND NOT (n.nspname = 'core' AND k.relname = 'permission') ORDER BY 1";

/// Live lint over the migrated catalog: column rules against the embedded
/// classification, the stored `candor.column_class` equal to the file, L6
/// tenancy/RLS on every tenant table, and the tenant-table list of this build.
pub async fn live(conn: &mut PgConnection) -> Result<Vec<String>> {
    let class = parse_classification(CLASSIFICATION_TSV)?;
    let rows = sqlx::query(SQL_LIVE_COLUMNS)
        .fetch_all(&mut *conn)
        .await
        .map_err(db)?;
    let mut cols: Vec<ColumnRow> = Vec::with_capacity(rows.len());
    for r in &rows {
        cols.push((
            r.try_get(0).map_err(db)?,
            r.try_get(1).map_err(db)?,
            r.try_get(2).map_err(db)?,
            r.try_get(3).map_err(db)?,
            r.try_get(4).map_err(db)?,
        ));
    }
    let mut v = check_columns(&cols, &class);
    let stored = sqlx::query(SQL_LIVE_CLASS)
        .fetch_all(&mut *conn)
        .await
        .map_err(db)?;
    if stored.len() != class.len() {
        v.push("L5: stored column_class row count differs from the build".into());
    }
    for r in &stored {
        let (s, t, c): (String, String, String) = (
            r.try_get(0).map_err(db)?,
            r.try_get(1).map_err(db)?,
            r.try_get(2).map_err(db)?,
        );
        let k: String = r.try_get(3).map_err(db)?;
        let ct: bool = r.try_get(4).map_err(db)?;
        let ok = class.iter().any(|x| {
            x.schema == s && x.table == t && x.column == c && x.class.as_str() == k && x.ciphertext == ct
        });
        if !ok {
            v.push(format!("L5: stored classification of {s}.{t}.{c} differs from the build"));
        }
    }
    let bad = sqlx::query(SQL_LIVE_RLS)
        .fetch_all(&mut *conn)
        .await
        .map_err(db)?;
    for r in &bad {
        let n: String = r.try_get(0).map_err(db)?;
        v.push(format!("L6: {n} lacks tenant_id, forced RLS or p_tenant"));
    }
    let live_tables = sqlx::query(SQL_LIVE_TABLES)
        .fetch_all(&mut *conn)
        .await
        .map_err(db)?;
    let mut names: Vec<String> = Vec::with_capacity(live_tables.len());
    for r in &live_tables {
        names.push(r.try_get(0).map_err(db)?);
    }
    let mut expected: Vec<&str> = TENANT_TABLES.to_vec();
    expected.sort_unstable();
    if names.iter().map(String::as_str).collect::<Vec<_>>() != expected {
        v.push("L6: live tenant-table set differs from the build".into());
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_pass_static_lint() {
        let class = parse_classification(CLASSIFICATION_TSV).unwrap();
        for (_, sql) in crate::migrate::MIGRATIONS {
            let v = check_sql(sql, &class);
            assert!(v.is_empty(), "{v:?}");
        }
    }

    #[test]
    fn tenant_tables_match_file() {
        let class = parse_classification(CLASSIFICATION_TSV).unwrap();
        let mut from_file: Vec<String> = class
            .iter()
            .filter(|r| r.schema != "candor" && !(r.schema == "core" && r.table == "permission"))
            .map(|r| format!("{}.{}", r.schema, r.table))
            .collect();
        from_file.sort();
        from_file.dedup();
        let mut listed: Vec<String> = TENANT_TABLES.iter().map(|s| (*s).to_string()).collect();
        listed.sort();
        assert_eq!(from_file, listed);
    }

    #[test]
    fn lint_catches_violations() {
        let class = parse_classification(CLASSIFICATION_TSV).unwrap();
        assert!(l2_violation("client_ip"));
        assert!(l2_violation("x_forwarded_for"));
        assert!(!l2_violation("epoch_index"));
        let rows: Vec<ColumnRow> = vec![
            ("core".into(), "case".into(), "client_addr".into(), "inet".into(), Some("now()".into())),
            ("core".into(), "case".into(), "seen".into(), "timestamp with time zone".into(), None),
            ("core".into(), "case".into(), "title".into(), "text".into(), None),
            ("core".into(), "case".into(), "coi_user".into(), "uuid".into(), None),
            ("core".into(), "import_envelope".into(), "is_chaff".into(), "boolean".into(), None),
        ];
        let v = check_columns(&rows, &class);
        for code in ["L1", "L2", "L3", "L4", "L5", "L14", "L16", "L18"] {
            assert!(v.iter().any(|m| m.starts_with(code)), "{code}: {v:?}");
        }
        let sql = "CREATE TABLE core.x (\n  a uuid,\n  b timestamptz\n);\nCREATE UNLOGGED TABLE core.y (a uuid);";
        let v = check_sql(sql, &class);
        assert!(v.iter().any(|m| m.contains("unlogged")), "{v:?}");
        assert!(v.iter().any(|m| m.starts_with("L3")), "{v:?}");
        let sql2 = "CREATE FUNCTION f() RETURNS int SECURITY DEFINER AS $$ SELECT 1 $$;\nCREATE FUNCTION g() RETURNS int SECURITY DEFINER AS $$ SELECT 1 $$;";
        assert!(check_sql(sql2, &class).iter().any(|m| m.contains("security definer")));
    }
}
