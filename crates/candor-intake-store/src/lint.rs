// SPDX-License-Identifier: AGPL-3.0-or-later
//! Intake schema lint (09 §8 L1–L4, L11–L13, L15; DB-007, DB-008). Used by the
//! static test over the migration SQL (always runs) and by the live test against a
//! migrated PostgreSQL database (`CANDOR_TEST_PG`). Returns human-readable
//! violations; an empty list means the schema passes.

/// Expected columns per table: 09 §5.1 plus the documented additions
/// (`envelope.epoch_index`, `intake_meta.restore_pending`,
/// `intake_meta.deletion_acked_seq/_hash/_sig`, `reply.pub_gen`, `schema_migration`),
/// without `source_account.quota_bucket` (quota is RAM-only, AUD-RM2-STO-01) and
/// with the fixed-shape envelope group of ADR-052(1)/(2): no account reference,
/// three parts each with `object_hash` and `slot_block`.
pub const EXPECTED: &[(&str, &[&str])] = &[
    (
        "intake_meta",
        &[
            "tenant_id",
            "schema_hash",
            "kdf_salt",
            "relay_req_counter",
            "last_batch_no",
            "directory_version",
            "kd_tree_size_hwm",
            "kd_checkpoint_day_hwm",
            "config_version",
            "restore_pending",
            "deletion_acked_seq",
            "deletion_acked_hash",
            "deletion_acked_sig",
        ],
    ),
    (
        "source_account",
        &[
            "account_id",
            "locator_hash",
            "auth_pk",
            "xwing_pk",
            "prefs_ct",
            "activity_month",
        ],
    ),
    (
        "envelope",
        &[
            "envelope_ref",
            "channel_id",
            "group_sha256",
            "disposition_ct",
            "epoch_index",
            "received_date",
            "release_day",
            "batch_no",
            "state",
        ],
    ),
    (
        "envelope_part",
        &[
            "envelope_ref",
            "part_no",
            "object_hash",
            "slot_block",
            "blob_id",
            "padded_size",
        ],
    ),
    (
        "reply",
        &[
            "reply_ref",
            "source_account_id",
            "reply_ct",
            "size_bucket",
            "available_day",
            "slot",
            "pub_gen",
        ],
    ),
    (
        "deletion_list",
        &[
            "seq",
            "kind",
            "del_hash",
            "del_day",
            "prev_hash",
            "sig",
            "relayed",
        ],
    ),
    (
        "directory_snapshot",
        &["version", "body", "signatures", "applied_day"],
    ),
    ("counter_month", &["month", "channel_id", "name", "value"]),
    ("schema_migration", &["version", "sha256"]),
];

/// L2 network-identity name tokens (09 §8).
const L2_TOKENS: &[&str] = &[
    "ip",
    "ips",
    "ipaddr",
    "remote",
    "peer",
    "referer",
    "referrer",
    "geo",
    "geoip",
    "lat",
    "lng",
    "lon",
    "latitude",
    "longitude",
    "circuit",
    "asn",
    "hostname",
    "ua",
    "useragent",
];
/// L2 multi-token names.
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
    let toks: Vec<&str> = n.split('_').collect();
    if toks.iter().any(|t| L2_TOKENS.contains(t)) {
        return true;
    }
    L2_PHRASES.iter().any(|p| {
        n == *p
            || n.starts_with(&format!("{p}_"))
            || n.ends_with(&format!("_{p}"))
            || n.contains(&format!("_{p}_"))
    })
}

/// L11: forbidden intake column names (ADR-039). `deletion_list.kind` is listed
/// explicitly in 09 §5.1 and is exempt (SPEC-NOTES).
#[must_use]
pub fn l11_violation(table: &str, column: &str) -> bool {
    let c = column.to_ascii_lowercase();
    c == "tier"
        || (c == "kind" && table != "deletion_list")
        || c == "fetched"
        || c.starts_with("fetched_")
        || c == "read"
        || (c.starts_with("last_") && !(table == "intake_meta" && c == "last_batch_no"))
        || c.ends_with("_history")
}

/// L12: anonymous recipients on envelope tables.
#[must_use]
pub fn l12_violation(table: &str, column: &str) -> bool {
    let c = column.to_ascii_lowercase();
    (table == "envelope" || table == "envelope_part")
        && (c.contains("slot_key") || c.contains("recipient_key") || c.contains("recipients"))
}

/// Forbidden PostgreSQL data types anywhere in the intake DB (L1, L3, L11).
const FORBIDDEN_TYPES: &[&str] = &[
    "inet",
    "cidr",
    "macaddr",
    "macaddr8",
    "timestamp without time zone",
    "timestamp with time zone",
    "time without time zone",
    "time with time zone",
    "interval",
];

/// Lint live catalog rows `(table, column, data_type, column_default)`.
#[must_use]
pub fn check_columns(rows: &[(String, String, String, Option<String>)]) -> Vec<String> {
    let mut v = Vec::new();
    for (t, c, ty, def) in rows {
        if FORBIDDEN_TYPES.contains(&ty.as_str()) {
            v.push(format!("L1/L3: {t}.{c} has forbidden type {ty}"));
        }
        if l2_violation(c) {
            v.push(format!("L2: {t}.{c} network-identity name"));
        }
        if l11_violation(t, c) {
            v.push(format!("L11: {t}.{c} forbidden name"));
        }
        if l12_violation(t, c) {
            v.push(format!("L12: {t}.{c} recipient column"));
        }
        if let Some(d) = def {
            let d = d.to_ascii_lowercase();
            if [
                "now(",
                "current_timestamp",
                "clock_timestamp",
                "localtimestamp",
                "transaction_timestamp",
                "statement_timestamp",
                "current_date",
                "current_time",
            ]
            .iter()
            .any(|f| d.contains(f))
            {
                v.push(format!("L4: {t}.{c} time default"));
            }
        }
        if t.to_ascii_lowercase().contains("draft") {
            v.push(format!("L13: draft table {t}"));
        }
        match EXPECTED.iter().find(|(et, _)| et == t) {
            Some((_, cols)) if cols.contains(&c.as_str()) => {}
            Some(_) => v.push(format!("L11: {t}.{c} not in 09 §5.1")),
            None => v.push(format!("L11/L15: unexpected table {t}")),
        }
    }
    for (et, cols) in EXPECTED {
        for c in *cols {
            if !rows.iter().any(|(t, cc, _, _)| t == et && cc == c) {
                v.push(format!("missing column {et}.{c}"));
            }
        }
    }
    v
}

/// Static lint over migration SQL text: forbidden type keywords, time functions,
/// replication features, and the column set of every `CREATE TABLE`.
#[must_use]
pub fn check_sql(sql: &str) -> Vec<String> {
    let mut v = Vec::new();
    let lower: String = sql
        .lines()
        .map(|l| l.split("--").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    for kw in [
        "timestamp",
        "timestamptz",
        " time ",
        "interval",
        "inet",
        "cidr",
        "macaddr",
        "now()",
        "clock_timestamp",
        "current_date",
        "current_time",
        "localtime",
        "publication",
        "replication slot",
        "pg_logical",
        "track_commit_timestamp",
        "security definer",
        "leakproof",
        "bypassrls ",
        "superuser ",
        "unlogged",
    ] {
        // `NOBYPASSRLS` / `NOSUPERUSER` are fine; the bare attribute is not.
        let hit = lower.match_indices(kw).any(|(i, _)| {
            let prev = lower.get(i.saturating_sub(2)..i).unwrap_or("");
            !(prev == "no" && (kw == "bypassrls " || kw == "superuser "))
        });
        if hit {
            v.push(format!("forbidden keyword `{}`", kw.trim()));
        }
    }
    // Column sets.
    let mut tables: Vec<(String, Vec<String>)> = Vec::new();
    let mut cur: Option<(String, Vec<String>)> = None;
    for line in lower.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("create table candor.") {
            let name = rest.split([' ', '(']).next().unwrap_or("").to_string();
            cur = Some((name, Vec::new()));
            continue;
        }
        if let Some((_, cols)) = cur.as_mut() {
            if l.starts_with(");") {
                if let Some(t) = cur.take() {
                    tables.push(t);
                }
                continue;
            }
            let first = l.split_whitespace().next().unwrap_or("");
            if !first.is_empty()
                && !["check", "unique", "primary", "foreign", "constraint"]
                    .contains(&first.trim_end_matches('('))
            {
                cols.push(first.to_string());
            }
        }
    }
    let rows: Vec<(String, String, String, Option<String>)> = tables
        .iter()
        .flat_map(|(t, cols)| {
            cols.iter()
                .map(move |c| (t.clone(), c.clone(), String::new(), None))
        })
        .collect();
    v.extend(check_columns(&rows));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DB-007/DB-008, 09 §8 L1–L4, L11–L13: the shipped migrations pass.
    #[test]
    fn migrations_pass_static_lint() {
        for (_, sql) in crate::pg::MIGRATIONS {
            let v = check_sql(sql);
            assert!(v.is_empty(), "{v:?}");
        }
    }

    #[test]
    fn lint_catches_violations() {
        assert!(l2_violation("client_ip"));
        assert!(l2_violation("user_agent"));
        assert!(l2_violation("x_forwarded_for"));
        assert!(!l2_violation("epoch_index"));
        assert!(!l2_violation("relay_req_counter"));
        assert!(l11_violation("envelope", "kind"));
        assert!(!l11_violation("deletion_list", "kind"));
        assert!(l11_violation("source_account", "last_seen"));
        assert!(l11_violation("reply", "fetched"));
        let bad = "CREATE TABLE candor.reply (\n  reply_ref uuid,\n  fetched_at timestamptz\n);";
        let v = check_sql(bad);
        assert!(v.iter().any(|m| m.contains("timestamp")), "{v:?}");
        assert!(v.iter().any(|m| m.contains("fetched_at")), "{v:?}");
        let draft = "CREATE TABLE candor.draft_part (\n  x bytea\n);";
        assert!(check_sql(draft).iter().any(|m| m.contains("L13")));
        let rows = vec![(
            "envelope".to_string(),
            "client_addr".to_string(),
            "inet".to_string(),
            Some("now()".to_string()),
        )];
        let v = check_columns(&rows);
        assert!(v.iter().any(|m| m.starts_with("L1/L3")));
        assert!(v.iter().any(|m| m.starts_with("L2")));
        assert!(v.iter().any(|m| m.starts_with("L4")));
    }
}
