// SPDX-License-Identifier: AGPL-3.0-or-later
//! Source-level gates for this crate (BUILD-BRIEF "Security and OPSEC bar";
//! 07 BE-031 time-lint; R7 SI-E-05 no dynamic SQL; ADR-016 no ad-hoc logging).
#![allow(clippy::unwrap_used, clippy::panic)]

/// Every source file of the crate, embedded at compile time (the workspace
/// clippy configuration bans direct filesystem reads, ADR-027). A new file in
/// `src/` must be added here; `every_module_is_listed` checks `lib.rs`.
const SOURCES: &[(&str, &str)] = &[
    ("deaddrop.rs", include_str!("../src/deaddrop.rs")),
    ("deletion.rs", include_str!("../src/deletion.rs")),
    ("error.rs", include_str!("../src/error.rs")),
    ("lib.rs", include_str!("../src/lib.rs")),
    ("lint.rs", include_str!("../src/lint.rs")),
    ("memory.rs", include_str!("../src/memory.rs")),
    ("pg.rs", include_str!("../src/pg.rs")),
    ("rng.rs", include_str!("../src/rng.rs")),
    ("store.rs", include_str!("../src/store.rs")),
    ("types.rs", include_str!("../src/types.rs")),
    ("validate.rs", include_str!("../src/validate.rs")),
];

fn sources() -> Vec<(String, String)> {
    SOURCES
        .iter()
        .map(|(p, s)| ((*p).to_string(), (*s).to_string()))
        .collect()
}

/// Every `mod` declared in lib.rs is in [`SOURCES`].
#[test]
fn every_module_is_listed() {
    let lib = include_str!("../src/lib.rs");
    for line in lib.lines() {
        let l = line.trim();
        let Some(rest) = l
            .strip_prefix("pub mod ")
            .or_else(|| l.strip_prefix("mod "))
        else {
            continue;
        };
        let name = format!("{}.rs", rest.trim_end_matches(';'));
        assert!(SOURCES.iter().any(|(p, _)| *p == name), "{name} not listed");
    }
}

/// Strip `#[cfg(test)]` modules (tests may print diagnostics).
fn non_test(src: &str) -> &str {
    src.split("#[cfg(test)]").next().unwrap_or(src)
}

#[test]
fn every_source_file_has_spdx_header() {
    for (p, s) in sources() {
        assert!(
            s.starts_with("// SPDX-License-Identifier: AGPL-3.0-or-later"),
            "{p}"
        );
    }
    let sql = include_str!("../migrations/0001_intake_schema.sql");
    assert!(sql.starts_with("-- SPDX-License-Identifier: AGPL-3.0-or-later"));
}

/// No wall clock finer than a day may be read by the store (it reads none).
#[test]
fn no_wall_clock_access() {
    for (p, s) in sources() {
        for banned in [
            "SystemTime",
            "Instant::now",
            "chrono::",
            "Utc::now",
            "time::OffsetDateTime",
            "now()",
        ] {
            // lint.rs names these functions as patterns it rejects.
            if p.ends_with("lint.rs") && banned == "now()" {
                continue;
            }
            assert!(!non_test(&s).contains(banned), "{p} uses {banned}");
        }
    }
}

/// No dynamic SQL: sqlx 0.9 accepts only `SqlSafeStr`; this crate never opts
/// out with `AssertSqlSafe`, and never builds query text with `format!`.
#[test]
fn no_dynamic_sql() {
    for (p, s) in sources() {
        let s = non_test(&s);
        assert!(!s.contains("AssertSqlSafe"), "{p}");
        assert!(!s.contains("QueryBuilder"), "{p}");
        if p.ends_with("pg.rs") {
            assert!(!s.contains("format!"), "{p} must not format strings");
        }
    }
}

/// No ad-hoc output or logging (typed candor-log events belong to the daemon).
#[test]
fn no_ad_hoc_output() {
    for (p, s) in sources() {
        let s = non_test(&s);
        for banned in [
            "println!",
            "eprintln!",
            "print!(",
            "eprint!(",
            "dbg!",
            "tracing::",
            "log::",
            "std::io::stderr",
            "std::io::stdout",
        ] {
            assert!(!s.contains(banned), "{p} uses {banned}");
        }
    }
}

/// Every connection disables sqlx statement logging.
#[test]
fn statement_logging_disabled() {
    let pg = include_str!("../src/pg.rs");
    assert_eq!(
        pg.matches("connect_with(").count(),
        pg.matches("disable_statement_logging()").count()
    );
}
