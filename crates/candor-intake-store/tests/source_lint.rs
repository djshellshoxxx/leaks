// SPDX-License-Identifier: AGPL-3.0-or-later
//! Source-level gates for this crate (BUILD-BRIEF "Security and OPSEC bar";
//! 07 BE-031 time-lint; R7 SI-E-05 no dynamic SQL; ADR-016 no ad-hoc logging).
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::Path;

fn sources() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut v = Vec::new();
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "rs") {
            v.push((p.display().to_string(), fs::read_to_string(&p).unwrap()));
        }
    }
    assert!(v.len() >= 8);
    v
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
    let sql = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations/0001_intake_schema.sql"),
    )
    .unwrap();
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
    let pg = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/pg.rs")).unwrap();
    assert_eq!(
        pg.matches("connect_with(").count(),
        pg.matches("disable_statement_logging()").count()
    );
}
