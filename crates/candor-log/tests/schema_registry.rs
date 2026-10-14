// SPDX-License-Identifier: AGPL-3.0-or-later
//! LOG-014: `audit/schema.yaml` is the reviewed schema registry; any drift
//! between it and the compiled `AuditEvent` catalog fails CI.
//!
//! To update after an approved catalog change (`audit-schema` label, two
//! code owners): run this test, review the expected file it writes under
//! the cargo test tmpdir (path in the failure message) and copy it over
//! `audit/schema.yaml` in the same PR.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use candor_log::event::{AuditEvent, CATALOG, SCHEMA};
use candor_log::schema::registry_yaml;

const COMMITTED: &str = include_str!("../audit/schema.yaml");

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "test fixture: writes the expected registry under cargo's test tmpdir"
)]
fn registry_matches_catalog() {
    let expected = registry_yaml();
    if expected == COMMITTED {
        return;
    }
    let line = expected
        .lines()
        .zip(COMMITTED.lines())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| expected.lines().count().min(COMMITTED.lines().count()));
    let out = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("audit-schema.expected.yaml");
    std::fs::write(&out, &expected).expect("write expected registry"); // safefs-lint: allow(test fixture)
    panic!(
        "audit/schema.yaml drifted from the AuditEvent catalog at line {} (LOG-014). \
         Expected registry written to {}",
        line + 1,
        out.display()
    );
}

#[test]
fn schema_agrees_with_catalog_and_samples() {
    assert_eq!(SCHEMA.len(), CATALOG.len());
    let samples = AuditEvent::samples();
    assert_eq!(samples.len(), SCHEMA.len());
    let mut names = BTreeSet::new();
    for ((s, (n, c)), ev) in SCHEMA.iter().zip(CATALOG).zip(&samples) {
        assert_eq!(s.name, *n);
        assert_eq!(s.class, *c);
        assert_eq!(ev.type_name(), s.name);
        let f: Vec<_> = s.fields.iter().map(|f| f.name).collect();
        assert_eq!(ev.field_names(), f.as_slice());
        assert!(names.insert(s.name), "duplicate type {}", s.name);
    }
}

/// LOG-020 / ADR-037(3): no COI codes anywhere in the registry; LOG-001:
/// no free-text or source-metadata field types.
#[test]
fn registry_forbids_coi_codes_and_free_text_types() {
    for e in SCHEMA {
        for f in e.fields {
            for code in (f.codes)() {
                assert!(
                    !code.contains("COI"),
                    "{}.{} carries a COI code",
                    e.name,
                    f.name
                );
            }
            let t: String = f.rust_type.chars().filter(|c| !c.is_whitespace()).collect();
            const BANNED: [&str; 11] = [
                "String",
                "str",
                "OsString",
                "IpAddr",
                "Ipv4Addr",
                "Ipv6Addr",
                "SocketAddr",
                "PathBuf",
                "Path",
                "SystemTime",
                "Instant",
            ];
            let free_text = t
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|seg| BANNED.contains(&seg));
            assert!(
                !free_text && !t.contains("Vec<u8>"),
                "{}.{} has banned type {t}",
                e.name,
                f.name
            );
        }
    }
}

/// The committed registry is well-formed: every event appears once and in
/// catalog order (guards against hand edits that reorder entries).
#[test]
fn committed_registry_lists_catalog_in_order() {
    let types: Vec<&str> = COMMITTED
        .lines()
        .filter_map(|l| l.strip_prefix("  - type: \""))
        .filter_map(|l| l.strip_suffix('"'))
        .collect();
    let catalog: Vec<&str> = CATALOG.iter().map(|(n, _)| *n).collect();
    assert_eq!(types, catalog);
}
