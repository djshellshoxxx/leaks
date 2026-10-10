// SPDX-License-Identifier: AGPL-3.0-or-later

const MIGRATION: &str = include_str!("../migrations/0001_core.sql");

#[test]
fn every_core_table_has_forced_rls_and_tenant_policy() {
    for table in ["core.import_envelope", "core.case_record"] {
        assert!(MIGRATION.contains(&format!("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")));
        assert!(MIGRATION.contains(&format!("ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")));
    }
    assert!(
        MIGRATION.contains(
            "USING (tenant_id = candor.tenant()) WITH CHECK (tenant_id = candor.tenant())"
        )
    );
    assert!(!MIGRATION.to_ascii_uppercase().contains("BYPASSRLS"));
}

#[test]
fn source_linked_import_metadata_is_day_granularity_only() {
    let lower = MIGRATION.to_ascii_lowercase();
    assert!(lower.contains("import_day date not null"));
    assert!(!lower.contains("timestamp"));
    assert!(!lower.contains("inet"));
    assert!(!lower.contains("user_agent"));
    assert!(!lower.contains("ip_address"));
}

#[test]
fn import_deduplication_is_tenant_scoped() {
    assert!(MIGRATION.contains("UNIQUE (tenant_id, header_digest)"));
    assert!(MIGRATION.contains("CHECK (octet_length(header_digest) = 32)"));
}
