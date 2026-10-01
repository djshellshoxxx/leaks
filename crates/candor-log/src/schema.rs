// SPDX-License-Identifier: AGPL-3.0-or-later
//! Audit schema registry (20 §7, LOG-014).
//!
//! `audit/schema.yaml` (in this crate) is the reviewed registry of every
//! catalog event: type name, class, stream, timestamp policy and the
//! allow-listed payload fields with their types and closed code sets. It is
//! rendered deterministically from [`crate::event::SCHEMA`] by
//! [`registry_yaml`], and `tests/schema_registry.rs` fails on any drift in
//! either direction, so the registry and the compiled enum cannot diverge
//! (see SPEC-NOTES "Implementation decision: schema registry").

use crate::event::{EventClass, SCHEMA, TimePolicy};

/// Schema of one catalog event type.
#[derive(Debug, Clone, Copy)]
pub struct EventSchema {
    /// Canonical type name (20 §5).
    pub name: &'static str,
    /// Event class.
    pub class: EventClass,
    /// Timestamp derivation policy.
    pub time_policy: TimePolicy,
    /// Allow-listed payload fields, in payload order.
    pub fields: &'static [FieldSchema],
}

/// Schema of one payload field.
#[derive(Debug, Clone, Copy)]
pub struct FieldSchema {
    /// Payload key.
    pub name: &'static str,
    /// Rust field type as written in the catalog.
    pub rust_type: &'static str,
    /// Closed code set (empty when the type is not an enumerated code).
    pub codes: fn() -> &'static [&'static str],
}

/// Registry format version.
pub const REGISTRY_VERSION: u32 = 1;

const HEADER: &str = "\
# SPDX-License-Identifier: AGPL-3.0-or-later
# Candor audit schema registry (specs/20-LOGGING-AUDITING.md §5, §7; LOG-014).
# Changes to this file require the `audit-schema` review label and two
# code-owner approvals (27). It must equal candor_log::schema::registry_yaml();
# crates/candor-log/tests/schema_registry.rs fails on any drift.
";

fn class_name(c: EventClass) -> &'static str {
    match c {
        EventClass::Security => "SECURITY",
        EventClass::Case => "CASE",
        EventClass::System => "SYSTEM",
    }
}

fn time_policy_name(t: TimePolicy) -> &'static str {
    match t {
        TimePolicy::Staff => "staff",
        TimePolicy::DateOnly => "date_only",
        TimePolicy::System => "system",
    }
}

/// YAML double-quoted scalar. Inputs are compile-time catalog constants;
/// escaping is still complete for `"`, `\` and control characters.
fn quoted(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04X}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Normalizes `stringify!` spacing of a type (`Option < X >` → `Option<X>`).
fn type_text(t: &str) -> String {
    t.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Renders the registry from the compiled catalog.
pub fn registry_yaml() -> String {
    let mut o = String::with_capacity(64 * 1024);
    o.push_str(HEADER);
    o.push_str(&format!("version: {REGISTRY_VERSION}\nevents:\n"));
    for e in SCHEMA {
        o.push_str("  - type: ");
        quoted(&mut o, e.name);
        o.push_str("\n    class: ");
        o.push_str(class_name(e.class));
        o.push_str("\n    stream: ");
        o.push_str(e.class.stream().code());
        o.push_str("\n    ts: ");
        o.push_str(time_policy_name(e.time_policy));
        if e.fields.is_empty() {
            o.push_str("\n    fields: []\n");
            continue;
        }
        o.push_str("\n    fields:\n");
        for f in e.fields {
            o.push_str("      - name: ");
            quoted(&mut o, f.name);
            o.push_str("\n        type: ");
            quoted(&mut o, &type_text(f.rust_type));
            let codes = (f.codes)();
            if !codes.is_empty() {
                o.push_str("\n        codes: [");
                for (i, c) in codes.iter().enumerate() {
                    if i > 0 {
                        o.push_str(", ");
                    }
                    quoted(&mut o, c);
                }
                o.push(']');
            }
            o.push('\n');
        }
    }
    o
}
