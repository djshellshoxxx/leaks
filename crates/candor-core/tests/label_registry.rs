// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CRYPTO-012 / CI job `label-registry`: every `candor/...` literal in this crate's
//! sources must live in `src/labels.rs`; registry values are unique.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use candor_core::labels::REGISTRY;
use std::collections::HashSet;

#[test]
fn registry_unique() {
    let mut seen = HashSet::new();
    for l in REGISTRY {
        assert!(seen.insert(l.value), "duplicate label {}", l.name);
    }
}

#[test]
fn no_unregistered_literals_in_sources() {
    let src = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    let mut stack = vec![std::path::PathBuf::from(src)];
    let mut checked = 0;
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d).expect("read_dir"); // safefs-lint: allow(test-only scan of own sources, CRYPTO-012)
        for e in entries {
            let p = e.expect("entry").path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if p.extension().and_then(|x| x.to_str()) != Some("rs") || p.ends_with("labels.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&p).expect("read"); // safefs-lint: allow(test-only scan of own sources, CRYPTO-012)
            checked += 1;
            for (n, line) in text.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                assert!(
                    !code.contains("\"candor/"),
                    "unregistered label literal in {}:{}",
                    p.display(),
                    n + 1
                );
            }
        }
    }
    assert!(checked > 10, "scanned {checked} files");
}

/// AUD-RM1-CORE-10 / IMPL-RM1 §4 A5 (CRYPTO-012): the registry is unique but not
/// prefix-free (04 §10 itself defines labels that prefix others). Injectivity of the
/// full inputs is argued per pair that shares a use (same primitive position):
///
/// * every suffix appended to a label is fixed-width at every use site, so two inputs
///   built from labels `A` (a proper prefix of `B`) can only collide if they have the
///   same total length; and
/// * for every such pair the total lengths differ, *and* the byte of `B` that follows
///   `A` is outside the set of possible first suffix bytes of `A`.
///
/// Pairs whose shared uses are disjoint (salt vs info vs hash domain) are injective by
/// position. Any new prefix pair that shares a use and is not in the table below fails
/// this test until its argument is recorded here and in SPEC-NOTES.
#[test]
fn prefix_pairs_are_injective() {
    use candor_core::labels::LabelUse;
    // (name, suffix length after the label, inclusive range of the suffix's first byte)
    // for the shared uses. A suffix length of 0 means the label is the whole input.
    let suffix = |name: &str, u: LabelUse| -> Option<(usize, (u8, u8))> {
        match (name, u) {
            // HKDF info `label ‖ u8 i`, i = slot position 0..15 (§13.2).
            ("DUMMY_SLOT" | "DUMMY_SLOT_PT", LabelUse::HkdfInfo) => Some((1, (0x00, 0x0F))),
            // HKDF info: the label alone (§10 table, salt = device_id).
            ("DESK_KEYSTORE" | "DESK_KEYSTORE_SLOT", LabelUse::HkdfInfo) => Some((0, (0, 0))),
            // AAD `label ‖ user_id ‖ device_id ‖ key_id` (64) / `… ‖ u8 i` (33) (§9.9).
            ("DESK_KEYSTORE", LabelUse::Aad) => Some((64, (0x00, 0xFF))),
            ("DESK_KEYSTORE_SLOT", LabelUse::Aad) => Some((33, (0x00, 0xFF))),
            // HPKE info `label ‖ u16 suite ‖ tenant` / `… ‖ recipient_key_id` (§9.9).
            ("WRAP_CUSTODIAN", LabelUse::HpkeInfo) => Some((18, (0x00, 0x00))),
            ("WRAP_CUSTODIAN_GROUP", LabelUse::HpkeInfo) => Some((50, (0x00, 0x00))),
            _ => None,
        }
    };
    // Suite ids are < 0x0100, so the suite's first byte is 0x00.
    for s in [candor_core::Suite::CandorStd1, candor_core::Suite::CandorFips1] {
        assert_eq!(s.to_be_bytes()[0], 0x00);
    }
    let mut pairs = 0;
    for a in REGISTRY {
        for b in REGISTRY {
            if a.value.len() >= b.value.len() || !b.value.starts_with(a.value) {
                continue;
            }
            for u in a.uses.iter().filter(|u| b.uses.contains(u)) {
                pairs += 1;
                let (la, (lo, hi)) = suffix(a.name, *u).unwrap_or_else(|| {
                    panic!("prefix pair {} < {} ({u:?}) needs an injectivity argument", a.name, b.name)
                });
                let (lb, _) = suffix(b.name, *u).unwrap_or_else(|| {
                    panic!("prefix pair {} < {} ({u:?}) needs an injectivity argument", a.name, b.name)
                });
                assert_ne!(
                    a.value.len() + la,
                    b.value.len() + lb,
                    "{} / {}: equal total lengths",
                    a.name,
                    b.name
                );
                let next = b.value[a.value.len()];
                // Where A's suffix cannot start with every byte value, the byte of B
                // after A must also be impossible there (second, independent argument).
                if la > 0 && (lo, hi) != (0x00, 0xFF) {
                    assert!(
                        !(lo..=hi).contains(&next),
                        "{} / {}: suffix byte collides",
                        a.name,
                        b.name
                    );
                }
            }
        }
    }
    assert_eq!(pairs, 4, "shared-use prefix pairs changed; update the argument");
}
