// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CRYPTO-012 / CI job `label-registry`: every `candor/...` literal in this crate's
//! sources must live in `src/labels.rs`; registry values are unique.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::arithmetic_side_effects)]

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
        for e in std::fs::read_dir(&d).expect("read_dir") { // safefs-lint: allow(test-only scan of own sources, CRYPTO-012)
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
                assert!(!code.contains("\"candor/"), "unregistered label literal in {}:{}", p.display(), n + 1);
            }
        }
    }
    assert!(checked > 10, "scanned {checked} files");
}
