// SPDX-License-Identifier: AGPL-3.0-or-later
//! Self-test of scripts/lint-logging.sh against a fixture workspace (LOG-001).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::Command;

fn fixture(name: &str, src: &str, allow: Option<&str>) -> (PathBuf, std::process::Output) {
    // Test-only fixture workspace for the lint self-test; not trust-path code.
    use std::fs as f; // safefs-lint: allow(test fixture)
    let tmp = std::env::temp_dir();
    let root = tmp.join(format!("candor-lint-{name}-{}", std::process::id())); // safefs-lint: allow(test fixture)
    let src_dir = root.join("crates/x/src"); // safefs-lint: allow(test fixture)
    let manifest = root.join("crates/x/Cargo.toml"); // safefs-lint: allow(test fixture)
    let lib = src_dir.join("lib.rs"); // safefs-lint: allow(test fixture)
    let script_dir = root.join("tools"); // safefs-lint: allow(test fixture)
    let script = script_dir.join("lint-logging.sh"); // safefs-lint: allow(test fixture)
    let allow_path = script_dir.join("lint-logging.allow"); // safefs-lint: allow(test fixture)
    let orig = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/lint-logging.sh");
    let _ = f::remove_dir_all(&root);
    f::create_dir_all(&src_dir).unwrap();
    f::create_dir_all(&script_dir).unwrap();
    f::write(&manifest, "[package]\nname = \"x\"\n").unwrap();
    f::write(&lib, src).unwrap();
    // Copy the script so that its allow file can be replaced.
    f::copy(orig, &script).unwrap();
    if let Some(a) = allow {
        f::write(&allow_path, a).unwrap();
    }
    let out = Command::new("bash")
        .arg(&script)
        .arg(&root)
        .output()
        .unwrap();
    (root, out)
}

#[test]
fn flags_free_text_logging() {
    for (i, src) in [
        "pub fn f(ip: &str) { println!(\"client {}\", ip); }",
        "pub fn f() { eprintln!(\"x\"); }",
        "pub fn f() { dbg!(1); }",
        "pub fn f() { log::info!(\"x\"); }",
        "pub fn f() { tracing::debug!(\"x\"); }",
        "use tracing::info;\npub fn f() { info!(\"x\"); }",
    ]
    .iter()
    .enumerate()
    {
        let (root, out) = fixture(&format!("bad{i}"), src, None);
        assert_eq!(out.status.code(), Some(1), "{src}");
        let _ = std::fs::remove_dir_all(root); // safefs-lint: allow(test fixture)
    }
}

#[test]
fn clean_and_allow_listed_pass() {
    let (root, out) = fixture(
        "ok",
        "/// mentions println! in a comment\npub fn f() {}",
        None,
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let _ = std::fs::remove_dir_all(root); // safefs-lint: allow(test fixture)
    let (root, out) = fixture(
        "allowed",
        "pub fn f() { println!(\"x\"); }",
        Some("crates/x/src/lib.rs  non-trust-path dev tool\n"),
    );
    assert_eq!(out.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(root); // safefs-lint: allow(test fixture)
    // An exception without a reason is a usage error.
    let (root, out) = fixture("noreason", "pub fn f() {}", Some("crates/x/src/lib.rs\n"));
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(root); // safefs-lint: allow(test fixture)
}
