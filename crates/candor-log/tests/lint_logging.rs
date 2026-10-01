// SPDX-License-Identifier: AGPL-3.0-or-later
//! Self-test of scripts/lint-logging.sh against a fixture workspace (LOG-001).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(
    clippy::disallowed_methods,
    reason = "test fixture: builds a throw-away workspace under the temp dir"
)]

use std::path::PathBuf;
use std::process::Command;

fn fixture(name: &str, src: &str, allow: Option<&str>) -> (PathBuf, std::process::Output) {
    fixture_with(name, src, "[package]\nname = \"x\"\n", allow)
}

fn fixture_with(
    name: &str,
    src: &str,
    manifest_text: &str,
    allow: Option<&str>,
) -> (PathBuf, std::process::Output) {
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
    f::write(&manifest, manifest_text).unwrap();
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
        // AUD-RM1-LOG-09 regression fixtures (each passed the old script):
        "pub fn f(ip: &str) { let _u = \"//\"; println!(\"{ip}\"); }",
        "pub fn f(ip: &str) { lg::log!(Level::Warn, \"{}\", ip); }",
        "use std::io::Write;\npub fn f(ip: &str) { let _ = writeln!(std::io::stderr(), \"{ip}\"); }",
        "pub fn f(ip: &str) { panic!(\"bad peer {ip}\"); }",
        "pub fn f() { let s = r#\"//\"#; eprintln!(\"{s}\"); }",
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

#[test]
fn flags_logging_dependencies_in_any_form() {
    // AUD-RM1-LOG-09: table form and renamed dependencies.
    for (i, m) in [
        "[package]\nname = \"x\"\n[dependencies.log]\nversion = \"0.4\"\n",
        "[package]\nname = \"x\"\n[dependencies]\nlg = { package = \"log\", version = \"0.4\" }\n",
        "[package]\nname = \"x\"\n[target.'cfg(unix)'.dependencies.tracing]\nversion = \"0.1\"\n",
    ]
    .iter()
    .enumerate()
    {
        let (root, out) = fixture_with(&format!("dep{i}"), "pub fn f() {}", m, None);
        assert_eq!(out.status.code(), Some(1), "{m}");
        let _ = std::fs::remove_dir_all(root); // safefs-lint: allow(test fixture)
    }
}

#[test]
fn comments_and_strings_do_not_hide_or_trigger() {
    for (i, src) in [
        "/* println!(\"x\") */\npub fn f() {}",
        "pub fn f() -> &'static str { \"println!(x) // not code\" }",
        "//! eprintln! in docs\npub fn f() {}",
    ]
    .iter()
    .enumerate()
    {
        let (root, out) = fixture(&format!("okc{i}"), src, None);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{src}\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
        let _ = std::fs::remove_dir_all(root); // safefs-lint: allow(test fixture)
    }
}
