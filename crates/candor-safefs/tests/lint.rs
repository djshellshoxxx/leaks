// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Tests for `scripts/lint-safefs.sh` (ST-005, SDL-030) on fixture
//! workspaces.
#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "test fixtures build hostile trees and archives directly"
)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::Command;

fn script() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/lint-safefs.sh")
}

fn ws(files: &[(&str, &str)]) -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    for (p, c) in files {
        let full = d.path().join(p);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, c).unwrap();
    }
    d
}

#[test]
fn audit_bypasses_are_caught() {
    // AUD-RM1-SFS-01 regression fixtures (each passed the old script).
    for bad in [
        "extern crate std as s;\nfn f() { let _ = s::fs::write(\"x\", b\"\"); }\n",
        "fn f(v: &mut Vec<u8>) {\n    *v = s::fs::read(p).unwrap_or_default();\n}\n",
        "fn f() { let _ = rustix::fs::openat(d, \"x\", f, m); }\n",
        "fn f() { unsafe { libc::open(p, 0) }; }\n",
        "fn f() { let _ = nix::fcntl::open(p, f, m); }\n",
        "#[allow(clippy::disallowed_methods)]\nfn f() {}\n",
    ] {
        let d = ws(&[("crates/a/src/lib.rs", bad)]);
        let (code, out) = run(d.path(), &[]);
        assert_eq!(code, 1, "not caught: {bad}\n{out}");
    }
    for manifest in [
        "[package]\nname = \"a\"\n[dependencies.tar]\nversion = \"0.4\"\n",
        "[package]\nname = \"a\"\n[dependencies]\narc = { package = \"zip\", version = \"4\" }\n",
        "[package]\nname = \"a\"\n[target.'cfg(unix)'.dev-dependencies.zip]\nversion = \"4\"\n",
    ] {
        let d = ws(&[
            ("crates/a/Cargo.toml", manifest),
            ("crates/a/src/lib.rs", ""),
        ]);
        assert_eq!(run(d.path(), &[]).0, 1, "not caught: {manifest}");
    }
    // A crate-local clippy.toml would replace the workspace bans.
    let d = ws(&[
        ("crates/a/clippy.toml", "msrv = \"1.94\"\n"),
        ("crates/a/src/lib.rs", ""),
    ]);
    assert_eq!(run(d.path(), &[]).0, 1);
}

#[test]
fn renamed_dependency_resolved_through_cargo_metadata() {
    // A quoted key escapes the regex layer; cargo metadata resolves it.
    let d = ws(&[
        (
            "Cargo.toml",
            "[workspace]\nresolver = \"3\"\nmembers = [\"crates/*\"]\n",
        ),
        (
            "crates/a/Cargo.toml",
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\n\"tar\" = \"0.4\"\n",
        ),
        ("crates/a/src/lib.rs", ""),
    ]);
    let (code, out) = run(d.path(), &[]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("cargo metadata"), "{out}");
    // A broken workspace manifest fails closed (status 2), never "OK".
    let d = ws(&[
        ("Cargo.toml", "[workspace]\nmembers = [\n"),
        ("crates/a/src/lib.rs", ""),
    ]);
    assert_eq!(run(d.path(), &[]).0, 2);
}

fn run(root: &Path, extra: &[&str]) -> (i32, String) {
    let out = Command::new("bash")
        .arg(script())
        .args(extra)
        .arg(root)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn clean_workspace_passes() {
    let d = ws(&[
        (
            "crates/a/Cargo.toml",
            "[package]\nname = \"a\"\n[dependencies]\nserde = \"1\"\n",
        ),
        (
            "crates/a/src/lib.rs",
            "// std::fs mentioned in a comment only\nfn f(v: &[String]) -> String { v.join(\",\") }\n",
        ),
        // candor-safefs itself is exempt.
        (
            "crates/candor-safefs/Cargo.toml",
            "[dependencies]\ntar = \"=0.4.46\"\n",
        ),
        ("crates/candor-safefs/src/lib.rs", "use std::fs::File;\n"),
    ]);
    let (code, out) = run(d.path(), &[]);
    assert_eq!(code, 0, "{out}");
}

#[test]
fn violations_fail() {
    for bad in [
        "use std::fs;\n",
        "fn f() { let _ = std::fs::write(\"x\", b\"\"); }\n",
        "use std::{io, fs};\n",
        "fn f(base: &std::path::Path, n: &str) { let _ = base.join(n); }\n",
        "fn f(p: &mut PathBuf) { dest_dir.push(name); }\n",
        "fn f() { tar::Archive::new(r).unpack(dst); }\n",
        "fn f() { let a = ZipArchive::new(r); a.extract(d); }\n",
        "fn f() { tokio::fs::write(p, b).await; }\n",
    ] {
        let d = ws(&[("crates/a/src/lib.rs", bad)]);
        let (code, out) = run(d.path(), &[]);
        assert_eq!(code, 1, "not caught: {bad}\n{out}");
    }
    let d = ws(&[
        ("crates/a/Cargo.toml", "[dependencies]\nzip = \"4\"\n"),
        ("crates/a/src/lib.rs", ""),
    ]);
    assert_eq!(run(d.path(), &[]).0, 1);
}

#[test]
fn allow_marker_and_tests_scope() {
    let d = ws(&[
        (
            "crates/a/src/lib.rs",
            "use std::fs; // safefs-lint: allow(reads static config shipped in package)\n",
        ),
        ("crates/a/tests/t.rs", "use std::fs;\n"),
    ]);
    assert_eq!(run(d.path(), &[]).0, 0);
    assert_eq!(run(d.path(), &["--include-tests"]).0, 1);
    // An empty reason does not exempt.
    let d = ws(&[(
        "crates/a/src/lib.rs",
        "use std::fs; // safefs-lint: allow()\n",
    )]);
    assert_eq!(run(d.path(), &[]).0, 1);
}
