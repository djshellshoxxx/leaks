// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Tests for `scripts/lint-safefs.sh` (ST-005, SDL-030) on fixture
//! workspaces.
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
