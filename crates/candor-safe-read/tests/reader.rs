// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Unit tests of the reader's refusal rules (AUD-RM2-DEP-24/26): symlinked components, FIFO
//! (no block), device, directory, owner, mode, link count, size cap, missing, MD5 KAT.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::disallowed_methods,
    reason = "test fixtures in a tempdir"
)]

use candor_safe_read::{
    Policy, Status, copy, md5_line, private_dir, read_checked, write_md5_report,
};
use rustix::fs::{CWD, FileType, Mode};

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::time::{Duration, Instant};

fn policy_for(p: &std::path::Path, max: u64) -> Policy {
    Policy {
        max_bytes: max,
        owners: vec![std::fs::metadata(p).unwrap().uid()],
        deny_mode: 0o002,
    }
}
fn dirfd(p: &std::path::Path) -> std::os::fd::OwnedFd {
    rustix::fs::openat(
        CWD,
        p,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY,
        Mode::empty(),
    )
    .unwrap()
}
fn s(p: &std::path::Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn copies_regular_file() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("f");
    std::fs::write(&f, b"abc").unwrap();
    let out = d.path().join("out");
    copy(s(&f), dirfd(d.path()), "out", &policy_for(&f, 16)).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), b"abc");
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn refuses_symlinks_and_dotdot() {
    let d = tempfile::tempdir().unwrap();
    let real = d.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let f = real.join("f");
    std::fs::write(&f, b"x").unwrap();
    std::os::unix::fs::symlink(&real, d.path().join("link")).unwrap();
    std::os::unix::fs::symlink(&f, real.join("l")).unwrap();
    let p = policy_for(&f, 16);
    assert_eq!(
        read_checked(s(&d.path().join("link/f")), &p),
        Err(Status::Link)
    );
    assert_eq!(read_checked(s(&real.join("l")), &p), Err(Status::Link));
    assert_eq!(
        read_checked(&format!("{}/../real/f", s(&real)), &p),
        Err(Status::Link)
    );
    assert_eq!(read_checked("relative/f", &p), Err(Status::Usage));
}

#[test]
fn refuses_fifo_without_blocking_device_and_directory() {
    let d = tempfile::tempdir().unwrap();
    let fifo = d.path().join("fifo");
    rustix::fs::mknodat(CWD, &fifo, FileType::Fifo, Mode::from_raw_mode(0o600), 0).unwrap();
    let p = policy_for(d.path(), 16);
    let t = Instant::now();
    assert_eq!(read_checked(s(&fifo), &p), Err(Status::NotRegular));
    assert!(t.elapsed() < Duration::from_secs(5));
    let any = Policy {
        owners: vec![0, p.owners.first().copied().unwrap()],
        ..p
    };
    assert_eq!(read_checked("/dev/null", &any), Err(Status::NotRegular));
    assert_eq!(read_checked(s(d.path()), &any), Err(Status::NotRegular));
}

#[test]
fn enforces_owner_mode_links_size() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("f");
    std::fs::write(&f, b"12345").unwrap();
    let p = policy_for(&f, 16);
    let other = Policy {
        owners: vec![p.owners.first().copied().unwrap().wrapping_add(4242)],
        ..p.clone()
    };
    assert_eq!(read_checked(s(&f), &other), Err(Status::Policy));
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o646)).unwrap();
    assert_eq!(read_checked(s(&f), &p), Err(Status::Policy));
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::hard_link(&f, d.path().join("h")).unwrap();
    assert_eq!(read_checked(s(&f), &p), Err(Status::Policy));
    std::fs::remove_file(d.path().join("h")).unwrap();
    assert_eq!(
        read_checked(
            s(&f),
            &Policy {
                max_bytes: 4,
                ..p.clone()
            }
        ),
        Err(Status::TooLarge)
    );
    assert_eq!(
        read_checked(s(&d.path().join("nope")), &p),
        Err(Status::Missing)
    );
    assert_eq!(read_checked(s(&f), &p), Ok(b"12345".to_vec()));
}

#[test]
fn refused_copy_creates_no_output() {
    let d = tempfile::tempdir().unwrap();
    let out = d.path().join("out");
    let p = policy_for(d.path(), 16);
    assert_eq!(
        copy(s(&d.path().join("nope")), dirfd(d.path()), "out", &p),
        Err(Status::Missing)
    );
    assert!(!out.exists());
}

#[test]
fn md5_known_answer_and_errors() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("f");
    std::fs::write(&f, b"abc").unwrap();
    let p = policy_for(&f, 16);
    assert_eq!(md5_line(s(&f), &p), "OK 900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(md5_line(s(&d.path().join("nope")), &p), "ERR 11");
    let out = d.path().join("report");
    let paths = vec![s(&f).to_string(), s(&d.path().join("nope")).to_string()];
    write_md5_report(dirfd(d.path()), "report", &paths, &p).unwrap();
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        "OK 900150983cd24fb0d6963f7d28e17f72\nERR 11\n"
    );
}

#[test]
fn policy_parsing() {
    assert!(Policy::parse("10", "0,1000", "022").is_ok());
    assert_eq!(Policy::parse("x", "0", "022").err(), Some(Status::Usage));
    assert_eq!(Policy::parse("10", "", "022").err(), Some(Status::Usage));
    assert_eq!(Policy::parse("10", "0", "9").err(), Some(Status::Usage));
    assert_eq!(Policy::parse("10", "0,a", "022").err(), Some(Status::Usage));
}

/// AUD-RM2-DEP-30: OUT is created new beneath the work-dir fd; an existing file, symlink or
/// FIFO there, an escaping name and a non-private directory are all refused without blocking.
#[test]
fn output_is_exclusive_beneath_a_private_dir() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("f");
    std::fs::write(&f, b"abc").unwrap();
    let p = policy_for(&f, 16);
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(private_dir(dirfd(d.path())).err(), Some(Status::Io));
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let dir = private_dir(dirfd(d.path())).unwrap();
    std::fs::write(d.path().join("exists"), b"keep").unwrap();
    assert_eq!(copy(s(&f), &dir, "exists", &p), Err(Status::Io));
    assert_eq!(std::fs::read(d.path().join("exists")).unwrap(), b"keep");
    let victim = d.path().join("victim");
    std::os::unix::fs::symlink(&victim, d.path().join("sl")).unwrap();
    assert_eq!(copy(s(&f), &dir, "sl", &p), Err(Status::Io));
    assert!(!victim.exists());
    std::fs::create_dir(d.path().join("sub")).unwrap();
    std::os::unix::fs::symlink(d.path().join("sub"), d.path().join("sdir")).unwrap();
    assert_eq!(copy(s(&f), &dir, "sdir/x", &p), Err(Status::Io));
    rustix::fs::mknodat(
        CWD,
        d.path().join("fifo"),
        FileType::Fifo,
        Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    let t = Instant::now();
    assert_eq!(copy(s(&f), &dir, "fifo", &p), Err(Status::Io));
    assert!(t.elapsed() < Duration::from_secs(5));
    for bad in ["/abs", "../x", "a/../b", "./x", "", "a//b"] {
        assert_eq!(copy(s(&f), &dir, bad, &p), Err(Status::Usage), "{bad}");
    }
    copy(s(&f), &dir, "sub/x", &p).unwrap();
    assert_eq!(std::fs::read(d.path().join("sub/x")).unwrap(), b"abc");
}
