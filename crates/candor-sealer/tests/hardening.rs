// SPDX-License-Identifier: AGPL-3.0-or-later
//! Process hardening (07 §4.4, BE-003; R7 SI-A-05, SI-B-03). Runs in its own
//! test binary because the settings are process-wide.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::unix::fs::PermissionsExt; // safefs-lint: allow(test fixture setup)

use candor_sealer::server::hardening::{
    LandlockLevel, disable_core_dumps, lock_memory, restrict_filesystem,
};

fn status_field(name: &str) -> String {
    let s = std::fs::read_to_string("/proc/self/status").unwrap(); // safefs-lint: allow(test reads procfs)
    s.lines()
        .find(|l| l.starts_with(name))
        .map(|l| l.trim_start_matches(name).trim().to_owned())
        .unwrap_or_default()
}

#[test]
fn hardening_applies() {
    disable_core_dumps().unwrap();
    assert_eq!(
        rustix::process::getrlimit(rustix::process::Resource::Core).current,
        Some(0)
    );
    assert_eq!(
        rustix::process::dumpable_behavior().unwrap(),
        rustix::process::DumpableBehavior::NotDumpable
    );
    // mlockall needs CAP_IPC_LOCK or a large LimitMEMLOCK (the systemd unit
    // sets LimitMEMLOCK=2G); report rather than fail where the sandbox denies it.
    match lock_memory() {
        Ok(()) => assert_ne!(status_field("VmLck:"), "0 kB"),
        Err(e) => eprintln!("mlockall unavailable in this environment: {e}"),
    }
    // Landlock in a dedicated thread: only the staging root stays reachable.
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap(); // safefs-lint: allow(test fixture setup)
    let staging = dir.path().to_path_buf();
    let t = std::thread::spawn(move || {
        let full = restrict_filesystem(&staging, LandlockLevel::BestEffort).unwrap();
        let outside = std::fs::read_to_string("/proc/self/status").is_ok() // safefs-lint: allow(test probes Landlock)
            || std::fs::read("/etc/hostname").is_ok(); // safefs-lint: allow(test probes Landlock)
        let inside = std::fs::write(staging.join("probe"), b"x").is_ok(); // safefs-lint: allow(test probes Landlock)
        (full, outside, inside)
    });
    let (full, outside, inside) = t.join().unwrap();
    assert!(inside, "staging must stay writable");
    if full {
        assert!(!outside, "Landlock enforced but outside path readable");
    } else {
        eprintln!("Landlock not fully enforced by this kernel/sandbox");
    }
}
