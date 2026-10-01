// SPDX-License-Identifier: AGPL-3.0-or-later
//! Process hardening (07 §4.4, BE-003; R7 SI-A-05, SI-B-03) and its enforcement
//! (ADR-052(5), AUD-RM2-SEA-06/18). Runs in its own test binary because the
//! settings are process-wide. Fails (does not merely report) when hardening
//! cannot be applied, so CI notices an environment that cannot run the sealer.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::os::unix::fs::PermissionsExt; // safefs-lint: allow(test fixture setup)

use candor_core::sig::SigningKey;
use candor_sealer::server::hardening::{
    HardeningError, InsecureDevMode, LandlockLevel, harden_process, report, self_check,
};
use candor_sealer::server::{ChaffConfig, Limits, Sealer};
use common::*;

fn status_field(name: &str) -> String {
    let s = std::fs::read_to_string("/proc/self/status").unwrap(); // safefs-lint: allow(test reads procfs)
    s.lines()
        .find(|l| l.starts_with(name))
        .map(|l| l.trim_start_matches(name).trim().to_owned())
        .unwrap_or_default()
}

/// A production-configured sealer (no developer override, chaff on).
fn production_sealer(f: &Fixture, peer_uid: u32) -> Sealer {
    let mut cfg = config(ChaffConfig::default(), Limits::default(), peer_uid);
    cfg.insecure_dev = None;
    Sealer::new(
        cfg,
        SigningKey::from_seed(&[0x35; 32]),
        f.staging,
        f.clock.clone(),
        f.sink.clone(),
    )
    .unwrap()
}

async fn serve_result(
    s: &Sealer,
    dir: &std::path::Path,
    name: &str,
) -> Option<std::io::Result<()>> {
    let listener = tokio::net::UnixListener::bind(dir.join(name)).unwrap();
    let s = s.clone();
    let h = tokio::spawn(async move { s.serve(listener).await });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    if h.is_finished() {
        Some(h.await.unwrap())
    } else {
        h.abort();
        None
    }
}

#[test]
fn hardening_is_applied_and_enforced_before_serving() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let f = fixture();
    let sock_dir = tempfile::tempdir().unwrap();

    // 1. Unhardened: the self-check fails and a production sealer refuses to
    //    serve (fail closed), whatever the peer UID.
    assert_eq!(self_check().unwrap_err(), HardeningError::NotApplied);
    let prod = production_sealer(&f, 54_321);
    let r = rt.block_on(serve_result(&prod, sock_dir.path(), "a.sock"));
    assert_eq!(
        r.expect("serve must return at once").unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    // Chaff can only be disabled with the developer override.
    let mut cfg = config(
        ChaffConfig {
            enabled: false,
            ..ChaffConfig::default()
        },
        Limits::default(),
        54_321,
    );
    cfg.insecure_dev = None;
    assert!(
        Sealer::new(
            cfg,
            SigningKey::from_seed(&[0x35; 32]),
            f.staging,
            f.clock.clone(),
            f.sink.clone()
        )
        .is_err()
    );

    // 2. Harden (Landlock Required) in a dedicated thread; only the staging
    //    root stays reachable from it. Any failure fails the test.
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap(); // safefs-lint: allow(test fixture setup)
    let staging = dir.path().to_path_buf();
    let t = std::thread::spawn(move || {
        let full = harden_process(&staging, LandlockLevel::Required);
        let outside = std::fs::read_to_string("/proc/self/status").is_ok() // safefs-lint: allow(test probes Landlock)
            || std::fs::read("/etc/hostname").is_ok(); // safefs-lint: allow(test probes Landlock)
        let inside = std::fs::write(staging.join("probe"), b"x").is_ok(); // safefs-lint: allow(test probes Landlock)
        (full, outside, inside)
    });
    let (full, outside, inside) = t.join().unwrap();
    assert_eq!(
        full,
        Ok(true),
        "hardening must apply with Landlock enforced"
    );
    assert!(inside, "staging must stay writable");
    assert!(!outside, "Landlock enforced but outside path readable");
    assert_eq!(
        rustix::process::getrlimit(rustix::process::Resource::Core).current,
        Some(0)
    );
    assert_eq!(
        rustix::process::dumpable_behavior().unwrap(),
        rustix::process::DumpableBehavior::NotDumpable
    );
    assert_ne!(status_field("VmLck:"), "0 kB", "mlockall must lock memory");
    let rep = report().unwrap();
    assert!(rep.core_dumps_disabled && rep.memory_locked && rep.landlock_enforced);
    assert_eq!(self_check(), Ok(rep));

    // 3. Hardened: a peer UID of root or of the sealer itself is refused.
    let own = rustix::process::getuid().as_raw();
    for bad in [0, own] {
        let s = production_sealer(&f, bad);
        let r = rt.block_on(serve_result(&s, sock_dir.path(), &format!("b{bad}.sock")));
        assert_eq!(
            r.expect("serve must return at once").unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
    // 4. Hardened and a distinct peer UID: the sealer serves (does not return).
    let s = production_sealer(&f, 54_321);
    assert!(
        rt.block_on(serve_result(&s, sock_dir.path(), "c.sock"))
            .is_none()
    );
}

/// The developer override can only be obtained by writing a typed audit event;
/// without a working audit sink it is refused.
#[test]
fn developer_override_is_audit_logged() {
    use candor_log::codes::{HostRole, StreamId};
    use candor_log::ids::{AuditIdKey, TenantRef};
    let new_log = || {
        candor_log::AuditLog::new(
            TenantRef::derive(&AuditIdKey::new([3; 32]), b"tenant"),
            HostRole::Intake,
            candor_log::SoftwareSigner::from_seed(&zeroize::Zeroizing::new([9; 32])),
            candor_log::SystemClock,
            candor_log::CheckpointPolicy::DEFAULT,
        )
    };
    let mut log = new_log();
    let sink = candor_log::sink::MemorySink::new();
    log.set_primary_sink(Box::new(sink.clone()));
    InsecureDevMode::acknowledge(&mut log).unwrap();
    let recs = sink.0.lock().unwrap().records(StreamId::Sys);
    assert_eq!(recs.len(), 1, "exactly one sys.health record");
    // No primary sink: nothing can be logged, so no override.
    let mut bare = new_log();
    assert_eq!(
        InsecureDevMode::acknowledge(&mut bare).unwrap_err(),
        HardeningError::DevFlagNotLogged
    );
}
