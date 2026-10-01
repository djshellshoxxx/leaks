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
// Landlock probes and fixture setup use std::fs/std::net directly.
#![allow(clippy::disallowed_methods)] // safefs-lint: allow(test probes Landlock)

mod common;

use candor_core::sig::SigningKey;
use candor_sealer::server::hardening::{
    HardeningError, InsecureDevMode, LandlockLevel, confined_runtime, harden_process, report,
    self_check, thread_confined,
};
use candor_sealer::server::{ChaffConfig, Limits, Sealer};
use common::*;

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
    l: std::os::unix::net::UnixListener,
) -> Option<std::io::Result<()>> {
    l.set_nonblocking(true).unwrap();
    let listener = tokio::net::UnixListener::from_std(l).unwrap();
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

/// Runs on the main thread (`harness = false`): `harden_process` requires the
/// main thread to be the only thread (AUD-RM2-SEA-20).
fn main() {
    // Production sealers take the memory budget and quota from the unit's
    // environment (SEA-29). Environment changes need `unsafe` in-process, so
    // the binary re-executes itself with the variables set.
    if std::env::var_os(candor_sealer::server::MEMORY_BUDGET_ENV).is_none() {
        // Without the variables a production sealer refuses to start.
        let f = fixture();
        let mut cfg = config(ChaffConfig::default(), Limits::default(), 54_321);
        cfg.insecure_dev = None;
        let r = Sealer::new(
            cfg,
            SigningKey::from_seed(&[0x35; 32]),
            f.staging,
            f.clock.clone(),
            f.sink.clone(),
        );
        assert_eq!(r.err(), Some(candor_sealer::server::StartError::Config));
        let exe = std::env::current_exe().unwrap();
        let status = std::process::Command::new(exe) // safefs-lint: allow(test re-exec with env)
            .env(candor_sealer::server::MEMORY_BUDGET_ENV, "64")
            .env(candor_sealer::server::SESSION_UPLOAD_ENV, "16")
            .env(candor_sealer::server::UPLOAD_SLOTS_ENV, "8")
            .env(candor_sealer::server::MAX_SESSIONS_ENV, "8")
            .status()
            .unwrap();
        assert!(status.success(), "hardening scenarios failed");
        return;
    }
    developer_override_is_audit_logged();
    hardening_is_applied_and_enforced_before_serving();
}

fn hardening_is_applied_and_enforced_before_serving() {
    let f = fixture();
    let sock_dir = tempfile::tempdir().unwrap();
    // Sockets are bound before Landlock (binding creates a filesystem node
    // outside the staging root, which the hardened process may not do).
    let bind = |n: &str| {
        let p = sock_dir.path().join(n); // safefs-lint: allow(test socket path in own tempdir)
        std::os::unix::net::UnixListener::bind(p).unwrap()
    };
    let (la, lb0, lb1, lc, ld) = (bind("a"), bind("b0"), bind("b1"), bind("c"), bind("d"));

    // 1. Unhardened: the self-check fails and a production sealer refuses to
    //    serve (fail closed), whatever the peer UID.
    assert_eq!(self_check().unwrap_err(), HardeningError::NotApplied);
    assert!(!thread_confined());
    assert_eq!(confined_runtime(1).unwrap_err(), HardeningError::NotApplied);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let prod = production_sealer(&f, 54_321);
    let r = rt.block_on(serve_result(&prod, la));
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
    rt.shutdown_timeout(std::time::Duration::from_secs(5));

    // 2. AUD-RM2-SEA-20 PoC: hardening on a helper thread is refused and
    //    records nothing (the main thread would stay unconfined); so is
    //    hardening from inside a runtime.
    let staging = f.staging_path.clone();
    let st = staging.clone();
    let helper = std::thread::spawn(move || harden_process(&st, LandlockLevel::Required));
    assert_eq!(helper.join().unwrap(), Err(HardeningError::NotMainThread));
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let st = staging.clone();
    assert_eq!(
        rt.block_on(async move { harden_process(&st, LandlockLevel::Required) }),
        Err(HardeningError::NotMainThread)
    );
    drop(rt);
    assert!(report().is_none());
    assert_eq!(self_check().unwrap_err(), HardeningError::NotApplied);

    // Threads that exist before hardening stay outside the Landlock domain:
    // a plain thread and the workers of a runtime built too early.
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let early = std::thread::spawn(move || {
        rx.recv().unwrap();
        thread_confined()
    });
    let early_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    // 3. Harden on the main thread, outside any runtime. Any failure fails
    //    the test (CI must be able to run the sealer hardened).
    assert_eq!(
        harden_process(&staging, LandlockLevel::Required),
        Ok(true),
        "hardening must apply with Landlock enforced"
    );
    assert!(thread_confined());
    let outside = std::fs::read_to_string("/proc/self/status").is_ok() // safefs-lint: allow(test probes Landlock)
        || std::fs::read("/etc/hostname").is_ok(); // safefs-lint: allow(test probes Landlock)
    assert!(!outside, "Landlock enforced but outside path readable");
    assert!(
        std::net::TcpListener::bind("127.0.0.1:0").is_err(),
        "Landlock ABI 4 must deny TCP bind"
    );
    let rep = report().unwrap();
    assert!(rep.core_dumps_disabled && rep.memory_locked && rep.landlock_enforced);
    assert_eq!(self_check(), Ok(rep));
    assert_eq!(
        rustix::process::getrlimit(rustix::process::Resource::Core).current,
        Some(0)
    );
    assert_eq!(
        rustix::process::dumpable_behavior().unwrap(),
        rustix::process::DumpableBehavior::NotDumpable
    );

    // The per-thread probe sees the early threads as unconfined, and a
    // production sealer served from the early runtime refuses to serve
    // although the process-wide record says "hardened" (the auditor's PoC).
    tx.send(()).unwrap();
    assert!(
        !early.join().unwrap(),
        "pre-hardening thread must probe unconfined"
    );
    let prod = production_sealer(&f, 54_321);
    let r = early_rt.block_on(async move {
        tokio::spawn(async move { serve_result(&prod, ld).await })
            .await
            .unwrap()
    });
    assert_eq!(
        r.expect("serve must return at once").unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    early_rt.shutdown_background();

    // A runtime built by hand after hardening is not trusted either (its
    // threads were not recorded): serving from it fails closed.
    let manual = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    assert!(!manual.block_on(async { tokio::spawn(async { thread_confined() }).await.unwrap() }));
    manual.shutdown_background();

    // 4. The sealer's runtime (built after hardening): every worker and
    //    blocking thread is confined, and the self-check passes inside it.
    let rt = confined_runtime(2).unwrap();
    let per_worker = rt.block_on(async {
        let mut v = Vec::new();
        for _ in 0..16 {
            v.push(tokio::spawn(async {
                (thread_confined(), self_check().is_ok())
            }));
        }
        let mut out = Vec::new();
        for h in v {
            out.push(h.await.unwrap());
        }
        out.push(
            tokio::task::spawn_blocking(|| (thread_confined(), self_check().is_ok()))
                .await
                .unwrap(),
        );
        out
    });
    assert!(per_worker.iter().all(|(c, ok)| *c && *ok), "{per_worker:?}");

    // 5. Hardened: a peer UID of root or of the sealer itself is refused.
    let own = rustix::process::getuid().as_raw();
    for (bad, l) in [(0, lb0), (own, lb1)] {
        let s = production_sealer(&f, bad);
        let r = rt.block_on(serve_result(&s, l));
        assert_eq!(
            r.expect("serve must return at once").unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
    // 6. Hardened and a distinct peer UID: the sealer serves (does not return).
    let s = production_sealer(&f, 54_321);
    assert!(rt.block_on(serve_result(&s, lc)).is_none());
}

/// The developer override can only be obtained by writing a typed audit event;
/// without a working audit sink it is refused.
fn developer_override_is_audit_logged() {
    use candor_log::codes::{HostRole, StreamId};
    use candor_log::ids::TenantRef;
    let new_log = || {
        candor_log::AuditLog::new(
            TenantRef::generate().unwrap(),
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
