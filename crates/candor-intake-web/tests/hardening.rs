// SPDX-License-Identifier: AGPL-3.0-or-later
//! `harden_process` (07 §4.4, IMPL-00 §9, IMPL-RM2 §2.2; ST-110 in part):
//! after hardening the process is not dumpable, has `RLIMIT_CORE = 0`, cannot
//! open any file or make a TCP connection (Landlock), and still serves a
//! request end to end over the inherited Unix listener while reaching the
//! sealer's pathname socket. `harness = false`: hardening must run on the
//! main thread before any runtime exists.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    // Test fixture only: probes that the filesystem is closed, socket paths
    // in a private temp directory.
    clippy::disallowed_methods
)]

mod support;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use candor_intake_web::hardening::{HardeningError, LandlockLevel, harden_process};
use candor_intake_web::{DayClock, SealerClient, Web, WebConfig};
use support::*;

fn main() {
    // Everything that needs the filesystem happens before hardening, as in
    // production (systemd passes the listening socket).
    let dir = tempfile::tempdir().unwrap();
    let web_path = dir.path().join("http.sock"); // safefs-lint: allow(test socket path in own tempdir)
    let sealer_path = dir.path().join("seal.sock"); // safefs-lint: allow(test socket path in own tempdir)
    let web_l = std::os::unix::net::UnixListener::bind(&web_path).unwrap();
    let sealer_l = std::os::unix::net::UnixListener::bind(&sealer_path).unwrap();
    web_l.set_nonblocking(true).unwrap();
    sealer_l.set_nonblocking(true).unwrap();
    let readable = dir.path().join("probe"); // safefs-lint: allow(test probe file in own tempdir)
    std::fs::write(&readable, b"x").unwrap(); // safefs-lint: allow(probe file in own tempdir)

    let report = match harden_process(LandlockLevel::Required) {
        Ok(r) => r,
        // A kernel without Landlock ABI 6 refuses Required (fail closed);
        // then check the best-effort path so the rest is still exercised.
        Err(HardeningError::Landlock) => harden_process(LandlockLevel::BestEffort).unwrap(),
        Err(e) => panic!("hardening failed: {e}"),
    };
    assert!(report.core_dumps_disabled && report.memory_locked);
    assert_eq!(
        rustix::process::dumpable_behavior().unwrap(),
        rustix::process::DumpableBehavior::NotDumpable
    );
    let lim = rustix::process::getrlimit(rustix::process::Resource::Core);
    assert_eq!((lim.current, lim.maximum), (Some(0), Some(0)));
    if report.landlock_enforced {
        let probe = std::fs::read(&readable); // safefs-lint: allow(Landlock denial probe)
        assert!(probe.is_err(), "no filesystem access");
        let probe = std::fs::read("/etc/hostname"); // safefs-lint: allow(Landlock denial probe)
        assert!(probe.is_err(), "no filesystem access");
        assert!(
            std::net::TcpStream::connect("127.0.0.1:9").is_err(),
            "no TCP connect"
        );
        assert!(
            std::net::TcpListener::bind("127.0.0.1:0").is_err(),
            "no TCP bind"
        );
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let sealer = spawn_sealer_on(tokio::net::UnixListener::from_std(sealer_l).unwrap());
        let mut cfg = WebConfig::new(HOST.into(), TENANT, site());
        cfg.max_file_bytes = 1 << 20;
        let web = Web::new(
            cfg,
            SealerClient::new(sealer_path.clone()),
            FakeStore(Arc::new(StoreState::default())),
            Arc::new(Clock(AtomicBool::new(true))) as Arc<dyn DayClock>,
        )
        .unwrap();
        tokio::spawn(candor_intake_web::serve(
            Arc::clone(&web),
            tokio::net::UnixListener::from_std(web_l).unwrap(),
        ));
        let r = parse(&raw(&web_path, 1, &get_req("/en/", &[])).await);
        assert_eq!(r.status, 200);
        let cookie = r.cookie().unwrap();
        let body = format!(
            "csrf={}&channel_id={}&mode=anonymous",
            r.csrf(),
            "c1".repeat(16)
        );
        let r = parse(&raw(&web_path, 1, &post_req("/en/new", &[&cookie], &body, &[])).await);
        assert_eq!(r.status, 200, "the sealer's pathname socket is reachable");
        assert_eq!(sealer.count(candor_sealer::proto::Op::SessionOpen), 1);
    });
    // Success is the exit status (harness = false).
    let _ = report;
}
