// SPDX-License-Identifier: AGPL-3.0-or-later
//! AUD-RM2-SEA-04 regression (the auditor's PoC): when the fd limit is reached,
//! `accept()` fails with `EMFILE`; the listener must back off and keep serving
//! instead of returning (ADR-052(4)). Own test binary: it lowers the process
//! fd limit.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

// Unix socket paths inside the fixture tempdir.
#![allow(clippy::disallowed_methods)] // safefs-lint: allow(test socket path in own tempdir)

mod common;

use std::os::unix::net::UnixStream;
use std::time::Duration;

use candor_sealer::proto::*;
use common::*;
use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

fn open_fds() -> u64 {
    std::fs::read_dir("/proc/self/fd").unwrap().count() as u64 // safefs-lint: allow(test reads procfs)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_survives_emfile() {
    let f = fixture();
    let path = f.dir.path().join("seal.sock"); // safefs-lint: allow(test socket path)
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let s = f.sealer.clone();
    let server = tokio::spawn(async move { s.serve(listener).await });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let orig = getrlimit(Resource::Nofile);
    let p = path.clone();
    let clients = tokio::task::spawn_blocking(move || {
        // Leave room for a few client sockets only: the server side of the
        // accepted connections then exhausts the table.
        let cur = open_fds();
        setrlimit(
            Resource::Nofile,
            Rlimit {
                current: Some(cur + 8),
                maximum: orig.maximum,
            },
        )
        .unwrap();
        let mut v = Vec::new();
        for _ in 0..16 {
            match UnixStream::connect(&p) {
                Ok(c) => v.push(c),
                Err(_) => break,
            }
        }
        std::thread::sleep(Duration::from_millis(300));
        v
    })
    .await
    .unwrap();
    assert!(f.sealer.accept_errors() > 0, "EMFILE was not reached");
    assert!(!server.is_finished(), "serve returned on EMFILE");
    drop(clients);
    setrlimit(Resource::Nofile, orig).unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(!server.is_finished());

    // New connections are served again.
    let p = path.clone();
    tokio::task::spawn_blocking(move || {
        let mut c = UnixStream::connect(&p).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let r = call(
            &mut c,
            1,
            &Request::Hello {
                proto: PROTO_VERSION,
            },
        )
        .unwrap();
        assert!(matches!(r, Response::Hello { .. }));
    })
    .await
    .unwrap();
    server.abort();
}
