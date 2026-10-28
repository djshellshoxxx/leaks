// SPDX-License-Identifier: AGPL-3.0-or-later
//! IPC listener resource bounds (ADR-052(4), AUD-RM2-SEA-04; 07 §5.2, §11,
//! BE-006): connection cap with BUSY, handshake / frame / idle timeouts, and no
//! large buffer before HELLO.
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

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use candor_sealer::proto::*;
use candor_sealer::server::{ChaffConfig, Limits};
use common::*;

fn short_limits() -> Limits {
    Limits {
        max_connections: 2,
        handshake_timeout: Duration::from_millis(300),
        frame_timeout: Duration::from_millis(300),
        idle_timeout: Duration::from_millis(600),
        write_timeout: Duration::from_millis(300),
        ..Limits::default()
    }
}

fn setup() -> (Fixture, std::path::PathBuf) {
    let f = fixture_with(
        ChaffConfig {
            enabled: false,
            ..ChaffConfig::default()
        },
        short_limits(),
    );
    let path = f.dir.path().join("seal.sock"); // safefs-lint: allow(test socket path)
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let s = f.sealer.clone();
    tokio::spawn(async move { s.serve(listener).await });
    (f, path)
}

fn client(path: &std::path::Path) -> UnixStream {
    let c = UnixStream::connect(path).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    c
}

fn hello(c: &mut UnixStream) {
    let r = call(
        c,
        1,
        &Request::Hello {
            proto: PROTO_VERSION,
        },
    )
    .unwrap();
    assert!(matches!(r, Response::Hello { .. }));
}

/// Read until EOF/reset; returns how long it took.
fn wait_closed(c: &mut UnixStream) -> Duration {
    let t = Instant::now();
    let mut b = [0u8; 64];
    loop {
        match c.read(&mut b) {
            Ok(0) | Err(_) => return t.elapsed(),
            Ok(_) => {}
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_cap_answers_busy_and_frees_slots() {
    let (_f, path) = setup();
    tokio::task::spawn_blocking(move || {
        let mut a = client(&path);
        hello(&mut a);
        let mut b = client(&path);
        hello(&mut b);
        // Third connection: one BUSY frame, then closed, without reading.
        let mut c = client(&path);
        let body = read_frame(&mut c).unwrap().unwrap();
        let (_, r) = decode_response(Op::Hello, &body).unwrap();
        assert_eq!(r, Response::error(ErrorCode::Busy));
        wait_closed(&mut c);
        // Closing one frees a slot.
        drop(a);
        std::thread::sleep(Duration::from_millis(100));
        let mut d = client(&path);
        hello(&mut d);
        let r = call(&mut b, 2, &Request::Status).unwrap();
        assert!(matches!(r, Response::Status { .. }));
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeouts_close_stalled_and_idle_connections() {
    let (_f, path) = setup();
    tokio::task::spawn_blocking(move || {
        // Connect and send nothing: closed after the handshake timeout.
        let mut c = client(&path);
        assert!(wait_closed(&mut c) < Duration::from_secs(5));
        // Stalled prefix before HELLO (slowloris): closed.
        let mut c = client(&path);
        c.write_all(&20u32.to_be_bytes()).unwrap();
        assert!(wait_closed(&mut c) < Duration::from_secs(5));
        // After HELLO: a prefix announcing 1,000 bytes, then nothing.
        let mut c = client(&path);
        hello(&mut c);
        c.write_all(&1000u32.to_be_bytes()).unwrap();
        c.write_all(&[0xa4; 10]).unwrap();
        assert!(wait_closed(&mut c) < Duration::from_secs(5));
        // Idle after HELLO: closed after the idle timeout, not before.
        let mut c = client(&path);
        hello(&mut c);
        let d = wait_closed(&mut c);
        assert!(
            d >= Duration::from_millis(500) && d < Duration::from_secs(5),
            "{d:?}"
        );
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_large_frame_before_hello() {
    let (_f, path) = setup();
    tokio::task::spawn_blocking(move || {
        // A prefix within MAX_FRAME_LEN but above the pre-HELLO limit is refused
        // before any body buffer is allocated.
        let mut c = client(&path);
        c.write_all(&(MAX_FRAME_LEN as u32).to_be_bytes()).unwrap();
        let body = read_frame(&mut c).unwrap().unwrap();
        let (_, r) = decode_response(Op::Hello, &body).unwrap();
        assert_eq!(r, Response::error(ErrorCode::BadFrame));
        wait_closed(&mut c);
    })
    .await
    .unwrap();
}
