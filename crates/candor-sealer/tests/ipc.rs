// SPDX-License-Identifier: AGPL-3.0-or-later
//! IPC over a real Unix socket (07 §5.2, BE-006): HELLO first, strict framing,
//! BAD_FRAME closes the connection, SO_PEERCRED UID check.
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

use candor_sealer::proto::*;
use candor_sealer::server::{ChaffConfig, Limits};
use common::*;

fn serve(f: &Fixture) -> std::path::PathBuf {
    let path = f.dir.path().join("seal.sock"); // safefs-lint: allow(test socket path)
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let s = f.sealer.clone();
    tokio::spawn(async move { s.serve(listener).await });
    path
}

fn client(path: &std::path::Path) -> UnixStream {
    let c = UnixStream::connect(path).unwrap();
    c.set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .unwrap();
    c
}

fn closed(c: &mut UnixStream) -> bool {
    let mut b = [0u8; 1];
    matches!(c.read(&mut b), Ok(0) | Err(_))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socket_round_trip_and_bad_frames() {
    let f = fixture();
    let path = serve(&f);
    tokio::task::spawn_blocking(move || {
        let mut c = client(&path);
        // Anything before HELLO is a protocol violation.
        let r = call(&mut c, 1, &Request::Status).unwrap();
        assert_eq!(r, Response::error(ErrorCode::BadFrame));
        assert!(closed(&mut c));

        let mut c = client(&path);
        let r = call(
            &mut c,
            1,
            &Request::Hello {
                proto: PROTO_VERSION,
            },
        )
        .unwrap();
        assert_eq!(
            r,
            Response::Hello {
                proto: PROTO_VERSION,
                snapshot_version: 1
            }
        );
        let s = SessionHandle([5; 16]);
        assert_eq!(
            call(
                &mut c,
                2,
                &Request::SessionOpen {
                    sess: s,
                    channel_id: CHANNEL
                }
            )
            .unwrap(),
            Response::Empty
        );
        let Response::Draft(v) = call(&mut c, 3, &Request::DraftGet { sess: s }).unwrap() else {
            panic!()
        };
        assert!(v.parts.is_empty());
        let Response::Status { .. } = call(&mut c, 4, &Request::Status).unwrap() else {
            panic!()
        };
        // A second HELLO is refused and closes.
        let r = call(
            &mut c,
            5,
            &Request::Hello {
                proto: PROTO_VERSION,
            },
        )
        .unwrap();
        assert_eq!(r, Response::error(ErrorCode::BadFrame));
        assert!(closed(&mut c));

        // Oversize length prefix: BAD_FRAME, then close, before reading a body.
        let mut c = client(&path);
        c.write_all(&(MAX_FRAME_LEN as u32 + 1).to_be_bytes())
            .unwrap();
        let body = read_frame(&mut c).unwrap().unwrap();
        let (_, r) = decode_response(Op::Hello, &body).unwrap();
        assert_eq!(r, Response::error(ErrorCode::BadFrame));
        assert!(closed(&mut c));

        // Garbage body after HELLO.
        let mut c = client(&path);
        call(
            &mut c,
            1,
            &Request::Hello {
                proto: PROTO_VERSION,
            },
        )
        .unwrap();
        write_frame(&mut c, &[0xa1, 0x61, 0x76, 0x01]).unwrap();
        let body = read_frame(&mut c).unwrap().unwrap();
        let (_, r) = decode_response(Op::Hello, &body).unwrap();
        assert_eq!(r, Response::error(ErrorCode::BadFrame));
        assert!(closed(&mut c));

        // Wrong protocol version.
        let mut c = client(&path);
        let r = call(&mut c, 1, &Request::Hello { proto: 1 }).unwrap();
        assert_eq!(r, Response::error(ErrorCode::BadFrame));
        assert!(closed(&mut c));
    })
    .await
    .unwrap();
    // Session state survives connection churn (it is keyed by handle).
    assert_eq!(f.sealer.session_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_peer_uid_is_disconnected_without_a_byte() {
    let other = rustix_uid().wrapping_add(4242);
    let f = fixture_full(
        ChaffConfig {
            enabled: false,
            ..ChaffConfig::default()
        },
        Limits::default(),
        other,
    );
    let path = serve(&f);
    tokio::task::spawn_blocking(move || {
        let mut c = client(&path);
        let _ = write_frame(
            &mut c,
            &encode_request(
                1,
                &Request::Hello {
                    proto: PROTO_VERSION,
                },
            )
            .unwrap(),
        );
        assert!(closed(&mut c));
    })
    .await
    .unwrap();
}
