// SPDX-License-Identifier: AGPL-3.0-or-later
//! AUD-RM2-SEA-01 (C-06 side): the sealer client tells "the sealer is not
//! reachable" (nothing was sent: `Unavailable`) from "the request was sent
//! and not answered in time" (`NoReply`), so a `SEAL_FINISH` whose outcome is
//! unknown is never shown to the source as "not sent".
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    // Test fixture only: socket paths in a private temp dir.
    clippy::disallowed_methods
)]

use std::time::Duration;

use candor_intake_web::{SealerClient, SealerError};
use candor_sealer::proto::{
    Op, PROTO_VERSION, Request, Response, SessionHandle, decode_request, encode_response, frame,
    frame_len,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

async fn read_req(s: &mut tokio::net::UnixStream) -> Option<(u32, Request)> {
    let mut p = [0u8; 4];
    s.read_exact(&mut p).await.ok()?;
    let mut b = vec![0u8; frame_len(p).ok()?];
    s.read_exact(&mut b).await.ok()?;
    decode_request(&b).ok()
}

/// A fake sealer that answers HELLO and then never answers.
async fn silent_sealer(l: UnixListener) {
    loop {
        let Ok((mut s, _)) = l.accept().await else {
            return;
        };
        tokio::spawn(async move {
            if let Some((rid, Request::Hello { .. })) = read_req(&mut s).await {
                let resp = Response::Hello {
                    proto: PROTO_VERSION,
                    snapshot_version: 1,
                };
                let msg = encode_response(Op::Hello, rid, &resp).unwrap();
                s.write_all(&frame(&msg).unwrap()).await.unwrap();
            }
            let _ = read_req(&mut s).await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
    }
}

#[tokio::test]
async fn unanswered_seal_finish_is_no_reply_not_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("seal.sock"); // safefs-lint: allow(test socket path in own tempdir)
    let l = UnixListener::bind(&path).unwrap();
    tokio::spawn(silent_sealer(l));
    let c = SealerClient::new(path.clone());
    let req = Request::SealFinish {
        sess: SessionHandle([1; 16]),
        delayed_delivery: false,
    };
    let e = c.call(&req, Duration::from_millis(300)).await.unwrap_err();
    assert_eq!(e, SealerError::NoReply, "sent, outcome unknown");
    // Nothing listening: nothing was sent.
    let gone = SealerClient::new(dir.path().join("nobody.sock")); // safefs-lint: allow(test socket path in own tempdir)
    let e = gone
        .call(&req, Duration::from_millis(300))
        .await
        .unwrap_err();
    assert_eq!(e, SealerError::Unavailable);
}
