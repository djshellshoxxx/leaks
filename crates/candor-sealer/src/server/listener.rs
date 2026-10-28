// SPDX-License-Identifier: AGPL-3.0-or-later
//! Unix-socket listener (07 §5.2): SO_PEERCRED check on accept, `HELLO` first,
//! strict framing; any malformed frame gets `ERR{BAD_FRAME}` and the connection
//! is closed (07 BE-006). The sealer opens no network socket (07 BE-003).
//!
//! Resource bounds (ADR-052(4), AUD-RM2-SEA-04):
//! * a global connection cap; a connection over the cap gets one `ERR{BUSY}`
//!   frame (non-blocking write) and is closed;
//! * before `HELLO`, frames are limited to [`MAX_PREHELLO_FRAME`] bytes and
//!   must arrive within the handshake timeout, so an idle or unauthenticated
//!   connection never holds more than a 4-byte prefix buffer;
//! * after a length prefix the body must arrive within the frame timeout, an
//!   established connection is closed after the idle timeout, and every write
//!   has a deadline;
//! * `accept()` errors (`EMFILE`, `ENFILE`, `ENOBUFS`, …) are transient: they
//!   are counted, the loop backs off (10 ms doubling to 1 s) and continues. The
//!   accept loop never returns.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use zeroize::Zeroizing;

use super::{Limits, Sealer};
use crate::proto::{
    ErrorCode, Op, Request, Response, decode_request, encode_response, frame, frame_len,
};

/// Largest frame accepted before a successful `HELLO` (a `HELLO` is ~25 bytes).
pub const MAX_PREHELLO_FRAME: usize = 256;

const BACKOFF_MIN: Duration = Duration::from_millis(10);
const BACKOFF_MAX: Duration = Duration::from_secs(1);

pub(crate) async fn serve(
    sealer: Sealer,
    listener: UnixListener,
    allowed_uid: u32,
    accept_errors: Arc<AtomicU64>,
) -> std::io::Result<()> {
    let lim = sealer.limits().clone();
    let slots = Arc::new(Semaphore::new(lim.max_connections));
    let mut backoff = BACKOFF_MIN;
    loop {
        // An unconfined serving thread was seen: stop serving (SEA-20).
        if super::hardening::poisoned() {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        }
        let stream = match listener.accept().await {
            Ok((stream, _)) => {
                backoff = BACKOFF_MIN;
                stream
            }
            Err(_) => {
                // Transient (fd exhaustion etc.): count, back off, keep serving.
                accept_errors.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(backoff).await;
                backoff = backoff.saturating_mul(2).min(BACKOFF_MAX);
                continue;
            }
        };
        let peer_ok = stream
            .peer_cred()
            .map(|c| c.uid() == allowed_uid)
            .unwrap_or(false);
        if !peer_ok {
            drop(stream);
            continue;
        }
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            refuse_busy(stream);
            continue;
        };
        let s = sealer.clone();
        let l = lim.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = connection(s, stream, &l).await;
        });
    }
}

/// Over the connection cap: one `ERR{BUSY}` frame if the (non-blocking) socket
/// buffer takes it right away — it never waits — then close.
fn refuse_busy(stream: UnixStream) {
    use std::io::Write;
    let resp = Response::error(ErrorCode::Busy);
    if let (Ok(f), Ok(mut s)) = (
        encode_response(Op::Hello, 0, &resp).and_then(|b| frame(&b)),
        stream.into_std(),
    ) {
        let _ = s.write(&f);
    }
}

async fn write_all_timed(stream: &mut UnixStream, data: &[u8], d: Duration) -> Result<(), ()> {
    match timeout(d, async {
        stream.write_all(data).await?;
        stream.flush().await
    })
    .await
    {
        Ok(Ok(())) => Ok(()),
        _ => Err(()),
    }
}

async fn write_msg(
    stream: &mut UnixStream,
    op: Op,
    rid: u32,
    resp: &Response,
    lim: &Limits,
) -> Result<(), ()> {
    let body = encode_response(op, rid, resp).map_err(|_| ())?;
    let f = frame(&body).map_err(|_| ())?;
    write_all_timed(stream, &f, lim.write_timeout).await
}

async fn bad_frame(stream: &mut UnixStream, rid: u32, lim: &Limits) {
    // The op of an undecodable request is unknown; error responses carry op 0.
    let resp = Response::error(ErrorCode::BadFrame);
    if let Ok(f) = encode_response(Op::Hello, rid, &resp).and_then(|b| frame(&b)) {
        let _ = write_all_timed(stream, &f, lim.write_timeout).await;
    }
}

async fn connection(sealer: Sealer, mut stream: UnixStream, lim: &Limits) -> Result<(), ()> {
    let mut hello = false;
    loop {
        let wait = if hello {
            lim.idle_timeout
        } else {
            lim.handshake_timeout
        };
        let mut prefix = [0u8; 4];
        match timeout(wait, stream.read_exact(&mut prefix)).await {
            Ok(Ok(_)) => {}
            // EOF, reset, idle or handshake timeout: close.
            _ => return Ok(()),
        }
        let Ok(n) = frame_len(prefix) else {
            bad_frame(&mut stream, 0, lim).await;
            return Err(());
        };
        if !hello && n > MAX_PREHELLO_FRAME {
            bad_frame(&mut stream, 0, lim).await;
            return Err(());
        }
        let mut buf = Zeroizing::new(vec![0u8; n]);
        match timeout(lim.frame_timeout, stream.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            _ => return Err(()),
        }
        let decoded = decode_request(&buf);
        drop(buf);
        let Ok((rid, req)) = decoded else {
            bad_frame(&mut stream, 0, lim).await;
            return Err(());
        };
        let op = req.op();
        if (op == Op::Hello) == hello {
            bad_frame(&mut stream, rid, lim).await;
            return Err(());
        }
        // Every frame is handled on a confined thread (SEA-20).
        if !super::hardening::guard() {
            return Err(());
        }
        let is_hello = matches!(req, Request::Hello { .. });
        let resp = sealer.handle(req).await;
        let close = matches!(
            resp,
            Response::Error {
                code: ErrorCode::BadFrame,
                ..
            }
        );
        if is_hello && !close {
            hello = true;
        }
        write_msg(&mut stream, op, rid, &resp, lim).await?;
        if close {
            return Err(());
        }
    }
}
