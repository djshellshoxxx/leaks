// SPDX-License-Identifier: AGPL-3.0-or-later
//! Unix-socket listener (07 §5.2): SO_PEERCRED check on accept, `HELLO` first,
//! strict framing; any malformed frame gets `ERR{BAD_FRAME}` and the connection
//! is closed (07 BE-006). The sealer opens no network socket (07 BE-003).

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroizing;

use super::Sealer;
use crate::proto::{
    ErrorCode, Op, Request, Response, decode_request, encode_response, frame, frame_len,
};

pub(crate) async fn serve(
    sealer: Sealer,
    listener: UnixListener,
    allowed_uid: u32,
) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let peer_ok = stream
            .peer_cred()
            .map(|c| c.uid() == allowed_uid)
            .unwrap_or(false);
        if !peer_ok {
            drop(stream);
            continue;
        }
        let s = sealer.clone();
        tokio::spawn(async move {
            let _ = connection(s, stream).await;
        });
    }
}

async fn write_msg(stream: &mut UnixStream, op: Op, rid: u32, resp: &Response) -> Result<(), ()> {
    let body = encode_response(op, rid, resp).map_err(|_| ())?;
    let f = frame(&body).map_err(|_| ())?;
    stream.write_all(&f).await.map_err(|_| ())?;
    stream.flush().await.map_err(|_| ())
}

async fn bad_frame(stream: &mut UnixStream) {
    // The op of an undecodable request is unknown; error responses carry op 0.
    let resp = Response::error(ErrorCode::BadFrame);
    if let Ok(f) = encode_response(Op::Hello, 0, &resp).and_then(|b| frame(&b)) {
        let _ = stream.write_all(&f).await;
    }
}

async fn connection(sealer: Sealer, mut stream: UnixStream) -> Result<(), ()> {
    let mut hello = false;
    loop {
        let mut prefix = [0u8; 4];
        if stream.read_exact(&mut prefix).await.is_err() {
            return Ok(()); // EOF or reset
        }
        let Ok(n) = frame_len(prefix) else {
            bad_frame(&mut stream).await;
            return Err(());
        };
        let mut buf = Zeroizing::new(vec![0u8; n]);
        if stream.read_exact(&mut buf).await.is_err() {
            return Err(());
        }
        let decoded = decode_request(&buf);
        drop(buf);
        let Ok((rid, req)) = decoded else {
            bad_frame(&mut stream).await;
            return Err(());
        };
        let op = req.op();
        if (op == Op::Hello) == hello {
            bad_frame(&mut stream).await;
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
        write_msg(&mut stream, op, rid, &resp).await?;
        if close {
            return Err(());
        }
    }
}
