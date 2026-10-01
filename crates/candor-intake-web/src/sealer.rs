// SPDX-License-Identifier: AGPL-3.0-or-later
//! Client of the Intake Sealer IPC (07 §5.2) over its Unix socket, using only
//! `candor_sealer::proto` (RM-2 addendum: the web depends on the protocol
//! types, never on the sealer's internals).
//!
//! One connection per call: connect, `HELLO` (protocol 2 or fail), one
//! request, one response, close. No connection is ever reused, so a late or
//! stray response can never be read as the answer to another request, and a
//! request is never replayed on a fresh connection. Every step has a
//! deadline; concurrency is bounded ([`SEALER_POOL`]). Any I/O, framing or
//! version failure is [`SealerError::Unavailable`], which the web turns into
//! the uniform busy page (fail closed, 07 §13: no fallback of any kind).
//! The web holds no keys: everything key-bearing stays in the sealer.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use candor_sealer::proto::{
    ErrorCode, PROTO_VERSION, Request, Response, decode_response, encode_request, frame,
    frame_len,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::limits::{SEALER_CONNECT_TIMEOUT, SEALER_POOL};

/// Sealer call failure (content-free).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealerError {
    /// Socket, deadline, framing or protocol failure: the sealer is treated
    /// as down.
    Unavailable,
    /// The sealer answered with an error code (and, for
    /// `NO_ELIGIBLE_TRIAGE`/`UNAVAILABLE`, possibly an alternative channel).
    Code(ErrorCode, Option<[u8; 16]>),
}

/// The sealer client.
pub struct SealerClient {
    path: PathBuf,
    permits: Semaphore,
    rid: AtomicU32,
}

impl core::fmt::Debug for SealerClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SealerClient")
    }
}

impl SealerClient {
    /// A client for the sealer socket at `path` (e.g.
    /// `/run/candor/sealer/seal.sock`).
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            permits: Semaphore::new(SEALER_POOL),
            rid: AtomicU32::new(1),
        }
    }

    async fn read_frame(s: &mut UnixStream) -> Result<Zeroizing<Vec<u8>>, SealerError> {
        let mut prefix = [0u8; 4];
        s.read_exact(&mut prefix)
            .await
            .map_err(|_| SealerError::Unavailable)?;
        let n = frame_len(prefix).map_err(|_| SealerError::Unavailable)?;
        let mut body = Zeroizing::new(vec![0u8; n]);
        s.read_exact(&mut body)
            .await
            .map_err(|_| SealerError::Unavailable)?;
        Ok(body)
    }

    async fn exchange(
        s: &mut UnixStream,
        rid: u32,
        req: &Request,
    ) -> Result<Response, SealerError> {
        let msg = encode_request(rid, req).map_err(|_| SealerError::Unavailable)?;
        let f = frame(&msg).map_err(|_| SealerError::Unavailable)?;
        s.write_all(&f).await.map_err(|_| SealerError::Unavailable)?;
        let body = Self::read_frame(s).await?;
        let (got, resp) =
            decode_response(req.op(), &body).map_err(|_| SealerError::Unavailable)?;
        if got != rid {
            return Err(SealerError::Unavailable);
        }
        Ok(resp)
    }

    /// Send `req` and return the sealer's response, all within `deadline`.
    /// `Response::Error` is returned as [`SealerError::Code`].
    pub async fn call(&self, req: &Request, deadline: Duration) -> Result<Response, SealerError> {
        let work = async {
            let _permit = self
                .permits
                .acquire()
                .await
                .map_err(|_| SealerError::Unavailable)?;
            let mut s = timeout(SEALER_CONNECT_TIMEOUT, UnixStream::connect(&self.path))
                .await
                .map_err(|_| SealerError::Unavailable)?
                .map_err(|_| SealerError::Unavailable)?;
            let hello = Request::Hello {
                proto: PROTO_VERSION,
            };
            let rid0 = self.next_rid();
            match Self::exchange(&mut s, rid0, &hello).await? {
                Response::Hello { proto, .. } if proto == PROTO_VERSION => {}
                _ => return Err(SealerError::Unavailable),
            }
            let rid = self.next_rid();
            let resp = Self::exchange(&mut s, rid, req).await?;
            // Close the connection: one request per connection.
            let _ = s.shutdown().await;
            match resp {
                Response::Error {
                    code,
                    alternative_channel_id,
                } => Err(SealerError::Code(code, alternative_channel_id)),
                r => Ok(r),
            }
        };
        timeout(deadline, work)
            .await
            .map_err(|_| SealerError::Unavailable)?
    }

    fn next_rid(&self) -> u32 {
        // Wrapping counter; uniqueness per connection is all that matters.
        self.rid.fetch_add(1, Ordering::Relaxed)
    }
}
