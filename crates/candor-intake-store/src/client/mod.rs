// SPDX-License-Identifier: AGPL-3.0-or-later
//! `istore.sock` client (feature `client`).
//!
//! * [`Conn`]: one blocking connection with a per-call deadline. Any
//!   transport error, timeout or undecodable reply **closes** the socket, so
//!   a late reply can never be read as the answer to a later request; the
//!   next call reconnects through the integrator's connector (the crate
//!   handles no socket paths). The sealer's `EnvelopeSink` is built on it
//!   (`candor_sealer::server::istore`), with the staged hand-over on the same
//!   socket.
//! * [`IstoreClient`]: the web tier's [`StoreReads`] over a small pool of
//!   connections, run on `spawn_blocking`. Every failure is the content-free
//!   [`StoreUnavailable`].

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use rustix::net::sockopt::{Timeout, set_socket_timeout};

use crate::proto::{
    ErrorCode, MAX_FRAME_LEN, Request, Response, decode_response, encode_request, max_response_len,
};
use crate::reads::{AccountView, StoreReads, StoreUnavailable};
use crate::sockio::{recv_datagram, send_bytes};
use crate::types::{AccountId, Day, ReplyRef, StoredReply};

/// Opens a fresh connection to `istore.sock` (the integrator owns the path).
pub type Connector = Arc<dyn Fn() -> std::io::Result<OwnedFd> + Send + Sync>;

/// Client failure. Carries no data beyond the store's uniform code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientError {
    /// Connect, send, receive, timeout or decode failure: the connection
    /// was closed; nothing is known about the request's outcome.
    Transport,
    /// The store answered with an error code (the connection stays open,
    /// except after `BadFrame`/`Forbidden`, which the server closes).
    Store(ErrorCode),
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport => f.write_str("istore transport failure"),
            Self::Store(c) => write!(f, "istore error {c:?}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// Default per-call deadline.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Default pool size of [`IstoreClient`].
pub const DEFAULT_POOL: usize = 8;

/// One blocking connection.
pub struct Conn {
    sock: Option<OwnedFd>,
    connector: Connector,
    timeout: Duration,
    rid: u32,
    buf: Vec<u8>,
}

impl core::fmt::Debug for Conn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Conn")
            .field("open", &self.sock.is_some())
            .finish_non_exhaustive()
    }
}

impl Conn {
    /// A connection that connects lazily on the first call.
    #[must_use]
    pub fn new(connector: Connector, timeout: Duration) -> Self {
        Self {
            sock: None,
            connector,
            timeout,
            rid: 0,
            buf: Vec::new(),
        }
    }

    /// Connected and without a failure since.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.sock.is_some()
    }

    /// Close the socket (the next call reconnects).
    pub fn close(&mut self) {
        self.sock = None;
    }

    /// Connect if closed.
    pub fn ensure(&mut self) -> Result<(), ClientError> {
        if self.sock.is_none() {
            let s = (self.connector)().map_err(|_| ClientError::Transport)?;
            set_socket_timeout(&s, Timeout::Send, Some(self.timeout))
                .map_err(|_| ClientError::Transport)?;
            set_socket_timeout(&s, Timeout::Recv, Some(self.timeout))
                .map_err(|_| ClientError::Transport)?;
            self.sock = Some(s);
        }
        Ok(())
    }

    /// The open socket (for the staged hand-over after `COMMIT_GROUP`).
    #[must_use]
    pub fn socket(&self) -> Option<BorrowedFd<'_>> {
        self.sock.as_ref().map(AsFd::as_fd)
    }

    /// One request/response exchange. A reply with another `rid`, a decode
    /// failure, a timeout or an I/O error closes the connection.
    pub fn call(&mut self, req: &Request) -> Result<Response, ClientError> {
        self.ensure()?;
        let r = self.call_inner(req);
        if matches!(
            r,
            Err(ClientError::Transport)
                | Err(ClientError::Store(
                    ErrorCode::BadFrame | ErrorCode::Forbidden
                ))
        ) {
            self.close();
        }
        r
    }

    fn call_inner(&mut self, req: &Request) -> Result<Response, ClientError> {
        let sock = self.sock.as_ref().ok_or(ClientError::Transport)?;
        // rid 0 is reserved for errors the server sends before reading a
        // request (over the connection cap).
        self.rid = self.rid.wrapping_add(1).max(1);
        let rid = self.rid;
        let bytes = encode_request(rid, req).map_err(|_| ClientError::Transport)?;
        let op = req.op();
        let want = max_response_len(op)
            .saturating_add(1)
            .min(MAX_FRAME_LEN.saturating_add(1));
        if self.buf.len() < want {
            self.buf.resize(want, 0);
        }
        if send_bytes(sock.as_fd(), &bytes).is_err() {
            // The server may have refused the connection (BUSY) before our
            // request arrived: surface that code if it is waiting.
            if let Ok(Some(n)) = recv_datagram(sock.as_fd(), &mut self.buf)
                && let Some(data) = self.buf.get(..n)
                && let Ok((0, Response::Error(c))) = decode_response(op, data)
            {
                return Err(ClientError::Store(c));
            }
            return Err(ClientError::Transport);
        }
        let n = recv_datagram(sock.as_fd(), &mut self.buf)
            .map_err(|()| ClientError::Transport)?
            .ok_or(ClientError::Transport)?;
        let data = self.buf.get(..n).ok_or(ClientError::Transport)?;
        let (got, resp) = decode_response(op, data).map_err(|_| ClientError::Transport)?;
        match resp {
            Response::Error(c) if got == rid || got == 0 => Err(ClientError::Store(c)),
            r if got == rid => Ok(r),
            _ => Err(ClientError::Transport),
        }
    }
}

/// The web tier's store reads over `istore.sock`.
pub struct IstoreClient {
    idle: Mutex<Vec<Conn>>,
    permits: Arc<tokio::sync::Semaphore>,
    connector: Connector,
    timeout: Duration,
}

impl core::fmt::Debug for IstoreClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IstoreClient")
    }
}

impl IstoreClient {
    /// A client with at most `pool` concurrent connections (≥ 1) and a
    /// per-call deadline.
    #[must_use]
    pub fn new(connector: Connector, pool: usize, timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            idle: Mutex::new(Vec::new()),
            permits: Arc::new(tokio::sync::Semaphore::new(pool.max(1))),
            connector,
            timeout,
        })
    }

    /// Run `f` with a pooled connection on a blocking thread. A connection
    /// that failed is dropped, not returned to the pool.
    async fn with_conn<T, F>(self: &Arc<Self>, f: F) -> Result<T, StoreUnavailable>
    where
        T: Send + 'static,
        F: FnOnce(&mut Conn) -> Result<T, ClientError> + Send + 'static,
    {
        let _permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| StoreUnavailable)?;
        let me = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let mut conn = me
                .idle
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop()
                .unwrap_or_else(|| Conn::new(Arc::clone(&me.connector), me.timeout));
            let r = f(&mut conn);
            if conn.is_open() {
                me.idle
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(conn);
            }
            r.map_err(|_| StoreUnavailable)
        })
        .await
        .map_err(|_| StoreUnavailable)?
    }
}

impl StoreReads for Arc<IstoreClient> {
    async fn serving_allowed(&self) -> Result<bool, StoreUnavailable> {
        self.with_conn(|c| match c.call(&Request::ServingAllowed)? {
            Response::ServingAllowed(b) => Ok(b),
            _ => Err(ClientError::Transport),
        })
        .await
    }

    async fn account(&self, tag: [u8; 32]) -> Result<Option<AccountView>, StoreUnavailable> {
        self.with_conn(move |c| match c.call(&Request::AccountLookup { tag })? {
            Response::Account(a) => Ok(a.map(|a| AccountView {
                account_id: AccountId(a.account_id),
                auth_pk: a.auth_pk,
                prefs_ct: a.prefs_ct,
            })),
            _ => Err(ClientError::Transport),
        })
        .await
    }

    async fn mailbox(&self, account: AccountId) -> Result<Vec<StoredReply>, StoreUnavailable> {
        self.with_conn(move |c| {
            let heads = match c.call(&Request::MailboxList { account: account.0 })? {
                Response::MailboxList(v) => v,
                _ => return Err(ClientError::Transport),
            };
            let mut out = Vec::with_capacity(heads.len());
            for h in heads {
                let ct = match c.call(&Request::MailboxRead {
                    account: account.0,
                    reply: h.reply_ref,
                })? {
                    Response::ReplyCt(ct) => ct,
                    _ => return Err(ClientError::Transport),
                };
                out.push(StoredReply {
                    reply_ref: ReplyRef(h.reply_ref),
                    slot: h.slot,
                    reply_ct: ct,
                    size_bucket: h.size_bucket,
                    available_day: Day(h.available_day),
                });
            }
            Ok(out)
        })
        .await
    }
}
