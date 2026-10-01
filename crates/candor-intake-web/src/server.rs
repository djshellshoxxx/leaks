// SPDX-License-Identifier: AGPL-3.0-or-later
//! The accept loop and per-connection handling (07 §5.1, §11; IMPL-RM2 §2.6;
//! ST-044, ST-075, ST-101).
//!
//! * Listener: a Unix stream socket only (the API takes a
//!   `tokio::net::UnixListener`; there is no TCP code path, NET-002). tor
//!   connects to it; every stream starts with tor's PROXY line.
//! * Connection caps: [`MAX_CONNECTIONS`] served; up to
//!   [`crate::limits::MAX_OVERFLOW_CONNECTIONS`] more have their head read
//!   only to answer the busy page in the right size class; beyond, closed.
//! * Deadlines: PROXY line and head within [`HEADER_TIMEOUT`] of accept;
//!   body reads idle ≤ [`BODY_IDLE_TIMEOUT`] and bounded in total; writes
//!   bounded. `accept` errors (EMFILE …) back off and the loop continues
//!   (ADR-052(4)).
//! * One request per connection; after the response the write side is shut
//!   down and unread request bytes are drained briefly so the response is
//!   not lost to a reset, then the socket is closed.
//! * The handler runs in its own task: a panic becomes the fixed 500 page in
//!   unwinding builds (release builds abort, IMPL-00 §2) and no payload,
//!   location or input is ever printed (see [`crate::install_panic_hook`]).
//! * Nothing about a connection is logged or kept (no access log, A1).

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::{timeout, timeout_at};
use zeroize::Zeroizing;

use crate::app::{Reply, Web, head_error_reply};
use crate::config::StoreReads;
use crate::http::{Method, find_head_end, parse_head};
use crate::limits::{
    BODY_IDLE_TIMEOUT, FORM_TOTAL_TIMEOUT, HEADER_TIMEOUT, LINGER_BYTES, LINGER_TIMEOUT,
    MAX_CONNECTIONS, MAX_HEAD_BYTES, MAX_PROXY_LINE, UPLOAD_TOTAL_TIMEOUT, WRITE_TIMEOUT,
};
use crate::proxy::{find_line_end, parse_proxy_line};
use crate::ratelimit::CircuitToken;

/// Body read failure (content-free).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyError {
    /// The client stopped sending (idle or total deadline) or closed early.
    Stalled,
    /// The body is larger than the caller's limit.
    TooLarge,
}

/// The request body: bytes already read with the head, then the socket, up
/// to exactly `Content-Length`.
pub struct BodyReader {
    leftover: Zeroizing<Vec<u8>>,
    pos: usize,
    reader: Option<OwnedReadHalf>,
    remaining: u64,
    total: u64,
    deadline: Instant,
}

impl core::fmt::Debug for BodyReader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BodyReader")
    }
}

impl BodyReader {
    /// A body held entirely in memory (tests and the fuzz harness).
    #[must_use]
    pub fn from_bytes(b: Vec<u8>) -> Self {
        let total = u64::try_from(b.len()).unwrap_or(u64::MAX);
        Self {
            leftover: Zeroizing::new(b),
            pos: 0,
            reader: None,
            remaining: 0,
            total,
            deadline: Instant::now()
                .checked_add(FORM_TOTAL_TIMEOUT)
                .unwrap_or_else(Instant::now),
        }
    }

    /// `Content-Length`.
    #[must_use]
    pub fn content_length(&self) -> u64 {
        self.total
    }

    /// Allow the long upload deadline (multipart routes only).
    pub fn allow_upload_time(&mut self) {
        if let Some(t) = Instant::now().checked_add(UPLOAD_TOTAL_TIMEOUT) {
            self.deadline = t;
        }
    }

    /// The next at most `max` bytes, `None` at the end of the body.
    pub async fn next(&mut self, max: usize) -> Result<Option<Zeroizing<Vec<u8>>>, BodyError> {
        if max == 0 {
            return Ok(Some(Zeroizing::new(Vec::new())));
        }
        if self.pos < self.leftover.len() {
            let end = self.pos.saturating_add(max).min(self.leftover.len());
            let out = Zeroizing::new(self.leftover.get(self.pos..end).unwrap_or_default().to_vec());
            self.pos = end;
            return Ok(Some(out));
        }
        if self.remaining == 0 {
            return Ok(None);
        }
        let Some(r) = self.reader.as_mut() else {
            return Err(BodyError::Stalled);
        };
        let want = usize::try_from(self.remaining).unwrap_or(usize::MAX).min(max);
        let mut buf = Zeroizing::new(vec![0u8; want]);
        let idle_end = Instant::now()
            .checked_add(BODY_IDLE_TIMEOUT)
            .unwrap_or(self.deadline)
            .min(self.deadline);
        let n = match timeout_at(idle_end.into(), r.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return Err(BodyError::Stalled),
        };
        buf.truncate(n);
        self.remaining = self
            .remaining
            .saturating_sub(u64::try_from(n).unwrap_or(u64::MAX));
        Ok(Some(buf))
    }

    /// The whole body, at most `limit` bytes (checked before reading).
    pub async fn read_all(&mut self, limit: usize) -> Result<Zeroizing<Vec<u8>>, BodyError> {
        let total = usize::try_from(self.total).map_err(|_| BodyError::TooLarge)?;
        if total > limit {
            return Err(BodyError::TooLarge);
        }
        let mut out = Zeroizing::new(Vec::with_capacity(total));
        while let Some(chunk) = self.next(total.saturating_sub(out.len()).max(1)).await? {
            if chunk.is_empty() || out.len().saturating_add(chunk.len()) > total {
                return Err(BodyError::TooLarge);
            }
            out.extend_from_slice(&chunk);
            if out.len() == total {
                break;
            }
        }
        if out.len() != total {
            return Err(BodyError::Stalled);
        }
        Ok(out)
    }

    fn take_reader(&mut self) -> Option<OwnedReadHalf> {
        self.reader.take()
    }
}

/// Serve `listener` forever (returns only if the listener itself fails
/// permanently, which tokio does not report; transient accept errors back
/// off and continue).
pub async fn serve<S: StoreReads + 'static>(web: Arc<Web<S>>, listener: UnixListener) {
    let mut backoff = Duration::from_millis(10);
    loop {
        let stream = match listener.accept().await {
            Ok((s, _)) => {
                backoff = Duration::from_millis(10);
                s
            }
            Err(_) => {
                tokio::time::sleep(backoff).await;
                backoff = backoff.saturating_mul(2).min(Duration::from_secs(1));
                continue;
            }
        };
        let web2 = Arc::clone(&web);
        if let Ok(permit) = Arc::clone(&web.serving).try_acquire_owned() {
            tokio::spawn(async move {
                connection(web2, stream, false).await;
                drop(permit);
            });
        } else if let Ok(permit) = Arc::clone(&web.overflow).try_acquire_owned() {
            tokio::spawn(async move {
                connection(web2, stream, true).await;
                drop(permit);
            });
        } else {
            // Over both caps: close unread.
            drop(stream);
        }
    }
}

const _: () = assert!(MAX_CONNECTIONS > 0);

/// Read the PROXY line and the head, within [`HEADER_TIMEOUT`].
async fn read_head(stream: &mut UnixStream) -> Option<(u32, Zeroizing<Vec<u8>>, usize)> {
    let deadline = Instant::now().checked_add(HEADER_TIMEOUT)?;
    let cap = MAX_PROXY_LINE.saturating_add(MAX_HEAD_BYTES);
    let mut buf = Zeroizing::new(Vec::with_capacity(cap));
    let mut tmp = Zeroizing::new([0u8; 4096]);
    let mut circuit: Option<(u32, usize)> = None;
    loop {
        if circuit.is_none()
            && let Some(end) = find_line_end(&buf)
        {
            let id = parse_proxy_line(buf.get(..end)?)?;
            circuit = Some((id, end));
        }
        if circuit.is_none() && buf.len() >= MAX_PROXY_LINE {
            return None;
        }
        if let Some((id, start)) = circuit {
            let rest = buf.get(start..)?;
            if let Some(h) = find_head_end(rest) {
                return Some((id, buf, start.checked_add(h)?));
            }
            if rest.len() >= MAX_HEAD_BYTES {
                // Too large: report as an empty head so the caller answers
                // the uniform error page.
                return Some((id, buf, 0));
            }
        }
        let room = cap.saturating_sub(buf.len()).min(tmp.len());
        if room == 0 {
            return None;
        }
        let slot = tmp.get_mut(..room)?;
        let n = match timeout_at(deadline.into(), stream.read(slot)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return None,
        };
        buf.extend_from_slice(tmp.get(..n)?);
    }
}

async fn write_reply(w: &mut OwnedWriteHalf, reply: &Reply, head_only: bool) -> bool {
    let work = async {
        w.write_all(&reply.head).await?;
        if !head_only {
            w.write_all(reply.body.as_slice()).await?;
        }
        w.flush().await
    };
    matches!(timeout(WRITE_TIMEOUT, work).await, Ok(Ok(())))
}

/// After the response: shut down writing, drain unread bytes briefly.
async fn linger(mut w: OwnedWriteHalf, r: Option<OwnedReadHalf>) {
    let _ = w.shutdown().await;
    if let Some(mut r) = r {
        let mut sink = [0u8; 4096];
        let mut left = LINGER_BYTES;
        let end = Instant::now().checked_add(LINGER_TIMEOUT);
        while left > 0 {
            let Some(end) = end else { break };
            match timeout_at(end.into(), r.read(&mut sink)).await {
                Ok(Ok(n)) if n > 0 => left = left.saturating_sub(n),
                _ => break,
            }
        }
    }
}

async fn connection<S: StoreReads + 'static>(web: Arc<Web<S>>, mut stream: UnixStream, overflow: bool) {
    let received = Instant::now();
    let Some((circuit_id, buf, head_end)) = read_head(&mut stream).await else {
        return;
    };
    let circuit: CircuitToken = web.limiter.token(circuit_id);
    let proxy_end = find_line_end(&buf).unwrap_or(0);
    let head_bytes = buf.get(proxy_end..head_end).unwrap_or_default();
    let parsed = if head_end == 0 {
        Err(crate::http::HeadError {
            kind: crate::http::HeadErrorKind::Malformed,
            head: false,
            post: false,
            cookie: false,
        })
    } else {
        parse_head(head_bytes, &web.cfg.onion_host)
    };
    let (rd, mut wr) = stream.into_split();
    let head = match parsed {
        Ok(h) => h,
        Err(e) => {
            let reply = head_error_reply(&web, e.kind, e.head, e.post, e.cookie, circuit);
            if write_reply(&mut wr, &reply, e.head).await {
                linger(wr, Some(rd)).await;
            }
            return;
        }
    };
    let head_only = head.method == Method::Head;
    let leftover = Zeroizing::new(buf.get(head_end..).unwrap_or_default().to_vec());
    drop(buf);
    let cl = head.content_length.unwrap_or(0);
    let left = u64::try_from(leftover.len()).unwrap_or(u64::MAX);
    // Bytes beyond Content-Length (a pipelined or smuggled request): refused.
    // GET/HEAD bodies are refused too.
    let bad_framing = left > cl || (head.method != Method::Post && cl > 0);
    if overflow || bad_framing {
        let post = head.method == Method::Post;
        let cookie = head.session_cookie_present;
        let reply = if overflow {
            crate::app::busy_reply(&web, &head, circuit)
        } else {
            head_error_reply(
                &web,
                crate::http::HeadErrorKind::Malformed,
                head_only,
                post,
                cookie,
                circuit,
            )
        };
        if write_reply(&mut wr, &reply, head_only).await {
            linger(wr, Some(rd)).await;
        }
        return;
    }
    let body = BodyReader {
        leftover,
        pos: 0,
        reader: Some(rd),
        remaining: cl.saturating_sub(left),
        total: cl,
        deadline: received
            .checked_add(FORM_TOTAL_TIMEOUT)
            .unwrap_or(received),
    };
    let post_or_cookie = head.method == Method::Post || head.session_cookie_present;
    let task = tokio::spawn(Arc::clone(&web).handle(head, circuit, received, body));
    let (reply, rd) = match task.await {
        Ok((reply, mut body)) => (reply, body.take_reader()),
        // A panic in the handler (unwinding builds): the fixed 500 page.
        Err(_) => (web.fallback(post_or_cookie), None),
    };
    if write_reply(&mut wr, &reply, head_only).await {
        linger(wr, rd).await;
    }
}
