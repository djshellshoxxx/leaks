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
    MAX_CONNECTIONS, MAX_HEAD_BYTES, MAX_PROXY_LINE, MIN_UPLOAD_RATE, UPLOAD_GRACE,
    UPLOAD_TOTAL_TIMEOUT, WRITE_TIMEOUT,
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
    /// Upload mode (AUD-RM2-WEB-07): when the minimum-rate clock started and
    /// how many body bytes have been delivered since.
    rate: Option<(Instant, u64)>,
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
            rate: None,
        }
    }

    /// `Content-Length`.
    #[must_use]
    pub fn content_length(&self) -> u64 {
        self.total
    }

    /// Upload mode (multipart routes only, AUD-RM2-WEB-07): the deadline
    /// becomes [`UPLOAD_GRACE`] + `Content-Length` / [`MIN_UPLOAD_RATE`]
    /// (at most [`UPLOAD_TOTAL_TIMEOUT`]), and every read must keep the
    /// average rate since now at or above [`MIN_UPLOAD_RATE`] after the
    /// grace period, so a trickle cannot hold the slot.
    pub fn allow_upload_time(&mut self) {
        let now = Instant::now();
        let budget = UPLOAD_GRACE
            .saturating_add(rate_time(self.total))
            .min(UPLOAD_TOTAL_TIMEOUT);
        if let Some(t) = now.checked_add(budget) {
            self.deadline = t;
        }
        self.rate = Some((now, 0));
    }

    /// The latest time the next byte may arrive under the rate floor.
    fn rate_deadline(&self) -> Option<Instant> {
        let (start, got) = self.rate?;
        start.checked_add(UPLOAD_GRACE.saturating_add(rate_time(got)))
    }

    fn delivered(&mut self, n: usize) {
        if let Some((_, got)) = self.rate.as_mut() {
            *got = got.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        }
    }

    /// The next at most `max` bytes, `None` at the end of the body.
    pub async fn next(&mut self, max: usize) -> Result<Option<Zeroizing<Vec<u8>>>, BodyError> {
        if max == 0 {
            return Ok(Some(Zeroizing::new(Vec::new())));
        }
        if self.pos < self.leftover.len() {
            let end = self.pos.saturating_add(max).min(self.leftover.len());
            let out = Zeroizing::new(
                self.leftover
                    .get(self.pos..end)
                    .unwrap_or_default()
                    .to_vec(),
            );
            self.pos = end;
            self.delivered(out.len());
            return Ok(Some(out));
        }
        if self.remaining == 0 {
            return Ok(None);
        }
        let mut idle_end = Instant::now()
            .checked_add(BODY_IDLE_TIMEOUT)
            .unwrap_or(self.deadline)
            .min(self.deadline);
        if let Some(r) = self.rate_deadline() {
            idle_end = idle_end.min(r);
        }
        let Some(r) = self.reader.as_mut() else {
            return Err(BodyError::Stalled);
        };
        let want = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(max);
        let mut buf = Zeroizing::new(vec![0u8; want]);
        let n = match timeout_at(idle_end.into(), r.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return Err(BodyError::Stalled),
        };
        buf.truncate(n);
        self.delivered(n);
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

    /// Read the rest of a small body (at most `limit` bytes in total) into
    /// memory now, so that later reads are served from it. Used to anchor
    /// the login floor at the end of the full request (AUD-RM2-WEB-06). A
    /// larger body is left unread (the route refuses it); a failed read
    /// leaves the reader failing, as it would have anyway.
    pub async fn buffer_all(&mut self, limit: usize) {
        let Ok(total) = usize::try_from(self.total) else {
            return;
        };
        if total > limit || self.remaining == 0 {
            return;
        }
        let mut out = Zeroizing::new(Vec::with_capacity(total));
        out.extend_from_slice(self.leftover.get(self.pos..).unwrap_or_default());
        while out.len() < total {
            let want = total.saturating_sub(out.len());
            // Serve from the socket only (leftover already copied).
            self.pos = self.leftover.len();
            match self.next(want).await {
                Ok(Some(c)) if !c.is_empty() => out.extend_from_slice(&c),
                _ => {
                    self.reader = None;
                    return;
                }
            }
        }
        self.leftover = out;
        self.pos = 0;
    }

    fn take_reader(&mut self) -> Option<OwnedReadHalf> {
        self.reader.take()
    }
}

/// Time to transfer `bytes` at [`MIN_UPLOAD_RATE`].
fn rate_time(bytes: u64) -> Duration {
    Duration::from_millis(
        bytes
            .saturating_mul(1000)
            .checked_div(MIN_UPLOAD_RATE)
            .unwrap_or(u64::MAX),
    )
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
    // Head-end search resumes here (no `CRLF CRLF` starts before it): the
    // per-read cost is linear in the new bytes (AUD-RM2-WEB-02 class).
    let mut scanned = 0usize;
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
            let from = scanned.min(rest.len());
            if let Some(h) = find_head_end(rest.get(from..)?) {
                return Some((id, buf, start.checked_add(from)?.checked_add(h)?));
            }
            scanned = rest.len().saturating_sub(3);
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

async fn connection<S: StoreReads + 'static>(
    web: Arc<Web<S>>,
    mut stream: UnixStream,
    overflow: bool,
) {
    let Some((circuit_id, buf, head_end)) = read_head(&mut stream).await else {
        return;
    };
    // AUD-RM2-WEB-06: request time starts when the head is complete, so a
    // client cannot spend its own login floor on a slow head.
    let received = Instant::now();
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
        deadline: received.checked_add(FORM_TOTAL_TIMEOUT).unwrap_or(received),
        rate: None,
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;

    /// AUD-RM2-WEB-07: an upload's deadline scales with its declared size
    /// (grace + size at the minimum rate, ≤ 4 h), and every read must keep
    /// the average rate since the start at or above the floor.
    #[test]
    fn upload_deadlines_follow_the_minimum_rate() {
        let mut b = BodyReader::from_bytes(vec![0u8; 10]);
        b.total = 1_024_000; // 1000 s at 1 KiB/s
        let before = Instant::now();
        b.allow_upload_time();
        let (start, got) = b.rate.unwrap();
        assert_eq!(got, 0);
        assert!(start >= before);
        assert_eq!(b.deadline, start + UPLOAD_GRACE + Duration::from_secs(1000));
        // Nothing delivered yet: the next byte is due within the grace.
        assert_eq!(b.rate_deadline().unwrap(), start + UPLOAD_GRACE);
        // 10 KiB delivered buys 10 more seconds, no more.
        b.delivered(10 * 1024);
        assert_eq!(
            b.rate_deadline().unwrap(),
            start + UPLOAD_GRACE + Duration::from_secs(10)
        );
        // A huge declared size is still capped at 4 h.
        let mut big = BodyReader::from_bytes(Vec::new());
        big.total = u64::MAX;
        big.allow_upload_time();
        let (s2, _) = big.rate.unwrap();
        assert_eq!(big.deadline, s2 + UPLOAD_TOTAL_TIMEOUT);
        // Forms have no rate clock.
        assert!(BodyReader::from_bytes(Vec::new()).rate_deadline().is_none());
    }
}
