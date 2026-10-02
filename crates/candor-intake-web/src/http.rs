// SPDX-License-Identifier: AGPL-3.0-or-later
//! Strict HTTP/1.1 request-head parser and response-head serializer
//! (07 §5.1, IMPL-00 §7, IMPL-RM2 §2.6; ST-044, ST-075).
//!
//! Request heads are tokenized by `httparse` (lead decision, SPEC-NOTES
//! decision 1); the policy below is applied on top of it.
//!
//! The service speaks the smallest HTTP/1.1 subset Tor Browser needs: one
//! request per connection (the connection is closed after the response, so
//! there is no pipelining and no request smuggling across requests), origin-
//! form targets without query strings, `Content-Length` framing only. Anything
//! else is refused:
//!
//! * `Transfer-Encoding` (any value), `Content-Encoding`, `Expect`, `Upgrade`,
//!   `TE` (ambiguous framing and compression, INC-116, RUSTSEC-2020-0008 class);
//! * obsolete line folding, bare CR or LF, whitespace before a colon, a field
//!   name that is not a token, a control byte in a value;
//! * more than [`MAX_HEADERS`] fields, a head over [`MAX_HEAD_BYTES`], a request
//!   line over [`MAX_REQUEST_LINE`];
//! * a version other than `HTTP/1.1`, a missing or foreign `Host`;
//! * a second `Host`, `Content-Length`, `Content-Type`, `Cookie`, `Origin` or
//!   `Sec-Fetch-Site`, and a second `__Host-cs` / `__Host-cpre` cookie;
//! * a POST without `Content-Length`.
//!
//! Only these headers are interpreted. `User-Agent`, `Accept-Language` and
//! every other header are syntax-checked and dropped unread (A1: nothing about
//! the client is kept). The parser is a pure function over bytes: it never
//! panics, allocates only bounded strings, and is fuzzed (`fuzz_http_request`)
//! and property-tested.

use zeroize::Zeroizing;

use crate::limits::{MAX_HEAD_BYTES, MAX_HEADERS, MAX_PATH, MAX_REQUEST_LINE};

/// Name of the session cookie (11 §5.6).
pub const SESSION_COOKIE: &str = "__Host-cs";
/// Name of the pre-session cookie (11 §5.6, AUD-RM1-SUI-06).
pub const PRE_SESSION_COOKIE: &str = "__Host-cpre";
/// Length of our cookie values: 32 random bytes as lowercase hex.
pub const COOKIE_VALUE_LEN: usize = 64;

/// Accepted request methods (11 §5.3: GET, HEAD, POST; others get 405).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// GET.
    Get,
    /// HEAD (same head as GET, no body).
    Head,
    /// POST.
    Post,
}

/// The `Origin` request header (08 §3.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginHeader {
    /// Not sent.
    Absent,
    /// `Origin: null` (what browsers send for a POST under
    /// `Referrer-Policy: no-referrer`, Fetch §3.1).
    Null,
    /// Any other value (compared exactly with the onion origin).
    Value(String),
}

/// The `Sec-Fetch-Site` request header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchSite {
    /// Not sent (older browsers).
    Absent,
    /// `same-origin`.
    SameOrigin,
    /// `none`, `same-site`, `cross-site` or anything else.
    Other,
}

/// A parsed request head. Holds no client metadata: no address, no
/// `User-Agent`, no `Accept-Language`, no time.
#[derive(Clone)]
pub struct RequestHead {
    /// Method.
    pub method: Method,
    /// Path if it consists only of `[A-Za-z0-9/._-]` and starts with `/`
    /// (≤ [`MAX_PATH`]); `None` otherwise (the uniform 404).
    pub path: Option<String>,
    /// `Content-Length`, if sent.
    pub content_length: Option<u64>,
    /// `Content-Type`, if sent (ASCII, as sent).
    pub content_type: Option<String>,
    /// `Origin`.
    pub origin: OriginHeader,
    /// `Sec-Fetch-Site`.
    pub fetch_site: FetchSite,
    /// A `__Host-cs` cookie was sent (well-formed or not): with the method
    /// this alone decides the size class (11 §5.4).
    pub session_cookie_present: bool,
    /// The `__Host-cs` value, if well-formed (64 lowercase hex characters).
    pub session_cookie: Option<Zeroizing<String>>,
    /// The `__Host-cpre` value, if well-formed.
    pub pre_cookie: Option<Zeroizing<String>>,
}

impl core::fmt::Debug for RequestHead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // No path (could carry probing input), no cookie values.
        f.debug_struct("RequestHead")
            .field("method", &self.method)
            .field("session_cookie_present", &self.session_cookie_present)
            .finish_non_exhaustive()
    }
}

/// Why a head was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadErrorKind {
    /// Syntax, framing or policy violation (uniform error page).
    Malformed,
    /// A well-formed method other than GET, HEAD or POST (405, SUI-056).
    MethodNotAllowed,
}

/// A refused head, with what is known for choosing the size class of the
/// error page: whether the method was POST and whether a session cookie was
/// sent (best effort; unknown → GET without cookie).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadError {
    /// Kind.
    pub kind: HeadErrorKind,
    /// The method was HEAD (the error response carries no body).
    pub head: bool,
    /// The method was POST.
    pub post: bool,
    /// A `__Host-cs` cookie was seen.
    pub cookie: bool,
}

/// Index just past the `CRLF CRLF` that ends the head, if present in `buf`.
#[must_use]
pub fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .and_then(|i| i.checked_add(4))
}

fn is_field_vchar(b: u8) -> bool {
    // VCHAR, SP, HTAB, obs-text. No CTL, no DEL.
    b == b'\t' || b == b' ' || (0x21..=0x7e).contains(&b) || b >= 0x80
}

fn trim_ows(v: &[u8]) -> &[u8] {
    let start = v
        .iter()
        .position(|b| *b != b' ' && *b != b'\t')
        .unwrap_or(v.len());
    let end = v
        .iter()
        .rposition(|b| *b != b' ' && *b != b'\t')
        .map_or(start, |i| i.saturating_add(1));
    v.get(start..end).unwrap_or_default()
}

fn ascii_string(v: &[u8]) -> Option<String> {
    if v.iter().all(|b| (0x20..=0x7e).contains(b)) {
        String::from_utf8(v.to_vec()).ok()
    } else {
        None
    }
}

/// Our cookie values: exactly 64 lowercase hex characters.
#[must_use]
pub fn valid_cookie_value(v: &[u8]) -> bool {
    v.len() == COOKIE_VALUE_LEN
        && v.iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

fn path_ok(p: &[u8]) -> bool {
    p.first() == Some(&b'/')
        && p.len() <= MAX_PATH
        && p.iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
}

struct Cookies {
    present: bool,
    session: Option<Zeroizing<String>>,
    pre: Option<Zeroizing<String>>,
}

/// Parse a `Cookie` header value. `Err` on a duplicated cookie of ours.
fn parse_cookies(v: &[u8]) -> Result<Cookies, ()> {
    let mut out = Cookies {
        present: false,
        session: None,
        pre: None,
    };
    let mut seen_pre = false;
    for piece in v.split(|b| *b == b';') {
        let piece = trim_ows(piece);
        let Some(eq) = piece.iter().position(|b| *b == b'=') else {
            continue;
        };
        let (name, value) = piece.split_at(eq);
        let value = value.get(1..).unwrap_or_default();
        if name == SESSION_COOKIE.as_bytes() {
            if out.present {
                return Err(());
            }
            out.present = true;
            if valid_cookie_value(value) {
                out.session = ascii_string(value).map(Zeroizing::new);
            }
        } else if name == PRE_SESSION_COOKIE.as_bytes() {
            if seen_pre {
                return Err(());
            }
            seen_pre = true;
            if valid_cookie_value(value) {
                out.pre = ascii_string(value).map(Zeroizing::new);
            }
        }
    }
    Ok(out)
}

/// Best-effort size class of a refused head (11 §5.4: method and session
/// cookie presence). Used only to pick the error page's class when the head
/// is too broken to tokenize; never to accept anything.
fn rough_class(buf: &[u8]) -> HeadError {
    let cookie_marker = b"__Host-cs=";
    HeadError {
        kind: HeadErrorKind::Malformed,
        head: buf.starts_with(b"HEAD "),
        post: buf.starts_with(b"POST "),
        cookie: buf.windows(cookie_marker.len()).any(|w| w == cookie_marker),
    }
}

/// Policy checks over the raw bytes that httparse is more lenient about:
/// every line ends in CRLF (no bare CR or LF anywhere, httparse accepts bare
/// LF), no empty line before the request line (httparse skips those), no
/// obsolete line folding, and a bounded request line.
fn raw_line_discipline(buf: &[u8]) -> bool {
    if !buf.ends_with(b"\r\n\r\n") || buf.starts_with(b"\r\n") {
        return false;
    }
    for (i, b) in buf.iter().enumerate() {
        let next = buf.get(i.saturating_add(1)).copied();
        let prev = i.checked_sub(1).and_then(|j| buf.get(j)).copied();
        match b {
            b'\r' if next != Some(b'\n') => return false,
            b'\n' if prev != Some(b'\r') => return false,
            // obs-fold: a line that starts with SP or HTAB.
            b'\n' if matches!(next, Some(b' ' | b'\t')) => return false,
            _ => {}
        }
    }
    buf.windows(2)
        .position(|w| w == b"\r\n")
        .is_some_and(|n| n <= MAX_REQUEST_LINE)
}

/// Parse a complete request head (`buf` ends with the blank line, as found by
/// [`find_head_end`]). `host` is the onion host name the `Host` header must
/// equal (ASCII case-insensitive, no port).
///
/// Tokenization is httparse's (lead decision, SPEC-NOTES decision 1); the
/// strict-subset policy is applied on top: raw CRLF discipline, HTTP/1.1
/// only, origin-form targets, at most [`MAX_HEADERS`] fields, refused
/// framing headers, no duplicates of the interpreted headers, and a
/// `Content-Length` on every POST.
pub fn parse_head(buf: &[u8], host: &str) -> Result<RequestHead, HeadError> {
    let mut err = rough_class(buf);
    if buf.len() > MAX_HEAD_BYTES || !raw_line_discipline(buf) {
        return Err(err);
    }
    let mut fields = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut fields);
    // Default config: single SPs in the request line, no obs-fold, invalid
    // header lines are errors (not skipped).
    match httparse::ParserConfig::default().parse_request(&mut req, buf) {
        Ok(httparse::Status::Complete(n)) if n == buf.len() => {}
        _ => return Err(err),
    }
    let (Some(m), Some(target), Some(version)) = (req.method, req.path, req.version) else {
        return Err(err);
    };
    let target = target.as_bytes();
    // Cookie presence is re-derived below from the parsed field.
    err.cookie = false;
    let method = match m {
        "GET" => Method::Get,
        "HEAD" => Method::Head,
        "POST" => Method::Post,
        _ => {
            // A valid token (httparse checked it): 405 (SUI-056), but only for
            // an otherwise sane request line.
            if version == 1 && target.first() == Some(&b'/') {
                err.kind = HeadErrorKind::MethodNotAllowed;
            }
            return Err(err);
        }
    };
    err.post = method == Method::Post;
    err.head = method == Method::Head;
    if version != 1 {
        return Err(err);
    }
    // Origin-form only (no absolute-form, authority-form or `*`), visible
    // ASCII only.
    if target.first() != Some(&b'/') || !target.iter().all(|b| (0x21..=0x7e).contains(b)) {
        return Err(err);
    }
    let path = if path_ok(target) {
        ascii_string(target)
    } else {
        None
    };

    let mut host_seen = false;
    let mut content_length: Option<u64> = None;
    let mut content_type: Option<String> = None;
    let mut origin = OriginHeader::Absent;
    let mut origin_seen = false;
    let mut fetch_site = FetchSite::Absent;
    let mut fetch_seen = false;
    let mut cookies: Option<Cookies> = None;
    let mut bad = false;
    for field in req.headers.iter() {
        let value = trim_ows(field.value);
        if field.name.is_empty() || !value.iter().all(|b| is_field_vchar(*b)) {
            return Err(err);
        }
        let lower = field.name.to_ascii_lowercase();
        match lower.as_str() {
            "host" => {
                if host_seen || !value.eq_ignore_ascii_case(host.as_bytes()) {
                    bad = true;
                }
                host_seen = true;
            }
            "content-length" => {
                if content_length.is_some()
                    || value.is_empty()
                    || value.len() > 19
                    || !value.iter().all(u8::is_ascii_digit)
                {
                    bad = true;
                } else {
                    let s = core::str::from_utf8(value).map_err(|_| err)?;
                    content_length = Some(s.parse::<u64>().map_err(|_| err)?);
                }
            }
            "content-type" => {
                if content_type.is_some() {
                    bad = true;
                }
                content_type = ascii_string(value);
                if content_type.is_none() {
                    bad = true;
                }
            }
            "origin" => {
                if origin_seen {
                    bad = true;
                }
                origin_seen = true;
                origin = match value {
                    b"null" => OriginHeader::Null,
                    v => match ascii_string(v) {
                        Some(s) => OriginHeader::Value(s),
                        None => {
                            bad = true;
                            OriginHeader::Absent
                        }
                    },
                };
            }
            "sec-fetch-site" => {
                if fetch_seen {
                    bad = true;
                }
                fetch_seen = true;
                fetch_site = if value == b"same-origin" {
                    FetchSite::SameOrigin
                } else {
                    FetchSite::Other
                };
            }
            "cookie" => {
                if cookies.is_some() {
                    bad = true;
                    continue;
                }
                match parse_cookies(value) {
                    Ok(c) => {
                        err.cookie = c.present;
                        cookies = Some(c);
                    }
                    Err(()) => {
                        err.cookie = true;
                        bad = true;
                    }
                }
            }
            // Ambiguous framing, compression and protocol switches.
            "transfer-encoding" | "content-encoding" | "expect" | "upgrade" | "te"
            | "http2-settings" | "trailer" => bad = true,
            _ => {}
        }
    }
    // Content-Length framing is mandatory for POST (no chunked, no
    // read-until-close).
    if method == Method::Post && content_length.is_none() {
        bad = true;
    }
    if bad || !host_seen {
        return Err(err);
    }
    let cookies = cookies.unwrap_or(Cookies {
        present: false,
        session: None,
        pre: None,
    });
    Ok(RequestHead {
        method,
        path,
        content_length,
        content_type,
        origin,
        fetch_site,
        session_cookie_present: cookies.present,
        session_cookie: cookies.session,
        pre_cookie: cookies.pre,
    })
}

/// Serialize the response head exactly as the source-UI contract requires
/// (AUD-RM1-SUI-05 item 7): `HTTP/1.1 {status} {reason}\r\n`, every header of
/// the page in order as `Name: value\r\n`, then `\r\n`. Nothing is added.
/// `None` if the status has no reason phrase or the result is not exactly
/// the class head length (fail closed: the caller sends the fallback page).
#[must_use]
pub fn serialize_head(page: &candor_source_ui::Page) -> Option<Zeroizing<Vec<u8>>> {
    let reason = candor_source_ui::reason_phrase(page.status)?;
    let want = page.class.head_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(want));
    out.extend_from_slice(b"HTTP/1.1 ");
    out.extend_from_slice(page.status.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(reason.as_bytes());
    out.extend_from_slice(b"\r\n");
    for (name, value) in &page.headers {
        if value.bytes().any(|b| b == b'\r' || b == b'\n') {
            return None;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    (out.len() == want && page.head_len() == Some(want)).then_some(out)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    const HOST: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

    fn req(lines: &[&str]) -> Vec<u8> {
        let mut s = lines.join("\r\n");
        s.push_str("\r\n\r\n");
        s.into_bytes()
    }

    #[test]
    fn minimal_get() {
        let h = parse_head(&req(&["GET /en/ HTTP/1.1", &format!("Host: {HOST}")]), HOST).unwrap();
        assert_eq!(h.method, Method::Get);
        assert_eq!(h.path.as_deref(), Some("/en/"));
        assert!(!h.session_cookie_present);
    }

    #[test]
    fn query_string_is_not_a_route() {
        let h = parse_head(
            &req(&["GET /en/?x=1 HTTP/1.1", &format!("Host: {HOST}")]),
            HOST,
        )
        .unwrap();
        assert_eq!(h.path, None);
    }

    #[test]
    fn cookies_parsed_and_validated() {
        let cs = "a".repeat(64);
        let h = parse_head(
            &req(&[
                "POST /en/q HTTP/1.1",
                &format!("Host: {HOST}"),
                &format!("Cookie: other=1; __Host-cs={cs}; __Host-cpre=zz"),
                "Content-Length: 0",
            ]),
            HOST,
        )
        .unwrap();
        assert!(h.session_cookie_present);
        assert_eq!(
            h.session_cookie.as_deref().map(String::as_str),
            Some(cs.as_str())
        );
        assert!(h.pre_cookie.is_none(), "malformed value dropped");
        // Duplicate session cookie: refused, class still known (POST + cookie).
        let e = parse_head(
            &req(&[
                "POST /en/q HTTP/1.1",
                &format!("Host: {HOST}"),
                &format!("Cookie: __Host-cs={cs}; __Host-cs={cs}"),
            ]),
            HOST,
        )
        .unwrap_err();
        assert!(e.post && e.cookie);
    }

    #[test]
    fn rejects_ambiguous_framing_and_bad_syntax() {
        let host = format!("Host: {HOST}");
        let cases: Vec<Vec<u8>> = vec![
            req(&["POST /en/q HTTP/1.1", &host, "Transfer-Encoding: chunked"]),
            req(&[
                "POST /en/q HTTP/1.1",
                &host,
                "Content-Length: 5",
                "Transfer-Encoding: chunked",
            ]),
            req(&[
                "POST /en/q HTTP/1.1",
                &host,
                "Content-Length: 5",
                "Content-Length: 5",
            ]),
            req(&["POST /en/q HTTP/1.1", &host, "Content-Length: +5"]),
            req(&["POST /en/q HTTP/1.1", &host, "Content-Length: 5, 5"]),
            req(&["POST /en/q HTTP/1.1", &host, "Content-Encoding: gzip"]),
            req(&["POST /en/q HTTP/1.1", &host, "Expect: 100-continue"]),
            req(&["GET /en/ HTTP/1.1", &host, "X: a", " folded"]),
            req(&["GET /en/ HTTP/1.1", &host, "X : a"]),
            req(&["GET /en/ HTTP/1.1", &host, "X\x01: a"]),
            req(&["GET /en/ HTTP/1.1", &host, "X: a\x7fb"]),
            req(&["GET /en/ HTTP/1.0", &host]),
            req(&["GET  /en/ HTTP/1.1", &host]),
            req(&["GET http://x/en/ HTTP/1.1", &host]),
            req(&["GET /en/ HTTP/1.1"]),
            req(&["GET /en/ HTTP/1.1", "Host: evil.onion"]),
            req(&["GET /en/ HTTP/1.1", &host, &host]),
            b"GET /en/ HTTP/1.1\nHost: x\n\n".to_vec(),
            b"GET /en/ HTTP/1.1\r\nHost: a\rb\r\n\r\n".to_vec(),
        ];
        for c in &cases {
            let e = parse_head(c, HOST).unwrap_err();
            assert_eq!(
                e.kind,
                HeadErrorKind::Malformed,
                "{:?}",
                String::from_utf8_lossy(c)
            );
        }
    }

    #[test]
    fn other_methods_get_405() {
        let e =
            parse_head(&req(&["PUT /en/ HTTP/1.1", &format!("Host: {HOST}")]), HOST).unwrap_err();
        assert_eq!(e.kind, HeadErrorKind::MethodNotAllowed);
    }

    #[test]
    fn header_count_bounded() {
        let mut l = vec!["GET /en/ HTTP/1.1".to_owned(), format!("Host: {HOST}")];
        for i in 0..MAX_HEADERS {
            l.push(format!("X-{i}: v"));
        }
        let refs: Vec<&str> = l.iter().map(String::as_str).collect();
        assert!(parse_head(&req(&refs), HOST).is_err());
    }

    #[test]
    fn head_end_found() {
        assert_eq!(find_head_end(b"a\r\n\r\nrest"), Some(5));
        assert_eq!(find_head_end(b"a\r\n\r"), None);
    }

    proptest::proptest! {
        /// ST-044: arbitrary bytes never panic.
        #[test]
        fn parse_total(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048)) {
            let _ = parse_head(&data, HOST);
            let _ = find_head_end(&data);
        }

        /// Arbitrary header values never make a well-formed request panic,
        /// and values with CR/LF/CTL are refused.
        #[test]
        fn header_values(v in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256)) {
            let mut b = format!("GET /en/ HTTP/1.1\r\nHost: {HOST}\r\nX-T: ").into_bytes();
            b.extend_from_slice(&v);
            b.extend_from_slice(b"\r\n\r\n");
            let r = parse_head(&b, HOST);
            let line_break = v.iter().any(|c| *c == b'\r' || *c == b'\n');
            if !line_break && v.iter().any(|c| (*c < 0x20 && *c != b'\t') || *c == 0x7f) {
                proptest::prop_assert!(r.is_err());
            }
        }
    }
}
