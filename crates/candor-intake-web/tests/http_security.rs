// SPDX-License-Identifier: AGPL-3.0-or-later
//! HTTP security suite over the Unix socket (IMPL-RM2 §5 `http_security`):
//! ST-071 CSRF matrix, ST-075 smuggling corpus, ST-065 route registry,
//! ST-079 rate limits, ST-101 slow requests, AT-017/AT-018 no reflection,
//! NET-012 PROXY line required, A5 uniform responses.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use std::time::{Duration, Instant};

use candor_sealer::proto::Op;
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// ST-071: every POST needs the token and acceptable `Origin` /
/// `Sec-Fetch-Site` before anything changes. Rejections are the uniform
/// error page and reach the sealer with no operation at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn csrf_matrix() {
    let h = harness().await;
    let (pre, tok) = h.pre().await;
    let body = format!("csrf={tok}&channel_id={}&mode=anonymous", "c1".repeat(16));
    let cases: Vec<(&str, Vec<&str>, String)> = vec![
        (
            "missing token",
            vec![&pre],
            format!("channel_id={}&mode=anonymous", "c1".repeat(16)),
        ),
        (
            "wrong token",
            vec![&pre],
            format!(
                "csrf={}&channel_id={}&mode=anonymous",
                "a".repeat(64),
                "c1".repeat(16)
            ),
        ),
        ("no pre-session cookie", vec![], body.clone()),
        (
            "foreign pre-session cookie",
            vec!["__Host-cpre=0000000000000000000000000000000000000000000000000000000000000000"],
            body.clone(),
        ),
        ("unknown field", vec![&pre], format!("{body}&evil=1")),
        (
            "duplicate field",
            vec![&pre],
            format!("{body}&mode=anonymous"),
        ),
    ];
    for (why, cookies, b) in &cases {
        let r = h.post_on(9, "/en/new", cookies, b).await;
        assert_eq!(r.status, 500, "{why}");
    }
    // Header checks (before the body is read).
    let https = format!("Origin: https://{HOST}");
    let bad_headers: Vec<(&str, Vec<&str>)> = vec![
        (
            "foreign origin",
            vec!["Origin: http://evil.onion", "Sec-Fetch-Site: same-origin"],
        ),
        (
            "https origin",
            vec![https.as_str(), "Sec-Fetch-Site: same-origin"],
        ),
        (
            "cross-site",
            vec!["Origin: null", "Sec-Fetch-Site: cross-site"],
        ),
        (
            "same-site",
            vec!["Origin: null", "Sec-Fetch-Site: same-site"],
        ),
        ("none", vec!["Origin: null", "Sec-Fetch-Site: none"]),
        ("two origins", vec!["Origin: null", "Origin: null"]),
    ];
    for (why, extra) in bad_headers {
        let mut req = format!(
            "POST /en/new HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nCookie: {pre}\r\n",
            body.len()
        );
        for e in &extra {
            req.push_str(e);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");
        req.push_str(&body);
        let r = parse(&raw(&h.web_sock, 2, req.as_bytes()).await);
        assert_eq!(r.status, 500, "{why}");
    }
    assert!(
        h.sealer.ops().is_empty(),
        "no rejected request reached the sealer"
    );
    // The exact onion origin and the absent headers are accepted.
    let s = String::from_utf8(post_req("/en/new", &[&pre], &body, &[])).unwrap();
    let s = s.replace("Origin: null", &format!("Origin: {ORIGIN}"));
    let r = parse(&raw(&h.web_sock, 3, s.as_bytes()).await);
    assert_eq!(r.status, 200);
    // A session token is not a pre-session token and vice versa; another
    // session's token is refused.
    let (cs1, tok1) = h.start("anonymous").await;
    let (_cs2, tok2) = h.start("anonymous").await;
    assert_ne!(tok1, tok2);
    let r = h
        .post("/en/concerns", &[&cs1], &format!("csrf={tok2}"))
        .await;
    assert_eq!(r.status, 500);
    let r = h
        .post("/en/concerns", &[&cs1], &format!("csrf={tok}"))
        .await;
    assert_eq!(r.status, 500);
    let r = h
        .post("/en/concerns", &[&cs1], &format!("csrf={tok1}"))
        .await;
    assert_eq!(r.status, 200);
}

/// ST-075 smuggling / framing corpus: every ambiguous request gets exactly
/// one uniform error response and the connection is closed (no second
/// request is ever parsed from the same connection).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn smuggling_corpus() {
    let h = harness().await;
    let host = format!("Host: {HOST}");
    let corpus: Vec<String> = vec![
        format!("POST /en/login HTTP/1.1\r\n{host}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
        format!(
            "POST /en/login HTTP/1.1\r\n{host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        ),
        format!(
            "POST /en/login HTTP/1.1\r\n{host}\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n"
        ),
        format!(
            "POST /en/login HTTP/1.1\r\n{host}\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nabcd"
        ),
        format!("POST /en/login HTTP/1.1\r\n{host}\r\nContent-Length : 4\r\n\r\nabcd"),
        format!(
            "POST /en/login HTTP/1.1\r\n{host}\r\nContent-Length: 4\r\n Transfer-Encoding: chunked\r\n\r\nabcd"
        ),
        format!(
            "POST /en/login HTTP/1.1\r\n{host}\r\nTransfer-Encoding:\tchunked\r\n\r\n0\r\n\r\n"
        ),
        format!("POST /en/login HTTP/1.1\n{host}\nContent-Length: 0\n\n"),
        format!("GET /en/ HTTP/1.1\r\n{host}\r\nContent-Length: 5\r\n\r\nGET /"),
        // Pipelining: a second request after the first one's body.
        format!(
            "POST /en/leave HTTP/1.1\r\n{host}\r\nContent-Length: 0\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nGET /en/ HTTP/1.1\r\n{host}\r\n\r\n"
        ),
        format!("GET /en/ HTTP/1.1\r\n{host}\r\n\r\nGET /en/status HTTP/1.1\r\n{host}\r\n\r\n"),
        format!("GET /en/ HTTP/2.0\r\n{host}\r\n\r\n"),
        format!("GET /en/ HTTP/1.1\r\nHost: other.onion\r\n\r\n"),
        format!("GET /en/ HTTP/1.1\r\n{host}\r\nUpgrade: h2c\r\nHTTP2-Settings: AAA\r\n\r\n"),
        format!("GET /en/ HTTP/1.1\r\n{host}\r\nExpect: 100-continue\r\n\r\n"),
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_owned(),
    ];
    for (i, req) in corpus.iter().enumerate() {
        let out = raw(&h.web_sock, 10 + i as u32, req.as_bytes()).await;
        if out.is_empty() {
            // No CRLF CRLF at all (bare LF): closed unparsed, no response.
            assert!(!req.contains("\r\n\r\n"), "case {i}");
            continue;
        }
        let r = parse(&out);
        // Exactly one response: the head plus one padded body.
        assert_eq!(
            out.len(),
            2048 + r.body.len(),
            "case {i}: one response only"
        );
        assert!(
            r.body.len() == 65_536 || r.body.len() == 131_072,
            "case {i}"
        );
        assert!(
            [404, 405, 500].contains(&r.status),
            "case {i}: status {}",
            r.status
        );
    }
    assert!(h.sealer.ops().is_empty());
}

/// NET-012 / NET-001: a stream without tor's PROXY line is never served, and
/// a malformed PROXY line closes the connection without a byte.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_line_required() {
    let h = harness().await;
    for pre in [
        "".to_owned(),
        "PROXY TCP4 10.0.0.1 10.0.0.2 1 80\r\n".to_owned(),
        "PROXY UNKNOWN\r\n".to_owned(),
    ] {
        let mut s = tokio::net::UnixStream::connect(&h.web_sock).await.unwrap();
        let req = format!("{pre}GET /en/ HTTP/1.1\r\nHost: {HOST}\r\n\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        s.shutdown().await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(15), s.read_to_end(&mut out)).await;
        assert!(out.is_empty(), "no response without a valid PROXY line");
    }
}

/// ST-101: a client that stops sending its head is cut off at the 10 s
/// header deadline without a response.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slowloris_head_deadline() {
    let h = harness().await;
    let mut s = tokio::net::UnixStream::connect(&h.web_sock).await.unwrap();
    s.write_all(proxy_line(5).as_bytes()).await.unwrap();
    s.write_all(b"GET /en/ HTTP/1.1\r\nHost: ").await.unwrap();
    let start = Instant::now();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(20), s.read_to_end(&mut out)).await;
    let el = start.elapsed();
    assert!(out.is_empty());
    assert!(
        el >= Duration::from_secs(9) && el < Duration::from_secs(13),
        "{el:?}"
    );
}

/// Oversize head (> 16 KiB) and too many headers: refused, bounded memory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversize_heads() {
    let h = harness().await;
    let big = format!(
        "GET /en/ HTTP/1.1\r\nHost: {HOST}\r\nX: {}\r\n\r\n",
        "a".repeat(20_000)
    );
    let out = raw(&h.web_sock, 1, big.as_bytes()).await;
    if !out.is_empty() {
        assert_eq!(parse(&out).status, 500);
    }
    let mut many = format!("GET /en/ HTTP/1.1\r\nHost: {HOST}\r\n");
    for i in 0..60 {
        many.push_str(&format!("X-{i}: 1\r\n"));
    }
    many.push_str("\r\n");
    assert_eq!(
        parse(&raw(&h.web_sock, 1, many.as_bytes()).await).status,
        500
    );
    // Body over the form limit: refused before it is read.
    let (pre, tok) = h.pre().await;
    let body = format!("csrf={tok}&passphrase={}", "a".repeat(120 * 1024));
    assert_eq!(h.post("/en/login", &[&pre], &body).await.status, 500);
}

/// ST-065: unknown paths, query strings, foreign locales, `/app/v1` and the
/// withdrawn routes are the same 404 page; methods other than GET/HEAD/POST
/// get 405; GET on POST-only routes gets 405 and changes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn route_registry_deny_by_default() {
    let h = harness().await;
    let mut sizes = Vec::new();
    for p in [
        "/en/nope",
        "/en/?x=1",
        "/de/",
        "/app/v1/replies",
        "/en/saved",
        "/en/static/a.css",
        "/en/../en/",
        "/en/keys",
        "/EN/",
    ] {
        let r = h.get(p, &[]).await;
        assert_eq!(r.status, 404, "{p}");
        sizes.push(r.body.len());
    }
    assert!(sizes.iter().all(|s| *s == 65_536));
    for p in ["/en/submit", "/en/leave", "/en/extend", "/en/check"] {
        assert_eq!(h.get(p, &[]).await.status, 405, "{p}");
    }
    for m in ["PUT", "DELETE", "OPTIONS", "TRACE", "PATCH"] {
        let r = parse(
            &raw(
                &h.web_sock,
                1,
                format!("{m} /en/ HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes(),
            )
            .await,
        );
        assert_eq!(r.status, 405, "{m}");
    }
    assert!(h.sealer.ops().is_empty());
}

/// AT-017 / AT-018 / A1: nothing the client sends is reflected: not the
/// User-Agent, a path, header or field canary, not on any error path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_reflection_of_input() {
    let h = harness().await;
    let canary = "canary-zx81-reflect";
    let reqs = vec![
        format!(
            "GET /en/{canary} HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: {canary}\r\nX-{canary}: {canary}\r\n\r\n"
        ),
        format!(
            "GET /en/ HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: {canary}\r\nAccept-Language: {canary}\r\nReferer: http://{canary}/\r\n\r\n"
        ),
        format!(
            "POST /en/login HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 27\r\n\r\ncsrf={canary}&a=b"
        ),
        format!(
            "GET /en/ HTTP/1.1\r\nHost: {HOST}\r\nCookie: __Host-cs={canary}; {canary}=1\r\n\r\n"
        ),
    ];
    for r in reqs {
        let out = raw(&h.web_sock, 1, r.as_bytes()).await;
        assert!(!out.is_empty());
        assert!(
            !String::from_utf8_lossy(&out).contains(canary),
            "reflected: {r:.40}"
        );
    }
    // A field canary in a login attempt with a bad word count.
    let (pre, tok) = h.pre().await;
    let r = h
        .post(
            "/en/login",
            &[&pre],
            &format!("csrf={tok}&action=login&passphrase={canary}"),
        )
        .await;
    assert!(!r.text().contains(canary));
}

/// ST-079: per-circuit login limit (5 / 10 min) gives the same busy page;
/// another circuit is unaffected; the circuit id is never shown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn login_rate_limit_per_circuit() {
    let h = harness_with(|c| c.login_floor = Duration::from_secs(2)).await;
    let (pre, tok) = h.pre().await;
    let body = format!("csrf={tok}&layout=ten");
    let mut statuses = Vec::new();
    for _ in 0..6 {
        statuses.push(h.post_on(77, "/en/login", &[&pre], &body).await.status);
    }
    assert_eq!(&statuses[..5], &[200; 5]);
    assert_eq!(statuses[5], 429);
    assert_eq!(h.post_on(78, "/en/login", &[&pre], &body).await.status, 200);
    assert_eq!(h.sealer.count(Op::LoginDerive), 0);
}

/// A6: random garbage on the socket never crashes the service, which keeps
/// answering afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn garbage_does_not_kill_the_service() {
    let h = harness().await;
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    for i in 0..200u32 {
        let mut junk = Vec::new();
        for _ in 0..(i * 13 % 3000) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            junk.push((seed & 0xff) as u8);
        }
        if i % 2 == 0 {
            let mut v = b"GET /en/ HTTP/1.1\r\n".to_vec();
            v.extend_from_slice(&junk);
            junk = v;
        }
        let _ = raw(&h.web_sock, i, &junk).await;
    }
    assert_eq!(h.get("/en/", &[]).await.status, 200);
}
