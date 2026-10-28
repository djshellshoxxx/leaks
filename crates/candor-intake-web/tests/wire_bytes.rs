// SPDX-License-Identifier: AGPL-3.0-or-later
//! AUD-RM1-SUI-14 / ST-074 / IMPL-RM2-016: the exact bytes on the wire.
//!
//! Every response head is exactly 2,048 bytes (`SizeClass::head_bytes`),
//! starts with `HTTP/1.1 {status} {reason}`, carries exactly the 11 §5.3
//! header set in source-ui order, at most one `Set-Cookie` (the session
//! cookie `__Host-cs` or the pre-session `__Host-cpre`, in their exact form),
//! the fixed-width `X-Pad` last, nothing else (no `Date`, `Server`,
//! `Connection`, `Transfer-Encoding`, `ETag`, `Last-Modified`), and a body of
//! exactly 65,536 (P1) or 131,072 (P2) bytes, with HEAD sending the same head
//! and no body.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use support::*;

/// The 11 §5.3 header names in the order source-ui emits them.
const BASE: [&str; 14] = [
    "Content-Type",
    "Content-Length",
    "Content-Security-Policy",
    "Cache-Control",
    "Referrer-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
    "Origin-Agent-Cluster",
    "Permissions-Policy",
    "X-Robots-Tag",
    "Content-Language",
];

fn check_head(r: &Resp, status: &str, class: usize, cookie: Option<&str>, clear: bool) {
    let head = String::from_utf8(r.head.clone()).unwrap();
    assert_eq!(r.head.len(), 2048, "fixed head length");
    assert!(
        head.starts_with(&format!("HTTP/1.1 {status}\r\n")),
        "{head:.40}"
    );
    assert!(head.ends_with("\r\n\r\n"));
    let names: Vec<&str> = r.headers.iter().map(|(k, _)| k.as_str()).collect();
    let mut want: Vec<&str> = BASE.to_vec();
    if clear {
        want.push("Clear-Site-Data");
    }
    if cookie.is_some() {
        want.push("Set-Cookie");
    }
    want.push("X-Pad");
    assert_eq!(names, want, "exact header set and order");
    for banned in [
        "Date",
        "Server",
        "Connection",
        "Transfer-Encoding",
        "ETag",
        "Last-Modified",
        "Content-Encoding",
        "Alt-Svc",
    ] {
        assert!(r.header(banned).is_none(), "{banned} must not be sent");
    }
    assert_eq!(r.header("Content-Length").unwrap(), class.to_string());
    assert_eq!(r.header("Cache-Control").unwrap(), "no-store, max-age=0");
    assert_eq!(r.header("Referrer-Policy").unwrap(), "no-referrer");
    assert_eq!(r.header("X-Content-Type-Options").unwrap(), "nosniff");
    assert_eq!(
        r.header("Cross-Origin-Opener-Policy").unwrap(),
        "same-origin"
    );
    assert_eq!(
        r.header("Cross-Origin-Resource-Policy").unwrap(),
        "same-origin"
    );
    let csp = r.header("Content-Security-Policy").unwrap();
    assert!(csp.starts_with("default-src 'none'; style-src 'sha256-"));
    assert!(csp.contains("frame-ancestors 'none'"));
    assert!(!csp.contains("script-src"), "no script source at all");
    assert_eq!(csp, candor_source_ui::content_security_policy());
    let pad = r.header("X-Pad").unwrap();
    assert!(pad.bytes().all(|b| b == b'0'));
    if let Some(c) = cookie {
        let v = r.header("Set-Cookie").unwrap();
        assert!(v.starts_with(c), "{v}");
        let value = &v[c.len()..c.len() + 64];
        assert!(
            value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }
}

/// GET without a session cookie: P1, 200, the pre-session cookie
/// `__Host-cpre=<64 hex>; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=900`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_p1_exact_wire_bytes() {
    let h = harness().await;
    let raw = raw(&h.web_sock, 1, &get_req("/en/", &[])).await;
    assert_eq!(raw.len(), 2048 + 65_536, "head + P1 body, nothing else");
    let r = parse(&raw);
    check_head(&r, "200 OK", 65_536, Some("__Host-cpre="), false);
    assert!(
        r.header("Set-Cookie")
            .unwrap()
            .ends_with("; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=900")
    );
    assert_eq!(r.body.len(), 65_536);
    // HEAD: the same head (same cookie format), no body.
    let head_req = format!("HEAD /en/ HTTP/1.1\r\nHost: {HOST}\r\n\r\n");
    let raw = support::raw(&h.web_sock, 1, head_req.as_bytes()).await;
    assert_eq!(raw.len(), 2048);
    check_head(&parse(&raw), "200 OK", 65_536, Some("__Host-cpre="), false);
}

/// POST that creates a session: P2, 200, exactly one cookie, the session
/// cookie without Max-Age/Expires.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_cookie_exact_wire_bytes() {
    let h = harness().await;
    let (pre, tok) = h.pre().await;
    let body = format!("csrf={tok}&channel_id={}&mode=anonymous", "c1".repeat(16));
    let raw = raw(&h.web_sock, 1, &post_req("/en/new", &[&pre], &body, &[])).await;
    assert_eq!(raw.len(), 2048 + 131_072);
    let r = parse(&raw);
    check_head(&r, "200 OK", 131_072, Some("__Host-cs="), false);
    let c = r.header("Set-Cookie").unwrap();
    assert_eq!(
        c.len(),
        "__Host-cs=".len() + 64 + "; Path=/; Secure; HttpOnly; SameSite=Strict".len()
    );
    assert!(c.ends_with("; Path=/; Secure; HttpOnly; SameSite=Strict"));
    assert!(!c.contains("Max-Age") && !c.contains("Expires") && !c.contains("Domain"));
    // A GET inside the session: P2, no cookie at all, the same head length.
    let cookie = r.cookie().unwrap();
    let r = h.get("/en/q", &[&cookie]).await;
    check_head(&r, "200 OK", 131_072, None, false);
}

/// Error, busy, not-found and 405 pages: the same head length and the class
/// of the request; Leave sends Clear-Site-Data and no cookie.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn error_pages_exact_wire_bytes() {
    let h = harness().await;
    let r = h.get("/en/nope", &[]).await;
    check_head(&r, "404 Not Found", 65_536, Some("__Host-cpre="), false);
    let r = parse(
        &raw(
            &h.web_sock,
            1,
            format!("PUT /en/ HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes(),
        )
        .await,
    );
    check_head(
        &r,
        "405 Method Not Allowed",
        65_536,
        Some("__Host-cpre="),
        false,
    );
    // Bad CSRF on POST: the uniform 500 page, P2.
    let r = h.post("/en/login", &[], "csrf=00&action=login").await;
    check_head(
        &r,
        "500 Internal Server Error",
        131_072,
        Some("__Host-cpre="),
        false,
    );
    // Leave: Clear-Site-Data, no cookie set.
    let (pre, tok) = h.pre().await;
    let r = h.post("/en/leave", &[&pre], &format!("csrf={tok}")).await;
    check_head(&r, "200 OK", 131_072, None, true);
    // Busy (sealer busy on /new): 429, P2.
    h.sealer
        .busy
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (pre, tok) = h.pre().await;
    let body = format!("csrf={tok}&channel_id={}&mode=anonymous", "c1".repeat(16));
    let r = h.post("/en/new", &[&pre], &body).await;
    check_head(
        &r,
        "429 Too Many Requests",
        131_072,
        Some("__Host-cpre="),
        false,
    );
}

/// robots.txt (SW-20): padded to P1, text/plain, same fixed head length.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn robots_exact_wire_bytes() {
    let h = harness().await;
    let raw = raw(&h.web_sock, 1, &get_req("/robots.txt", &[])).await;
    assert_eq!(raw.len(), 2048 + 65_536);
    let r = parse(&raw);
    assert_eq!(
        r.header("Content-Type").unwrap(),
        "text/plain; charset=utf-8"
    );
    assert!(r.text().starts_with("User-agent: *\nDisallow: /\n"));
    assert!(r.header("Date").is_none());
}
