// SPDX-License-Identifier: AGPL-3.0-or-later
//! Layout conformance: size classes, budgets, response headers, head length and overflow.

use super::preview::{all_cases, sample_view_model};
use super::{max_content, render_ok, variants};
use candor_source_ui::*;
use zeroize::Zeroizing;

// ST: SUI-005 / API-009 — padding lands exactly on the class; class by method and cookie only.
#[test]
fn size_classes_exact() {
    for (s, l, m, e) in variants() {
        let (p, b) = render_ok(s, l, m, e);
        let vm = sample_view_model(s, m, e);
        let expect = if s == Screen::MethodNotAllowed {
            SizeClass::P1
        } else {
            SizeClass::for_request(vm.ctx.method, vm.ctx.has_session_cookie)
        };
        assert_eq!(p.class, expect);
        assert_eq!(p.body.len(), expect.bytes());
        assert_eq!(b.len(), expect.bytes());
        assert_eq!(
            p.header("Content-Length"),
            Some(expect.bytes().to_string().as_str())
        );
        assert!(p.unpadded_len <= expect.max_unpadded());
        assert!(
            b.trim_end().ends_with("--></body>\n</html>"),
            "{}",
            s.spec_id()
        );
    }
}

// ST: SUI-005 — sizes do not depend on content (inbox with 0 vs 20 messages; short vs long review).
#[test]
fn size_independent_of_content() {
    let l = Locale::En;
    let mut a = sample_view_model(Screen::Inbox, Mode::Anonymous, false);
    a.inbox.messages.clear();
    let mut b = a.clone();
    for i in 0..20u8 {
        b.inbox.messages.push(InboxMessage {
            sender: Zeroizing::new("Team".into()),
            date: Day::new(2026, 10, 1 + i).unwrap(),
            text: Zeroizing::new("x".repeat(2000)),
        });
    }
    let pa = render(Screen::Inbox, &a, &l).unwrap();
    let pb = render(Screen::Inbox, &b, &l).unwrap();
    assert_eq!(pa.body.len(), pb.body.len());
    let mut wrong = sample_view_model(Screen::Login, Mode::Anonymous, true);
    wrong.ctx.method = Method::Post;
    let mut right = sample_view_model(Screen::Inbox, Mode::Anonymous, false);
    right.ctx.method = Method::Post;
    right.ctx.has_session_cookie = false;
    let pw = render(Screen::Login, &wrong, &l).unwrap();
    let pr = render(Screen::Inbox, &right, &l).unwrap();
    assert_eq!(pw.body.len(), pr.body.len(), "wrong vs right passphrase");
}

// ST: SUI-002, SUI-036, SUI-055 — exact header set; CSP pins the served stylesheet.
#[test]
fn response_headers() {
    for (s, l, m, e) in variants() {
        let (p, b) = render_ok(s, l, m, e);
        for h in PROHIBITED_HEADERS {
            assert!(p.header(h).is_none(), "{h}");
        }
        assert_eq!(p.header("Cache-Control"), Some("no-store, max-age=0"));
        assert_eq!(p.header("Referrer-Policy"), Some("no-referrer"));
        assert_eq!(p.header("X-Content-Type-Options"), Some("nosniff"));
        assert_eq!(p.header("X-Frame-Options"), Some("DENY"));
        assert_eq!(p.header("Cross-Origin-Opener-Policy"), Some("same-origin"));
        assert_eq!(
            p.header("Cross-Origin-Embedder-Policy"),
            Some("require-corp")
        );
        assert_eq!(
            p.header("Cross-Origin-Resource-Policy"),
            Some("same-origin")
        );
        assert_eq!(p.header("Origin-Agent-Cluster"), Some("?1"));
        assert_eq!(p.header("Content-Language"), Some(l.tag()));
        assert!(
            p.header("Permissions-Policy")
                .unwrap()
                .contains("camera=()")
        );
        assert_eq!(p.header("Content-Type"), Some("text/html; charset=utf-8"));
        let csp = p.header("Content-Security-Policy").unwrap();
        assert_eq!(csp, content_security_policy());
        // The CSP hash covers exactly the bytes inside <style>.
        let start = b.find("<style>").unwrap() + "<style>".len();
        let end = b.find("</style>").unwrap();
        assert_eq!(&b[start..end], stylesheet());
        assert!(csp.contains(stylesheet_hash()));
        assert_eq!(p.header("Clear-Site-Data").is_some(), s.clears_site_data());
        assert_eq!(p.status, s.status());
    }
}

// ST: A11Y-009 / A11Y-018 / 11 §12 — stylesheet obligations.
#[test]
fn stylesheet_obligations() {
    let css = stylesheet();
    assert!(css.len() <= MAX_CSS_BYTES);
    assert!(css.contains(":focus-visible{outline:3px solid"));
    assert!(css.contains("outline-offset:2px"));
    assert!(css.contains("@media (prefers-reduced-motion:reduce)"));
    assert!(css.contains("@media (forced-colors:active)"));
    assert!(css.contains("@media (scripting:enabled)"));
    assert!(css.contains("system-ui"));
    assert!(!css.contains("position:fixed") && !css.contains("position:sticky"));
    assert!(!css.contains("@font-face") && !css.contains("url("));
    assert!(!css.contains("outline:none}") || css.contains("main:focus{outline:none}"));
    // Inline SVG budget (11 §5.4).
    let (_, b) = render_ok(Screen::Landing, Locale::En, Mode::Anonymous, false);
    let svg: usize = b
        .match_indices("<svg")
        .map(|(i, _)| b[i..].find("</svg>").unwrap() + 6)
        .sum();
    assert!(svg <= MAX_SVG_BYTES);
}

#[test]
fn robots_padded() {
    let p = robots_txt();
    assert_eq!(p.body.len(), SizeClass::P1.bytes());
}

// ST: SUI-005 — the largest P1 page (S02) keeps headroom in every built-in locale.
#[test]
fn s02_budget_report() {
    for l in Locale::ALL {
        let vm = max_content(sample_view_model(Screen::Safety, Mode::Anonymous, false));
        let p = render(Screen::Safety, &vm, &l).unwrap();
        assert!(
            p.unpadded_len <= SizeClass::P1.max_unpadded(),
            "{}",
            l.tag()
        );
        println!(
            "S02 {}: {} of {} bytes",
            l.tag(),
            p.unpadded_len,
            SizeClass::P1.max_unpadded()
        );
    }
}

// ST: AUD-RM1-SUI-03 — a page larger than its class fails closed (the fixed render buffer never
// grows); it is not truncated or moved to a larger class.
#[test]
fn oversized_chrome_fails_closed() {
    let mut vm = sample_view_model(Screen::Safety, Mode::Anonymous, false);
    vm.deployment.jurisdiction_rights_text = Some("x".repeat(70_000));
    assert!(matches!(
        render(Screen::Safety, &vm, &Locale::En),
        Err(RenderError::OverBudget(_))
    ));
}

// ST: AUD-RM1-SUI-05 (guard, not a fix) — the crate's own header block varies only by
// `Clear-Site-Data` and the language tag, and P2 responses with the largest and smallest header
// block (plus a 200-byte allowance for the session layer's `Set-Cookie`) need the same number
// of 498-byte Tor RELAY cell payloads. A change that breaks this must pad the header block.
// ST: AUD-RM1-SUI-05 / SUI-005 / ADR-011 — the serialized response head (status line, headers,
// blank line) has the same length for every screen × locale × session state × cookie presence,
// so with the fixed body every response of a class has the same wire size.
#[test]
fn response_head_length_is_constant() {
    let attrs = "; Path=/; Secure; HttpOnly; SameSite=Strict";
    let max_cookie = format!(
        "__Host-cs={}{attrs}",
        "A".repeat(MAX_SET_COOKIE_BYTES - "__Host-cs=".len() - attrs.len())
    );
    assert_eq!(max_cookie.len(), MAX_SET_COOKIE_BYTES);
    let cookies = [
        None,
        Some("__Host-cs=x; Path=/; Secure; HttpOnly; SameSite=Strict"),
        Some("__Host-cs=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"),
        Some(max_cookie.as_str()),
    ];
    let mut totals = std::collections::HashMap::new();
    for (s, l) in all_cases() {
        for (method, session) in [
            (Method::Get, false),
            (Method::Get, true),
            (Method::Post, false),
            (Method::Post, true),
        ] {
            let mut vm = sample_view_model(s, Mode::Anonymous, false);
            vm.ctx.method = method;
            vm.ctx.has_session_cookie = session;
            let mut p =
                render(s, &vm, &l).unwrap_or_else(|e| panic!("{} {}: {e:?}", s.spec_id(), l.tag()));
            for c in cookies {
                finalize_headers(&mut p, c).unwrap();
                assert_eq!(p.header("Set-Cookie"), c);
                assert_eq!(p.headers.last().unwrap().0, PAD_HEADER);
                let head = p.head_len().unwrap();
                assert_eq!(
                    head,
                    p.class.head_bytes(),
                    "{} {} {c:?}",
                    s.spec_id(),
                    l.tag()
                );
                let total = head + p.body.len();
                assert_eq!(*totals.entry(p.class.bytes()).or_insert(total), total);
                // Serialize exactly as C-06 must and compare.
                let mut wire = format!(
                    "HTTP/1.1 {} {}\r\n",
                    p.status,
                    reason_phrase(p.status).unwrap()
                );
                for (k, v) in &p.headers {
                    wire.push_str(&format!("{k}: {v}\r\n"));
                }
                wire.push_str("\r\n");
                assert_eq!(wire.len(), p.class.head_bytes());
            }
        }
    }
    let p = robots_txt();
    assert_eq!(p.head_len(), Some(SizeClass::P1.head_bytes()));
}

// ST: SUI-005 / SUI-069 / SUI-078 — worst-case optional content still fits its class.
#[test]
fn max_content_fits_size_classes() {
    for (s, l) in all_cases() {
        let vm = max_content(sample_view_model(s, Mode::Anonymous, false));
        let p = render(s, &vm, &l).unwrap_or_else(|e| panic!("{} {}: {e:?}", s.spec_id(), l.tag()));
        assert_eq!(p.body.len(), p.class.bytes());
    }
}
