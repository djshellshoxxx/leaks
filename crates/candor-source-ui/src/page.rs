// SPDX-License-Identifier: AGPL-3.0-or-later
//! The Tier W page contract: size classes and padding (11 §5.4), response headers and the
//! hash-pinned CSP (11 §5.3).

use core::fmt;
use std::sync::LazyLock;

use base64::Engine as _;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::model::Method;

/// Source of the single inline stylesheet (`static/source.css`).
const STYLESHEET_SOURCE: &str = include_str!("../static/source.css");

/// The served inline stylesheet (SUI-003): the source with comments and line breaks removed,
/// to save bytes in the P1 budget. Hash-pinned in the CSP.
pub fn stylesheet() -> &'static str {
    static CSS: LazyLock<String> = LazyLock::new(|| minify_css(STYLESHEET_SOURCE));
    CSS.as_str()
}

/// Removes `/* … */` comments and line breaks. The stylesheet contains no strings that could
/// hold comment markers, so this is a plain scan.
fn minify_css(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(start) = rest.find("/*") {
        out.push_str(rest.get(..start).unwrap_or(""));
        rest = rest
            .get(start..)
            .and_then(|r| r.find("*/").and_then(|e| r.get(e.saturating_add(2)..)))
            .unwrap_or("");
    }
    out.push_str(rest);
    out.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

/// Maximum inline CSS size (11 §5.4 P1 row).
pub const MAX_CSS_BYTES: usize = 20_480;

/// Maximum total inline SVG per page (11 §5.4 P1 row).
pub const MAX_SVG_BYTES: usize = 4_096;

/// Opening and closing of the padding comment.
const PAD_OPEN: &str = "<!--";
const PAD_CLOSE: &str = "-->";

/// Response size class (11 §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeClass {
    /// 65,536 bytes: every GET/HEAD without a session cookie.
    P1,
    /// 131,072 bytes: every POST response and every GET with a session cookie.
    P2,
}

impl SizeClass {
    /// The class is determined only by the method and the presence of the session cookie,
    /// never by content (11 §5.4, SUI-005).
    pub fn for_request(method: Method, has_session_cookie: bool) -> SizeClass {
        match (method, has_session_cookie) {
            (Method::Get | Method::Head, false) => SizeClass::P1,
            _ => SizeClass::P2,
        }
    }

    /// Exact `Content-Length`.
    pub fn bytes(self) -> usize {
        match self {
            SizeClass::P1 => 65_536,
            SizeClass::P2 => 131_072,
        }
    }

    /// Maximum unpadded content.
    pub fn max_unpadded(self) -> usize {
        match self {
            SizeClass::P1 => 61_440,
            SizeClass::P2 => 129_024,
        }
    }
}

/// `sha256-…` source for the stylesheet.
pub fn stylesheet_hash() -> &'static str {
    static HASH: LazyLock<String> = LazyLock::new(|| {
        let digest = Sha256::digest(stylesheet().as_bytes());
        format!(
            "sha256-{}",
            base64::engine::general_purpose::STANDARD.encode(digest.as_slice())
        )
    });
    HASH.as_str()
}

/// The Tier W Content-Security-Policy (11 §5.3; the only Tier W policy, RVW-A-21).
pub fn content_security_policy() -> String {
    format!(
        "default-src 'none'; style-src '{}'; img-src 'self' data:; form-action 'self'; \
         frame-ancestors 'none'; base-uri 'none'; sandbox allow-forms allow-same-origin; \
         require-trusted-types-for 'script'",
        stylesheet_hash()
    )
}

/// `Permissions-Policy` (11 §5.3).
pub const PERMISSIONS_POLICY: &str = "accelerometer=(), ambient-light-sensor=(), autoplay=(), \
bluetooth=(), camera=(), clipboard-read=(), display-capture=(), encrypted-media=(), \
fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), magnetometer=(), \
microphone=(), midi=(), payment=(), publickey-credentials-get=(), screen-wake-lock=(), \
serial=(), usb=(), xr-spatial-tracking=(), browsing-topics=()";

/// Headers that must never be sent (11 §5.3, SUI-055, API-009). `Set-Cookie` is set only by
/// the session layer (§5.6), never by this crate.
pub const PROHIBITED_HEADERS: &[&str] = &[
    "Server",
    "X-Powered-By",
    "ETag",
    "Last-Modified",
    "Date",
    "Content-Encoding",
    "Alt-Svc",
    "Report-To",
    "NEL",
    "Link",
    "Set-Cookie",
];

/// A rendered response: status, headers and the padded body.
///
/// The body may contain a passphrase (S10) or the source's own text, so it is zeroized on
/// drop and never printed by `Debug`.
pub struct Page {
    /// HTTP status code.
    pub status: u16,
    /// Response headers, in a fixed order. The server must add nothing else except the
    /// session cookie (§5.6) and must not add `Date` (11 §5.3, SUI-055).
    pub headers: Vec<(&'static str, String)>,
    /// Padded HTML, exactly `class.bytes()` long.
    pub body: Zeroizing<Vec<u8>>,
    /// The size class.
    pub class: SizeClass,
    /// The unpadded length, for CI budget reporting only. It is the true content size: never
    /// log it, export it as a metric or put it in a header (AUD-RM1-SUI-09).
    #[doc(hidden)]
    pub unpadded_len: usize,
    /// The part shown (0-based; 0 on screens without parts).
    pub part: usize,
    /// Number of parts of this screen (1 when everything fits). Like `unpadded_len` it depends
    /// on content length: use it only to build navigation, never log or export it.
    pub parts: usize,
}

impl fmt::Debug for Page {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Page")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field(
                "body",
                &format_args!("[{} bytes redacted]", self.body.len()),
            )
            .field("class", &self.class)
            .finish_non_exhaustive()
    }
}

impl Page {
    /// Header value by case-insensitive name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Padding failure: the unpadded content exceeds the class budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverBudget {
    /// Unpadded length.
    pub len: usize,
    /// Class.
    pub class: SizeClass,
}

/// Pads `html` to exactly `class.bytes()` with an HTML comment of ASCII spaces inserted
/// before the last `</body>` (11 §5.4 rule 1). If there is no `</body>`, the comment is
/// appended at the end.
pub fn pad_html(html: &str, class: SizeClass) -> Result<Zeroizing<Vec<u8>>, OverBudget> {
    let len = html.len();
    let over = OverBudget { len, class };
    if len > class.max_unpadded() {
        return Err(over);
    }
    let fill = class
        .bytes()
        .checked_sub(len)
        .and_then(|r| r.checked_sub(PAD_OPEN.len()))
        .and_then(|r| r.checked_sub(PAD_CLOSE.len()))
        .ok_or(over)?;
    let at = html.rfind("</body>").unwrap_or(len);
    let (head, tail) = html.split_at(at);
    let mut out = Zeroizing::new(Vec::with_capacity(class.bytes()));
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(PAD_OPEN.as_bytes());
    let filled = out.len().saturating_add(fill);
    out.resize(filled, b' ');
    out.extend_from_slice(PAD_CLOSE.as_bytes());
    out.extend_from_slice(tail.as_bytes());
    if out.len() != class.bytes() {
        return Err(over);
    }
    Ok(out)
}

/// Builds the §5.3 header set for an HTML page.
pub(crate) fn html_headers(
    content_language: &str,
    body_len: usize,
    clear_site_data: bool,
) -> Vec<(&'static str, String)> {
    let mut h = vec![
        ("Content-Type", "text/html; charset=utf-8".to_owned()),
        ("Content-Length", body_len.to_string()),
        ("Content-Security-Policy", content_security_policy()),
        ("Cache-Control", "no-store, max-age=0".to_owned()),
        ("Referrer-Policy", "no-referrer".to_owned()),
        ("X-Content-Type-Options", "nosniff".to_owned()),
        ("X-Frame-Options", "DENY".to_owned()),
        ("Cross-Origin-Opener-Policy", "same-origin".to_owned()),
        ("Cross-Origin-Embedder-Policy", "require-corp".to_owned()),
        ("Cross-Origin-Resource-Policy", "same-origin".to_owned()),
        ("Origin-Agent-Cluster", "?1".to_owned()),
        ("Permissions-Policy", PERMISSIONS_POLICY.to_owned()),
        ("X-Robots-Tag", "noindex, nofollow, noarchive".to_owned()),
        ("Content-Language", content_language.to_owned()),
    ];
    if clear_site_data {
        h.push((
            "Clear-Site-Data",
            "\"cache\", \"cookies\", \"storage\"".to_owned(),
        ));
    }
    h
}

/// `/robots.txt` (08 SW-20), padded to P1 with trailing spaces after a newline (11 §5.5).
pub fn robots_txt() -> Page {
    let text = "User-agent: *\nDisallow: /\n";
    let class = SizeClass::P1;
    let mut body = Zeroizing::new(Vec::with_capacity(class.bytes()));
    body.extend_from_slice(text.as_bytes());
    body.resize(class.bytes(), b' ');
    let mut headers = html_headers("en", body.len(), false);
    if let Some(ct) = headers.iter_mut().find(|(n, _)| *n == "Content-Type") {
        ct.1 = "text/plain; charset=utf-8".to_owned();
    }
    headers.retain(|(n, _)| *n != "Content-Language");
    Page {
        status: 200,
        headers,
        body,
        class,
        unpadded_len: text.len(),
        part: 0,
        parts: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn class_by_method_and_cookie_only() {
        assert_eq!(SizeClass::for_request(Method::Get, false), SizeClass::P1);
        assert_eq!(SizeClass::for_request(Method::Head, false), SizeClass::P1);
        assert_eq!(SizeClass::for_request(Method::Get, true), SizeClass::P2);
        assert_eq!(SizeClass::for_request(Method::Post, false), SizeClass::P2);
        assert_eq!(SizeClass::for_request(Method::Post, true), SizeClass::P2);
    }

    #[test]
    fn csp_shape() {
        let csp = content_security_policy();
        assert!(csp.starts_with("default-src 'none'; style-src 'sha256-"));
        assert!(!csp.contains("unsafe"));
        assert!(!csp.contains("http"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("base-uri 'none'"));
        assert!(csp.contains("form-action 'self'"));
    }

    #[test]
    fn css_budget() {
        assert!(
            stylesheet().len() <= MAX_CSS_BYTES,
            "{}",
            stylesheet().len()
        );
        assert!(!stylesheet().contains("/*") && !stylesheet().contains('\n'));
    }

    #[test]
    fn over_budget_is_error_not_panic() {
        let big = "a".repeat(SizeClass::P1.max_unpadded() + 1);
        assert!(pad_html(&big, SizeClass::P1).is_err());
        let ok = "a".repeat(SizeClass::P1.max_unpadded());
        assert_eq!(
            pad_html(&ok, SizeClass::P1).map(|b| b.len()).ok(),
            Some(65_536)
        );
    }

    #[test]
    fn robots_is_p1() {
        let p = robots_txt();
        assert_eq!(p.body.len(), 65_536);
        assert_eq!(p.header("Content-Length"), Some("65536"));
        assert!(p.body.starts_with(b"User-agent: *\nDisallow: /\n"));
    }

    proptest! {
        // ST: SUI-005 padding lands exactly on the class size for any content within budget.
        #[test]
        fn padding_exact(len in 0usize..61_440, p2 in any::<bool>()) {
            let class = if p2 { SizeClass::P2 } else { SizeClass::P1 };
            let html = format!("<html><body>{}</body></html>", "x".repeat(len.saturating_sub(26)));
            let padded = pad_html(&html, class);
            if html.len() <= class.max_unpadded() {
                let padded = padded.map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
                prop_assert_eq!(padded.len(), class.bytes());
                let s = String::from_utf8_lossy(&padded);
                prop_assert!(s.ends_with("--></body></html>"));
            }
        }
    }
}
