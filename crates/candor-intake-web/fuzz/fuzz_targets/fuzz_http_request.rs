// SPDX-License-Identifier: AGPL-3.0-or-later
//! ST-044 `fuzz_http_request`: tor's PROXY line and the strict HTTP/1.1
//! request-head parser over arbitrary bytes. Never panics; bounded work;
//! an accepted head satisfies the parser's invariants (only GET/HEAD/POST,
//! routable paths are `[A-Za-z0-9/._-]` and start with `/`, cookie values
//! are 64 lowercase hex characters).
#![no_main]

use candor_intake_web::http::{find_head_end, parse_head};
use candor_intake_web::proxy::{find_line_end, parse_proxy_line};
use libfuzzer_sys::fuzz_target;

const HOST: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

fuzz_target!(|data: &[u8]| {
    // As the server reads it: PROXY line, then the head.
    let rest = match find_line_end(data) {
        Some(end) => {
            let _ = parse_proxy_line(&data[..end]);
            &data[end..]
        }
        None => data,
    };
    for input in [rest, data] {
        let head = match find_head_end(input) {
            Some(end) => &input[..end],
            None => input,
        };
        if let Ok(h) = parse_head(head, HOST) {
            if let Some(p) = &h.path {
                assert!(p.starts_with('/'));
                assert!(p.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)));
            }
            if let Some(c) = &h.session_cookie {
                assert_eq!(c.len(), 64);
                assert!(h.session_cookie_present);
            }
        }
    }
});
