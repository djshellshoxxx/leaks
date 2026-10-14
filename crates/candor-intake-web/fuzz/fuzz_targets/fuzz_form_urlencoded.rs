// SPDX-License-Identifier: AGPL-3.0-or-later
//! ST-054 `fuzz_form_urlencoded`: the strict form parser with the field
//! allow-list of a route chosen by the first input byte. Never panics;
//! accepted text fields contain no NUL, no bare CR and stay within limits.
#![no_main]

use candor_intake_web::form::parse_form;
use candor_intake_web::limits::MAX_LONG_BYTES;
use candor_intake_web::routes::{REGISTRY, rule};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((sel, body)) = data.split_first() else {
        return;
    };
    let route = REGISTRY[usize::from(*sel) % REGISTRY.len()].route;
    if let Ok(f) = parse_form(body, &|n| rule(route, n)) {
        for n in ["csrf", "what", "who", "anything_else", "where", "text", "full_name", "passphrase"] {
            for v in f.all(n) {
                assert!(v.len() <= MAX_LONG_BYTES);
                assert!(!v.contains('\0'));
                if n != "passphrase" {
                    assert!(!v.contains('\r'));
                }
            }
        }
    }
});
