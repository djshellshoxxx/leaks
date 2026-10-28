// SPDX-License-Identifier: AGPL-3.0-or-later
//! ST-043 `fuzz_multipart_intake`: the streaming multipart parser fed in
//! chunk sizes derived from the input. Never panics; never holds more than
//! its fixed buffer; data events are at most one upload chunk; at most the
//! allowed number of parts is ever reported.
#![no_main]

use candor_intake_web::limits::{MAX_MULTIPART_PARTS, UPLOAD_CHUNK};
use candor_intake_web::multipart::{Event, Multipart, boundary_from_content_type};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&step, rest)) = data.split_first() else {
        return;
    };
    // Exercise the Content-Type parser on a prefix too.
    if let Some(nl) = rest.iter().position(|b| *b == b'\n') {
        if let Ok(ct) = core::str::from_utf8(&rest[..nl]) {
            let _ = boundary_from_content_type(ct);
        }
    }
    let step = usize::from(step).max(1);
    let mut p = Multipart::new("----geckoformboundary1234");
    let mut parts = 0usize;
    let mut i = 0usize;
    loop {
        loop {
            match p.next_event() {
                Ok(Some(Event::Part(_))) => {
                    parts += 1;
                    assert!(parts <= MAX_MULTIPART_PARTS);
                }
                Ok(Some(Event::Data(d))) => assert!(d.len() <= UPLOAD_CHUNK),
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => return,
            }
        }
        if i >= rest.len() {
            break;
        }
        let n = step.min(rest.len() - i).min(p.room());
        if n == 0 {
            return;
        }
        if p.feed(&rest[i..i + n]).is_err() {
            return;
        }
        i += n;
    }
    let _ = p.finish();
});
