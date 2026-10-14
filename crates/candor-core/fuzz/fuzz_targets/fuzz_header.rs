// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CoreHeader decoder (§13.1): never panics; decode∘encode is the identity on success.
#![no_main]
use candor_core::header::CoreHeader;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = CoreHeader::decode(data) {
        let enc = h.encode().expect("valid header re-encodes");
        assert_eq!(&enc[..], data);
    }
});
