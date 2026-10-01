// SPDX-License-Identifier: Apache-2.0 OR MIT
//! ST-040 `fuzz_envelope_parse`: sealed-object framing parser never panics or
//! over-allocates; opening with a fixed CK never succeeds on garbage.
#![no_main]
use candor_core::object::parse;
use candor_core::secret::ContentKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = parse(data) {
        let _ = p.object_hash();
        assert!(p.open(&ContentKey::from_bytes([1; 32])).is_err());
    }
});
