// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Wrap Stanza decoder (§13.2): never panics; round-trips on success; EK-layer open
//! with a fixed key never panics.
#![no_main]
use candor_core::secret::ErasureKey;
use candor_core::stanza::WrapStanza;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = WrapStanza::decode(data) {
        assert_eq!(s.encode().expect("re-encode"), data);
        let _ = s.open_casekey_ek(&ErasureKey::from_bytes([0; 32]), [0; 16], [0; 16], 0);
    }
});
