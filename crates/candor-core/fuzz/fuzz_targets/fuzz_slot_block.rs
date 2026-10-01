// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RecipientSlotBlock decoder (§13.2): never panics; round-trips on success.
#![no_main]
use candor_core::slots::RecipientSlotBlock;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(b) = RecipientSlotBlock::decode(data) {
        assert_eq!(b.encode(), data);
    }
});
