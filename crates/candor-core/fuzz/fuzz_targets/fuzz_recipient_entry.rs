// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Recipient List entry parser (ADR-050(3)): exactly 97 bytes, `slot_index < 16`;
//! never panics; round-trips; debug output never contains entry bytes.
#![no_main]
use candor_core::slots::RecipientListEntry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(e) = RecipientListEntry::from_bytes(data) {
        assert_eq!(e.to_bytes().as_slice(), data);
        assert!(e.ct_eq(&RecipientListEntry::from_bytes(data).expect("reparse")));
        assert!(e.slot_index() < 16);
        assert_eq!(format!("{e:?}"), "RecipientListEntry(<redacted>)");
    }
});
