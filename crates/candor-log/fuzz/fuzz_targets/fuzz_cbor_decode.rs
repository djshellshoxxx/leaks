// SPDX-License-Identifier: AGPL-3.0-or-later
//! AUD-RM1-LOG-10 `fuzz_cbor_decode`: the strict canonical decoder never
//! panics, and everything it accepts re-encodes to the identical bytes
//! (round-trip oracle: canonical ⇔ accepted).
#![no_main]

use candor_log::cbor;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = cbor::decode(data) {
        let again = cbor::encode(&v).expect("accepted value must re-encode");
        assert_eq!(again.as_slice(), data, "decoder accepted non-canonical bytes");
    }
});
