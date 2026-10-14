// SPDX-License-Identifier: Apache-2.0 OR MIT
//! ST-041 `fuzz_stream_decrypt`: input `u16be(L) ‖ ciphertext`, plaintext length 4·L.
//! The buffered API and the chunk reader agree: the stream is accepted by one iff it
//! is accepted by the other, and then both release the same bytes; a different key
//! never authenticates anything.
#![no_main]
#[path = "common.rs"]
mod common;

use candor_core::secret::AeadKey;
use candor_core::stream::{StreamDecryptor, decrypt};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((len_bytes, ct)) = data.split_first_chunk::<2>() else {
        return;
    };
    let len = u64::from(u16::from_be_bytes(*len_bytes)) * 4;
    let key = || AeadKey::from_bytes(common::STREAM_KEY);
    let buffered = decrypt(key(), len, ct);
    let mut rd = StreamDecryptor::new(key(), len).reader(ct);
    let mut released = Vec::new();
    for c in rd.by_ref() {
        match c {
            Ok(c) => released.extend_from_slice(&c),
            Err(_) => break,
        }
    }
    let fin = rd.finish();
    assert_eq!(fin.is_ok(), buffered.is_ok());
    if let Ok(pt) = buffered {
        assert_eq!(pt.as_slice(), released.as_slice());
    }
    assert!(decrypt(AeadKey::from_bytes([4; 32]), len, ct).is_err());
});
