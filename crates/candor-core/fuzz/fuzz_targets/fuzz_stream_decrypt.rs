// SPDX-License-Identifier: Apache-2.0 OR MIT
//! ST-041 `fuzz_stream_decrypt`: malformed STREAM input yields an error and zero
//! plaintext output (plaintext-release oracle via the chunk reader).
#![no_main]
use candor_core::secret::AeadKey;
use candor_core::stream::{StreamDecryptor, decrypt};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((len_bytes, ct)) = data.split_first_chunk::<2>() else { return };
    let len = u64::from(u16::from_be_bytes(*len_bytes)) * 4;
    assert!(decrypt(AeadKey::from_bytes([3; 32]), len, ct).is_err());
    let mut rd = StreamDecryptor::new(AeadKey::from_bytes([3; 32]), len).reader(ct);
    let released: usize = rd.by_ref().filter_map(Result::ok).map(|c| c.len()).sum();
    assert_eq!(released, 0);
    assert!(rd.finish().is_err());
});
