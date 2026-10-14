// SPDX-License-Identifier: Apache-2.0 OR MIT
//! ST-042 `fuzz_hpke_open` (AUD-RM1-CORE-05(a)): HPKE base-mode open with X-Wing
//! (`kem::open_base`) on `enc ‖ ct` never panics; a ciphertext that opens under the
//! fixed info/aad never opens under another info or aad; 1216-byte inputs also go
//! through public-key validation (ML-KEM modulus check, X25519 low-order rejection).
#![no_main]
#[path = "common.rs"]
mod common;

use candor_core::Suite;
use candor_core::kem::{KemPublicKey, open_base};
use candor_core::suite::{XWING_NENC, XWING_NPK};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() == XWING_NPK {
        let _ = KemPublicKey::from_bytes(Suite::CandorStd1, data);
    }
    let (enc, ct) = data.split_at(data.len().min(XWING_NENC));
    let sk = &common::member().private;
    if open_base(sk, enc, common::HPKE_INFO, common::HPKE_AAD, ct).is_ok() {
        assert!(open_base(sk, enc, b"other-info", common::HPKE_AAD, ct).is_err());
        assert!(open_base(sk, enc, common::HPKE_INFO, b"other-aad", ct).is_err());
    }
});
