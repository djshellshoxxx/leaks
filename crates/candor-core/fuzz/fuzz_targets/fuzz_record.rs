// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Encrypted record parser (§13.8): never panics; only the seeded record (sealed
//! under the fixed key and AAD) or byte-identical copies authenticate.
#![no_main]
#[path = "common.rs"]
mod common;

use candor_core::record::{RecordAad, open_record, record_header};
use candor_core::secret::AeadKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = record_header(data);
    let aad = RecordAad::Case { tenant_id: [0; 16], case_id: [0; 16], table_id: 0, column_id: 0, record_id: [0; 16], row_version: 0 };
    if let Ok(pt) = open_record(&AeadKey::from_bytes(common::RECORD_KEY), &aad, data) {
        assert_eq!(pt.as_slice(), b"seed");
    }
    assert!(open_record(&AeadKey::from_bytes([8; 32]), &aad, data).is_err());
});
