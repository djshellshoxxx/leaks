// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Passphrase normalization (§11.3, ST-053) and the constant-time wordlist check:
//! never panic on any UTF-8 input; normalization is idempotent and canonical
//! (no leading, trailing or doubled spaces); over-long input is refused.
#![no_main]
use candor_core::passphrase::{MAX_PASSPHRASE_INPUT_LEN, Wordlist, normalize};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = core::str::from_utf8(data) else {
        return;
    };
    match normalize(s) {
        Ok(n) => {
            assert!(s.len() <= MAX_PASSPHRASE_INPUT_LEN);
            assert!(!n.starts_with(' ') && !n.ends_with(' ') && !n.contains("  "));
            if n.len() <= MAX_PASSPHRASE_INPUT_LEN {
                assert_eq!(normalize(&n).expect("renormalize").as_str(), n.as_str());
            }
        }
        Err(_) => {}
    }
    let _ = Wordlist::eff_large().expect("wordlist").check(s);
});
