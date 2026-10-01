// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Passphrase normalization (§11.3, ST-053) and the constant-time wordlist check:
//! never panic on any UTF-8 input; output is canonical (no leading, trailing or
//! doubled spaces); over-long input is refused; re-normalizing succeeds and is the
//! identity on ASCII output. (§11.3 is not idempotent in general: lowercasing after
//! NFKC can emit non-NFKC combining sequences, e.g. U+0130 + U+031F; see SPEC-NOTES.)
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
                let again = normalize(&n).expect("renormalize");
                if n.is_ascii() {
                    assert_eq!(again.as_str(), n.as_str());
                }
            }
        }
        Err(_) => {}
    }
    let _ = Wordlist::eff_large().expect("wordlist").check(s);
});
