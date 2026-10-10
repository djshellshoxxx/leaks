// SPDX-License-Identifier: AGPL-3.0-or-later
//! AUD-RM1-LOG-10 `fuzz_checkpoint_parse`: arbitrary checkpoint bytes and
//! signatures never panic the parser or the signature/witness checks, and
//! every parsed checkpoint satisfies the body invariants.
#![no_main]

use candor_log::chain::CheckpointSigner;
use candor_log::{SignedCheckpoint, SoftwareSigner};
use libfuzzer_sys::fuzz_target;
use zeroize::Zeroizing;

fuzz_target!(|data: &[u8]| {
    let (sig, body) = data.split_at(data.len().min(64));
    let mut s = [0u8; 64];
    s[..sig.len()].copy_from_slice(sig);
    if let Ok(cp) = SignedCheckpoint::from_parts(body.to_vec(), s) {
        let key = SoftwareSigner::from_seed(&Zeroizing::new([7; 32])).verifying_key();
        let _ = cp.verify_signature(&key);
        let _ = cp.verify_cosignature(&key, &s);
        assert_eq!(cp.bytes(), body);
        assert!(cp.body().end_seq >= cp.body().first_seq);
    }
});
