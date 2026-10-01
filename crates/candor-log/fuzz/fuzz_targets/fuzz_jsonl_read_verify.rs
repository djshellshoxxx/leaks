// SPDX-License-Identifier: AGPL-3.0-or-later
//! AUD-RM1-LOG-10 `fuzz_jsonl_read_verify`: hostile JSON-lines record and
//! checkpoint files (the stored audit format) never panic the bounded
//! reader or the verifier, and never verify as a non-empty stream without
//! a valid instance signature.
#![no_main]

use candor_log::chain::CheckpointSigner;
use candor_log::codes::StreamId;
use candor_log::ids::{AuditIdKey, TenantRef};
use candor_log::sink::read_stream;
use candor_log::verify::{VerifyParams, verify_stream};
use candor_log::SoftwareSigner;
use libfuzzer_sys::fuzz_target;
use zeroize::Zeroizing;

fuzz_target!(|data: &[u8]| {
    // First byte: stream; then the record file and checkpoint file split at
    // the first 0xff byte (not valid inside UTF-8 JSON).
    let Some((&sel, rest)) = data.split_first() else { return };
    let stream = match sel % 3 {
        0 => StreamId::Sec,
        1 => StreamId::Case,
        _ => StreamId::Sys,
    };
    let cut = rest.iter().position(|&b| b == 0xff).unwrap_or(rest.len());
    let (recs, cps) = rest.split_at(cut);
    let cps = cps.get(1..).unwrap_or_default();
    let Ok((records, checkpoints)) = read_stream(stream, recs, cps) else { return };
    let key = SoftwareSigner::from_seed(&Zeroizing::new([7; 32])).verifying_key();
    let tenant = TenantRef::derive(&AuditIdKey::new([1; 32]), b"t");
    for allow_pruned_prefix in [false, true] {
        let p = VerifyParams {
            tenant,
            stream,
            key: &key,
            trusted_latest: None,
            allow_pruned_prefix,
        };
        if let Ok(rep) = verify_stream(&p, &records, &checkpoints) {
            // Without the signing key, no checkpoint can verify, so anything
            // accepted is an unattested chain from genesis.
            assert_eq!(rep.checkpoints, 0);
            assert_eq!(rep.redacted, 0, "unbound redaction accepted");
            assert_eq!(rep.first_seq.unwrap_or(0), 0, "unbound prune accepted");
        }
    }
});
