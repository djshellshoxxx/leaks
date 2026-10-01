// SPDX-License-Identifier: AGPL-3.0-or-later
//! AUD-RM1-LOG-10 `fuzz_jsonl_read_verify`: hostile JSON-lines record and
//! checkpoint files (the stored audit format) never panic the bounded
//! reader or the verifier; anything accepted is internally consistent and
//! attested only by checkpoints that carry a valid instance signature.
#![no_main]

use candor_log::SoftwareSigner;
use candor_log::chain::CheckpointSigner;
use candor_log::codes::StreamId;
use candor_log::disposal::{ApproverKeys, DisposalApprover, SoftwareApprover};
use candor_log::sink::read_stream;
use candor_log::verify::{VerifyParams, verify_stream};
use libfuzzer_sys::fuzz_target;
use zeroize::Zeroizing;

#[path = "det.rs"]
mod det;

fuzz_target!(|data: &[u8]| {
    // First byte: stream; then the record file and checkpoint file split at
    // the first 0xff byte (not valid inside UTF-8 JSON).
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let stream = match sel % 5 {
        0 => StreamId::Sec,
        1 => StreamId::Case,
        2 => StreamId::Sys,
        3 => StreamId::CaseSlot,
        _ => StreamId::SysSlot,
    };
    let cut = rest.iter().position(|&b| b == 0xff).unwrap_or(rest.len());
    let (recs, cps) = rest.split_at(cut);
    let cps = cps.get(1..).unwrap_or_default();
    let Ok((records, checkpoints)) = read_stream(stream, recs, cps) else {
        return;
    };
    let key = SoftwareSigner::from_seed(&Zeroizing::new([7; 32])).verifying_key();
    let tenant = det::tenant(b't');
    let approvers = ApproverKeys::new(
        vec![
            SoftwareApprover::from_seed(&Zeroizing::new([21; 32])).verifying_key(),
            SoftwareApprover::from_seed(&Zeroizing::new([22; 32])).verifying_key(),
        ],
        &key,
    )
    .expect("approver keys");
    for allow_pruned_prefix in [false, true] {
        let p = VerifyParams {
            tenant,
            stream,
            key: &key,
            approver_keys: &approvers,
            trusted_latest: None,
            allow_pruned_prefix,
            min_retention_days: None,
        };
        if let Ok(rep) = verify_stream(&p, &records, &checkpoints) {
            assert_eq!(rep.checkpoints, checkpoints.len() as u64);
            assert!(checkpoints.iter().all(|c| c.verify_signature(&key)));
            assert!(rep.next_seq >= rep.first_seq.unwrap_or(0));
            assert!(rep.redacted <= rep.records);
            if !allow_pruned_prefix {
                assert_eq!(
                    rep.first_seq.unwrap_or(0),
                    0,
                    "prefix accepted without opt-in"
                );
            }
        }
    }
});
