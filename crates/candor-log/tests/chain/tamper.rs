// SPDX-License-Identifier: AGPL-3.0-or-later
//! AUD-004 chain tampering regressions; exact assertions moved from `chain.rs`.
use super::*;

// AUD-004 tamper fixtures: modified payload, reordered, deleted, truncated,
// forged signature.
#[test]
fn deletion_of_middle_event_detected() {
    let (mut recs, cps, key) = setup(12, 5);
    recs.remove(6);
    assert_eq!(code_of(&recs, &cps, &key), VerifyFailureCode::SequenceGap);
}

#[test]
fn reordering_detected() {
    let (mut recs, cps, key) = setup(12, 5);
    recs.swap(3, 4);
    assert_eq!(code_of(&recs, &cps, &key), VerifyFailureCode::SequenceOrder);
}

#[test]
fn modification_detected() {
    let (mut recs, cps, key) = setup(12, 5);
    // Re-encode record 3 with a different case ID but keep it canonical.
    let ChainRecord::Full { bytes, salt, .. } = &recs[3] else {
        panic!()
    };
    let mut b = bytes.clone();
    let pos = b.windows(16).position(|w| w == case(3).as_bytes()).unwrap();
    b[pos] ^= 0x99;
    recs[3] = ChainRecord::Full {
        bytes: b,
        salt: *salt,
        claimed_hash: None,
    };
    assert_eq!(code_of(&recs, &cps, &key), VerifyFailureCode::ChainMismatch);
}

#[test]
fn modification_of_last_record_detected_by_checkpoint() {
    let (mut recs, cps, key) = setup(10, 5);
    let ChainRecord::Full { bytes, salt, .. } = &recs[9] else {
        panic!()
    };
    let mut b = bytes.clone();
    let pos = b.windows(16).position(|w| w == case(9).as_bytes()).unwrap();
    b[pos] ^= 0x42;
    recs[9] = ChainRecord::Full {
        bytes: b,
        salt: *salt,
        claimed_hash: None,
    };
    assert_eq!(
        code_of(&recs, &cps, &key),
        VerifyFailureCode::MerkleMismatch
    );
}

#[test]
fn truncation_below_checkpoint_detected() {
    let (mut recs, cps, key) = setup(10, 5);
    recs.truncate(8);
    assert_eq!(code_of(&recs, &cps, &key), VerifyFailureCode::Truncated);
}

#[test]
fn deleting_head_detected() {
    let (recs, cps, key) = setup(10, 5);
    assert_eq!(
        code_of(&recs[1..], &cps, &key),
        VerifyFailureCode::MissingPrefix
    );
}

#[test]
fn forged_checkpoint_rejected() {
    let (recs, cps, _key) = setup(10, 5);
    let other = signer(99).verifying_key_for_test();
    assert_eq!(
        code_of(&recs, &cps, &other),
        VerifyFailureCode::BadSignature
    );
    // Tampered signature bytes.
    let mut sig = *cps[0].signature();
    sig[0] ^= 1;
    let bad = candor_log::SignedCheckpoint::from_parts(cps[0].bytes().to_vec(), sig).unwrap();
    let key = signer(7).verifying_key_for_test();
    let mut cps2 = cps.clone();
    cps2[0] = bad;
    assert_eq!(code_of(&recs, &cps2, &key), VerifyFailureCode::BadSignature);
    // Dropping a checkpoint breaks the checkpoint chain.
    let cps3 = vec![cps[1].clone()];
    assert_eq!(
        code_of(&recs, &cps3, &key),
        VerifyFailureCode::CheckpointChain
    );
}

