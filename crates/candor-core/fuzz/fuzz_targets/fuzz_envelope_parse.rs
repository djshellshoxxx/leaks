// SPDX-License-Identifier: Apache-2.0 OR MIT
//! ST-040 `fuzz_envelope_parse` (structure-aware, AUD-RM1-CORE-06): input is
//! `[slot block ‖] sealed object`. Exercises parse → header-derived binding →
//! header-MAC check → STREAM open under the fixed CK, and for intake objects
//! slot-block commitment → trial-open with the fuzz member → payload open → Recipient
//! List parse (toy layout `u32be(5) ‖ "hello" ‖ u8 n ‖ n × entry`) → full slot
//! re-derivation. Invariants: plaintext is released only if the header MAC verifies,
//! and never under a different CK.
#![no_main]
#[path = "common.rs"]
mod common;

use candor_core::object::parse;
use candor_core::secret::ContentKey;
use candor_core::slots::{RECIPIENT_ENTRY_LEN, RecipientListEntry, RecipientSlotBlock, SLOT_BLOCK_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (block, obj) = match data.split_at_checked(SLOT_BLOCK_LEN) {
        Some((b, rest)) => match RecipientSlotBlock::decode(b) {
            Ok(blk) => (Some(blk), rest),
            Err(_) => (None, data),
        },
        None => (None, data),
    };
    let Ok(p) = parse(obj) else { return };
    let _ = p.object_hash();
    let _ = format!("{p:?}");
    let ck = ContentKey::from_bytes(common::CK);
    let opened = p.open(&ck);
    if opened.is_ok() {
        assert!(p.verify(&ck).is_ok());
    }
    assert!(p.open(&ContentKey::from_bytes([1; 32])).is_err());
    if let Ok((dec, payload)) = p.open_stream(&ck) {
        let mut rd = dec.reader(payload);
        let released: usize = rd.by_ref().filter_map(Result::ok).map(|c| c.len()).sum();
        let fin = rd.finish();
        assert_eq!(fin.is_ok(), opened.is_ok());
        if let Ok(pt) = &opened {
            assert_eq!(released, pt.len());
        }
    }
    let (Some(blk), Ok(binding)) = (block, p.slot_binding_from_header()) else { return };
    if p.check_slot_block(&blk).is_err() {
        return;
    }
    let Ok((ck2, _)) = blk.trial_open(&common::member().private, &binding) else { return };
    let Ok(pt) = p.open(&ck2) else { return };
    let n = usize::from(pt.get(9).copied().unwrap_or(0));
    let entries: Vec<RecipientListEntry> = pt
        .get(10..10 + n * RECIPIENT_ENTRY_LEN)
        .unwrap_or_default()
        .chunks(RECIPIENT_ENTRY_LEN)
        .filter_map(|e| RecipientListEntry::from_bytes(e).ok())
        .collect();
    let _ = blk.verify_slot_block(&ck2, &binding, &entries, common::directory);
});
