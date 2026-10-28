// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RecipientSlotBlock (§13.2, ST-040): input = `slot block ‖ n × 97-byte Recipient
//! List entries`. The decoder never panics and round-trips; with the fuzz member key,
//! trial-open runs over all 16 slots and, when it yields CK, full ADR-050(3)
//! re-derivation of all slots runs against the trailing entries.
#![no_main]
#[path = "common.rs"]
mod common;

use candor_core::Suite;
use candor_core::slots::{
    RECIPIENT_ENTRY_LEN, RecipientListEntry, RecipientSlotBlock, SLOT_BLOCK_LEN, SlotBinding,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (blk, tail) = data.split_at(data.len().min(SLOT_BLOCK_LEN));
    let Ok(b) = RecipientSlotBlock::decode(blk) else {
        let _ = RecipientSlotBlock::decode(data);
        return;
    };
    assert_eq!(b.encode(), blk);
    let _ = b.hash();
    let binding = SlotBinding {
        suite: Suite::CandorStd1,
        object_id: common::SEED_OBJECT_ID,
        payload_nonce: common::SEED_PAYLOAD_NONCE,
        context: common::member_ctx(),
    };
    if let Ok((ck, pos)) = b.trial_open(&common::member().private, &binding) {
        assert!(pos < 16);
        let entries: Vec<RecipientListEntry> = tail
            .chunks(RECIPIENT_ENTRY_LEN)
            .filter_map(|e| RecipientListEntry::from_bytes(e).ok())
            .collect();
        let _ = b.verify_slot_block(&ck, &binding, &entries, common::directory);
    }
});
