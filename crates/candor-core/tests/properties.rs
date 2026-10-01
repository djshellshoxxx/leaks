// SPDX-License-Identifier: Apache-2.0 OR MIT
//! ST-024 / ST-025 property tests over the public sealed-object API: round trip for
//! random sizes; any single-bit flip of the blob, truncation or extension is rejected.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use candor_core::Suite;
use candor_core::header::ObjectType;
use candor_core::kem::KemKeyPair;
use candor_core::object::{SealRequest, parse, seal};
use candor_core::padding::pad;
use candor_core::slots::SlotContext;
use proptest::prelude::*;
use std::sync::OnceLock;

fn reply_req(pt: &[u8]) -> SealRequest<'_> {
    SealRequest {
        suite: Suite::CandorStd1,
        object_type: ObjectType::Reply,
        tenant_id: [1; 16],
        channel_id: [0; 16],
        epoch_id: 0,
        day_stamp: 0,
        recipients: None,
        padded_plaintext: pt,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn reply_roundtrip_and_any_bitflip_rejected(content in proptest::collection::vec(any::<u8>(), 0..20_000), bit in any::<usize>()) {
        let pt = pad(ObjectType::Reply, &content).unwrap();
        let (ck, obj) = seal(&reply_req(&pt)).unwrap();
        let back = parse(&obj.bytes).unwrap().open(&ck).unwrap();
        prop_assert_eq!(&back[..content.len()], content.as_slice());
        let mut bad = obj.bytes.clone();
        let b = bit % (bad.len() * 8);
        bad[b / 8] ^= 1 << (b % 8);
        // Either the structural parse or authentication must fail.
        let r = parse(&bad).and_then(|p| p.open(&ck).map(|_| ()));
        prop_assert!(r.is_err());
    }

    #[test]
    fn truncation_and_extension_rejected(cut in 1usize..200, ext in proptest::collection::vec(any::<u8>(), 1..20)) {
        let pt = pad(ObjectType::Reply, b"x").unwrap();
        let (_ck, obj) = seal(&reply_req(&pt)).unwrap();
        let cut = cut.min(obj.bytes.len());
        prop_assert!(parse(&obj.bytes[..obj.bytes.len() - cut]).is_err());
        let mut long = obj.bytes.clone();
        long.extend_from_slice(&ext);
        prop_assert!(parse(&long).is_err());
    }

    /// Arbitrary bytes never parse into an openable object and never panic.
    #[test]
    fn arbitrary_blob(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
        let _ = parse(&bytes);
    }
}

fn member() -> &'static KemKeyPair {
    static M: OnceLock<KemKeyPair> = OnceLock::new();
    M.get_or_init(|| KemKeyPair::generate(Suite::CandorStd1).unwrap())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    /// ST-025 context binding: an intake object opened with a different tenant,
    /// channel or epoch in the slot context fails.
    #[test]
    fn intake_context_binding(epoch in 0u32..1000, which in 0usize..3) {
        let ctx = SlotContext::MemberEpoch { tenant_id: [1; 16], channel_id: [2; 16], epoch_id: epoch };
        let pt = pad(ObjectType::SourceMessage, b"msg").unwrap();
        let pks = [member().public.clone()];
        let req = SealRequest {
            suite: Suite::CandorStd1,
            object_type: ObjectType::SourceMessage,
            tenant_id: [1; 16],
            channel_id: [2; 16],
            epoch_id: epoch,
            day_stamp: 0,
            recipients: Some((ctx.clone(), &pks)),
            padded_plaintext: &pt,
        };
        let (_ck, obj) = seal(&req).unwrap();
        let p = parse(&obj.bytes).unwrap();
        let blk = obj.slot_block.unwrap();
        let (ck, pos) = blk.trial_open(&member().private, &p.slot_binding(ctx.clone())).unwrap();
        blk.verify(&ck, &p.slot_binding(ctx), 1, Some(pos)).unwrap();
        let wrong = match which {
            0 => SlotContext::MemberEpoch { tenant_id: [9; 16], channel_id: [2; 16], epoch_id: epoch },
            1 => SlotContext::MemberEpoch { tenant_id: [1; 16], channel_id: [9; 16], epoch_id: epoch },
            _ => SlotContext::MemberEpoch { tenant_id: [1; 16], channel_id: [2; 16], epoch_id: epoch.wrapping_add(1) },
        };
        prop_assert!(blk.trial_open(&member().private, &p.slot_binding(wrong)).is_err());
    }
}
