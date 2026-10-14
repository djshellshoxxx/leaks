// SPDX-License-Identifier: AGPL-3.0-or-later
//! Seed corpus for `fuzz_istore_frame`: one canonical encoding of every
//! request and response type, each in request mode (`0`) or response mode
//! (`1`). Run from `crates/candor-intake-store/fuzz`; writes
//! `seeds/fuzz_istore_frame/`.

use candor_intake_store::proto::*;
use candor_intake_store::{
    DISPOSITION_CT_LEN_STD, MAX_PREFS_CT, SLOT_BLOCK_LEN_STD, XWING_PK_LEN,
};

fn inline(h: u8, n: usize) -> InlineObject {
    InlineObject {
        object_hash: [h; 32],
        slot_block: vec![h; SLOT_BLOCK_LEN_STD],
        bytes: vec![h; n],
    }
}

fn requests() -> Vec<Request> {
    vec![
        Request::ServingAllowed,
        Request::AccountLookup { tag: [1; 32] },
        Request::MailboxList { account: [2; 16] },
        Request::MailboxRead { account: [2; 16], reply: [3; 16] },
        Request::CommitGroup(Box::new(CommitGroup {
            channel_id: [1; 16],
            epoch_index: 7,
            received_day: 20_741,
            release_offset_days: 3,
            disposition_ct: vec![9; DISPOSITION_CT_LEN_STD],
            main: inline(2, 300),
            bundle: BundleObject {
                object_hash: [4; 32],
                slot_block: vec![5; SLOT_BLOCK_LEN_STD],
                padded_size: 262_144,
            },
            identity: inline(6, 100),
        })),
        Request::AccountUpsert(Box::new(AccountUpsert {
            replaces: Some([8; 32]),
            lookup_tag: [9; 32],
            auth_pk: [10; 32],
            xwing_pk: vec![11; XWING_PK_LEN],
            prefs_ct: vec![12; 64],
            mailbox_ids: vec![[13; 32]],
            rewrapped: vec![([14; 32], vec![15; 40])],
        })),
        Request::AccountUpsert(Box::new(AccountUpsert {
            replaces: None,
            lookup_tag: [9; 32],
            auth_pk: [10; 32],
            xwing_pk: vec![11; XWING_PK_LEN],
            prefs_ct: vec![12; MAX_PREFS_CT],
            mailbox_ids: vec![],
            rewrapped: vec![],
        })),
        Request::Delete(Delete::Account { lookup_tags: vec![[1; 32], [2; 32]] }),
        Request::Delete(Delete::Mailbox { lookup_tag: [1; 32], mailbox_id: [2; 32] }),
        Request::Delete(Delete::Replies { lookup_tag: [1; 32], replies: vec![[3; 16], [4; 16]] }),
        Request::Relay(Op::RelayClaim),
        Request::Relay(Op::RelayBackup),
    ]
}

fn responses() -> Vec<(Op, Response)> {
    vec![
        (Op::CommitGroup, Response::Empty),
        (Op::AccountUpsert, Response::Empty),
        (Op::ServingAllowed, Response::ServingAllowed(true)),
        (Op::AccountLookup, Response::Account(None)),
        (
            Op::AccountLookup,
            Response::Account(Some(AccountInfo { account_id: [1; 16], auth_pk: [2; 32], prefs_ct: vec![3; 50] })),
        ),
        (
            Op::MailboxList,
            Response::MailboxList(vec![ReplyHeader { reply_ref: [4; 16], slot: 3, size_bucket: 2, available_day: 20_000 }; 3]),
        ),
        (Op::MailboxRead, Response::ReplyCt(vec![5; 500])),
        (Op::Delete, Response::Deleted(3)),
        (Op::Delete, Response::Error(ErrorCode::NotFound)),
        (Op::RelayClaim, Response::Error(ErrorCode::Forbidden)),
    ]
}

fn main() {
    let dir = std::path::Path::new("seeds/fuzz_istore_frame");
    std::fs::create_dir_all(dir).expect("seed dir");
    let mut n = 0usize;
    let mut put = |bytes: Vec<u8>| {
        std::fs::write(dir.join(format!("seed-{n:03}")), bytes).expect("write seed");
        n += 1;
    };
    for r in requests() {
        let mut b = vec![0u8];
        b.extend(encode_request(7, &r).expect("encode"));
        put(b);
    }
    for (op, r) in responses() {
        let mut b = vec![1u8];
        b.extend(encode_response(op, 7, &r).expect("encode"));
        put(b);
    }
    println!("wrote {n} seeds");
}
