// SPDX-License-Identifier: AGPL-3.0-or-later
//! ST-043 `fuzz_istore_frame`: the `istore` datagram parsers never panic or
//! over-allocate on arbitrary bytes, and whatever decodes re-encodes
//! byte-identically (one canonical layout).
//!
//! The first input byte selects a mode: `0` decodes a request, `1` decodes
//! a response against every op, `2` does both on the rest.
#![no_main]

use candor_intake_store::proto::{
    MAX_FRAME_LEN, Op, decode_request, decode_response, encode_request, encode_response,
    max_request_len, max_response_len,
};
use libfuzzer_sys::fuzz_target;

const OPS: [Op; 18] = [
    Op::ServingAllowed,
    Op::AccountLookup,
    Op::MailboxList,
    Op::MailboxRead,
    Op::CommitGroup,
    Op::AccountUpsert,
    Op::Delete,
    Op::RelayStatus,
    Op::RelayClaim,
    Op::RelayObject,
    Op::RelayAck,
    Op::RelayPushReplies,
    Op::RelayInstallSnapshot,
    Op::RelayDeletionList,
    Op::RelayAckDeletionHead,
    Op::RelayPushDeletionList,
    Op::RelayCounters,
    Op::RelayBackup,
];

fn requests(data: &[u8]) {
    if let Ok((rid, req)) = decode_request(data) {
        let again = encode_request(rid, &req).expect("decoded request re-encodes");
        assert_eq!(again, data, "non-canonical request accepted");
        assert!(data.len() <= max_request_len(req.op()));
    }
}

fn responses(data: &[u8]) {
    for op in OPS {
        if let Ok((rid, resp)) = decode_response(op, data) {
            let again = encode_response(op, rid, &resp).expect("decoded response re-encodes");
            assert_eq!(again, data, "non-canonical response accepted");
            assert!(data.len() <= max_response_len(op));
        }
        assert!(max_request_len(op) <= MAX_FRAME_LEN);
        assert!(max_response_len(op) <= MAX_FRAME_LEN);
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 3 {
        0 => requests(rest),
        1 => responses(rest),
        _ => {
            requests(rest);
            responses(rest);
        }
    }
});
