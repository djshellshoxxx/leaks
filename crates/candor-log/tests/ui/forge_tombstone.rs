// SPDX-License-Identifier: AGPL-3.0-or-later
// AUD-RM1-LOG-16: a disposal tombstone cannot be built outside the
// disposal API (private payload fields, no public set-hash helper).
use candor_log::AuditEvent;
use candor_log::disposal::CaseDisposal;
use candor_log::ids::{CaseRef, ReceiptId};

fn main() {
    let c = CaseRef::generate().unwrap();
    let _old = AuditEvent::CaseDisposed {
        case: c,
        receipt_id: ReceiptId::generate().unwrap(),
        removed_event_count: 1,
        redacted_set: [0u8; 32],
    };
    let _new = AuditEvent::CaseDisposed {
        disposal: CaseDisposal {
            case: c,
            receipt: ReceiptId::generate().unwrap(),
        },
    };
    let _h = candor_log::chain::redaction_set_hash(&[(0, [0u8; 32])]);
}
