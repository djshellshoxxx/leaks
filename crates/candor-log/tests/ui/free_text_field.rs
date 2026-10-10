// SPDX-License-Identifier: AGPL-3.0-or-later
// Events have no free-text message field: unknown fields do not exist.
use candor_log::AuditEvent;
use candor_log::ids::CaseRef;

fn main() {
    let _e = AuditEvent::CaseOpened {
        case: CaseRef::generate().unwrap(),
        message: "user agent Mozilla/5.0",
    };
}
