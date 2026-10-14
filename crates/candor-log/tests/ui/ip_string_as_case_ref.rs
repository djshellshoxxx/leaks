// SPDX-License-Identifier: AGPL-3.0-or-later
// A source IP string cannot be passed where an audit field is expected.
use candor_log::AuditEvent;

fn main() {
    let _e = AuditEvent::CaseOpened {
        case: String::from("203.0.113.7"),
    };
}
