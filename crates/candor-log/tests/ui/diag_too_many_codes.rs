// SPDX-License-Identifier: AGPL-3.0-or-later
// 20 §7: diag! carries at most MAX_DIAG_CODES codes.
use candor_log::codes::SessionEndReason::IdleTimeout as I;
fn main() {
    candor_log::diag!(Warn, "too many", I, I, I, I, I);
}
