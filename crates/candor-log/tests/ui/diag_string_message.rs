// SPDX-License-Identifier: AGPL-3.0-or-later
// 20 §7: diag! accepts only a string literal message, never a runtime string.
fn main() {
    let name = String::from("evidence.pdf");
    candor_log::diag!(Warn, name);
}
