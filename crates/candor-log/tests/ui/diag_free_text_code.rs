// SPDX-License-Identifier: AGPL-3.0-or-later
// 20 §7: diag! codes must be enumerated codes; strings/numbers are rejected.
fn main() {
    let ip = String::from("192.0.2.1");
    candor_log::diag!(Warn, "peer", ip);
    candor_log::diag!(Warn, "size", 4096u64);
}
