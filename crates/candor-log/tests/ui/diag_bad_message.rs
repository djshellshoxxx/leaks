// SPDX-License-Identifier: AGPL-3.0-or-later
// 20 §7: diag! messages are printable ASCII (no log injection), not formatted,
// and never a non-string literal.
fn main() {
    candor_log::diag!(Warn, "line\nforged entry");
    candor_log::diag!(Warn, b"bytes");
    candor_log::diag!(Warn, "{}", 1u8);
    candor_log::diag!(Verbose, "unknown level");
}
