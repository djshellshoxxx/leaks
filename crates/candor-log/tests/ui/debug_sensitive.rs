// SPDX-License-Identifier: AGPL-3.0-or-later
// Sensitive wrappers cannot be formatted (LOG-002).
use candor_log::sensitive::Sensitive;

fn main() {
    let ua = Sensitive::new(String::from("Mozilla/5.0"));
    let _s = format!("{:?}", ua);
}
