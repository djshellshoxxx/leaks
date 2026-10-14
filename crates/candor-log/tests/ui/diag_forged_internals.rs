// SPDX-License-Identifier: AGPL-3.0-or-later
// AUD-RM1-LOG-04: diag! internals cannot carry runtime text or forged codes.
use candor_log::diag::{DiagCodeValue, DiagLevel, __private};

struct Leak;
impl __private::Site for Leak {
    const LEVEL: DiagLevel = DiagLevel::Warn;
    const MESSAGE: &'static str = Box::leak(format!("{}", 1).into_boxed_str());
    const MODULE: &'static str = "m";
    const LINE: u32 = 1;
}

fn main() {
    let _c = DiagCodeValue::Code("203.0.113.7");
    __private::emit::<Leak>(&[]);
}
