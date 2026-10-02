// SPDX-License-Identifier: AGPL-3.0-or-later
//! LOG-001 / LOG-002 compile-fail tests.

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
