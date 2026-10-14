// SPDX-License-Identifier: Apache-2.0 OR MIT
//! ST-048 `fuzz_safefs_names`: arbitrary byte names, Unicode forms and
//! reserved names are sanitized into a single, inert, display-only component.
//!
//! Oracle: `DisplayName` guarantees (display.rs) hold for every input, and
//! the sanitized text, if (mis)used as a path, is exactly one normal
//! component, so it can never resolve outside a root. The store itself never
//! accepts a `DisplayName` (no `AsRef<Path>`), which the type system checks.
#![no_main]
mod common;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    common::check_display_name(&candor_safefs::DisplayName::from_bytes_lossy(data));
    if let Ok(s) = std::str::from_utf8(data) {
        let n = candor_safefs::DisplayName::sanitize(s);
        common::check_display_name(&n);
        // Debug must never echo the source-supplied text (EVID-008).
        let dbg = format!("{n:?}");
        assert!(dbg.starts_with("DisplayName(<") && dbg.ends_with(" bytes>)"));
    }
});
