// SPDX-License-Identifier: Apache-2.0 OR MIT
//! ST-049 `fuzz_archive` / ST-048 — tar (absolute/`..` names, PAX/GNU long names, links, devices).
//!
//! Oracle (see `common::extract_and_check`): never panics; nothing is
//! created outside the per-input root; the root holds only directories and
//! single-link regular files; the report respects every configured limit.
#![no_main]
mod common;

use candor_safefs::archive;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    common::extract_and_check(|root, opts| archive::extract_tar(data, root, opts));
});
