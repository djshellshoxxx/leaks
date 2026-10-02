// SPDX-License-Identifier: AGPL-3.0-or-later
//! Conformance suite against the in-memory store.
#![allow(clippy::unwrap_used)]

mod common;

use candor_intake_store::{MemoryStore, RandomDummyReplies, TenantId};

fn factory() -> Option<impl Fn(TenantId) -> std::future::Ready<MemoryStore>> {
    Some(|_t: TenantId| {
        std::future::ready(
            MemoryStore::with_config(common::TEST_DEADDROP, Box::new(RandomDummyReplies)).unwrap(),
        )
    })
}

conformance_tests!(factory());

/// The default in-memory configuration is valid and small.
#[test]
fn memory_default_config() {
    candor_intake_store::MEMORY_DEADDROP_CONFIG
        .validate()
        .unwrap();
    assert!(MemoryStore::new().is_ok());
}
