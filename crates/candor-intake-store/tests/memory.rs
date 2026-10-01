// SPDX-License-Identifier: AGPL-3.0-or-later
//! Conformance suite against the in-memory store.
#![allow(clippy::unwrap_used)]

mod common;

use candor_intake_store::{MemoryStore, TenantId};

fn factory() -> Option<impl Fn(TenantId) -> std::future::Ready<MemoryStore>> {
    Some(|_t: TenantId| std::future::ready(MemoryStore::new().unwrap()))
}

conformance_tests!(factory());
