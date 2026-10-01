// SPDX-License-Identifier: AGPL-3.0-or-later
//! Panic handling and metadata hygiene (IMPL-00 §4.4, 07 §8; A1, AT-018):
//! a handler panic becomes the fixed 500 page (unwinding test builds; release
//! builds abort) and the panic hook emits only a static diagnostic, never
//! the payload; the `StoreReads` seam works over the real `MemoryStore`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use std::sync::Mutex;
use std::sync::atomic::Ordering;

use candor_intake_store::{IntakeStore, MemoryStore, TenantId};
use candor_intake_web::StoreReads;
use candor_log::diag::{DiagRecord, DiagSink};
use support::*;

struct Capture(Mutex<Vec<DiagRecord>>);

impl DiagSink for Capture {
    fn record(&self, r: &DiagRecord) {
        self.0.lock().unwrap().push(*r);
    }
}

static SINK: Capture = Capture(Mutex::new(Vec::new()));

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_panic_is_the_fixed_500_page_and_logs_no_payload() {
    let _ = candor_log::diag::set_sink(&SINK);
    candor_intake_web::install_panic_hook();
    let h = harness().await;
    h.store.add_account(&passphrase_words().join(" "));
    h.store.panic.store(true, Ordering::SeqCst);
    let (pre, tok) = h.pre().await;
    let body = format!(
        "csrf={tok}&action=login&passphrase={}",
        enc(&passphrase_words().join(" "))
    );
    let r = h.post("/en/login", &[&pre], &body).await;
    assert_eq!(r.status, 500);
    assert_eq!(r.head.len(), 2048);
    assert_eq!(r.body.len(), 131_072);
    assert!(!r.text().contains("canary-panic"));
    // The service keeps serving.
    h.store.panic.store(false, Ordering::SeqCst);
    assert_eq!(h.get("/en/", &[]).await.status, 200);
    let recs = SINK.0.lock().unwrap();
    assert!(!recs.is_empty(), "the hook recorded the panic");
    for r in recs.iter() {
        assert!(!r.message().contains("canary"));
        assert_eq!(r.codes().count(), 0);
    }
    let _ = std::panic::take_hook();
}

/// The blanket `StoreReads` for every `IntakeStore` (MemoryStore here):
/// unknown locators are `None` (the caller then verifies against a dummy
/// key), restore-pending stops serving, nothing is written by reads.
#[tokio::test]
async fn store_reads_over_memory_store() {
    let s = MemoryStore::new().unwrap();
    s.init(TenantId([0x11; 16]), [0x5a; 32]).await.unwrap();
    assert_eq!(StoreReads::serving_allowed(&s).await, Ok(true));
    assert!(StoreReads::account(&s, [9; 32]).await.unwrap().is_none());
    s.mark_restore_pending().await.unwrap();
    assert_eq!(StoreReads::serving_allowed(&s).await, Ok(false));
    // Uninitialised store: an error, never a default.
    let u = MemoryStore::new().unwrap();
    assert!(StoreReads::account(&u, [9; 32]).await.is_err());
}

/// Debug output of the public types never carries secrets or input.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn debug_is_redacted() {
    let h = harness().await;
    assert_eq!(format!("{:?}", h.web), "Web");
    let r = h.get("/en/", &[]).await;
    let cookie = r.cookie().unwrap();
    let f = candor_intake_web::form::parse_form(b"csrf=abc", &|n| {
        candor_intake_web::routes::rule(candor_source_ui::Route::Leave, n)
    })
    .unwrap();
    assert!(!format!("{f:?}").contains("abc"));
    assert!(!format!("{:?}", h.web.health()).contains(&cookie));
}
