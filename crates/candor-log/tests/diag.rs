// SPDX-License-Identifier: AGPL-3.0-or-later
//! 20 §7 `diag!`: static message + enumerated codes, delivered to the
//! process-wide sink; no timestamp or dynamic data in the record.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use candor_log::codes::{Code, OperationClass, SessionEndReason};
use candor_log::diag;
use candor_log::diag::{DiagLevel, DiagRing, set_sink};

static RING: std::sync::LazyLock<DiagRing> = std::sync::LazyLock::new(|| DiagRing::new(16));

#[test]
fn diag_reaches_sink_with_static_contents() {
    set_sink(&*RING).unwrap();
    assert!(set_sink(&*RING).is_err(), "sink is set once");

    diag!(Error, "sealer unreachable");
    diag!(
        Warn,
        "session ended",
        SessionEndReason::IdleTimeout,
        Code::<OperationClass>::of::<3>(),
    );
    diag!(Trace, "trace detail");
    let line_debug = line!() - 1;

    let recs = RING.snapshot();
    let first = recs.first().unwrap();
    assert_eq!(first.level(), DiagLevel::Error);
    assert_eq!(first.message(), "sealer unreachable");
    assert_eq!(first.module(), module_path!());
    assert_eq!(first.codes().count(), 0);

    let second = recs.get(1).unwrap();
    let codes: Vec<_> = second.codes().collect();
    assert_eq!(codes.len(), 2);
    assert_eq!(codes[0].text(), Some("IDLE_TIMEOUT"));
    assert_eq!(codes[1].registry_code(), Some(("operation_class", 3)));
    // Trace/Info are compiled out unless debug_assertions (release ceiling Warn).
    let has_debug = recs.iter().any(|r| r.line() == line_debug);
    assert_eq!(has_debug, cfg!(debug_assertions));
    // Debug output of a record contains only static data.
    let dbg = format!("{second:?}");
    assert!(dbg.contains("session ended") && dbg.contains("IDLE_TIMEOUT"));

    // AUD-RM1-LOG-04: a hand-written call site bypassing the macro still
    // has to name a compile-time constant message; `__private::emit` asserts
    // it at monomorphisation (calling `emit::<Bad>` does not build) and
    // again at run time. A runtime string cannot be a `const` at all (see
    // tests/ui/diag_forged_internals.rs).
    struct Bad;
    impl candor_log::diag::__private::Site for Bad {
        const LEVEL: DiagLevel = DiagLevel::Error;
        const MESSAGE: &'static str = "203.0.113.7\n/home/src/leak.pdf";
        const MODULE: &'static str = "m";
        const LINE: u32 = 1;
        const DEBUG_ASSERTIONS: bool = true;
    }
    assert!(!candor_log::diag::__private::message_ok(
        <Bad as candor_log::diag::__private::Site>::MESSAGE
    ));
}
