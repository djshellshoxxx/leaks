// SPDX-License-Identifier: AGPL-3.0-or-later
//! 20 §7 `diag!`: static message + enumerated codes, delivered to the
//! process-wide sink; no timestamp or dynamic data in the record.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use candor_log::codes::{Code, OperationClass, SessionEndReason};
use candor_log::diag;
use candor_log::diag::{DiagCodeValue, DiagLevel, DiagRing, set_sink};

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
        Code::<OperationClass>::new(3),
    );
    diag!(Debug, "debug detail");
    let line_debug = line!() - 1;

    let recs = RING.snapshot();
    let first = recs.first().unwrap();
    assert_eq!(first.level(), DiagLevel::Error);
    assert_eq!(first.message(), "sealer unreachable");
    assert_eq!(first.module(), module_path!());
    assert_eq!(first.codes().count(), 0);

    let second = recs.get(1).unwrap();
    assert_eq!(
        second.codes().collect::<Vec<_>>(),
        [
            DiagCodeValue::Code("IDLE_TIMEOUT"),
            DiagCodeValue::Registry {
                space: "operation_class",
                code: 3
            }
        ]
    );
    // Debug/Info are compiled out unless debug_assertions (release ceiling Warn).
    let has_debug = recs.iter().any(|r| r.line() == line_debug);
    assert_eq!(has_debug, cfg!(debug_assertions));
    // Debug output of a record contains only static data.
    let dbg = format!("{second:?}");
    assert!(dbg.contains("session ended") && dbg.contains("IDLE_TIMEOUT"));
}
