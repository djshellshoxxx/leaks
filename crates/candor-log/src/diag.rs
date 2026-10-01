// SPDX-License-Identifier: AGPL-3.0-or-later
//! Restricted developer diagnostics: the only sanctioned alternative to the
//! banned free-text macros in trust-path crates (20 §7, LOG-001).
//!
//! [`diag!`](crate::diag!) accepts **only**
//! * a level ([`DiagLevel`] variant name),
//! * a string *literal* message of 1..=[`MAX_DIAG_MSG_BYTES`] bytes of
//!   printable ASCII (checked at compile time; no formatting, no
//!   interpolation, no control characters, so no log injection), and
//! * at most [`MAX_DIAG_CODES`] enumerated codes: closed code enums from
//!   [`crate::codes`] or numeric registry [`Code`](crate::codes::Code)s
//!   (the sealed [`DiagCode`] trait; strings, numbers, ids, paths, errors
//!   and every other type are rejected at compile time).
//!
//! A [`DiagRecord`] carries no timestamp, no host, process or request
//! data: only the static call site (`module_path!()`, `line!()`), the
//! static message and the codes (ADR-010/016; Z-INTAKE forbids per-request
//! logs, 20 §6.2).
//!
//! Release builds (`debug_assertions` off in the *calling* crate) compile
//! out `Info` and `Trace` diagnostics entirely, matching the
//! `release_max_level_warn` ceiling of 20 §7. Records go to the single
//! process-wide [`DiagSink`] installed with [`set_sink`]; without a sink
//! they are dropped (nothing is ever written to stdout/stderr or disk
//! here). [`DiagRing`] is a bounded in-memory sink (Z-RCP ring buffer).

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

use crate::field::sealed::Sealed;

/// Maximum message length in bytes.
pub const MAX_DIAG_MSG_BYTES: usize = 120;
/// Maximum number of codes per diagnostic.
pub const MAX_DIAG_CODES: usize = 4;
/// Upper bound on [`DiagRing`] capacity (records). With the bounded record
/// size this keeps a ring well under the 1 MiB Desk buffer (20 §6.2).
pub const MAX_RING_RECORDS: usize = 4096;

/// Diagnostic level, most severe first.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum DiagLevel {
    /// Error.
    Error,
    /// Warning.
    Warn,
    /// Informational (debug builds only).
    Info,
    /// Fine-grained tracing (debug builds only). Named `Trace`, not
    /// `Debug`, so it never shadows `core::fmt::Debug` in diagnostics.
    Trace,
}

/// The value of one enumerated code.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DiagCodeValue {
    /// Closed-enum code text (e.g. `"IDLE_TIMEOUT"`).
    Code(&'static str),
    /// Numeric registry code.
    Registry {
        /// Registry name ([`crate::codes::CodeSpace::NAME`]).
        space: &'static str,
        /// Code number.
        code: u16,
    },
}

/// Types `diag!` accepts as codes. Sealed: implemented only by the closed
/// code enums and [`Code`](crate::codes::Code) of this crate.
pub trait DiagCode: Sealed {
    /// The code value.
    fn diag_code(&self) -> DiagCodeValue;
}

/// One diagnostic. All contents are static or enumerated.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DiagRecord {
    level: DiagLevel,
    module: &'static str,
    line: u32,
    message: &'static str,
    codes: [Option<DiagCodeValue>; MAX_DIAG_CODES],
}

impl DiagRecord {
    /// Used by [`diag!`](crate::diag!); extra codes beyond
    /// [`MAX_DIAG_CODES`] are impossible (compile-time check) and would be
    /// dropped, never stored.
    #[doc(hidden)]
    pub fn __new(
        level: DiagLevel,
        module: &'static str,
        line: u32,
        message: &'static str,
        codes: &[DiagCodeValue],
    ) -> Self {
        let mut c = [None; MAX_DIAG_CODES];
        for (slot, v) in c.iter_mut().zip(codes.iter()) {
            *slot = Some(*v);
        }
        Self {
            level,
            module,
            line,
            message,
            codes: c,
        }
    }
    /// Level.
    pub fn level(&self) -> DiagLevel {
        self.level
    }
    /// Emitting module path (static).
    pub fn module(&self) -> &'static str {
        self.module
    }
    /// Source line of the call site.
    pub fn line(&self) -> u32 {
        self.line
    }
    /// Static message.
    pub fn message(&self) -> &'static str {
        self.message
    }
    /// Codes, in call order.
    pub fn codes(&self) -> impl Iterator<Item = DiagCodeValue> + '_ {
        self.codes.iter().flatten().copied()
    }
}

/// Receiver of diagnostics.
pub trait DiagSink: Send + Sync {
    /// Records one diagnostic. Must not block for long or panic.
    fn record(&self, r: &DiagRecord);
}

static SINK: OnceLock<&'static dyn DiagSink> = OnceLock::new();

/// [`set_sink`] was already called.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SinkAlreadySet;

/// Installs the process-wide sink (once; later calls fail).
pub fn set_sink(sink: &'static dyn DiagSink) -> Result<(), SinkAlreadySet> {
    SINK.set(sink).map_err(|_| SinkAlreadySet)
}

/// Whether `level` is compiled in, given the calling crate's
/// `debug_assertions` (release ceiling: `Warn`).
#[doc(hidden)]
pub const fn __enabled(level: DiagLevel, debug_assertions: bool) -> bool {
    debug_assertions || matches!(level, DiagLevel::Error | DiagLevel::Warn)
}

/// Compile-time message check: 1..=[`MAX_DIAG_MSG_BYTES`] bytes, printable
/// ASCII (0x20..=0x7E) only.
#[doc(hidden)]
pub const fn __message_ok(m: &str) -> bool {
    let b = m.as_bytes();
    if b.is_empty() || b.len() > MAX_DIAG_MSG_BYTES {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        // `i < b.len()` is checked by the loop condition.
        #[allow(clippy::indexing_slicing)]
        let c = b[i];
        if !(c.is_ascii_graphic() || c == b' ') {
            return false;
        }
        i = i.saturating_add(1);
    }
    true
}

/// Delivers a record to the installed sink, if any.
#[doc(hidden)]
pub fn __emit(r: &DiagRecord) {
    if let Some(s) = SINK.get() {
        s.record(r);
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! __diag_unit {
    ($x:expr) => {
        ()
    };
}

/// Emits a restricted diagnostic: `diag!(Warn, "static text", code, ...)`.
///
/// See [`crate::diag`] for the contract. Anything but a string literal
/// message and up to [`MAX_DIAG_CODES`](crate::diag::MAX_DIAG_CODES)
/// enumerated codes is a compile error.
#[macro_export]
macro_rules! diag {
    ($level:ident, $msg:literal $(, $code:expr)* $(,)?) => {{
        const __CANDOR_DIAG_MSG: &str = $msg;
        const _: () = assert!(
            $crate::diag::__message_ok(__CANDOR_DIAG_MSG),
            "diag!: message must be 1..=120 bytes of printable ASCII"
        );
        const __CANDOR_DIAG_ARITY: &[()] = &[ $( $crate::__diag_unit!($code) ),* ];
        const _: () = assert!(
            __CANDOR_DIAG_ARITY.len() <= $crate::diag::MAX_DIAG_CODES,
            "diag!: at most 4 codes"
        );
        const __CANDOR_DIAG_LEVEL: $crate::diag::DiagLevel = $crate::diag::DiagLevel::$level;
        if $crate::diag::__enabled(__CANDOR_DIAG_LEVEL, cfg!(debug_assertions)) {
            $crate::diag::__emit(&$crate::diag::DiagRecord::__new(
                __CANDOR_DIAG_LEVEL,
                module_path!(),
                line!(),
                __CANDOR_DIAG_MSG,
                &[ $( $crate::diag::DiagCode::diag_code(&$code) ),* ],
            ));
        }
    }};
}

/// Bounded in-memory ring of the most recent diagnostics (oldest dropped
/// first). Nothing is written to disk.
#[derive(Debug)]
pub struct DiagRing {
    cap: usize,
    buf: Mutex<VecDeque<DiagRecord>>,
}

impl DiagRing {
    /// A ring holding at most `capacity` records, clamped to
    /// 1..=[`MAX_RING_RECORDS`].
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.clamp(1, MAX_RING_RECORDS);
        Self {
            cap,
            buf: Mutex::new(VecDeque::with_capacity(cap)),
        }
    }
    /// Capacity in records.
    pub fn capacity(&self) -> usize {
        self.cap
    }
    /// Copy of the buffered records, oldest first.
    pub fn snapshot(&self) -> Vec<DiagRecord> {
        let g = self.buf.lock().unwrap_or_else(|p| p.into_inner());
        g.iter().copied().collect()
    }
    /// Drops all buffered records.
    pub fn clear(&self) {
        self.buf.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }
}

impl DiagSink for DiagRing {
    fn record(&self, r: &DiagRecord) {
        let mut g = self.buf.lock().unwrap_or_else(|p| p.into_inner());
        while g.len() >= self.cap {
            g.pop_front();
        }
        g.push_back(*r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codes::{Code, OperationClass, SessionEndReason};

    #[test]
    fn message_check() {
        assert!(__message_ok("ok"));
        assert!(!__message_ok(""));
        assert!(!__message_ok("line\nbreak"));
        assert!(!__message_ok("tab\there"));
        assert!(!__message_ok("caf\u{e9}"));
        assert!(!__message_ok("\u{202e}rtl"));
        assert!(__message_ok(&"x".repeat(MAX_DIAG_MSG_BYTES)));
        assert!(!__message_ok(&"x".repeat(MAX_DIAG_MSG_BYTES + 1)));
    }

    #[test]
    fn release_ceiling_is_warn() {
        assert!(__enabled(DiagLevel::Error, false));
        assert!(__enabled(DiagLevel::Warn, false));
        assert!(!__enabled(DiagLevel::Info, false));
        assert!(!__enabled(DiagLevel::Trace, false));
        assert!(__enabled(DiagLevel::Trace, true));
    }

    #[test]
    fn record_holds_codes_in_order_and_bounded() {
        let a = DiagCodeValue::Code("A");
        let r = DiagRecord::__new(DiagLevel::Warn, "m", 1, "msg", &[a; 6]);
        assert_eq!(r.codes().count(), MAX_DIAG_CODES);
        let c = Code::<OperationClass>::new(7).diag_code();
        assert_eq!(
            c,
            DiagCodeValue::Registry {
                space: "operation_class",
                code: 7
            }
        );
        assert_eq!(
            SessionEndReason::IdleTimeout.diag_code(),
            DiagCodeValue::Code("IDLE_TIMEOUT")
        );
    }

    #[test]
    fn ring_is_bounded_and_drops_oldest() {
        let ring = DiagRing::new(2);
        for line in 1..=5u32 {
            ring.record(&DiagRecord::__new(DiagLevel::Error, "m", line, "x", &[]));
        }
        let s = ring.snapshot();
        assert_eq!(s.iter().map(DiagRecord::line).collect::<Vec<_>>(), [4, 5]);
        assert_eq!(DiagRing::new(0).capacity(), 1);
        assert_eq!(DiagRing::new(usize::MAX).capacity(), MAX_RING_RECORDS);
        ring.clear();
        assert!(ring.snapshot().is_empty());
    }
}
