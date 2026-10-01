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

/// The value of one enumerated code. Opaque: only the sealed [`DiagCode`]
/// implementations of this crate can create one (AUD-RM1-LOG-04).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct DiagCodeValue(CodeInner);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum CodeInner {
    Code(&'static str),
    Registry { space: &'static str, code: u16 },
}

impl DiagCodeValue {
    pub(crate) const fn closed(code: &'static str) -> Self {
        Self(CodeInner::Code(code))
    }
    pub(crate) const fn registry(space: &'static str, code: u16) -> Self {
        Self(CodeInner::Registry { space, code })
    }
    /// Closed-enum code text (e.g. `"IDLE_TIMEOUT"`), if this is one.
    pub fn text(&self) -> Option<&'static str> {
        match self.0 {
            CodeInner::Code(s) => Some(s),
            CodeInner::Registry { .. } => None,
        }
    }
    /// `(registry name, code)` of a numeric registry code, if this is one.
    pub fn registry_code(&self) -> Option<(&'static str, u16)> {
        match self.0 {
            CodeInner::Registry { space, code } => Some((space, code)),
            CodeInner::Code(_) => None,
        }
    }
}

/// Types `diag!` accepts as codes. Sealed: implemented only by the closed
/// code enums and [`Code`](crate::codes::Code) of this crate.
pub trait DiagCode: Sealed {
    /// The code value.
    fn diag_code(&self) -> DiagCodeValue;
}

/// One diagnostic. All contents are compile-time constants or enumerated.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DiagRecord {
    level: DiagLevel,
    module: &'static str,
    line: u32,
    message: &'static str,
    codes: [Option<DiagCodeValue>; MAX_DIAG_CODES],
}

impl DiagRecord {
    /// Crate-internal constructor; callers go through [`diag!`](crate::diag!).
    pub(crate) fn new(
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
const fn enabled(level: DiagLevel, debug_assertions: bool) -> bool {
    debug_assertions || matches!(level, DiagLevel::Error | DiagLevel::Warn)
}

/// Message check: 1..=[`MAX_DIAG_MSG_BYTES`] bytes, printable ASCII
/// (0x20..=0x7E) only.
const fn message_ok(m: &str) -> bool {
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

/// Macro support. Not an API: everything a caller can reach here takes its
/// message, module and line from the associated **constants** of a
/// [`__private::Site`] type, so no runtime string (e.g. a leaked
/// `format!`) can become a diagnostic message; codes are opaque
/// [`DiagCodeValue`]s that only the sealed [`DiagCode`] types can produce
/// (AUD-RM1-LOG-04).
#[doc(hidden)]
pub mod __private {
    use super::{DiagCodeValue, DiagLevel, DiagRecord, MAX_DIAG_CODES, SINK};

    /// A `diag!` call site. All items are compile-time constants.
    pub trait Site {
        /// Level.
        const LEVEL: DiagLevel;
        /// Static message (validated at compile time and again at emission).
        const MESSAGE: &'static str;
        /// `module_path!()` of the call site.
        const MODULE: &'static str;
        /// `line!()` of the call site.
        const LINE: u32;
    }

    /// Whether `level` is compiled in.
    pub const fn enabled(level: DiagLevel, debug_assertions: bool) -> bool {
        super::enabled(level, debug_assertions)
    }

    /// Compile-time message check used by the macro.
    pub const fn message_ok(m: &str) -> bool {
        super::message_ok(m)
    }

    /// Delivers the diagnostic of site `S` to the installed sink, if any.
    /// The message is checked again at monomorphisation time and at run
    /// time; a record failing either check is dropped, never stored.
    pub fn emit<S: Site>(codes: &[DiagCodeValue]) {
        const {
            assert!(
                super::message_ok(S::MESSAGE),
                "diag!: message must be 1..=120 bytes of printable ASCII"
            );
        }
        if !super::message_ok(S::MESSAGE) || codes.len() > MAX_DIAG_CODES {
            return;
        }
        if let Some(s) = SINK.get() {
            s.record(&DiagRecord::new(
                S::LEVEL,
                S::MODULE,
                S::LINE,
                S::MESSAGE,
                codes,
            ));
        }
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
        struct __CandorDiagSite;
        impl $crate::diag::__private::Site for __CandorDiagSite {
            const LEVEL: $crate::diag::DiagLevel = $crate::diag::DiagLevel::$level;
            const MESSAGE: &'static str = $msg;
            const MODULE: &'static str = ::core::module_path!();
            const LINE: u32 = ::core::line!();
        }
        const _: () = ::core::assert!(
            $crate::diag::__private::message_ok(
                <__CandorDiagSite as $crate::diag::__private::Site>::MESSAGE
            ),
            "diag!: message must be 1..=120 bytes of printable ASCII"
        );
        const __CANDOR_DIAG_ARITY: &[()] = &[ $( $crate::__diag_unit!($code) ),* ];
        const _: () = ::core::assert!(
            __CANDOR_DIAG_ARITY.len() <= $crate::diag::MAX_DIAG_CODES,
            "diag!: at most 4 codes"
        );
        if $crate::diag::__private::enabled(
            <__CandorDiagSite as $crate::diag::__private::Site>::LEVEL,
            ::core::cfg!(debug_assertions),
        ) {
            $crate::diag::__private::emit::<__CandorDiagSite>(
                &[ $( $crate::diag::DiagCode::diag_code(&$code) ),* ],
            );
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
        assert!(message_ok("ok"));
        assert!(!message_ok(""));
        assert!(!message_ok("line\nbreak"));
        assert!(!message_ok("tab\there"));
        assert!(!message_ok("caf\u{e9}"));
        assert!(!message_ok("\u{202e}rtl"));
        assert!(message_ok(&"x".repeat(MAX_DIAG_MSG_BYTES)));
        assert!(!message_ok(&"x".repeat(MAX_DIAG_MSG_BYTES + 1)));
    }

    #[test]
    fn release_ceiling_is_warn() {
        assert!(enabled(DiagLevel::Error, false));
        assert!(enabled(DiagLevel::Warn, false));
        assert!(!enabled(DiagLevel::Info, false));
        assert!(!enabled(DiagLevel::Trace, false));
        assert!(enabled(DiagLevel::Trace, true));
    }

    #[test]
    fn record_holds_codes_in_order_and_bounded() {
        let a = DiagCodeValue::closed("A");
        let r = DiagRecord::new(DiagLevel::Warn, "m", 1, "msg", &[a; 6]);
        assert_eq!(r.codes().count(), MAX_DIAG_CODES);
        let c = Code::<OperationClass>::of::<7>().diag_code();
        assert_eq!(c.registry_code(), Some(("operation_class", 7)));
        assert_eq!(
            SessionEndReason::IdleTimeout.diag_code().text(),
            Some("IDLE_TIMEOUT")
        );
    }

    #[test]
    fn ring_is_bounded_and_drops_oldest() {
        let ring = DiagRing::new(2);
        for line in 1..=5u32 {
            ring.record(&DiagRecord::new(DiagLevel::Error, "m", line, "x", &[]));
        }
        let s = ring.snapshot();
        assert_eq!(s.iter().map(DiagRecord::line).collect::<Vec<_>>(), [4, 5]);
        assert_eq!(DiagRing::new(0).capacity(), 1);
        assert_eq!(DiagRing::new(usize::MAX).capacity(), MAX_RING_RECORDS);
        ring.clear();
        assert!(ring.snapshot().is_empty());
    }
}
