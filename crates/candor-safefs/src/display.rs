// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Metadata-only display names (ADR-027; 10 `declared_name`; ADR-042).

use std::fmt;
use unicode_normalization::UnicodeNormalization;

/// Maximum size of a sanitized display name in UTF-8 bytes.
pub const MAX_DISPLAY_NAME_BYTES: usize = 255;

const UNNAMED: &str = "(unnamed)";
const ELLIPSIS: char = '\u{2026}';

/// A sanitized, display-only name.
///
/// Guarantees (tested by property tests):
/// * valid UTF-8 in NFC, at most [`MAX_DISPLAY_NAME_BYTES`] bytes, never empty;
/// * no control characters (C0, DEL, C1), no line/paragraph separators, no
///   bidirectional controls (U+061C, U+200E, U+200F, U+202A..U+202E,
///   U+2066..U+2069);
/// * no path syntax: `/`, `\` and `:` are replaced by look-alike symbols
///   (U+2215, U+29F5, U+2236) and an all-dots name is replaced by
///   U+2024 characters, so even if misused as a path it is a single,
///   non-special component.
///
/// The type deliberately implements neither `AsRef<Path>` nor
/// `AsRef<OsStr>`; the store never accepts it. It is metadata only and must
/// be rendered as plain text (ADR-042).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DisplayName(String);

impl DisplayName {
    /// Sanitizes a UTF-8 string.
    pub fn sanitize(raw: &str) -> Self {
        // NFC first so that composed/decomposed forms render identically.
        let mut cleaned = String::with_capacity(raw.len().min(1024));
        for c in raw.nfc() {
            if let Some(r) = map_char(c) {
                cleaned.push(r);
            }
        }
        // Removing characters may expose new canonical compositions.
        let mut s: String = cleaned.nfc().collect();
        if !s.is_empty() && s.chars().all(|c| c == '.') {
            s = s.chars().map(|_| '\u{2024}').collect();
        }
        if s.is_empty() {
            return Self(UNNAMED.to_owned());
        }
        Self(truncate(s))
    }

    /// Sanitizes bytes of unknown encoding (invalid UTF-8 → U+FFFD).
    pub fn from_bytes_lossy(raw: &[u8]) -> Self {
        Self::sanitize(&String::from_utf8_lossy(raw))
    }

    /// Placeholder used when no name is available (e.g. gzip members, whose
    /// header filename is deliberately ignored — CVE-2026-35465).
    pub fn unnamed() -> Self {
        Self(UNNAMED.to_owned())
    }

    /// The sanitized text, for plain-text rendering only.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn map_char(c: char) -> Option<char> {
    match c {
        '/' => Some('\u{2215}'),
        '\\' => Some('\u{29F5}'),
        ':' => Some('\u{2236}'),
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => {
            None
        }
        '\u{2028}' | '\u{2029}' => None,
        c if c.is_control() => None,
        c => Some(c),
    }
}

fn truncate(s: String) -> String {
    if s.len() <= MAX_DISPLAY_NAME_BYTES {
        return s;
    }
    let budget = MAX_DISPLAY_NAME_BYTES.saturating_sub(ELLIPSIS.len_utf8());
    let mut out = String::with_capacity(MAX_DISPLAY_NAME_BYTES);
    for c in s.chars() {
        if out.len().saturating_add(c.len_utf8()) > budget {
            break;
        }
        out.push(c);
    }
    out.push(ELLIPSIS);
    // A prefix of an NFC string is normally NFC; re-normalize defensively
    // (normalization never lengthens a prefix that was already composed
    // beyond the budget in practice, but enforce the bound regardless).
    let n: String = out.nfc().collect();
    if n.len() <= MAX_DISPLAY_NAME_BYTES {
        n
    } else {
        UNNAMED.to_owned()
    }
}

impl fmt::Display for DisplayName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for DisplayName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Debug of a source-supplied name could land in logs (EVID-008):
        // print only its length.
        write!(f, "DisplayName(<{} bytes>)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn is_bidi(c: char) -> bool {
        matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
    }

    #[test]
    fn st080_corpus() {
        // ST-080 path traversal corpus: none survives as path syntax.
        for raw in [
            "../../.config/autostart/x.desktop",
            "/abs/path",
            "..\\x",
            "C:\\x",
            "a\0b",
            "..",
            ".",
            "",
            "\u{202E}gpj.exe",
            "evil\u{2066}name\u{2069}",
            "line\nbreak\r\t",
            "\u{85}c1",
        ] {
            let d = DisplayName::sanitize(raw);
            let s = d.as_str();
            assert!(!s.contains(['/', '\\', ':', '\0', '\n', '\r']), "{s:?}");
            assert!(s != "." && s != ".." && !s.is_empty());
            assert!(!s.chars().any(is_bidi));
        }
        assert_eq!(DisplayName::sanitize("\u{202E}gpj.exe").as_str(), "gpj.exe");
        assert_eq!(DisplayName::sanitize("").as_str(), "(unnamed)");
    }

    #[test]
    fn nfc_and_truncation() {
        assert_eq!(DisplayName::sanitize("e\u{301}").as_str(), "\u{e9}");
        let long = "é".repeat(400);
        let d = DisplayName::sanitize(&long);
        assert!(d.as_str().len() <= MAX_DISPLAY_NAME_BYTES);
        assert!(d.as_str().ends_with(ELLIPSIS));
        assert!(!format!("{d:?}").contains('é'));
    }

    proptest! {
        #[test]
        fn invariants(raw in any::<String>()) {
            let d = DisplayName::sanitize(&raw);
            let s = d.as_str();
            prop_assert!(!s.is_empty());
            prop_assert!(s.len() <= MAX_DISPLAY_NAME_BYTES);
            let bad = |c: char| c.is_control() || is_bidi(c)
                || matches!(c, '/' | '\\' | ':' | '\u{2028}' | '\u{2029}');
            prop_assert!(!s.chars().any(bad), "forbidden char survived");
            prop_assert!(s != "." && s != "..");
            prop_assert!(unicode_normalization::is_nfc(s));
            // Idempotent.
            let again = DisplayName::sanitize(s);
            prop_assert_eq!(again.as_str(), s);
        }

        #[test]
        fn bytes_never_panic(raw in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let d = DisplayName::from_bytes_lossy(&raw);
            prop_assert!(d.as_str().len() <= MAX_DISPLAY_NAME_BYTES);
        }

        #[test]
        fn hostile_mix(parts in proptest::collection::vec(prop_oneof![
            Just("..".to_owned()), Just("/".to_owned()), Just("\\".to_owned()),
            Just("\u{202E}".to_owned()), Just("\u{2067}".to_owned()), Just("\0".to_owned()),
            Just("e\u{301}".to_owned()), Just("a".to_owned()), Just("\u{1b}[31m".to_owned()),
        ], 0..300)) {
            let raw: String = parts.concat();
            let d = DisplayName::sanitize(&raw);
            prop_assert!(d.as_str().len() <= MAX_DISPLAY_NAME_BYTES);
            let forbidden = ['/', '\\', '\0', '\u{1b}', '\u{202E}', '\u{2067}'];
            prop_assert!(!d.as_str().contains(forbidden), "forbidden char survived");
        }
    }
}
