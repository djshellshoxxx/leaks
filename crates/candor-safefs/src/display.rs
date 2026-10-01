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
/// * no invisible or blank-looking characters (AUD-RM1-SFS-02): every
///   `Default_Ignorable_Code_Point` (zero-width characters, U+FEFF, soft
///   hyphen, variation selectors, tag characters U+E0000..U+E0FFF, Hangul
///   fillers U+115F/U+1160/U+3164/U+FFA0, …), every other format (`Cf`)
///   character, private-use characters, noncharacters and the braille blank
///   U+2800 are removed; every whitespace run becomes one ASCII space and
///   leading/trailing whitespace is trimmed;
/// * an over-long name is shortened in the middle so its final extension
///   stays visible (`report…pdf.exe` cannot become `report.pdf…`);
/// * no path syntax: `/`, `\` and `:` are replaced by look-alike symbols
///   (U+2215, U+29F5, U+2236) and a name that is all dots after NFKC
///   (e.g. fullwidth `．．`) is replaced by U+2024 characters, so even if
///   misused as a path it is a single, non-special component.
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
        let mut pending_space = false;
        for c in raw.nfc() {
            match map_char(c) {
                Mapped::Keep(r) => {
                    if pending_space && !cleaned.is_empty() {
                        cleaned.push(' ');
                    }
                    pending_space = false;
                    cleaned.push(r);
                }
                // Whitespace runs collapse to one space; leading and
                // trailing whitespace is dropped.
                Mapped::Space => pending_space = true,
                Mapped::Drop => {}
            }
        }
        // Removing characters may expose new canonical compositions.
        let mut s: String = cleaned.nfc().collect();
        if !s.is_empty() && s.nfkc().all(|c| c == '.') {
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

enum Mapped {
    Keep(char),
    Space,
    Drop,
}

/// Invisible / blank-looking code points removed from display names:
/// `Default_Ignorable_Code_Point` (Unicode 16 DerivedCoreProperties), the
/// remaining `Cf` (format) characters, and blank-rendering fillers.
pub(crate) fn is_invisible(c: char) -> bool {
    matches!(
        c,
        // Default_Ignorable_Code_Point
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFF8}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}'
            // Other General_Category=Cf (format) characters
            | '\u{0600}'..='\u{0605}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            // Blank-rendering fillers that are neither DI nor whitespace
            | '\u{2800}'
            | '\u{3000}'
            // Private use (Co) and noncharacters
            | '\u{E000}'..='\u{F8FF}'
            | '\u{F0000}'..='\u{10FFFF}'
            | '\u{FDD0}'..='\u{FDEF}'
            | '\u{FFFE}'..='\u{FFFF}'
    ) || (u32::from(c) & 0xFFFE) == 0xFFFE
}

fn map_char(c: char) -> Mapped {
    match c {
        '/' => Mapped::Keep('\u{2215}'),
        '\\' => Mapped::Keep('\u{29F5}'),
        ':' => Mapped::Keep('\u{2236}'),
        // Line/paragraph separators and other whitespace (incl. NBSP,
        // U+2000..U+200A, U+202F, U+205F, U+3000) collapse to a space.
        c if c.is_whitespace() => Mapped::Space,
        c if c.is_control() || is_invisible(c) => Mapped::Drop,
        c => Mapped::Keep(c),
    }
}

/// Longest final extension (including the dot) kept visible on truncation.
const MAX_KEPT_EXTENSION_BYTES: usize = 32;

fn truncate(s: String) -> String {
    if s.len() <= MAX_DISPLAY_NAME_BYTES {
        return s;
    }
    // Keep the final extension visible: "head…ext" (AUD-RM1-SFS-02).
    let ext = s
        .rfind('.')
        .and_then(|i| s.get(i..))
        .filter(|e| e.len() > 1 && e.len() <= MAX_KEPT_EXTENSION_BYTES && !e.contains(' '))
        .unwrap_or("");
    let budget = MAX_DISPLAY_NAME_BYTES
        .saturating_sub(ELLIPSIS.len_utf8())
        .saturating_sub(ext.len());
    let mut out = String::with_capacity(MAX_DISPLAY_NAME_BYTES);
    for c in s.chars() {
        if out.len().saturating_add(c.len_utf8()) > budget {
            break;
        }
        out.push(c);
    }
    out.push(ELLIPSIS);
    out.push_str(ext);
    // A prefix of an NFC string is normally NFC; re-normalize defensively
    // and enforce the bound regardless.
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
            "\u{FF0E}\u{FF0E}",
            "\u{FE52}",
            "\u{2024}\u{2024}",
        ] {
            let d = DisplayName::sanitize(raw);
            let s = d.as_str();
            assert!(!s.contains(['/', '\\', ':', '\0', '\n', '\r']), "{s:?}");
            assert!(s != "." && s != ".." && !s.is_empty());
            assert!(!s.chars().any(is_bidi));
            // NFKC-dots names are rendered as U+2024 only (never '.').
            if s.nfkc().all(|c| c == '.') {
                assert!(s.chars().all(|c| c == '\u{2024}'), "{s:?}");
            }
        }
        assert_eq!(DisplayName::sanitize("\u{202E}gpj.exe").as_str(), "gpj.exe");
        assert_eq!(DisplayName::sanitize("").as_str(), "(unnamed)");
    }

    // AUD-RM1-SFS-02 regression: the audit PoC kept every one of these.
    #[test]
    fn invisible_and_filler_characters_removed() {
        let d = DisplayName::sanitize(
            "invoice\u{200B}\u{FEFF}\u{E0041}\u{00AD}.pdf\u{2800}\u{3164}.exe",
        );
        assert_eq!(d.as_str(), "invoice.pdf.exe");
        for c in [
            '\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}', '\u{2064}', '\u{206A}', '\u{206F}',
            '\u{FEFF}', '\u{00AD}', '\u{034F}', '\u{115F}', '\u{1160}', '\u{3164}', '\u{FFA0}',
            '\u{2800}', '\u{E0001}', '\u{E0041}', '\u{E007F}', '\u{FE0F}', '\u{E0100}',
            '\u{180E}', '\u{FFF9}', '\u{FFFB}', '\u{E000}', '\u{FDD0}', '\u{FFFF}',
            '\u{1D173}', '\u{17B4}',
        ] {
            let raw = format!("a{c}b");
            assert_eq!(DisplayName::sanitize(&raw).as_str(), "ab", "U+{:04X}", u32::from(c));
        }
        // Whitespace runs (incl. NBSP, ideographic, line separators) collapse.
        assert_eq!(
            DisplayName::sanitize("  a\u{00A0}\u{2003}\u{3000}\u{2028} b\t ").as_str(),
            "a b"
        );
        // Fullwidth dots (NFKC "..") are not a usable path component.
        assert_eq!(DisplayName::sanitize("\u{FF0E}\u{FF0E}").as_str(), "\u{2024}\u{2024}");
    }

    #[test]
    fn truncation_keeps_extension_visible() {
        let raw = format!("report.pdf{}.exe", "x".repeat(400));
        let d = DisplayName::sanitize(&raw);
        assert!(d.as_str().len() <= MAX_DISPLAY_NAME_BYTES);
        assert!(d.as_str().ends_with("\u{2026}.exe"), "{}", d.as_str());
        // Filler padding is removed before truncation.
        let raw = format!("report.pdf{}.exe", "\u{3164}".repeat(400));
        assert_eq!(DisplayName::sanitize(&raw).as_str(), "report.pdf.exe");
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
            let bad = |c: char| c.is_control() || is_bidi(c) || is_invisible(c)
                || (c.is_whitespace() && c != ' ')
                || matches!(c, '/' | '\\' | ':' | '\u{2028}' | '\u{2029}');
            prop_assert!(!s.chars().any(bad), "forbidden char survived");
            prop_assert!(!s.contains("  ") && !s.starts_with(' ') && !s.ends_with(' '));
            if s.nfkc().all(|c| c == '.') {
                prop_assert!(s.chars().all(|c| c == '\u{2024}'), "dots");
            }
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

        // AUD-RM1-SFS-02: invisible/filler characters never survive and the
        // result is idempotent.
        #[test]
        fn fillers_never_survive(parts in proptest::collection::vec(prop_oneof![
            Just("\u{200B}".to_owned()), Just("\u{FEFF}".to_owned()), Just("\u{E0041}".to_owned()),
            Just("\u{00AD}".to_owned()), Just("\u{2800}".to_owned()), Just("\u{3164}".to_owned()),
            Just("\u{115F}".to_owned()), Just("\u{1160}".to_owned()), Just("\u{FFA0}".to_owned()),
            Just("\u{2060}".to_owned()), Just("\u{FE0F}".to_owned()), Just("\u{00A0}".to_owned()),
            Just(" ".to_owned()), Just(".".to_owned()), Just("\u{FF0E}".to_owned()),
            Just("pdf".to_owned()), Just("exe".to_owned()),
        ], 0..300)) {
            let raw: String = parts.concat();
            let d = DisplayName::sanitize(&raw);
            let s = d.as_str();
            prop_assert!(!s.chars().any(is_invisible), "{:?}", s);
            prop_assert!(s.len() <= MAX_DISPLAY_NAME_BYTES);
            let again = DisplayName::sanitize(s);
            prop_assert_eq!(again.as_str(), s);
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
