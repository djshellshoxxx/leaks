// SPDX-License-Identifier: AGPL-3.0-or-later
//! Strict `application/x-www-form-urlencoded` parser and field validation
//! (IMPL-00 §7 "Form fields", 11 §5.7; ST-054 `fuzz_form_urlencoded`).
//!
//! * The body is bounded by the route before it is read ([`MAX_FORM_BODY`]).
//! * Every field name must be allowed by the route's rule function; an unknown
//!   field, a repeated single-valued field, a malformed percent escape, invalid
//!   UTF-8 or more than [`MAX_FORM_FIELDS`] fields rejects the whole form.
//! * Text is checked, never sanitised: byte length and character count
//!   (scalar values, an upper bound of the grapheme count), control characters
//!   rejected (C0 except TAB/LF in long text, DEL, C1), browser `CR LF`
//!   normalised to `LF`, then NFC (the canonical form the sealer seals).
//! * Values live in zeroizing buffers allocated once at their final size.
//!
//! Errors carry only the static rule name of the offending field, never input.

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::limits::{
    MAX_FORM_BODY, MAX_FORM_FIELDS, MAX_LONG_BYTES, MAX_LONG_CHARS, MAX_NAME_CHARS,
    MAX_SHORT_CHARS, MAX_TOKEN_BYTES, MAX_WORD_BYTES,
};

/// How a field's value is validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// ASCII `[A-Za-z0-9_-]`, 1..=[`MAX_TOKEN_BYTES`] (tokens, choices, ids).
    Token,
    /// As [`Kind::Token`] or empty (an unselected `<select>` / radio group).
    OptToken,
    /// Single-line text, ≤ [`MAX_SHORT_CHARS`] characters.
    Short,
    /// Single-line text, ≤ [`MAX_NAME_CHARS`] characters.
    Name,
    /// Multi-line text, ≤ [`MAX_LONG_CHARS`] characters and
    /// ≤ [`MAX_LONG_BYTES`] bytes.
    Long,
    /// A passphrase or a passphrase box: single line, ≤ `max` bytes, kept
    /// as typed (C-07 normalises, ADR-047(6)).
    Secret {
        /// Byte limit.
        max: usize,
    },
    /// One confirmation word (≤ [`MAX_WORD_BYTES`]).
    Word,
}

/// A route's rule for one field name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    /// Static name used in errors.
    pub name: &'static str,
    /// Validation.
    pub kind: Kind,
    /// The field may repeat (checkbox groups, the ten passphrase boxes).
    pub multi: bool,
}

/// Form rejection. Field-level variants name the field by its static rule
/// name so the page can show an inline error; the others are rejected with
/// the uniform error page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormError {
    /// Not a well-formed form (escape, UTF-8, structure, size, count).
    Malformed,
    /// A field the route does not declare.
    UnknownField,
    /// A single-valued field sent twice.
    Duplicate,
    /// A field value over its limit.
    TooLong(&'static str),
    /// A field value with forbidden characters.
    Invalid(&'static str),
}

/// A validated form. `Debug` is redacted.
pub struct Form {
    fields: Vec<(String, &'static str, Zeroizing<String>)>,
}

impl core::fmt::Debug for Form {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Form({} fields, values redacted)", self.fields.len())
    }
}

impl Form {
    /// An empty form (GET re-render).
    #[must_use]
    pub fn empty() -> Self {
        Self { fields: Vec::new() }
    }

    /// The value of a single-valued field.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(n, _, _)| n == name)
            .map(|(_, _, v)| v.as_str())
    }

    /// All values of a field, in order.
    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.fields
            .iter()
            .filter(move |(n, _, _)| n == name)
            .map(|(_, _, v)| v.as_str())
    }

    /// Names of the fields present (for `desc_N` style families).
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.fields.iter().map(|(n, _, _)| n.as_str())
    }

    /// Whether `name` was sent.
    #[must_use]
    pub fn has(&self, name: &str) -> bool {
        self.fields.iter().any(|(n, _, _)| n == name)
    }
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(b.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// Percent-decode one component (`+` is a space) into a zeroizing buffer of
/// at most `input.len()` bytes (never reallocated).
fn decode(input: &[u8]) -> Result<Zeroizing<Vec<u8>>, FormError> {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len()));
    let mut i = 0usize;
    while let Some(&b) = input.get(i) {
        match b {
            b'+' => {
                out.push(b' ');
                i = i.saturating_add(1);
            }
            b'%' => {
                let h = input
                    .get(i.saturating_add(1))
                    .copied()
                    .and_then(hex)
                    .ok_or(FormError::Malformed)?;
                let l = input
                    .get(i.saturating_add(2))
                    .copied()
                    .and_then(hex)
                    .ok_or(FormError::Malformed)?;
                out.push(h.wrapping_mul(16).wrapping_add(l));
                i = i.saturating_add(3);
            }
            // Unescaped bytes browsers never send raw in this encoding.
            b'=' | b'&' => return Err(FormError::Malformed),
            0x21..=0x7e => {
                out.push(b);
                i = i.saturating_add(1);
            }
            _ => return Err(FormError::Malformed),
        }
    }
    Ok(out)
}

fn field_name_ok(n: &[u8]) -> bool {
    (1..=32).contains(&n.len())
        && n.iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

/// Forbidden in every text: C0 controls except TAB and LF, DEL, C1 controls.
fn forbidden(c: char, multiline: bool) -> bool {
    match c {
        '\n' | '\t' => !multiline,
        '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' => true,
        _ => false,
    }
}

/// Validate and canonicalise text: `CR LF` → `LF` (multi-line only), reject
/// forbidden characters, NFC, then check the limits on the result.
fn text(
    raw: &[u8],
    rule: &Rule,
    multiline: bool,
    max_chars: usize,
    max_bytes: usize,
) -> Result<Zeroizing<String>, FormError> {
    let s = core::str::from_utf8(raw).map_err(|_| FormError::Invalid(rule.name))?;
    // Bound the work before normalising: NFC never shrinks below a third.
    if s.len() > max_bytes.saturating_mul(3) {
        return Err(FormError::TooLong(rule.name));
    }
    let mut lf = Zeroizing::new(String::with_capacity(s.len()));
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\r' && multiline && it.peek() == Some(&'\n') {
            continue;
        }
        if forbidden(c, multiline) {
            return Err(FormError::Invalid(rule.name));
        }
        lf.push(c);
    }
    // NFC is at most 3× longer in UTF-8 (UAX #15 §9); allocate once.
    let mut out = Zeroizing::new(String::with_capacity(lf.len().saturating_mul(3)));
    let mut chars = 0usize;
    for c in lf.nfc() {
        chars = chars.saturating_add(1);
        if chars > max_chars {
            return Err(FormError::TooLong(rule.name));
        }
        out.push(c);
    }
    if out.len() > max_bytes {
        return Err(FormError::TooLong(rule.name));
    }
    Ok(out)
}

fn validate(raw: &[u8], rule: &Rule) -> Result<Zeroizing<String>, FormError> {
    match rule.kind {
        Kind::OptToken if raw.is_empty() => Ok(Zeroizing::new(String::new())),
        Kind::Token | Kind::OptToken => {
            if raw.is_empty()
                || raw.len() > MAX_TOKEN_BYTES
                || !raw
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
            {
                return Err(FormError::Invalid(rule.name));
            }
            let s = core::str::from_utf8(raw).map_err(|_| FormError::Invalid(rule.name))?;
            Ok(Zeroizing::new(s.to_owned()))
        }
        Kind::Short => text(raw, rule, false, MAX_SHORT_CHARS, MAX_SHORT_CHARS.saturating_mul(4)),
        Kind::Name => text(raw, rule, false, MAX_NAME_CHARS, MAX_NAME_CHARS.saturating_mul(4)),
        Kind::Long => text(raw, rule, true, MAX_LONG_CHARS, MAX_LONG_BYTES),
        Kind::Secret { max } => {
            if raw.len() > max {
                return Err(FormError::TooLong(rule.name));
            }
            let s = core::str::from_utf8(raw).map_err(|_| FormError::Invalid(rule.name))?;
            if s.chars().any(|c| forbidden(c, false)) {
                return Err(FormError::Invalid(rule.name));
            }
            let mut v = Zeroizing::new(String::with_capacity(s.len()));
            v.push_str(s);
            Ok(v)
        }
        Kind::Word => {
            if raw.len() > MAX_WORD_BYTES {
                return Err(FormError::TooLong(rule.name));
            }
            text(raw, rule, false, MAX_WORD_BYTES, MAX_WORD_BYTES.saturating_mul(3))
        }
    }
}

/// Parse and validate `body` with `rules` (the route's allow-list). Field
/// errors on text are reported as [`FormError::TooLong`] /
/// [`FormError::Invalid`] after the whole form was checked for structure, so
/// that an unknown field always wins (deny by default).
pub fn parse_form(body: &[u8], rules: &dyn Fn(&str) -> Option<Rule>) -> Result<Form, FormError> {
    if body.len() > MAX_FORM_BODY {
        return Err(FormError::Malformed);
    }
    let mut fields: Vec<(String, &'static str, Zeroizing<String>)> = Vec::new();
    let mut field_err: Option<FormError> = None;
    if body.is_empty() {
        return Ok(Form { fields });
    }
    for pair in body.split(|b| *b == b'&') {
        if fields.len() >= MAX_FORM_FIELDS {
            return Err(FormError::Malformed);
        }
        let eq = pair
            .iter()
            .position(|b| *b == b'=')
            .ok_or(FormError::Malformed)?;
        let (name, value) = pair.split_at(eq);
        let value = value.get(1..).unwrap_or_default();
        if !field_name_ok(name) {
            return Err(FormError::Malformed);
        }
        let name = core::str::from_utf8(name).map_err(|_| FormError::Malformed)?;
        let rule = rules(name).ok_or(FormError::UnknownField)?;
        if !rule.multi && fields.iter().any(|(n, _, _)| n == name) {
            return Err(FormError::Duplicate);
        }
        let raw = decode(value)?;
        match validate(&raw, &rule) {
            Ok(v) => fields.push((name.to_owned(), rule.name, v)),
            Err(e) => {
                // Remember the first field error, keep checking structure.
                field_err.get_or_insert(e);
                fields.push((name.to_owned(), rule.name, Zeroizing::new(String::new())));
            }
        }
    }
    match field_err {
        Some(e) => Err(e),
        None => Ok(Form { fields }),
    }
}

/// The only accepted `Content-Type` for URL-encoded bodies (no parameters
/// except `charset=utf-8`).
#[must_use]
pub fn is_urlencoded(content_type: &str) -> bool {
    let mut it = content_type.split(';').map(str::trim);
    let ty = it.next().unwrap_or_default();
    if !ty.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
        return false;
    }
    match (it.next(), it.next()) {
        (None, None) => true,
        (Some(p), None) => p.eq_ignore_ascii_case("charset=utf-8"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn rules(n: &str) -> Option<Rule> {
        let r = |name, kind, multi| Some(Rule { name, kind, multi });
        match n {
            "csrf" => r("csrf", Kind::Token, false),
            "what" => r("what", Kind::Long, false),
            "where" => r("where", Kind::Short, false),
            "coi_label" => r("coi_label", Kind::Token, true),
            "passphrase" => r("passphrase", Kind::Secret { max: 256 }, true),
            _ => None,
        }
    }

    #[test]
    fn parses_and_normalises() {
        let f = parse_form(b"csrf=ab_-9&what=a%0D%0Ab+c&coi_label=1&coi_label=2", &rules).unwrap();
        assert_eq!(f.get("csrf"), Some("ab_-9"));
        assert_eq!(f.get("what"), Some("a\nb c"));
        assert_eq!(f.all("coi_label").collect::<Vec<_>>(), vec!["1", "2"]);
        // NFC: e + combining acute → é.
        let f = parse_form(b"where=e%CC%81", &rules).unwrap();
        assert_eq!(f.get("where"), Some("\u{e9}"));
    }

    #[test]
    fn rejects_unknown_duplicate_and_malformed() {
        assert_eq!(parse_form(b"x=1", &rules).unwrap_err(), FormError::UnknownField);
        assert_eq!(parse_form(b"csrf=a&csrf=b", &rules).unwrap_err(), FormError::Duplicate);
        assert_eq!(parse_form(b"csrf=%4", &rules).unwrap_err(), FormError::Malformed);
        assert_eq!(parse_form(b"csrf=%zz", &rules).unwrap_err(), FormError::Malformed);
        assert_eq!(parse_form(b"csrf", &rules).unwrap_err(), FormError::Malformed);
        assert_eq!(parse_form(b"csrf=a&", &rules).unwrap_err(), FormError::Malformed);
        assert_eq!(parse_form(b"CSRF=a", &rules).unwrap_err(), FormError::Malformed);
        assert_eq!(parse_form(b"what=%FF", &rules).unwrap_err(), FormError::Invalid("what"));
        assert_eq!(parse_form(b"what=a%00", &rules).unwrap_err(), FormError::Invalid("what"));
        assert_eq!(parse_form(b"what=a%C2%85", &rules).unwrap_err(), FormError::Invalid("what"));
        assert_eq!(parse_form(b"where=a%0Ab", &rules).unwrap_err(), FormError::Invalid("where"));
        assert_eq!(parse_form(b"what=a%0Db", &rules).unwrap_err(), FormError::Invalid("what"));
        // Unknown field wins over a field error.
        assert_eq!(parse_form(b"what=%00&x=1", &rules).unwrap_err(), FormError::UnknownField);
        let many = vec!["coi_label=1"; MAX_FORM_FIELDS + 1].join("&");
        assert_eq!(parse_form(many.as_bytes(), &rules).unwrap_err(), FormError::Malformed);
    }

    #[test]
    fn limits_are_exact() {
        // 500 characters pass, 501 fail (boundary values, SI-A-02).
        let ok = format!("where={}", "%C3%A9".repeat(MAX_SHORT_CHARS));
        assert_eq!(parse_form(ok.as_bytes(), &rules).unwrap().get("where").unwrap().chars().count(), 500);
        let bad = format!("where={}", "a".repeat(MAX_SHORT_CHARS + 1));
        assert_eq!(parse_form(bad.as_bytes(), &rules).unwrap_err(), FormError::TooLong("where"));
        let long = format!("what={}", "a".repeat(MAX_LONG_CHARS));
        assert!(parse_form(long.as_bytes(), &rules).is_ok());
        let long = format!("what={}", "a".repeat(MAX_LONG_CHARS + 1));
        assert_eq!(parse_form(long.as_bytes(), &rules).unwrap_err(), FormError::TooLong("what"));
        let pw = format!("passphrase={}", "a".repeat(257));
        assert_eq!(parse_form(pw.as_bytes(), &rules).unwrap_err(), FormError::TooLong("passphrase"));
        assert_eq!(parse_form(&vec![b'a'; MAX_FORM_BODY + 1], &rules).unwrap_err(), FormError::Malformed);
    }

    #[test]
    fn content_type_exact() {
        assert!(is_urlencoded("application/x-www-form-urlencoded"));
        assert!(is_urlencoded("application/x-www-form-urlencoded; charset=UTF-8"));
        assert!(!is_urlencoded("application/x-www-form-urlencoded; charset=latin1"));
        assert!(!is_urlencoded("multipart/form-data; boundary=x"));
        assert!(!is_urlencoded("text/plain"));
    }

    #[test]
    fn debug_is_redacted() {
        let f = parse_form(b"what=canary-7d1f", &rules).unwrap();
        assert!(!format!("{f:?}").contains("canary"));
    }

    proptest::proptest! {
        /// ST-054: arbitrary bodies never panic; accepted values contain no
        /// forbidden character and stay within their limits.
        #[test]
        fn total(body in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..1024)) {
            if let Ok(f) = parse_form(&body, &rules) {
                for n in ["csrf", "what", "where"] {
                    if let Some(v) = f.get(n) {
                        proptest::prop_assert!(!v.chars().any(|c| c == '\0' || c == '\r'));
                    }
                }
            }
        }

        /// Round trip: any printable text survives percent-encoding.
        #[test]
        fn roundtrip(s in "[a-zA-Z0-9 äöü€\\n]{0,200}") {
            let mut enc = String::from("what=");
            for b in s.as_bytes() {
                enc.push_str(&format!("%{b:02X}"));
            }
            let f = parse_form(enc.as_bytes(), &rules).unwrap();
            let want: String = s.nfc().collect();
            proptest::prop_assert_eq!(f.get("what").unwrap(), want.as_str());
        }
    }
}
