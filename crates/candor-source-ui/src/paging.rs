// SPDX-License-Identifier: AGPL-3.0-or-later
//! Budget-aware paging of variable content (AUD-RM1-SUI-01).
//!
//! The size class of a page depends only on the request (11 §5.4, ADR-051(2)), but escaping can
//! grow source and team text up to five times (`&` → `&amp;`). Screens with variable content
//! (S05, S06, S07, S08, S11 inbox, S12) therefore split it into **parts**:
//!
//! 1. The page chrome is rendered once in *measure* mode (every optional container, the part
//!    navigation with the largest part numbers, and the end-of-flow controls all present).
//! 2. The remaining budget is `max_unpadded − chrome − SLACK`.
//! 3. Every item (an answer, a message, a file row, a question, the draft) is rendered on its
//!    own into a fixed-capacity buffer. An item that does not fit is split into **pieces** of
//!    its text, cut on character boundaries by *escaped* length. A piece always fills a part on
//!    its own.
//! 4. Items are packed greedily into parts in order; the requested part is rendered.
//!
//! Nothing is truncated: every byte of source and team text is on exactly one part, and the
//! source reaches every part with the "Previous part" / "Next part" buttons (`part` field).
//! An editable piece carries a hidden `piece` field (`{field}-{start}-{end}-{total}-{tag}`,
//! byte offsets into the stored value plus a keyed MAC of the stored value) so that C-07 can
//! replace exactly that range ([`splice_piece`]) and refuse a stale page (AUD-RM1-SUI-11).

use core::fmt;
use core::ops::Range;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Name of the part-navigation field (a submit button value, 0-based part index).
pub const PART_FIELD: &str = "part";

/// Name of the hidden field that identifies an edited piece of a long value.
pub const PIECE_FIELD: &str = "piece";

/// Name of the hidden field listing the questions shown on a multi-part S05 page.
pub const SHOWN_FIELD: &str = "shown";

/// Bytes kept free on every page in addition to the measured chrome.
pub(crate) const SLACK: usize = 512;

/// Bytes added to the measured size of every item (loop whitespace, number widths).
pub(crate) const ITEM_SLACK: usize = 128;

/// Smallest text budget for one piece; below this the page fails closed.
pub(crate) const MIN_PIECE: usize = 4_096;

/// Largest part index shown in measure mode (also the largest number of parts).
pub(crate) const MAX_PARTS: usize = 9_999;

/// Escaped width of one character, identical to [`crate::view::escape`] and askama's HTML
/// escaper (`&#34;`, `&#39;`).
fn width(c: char) -> usize {
    match c {
        '&' | '"' | '\'' => 5,
        '<' | '>' => 4,
        c => c.len_utf8(),
    }
}

/// Length in bytes of `s` after HTML escaping. Callers can use it to pre-check content; the
/// renderer splits anything that does not fit instead of failing.
pub fn escaped_len(s: &str) -> usize {
    s.chars().fold(0usize, |n, c| n.saturating_add(width(c)))
}

/// Splits `text` into consecutive ranges whose escaped length is at most `budget` bytes.
///
/// Cuts fall on character boundaries, preferably after whitespace in the second half of a
/// piece, and never between `\r` and `\n`. The ranges cover `text` exactly, in order. Returns
/// one empty range for empty text. `budget` must be at least 8 (one escaped character plus
/// room); smaller budgets are raised to 8.
pub(crate) fn split_escaped(text: &str, budget: usize) -> Vec<Range<usize>> {
    let budget = budget.max(8);
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut acc = 0usize;
    // Byte offset after the last whitespace in the current piece, and the escaped length up
    // to there.
    let mut brk: Option<(usize, usize)> = None;
    let mut prev: Option<char> = None;
    for (i, c) in text.char_indices() {
        let w = width(c);
        if acc.saturating_add(w) > budget && i > start {
            let mut cut = match brk {
                Some((b, at)) if b > start && at >= budget / 2 => b,
                _ => i,
            };
            if cut == i && c == '\n' && prev == Some('\r') && i.saturating_sub(1) > start {
                cut = i.saturating_sub(1);
            }
            out.push(start..cut);
            start = cut;
            acc = text.get(cut..i).map_or(0, escaped_len);
            brk = None;
        }
        acc = acc.saturating_add(w);
        if c.is_whitespace() && c != '\r' {
            brk = Some((i.saturating_add(c.len_utf8()), acc));
        }
        prev = Some(c);
    }
    if start < text.len() || out.is_empty() {
        out.push(start..text.len());
    }
    out
}

/// Length in bytes of the piece tag (HMAC-SHA256 truncated to 128 bits).
const TAG_LEN: usize = 16;

/// Domain separation for the piece MAC.
const PIECE_DOMAIN: &[u8] = b"candor-sui-piece-v1\0";

/// Per-session secret that binds every `piece` field to the exact stored value it was cut from
/// (AUD-RM1-SUI-11). C-06/C-07 create it from a CSPRNG when the session starts, keep it only in
/// RAM with the session (sealer session record) and pass the same key to [`crate::render`]
/// (`PageContext::piece_key`) and [`splice_piece`]. It is zeroized on drop and never printed.
#[derive(Clone)]
pub struct PieceKey(Zeroizing<[u8; 32]>);

impl PieceKey {
    /// Wraps 32 secret bytes.
    pub fn new(bytes: [u8; 32]) -> PieceKey {
        PieceKey(Zeroizing::new(bytes))
    }

    fn mac(&self, field: &str, start: usize, end: usize, stored: &str) -> Option<Hmac<Sha256>> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(self.0.as_slice()).ok()?;
        let n = |v: usize| u64::try_from(v).unwrap_or(u64::MAX).to_be_bytes();
        mac.update(PIECE_DOMAIN);
        mac.update(field.as_bytes());
        mac.update(&[0]);
        mac.update(&n(start));
        mac.update(&n(end));
        mac.update(&n(stored.len()));
        mac.update(stored.as_bytes());
        Some(mac)
    }
}

impl fmt::Debug for PieceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PieceKey([redacted])")
    }
}

/// One piece of a long value as sent back by the form (`{field}-{start}-{end}-{total}-{tag}`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PieceRef<'a> {
    /// Field (question id or `text`), validated `[a-z0-9_]{1,32}`.
    pub field: &'a str,
    /// Start byte offset in the stored value.
    pub start: usize,
    /// End byte offset in the stored value.
    pub end: usize,
    /// Byte length of the stored value when the page was rendered.
    pub total: usize,
    /// Keyed MAC (truncated HMAC-SHA256 under the session [`PieceKey`]) of the field, the
    /// offsets and the whole stored value at render time. Not secret, but only checked by
    /// [`splice_piece`] in constant time.
    pub tag: [u8; TAG_LEN],
}

impl fmt::Debug for PieceRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Offsets only; no content.
        write!(
            f,
            "PieceRef({}, {}..{} of {})",
            self.field, self.start, self.end, self.total
        )
    }
}

/// Parses a `piece` field value strictly. Returns `None` for anything malformed.
pub fn parse_piece(v: &str) -> Option<PieceRef<'_>> {
    if v.len() > 128 {
        return None;
    }
    let mut it = v.split('-');
    let field = it.next()?;
    if !crate::view::valid_id(field) {
        return None;
    }
    let num = |s: Option<&str>| -> Option<usize> {
        let s = s?;
        if s.is_empty() || s.len() > 9 || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        s.parse().ok()
    };
    let start = num(it.next())?;
    let end = num(it.next())?;
    let total = num(it.next())?;
    let tag = unhex(it.next()?)?;
    if it.next().is_some() || start > end || end > total {
        return None;
    }
    Some(PieceRef {
        field,
        start,
        end,
        total,
        tag,
    })
}

/// Strict lowercase hex of exactly [`TAG_LEN`] bytes.
fn unhex(s: &str) -> Option<[u8; TAG_LEN]> {
    let b = s.as_bytes();
    if b.len() != TAG_LEN.checked_mul(2)? {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    };
    let mut out = [0u8; TAG_LEN];
    for (o, pair) in out.iter_mut().zip(b.chunks_exact(2)) {
        let hi = nib(*pair.first()?)?;
        let lo = nib(*pair.get(1)?)?;
        *o = (hi << 4) | lo;
    }
    Some(out)
}

/// Formats a `piece` field value for `range` of `stored`, bound to `stored` by a keyed MAC.
pub(crate) fn piece_value(
    key: &PieceKey,
    field: &str,
    r: &Range<usize>,
    stored: &str,
) -> Option<String> {
    let tag = key.mac(field, r.start, r.end, stored)?.finalize().into_bytes();
    let mut v = format!("{field}-{}-{}-{}-", r.start, r.end, stored.len());
    for b in tag.iter().take(TAG_LEN) {
        v.push(char::from(HEX.get(usize::from(b >> 4)).copied()?));
        v.push(char::from(HEX.get(usize::from(b & 0x0f)).copied()?));
    }
    Some(v)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Why a piece could not be applied. C-07 then re-renders the page with the posted text kept
/// (11 §5.7) instead of guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpliceError {
    /// The stored value changed since the page was rendered (any change, including one of the
    /// same length, or a piece from another session or field: the keyed MAC does not match).
    Stale,
    /// The offsets are not on character boundaries of the stored value.
    Boundary,
}

/// Replaces `piece.start..piece.end` of `stored` with `edited`.
///
/// Fails closed with [`SpliceError::Stale`] unless `piece.tag` is the keyed MAC (under `key`,
/// the session's [`PieceKey`]) of the field, the offsets and the **whole current** `stored`
/// value, compared in constant time. So any change to the stored value since the page was
/// rendered, even one that keeps its length (a second tab, a re-posted older part), is
/// refused (AUD-RM1-SUI-11). Fails with [`SpliceError::Boundary`] if the offsets are not
/// character boundaries. `field` is the name of the form field the value belongs to; it must
/// equal `piece.field`. The result is zeroized on drop and allocated once (no reallocation
/// copies).
pub fn splice_piece(
    key: &PieceKey,
    field: &str,
    stored: &str,
    piece: &PieceRef<'_>,
    edited: &str,
) -> Result<Zeroizing<String>, SpliceError> {
    if stored.len() != piece.total || field != piece.field {
        return Err(SpliceError::Stale);
    }
    let mac = key
        .mac(piece.field, piece.start, piece.end, stored)
        .ok_or(SpliceError::Stale)?;
    // `verify_truncated_left` compares in constant time.
    if mac.verify_truncated_left(&piece.tag).is_err() {
        return Err(SpliceError::Stale);
    }
    let head = stored.get(..piece.start).ok_or(SpliceError::Boundary)?;
    let tail = stored.get(piece.end..).ok_or(SpliceError::Boundary)?;
    if piece.start > piece.end {
        return Err(SpliceError::Boundary);
    }
    let cap = head
        .len()
        .saturating_add(edited.len())
        .saturating_add(tail.len());
    let mut out = Zeroizing::new(String::with_capacity(cap));
    out.push_str(head);
    out.push_str(edited);
    out.push_str(tail);
    Ok(out)
}

/// A `fmt::Write` sink with a fixed capacity, allocated once. Writing past the capacity fails
/// (and sets `overflow`) instead of reallocating, so no stale copy of the page (passphrase,
/// source text) is left in freed heap memory (AUD-RM1-SUI-03).
pub(crate) struct CappedWriter {
    buf: Zeroizing<String>,
    cap: usize,
    pub(crate) overflow: bool,
}

impl CappedWriter {
    pub(crate) fn new(cap: usize) -> CappedWriter {
        CappedWriter {
            buf: Zeroizing::new(String::with_capacity(cap)),
            cap,
            overflow: false,
        }
    }

    pub(crate) fn into_inner(self) -> Zeroizing<String> {
        self.buf
    }
}

impl fmt::Write for CappedWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.buf.len().saturating_add(s.len()) > self.cap {
            self.overflow = true;
            return Err(fmt::Error);
        }
        self.buf.push_str(s);
        Ok(())
    }
}

/// Where an item goes in the screen template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Region {
    /// S05 questions (inside the step form).
    Questions,
    /// S08 answers (`<dl>`).
    Answers,
    /// S08 file list (`<ul>`).
    ReviewFiles,
    /// S08 identity hints (`<ul>`).
    Hints,
    /// S11/S12 team messages.
    Messages,
    /// S12 message text field (one field, or pieces of a long draft).
    Composer,
    /// S06 attached-file rows.
    FileRows,
    /// S07 metadata rows.
    MetaRows,
}

/// One rendered item.
pub(crate) struct Item {
    pub(crate) region: Region,
    pub(crate) html: Zeroizing<String>,
    /// A piece of a split value: always on a part of its own.
    pub(crate) exclusive: bool,
}

/// Paging state of a page view.
#[derive(Default)]
pub(crate) enum Paging {
    /// The screen has no variable regions.
    #[default]
    Off,
    /// Chrome measurement: containers, navigation and end-of-flow controls all present.
    Measure,
    /// Showing part `cur` of `parts`.
    Show {
        items: Vec<Item>,
        parts: Vec<Range<usize>>,
        cur: usize,
    },
}

/// Packs items into parts of at most `budget` bytes each (sizes include [`ITEM_SLACK`]).
/// Returns `None` if one item alone is larger than the budget or there are too many parts.
pub(crate) fn pack(items: &[Item], budget: usize) -> Option<Vec<Range<usize>>> {
    let mut parts: Vec<Range<usize>> = Vec::new();
    let mut start = 0usize;
    let mut used = 0usize;
    let mut cur_exclusive = false;
    for (i, it) in items.iter().enumerate() {
        let size = it.html.len().saturating_add(ITEM_SLACK);
        if size > budget {
            return None;
        }
        let open = i > start;
        if open && (it.exclusive || cur_exclusive || used.saturating_add(size) > budget) {
            parts.push(start..i);
            start = i;
            used = 0;
        }
        used = used.saturating_add(size);
        cur_exclusive = it.exclusive;
    }
    parts.push(start..items.len());
    (parts.len() <= MAX_PARTS).then_some(parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn widths_match_escape() {
        for s in ["", "a", "&\"'<>", "é€😀", "x&y"] {
            assert_eq!(escaped_len(s), crate::view::escape(s).len(), "{s}");
        }
    }

    #[test]
    fn split_prefers_whitespace_and_keeps_crlf() {
        let t = "aaaa bbbb cccc";
        let r = split_escaped(t, 10);
        let pieces: Vec<&str> = r.iter().filter_map(|r| t.get(r.clone())).collect();
        assert_eq!(pieces.concat(), t);
        assert_eq!(pieces.first().copied(), Some("aaaa bbbb "));
        let t = "aaaaaaa\r\nbb";
        let r = split_escaped(t, 8);
        for x in &r {
            assert!(!t.get(..x.end).unwrap_or("").ends_with('\r') || x.end == t.len());
        }
        assert_eq!(split_escaped("", 100), vec![0..0]);
    }

    const T: &str = "0123456789abcdef0123456789abcdef";

    fn key(b: u8) -> PieceKey {
        PieceKey::new([b; 32])
    }

    fn pv(k: &PieceKey, field: &str, r: Range<usize>, s: &str) -> String {
        piece_value(k, field, &r, s).unwrap_or_default()
    }

    fn piece(v: &str) -> PieceRef<'_> {
        parse_piece(v).unwrap_or(PieceRef {
            field: "x",
            start: 0,
            end: 0,
            total: 0,
            tag: [0; TAG_LEN],
        })
    }

    #[test]
    fn piece_round_trip() {
        let v = pv(&key(1), "what", 3..10, "0123456789abcdefghij");
        let p = piece(&v);
        assert_eq!((p.field, p.start, p.end, p.total), ("what", 3, 10, 20));
        assert_eq!(v.len(), "what-3-10-20-".len() + 2 * TAG_LEN);
        assert!(format!("{p:?}").starts_with("PieceRef(what, 3..10 of 20)"));
        assert_eq!(format!("{:?}", key(1)), "PieceKey([redacted])");
        for bad in [
            "".to_owned(),
            "what".to_owned(),
            "what-1-2".to_owned(),
            "what-1-2-3".to_owned(),
            format!("what-2-1-3-{T}"),
            format!("what-1-4-3-{T}"),
            format!("WHAT-1-2-3-{T}"),
            format!("what-1-2-3-{T}-4"),
            format!("what-+1-2-3-{T}"),
            format!("what--2-3-{T}"),
            format!("what-1-2-9999999999-{T}"),
            format!("what-1-2-3-{}", T.to_uppercase()),
            format!("what-1-2-3-{}", &T[1..]),
            format!("what-1-2-3-{T}0"),
            format!("what-1-2-3-{}g", &T[1..]),
        ] {
            assert_eq!(parse_piece(&bad), None, "{bad}");
        }
    }

    #[test]
    fn splice_checks() {
        let k = key(7);
        let stored = "héllo world";
        let v = pv(&k, "what", 0..6, stored);
        let p = piece(&v);
        assert_eq!(
            splice_piece(&k, "what", stored, &p, "HELLO").map(|s| s.to_string()),
            Ok("HELLO world".to_owned())
        );
        // Offsets are MAC-bound: changing them is stale, not a boundary error.
        let moved = PieceRef { end: 2, ..p };
        assert_eq!(
            splice_piece(&k, "what", stored, &moved, "x").map(|s| s.to_string()),
            Err(SpliceError::Stale)
        );
        let v2 = pv(&k, "what", 0..2, stored);
        let bad = piece(&v2);
        assert_eq!(
            splice_piece(&k, "what", stored, &bad, "x").map(|s| s.to_string()),
            Err(SpliceError::Boundary)
        );
        let stale = PieceRef { total: 3, ..p };
        assert_eq!(
            splice_piece(&k, "what", stored, &stale, "x").map(|s| s.to_string()),
            Err(SpliceError::Stale)
        );
        // Another session's key, or another field, is refused.
        assert_eq!(
            splice_piece(&key(8), "what", stored, &p, "x").map(|s| s.to_string()),
            Err(SpliceError::Stale)
        );
        assert_eq!(
            splice_piece(&k, "who", stored, &p, "x").map(|s| s.to_string()),
            Err(SpliceError::Stale)
        );
    }

    // ST: AUD-RM1-SUI-11 — a same-length change of the stored value is detected (the audit's
    // harness case: `splice_piece("XYZdef", "text-0-3-6", "123")` must not succeed).
    #[test]
    fn same_length_change_is_stale() {
        let k = key(3);
        let v = pv(&k, "text", 0..3, "abcdef");
        let p = piece(&v);
        assert_eq!(
            splice_piece(&k, "text", "abcdef", &p, "123").map(|s| s.to_string()),
            Ok("123def".to_owned())
        );
        for changed in ["XYZdef", "abcdeF", "fedcba"] {
            assert_eq!(changed.len(), 6);
            assert_eq!(
                splice_piece(&k, "text", changed, &p, "123").map(|s| s.to_string()),
                Err(SpliceError::Stale),
                "{changed}"
            );
        }
    }

    #[test]
    fn capped_writer_never_grows() {
        use core::fmt::Write as _;
        let mut w = CappedWriter::new(4);
        assert!(w.write_str("abcd").is_ok());
        assert!(w.write_str("e").is_err());
        assert!(w.overflow);
        let s = w.into_inner();
        assert_eq!(s.as_str(), "abcd");
    }

    fn item(len: usize, exclusive: bool) -> Item {
        Item {
            region: Region::Messages,
            html: Zeroizing::new("x".repeat(len)),
            exclusive,
        }
    }

    #[test]
    fn pack_rules() {
        let items = vec![
            item(10, false),
            item(10, false),
            item(500, true),
            item(10, false),
        ];
        let parts = pack(&items, 500 + ITEM_SLACK - 1);
        assert_eq!(parts, None, "item over budget");
        let parts = pack(&items, 1000);
        assert_eq!(parts, Some(vec![0..2, 2..3, 3..4]));
        let empty = pack(&[], 100).unwrap_or_default();
        assert_eq!(empty.len(), 1);
        assert!(empty.iter().all(|r| r.is_empty()));
    }

    proptest! {
        // ST: AUD-RM1-SUI-11 — any modification of the stored value (same length or not) makes
        // every piece of the old value stale.
        #[test]
        fn any_change_is_stale(s in "[a-z]{1,40}", i in 0usize..40, c in "[A-Z]") {
            let k = key(9);
            let i = i % s.len();
            let mut changed = s.clone();
            changed.replace_range(i..i + 1, &c);
            let v = pv(&k, "text", 0..s.len(), &s);
            let p = piece(&v);
            prop_assert!(splice_piece(&k, "text", &s, &p, "z").is_ok());
            prop_assert_eq!(
                splice_piece(&k, "text", &changed, &p, "z").map(|x| x.to_string()),
                Err(SpliceError::Stale)
            );
        }

        // ST: AUD-RM1-SUI-01 — pieces cover the text exactly, on char boundaries, each within
        // the escaped budget.
        #[test]
        fn split_covers_and_fits(text in any::<String>(), budget in 8usize..200) {
            let ranges = split_escaped(&text, budget);
            let mut next = 0usize;
            for r in &ranges {
                prop_assert_eq!(r.start, next);
                let p = text.get(r.clone());
                prop_assert!(p.is_some());
                prop_assert!(escaped_len(p.unwrap_or("")) <= budget);
                next = r.end;
            }
            prop_assert_eq!(next, text.len());
            for r in ranges.iter().skip(1) {
                prop_assert!(!r.is_empty());
            }
        }
    }
}
