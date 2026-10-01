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
//! An editable piece carries a hidden `piece` field (`{field}-{start}-{end}-{total}`, byte
//! offsets into the stored value) so that C-07 can replace exactly that range
//! ([`splice_piece`]).

use core::fmt;
use core::ops::Range;

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

/// One piece of a long value as sent back by the form (`{field}-{start}-{end}-{total}`).
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
    if v.len() > 64 {
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
    if it.next().is_some() || start > end || end > total {
        return None;
    }
    Some(PieceRef {
        field,
        start,
        end,
        total,
    })
}

/// Formats a `piece` field value.
pub(crate) fn piece_value(field: &str, r: &Range<usize>, total: usize) -> String {
    format!("{field}-{}-{}-{total}", r.start, r.end)
}

/// Why a piece could not be applied. C-07 then re-renders the page with the posted text kept
/// (11 §5.7) instead of guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpliceError {
    /// The stored value changed since the page was rendered (length differs).
    Stale,
    /// The offsets are not on character boundaries of the stored value.
    Boundary,
}

/// Replaces `piece.start..piece.end` of `stored` with `edited`. Fails closed if the stored
/// value changed since rendering or the offsets are not character boundaries. The result is
/// zeroized on drop and allocated once (no reallocation copies).
pub fn splice_piece(
    stored: &str,
    piece: &PieceRef<'_>,
    edited: &str,
) -> Result<Zeroizing<String>, SpliceError> {
    if stored.len() != piece.total {
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

    #[test]
    fn piece_round_trip() {
        let v = piece_value("what", &(3..10), 20);
        let p = parse_piece(&v);
        assert_eq!(
            p,
            Some(PieceRef {
                field: "what",
                start: 3,
                end: 10,
                total: 20
            })
        );
        for bad in [
            "",
            "what",
            "what-1-2",
            "what-2-1-3",
            "what-1-4-3",
            "WHAT-1-2-3",
            "what-1-2-3-4",
            "what-+1-2-3",
            "what--2-3",
            "what-1-2-9999999999",
        ] {
            assert_eq!(parse_piece(bad), None, "{bad}");
        }
    }

    #[test]
    fn splice_checks() {
        let stored = "héllo world";
        let p = PieceRef {
            field: "what",
            start: 0,
            end: 6,
            total: stored.len(),
        };
        assert_eq!(
            splice_piece(stored, &p, "HELLO").map(|s| s.to_string()),
            Ok("HELLO world".to_owned())
        );
        let bad = PieceRef { end: 2, ..p };
        assert_eq!(
            splice_piece(stored, &bad, "x").map(|s| s.to_string()),
            Err(SpliceError::Boundary)
        );
        let stale = PieceRef { total: 3, ..p };
        assert_eq!(
            splice_piece(stored, &stale, "x").map(|s| s.to_string()),
            Err(SpliceError::Stale)
        );
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
        let items = vec![item(10, false), item(10, false), item(500, true), item(10, false)];
        let parts = pack(&items, 400 + ITEM_SLACK * 2);
        assert_eq!(parts, None, "item over budget");
        let parts = pack(&items, 1000);
        assert_eq!(parts, Some(vec![0..2, 2..3, 3..4]));
        assert_eq!(pack(&[], 100), Some(vec![0..0]));
    }

    proptest! {
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
