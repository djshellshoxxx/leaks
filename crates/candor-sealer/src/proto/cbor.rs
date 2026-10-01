// SPDX-License-Identifier: AGPL-3.0-or-later
//! Minimal deterministic CBOR (RFC 8949 §4.2.1 core deterministic encoding).
//!
//! Only the subset the sealer needs: unsigned integers, byte strings, text
//! strings, arrays, maps, `false`/`true`/`null`. The decoder is strict
//! (04 §13, 07 BE-006): shortest-form heads only, definite lengths only, no tags,
//! no floats, no negative integers, no other simple values, valid UTF-8, map keys
//! in canonical order with no duplicates (enforced by [`Dec::key`]), and an item
//! budget so that hostile input cannot cause unbounded work. Decoding is
//! schema-driven and iterative: nothing recurses on attacker-controlled depth.
//!
//! The encoder works over [`Zeroizing`] buffers because encoded maps carry draft
//! text and passphrase words.

use zeroize::{Zeroize, Zeroizing};

/// CBOR decoding failure. Carries no input bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborError {
    /// Input ended early.
    Truncated,
    /// A head was not in its shortest form.
    NonCanonical,
    /// Indefinite length, tag, float, negative integer or other unsupported item.
    Unsupported,
    /// The item has a different major type than the schema expects.
    WrongType,
    /// A length, count or value exceeds the schema limit.
    Limit,
    /// A map key is unknown, duplicated, out of order or missing.
    Key,
    /// Bytes remain after the top-level item.
    Trailing,
    /// A text string is not valid UTF-8.
    Utf8,
}

impl core::fmt::Display for CborError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated CBOR",
            Self::NonCanonical => "non-canonical CBOR",
            Self::Unsupported => "unsupported CBOR item",
            Self::WrongType => "unexpected CBOR type",
            Self::Limit => "CBOR limit exceeded",
            Self::Key => "unexpected CBOR map key",
            Self::Trailing => "trailing bytes after CBOR item",
            Self::Utf8 => "invalid UTF-8 in CBOR text",
        })
    }
}

impl std::error::Error for CborError {}

const MAJOR_UINT: u8 = 0x00;
const MAJOR_BYTES: u8 = 0x40;
const MAJOR_TEXT: u8 = 0x60;
const MAJOR_ARRAY: u8 = 0x80;
const MAJOR_MAP: u8 = 0xa0;
const FALSE: u8 = 0xf4;
const TRUE: u8 = 0xf5;
const NULL: u8 = 0xf6;

/// Deterministic CBOR writer. Callers write map keys in canonical order (for
/// unsigned keys: ascending; for the envelope's text keys: shorter first).
#[derive(Default)]
pub struct Enc {
    buf: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for Enc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Enc")
            .field("len", &self.buf.len())
            .finish_non_exhaustive()
    }
}

impl Enc {
    /// Empty writer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Writer whose buffer is allocated once at `cap` bytes. Secret-bearing
    /// encodings size `cap` to their maximum so the buffer never reallocates
    /// (a reallocation would leave an unzeroized copy behind; R7 SI-A-05).
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Zeroizing::new(Vec::with_capacity(cap)),
        }
    }

    fn head(&mut self, major: u8, v: u64) {
        if let Ok(small) = u8::try_from(v) {
            if small < 24 {
                self.buf.push(major | small);
            } else {
                self.buf.push(major | 24);
                self.buf.push(small);
            }
        } else if let Ok(x) = u16::try_from(v) {
            self.buf.push(major | 25);
            self.buf.extend_from_slice(&x.to_be_bytes());
        } else if let Ok(x) = u32::try_from(v) {
            self.buf.push(major | 26);
            self.buf.extend_from_slice(&x.to_be_bytes());
        } else {
            self.buf.push(major | 27);
            self.buf.extend_from_slice(&v.to_be_bytes());
        }
    }

    fn len_head(&mut self, major: u8, n: usize) {
        // usize ≤ u64 on every supported target.
        self.head(major, u64::try_from(n).unwrap_or(u64::MAX));
    }

    /// Unsigned integer.
    pub fn uint(&mut self, v: u64) -> &mut Self {
        self.head(MAJOR_UINT, v);
        self
    }

    /// Byte string.
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.len_head(MAJOR_BYTES, b.len());
        self.buf.extend_from_slice(b);
        self
    }

    /// Text string.
    pub fn text(&mut self, s: &str) -> &mut Self {
        self.len_head(MAJOR_TEXT, s.len());
        self.buf.extend_from_slice(s.as_bytes());
        self
    }

    /// Array head with `n` items.
    pub fn array(&mut self, n: usize) -> &mut Self {
        self.len_head(MAJOR_ARRAY, n);
        self
    }

    /// Map head with `n` entries.
    pub fn map(&mut self, n: usize) -> &mut Self {
        self.len_head(MAJOR_MAP, n);
        self
    }

    /// Boolean.
    pub fn bool(&mut self, b: bool) -> &mut Self {
        self.buf.push(if b { TRUE } else { FALSE });
        self
    }

    /// `null`.
    pub fn null(&mut self) -> &mut Self {
        self.buf.push(NULL);
        self
    }

    /// Append pre-encoded CBOR (must itself be one canonical item).
    pub fn raw(&mut self, item: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(item);
        self
    }

    /// Bytes written so far.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Finish.
    #[must_use]
    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.buf
    }
}

/// Default item budget for one decode (bounds CPU on hostile input).
pub const DEFAULT_ITEM_BUDGET: usize = 8192;

/// Strict, schema-driven CBOR reader over a borrowed buffer.
#[derive(Debug)]
pub struct Dec<'a> {
    buf: &'a [u8],
    pos: usize,
    budget: usize,
}

/// Open map being read: entries not yet consumed.
#[derive(Debug)]
#[must_use]
pub struct MapKeys {
    remaining: usize,
}

impl<'a> Dec<'a> {
    /// Reader with the default item budget.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            budget: DEFAULT_ITEM_BUDGET,
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        let end = self.pos.checked_add(n).ok_or(CborError::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(CborError::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], CborError> {
        let s = self.take(N)?;
        s.try_into().map_err(|_| CborError::Truncated)
    }

    /// Read one head: `(major << 5 bits, value)`. Rejects non-shortest forms,
    /// indefinite lengths, tags, floats and simple values other than
    /// false/true/null.
    fn head(&mut self) -> Result<(u8, u64), CborError> {
        self.budget = self.budget.checked_sub(1).ok_or(CborError::Limit)?;
        let b = *self.take(1)?.first().ok_or(CborError::Truncated)?;
        let major = b & 0xe0;
        let info = b & 0x1f;
        match major {
            // Negative integers and tags are never part of a Candor schema.
            0x20 | 0xc0 => return Err(CborError::Unsupported),
            0xe0 => {
                return match b {
                    FALSE | TRUE | NULL => Ok((major, u64::from(info))),
                    _ => Err(CborError::Unsupported),
                };
            }
            _ => {}
        }
        let v = match info {
            0..=23 => u64::from(info),
            24 => {
                let v = u64::from(u8::from_be_bytes(self.take_array::<1>()?));
                if v < 24 {
                    return Err(CborError::NonCanonical);
                }
                v
            }
            25 => {
                let v = u64::from(u16::from_be_bytes(self.take_array::<2>()?));
                if v <= 0xff {
                    return Err(CborError::NonCanonical);
                }
                v
            }
            26 => {
                let v = u64::from(u32::from_be_bytes(self.take_array::<4>()?));
                if v <= 0xffff {
                    return Err(CborError::NonCanonical);
                }
                v
            }
            27 => {
                let v = u64::from_be_bytes(self.take_array::<8>()?);
                if v <= 0xffff_ffff {
                    return Err(CborError::NonCanonical);
                }
                v
            }
            _ => return Err(CborError::Unsupported),
        };
        Ok((major, v))
    }

    fn expect(&mut self, major: u8) -> Result<u64, CborError> {
        let (m, v) = self.head()?;
        if m == major {
            Ok(v)
        } else {
            Err(CborError::WrongType)
        }
    }

    fn len_of(&mut self, major: u8, max: usize) -> Result<usize, CborError> {
        let v = self.expect(major)?;
        let n = usize::try_from(v).map_err(|_| CborError::Limit)?;
        if n > max {
            return Err(CborError::Limit);
        }
        Ok(n)
    }

    /// Unsigned integer.
    pub fn uint(&mut self) -> Result<u64, CborError> {
        self.expect(MAJOR_UINT)
    }

    /// Unsigned integer `≤ max`.
    pub fn uint_max(&mut self, max: u64) -> Result<u64, CborError> {
        let v = self.uint()?;
        if v > max {
            return Err(CborError::Limit);
        }
        Ok(v)
    }

    /// `u8`.
    pub fn u8(&mut self) -> Result<u8, CborError> {
        u8::try_from(self.uint()?).map_err(|_| CborError::Limit)
    }

    /// `u16`.
    pub fn u16(&mut self) -> Result<u16, CborError> {
        u16::try_from(self.uint()?).map_err(|_| CborError::Limit)
    }

    /// `u32`.
    pub fn u32(&mut self) -> Result<u32, CborError> {
        u32::try_from(self.uint()?).map_err(|_| CborError::Limit)
    }

    /// Byte string of at most `max` bytes (checked before anything is copied).
    pub fn bytes(&mut self, max: usize) -> Result<&'a [u8], CborError> {
        let n = self.len_of(MAJOR_BYTES, max)?;
        self.take(n)
    }

    /// Byte string of exactly `N` bytes.
    pub fn bytes_n<const N: usize>(&mut self) -> Result<[u8; N], CborError> {
        let b = self.bytes(N)?;
        b.try_into().map_err(|_| CborError::Limit)
    }

    /// Text string of at most `max` bytes.
    pub fn text(&mut self, max: usize) -> Result<&'a str, CborError> {
        let n = self.len_of(MAJOR_TEXT, max)?;
        let b = self.take(n)?;
        core::str::from_utf8(b).map_err(|_| CborError::Utf8)
    }

    /// Array head with at most `max` items.
    pub fn array(&mut self, max: usize) -> Result<usize, CborError> {
        self.len_of(MAJOR_ARRAY, max)
    }

    /// Array head with exactly `n` items.
    pub fn array_exact(&mut self, n: usize) -> Result<(), CborError> {
        if self.array(n)? == n {
            Ok(())
        } else {
            Err(CborError::Limit)
        }
    }

    /// Boolean.
    pub fn bool(&mut self) -> Result<bool, CborError> {
        match self.buf.get(self.pos).copied() {
            Some(FALSE) | Some(TRUE) => {
                let (_, v) = self.head()?;
                Ok(v == u64::from(TRUE & 0x1f))
            }
            Some(_) => Err(CborError::WrongType),
            None => Err(CborError::Truncated),
        }
    }

    /// Consume a `null` if one is next; returns whether it was consumed.
    pub fn null(&mut self) -> Result<bool, CborError> {
        if self.buf.get(self.pos).copied() == Some(NULL) {
            self.head()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Map head with at most `max` entries.
    pub fn map(&mut self, max: usize) -> Result<MapKeys, CborError> {
        Ok(MapKeys {
            remaining: self.len_of(MAJOR_MAP, max)?,
        })
    }

    /// If the next key of `m` is `k`, consume it and return `true`. If the next key
    /// is greater than `k` (or the map is exhausted), return `false`, consuming
    /// nothing (key `k` is absent). A smaller key is unknown, duplicated or out of
    /// canonical order and is an error. Callers ask for keys in ascending order.
    pub fn key(&mut self, m: &mut MapKeys, k: u64) -> Result<bool, CborError> {
        if m.remaining == 0 {
            return Ok(false);
        }
        let (save_pos, save_budget) = (self.pos, self.budget);
        let next = self.uint().map_err(|e| match e {
            CborError::WrongType => CborError::Key,
            other => other,
        })?;
        if next == k {
            m.remaining = m.remaining.checked_sub(1).ok_or(CborError::Key)?;
            Ok(true)
        } else {
            self.pos = save_pos;
            self.budget = save_budget;
            if next > k {
                Ok(false)
            } else {
                Err(CborError::Key)
            }
        }
    }

    /// Require key `k` next.
    pub fn req(&mut self, m: &mut MapKeys, k: u64) -> Result<(), CborError> {
        if self.key(m, k)? {
            Ok(())
        } else {
            Err(CborError::Key)
        }
    }

    /// Require a text key equal to `k` next (the IPC envelope's keys).
    pub fn text_key(&mut self, m: &mut MapKeys, k: &str) -> Result<(), CborError> {
        if m.remaining == 0 {
            return Err(CborError::Key);
        }
        let got = self.text(64).map_err(|e| match e {
            CborError::WrongType => CborError::Key,
            other => other,
        })?;
        if got != k {
            return Err(CborError::Key);
        }
        m.remaining = m.remaining.checked_sub(1).ok_or(CborError::Key)?;
        Ok(())
    }

    /// All entries of `m` must have been consumed (no unknown keys).
    pub fn end_map(&self, m: MapKeys) -> Result<(), CborError> {
        if m.remaining == 0 {
            Ok(())
        } else {
            Err(CborError::Key)
        }
    }

    /// The whole buffer must have been consumed.
    pub fn finish(&self) -> Result<(), CborError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(CborError::Trailing)
        }
    }

    /// Current offset.
    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// The raw bytes between two offsets of this buffer.
    #[must_use]
    pub fn slice(&self, from: usize, to: usize) -> Option<&'a [u8]> {
        self.buf.get(from..to)
    }
}

/// An encodable value tree for building inner formats (§13.4) from trusted data.
/// Maps use unsigned keys and are emitted in ascending key order; duplicate keys
/// are rejected at encoding time. Text and byte payloads are zeroized on drop.
#[derive(Clone)]
pub enum Value {
    /// Unsigned integer.
    U(u64),
    /// Byte string.
    B(Zeroizing<Vec<u8>>),
    /// Text string.
    T(Zeroizing<String>),
    /// Array.
    A(Vec<Value>),
    /// Map with unsigned keys.
    M(Vec<(u64, Value)>),
    /// Boolean.
    Bool(bool),
    /// `null`.
    Null,
}

impl Drop for Value {
    /// Integers in inner formats can be draft-sensitive (COI ticks, categories,
    /// questionnaire field ids, mode): wipe them in place before the backing
    /// buffer is freed (AUD-RM2-SEA-08). Byte and text payloads are `Zeroizing`.
    fn drop(&mut self) {
        match self {
            Self::U(v) => v.zeroize(),
            Self::Bool(b) => b.zeroize(),
            _ => {}
        }
    }
}

impl core::fmt::Debug for Value {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Value(<redacted>)")
    }
}

impl Value {
    /// Byte string from a slice.
    #[must_use]
    pub fn bytes(b: &[u8]) -> Self {
        Self::B(Zeroizing::new(b.to_vec()))
    }

    /// Text from a slice.
    #[must_use]
    pub fn text(s: &str) -> Self {
        Self::T(Zeroizing::new(s.to_owned()))
    }

    /// Encode canonically.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, CborError> {
        let mut e = Enc::with_capacity(self.encoded_len_hint());
        self.encode_into(&mut e)?;
        Ok(e.into_bytes())
    }

    /// Upper bound of the encoded length (each head ≤ 9 bytes), used to size the
    /// output buffer once.
    #[must_use]
    pub fn encoded_len_hint(&self) -> usize {
        match self {
            Self::U(_) | Self::Bool(_) | Self::Null => 9,
            Self::B(b) => b.len().saturating_add(9),
            Self::T(t) => t.len().saturating_add(9),
            Self::A(items) => items
                .iter()
                .fold(9usize, |acc, i| acc.saturating_add(i.encoded_len_hint())),
            Self::M(entries) => entries.iter().fold(9usize, |acc, (_, v)| {
                acc.saturating_add(9).saturating_add(v.encoded_len_hint())
            }),
        }
    }

    /// Encode into a writer. Recursion depth is bounded by the (trusted) value tree.
    pub fn encode_into(&self, e: &mut Enc) -> Result<(), CborError> {
        match self {
            Self::U(v) => {
                e.uint(*v);
            }
            Self::B(b) => {
                e.bytes(b);
            }
            Self::T(t) => {
                e.text(t);
            }
            Self::A(items) => {
                e.array(items.len());
                for i in items {
                    i.encode_into(e)?;
                }
            }
            Self::M(entries) => {
                let mut order: Vec<&(u64, Value)> = entries.iter().collect();
                order.sort_by_key(|(k, _)| *k);
                if order.windows(2).any(|w| matches!(w, [a, b] if a.0 == b.0)) {
                    return Err(CborError::Key);
                }
                e.map(order.len());
                for (k, v) in order {
                    e.uint(*k);
                    v.encode_into(e)?;
                }
            }
            Self::Bool(b) => {
                e.bool(*b);
            }
            Self::Null => {
                e.null();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn heads_are_shortest_and_round_trip() {
        for v in [
            0u64,
            23,
            24,
            255,
            256,
            65535,
            65536,
            u64::from(u32::MAX),
            u64::from(u32::MAX) + 1,
            u64::MAX,
        ] {
            let mut e = Enc::new();
            e.uint(v);
            let b = e.into_bytes();
            let mut d = Dec::new(&b);
            assert_eq!(d.uint().unwrap(), v);
            d.finish().unwrap();
        }
    }

    #[test]
    fn rejects_non_canonical_indefinite_tags_floats() {
        for bad in [
            &[0x18, 0x05][..],         // 5 in two bytes
            &[0x19, 0x00, 0x10],       // 16 in three bytes
            &[0x1a, 0, 0, 0xff, 0xff], // u16 in five bytes
            &[0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
            &[0x5f, 0xff],                   // indefinite bytes
            &[0xc0, 0x00],                   // tag
            &[0xf9, 0x00, 0x00],             // half float
            &[0xfb, 0, 0, 0, 0, 0, 0, 0, 0], // double
            &[0x20],                         // negative int
            &[0xf7],                         // undefined
        ] {
            let mut d = Dec::new(bad);
            assert!(d.uint().is_err() || d.finish().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn map_keys_must_be_canonical_and_known() {
        // {1: 0, 2: 0}
        let ok = [0xa2, 0x01, 0x00, 0x02, 0x00];
        let mut d = Dec::new(&ok);
        let mut m = d.map(4).unwrap();
        d.req(&mut m, 1).unwrap();
        d.uint().unwrap();
        assert!(d.key(&mut m, 0).is_ok() && d.key(&mut m, 2).unwrap());
        d.uint().unwrap();
        d.end_map(m).unwrap();
        d.finish().unwrap();
        // out of order {2: 0, 1: 0}
        let bad = [0xa2, 0x02, 0x00, 0x01, 0x00];
        let mut d = Dec::new(&bad);
        let mut m = d.map(4).unwrap();
        assert!(!d.key(&mut m, 1).unwrap());
        d.req(&mut m, 2).unwrap();
        d.uint().unwrap();
        assert_eq!(d.key(&mut m, 3), Err(CborError::Key));
        // duplicate {1: 0, 1: 0}
        let dup = [0xa2, 0x01, 0x00, 0x01, 0x00];
        let mut d = Dec::new(&dup);
        let mut m = d.map(4).unwrap();
        d.req(&mut m, 1).unwrap();
        d.uint().unwrap();
        assert_eq!(d.key(&mut m, 2), Err(CborError::Key));
    }

    #[test]
    fn value_sorts_and_rejects_duplicates() {
        let v = Value::M(vec![(2, Value::U(1)), (1, Value::Null)]);
        assert_eq!(&v.encode().unwrap()[..], &[0xa2, 0x01, 0xf6, 0x02, 0x01]);
        let d = Value::M(vec![(1, Value::U(1)), (1, Value::Null)]);
        assert!(d.encode().is_err());
    }

    #[test]
    fn length_limits_checked_before_copy() {
        // bstr claiming 2^32 bytes
        let b = [0x5a, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(Dec::new(&b).bytes(1024), Err(CborError::Limit));
        assert_eq!(Dec::new(&[0x42, 0x01]).bytes(8), Err(CborError::Truncated));
        assert_eq!(Dec::new(&[0x62, 0xff, 0xfe]).text(8), Err(CborError::Utf8));
    }
}
