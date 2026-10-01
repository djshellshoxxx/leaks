// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hand-rolled deterministic CBOR (RFC 8949 §4.2.1 "core deterministic encoding").
//!
//! Only the subset needed by the audit envelope is supported: unsigned and
//! negative integers, byte strings, text strings, arrays, maps, `true`,
//! `false` and `null`. Rules enforced on encode **and** checked on decode:
//!
//! * integers and lengths use the shortest head form (preferred serialization);
//! * definite lengths only (no indefinite-length items);
//! * map keys are sorted by the bytewise lexicographic order of their
//!   deterministic encodings, and duplicate keys are rejected;
//! * no tags, no floating point, no simple values other than false/true/null;
//! * text strings are valid UTF-8.
//!
//! A byte string is canonical iff [`decode`] accepts it; then
//! `encode(&decode(b)?)? == b` (property-tested).
//!
//! The decoder is hostile-input safe: depth limit, every declared length is
//! checked against the remaining input before allocation, no indexing.

use core::fmt;

/// Maximum nesting depth accepted by the decoder.
pub const MAX_DEPTH: usize = 16;

/// A CBOR data item in the supported subset.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Value {
    /// Major type 0.
    Uint(u64),
    /// Major type 1: the value is `-1 - n`.
    Nint(u64),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3.
    Text(String),
    /// Major type 4.
    Array(Vec<Value>),
    /// Major type 5, as a list of entries (sorted on encode).
    Map(Vec<(Value, Value)>),
    /// Simple value false/true.
    Bool(bool),
    /// Simple value null.
    Null,
}

/// Encoding/decoding errors (no input data is echoed).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CborError {
    /// Input ended early.
    Truncated,
    /// Bytes remain after the top-level item.
    TrailingBytes,
    /// A head was not in shortest form.
    NonCanonicalHead,
    /// Indefinite length item.
    Indefinite,
    /// Unsupported major type / simple value / tag / float.
    Unsupported,
    /// Map keys not in canonical order.
    UnsortedKeys,
    /// Duplicate map key.
    DuplicateKey,
    /// Invalid UTF-8 in a text string.
    InvalidUtf8,
    /// Nesting too deep.
    TooDeep,
    /// Length does not fit in memory.
    TooLong,
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Truncated => "cbor: truncated",
            Self::TrailingBytes => "cbor: trailing bytes",
            Self::NonCanonicalHead => "cbor: non-canonical head",
            Self::Indefinite => "cbor: indefinite length",
            Self::Unsupported => "cbor: unsupported item",
            Self::UnsortedKeys => "cbor: unsorted map keys",
            Self::DuplicateKey => "cbor: duplicate map key",
            Self::InvalidUtf8 => "cbor: invalid utf-8",
            Self::TooDeep => "cbor: nesting too deep",
            Self::TooLong => "cbor: length too large",
        };
        f.write_str(s)
    }
}

impl std::error::Error for CborError {}

fn write_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let mt = major << 5;
    if n < 24 {
        // n < 24 so the cast is lossless.
        out.push(mt | (n as u8));
    } else if let Ok(b) = u8::try_from(n) {
        out.push(mt | 24);
        out.push(b);
    } else if let Ok(w) = u16::try_from(n) {
        out.push(mt | 25);
        out.extend_from_slice(&w.to_be_bytes());
    } else if let Ok(d) = u32::try_from(n) {
        out.push(mt | 26);
        out.extend_from_slice(&d.to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn len_u64(n: usize) -> u64 {
    // usize is at most 64 bits on every supported target.
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Deterministically encode `v`.
pub fn encode(v: &Value) -> Result<Vec<u8>, CborError> {
    let mut out = Vec::new();
    encode_into(&mut out, v, 0)?;
    Ok(out)
}

fn encode_into(out: &mut Vec<u8>, v: &Value, depth: usize) -> Result<(), CborError> {
    if depth > MAX_DEPTH {
        return Err(CborError::TooDeep);
    }
    let next = depth.saturating_add(1);
    match v {
        Value::Uint(n) => write_head(out, 0, *n),
        Value::Nint(n) => write_head(out, 1, *n),
        Value::Bytes(b) => {
            write_head(out, 2, len_u64(b.len()));
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            write_head(out, 3, len_u64(t.len()));
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(items) => {
            write_head(out, 4, len_u64(items.len()));
            for it in items {
                encode_into(out, it, next)?;
            }
        }
        Value::Map(entries) => {
            let mut enc: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(entries.len());
            for (k, val) in entries {
                let mut kb = Vec::new();
                encode_into(&mut kb, k, next)?;
                let mut vb = Vec::new();
                encode_into(&mut vb, val, next)?;
                enc.push((kb, vb));
            }
            enc.sort_by(|a, b| a.0.cmp(&b.0));
            for w in enc.windows(2) {
                if let [a, b] = w {
                    if a.0 == b.0 {
                        return Err(CborError::DuplicateKey);
                    }
                }
            }
            write_head(out, 5, len_u64(enc.len()));
            for (kb, vb) in enc {
                out.extend_from_slice(&kb);
                out.extend_from_slice(&vb);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
    }
    Ok(())
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, CborError> {
        let (b, rest) = self.rest.split_first().ok_or(CborError::Truncated)?;
        self.rest = rest;
        Ok(*b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        if n > self.rest.len() {
            return Err(CborError::Truncated);
        }
        let (a, b) = self.rest.split_at(n);
        self.rest = b;
        Ok(a)
    }

    fn arg(&mut self, info: u8) -> Result<u64, CborError> {
        match info {
            0..=23 => Ok(u64::from(info)),
            24 => {
                let v = u64::from(self.byte()?);
                if v < 24 {
                    return Err(CborError::NonCanonicalHead);
                }
                Ok(v)
            }
            25 => {
                let b = self.take(2)?;
                let arr: [u8; 2] = b.try_into().map_err(|_| CborError::Truncated)?;
                let v = u64::from(u16::from_be_bytes(arr));
                if v <= 0xff {
                    return Err(CborError::NonCanonicalHead);
                }
                Ok(v)
            }
            26 => {
                let b = self.take(4)?;
                let arr: [u8; 4] = b.try_into().map_err(|_| CborError::Truncated)?;
                let v = u64::from(u32::from_be_bytes(arr));
                if v <= 0xffff {
                    return Err(CborError::NonCanonicalHead);
                }
                Ok(v)
            }
            27 => {
                let b = self.take(8)?;
                let arr: [u8; 8] = b.try_into().map_err(|_| CborError::Truncated)?;
                let v = u64::from_be_bytes(arr);
                if v <= 0xffff_ffff {
                    return Err(CborError::NonCanonicalHead);
                }
                Ok(v)
            }
            31 => Err(CborError::Indefinite),
            _ => Err(CborError::Unsupported),
        }
    }

    fn len(&mut self, info: u8) -> Result<usize, CborError> {
        let n = self.arg(info)?;
        let n = usize::try_from(n).map_err(|_| CborError::TooLong)?;
        // Every element needs at least one byte, so a declared length larger
        // than the remaining input is necessarily truncated (no huge allocs).
        if n > self.rest.len() {
            return Err(CborError::Truncated);
        }
        Ok(n)
    }

    fn item(&mut self, depth: usize) -> Result<Value, CborError> {
        if depth > MAX_DEPTH {
            return Err(CborError::TooDeep);
        }
        let next = depth.saturating_add(1);
        let ib = self.byte()?;
        let major = ib >> 5;
        let info = ib & 0x1f;
        match major {
            0 => Ok(Value::Uint(self.arg(info)?)),
            1 => Ok(Value::Nint(self.arg(info)?)),
            2 => {
                let n = self.len(info)?;
                Ok(Value::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let n = self.len(info)?;
                let b = self.take(n)?;
                let s = core::str::from_utf8(b).map_err(|_| CborError::InvalidUtf8)?;
                Ok(Value::Text(s.to_owned()))
            }
            4 => {
                let n = self.len(info)?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.item(next)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let n = self.len(info)?;
                let mut entries = Vec::with_capacity(n);
                let mut prev_key: Option<&'a [u8]> = None;
                for _ in 0..n {
                    let before = self.rest;
                    let k = self.item(next)?;
                    let used = before.len().saturating_sub(self.rest.len());
                    let kbytes = before.get(..used).ok_or(CborError::Truncated)?;
                    if let Some(p) = prev_key {
                        match p.cmp(kbytes) {
                            core::cmp::Ordering::Less => {}
                            core::cmp::Ordering::Equal => return Err(CborError::DuplicateKey),
                            core::cmp::Ordering::Greater => return Err(CborError::UnsortedKeys),
                        }
                    }
                    prev_key = Some(kbytes);
                    let v = self.item(next)?;
                    entries.push((k, v));
                }
                Ok(Value::Map(entries))
            }
            7 => match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                31 => Err(CborError::Indefinite),
                _ => Err(CborError::Unsupported),
            },
            // 6 = tags: not part of the audit encoding.
            _ => Err(CborError::Unsupported),
        }
    }
}

/// Strictly decode one canonical item; any deviation from deterministic
/// encoding is an error.
pub fn decode(bytes: &[u8]) -> Result<Value, CborError> {
    let mut r = Reader { rest: bytes };
    let v = r.item(0)?;
    if !r.rest.is_empty() {
        return Err(CborError::TrailingBytes);
    }
    Ok(v)
}

impl Value {
    /// Text value from a static string (keys and enumerated codes only).
    pub fn text(s: &'static str) -> Self {
        Self::Text(s.to_owned())
    }

    /// Look up a text key in a map value.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Self::Map(entries) => entries.iter().find_map(|(k, v)| match k {
                Self::Text(t) if t == key => Some(v),
                _ => None,
            }),
            _ => None,
        }
    }

    /// As unsigned integer.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Uint(n) => Some(*n),
            _ => None,
        }
    }

    /// As byte string.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// As text string.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(t) => Some(t),
            _ => None,
        }
    }

    /// As bool.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// As 32-byte array.
    pub fn as_bytes32(&self) -> Option<[u8; 32]> {
        self.as_bytes().and_then(|b| b.try_into().ok())
    }
}

/// Builder for text-keyed maps.
#[derive(Debug, Default)]
pub struct MapBuilder {
    entries: Vec<(Value, Value)>,
}

impl MapBuilder {
    /// New empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry with a static text key.
    pub fn put(&mut self, key: &'static str, v: Value) -> &mut Self {
        self.entries.push((Value::text(key), v));
        self
    }

    /// Add an entry only when `v` is `Some`.
    pub fn put_opt(&mut self, key: &'static str, v: Option<Value>) -> &mut Self {
        if let Some(v) = v {
            self.put(key, v);
        }
        self
    }

    /// Finish.
    pub fn build(self) -> Value {
        Value::Map(self.entries)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    // RFC 8949 Appendix A known-answer vectors (subset).
    #[test]
    fn rfc8949_appendix_a_vectors() {
        let cases: &[(Value, &[u8])] = &[
            (Value::Uint(0), &[0x00]),
            (Value::Uint(23), &[0x17]),
            (Value::Uint(24), &[0x18, 0x18]),
            (Value::Uint(1000), &[0x19, 0x03, 0xe8]),
            (Value::Uint(1_000_000), &[0x1a, 0x00, 0x0f, 0x42, 0x40]),
            (
                Value::Uint(1_000_000_000_000),
                &[0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00],
            ),
            (Value::Nint(0), &[0x20]),
            (Value::Nint(99), &[0x38, 0x63]),
            (Value::Bool(false), &[0xf4]),
            (Value::Bool(true), &[0xf5]),
            (Value::Null, &[0xf6]),
            (Value::Bytes(vec![1, 2, 3, 4]), &[0x44, 1, 2, 3, 4]),
            (Value::Text("IETF".into()), &[0x64, 0x49, 0x45, 0x54, 0x46]),
            (
                Value::Array(vec![Value::Uint(1), Value::Uint(2), Value::Uint(3)]),
                &[0x83, 1, 2, 3],
            ),
        ];
        for (v, b) in cases {
            assert_eq!(encode(v).unwrap(), *b);
            assert_eq!(&decode(b).unwrap(), v);
        }
    }

    #[test]
    fn map_keys_sorted_bytewise() {
        // RFC 8949 §4.2.1: shorter encodings sort first ("b" < "aa").
        let m = Value::Map(vec![
            (Value::text("aa"), Value::Uint(1)),
            (Value::text("b"), Value::Uint(2)),
        ]);
        let e = encode(&m).unwrap();
        assert_eq!(e, [0xa2, 0x61, b'b', 0x02, 0x62, b'a', b'a', 0x01]);
    }

    #[test]
    fn rejects_non_canonical() {
        assert_eq!(decode(&[0x18, 0x05]), Err(CborError::NonCanonicalHead));
        assert_eq!(decode(&[0x19, 0x00, 0x10]), Err(CborError::NonCanonicalHead));
        assert_eq!(decode(&[0x5f, 0xff]), Err(CborError::Indefinite));
        assert_eq!(decode(&[0xc0, 0x00]), Err(CborError::Unsupported));
        assert_eq!(decode(&[0xf9, 0x00, 0x00]), Err(CborError::Unsupported));
        assert_eq!(decode(&[0x00, 0x00]), Err(CborError::TrailingBytes));
        assert_eq!(decode(&[0x62, 0xff, 0xfe]), Err(CborError::InvalidUtf8));
        // unsorted map {"b":1,"a":2}
        assert_eq!(
            decode(&[0xa2, 0x61, b'b', 1, 0x61, b'a', 2]),
            Err(CborError::UnsortedKeys)
        );
        assert_eq!(
            decode(&[0xa2, 0x61, b'a', 1, 0x61, b'a', 2]),
            Err(CborError::DuplicateKey)
        );
        // huge declared length, tiny input: no allocation, truncated.
        assert_eq!(
            decode(&[0x5b, 0, 0, 0, 1, 0, 0, 0, 0]),
            Err(CborError::Truncated)
        );
        let mut deep = vec![0x81; MAX_DEPTH + 2];
        deep.push(0);
        assert_eq!(decode(&deep), Err(CborError::TooDeep));
    }

    #[test]
    fn duplicate_key_rejected_on_encode() {
        let m = Value::Map(vec![
            (Value::text("a"), Value::Uint(1)),
            (Value::text("a"), Value::Uint(2)),
        ]);
        assert_eq!(encode(&m), Err(CborError::DuplicateKey));
    }
}
