// SPDX-License-Identifier: AGPL-3.0-or-later
//! In-house streaming `multipart/form-data` parser (07 §5.1 "Multipart
//! parser", INC-107; ST-043 `fuzz_multipart_intake`, ST-082).
//!
//! The parser is a pull state machine over a bounded internal buffer: the
//! server [`Multipart::feed`]s request bytes as they arrive and drains
//! [`Multipart::next_event`] until it returns `None`. File bytes are emitted
//! in chunks of at most [`UPLOAD_CHUNK`] as soon as they cannot be part of a
//! delimiter, so a file is never held in memory and never touches disk.
//!
//! Strictness:
//! * no preamble, the body starts with `--boundary CRLF`; after the closing
//!   delimiter only one optional `CRLF` may follow (trailing bytes rejected);
//! * at most [`MAX_MULTIPART_PARTS`] parts, each header block ≤
//!   [`MAX_PART_HEADER`]; only `Content-Disposition: form-data; name="…"`
//!   (plus `; filename="…"` for file parts) and `Content-Type` are allowed,
//!   each at most once;
//! * a part `Content-Type` of `multipart/*` (nesting) is rejected, as is any
//!   `Content-Transfer-Encoding`, `filename*` or other parameter;
//! * field names `[a-z_]{1,32}`; the filename is ≤ [`MAX_FILENAME_BYTES`]
//!   bytes of UTF-8 without control characters, NFC-normalised, and is only
//!   ever used as encrypted metadata (never a path, ADR-012/027);
//! * non-file values are ≤ [`MAX_PART_VALUE`] bytes.
//!
//! The parser never sniffs content and never echoes input in errors.

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::limits::{
    MAX_BOUNDARY, MAX_FILENAME_BYTES, MAX_MEDIA_TYPE_BYTES, MAX_MULTIPART_PARTS, MAX_PART_HEADER,
    MAX_PART_VALUE, UPLOAD_CHUNK,
};

/// Parse failure (content-free).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultipartError {
    /// Syntax or policy violation.
    Malformed,
    /// More parts than allowed.
    TooManyParts,
    /// A non-file value or a header block over its limit.
    TooLarge,
}

/// One part's header.
pub struct PartHeader {
    /// Field name (`[a-z_]{1,32}`).
    pub name: String,
    /// Filename (NFC), present for file parts.
    pub filename: Option<Zeroizing<String>>,
    /// Claimed media type (ASCII, ≤ 127 bytes), only for file parts.
    pub content_type: Option<Zeroizing<String>>,
}

impl core::fmt::Debug for PartHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Field name is ours; filename and type are source metadata.
        f.debug_struct("PartHeader")
            .field("name", &self.name)
            .field("file", &self.filename.is_some())
            .finish_non_exhaustive()
    }
}

/// A parser event.
pub enum Event {
    /// A part begins.
    Part(PartHeader),
    /// Bytes of the current part (≤ [`UPLOAD_CHUNK`]).
    Data(Zeroizing<Vec<u8>>),
    /// The current part ended.
    PartEnd,
    /// The closing delimiter was seen.
    End,
}

impl core::fmt::Debug for Event {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Part(h) => write!(f, "Part({h:?})"),
            Self::Data(d) => write!(f, "Data([{} bytes redacted])", d.len()),
            Self::PartEnd => f.write_str("PartEnd"),
            Self::End => f.write_str("End"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Start,
    Headers,
    Body { file: bool },
    AfterDelimiter,
    Epilogue,
    Done,
    Failed,
}

/// Streaming parser state.
pub struct Multipart {
    /// `\r\n--boundary`.
    delim: Vec<u8>,
    buf: Zeroizing<Vec<u8>>,
    state: State,
    parts: usize,
    value_len: usize,
    pending_end: bool,
}

impl core::fmt::Debug for Multipart {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Multipart")
            .field("state", &self.state)
            .field("parts", &self.parts)
            .finish_non_exhaustive()
    }
}

/// Capacity of the internal buffer: one chunk plus a delimiter and its CRLF,
/// and room for a header block. [`Multipart::feed`] callers must not feed more
/// than [`Multipart::room`] at once.
const BUF_CAP: usize = UPLOAD_CHUNK + MAX_BOUNDARY + 8 + MAX_PART_HEADER;

fn bchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&b)
}

/// Parse the request `Content-Type` and return the boundary: exactly
/// `multipart/form-data; boundary=<1..70 bchars>` (optionally quoted).
#[must_use]
pub fn boundary_from_content_type(ct: &str) -> Option<String> {
    let mut it = ct.split(';').map(str::trim);
    if !it.next()?.eq_ignore_ascii_case("multipart/form-data") {
        return None;
    }
    let p = it.next()?;
    if it.next().is_some() {
        return None;
    }
    let (k, v) = p.split_once('=')?;
    if !k.trim().eq_ignore_ascii_case("boundary") {
        return None;
    }
    let v = v.trim();
    let v = v
        .strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .unwrap_or(v);
    let ok = (1..=MAX_BOUNDARY).contains(&v.len()) && v.bytes().all(bchar) && !v.ends_with(' ');
    ok.then(|| v.to_owned())
}

impl Multipart {
    /// A parser for `boundary` (from [`boundary_from_content_type`]).
    #[must_use]
    pub fn new(boundary: &str) -> Self {
        let mut delim = Vec::with_capacity(boundary.len().saturating_add(4));
        delim.extend_from_slice(b"\r\n--");
        delim.extend_from_slice(boundary.as_bytes());
        Self {
            delim,
            buf: Zeroizing::new(Vec::with_capacity(BUF_CAP)),
            state: State::Start,
            parts: 0,
            value_len: 0,
            pending_end: false,
        }
    }

    /// How many bytes [`Multipart::feed`] accepts now.
    #[must_use]
    pub fn room(&self) -> usize {
        BUF_CAP.saturating_sub(self.buf.len())
    }

    /// The closing delimiter (and its optional CRLF) has been consumed.
    #[must_use]
    pub fn finished(&self) -> bool {
        matches!(self.state, State::Done | State::Epilogue)
    }

    /// Append input (at most [`Multipart::room`] bytes; more is an error so the
    /// buffer never grows past its fixed capacity).
    pub fn feed(&mut self, input: &[u8]) -> Result<(), MultipartError> {
        if self.state == State::Failed {
            return Err(MultipartError::Malformed);
        }
        if input.len() > self.room() {
            self.state = State::Failed;
            return Err(MultipartError::TooLarge);
        }
        if self.state == State::Done && !input.is_empty() {
            self.state = State::Failed;
            return Err(MultipartError::Malformed);
        }
        self.buf.extend_from_slice(input);
        Ok(())
    }

    /// Input is complete (`Content-Length` reached): anything but a finished
    /// body is an error.
    pub fn finish(&mut self) -> Result<(), MultipartError> {
        match self.state {
            State::Done => Ok(()),
            State::Epilogue if self.buf.is_empty() => {
                self.state = State::Done;
                Ok(())
            }
            _ => {
                self.state = State::Failed;
                Err(MultipartError::Malformed)
            }
        }
    }

    fn fail<T>(&mut self, e: MultipartError) -> Result<T, MultipartError> {
        self.state = State::Failed;
        Err(e)
    }

    fn consume(&mut self, n: usize) {
        let n = n.min(self.buf.len());
        self.buf.drain(..n);
    }

    /// The next event, `Ok(None)` when more input is needed (or the body is
    /// complete).
    pub fn next_event(&mut self) -> Result<Option<Event>, MultipartError> {
        loop {
            if self.pending_end {
                self.pending_end = false;
                return Ok(Some(Event::PartEnd));
            }
            match self.state {
                State::Failed => return Err(MultipartError::Malformed),
                State::Done => return Ok(None),
                State::Start => {
                    // `--boundary\r\n` (the delimiter without its leading CRLF).
                    let first = self.delim.get(2..).unwrap_or_default().to_vec();
                    let need = first.len().saturating_add(2);
                    if self.buf.len() < need {
                        if !first.starts_with(
                            self.buf
                                .get(..self.buf.len().min(first.len()))
                                .unwrap_or_default(),
                        ) {
                            return self.fail(MultipartError::Malformed);
                        }
                        return Ok(None);
                    }
                    if self.buf.get(..first.len()) != Some(first.as_slice())
                        || self.buf.get(first.len()..need) != Some(b"\r\n".as_slice())
                    {
                        return self.fail(MultipartError::Malformed);
                    }
                    self.consume(need);
                    self.state = State::Headers;
                }
                State::Headers => {
                    let Some(end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                        if self.buf.len() > MAX_PART_HEADER {
                            return self.fail(MultipartError::TooLarge);
                        }
                        return Ok(None);
                    };
                    if end > MAX_PART_HEADER {
                        return self.fail(MultipartError::TooLarge);
                    }
                    self.parts = self.parts.saturating_add(1);
                    if self.parts > MAX_MULTIPART_PARTS {
                        return self.fail(MultipartError::TooManyParts);
                    }
                    let block = self.buf.get(..end).unwrap_or_default().to_vec();
                    let header = match parse_part_header(&block) {
                        Ok(h) => h,
                        Err(e) => return self.fail(e),
                    };
                    self.consume(end.saturating_add(4));
                    self.value_len = 0;
                    self.state = State::Body {
                        file: header.filename.is_some(),
                    };
                    return Ok(Some(Event::Part(header)));
                }
                State::Body { file } => {
                    let dl = self.delim.len();
                    if let Some(at) = self
                        .buf
                        .windows(dl)
                        .position(|w| w == self.delim.as_slice())
                    {
                        if at > 0 {
                            let n = at.min(UPLOAD_CHUNK);
                            return self.emit(n, file).map(Some);
                        }
                        self.consume(dl);
                        self.state = State::AfterDelimiter;
                        self.pending_end = true;
                        continue;
                    }
                    // Keep a tail that could be the start of the delimiter.
                    let safe = self.buf.len().saturating_sub(dl.saturating_sub(1));
                    if safe == 0 {
                        return Ok(None);
                    }
                    let n = safe.min(UPLOAD_CHUNK);
                    // Emit only full chunks unless the buffer is nearly full,
                    // so tiny feeds do not become tiny IPC messages.
                    if n < UPLOAD_CHUNK && self.room() > UPLOAD_CHUNK / 2 && file {
                        return Ok(None);
                    }
                    return self.emit(n, file).map(Some);
                }
                State::AfterDelimiter => {
                    let Some(two) = self.buf.get(..2) else {
                        return Ok(None);
                    };
                    match two {
                        b"\r\n" => {
                            self.consume(2);
                            self.state = State::Headers;
                        }
                        b"--" => {
                            self.consume(2);
                            self.state = State::Epilogue;
                            return Ok(Some(Event::End));
                        }
                        _ => return self.fail(MultipartError::Malformed),
                    }
                }
                State::Epilogue => {
                    // Only one optional CRLF may follow the closing delimiter.
                    match self.buf.as_slice() {
                        [] => return Ok(None),
                        [b'\r'] => return Ok(None),
                        [b'\r', b'\n'] => {
                            self.consume(2);
                            self.state = State::Done;
                            return Ok(None);
                        }
                        _ => return self.fail(MultipartError::Malformed),
                    }
                }
            }
        }
    }

    fn emit(&mut self, n: usize, file: bool) -> Result<Event, MultipartError> {
        if !file {
            self.value_len = self.value_len.saturating_add(n);
            if self.value_len > MAX_PART_VALUE {
                return self.fail(MultipartError::TooLarge);
            }
        }
        let mut out = Zeroizing::new(Vec::with_capacity(n));
        out.extend_from_slice(self.buf.get(..n).unwrap_or_default());
        self.consume(n);
        Ok(Event::Data(out))
    }
}

fn part_name_ok(n: &str) -> bool {
    (1..=32).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

/// `name="value"` with a quoted value that contains no `"`, CR or LF.
fn quoted(param: &str, key: &str) -> Option<String> {
    let (k, v) = param.split_once('=')?;
    if k != key {
        return None;
    }
    let v = v.strip_prefix('"')?.strip_suffix('"')?;
    if v.contains('"') {
        return None;
    }
    Some(v.to_owned())
}

fn parse_part_header(block: &[u8]) -> Result<PartHeader, MultipartError> {
    let text = core::str::from_utf8(block).map_err(|_| MultipartError::Malformed)?;
    let mut disposition: Option<(String, Option<Zeroizing<String>>)> = None;
    let mut content_type: Option<Zeroizing<String>> = None;
    for line in text.split("\r\n") {
        if line.is_empty() || line.contains(['\r', '\n']) || line.starts_with([' ', '\t']) {
            return Err(MultipartError::Malformed);
        }
        let (name, value) = line.split_once(':').ok_or(MultipartError::Malformed)?;
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("content-disposition") {
            if disposition.is_some() {
                return Err(MultipartError::Malformed);
            }
            let mut params = value.split("; ");
            if params.next() != Some("form-data") {
                return Err(MultipartError::Malformed);
            }
            let field = quoted(params.next().ok_or(MultipartError::Malformed)?, "name")
                .ok_or(MultipartError::Malformed)?;
            if !part_name_ok(&field) {
                return Err(MultipartError::Malformed);
            }
            let filename = match params.next() {
                None => None,
                Some(p) => {
                    let f = quoted(p, "filename").ok_or(MultipartError::Malformed)?;
                    Some(filename(&f)?)
                }
            };
            if params.next().is_some() {
                return Err(MultipartError::Malformed);
            }
            disposition = Some((field, filename));
        } else if name.eq_ignore_ascii_case("content-type") {
            if content_type.is_some()
                || value.is_empty()
                || value.len() > MAX_MEDIA_TYPE_BYTES
                || !value
                    .bytes()
                    .all(|b| (0x21..=0x7e).contains(&b) || b == b' ')
                || value
                    .get(..10)
                    .is_some_and(|p| p.eq_ignore_ascii_case("multipart/"))
            {
                return Err(MultipartError::Malformed);
            }
            content_type = Some(Zeroizing::new(value.to_owned()));
        } else {
            // Content-Transfer-Encoding and everything else.
            return Err(MultipartError::Malformed);
        }
    }
    let (name, filename) = disposition.ok_or(MultipartError::Malformed)?;
    if filename.is_none() && content_type.is_some() {
        return Err(MultipartError::Malformed);
    }
    Ok(PartHeader {
        name,
        filename,
        content_type,
    })
}

/// Validate a filename as metadata: UTF-8, no control characters, NFC,
/// ≤ [`MAX_FILENAME_BYTES`] bytes after normalisation. Empty means "no file
/// chosen" and is reported by the route, not here.
fn filename(raw: &str) -> Result<Zeroizing<String>, MultipartError> {
    if raw.len() > MAX_FILENAME_BYTES.saturating_mul(3) || raw.chars().any(|c| c.is_control()) {
        return Err(MultipartError::Malformed);
    }
    let mut out = Zeroizing::new(String::with_capacity(raw.len().saturating_mul(3)));
    for c in raw.nfc() {
        out.push(c);
    }
    if out.len() > MAX_FILENAME_BYTES {
        return Err(MultipartError::TooLarge);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    const B: &str = "----geckoformboundary1234";

    /// Feed `body` in pieces of `step` bytes; collect a readable trace.
    pub(crate) fn run(body: &[u8], step: usize) -> Result<Vec<String>, MultipartError> {
        let mut p = Multipart::new(B);
        let mut out = Vec::new();
        let mut file: Vec<u8> = Vec::new();
        let mut i = 0;
        loop {
            while let Some(ev) = p.next_event()? {
                match ev {
                    Event::Part(h) => {
                        out.push(format!(
                            "part {} {:?}",
                            h.name,
                            h.filename.as_deref().map(String::as_str)
                        ));
                        file.clear();
                    }
                    Event::Data(d) => file.extend_from_slice(&d),
                    Event::PartEnd => out.push(format!("end {}", String::from_utf8_lossy(&file))),
                    Event::End => out.push("close".into()),
                }
            }
            if i >= body.len() {
                break;
            }
            let n = step.min(body.len() - i).min(p.room());
            p.feed(&body[i..i + n])?;
            i += n;
        }
        p.finish()?;
        Ok(out)
    }

    fn body(parts: &[(&str, Option<&str>, &str)]) -> Vec<u8> {
        let mut s = String::new();
        for (name, file, val) in parts {
            s.push_str(&format!("--{B}\r\n"));
            match file {
                Some(f) => s.push_str(&format!(
                    "Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\nContent-Type: application/pdf\r\n\r\n"
                )),
                None => s.push_str(&format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n")),
            }
            s.push_str(val);
            s.push_str("\r\n");
        }
        s.push_str(&format!("--{B}--\r\n"));
        s.into_bytes()
    }

    #[test]
    fn browser_shape_any_feed_size() {
        let b = body(&[
            ("csrf", None, "tok"),
            (
                "file",
                Some("r\u{e9}port.pdf"),
                "%PDF-1.7 \r\n--not-the-boundary\r\n data",
            ),
            ("action", None, "upload"),
        ]);
        for step in [1, 2, 3, 7, 64, 4096, 1 << 20] {
            let t = run(&b, step).unwrap();
            assert_eq!(
                t,
                vec![
                    "part csrf None".to_owned(),
                    "end tok".into(),
                    "part file Some(\"r\u{e9}port.pdf\")".into(),
                    "end %PDF-1.7 \r\n--not-the-boundary\r\n data".into(),
                    "part action None".into(),
                    "end upload".into(),
                    "close".into(),
                ],
                "step {step}"
            );
        }
    }

    #[test]
    fn boundary_parsing() {
        assert_eq!(
            boundary_from_content_type(&format!("multipart/form-data; boundary={B}")).as_deref(),
            Some(B)
        );
        assert_eq!(
            boundary_from_content_type("multipart/form-data; boundary=\"ab\"").as_deref(),
            Some("ab")
        );
        assert!(boundary_from_content_type("multipart/form-data").is_none());
        assert!(boundary_from_content_type("multipart/mixed; boundary=a").is_none());
        assert!(boundary_from_content_type("multipart/form-data; boundary=a; x=y").is_none());
        assert!(
            boundary_from_content_type(&format!(
                "multipart/form-data; boundary={}",
                "a".repeat(71)
            ))
            .is_none()
        );
        assert!(boundary_from_content_type("multipart/form-data; boundary=").is_none());
        assert!(boundary_from_content_type("multipart/form-data; boundary=a\u{0}b").is_none());
    }

    #[test]
    fn hostile_shapes_rejected() {
        let ok = body(&[("csrf", None, "t")]);
        let mut cases: Vec<Vec<u8>> = Vec::new();
        // Preamble.
        cases.push([b"preamble\r\n".as_slice(), &ok].concat());
        // Trailing bytes after the close.
        cases.push([ok.as_slice(), b"x"].concat());
        cases.push([ok.as_slice(), b"\r\n"].concat());
        // Truncated (no close).
        cases.push(ok[..ok.len() - 10].to_vec());
        // Nested multipart.
        cases.push(format!("--{B}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a\"\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\nz\r\n--{B}--\r\n").into_bytes());
        // Content-Transfer-Encoding.
        cases.push(format!("--{B}\r\nContent-Disposition: form-data; name=\"csrf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nz\r\n--{B}--\r\n").into_bytes());
        // filename*, extra params, bad names, duplicate disposition.
        cases.push(format!("--{B}\r\nContent-Disposition: form-data; name=\"file\"; filename*=UTF-8''a\r\n\r\nz\r\n--{B}--\r\n").into_bytes());
        cases.push(
            format!(
                "--{B}\r\nContent-Disposition: form-data; name=\"Csrf\"\r\n\r\nz\r\n--{B}--\r\n"
            )
            .into_bytes(),
        );
        cases.push(
            format!(
                "--{B}\r\nContent-Disposition: attachment; name=\"csrf\"\r\n\r\nz\r\n--{B}--\r\n"
            )
            .into_bytes(),
        );
        cases.push(format!("--{B}\r\nContent-Disposition: form-data; name=\"csrf\"\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nz\r\n--{B}--\r\n").into_bytes());
        // Content-Type on a non-file part; control character in a filename.
        cases.push(format!("--{B}\r\nContent-Disposition: form-data; name=\"csrf\"\r\nContent-Type: text/plain\r\n\r\nz\r\n--{B}--\r\n").into_bytes());
        cases.push(format!("--{B}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a\u{1}b\"\r\n\r\nz\r\n--{B}--\r\n").into_bytes());
        // Header folding; garbage after the delimiter.
        cases.push(
            format!(
                "--{B}\r\nContent-Disposition: form-data;\r\n name=\"csrf\"\r\n\r\nz\r\n--{B}--\r\n"
            )
            .into_bytes(),
        );
        cases.push(
            format!("--{B}\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\nz\r\n--{B}xx")
                .into_bytes(),
        );
        for (i, c) in cases.iter().enumerate() {
            for step in [1, 5, 1 << 20] {
                assert!(run(c, step).is_err(), "case {i} step {step}");
            }
        }
    }

    #[test]
    fn limits() {
        // Five parts.
        let five: Vec<(&str, Option<&str>, &str)> = vec![("a", None, "1"); 5];
        assert_eq!(
            run(&body(&five), 1 << 20).unwrap_err(),
            MultipartError::TooManyParts
        );
        // Non-file value over the limit.
        let big = "x".repeat(MAX_PART_VALUE + 1);
        assert_eq!(
            run(&body(&[("csrf", None, &big)]), 1 << 20).unwrap_err(),
            MultipartError::TooLarge
        );
        // Filename over 255 bytes.
        let long = "n".repeat(MAX_FILENAME_BYTES + 1);
        assert!(run(&body(&[("file", Some(&long), "x")]), 1 << 20).is_err());
        // Header block over 1 KiB.
        let mut h = format!(
            "--{B}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a\"\r\nContent-Type: "
        );
        h.push_str(&"a".repeat(MAX_PART_HEADER));
        h.push_str("\r\n\r\nx\r\n");
        assert!(run(h.as_bytes(), 1 << 20).is_err());
        // Feeding more than the room is refused.
        let mut p = Multipart::new(B);
        assert_eq!(
            p.feed(&vec![0u8; BUF_CAP + 1]).unwrap_err(),
            MultipartError::TooLarge
        );
    }

    #[test]
    fn large_file_streams_in_chunks() {
        let data = "y".repeat(3 * UPLOAD_CHUNK + 17);
        let b = body(&[("csrf", None, "t"), ("file", Some("a.bin"), &data)]);
        let mut p = Multipart::new(B);
        let mut i = 0;
        let mut max_chunk = 0;
        let mut total = 0;
        loop {
            while let Some(ev) = p.next_event().unwrap() {
                if let Event::Data(d) = ev {
                    max_chunk = max_chunk.max(d.len());
                    total += d.len();
                }
            }
            if i == b.len() {
                break;
            }
            let n = 10_000.min(b.len() - i).min(p.room());
            p.feed(&b[i..i + n]).unwrap();
            i += n;
        }
        p.finish().unwrap();
        assert!(max_chunk <= UPLOAD_CHUNK);
        assert_eq!(total, data.len() + 1);
    }

    proptest::proptest! {
        /// ST-043: arbitrary bodies and feed sizes never panic, and the buffer
        /// never exceeds its capacity.
        #[test]
        fn total(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096), step in 1usize..512) {
            let _ = run(&data, step);
        }

        /// Any file content round-trips exactly, whatever the feed size.
        #[test]
        fn file_roundtrip(content in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..3000), step in 1usize..700) {
            let mut b = format!("--{B}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f\"\r\n\r\n").into_bytes();
            b.extend_from_slice(&content);
            b.extend_from_slice(format!("\r\n--{B}--\r\n").as_bytes());
            let mut p = Multipart::new(B);
            let mut got = Vec::new();
            let mut i = 0;
            let mut ok = true;
            loop {
                loop {
                    match p.next_event() {
                        Ok(Some(Event::Data(d))) => got.extend_from_slice(&d),
                        Ok(Some(_)) => {}
                        Ok(None) => break,
                        Err(_) => { ok = false; break; }
                    }
                }
                if !ok || i == b.len() { break; }
                let n = step.min(b.len() - i).min(p.room());
                p.feed(&b[i..i + n]).unwrap();
                i += n;
            }
            // Content containing the delimiter itself legitimately splits the
            // part; otherwise it must round-trip.
            let delim = format!("\r\n--{B}").into_bytes();
            if !content.windows(delim.len()).any(|w| w == delim.as_slice()) {
                proptest::prop_assert!(ok);
                proptest::prop_assert!(p.finish().is_ok());
                proptest::prop_assert_eq!(got, content);
            }
        }
    }
}
