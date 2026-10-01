// SPDX-License-Identifier: Apache-2.0 OR MIT
//! tar / tar.gz / gzip extraction.
//!
//! The tar crate is used in *raw* mode: GNU long-name and pax extension
//! headers are read here with explicit size bounds (the crate's own
//! handling buffers them without a bound). The gzip header's FNAME,
//! FCOMMENT and FEXTRA fields are never read (CVE-2026-35465).

use super::{ArchiveError, ExtractOptions, ExtractionReport, LimitKind, RejectReason, Session};
use crate::{DisplayName, SafeRoot};
use flate2::read::MultiGzDecoder;
use std::cell::Cell;
use std::io::{self, Read};
use std::rc::Rc;
use tar::{Archive, EntryType};

/// Maximum size of a pax extended header we accept.
const MAX_PAX_BYTES: u64 = 64 * 1024;
/// Per-entry header overhead allowance for the decompressed-stream cap
/// (header block, padding, possible extension header blocks).
const PER_ENTRY_OVERHEAD: u64 = 4 * 1024;

#[derive(Default)]
struct Meter {
    compressed_in: Cell<u64>,
    tripped: Cell<Option<LimitKind>>,
}

/// Counts raw (compressed) bytes consumed.
struct CountIn<R> {
    inner: R,
    meter: Rc<Meter>,
}

impl<R: Read> Read for CountIn<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        let m = &self.meter.compressed_in;
        m.set(m.get().saturating_add(u64::try_from(n).unwrap_or(u64::MAX)));
        Ok(n)
    }
}

/// Caps bytes produced by the (decompressed) stream and, for compressed
/// input, the running ratio produced / consumed. Counts every byte the tar
/// parser reads, including headers and the data of skipped members.
struct CapOut<R> {
    inner: R,
    meter: Rc<Meter>,
    produced: u64,
    cap: u64,
    ratio: Option<u64>,
}

impl<R: Read> Read for CapOut<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.meter.tripped.get().is_some() {
            return Err(io::Error::other("limit"));
        }
        let n = self.inner.read(buf)?;
        self.produced = self.produced.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        let mut hit = None;
        if self.produced > self.cap {
            hit = Some(LimitKind::TotalSize);
        } else if let Some(r) = self.ratio {
            let consumed = self.meter.compressed_in.get().max(1);
            if self.produced > consumed.saturating_mul(r) {
                hit = Some(LimitKind::Ratio);
            }
        }
        if let Some(k) = hit {
            self.meter.tripped.set(Some(k));
            return Err(io::Error::other("limit"));
        }
        Ok(n)
    }
}

fn stream_cap(s: &Session<'_>) -> u64 {
    let l = s.limits();
    l.max_total_uncompressed
        .saturating_add(l.max_entries.saturating_add(16).saturating_mul(PER_ENTRY_OVERHEAD))
        .saturating_add(2 * MAX_PAX_BYTES)
}

/// Extracts an uncompressed tar stream.
pub fn extract_tar<R: Read>(
    reader: R,
    root: &SafeRoot,
    opts: &ExtractOptions,
) -> Result<ExtractionReport, ArchiveError> {
    let mut s = Session::new(root, opts)?;
    let meter = Rc::new(Meter::default());
    let cap = stream_cap(&s);
    let src = CapOut { inner: reader, meter: Rc::clone(&meter), produced: 0, cap, ratio: None };
    let res = run_tar(src, &mut s, &meter);
    s.finish(res)
}

/// Extracts a gzip-compressed tar stream. The total ratio is enforced on
/// decompressed bytes vs compressed bytes actually consumed.
pub fn extract_tar_gz<R: Read>(
    reader: R,
    root: &SafeRoot,
    opts: &ExtractOptions,
) -> Result<ExtractionReport, ArchiveError> {
    let mut s = Session::new(root, opts)?;
    let meter = Rc::new(Meter::default());
    let cap = stream_cap(&s);
    let ratio = Some(s.limits().max_ratio);
    let gz = MultiGzDecoder::new(CountIn { inner: reader, meter: Rc::clone(&meter) });
    let src = CapOut { inner: gz, meter: Rc::clone(&meter), produced: 0, cap, ratio };
    let res = run_tar(src, &mut s, &meter);
    s.finish(res)
}

/// Decompresses a single gzip stream into one object. The header file name
/// is ignored entirely (never parsed into a name or path, CVE-2026-35465);
/// the member's display name is "(unnamed)".
pub fn extract_gzip<R: Read>(
    reader: R,
    root: &SafeRoot,
    opts: &ExtractOptions,
) -> Result<ExtractionReport, ArchiveError> {
    let mut s = Session::new(root, opts)?;
    let meter = Rc::new(Meter::default());
    let l = *s.limits();
    let gz = MultiGzDecoder::new(CountIn { inner: reader, meter: Rc::clone(&meter) });
    let mut src = CapOut {
        inner: gz,
        meter: Rc::clone(&meter),
        produced: 0,
        cap: l.max_entry_size.min(l.max_total_uncompressed),
        ratio: Some(l.max_ratio),
    };
    let res = (|| {
        s.count_entry()?;
        s.store_member(0, DisplayName::unnamed(), &mut src, None, &|_| Ok(()))
    })();
    let res = res.map_err(|e| tripped_or(&meter, e));
    s.finish(res)
}

fn tripped_or(meter: &Meter, e: ArchiveError) -> ArchiveError {
    match meter.tripped.get() {
        Some(k) => ArchiveError::LimitHit(k),
        None => e,
    }
}

/// Pending extension state for the next real entry.
#[derive(Default)]
struct Pending {
    name: Option<Result<Vec<u8>, RejectReason>>,
    sparse: bool,
    ext_headers: u64,
}

fn run_tar<R: Read>(src: R, s: &mut Session<'_>, meter: &Meter) -> Result<(), ArchiveError> {
    let mut ar = Archive::new(src);
    let res = run_tar_inner(&mut ar, s);
    res.map_err(|e| tripped_or(meter, e))
}

fn read_bounded<R: Read>(r: &mut R, size: u64, max: u64) -> Result<Option<Vec<u8>>, ArchiveError> {
    if size > max {
        return Ok(None);
    }
    let mut v = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
    r.take(size)
        .read_to_end(&mut v)
        .map_err(|_| ArchiveError::Malformed("extension header"))?;
    Ok(Some(v))
}

fn trim_nul(mut v: Vec<u8>) -> Vec<u8> {
    while v.last() == Some(&0) {
        v.pop();
    }
    v
}

/// Parses pax records `"<len> <key>=<value>\n"` strictly.
type PaxRecords<'a> = Vec<(&'a [u8], &'a [u8])>;

fn parse_pax(data: &[u8]) -> Result<PaxRecords<'_>, ArchiveError> {
    let bad = ArchiveError::Malformed("pax header");
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let sp = rest.iter().position(|&b| b == b' ').ok_or(ArchiveError::Malformed("pax header"))?;
        let len_txt = rest.get(..sp).ok_or(ArchiveError::Malformed("pax header"))?;
        if len_txt.is_empty() || len_txt.len() > 10 || !len_txt.iter().all(u8::is_ascii_digit) {
            return Err(bad);
        }
        let len: usize = std::str::from_utf8(len_txt)
            .ok()
            .and_then(|t| t.parse().ok())
            .ok_or(ArchiveError::Malformed("pax header"))?;
        let rec = rest.get(..len).ok_or(ArchiveError::Malformed("pax header"))?;
        if rec.last() != Some(&b'\n') {
            return Err(bad);
        }
        let body = rec
            .get(sp.saturating_add(1)..len.saturating_sub(1))
            .ok_or(ArchiveError::Malformed("pax header"))?;
        let eq = body.iter().position(|&b| b == b'=').ok_or(ArchiveError::Malformed("pax header"))?;
        let key = body.get(..eq).ok_or(ArchiveError::Malformed("pax header"))?;
        let val = body.get(eq.saturating_add(1)..).ok_or(ArchiveError::Malformed("pax header"))?;
        out.push((key, val));
        rest = rest.get(len..).ok_or(ArchiveError::Malformed("pax header"))?;
    }
    Ok(out)
}

fn run_tar_inner<R: Read>(ar: &mut Archive<R>, s: &mut Session<'_>) -> Result<(), ArchiveError> {
    let l = *s.limits();
    let max_ext_headers = l.max_entries.saturating_mul(3).saturating_add(16);
    let max_name = u64::try_from(l.max_path_bytes).unwrap_or(u64::MAX).saturating_add(1);
    let mut pending = Pending::default();
    let mut idx: u64 = 0;
    let entries = ar
        .entries()
        .map_err(|_| ArchiveError::Malformed("tar structure"))?
        .raw(true);
    for ent in entries {
        let mut ent = ent.map_err(|_| ArchiveError::Malformed("tar structure"))?;
        let et = ent.header().entry_type();
        let size = ent.header().entry_size().map_err(|_| ArchiveError::Malformed("tar size"))?;

        // Extension headers apply to the next entry.
        if et.is_gnu_longname() || et.is_gnu_longlink() || et.is_pax_local_extensions() || et.is_pax_global_extensions() {
            pending.ext_headers = pending.ext_headers.saturating_add(1);
            if pending.ext_headers > max_ext_headers {
                return Err(ArchiveError::LimitHit(LimitKind::Entries));
            }
            if et.is_gnu_longname() {
                if pending.name.is_some() {
                    return Err(ArchiveError::Malformed("repeated long name"));
                }
                pending.name = Some(match read_bounded(&mut ent, size, max_name)? {
                    Some(v) => Ok(trim_nul(v)),
                    None => Err(RejectReason::PathTooLong),
                });
            } else if et.is_gnu_longlink() {
                // Link target is irrelevant: link entries are rejected.
            } else {
                let data = read_bounded(&mut ent, size, MAX_PAX_BYTES)?
                    .ok_or(ArchiveError::LimitHit(LimitKind::HeaderSize))?;
                let global = et.is_pax_global_extensions();
                for (k, v) in parse_pax(&data)? {
                    match k {
                        b"size" => return Err(ArchiveError::Unsupported("pax size override")),
                        b"path" if global => {
                            return Err(ArchiveError::Unsupported("pax global path"));
                        }
                        b"path" => {
                            if pending.name.is_some() {
                                return Err(ArchiveError::Malformed("repeated long name"));
                            }
                            pending.name = Some(if v.len() > l.max_path_bytes {
                                Err(RejectReason::PathTooLong)
                            } else {
                                Ok(v.to_vec())
                            });
                        }
                        k if k.starts_with(b"GNU.sparse.") => pending.sparse = true,
                        _ => {}
                    }
                }
            }
            continue;
        }

        // A real entry.
        s.count_entry()?;
        let this_idx = idx;
        idx = idx.saturating_add(1);
        let pend = std::mem::take(&mut pending);
        let raw_name: Vec<u8> = match pend.name {
            Some(Ok(n)) => n,
            Some(Err(r)) => {
                s.reject(this_idx, b"", r);
                continue;
            }
            None => ent.path_bytes().into_owned(),
        };
        let key = match super::check_member_path(&raw_name, &l) {
            Ok(k) => k,
            Err(r) => {
                s.reject(this_idx, &raw_name, r);
                continue;
            }
        };
        let reason = match et {
            EntryType::Regular | EntryType::Continuous if pend.sparse => Some(RejectReason::Sparse),
            EntryType::Regular | EntryType::Continuous => None,
            EntryType::Directory => continue,
            EntryType::Symlink => Some(RejectReason::Symlink),
            EntryType::Link => Some(RejectReason::Hardlink),
            EntryType::Char | EntryType::Block | EntryType::Fifo => Some(RejectReason::DeviceOrSpecial),
            EntryType::GNUSparse => Some(RejectReason::Sparse),
            _ => Some(RejectReason::UnsupportedEntryType),
        };
        if let Some(r) = reason {
            s.reject(this_idx, &raw_name, r);
            continue;
        }
        if !s.first_use(key) {
            s.reject(this_idx, &raw_name, RejectReason::DuplicateName);
            continue;
        }
        s.store_member(
            this_idx,
            DisplayName::from_bytes_lossy(&raw_name),
            &mut ent,
            None,
            &|_| Ok(()),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pax_parser() {
        let ok = b"20 path=a/b/c.txt\n\n11 x=yz\n";
        // first record length 20 covers "20 path=a/b/c.txt\n\n"? build properly:
        let rec1 = b"17 path=a/b/c.tx\n";
        assert_eq!(rec1.len(), 17);
        let v = parse_pax(rec1).ok().unwrap_or_default();
        assert_eq!(v, vec![(&b"path"[..], &b"a/b/c.tx"[..])]);
        assert!(parse_pax(ok).is_err());
        for bad in [&b"x path=a\n"[..], b"99 path=a\n", b"5 a\n", b"0 \n", b"9 path=ab"] {
            assert!(parse_pax(bad).is_err());
        }
    }
}
