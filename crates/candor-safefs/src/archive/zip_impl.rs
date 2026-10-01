// SPDX-License-Identifier: Apache-2.0 OR MIT
//! ZIP extraction with Fifield overlap detection (B-CR-52) and
//! central/local header cross-checks.

use super::{ArchiveError, ExtractOptions, ExtractionReport, LimitKind, RejectReason, Session};
use crate::{DisplayName, SafeRoot};
use std::io::{Read, Seek, SeekFrom};
use zip::{CompressionMethod, ZipArchive};

const LOCAL_SIG: u32 = 0x0403_4b50;
const LOCAL_FIXED: u64 = 30;
const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;

struct Info {
    header_start: u64,
    data_start: u64,
    csize: u64,
    name: Vec<u8>,
    is_dir: bool,
    mode: Option<u32>,
    encrypted: bool,
    method: CompressionMethod,
}

fn malformed<E>(_: E) -> ArchiveError {
    ArchiveError::Malformed("zip structure")
}

/// Extracts a ZIP archive into `root` (FILE-019, ST-081).
///
/// Archive-level refusals: entry count over limit (checked before reading
/// any member), overlapping local-header/data ranges (Fifield), central and
/// local header name/offset disagreement, data beyond end of file, CRC
/// errors, any §10 limit hit. Member-level refusals are flagged in
/// [`ExtractionReport::rejected`].
pub fn extract_zip<R: Read + Seek>(
    mut reader: R,
    root: &SafeRoot,
    opts: &ExtractOptions,
) -> Result<ExtractionReport, ArchiveError> {
    let mut s = Session::new(root, opts)?;
    let res = run(&mut reader, &mut s);
    s.finish(res)
}

fn run<R: Read + Seek>(reader: &mut R, s: &mut Session<'_>) -> Result<(), ArchiveError> {
    let l = *s.limits();
    let archive_len = reader.seek(SeekFrom::End(0)).map_err(malformed)?;
    reader.seek(SeekFrom::Start(0)).map_err(malformed)?;

    // Pass 1: central directory scan (no member data read).
    let infos = {
        let mut za = ZipArchive::new(&mut *reader).map_err(malformed)?;
        let n = za.len();
        if u64::try_from(n).unwrap_or(u64::MAX) > l.max_entries {
            return Err(ArchiveError::LimitHit(LimitKind::Entries));
        }
        let mut v = Vec::with_capacity(n);
        for i in 0..n {
            let f = za.by_index_raw(i).map_err(malformed)?;
            v.push(Info {
                header_start: f.header_start(),
                data_start: f.data_start(),
                csize: f.compressed_size(),
                name: f.name_raw().to_vec(),
                is_dir: f.is_dir(),
                mode: f.unix_mode(),
                encrypted: f.encrypted(),
                method: f.compression(),
            });
        }
        v
    };

    // Pass 2: overlap check (Fifield). Each entry occupies
    // [header_start, data_start + csize); ranges must be disjoint and
    // inside the file.
    let mut ranges: Vec<(u64, u64)> = Vec::with_capacity(infos.len());
    for inf in &infos {
        let min_data = inf
            .header_start
            .checked_add(LOCAL_FIXED)
            .ok_or(ArchiveError::Malformed("offset overflow"))?;
        if inf.data_start < min_data {
            return Err(ArchiveError::OverlappingEntries);
        }
        let end = inf
            .data_start
            .checked_add(inf.csize)
            .ok_or(ArchiveError::Malformed("offset overflow"))?;
        if end > archive_len {
            return Err(ArchiveError::Malformed("member beyond end of file"));
        }
        ranges.push((inf.header_start, end));
    }
    ranges.sort_unstable();
    for w in ranges.windows(2) {
        if let [a, b] = w {
            if b.0 < a.1 {
                return Err(ArchiveError::OverlappingEntries);
            }
        }
    }

    // Pass 3: local header must agree with the central directory (name and
    // data offset), defeating parser-differential name smuggling.
    for inf in &infos {
        reader.seek(SeekFrom::Start(inf.header_start)).map_err(malformed)?;
        let mut fixed = [0u8; 30];
        reader.read_exact(&mut fixed).map_err(malformed)?;
        let sig = u32::from_le_bytes([fixed[0], fixed[1], fixed[2], fixed[3]]);
        let name_len = u64::from(u16::from_le_bytes([fixed[26], fixed[27]]));
        let extra_len = u64::from(u16::from_le_bytes([fixed[28], fixed[29]]));
        if sig != LOCAL_SIG {
            return Err(ArchiveError::Malformed("bad local header signature"));
        }
        if u64::try_from(inf.name.len()).unwrap_or(u64::MAX) != name_len {
            return Err(ArchiveError::Malformed("local/central name mismatch"));
        }
        let mut name = vec![0u8; inf.name.len()];
        reader.read_exact(&mut name).map_err(malformed)?;
        if name != inf.name {
            return Err(ArchiveError::Malformed("local/central name mismatch"));
        }
        let expect = inf
            .header_start
            .checked_add(LOCAL_FIXED)
            .and_then(|v| v.checked_add(name_len))
            .and_then(|v| v.checked_add(extra_len));
        if expect != Some(inf.data_start) {
            return Err(ArchiveError::Malformed("local header offset mismatch"));
        }
    }
    reader.seek(SeekFrom::Start(0)).map_err(malformed)?;

    // Pass 4: extraction.
    let mut za = ZipArchive::new(&mut *reader).map_err(malformed)?;
    let total_ratio_cap = archive_len.saturating_mul(l.max_ratio);
    let extra = move |total: u64| {
        if total > total_ratio_cap {
            Err(ArchiveError::LimitHit(LimitKind::Ratio))
        } else {
            Ok(())
        }
    };
    for (i, inf) in infos.iter().enumerate() {
        s.count_entry()?;
        let idx = u64::try_from(i).unwrap_or(u64::MAX);
        let key = match super::check_member_path(&inf.name, &l) {
            Ok(k) => k,
            Err(r) => {
                s.reject(idx, &inf.name, r);
                continue;
            }
        };
        let ftype = inf.mode.map(|m| m & S_IFMT);
        if ftype == Some(S_IFLNK) {
            s.reject(idx, &inf.name, RejectReason::Symlink);
            continue;
        }
        if inf.is_dir || ftype == Some(S_IFDIR) {
            continue; // directories are implicit; nothing is created
        }
        if !matches!(ftype, None | Some(0) | Some(S_IFREG)) {
            s.reject(idx, &inf.name, RejectReason::DeviceOrSpecial);
            continue;
        }
        if inf.encrypted {
            s.reject(idx, &inf.name, RejectReason::Encrypted);
            continue;
        }
        if !matches!(inf.method, CompressionMethod::Stored | CompressionMethod::Deflated) {
            s.reject(idx, &inf.name, RejectReason::UnsupportedCompression);
            continue;
        }
        if !s.first_use(key) {
            s.reject(idx, &inf.name, RejectReason::DuplicateName);
            continue;
        }
        let mut f = za.by_index(i).map_err(malformed)?;
        s.store_member(
            idx,
            DisplayName::from_bytes_lossy(&inf.name),
            &mut f,
            Some(inf.csize),
            &extra,
        )?;
    }
    Ok(())
}
