// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded archive extraction into a [`SafeRoot`] (10 §9 ARCHIVE_EXTRACT,
//! §10 limits, FILE-019, FILE-020, ST-081).
//!
//! * Members are stored under random [`ObjectId`]s; member names become
//!   [`DisplayName`] metadata only (ADR-027).
//! * Limits are enforced on bytes actually produced by the decompressor,
//!   never on declared sizes.
//! * Extraction is never recursive: members that look like archives are
//!   flagged ([`ExtractedMember::nested_archive`]); the caller may extract
//!   them explicitly with `nesting_level + 1`, bounded by
//!   [`ArchiveLimits::max_nesting_depth`].
//! * On any archive-level failure every member already written is removed
//!   (all-or-nothing) and no partial report is returned.
#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "candor-safefs is the single audited safe-path API (ADR-027); every path/fd operation here is reviewed"
)]

mod tar_impl;
mod zip_impl;

pub use tar_impl::{extract_gzip, extract_tar, extract_tar_gz};
pub use zip_impl::extract_zip;

use crate::{DisplayName, ObjectId, SafeFsError, SafeRoot, SlotTime};
use std::collections::HashSet;
use std::fmt;
use std::io::{self, Read, Write};
use unicode_normalization::UnicodeNormalization;

const GIB: u64 = 1 << 30;
const COPY_BUF: usize = 64 * 1024;
const SNIFF_LEN: usize = 512;

/// Archive limits (10 §10, profile `LP-DEFAULT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveLimits {
    /// Maximum number of entries (members, directories, links...).
    pub max_entries: u64,
    /// Maximum total uncompressed bytes of all extracted members.
    pub max_total_uncompressed: u64,
    /// Maximum uncompressed bytes of a single member.
    pub max_entry_size: u64,
    /// Maximum compression ratio, per member (zip) and total (`N` means N:1).
    pub max_ratio: u64,
    /// Maximum archive nesting depth (a top-level archive is level 1).
    pub max_nesting_depth: u32,
    /// Maximum member path length in bytes.
    pub max_path_bytes: usize,
    /// Maximum member path component count.
    pub max_path_components: usize,
}

impl ArchiveLimits {
    /// `LP-DEFAULT` from 10 §10.
    pub const DEFAULT: Self = Self {
        max_entries: 10_000,
        max_total_uncompressed: 4 * GIB,
        max_entry_size: 4 * GIB,
        max_ratio: 100,
        max_nesting_depth: 3,
        max_path_bytes: 1024,
        max_path_components: 32,
    };

    /// Hard ceilings from 10 §10; no configuration may exceed them.
    pub const HARD_CEILING: Self = Self {
        max_entries: 100_000,
        max_total_uncompressed: 32 * GIB,
        max_entry_size: 32 * GIB,
        max_ratio: 1000,
        max_nesting_depth: 5,
        max_path_bytes: 1024,
        max_path_components: 32,
    };

    /// Checks every limit is ≥ 1 and ≤ its hard ceiling.
    pub fn validate(&self) -> Result<(), ArchiveError> {
        let c = Self::HARD_CEILING;
        let ok = (1..=c.max_entries).contains(&self.max_entries)
            && (1..=c.max_total_uncompressed).contains(&self.max_total_uncompressed)
            && (1..=c.max_entry_size).contains(&self.max_entry_size)
            && (1..=c.max_ratio).contains(&self.max_ratio)
            && (1..=c.max_nesting_depth).contains(&self.max_nesting_depth)
            && (1..=c.max_path_bytes).contains(&self.max_path_bytes)
            && (1..=c.max_path_components).contains(&self.max_path_components);
        if ok {
            Ok(())
        } else {
            Err(ArchiveError::InvalidLimits)
        }
    }
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Options for one extraction call.
#[derive(Debug, Clone, Copy)]
pub struct ExtractOptions {
    /// Limits (validated against [`ArchiveLimits::HARD_CEILING`]).
    pub limits: ArchiveLimits,
    /// Nesting level of the archive being extracted: 1 for an archive that
    /// is itself an ORIGINAL; `n + 1` for a member of a level-`n` archive.
    pub nesting_level: u32,
    /// Timestamp written to every extracted object (ADR-038(1)).
    pub slot: SlotTime,
}

impl ExtractOptions {
    /// Default limits, level 1.
    pub fn new(slot: SlotTime) -> Self {
        Self {
            limits: ArchiveLimits::DEFAULT,
            nesting_level: 1,
            slot,
        }
    }

    fn check(&self) -> Result<(), ArchiveError> {
        self.limits.validate()?;
        if self.nesting_level == 0 || self.nesting_level > self.limits.max_nesting_depth {
            return Err(ArchiveError::LimitHit(LimitKind::NestingDepth));
        }
        Ok(())
    }
}

/// Which limit was hit (`LIMIT_HIT` flag, FILE-020).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LimitKind {
    /// Too many entries.
    Entries,
    /// Total uncompressed bytes exceeded.
    TotalSize,
    /// A member exceeded the per-entry size.
    EntrySize,
    /// Compression ratio exceeded.
    Ratio,
    /// Nesting depth exceeded.
    NestingDepth,
    /// An extension header (tar pax / GNU long name) is too large.
    HeaderSize,
}

/// Archive-level failure. The whole extraction is rolled back.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArchiveError {
    /// Limits outside the permitted range.
    InvalidLimits,
    /// A resource limit was hit (`LIMIT_HIT`).
    LimitHit(LimitKind),
    /// ZIP local headers / data ranges overlap (Fifield bomb, B-CR-52).
    OverlappingEntries,
    /// Structurally invalid archive (parser error, CRC mismatch, central /
    /// local header disagreement, ...).
    Malformed(&'static str),
    /// A construct this extractor refuses at archive level.
    Unsupported(&'static str),
    /// Storage error.
    Store(SafeFsError),
    /// The archive failed and removing the members already stored failed
    /// too (AUD-RM1-SFS-05): the listed objects are still in the root. The
    /// caller must remove them (retry [`crate::SafeRoot::remove`]) or
    /// destroy the scratch root; nothing may treat them as extracted.
    RollbackIncomplete(Vec<ObjectId>),
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => f.write_str("invalid archive limits"),
            Self::LimitHit(k) => write!(f, "archive limit hit: {k:?}"),
            Self::OverlappingEntries => f.write_str("overlapping zip entries"),
            Self::Malformed(r) => write!(f, "malformed archive: {r}"),
            Self::Unsupported(r) => write!(f, "unsupported archive construct: {r}"),
            Self::Store(e) => write!(f, "store error: {e}"),
            Self::RollbackIncomplete(ids) => {
                write!(
                    f,
                    "archive rollback incomplete: {} member(s) left",
                    ids.len()
                )
            }
        }
    }
}

impl std::error::Error for ArchiveError {}

impl From<SafeFsError> for ArchiveError {
    fn from(e: SafeFsError) -> Self {
        Self::Store(e)
    }
}

/// Why a single member was rejected (flagged, not extracted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectReason {
    /// Empty name (or only `.`/separators).
    EmptyName,
    /// NUL byte in name.
    NulInName,
    /// Absolute path, drive letter or UNC prefix.
    AbsolutePath,
    /// `..` component.
    ParentTraversal,
    /// Name longer than the limit.
    PathTooLong,
    /// Too many path components.
    TooManyComponents,
    /// Symbolic link.
    Symlink,
    /// Hard link.
    Hardlink,
    /// Device, FIFO, socket or other special file.
    DeviceOrSpecial,
    /// Duplicate name after NFC normalization.
    DuplicateName,
    /// Encrypted member (password only inside L2, 10 §9.5).
    Encrypted,
    /// Compression method not supported (only stored/deflate).
    UnsupportedCompression,
    /// Sparse file.
    Sparse,
    /// Any other entry type.
    UnsupportedEntryType,
}

/// A member stored in the root. `Debug` omits the size (P-07,
/// AUD-RM1-SFS-04).
#[derive(Clone)]
pub struct ExtractedMember {
    /// Position in the archive (0-based entry index).
    pub index: u64,
    /// Generated storage id (never derived from the member name).
    pub id: ObjectId,
    /// Sanitized display-only name.
    pub display_name: DisplayName,
    /// Bytes actually produced.
    pub size: u64,
    /// The member looks like an archive or compressed stream; it was NOT
    /// extracted. Extract explicitly with `nesting_level + 1` if wanted.
    pub nested_archive: bool,
}

/// A member that was rejected and flagged.
#[derive(Debug, Clone)]
pub struct RejectedMember {
    /// Position in the archive.
    pub index: u64,
    /// Sanitized display-only name.
    pub display_name: DisplayName,
    /// Reason.
    pub reason: RejectReason,
}

impl fmt::Debug for ExtractedMember {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtractedMember")
            .field("index", &self.index)
            .field("id", &self.id)
            .field("display_name", &self.display_name)
            .field("nested_archive", &self.nested_archive)
            .finish_non_exhaustive()
    }
}

/// Result of a successful extraction. `Debug` omits sizes (P-07,
/// AUD-RM1-SFS-04).
#[derive(Clone, Default)]
pub struct ExtractionReport {
    /// Extracted members.
    pub members: Vec<ExtractedMember>,
    /// Rejected (flagged) members.
    pub rejected: Vec<RejectedMember>,
    /// Total uncompressed bytes stored.
    pub total_bytes: u64,
}

impl fmt::Debug for ExtractionReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtractionReport")
            .field("members", &self.members)
            .field("rejected", &self.rejected)
            .finish_non_exhaustive()
    }
}

/// Validates a member name and returns its duplicate-detection key
/// (NFC, separators unified, empty and `.` components dropped).
pub(crate) fn check_member_path(raw: &[u8], l: &ArchiveLimits) -> Result<String, RejectReason> {
    if raw.is_empty() {
        return Err(RejectReason::EmptyName);
    }
    if raw.len() > l.max_path_bytes {
        return Err(RejectReason::PathTooLong);
    }
    if raw.contains(&0) {
        return Err(RejectReason::NulInName);
    }
    let s: String = String::from_utf8_lossy(raw).nfc().collect();
    let b = s.as_bytes();
    if matches!(b.first(), Some(b'/' | b'\\')) {
        return Err(RejectReason::AbsolutePath);
    }
    if let (Some(d), Some(b':')) = (b.first(), b.get(1))
        && d.is_ascii_alphabetic()
    {
        return Err(RejectReason::AbsolutePath);
    }
    let mut comps: Vec<&str> = Vec::new();
    for c in s.split(['/', '\\']) {
        match c {
            "" | "." => {}
            ".." => return Err(RejectReason::ParentTraversal),
            c => comps.push(c),
        }
    }
    if comps.is_empty() {
        return Err(RejectReason::EmptyName);
    }
    if comps.len() > l.max_path_components {
        return Err(RejectReason::TooManyComponents);
    }
    Ok(comps.join("/"))
}

/// Magic-byte sniff for nested archives / compressed streams.
pub(crate) fn looks_like_archive(head: &[u8]) -> bool {
    const MAGICS: &[&[u8]] = &[
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"PK\x07\x08",
        b"\x1f\x8b",
        b"BZh",
        b"\xfd7zXZ\x00",
        b"\x28\xb5\x2f\xfd",
        b"7z\xbc\xaf\x27\x1c",
        b"Rar!\x1a\x07",
        b"MSCF",
        b"\x60\xea", // ARJ
        b"LZIP",
    ];
    if MAGICS.iter().any(|m| head.starts_with(m)) {
        return true;
    }
    matches!(head.get(257..262), Some(b"ustar"))
}

/// Shared bookkeeping for one extraction.
pub(crate) struct Session<'a> {
    pub(crate) root: &'a SafeRoot,
    pub(crate) opts: ExtractOptions,
    pub(crate) report: ExtractionReport,
    pub(crate) entries: u64,
    seen: HashSet<String>,
}

impl<'a> Session<'a> {
    pub(crate) fn new(root: &'a SafeRoot, opts: &ExtractOptions) -> Result<Self, ArchiveError> {
        opts.check()?;
        Ok(Self {
            root,
            opts: *opts,
            report: ExtractionReport::default(),
            entries: 0,
            seen: HashSet::new(),
        })
    }

    pub(crate) fn limits(&self) -> &ArchiveLimits {
        &self.opts.limits
    }

    /// Counts one entry against `max_entries`.
    pub(crate) fn count_entry(&mut self) -> Result<(), ArchiveError> {
        self.entries = self.entries.saturating_add(1);
        if self.entries > self.opts.limits.max_entries {
            return Err(ArchiveError::LimitHit(LimitKind::Entries));
        }
        Ok(())
    }

    pub(crate) fn reject(&mut self, index: u64, raw_name: &[u8], reason: RejectReason) {
        self.report.rejected.push(RejectedMember {
            index,
            display_name: DisplayName::from_bytes_lossy(raw_name),
            reason,
        });
    }

    /// Registers a dedup key; false if already seen.
    pub(crate) fn first_use(&mut self, key: String) -> bool {
        self.seen.insert(key)
    }

    /// Streams one member into the store, enforcing per-entry size, total
    /// size and (if `compressed` is given) the per-member ratio, plus the
    /// caller's `extra` check on the running total.
    pub(crate) fn store_member<R: Read>(
        &mut self,
        index: u64,
        display_name: DisplayName,
        src: &mut R,
        compressed: Option<u64>,
        extra: &dyn Fn(u64) -> Result<(), ArchiveError>,
    ) -> Result<(), ArchiveError> {
        let l = self.opts.limits;
        let mut w = self.root.create_random()?;
        let mut buf = vec![0u8; COPY_BUF];
        let mut head: Vec<u8> = Vec::with_capacity(SNIFF_LEN);
        let mut produced: u64 = 0;
        loop {
            let n = match src.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(ArchiveError::Malformed("member data")),
            };
            let chunk = buf
                .get(..n)
                .ok_or(ArchiveError::Malformed("reader overrun"))?;
            produced = produced.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
            if produced > l.max_entry_size {
                return Err(ArchiveError::LimitHit(LimitKind::EntrySize));
            }
            let total = self.report.total_bytes.saturating_add(produced);
            if total > l.max_total_uncompressed {
                return Err(ArchiveError::LimitHit(LimitKind::TotalSize));
            }
            if let Some(c) = compressed
                && produced > c.saturating_mul(l.max_ratio)
            {
                return Err(ArchiveError::LimitHit(LimitKind::Ratio));
            }
            extra(total)?;
            if head.len() < SNIFF_LEN {
                let take = SNIFF_LEN.saturating_sub(head.len()).min(chunk.len());
                head.extend_from_slice(chunk.get(..take).unwrap_or(&[]));
            }
            w.write_all(chunk).map_err(|e| {
                if e.kind() == io::ErrorKind::InvalidData {
                    ArchiveError::LimitHit(LimitKind::EntrySize)
                } else {
                    ArchiveError::Store(SafeFsError::Io(e.kind()))
                }
            })?;
        }
        let id = w.commit(self.opts.slot)?;
        self.report.total_bytes = self.report.total_bytes.saturating_add(produced);
        self.report.members.push(ExtractedMember {
            index,
            id,
            display_name,
            size: produced,
            nested_archive: looks_like_archive(&head),
        });
        Ok(())
    }

    /// Finishes: on error removes every member written (all-or-nothing).
    pub(crate) fn finish(
        self,
        res: Result<(), ArchiveError>,
    ) -> Result<ExtractionReport, ArchiveError> {
        match res {
            Ok(()) => Ok(self.report),
            Err(e) => {
                let left: Vec<ObjectId> = self
                    .report
                    .members
                    .iter()
                    .filter(|m| {
                        !matches!(
                            self.root.remove(&m.id, self.opts.slot),
                            Ok(()) | Err(SafeFsError::NotFound)
                        )
                    })
                    .map(|m| m.id)
                    .collect();
                if left.is_empty() {
                    Err(e)
                } else {
                    Err(ArchiveError::RollbackIncomplete(left))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_rules() {
        let l = ArchiveLimits::DEFAULT;
        use RejectReason::*;
        for (n, r) in [
            (&b""[..], EmptyName),
            (b"./", EmptyName),
            (b"/etc/passwd", AbsolutePath),
            (b"\\\\server\\share", AbsolutePath),
            (b"C:\\x", AbsolutePath),
            (b"c:x", AbsolutePath),
            (b"../x", ParentTraversal),
            (b"a/../../x", ParentTraversal),
            (b"a\\..\\x", ParentTraversal),
            (b"a\0b", NulInName),
        ] {
            assert_eq!(check_member_path(n, &l), Err(r), "{n:?}");
        }
        assert_eq!(check_member_path(&[b'a'; 1025], &l), Err(PathTooLong));
        assert_eq!(
            check_member_path("a/".repeat(33).as_bytes(), &l),
            Err(TooManyComponents)
        );
        assert_eq!(
            check_member_path(b"a//./b", &l).ok().as_deref(),
            Some("a/b")
        );
        // NFC: decomposed and composed forms collide.
        assert_eq!(
            check_member_path("e\u{301}".as_bytes(), &l),
            check_member_path("\u{e9}".as_bytes(), &l)
        );
    }

    // AUD-RM1-SFS-05 regression: a rollback that cannot remove a stored
    // member reports the leftover ids instead of the bare archive error.
    #[test]
    fn incomplete_rollback_is_reported() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = SafeRoot::open(dir.path(), crate::RootPolicy::Scratch).unwrap();
        let slot = SlotTime::from_unix_secs(1_800_000_000).unwrap();
        let opts = ExtractOptions::new(slot);
        let mut s = Session::new(&root, &opts).unwrap();
        // A "member" whose entry cannot be unlinked (a directory).
        let stuck = ObjectId::random().unwrap();
        std::fs::create_dir(dir.path().join(stuck.to_name())).unwrap();
        s.report.members.push(ExtractedMember {
            index: 0,
            id: stuck,
            display_name: DisplayName::unnamed(),
            size: 1,
            nested_archive: false,
        });
        let res = s.finish(Err(ArchiveError::Malformed("x")));
        assert!(
            matches!(&res, Err(ArchiveError::RollbackIncomplete(ids)) if ids == &vec![stuck]),
            "rollback leftovers not reported"
        );
    }

    #[test]
    fn limits_validation() {
        assert!(ArchiveLimits::DEFAULT.validate().is_ok());
        assert!(ArchiveLimits::HARD_CEILING.validate().is_ok());
        let mut l = ArchiveLimits::DEFAULT;
        l.max_ratio = 1001;
        assert!(l.validate().is_err());
        l = ArchiveLimits::DEFAULT;
        l.max_nesting_depth = 6;
        assert!(l.validate().is_err());
        l = ArchiveLimits::DEFAULT;
        l.max_entries = 0;
        assert!(l.validate().is_err());
    }
}
