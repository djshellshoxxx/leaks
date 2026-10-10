// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared oracles for the candor-safefs fuzz targets (ST-048, ST-049).
//!
//! Harness code, not product code: it uses `std::fs` directly (outside the
//! `crates/*/src` scope of `scripts/lint-safefs.sh`) to build the
//! containment oracle independently of the code under test. Panics here are
//! findings, by design.
#![allow(dead_code)] // each target uses a subset

use candor_safefs::archive::{ArchiveError, ArchiveLimits, ExtractOptions, ExtractionReport};
use candor_safefs::{DisplayName, MAX_DISPLAY_NAME_BYTES, RootPolicy, SafeRoot, SlotTime};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

/// Small limits so each input runs fast and limit enforcement is reachable.
const LIMITS: ArchiveLimits = ArchiveLimits {
    max_entries: 64,
    max_total_uncompressed: 1 << 20,
    max_entry_size: 256 << 10,
    max_ratio: 100,
    max_nesting_depth: 3,
    max_path_bytes: 1024,
    max_path_components: 32,
};

/// Private per-process base path: `<tmp>/candor-safefs-fuzz-<pid>`. It is
/// created (mode 0700, failing if it already exists) for every input, must
/// contain nothing but the per-input root afterwards, and is removed again,
/// so no residue is left between inputs or after a clean run.
fn base() -> &'static Path {
    static BASE: OnceLock<PathBuf> = OnceLock::new();
    BASE.get_or_init(|| {
        let tmp = std::env::temp_dir()
            .canonicalize()
            .expect("temp dir resolves");
        tmp.join(format!("candor-safefs-fuzz-{}", std::process::id()))
    })
}

/// Checks every documented `DisplayName` guarantee plus the containment
/// property: as a path it is exactly one normal component.
pub fn check_display_name(n: &DisplayName) {
    let s = n.as_str();
    assert!(!s.is_empty());
    assert!(s.len() <= MAX_DISPLAY_NAME_BYTES);
    assert!(!s.chars().all(|c| c == '.'));
    // Fullwidth/compatibility dots never yield "." / ".." after NFKC-ish
    // folding: such names are rendered with U+2024 only.
    assert!(s != "\u{FF0E}" && s != "\u{FF0E}\u{FF0E}");
    for c in s.chars() {
        assert!(!c.is_control(), "control char survived");
        assert!(!matches!(c, '/' | '\\' | ':' | '\0'));
        assert!(!matches!(
            c,
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}' | '\u{2028}' | '\u{2029}'
        ));
        // AUD-RM1-SFS-02: no invisible / blank-looking characters, and no
        // whitespace other than single ASCII spaces.
        assert!(!matches!(
            c,
            '\u{00AD}' | '\u{034F}' | '\u{115F}' | '\u{1160}' | '\u{180B}'..='\u{180F}'
                | '\u{200B}'..='\u{200D}' | '\u{2060}'..='\u{206F}' | '\u{2800}'
                | '\u{3164}' | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}' | '\u{FFA0}'
                | '\u{FFF9}'..='\u{FFFB}' | '\u{E0000}'..='\u{E0FFF}'
                | '\u{E000}'..='\u{F8FF}'
        ), "invisible char survived");
        assert!(c == ' ' || !c.is_whitespace(), "non-space whitespace survived");
    }
    assert!(!s.contains("  ") && !s.starts_with(' ') && !s.ends_with(' '));
    let mut comps = Path::new(s).components();
    assert!(matches!(comps.next(), Some(Component::Normal(_))));
    assert!(comps.next().is_none());
}

/// Recursively checks that `dir` holds only 0700 directories and 0600
/// single-link regular files owned by us (no symlinks, devices, FIFOs,
/// sockets, hard links, setuid/setgid/sticky or exec bits on files).
fn check_tree(dir: &Path, uid: u32, depth: u32) {
    assert!(depth <= 4, "unexpected directory depth");
    for e in fs::read_dir(dir).expect("read_dir") {
        let e = e.expect("dir entry");
        let md = fs::symlink_metadata(e.path()).expect("lstat");
        let ft = md.file_type();
        assert_eq!(md.uid(), uid, "foreign owner");
        if ft.is_dir() {
            assert_eq!(md.mode() & 0o7777, 0o700, "directory mode");
            check_tree(&e.path(), uid, depth + 1);
        } else {
            assert!(ft.is_file(), "non-regular entry created");
            assert_eq!(md.mode() & 0o7777, 0o600, "file mode");
            assert_eq!(md.nlink(), 1, "hard link created");
        }
    }
}

fn check_report(root: &SafeRoot, r: &ExtractionReport) {
    let l = LIMITS;
    let n = (r.members.len() as u64).saturating_add(r.rejected.len() as u64);
    assert!(n <= l.max_entries, "entry limit exceeded");
    assert!(
        r.total_bytes <= l.max_total_uncompressed,
        "total limit exceeded"
    );
    let mut sum: u64 = 0;
    for m in &r.members {
        assert!(m.size <= l.max_entry_size, "entry size limit exceeded");
        sum = sum.checked_add(m.size).expect("size sum overflow");
        check_display_name(&m.display_name);
        let data = root
            .read_to_vec(&m.id, l.max_entry_size)
            .expect("reported member is stored");
        assert_eq!(data.len() as u64, m.size, "stored size mismatch");
    }
    for m in &r.rejected {
        check_display_name(&m.display_name);
    }
    assert_eq!(sum, r.total_bytes, "total_bytes mismatch");
}

/// Runs one extraction in a fresh private root and applies the containment
/// oracle, then removes the root.
pub fn extract_and_check(
    f: impl FnOnce(&SafeRoot, &ExtractOptions) -> Result<ExtractionReport, ArchiveError>,
) {
    let base = base();
    // create (not create_all): never reuse a directory someone else prepared.
    fs::DirBuilder::new()
        .mode(0o700)
        .create(base)
        .expect("create private fuzz base dir");
    let root_path = base.join("root");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&root_path)
        .expect("create per-input root");
    let uid = fs::symlink_metadata(&root_path).expect("lstat root").uid();
    {
        let root = SafeRoot::open(&root_path, RootPolicy::Scratch).expect("open root");
        let slot = SlotTime::from_unix_secs(0).expect("aligned slot");
        let mut opts = ExtractOptions::new(slot);
        opts.limits = LIMITS;
        if let Ok(report) = f(&root, &opts) {
            check_report(&root, &report);
        }
        // Containment: the base holds only the root, whatever the outcome.
        let names: Vec<_> = fs::read_dir(base)
            .expect("read base")
            .map(|e| e.expect("base entry").file_name())
            .collect();
        assert_eq!(
            names,
            [std::ffi::OsString::from("root")],
            "write escaped root"
        );
        check_tree(&root_path, uid, 0);
    }
    fs::remove_dir_all(base).expect("remove per-input base");
}
