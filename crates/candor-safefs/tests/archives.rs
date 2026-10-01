// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Malicious-archive suite (ST-081, FILE-019, FILE-020; B-CR-52 Fifield,
//! B-SD-28/33/35 TOB-SDW-012 / CVE-2025-24888 / CVE-2026-35465,
//! B-OS-03 CVE-2026-54706).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod common;
use candor_safefs::RootPolicy;
use candor_safefs::archive::*;
use common::*;
use std::io::{Cursor, Write};

fn opts() -> ExtractOptions {
    ExtractOptions::new(slot())
}

fn reasons(r: &ExtractionReport) -> Vec<RejectReason> {
    r.rejected.iter().map(|m| m.reason).collect()
}

// ---------------------------------------------------------------- zip

#[test]
fn zip_slip_absolute_and_drive_paths_rejected() {
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let a = zip(&[
        z(b"../../outside/evil.txt", b"pwn"),
        z(b"/etc/cron.d/evil", b"pwn"),
        z(b"C:\\Windows\\evil", b"pwn"),
        z(b"..\\..\\evil", b"pwn"),
        z(b"docs/./ok.txt", b"fine"),
    ]);
    let r = extract_zip(Cursor::new(a), &root, &opts()).unwrap();
    use RejectReason::*;
    assert_eq!(
        reasons(&r),
        vec![ParentTraversal, AbsolutePath, AbsolutePath, ParentTraversal]
    );
    assert_eq!(r.members.len(), 1);
    assert_eq!(
        r.members[0].display_name.as_str(),
        "docs\u{2215}.\u{2215}ok.txt"
    );
    assert_eq!(root.read_to_vec(&r.members[0].id, 100).unwrap(), b"fine");
    assert!(
        e.files_outside_root().is_empty(),
        "{:?}",
        e.files_outside_root()
    );
}

#[test]
fn zip_symlink_device_and_dirs() {
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let mut link = z(b"link", b"/etc/passwd");
    link.unix_mode = Some(0o120_777);
    let mut dev = z(b"dev", b"");
    dev.unix_mode = Some(0o020_644);
    let mut fifo = z(b"fifo", b"");
    fifo.unix_mode = Some(0o010_644);
    let mut dir = z(b"somedir/", b"");
    dir.unix_mode = Some(0o040_755);
    let mut reg = z(b"somedir/f", b"data");
    reg.unix_mode = Some(0o100_644);
    let r = extract_zip(
        Cursor::new(zip(&[link, dev, fifo, dir, reg])),
        &root,
        &opts(),
    )
    .unwrap();
    use RejectReason::*;
    assert_eq!(reasons(&r), vec![Symlink, DeviceOrSpecial, DeviceOrSpecial]);
    assert_eq!(r.members.len(), 1);
    assert_eq!(root.list().unwrap().len(), 1);
}

#[test]
fn zip_encrypted_and_unsupported_method_flagged() {
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let mut enc = z(b"enc", b"x");
    enc.flags = 1;
    let mut bz = z(b"bz", b"x");
    bz.method_override = Some(12);
    let r = extract_zip(Cursor::new(zip(&[enc, bz, z(b"ok", b"y")])), &root, &opts()).unwrap();
    assert_eq!(
        reasons(&r),
        vec![
            RejectReason::Encrypted,
            RejectReason::UnsupportedCompression
        ]
    );
    assert_eq!(r.members.len(), 1);
}

#[test]
fn zip_duplicate_names_after_nfc() {
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let a = zip(&[
        z("caf\u{e9}".as_bytes(), b"1"),
        z("cafe\u{301}".as_bytes(), b"2"),
        z(b"a//b", b"3"),
        z(b"a/b", b"4"),
    ]);
    let r = extract_zip(Cursor::new(a), &root, &opts()).unwrap();
    assert_eq!(
        reasons(&r),
        vec![RejectReason::DuplicateName, RejectReason::DuplicateName]
    );
    assert_eq!(r.members.len(), 2);
}

#[test]
fn zip_ratio_bomb_rejected_and_rolled_back() {
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let zeros = vec![0u8; 8 << 20];
    let mut bomb = z(b"bomb", &zeros);
    bomb.deflate = true;
    let a = zip(&[z(b"first", b"written before the bomb"), bomb]);
    let err = extract_zip(Cursor::new(a), &root, &opts()).unwrap_err();
    assert!(
        matches!(err, ArchiveError::LimitHit(LimitKind::Ratio)),
        "{err:?}"
    );
    assert!(root.list().unwrap().is_empty(), "rollback failed");
    assert!(
        std::fs::read_dir(&e.root_path).unwrap().next().is_none(),
        "residue left"
    );
}

#[test]
fn zip_lying_declared_size_counts_real_bytes() {
    // Declared uncompressed size 10, real 1 MiB: limits use produced bytes.
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let data = vec![7u8; 1 << 20];
    let payload = deflate(&data);
    let mut body = local_header(b"liar", 8, 0, crc(&data), payload.len() as u32, 10);
    body.extend_from_slice(&payload);
    let a = finish_zip(
        body,
        &[Cd {
            name: b"liar".to_vec(),
            method: 8,
            flags: 0,
            crc: crc(&data),
            csize: payload.len() as u32,
            usize: 10,
            offset: 0,
            unix_mode: None,
        }],
    );
    let mut o = opts();
    o.limits.max_entry_size = 1000;
    let res = extract_zip(Cursor::new(a), &root, &o);
    assert!(res.is_err(), "lying size accepted");
    assert!(root.list().unwrap().is_empty());
}

#[test]
fn zip_fifield_shared_local_header_rejected() {
    // Many central entries referencing one local header (Fifield 2019).
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let data = vec![0u8; 100_000];
    let payload = deflate(&data);
    let mut body = local_header(
        b"k",
        8,
        0,
        crc(&data),
        payload.len() as u32,
        data.len() as u32,
    );
    body.extend_from_slice(&payload);
    let cd = Cd {
        name: b"k".to_vec(),
        method: 8,
        flags: 0,
        crc: crc(&data),
        csize: payload.len() as u32,
        usize: data.len() as u32,
        offset: 0,
        unix_mode: None,
    };
    // Distinct central names, one shared local header: overlap.
    let cds: Vec<Cd> = (0..50)
        .map(|i| Cd {
            name: format!("k{i:02}").into_bytes(),
            ..cd.clone()
        })
        .collect();
    let err = extract_zip(Cursor::new(finish_zip(body.clone(), &cds)), &root, &opts()).unwrap_err();
    assert!(matches!(err, ArchiveError::OverlappingEntries), "{err:?}");
    // Identical central names: the zip crate would collapse them; we refuse.
    let cds: Vec<Cd> = (0..50).map(|_| cd.clone()).collect();
    let err = extract_zip(Cursor::new(finish_zip(body, &cds)), &root, &opts()).unwrap_err();
    assert!(matches!(err, ArchiveError::Malformed(_)), "{err:?}");
    assert!(root.list().unwrap().is_empty());
}

#[test]
fn zip_fifield_quoted_overlap_rejected() {
    // Entry A's stored data "quotes" entry B's local header + data.
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let b_data = b"inner".to_vec();
    let mut b_local = local_header(
        b"b",
        0,
        0,
        crc(&b_data),
        b_data.len() as u32,
        b_data.len() as u32,
    );
    b_local.extend_from_slice(&b_data);
    let a_hdr = local_header(
        b"a",
        0,
        0,
        crc(&b_local),
        b_local.len() as u32,
        b_local.len() as u32,
    );
    let b_off = a_hdr.len() as u32;
    let mut body = a_hdr;
    body.extend_from_slice(&b_local);
    let cds = [
        Cd {
            name: b"a".to_vec(),
            method: 0,
            flags: 0,
            crc: crc(&b_local),
            csize: b_local.len() as u32,
            usize: b_local.len() as u32,
            offset: 0,
            unix_mode: None,
        },
        Cd {
            name: b"b".to_vec(),
            method: 0,
            flags: 0,
            crc: crc(&b_data),
            csize: b_data.len() as u32,
            usize: b_data.len() as u32,
            offset: b_off,
            unix_mode: None,
        },
    ];
    let err = extract_zip(Cursor::new(finish_zip(body, &cds)), &root, &opts()).unwrap_err();
    assert!(matches!(err, ArchiveError::OverlappingEntries), "{err:?}");
}

#[test]
fn zip_central_local_name_mismatch_rejected() {
    // Parser differential: local header says "../x", central says "x".
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let data = b"d";
    let mut body = local_header(b"../x", 0, 0, crc(data), 1, 1);
    body.extend_from_slice(data);
    let a = finish_zip(
        body,
        &[Cd {
            name: b"zzzz".to_vec(),
            method: 0,
            flags: 0,
            crc: crc(data),
            csize: 1,
            usize: 1,
            offset: 0,
            unix_mode: None,
        }],
    );
    let err = extract_zip(Cursor::new(a), &root, &opts()).unwrap_err();
    assert!(matches!(err, ArchiveError::Malformed(_)), "{err:?}");
}

#[test]
fn zip_entry_count_and_size_limits() {
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let names: Vec<String> = (0..5).map(|i| format!("f{i}")).collect();
    let ents: Vec<Z<'_>> = names
        .iter()
        .map(|n| z(n.as_bytes(), &[1u8; 1000]))
        .collect();
    let a = zip(&ents);
    let mut o = opts();
    o.limits.max_entries = 3;
    assert!(matches!(
        extract_zip(Cursor::new(a.clone()), &root, &o),
        Err(ArchiveError::LimitHit(LimitKind::Entries))
    ));
    let mut o = opts();
    o.limits.max_total_uncompressed = 2500;
    assert!(matches!(
        extract_zip(Cursor::new(a.clone()), &root, &o),
        Err(ArchiveError::LimitHit(LimitKind::TotalSize))
    ));
    let mut o = opts();
    o.limits.max_entry_size = 999;
    assert!(matches!(
        extract_zip(Cursor::new(a.clone()), &root, &o),
        Err(ArchiveError::LimitHit(LimitKind::EntrySize))
    ));
    assert!(root.list().unwrap().is_empty());
    let r = extract_zip(Cursor::new(a), &root, &opts()).unwrap();
    assert_eq!(r.members.len(), 5);
    assert_eq!(r.total_bytes, 5000);
}

#[test]
fn zip_long_paths_rejected() {
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let long = vec![b'a'; 1025];
    let deep = "d/".repeat(40) + "f";
    let r = extract_zip(
        Cursor::new(zip(&[z(&long, b"x"), z(deep.as_bytes(), b"x")])),
        &root,
        &opts(),
    )
    .unwrap();
    assert_eq!(
        reasons(&r),
        vec![RejectReason::PathTooLong, RejectReason::TooManyComponents]
    );
}

#[test]
fn nested_archives_flagged_not_recursed() {
    // 42.zip-style nesting: extraction is never recursive; the caller opts in
    // per level and the depth limit is enforced.
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let inner = zip(&[z(b"leaf.txt", b"leaf")]);
    let outer = zip(&[
        z(b"inner.zip", &inner),
        z(b"t.gz", &gzip(b"x", None)),
        z(b"plain.txt", b"hello"),
    ]);
    let r = extract_zip(Cursor::new(outer), &root, &opts()).unwrap();
    assert_eq!(r.members.len(), 3);
    assert!(
        r.members[0].nested_archive && r.members[1].nested_archive && !r.members[2].nested_archive
    );
    assert_eq!(root.list().unwrap().len(), 3);
    // Explicit second level works...
    let mut o = opts();
    o.nesting_level = 2;
    let inner_r = root.open_read(&r.members[0].id).unwrap();
    let r2 = extract_zip(inner_r, &root, &o).unwrap();
    assert_eq!(r2.members.len(), 1);
    // ...but beyond max_nesting_depth (3) is refused.
    o.nesting_level = 4;
    assert!(matches!(
        extract_zip(Cursor::new(inner), &root, &o),
        Err(ArchiveError::LimitHit(LimitKind::NestingDepth))
    ));
    let mut l = ArchiveLimits::DEFAULT;
    l.max_nesting_depth = 9;
    o.limits = l;
    o.nesting_level = 1;
    assert!(matches!(
        extract_zip(Cursor::new(Vec::new()), &root, &o),
        Err(ArchiveError::InvalidLimits)
    ));
}

#[test]
fn zip_prepended_data_refused() {
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let mut a = b"MZ-not-really-an-exe".to_vec();
    a.extend(zip(&[z(b"f", b"x")]));
    assert!(extract_zip(Cursor::new(a), &root, &opts()).is_err());
}

#[test]
fn zip_garbage_is_malformed_not_panic() {
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    for g in [Vec::new(), b"PK\x05\x06".to_vec(), vec![0xffu8; 4096]] {
        assert!(extract_zip(Cursor::new(g), &root, &opts()).is_err());
    }
}

// ---------------------------------------------------------------- tar

#[test]
fn tar_traversal_links_devices() {
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let mut t = TarBuf::new();
    t.entry(b"../../outside/evil", b'0', b"pwn")
        .entry(b"/abs/evil", b'0', b"pwn")
        .entry_link(b"ln", b'2', b"", b"/etc/passwd")
        .entry_link(b"hl", b'1', b"", b"ok.txt")
        .entry(b"chr", b'3', b"")
        .entry(b"blk", b'4', b"")
        .entry(b"fifo", b'6', b"")
        .entry(b"vol", b'V', b"")
        .entry(b"dir/", b'5', b"")
        .entry(b"dir/ok.txt", b'0', b"good")
        .entry(b"dir//ok.txt", b'0', b"dup")
        .entry(b"sparse", b'S', b"");
    let r = extract_tar(Cursor::new(t.finish()), &root, &opts()).unwrap();
    use RejectReason::*;
    assert_eq!(
        reasons(&r),
        vec![
            ParentTraversal,
            AbsolutePath,
            Symlink,
            Hardlink,
            DeviceOrSpecial,
            DeviceOrSpecial,
            DeviceOrSpecial,
            UnsupportedEntryType,
            DuplicateName,
            Sparse
        ]
    );
    assert_eq!(r.members.len(), 1);
    assert_eq!(root.read_to_vec(&r.members[0].id, 10).unwrap(), b"good");
    assert!(e.files_outside_root().is_empty());
}

#[test]
fn tar_gnu_longname_and_pax_paths_checked() {
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let mut t = TarBuf::new();
    t.entry(b"././@LongLink", b'L', b"../../../../home/user/.bashrc\0")
        .entry(b"innocent", b'0', b"pwn");
    t.pax(&[("path", "/etc/shadow")])
        .entry(b"innocent2", b'0', b"pwn");
    let longname = format!("{}\0", "x/".repeat(20) + "file");
    t.entry(b"././@LongLink", b'L', longname.as_bytes())
        .entry(b"short", b'0', b"ok");
    let too_long = vec![b'a'; 5000];
    t.entry(b"././@LongLink", b'L', &too_long)
        .entry(b"y", b'0', b"z");
    let r = extract_tar(Cursor::new(t.finish()), &root, &opts()).unwrap();
    use RejectReason::*;
    assert_eq!(
        reasons(&r),
        vec![ParentTraversal, AbsolutePath, PathTooLong]
    );
    assert_eq!(r.members.len(), 1);
    assert!(r.members[0].display_name.as_str().ends_with("file"));
}

#[test]
fn tar_pax_size_override_and_huge_headers_refused() {
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let mut t = TarBuf::new();
    t.pax(&[("size", "1")]).entry(b"f", b'0', b"abc");
    assert!(matches!(
        extract_tar(Cursor::new(t.finish()), &root, &opts()),
        Err(ArchiveError::Unsupported(_))
    ));
    let mut t = TarBuf::new();
    let big = "v".repeat(70_000);
    t.pax(&[("comment", &big)]).entry(b"f", b'0', b"abc");
    assert!(matches!(
        extract_tar(Cursor::new(t.finish()), &root, &opts()),
        Err(ArchiveError::LimitHit(LimitKind::HeaderSize))
    ));
    let mut t = TarBuf::new();
    t.pax(&[("path", "a")])
        .pax(&[("path", "b")])
        .entry(b"f", b'0', b"abc");
    assert!(extract_tar(Cursor::new(t.finish()), &root, &opts()).is_err());
}

#[test]
fn tar_limits() {
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let mut t = TarBuf::new();
    for i in 0..5 {
        t.entry(format!("f{i}").as_bytes(), b'0', &[0u8; 1000]);
    }
    let a = t.finish();
    let mut o = opts();
    o.limits.max_entries = 4;
    assert!(matches!(
        extract_tar(Cursor::new(a.clone()), &root, &o),
        Err(ArchiveError::LimitHit(LimitKind::Entries))
    ));
    let mut o = opts();
    o.limits.max_total_uncompressed = 4500;
    assert!(matches!(
        extract_tar(Cursor::new(a.clone()), &root, &o),
        Err(ArchiveError::LimitHit(LimitKind::TotalSize))
    ));
    assert!(root.list().unwrap().is_empty());
    assert_eq!(
        extract_tar(Cursor::new(a), &root, &opts())
            .unwrap()
            .members
            .len(),
        5
    );
}

#[test]
fn tar_header_lies_about_size() {
    // Declared size larger than the stream: malformed, rolled back.
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let mut a = TarBuf::new();
    a.entry(b"ok", b'0', b"fine");
    let mut bytes = a.0.clone();
    bytes.extend_from_slice(&tar_header(b"liar", 1 << 20, b'0', b""));
    bytes.extend_from_slice(&[1u8; 512]);
    assert!(extract_tar(Cursor::new(bytes), &root, &opts()).is_err());
    assert!(root.list().unwrap().is_empty());
}

#[test]
fn tar_gz_ratio_bomb() {
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    // 64 MiB of zeros in a tar, gzipped (~65 KB): ratio ~1000:1.
    let size: u64 = 64 << 20;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(&tar_header(b"zeros", size, b'0', b""))
        .unwrap();
    let chunk = vec![0u8; 1 << 20];
    for _ in 0..64 {
        enc.write_all(&chunk).unwrap();
    }
    enc.write_all(&[0u8; 1024]).unwrap();
    let gz = enc.finish().unwrap();
    let err = extract_tar_gz(Cursor::new(gz.clone()), &root, &opts()).unwrap_err();
    assert!(
        matches!(err, ArchiveError::LimitHit(LimitKind::Ratio)),
        "{err:?}"
    );
    assert!(root.list().unwrap().is_empty());
    // With the ceiling ratio it is still capped by the total size limit.
    let mut o = opts();
    o.limits.max_ratio = 1000;
    o.limits.max_total_uncompressed = 1 << 20;
    let err = extract_tar_gz(Cursor::new(gz), &root, &o).unwrap_err();
    assert!(matches!(err, ArchiveError::LimitHit(_)), "{err:?}");
}

#[test]
fn tar_gz_header_filename_ignored() {
    // CVE-2026-35465: gzip FNAME with an absolute path must not influence
    // anything.
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let mut t = TarBuf::new();
    t.entry(b"a.txt", b'0', b"A");
    let fname = format!("{}/evil.sqlite", e.outside.display());
    let gz = gzip(&t.finish(), Some(fname.as_bytes()));
    let r = extract_tar_gz(Cursor::new(gz), &root, &opts()).unwrap();
    assert_eq!(r.members.len(), 1);
    assert_eq!(r.members[0].display_name.as_str(), "a.txt");
    assert!(e.files_outside_root().is_empty());
}

#[test]
fn gzip_fname_injection_and_bomb() {
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    for fname in [
        &b"/etc/passwd"[..],
        b"../../../../root/.bashrc",
        b"..\\..\\x",
        b"\xe2\x80\xaeevil",
    ] {
        let gz = gzip(b"payload", Some(fname));
        let r = extract_gzip(Cursor::new(gz), &root, &opts()).unwrap();
        assert_eq!(r.members.len(), 1);
        assert_eq!(r.members[0].display_name.as_str(), "(unnamed)");
        assert_eq!(root.read_to_vec(&r.members[0].id, 100).unwrap(), b"payload");
    }
    assert!(e.files_outside_root().is_empty());
    let bomb = gzip(&vec![0u8; 16 << 20], Some(b"/x"));
    let err = extract_gzip(Cursor::new(bomb), &root, &opts()).unwrap_err();
    assert!(
        matches!(err, ArchiveError::LimitHit(LimitKind::Ratio)),
        "{err:?}"
    );
    assert_eq!(root.list().unwrap().len(), 4);
    assert!(extract_gzip(Cursor::new(b"\x1f\x8bnot gzip".to_vec()), &root, &opts()).is_err());
}

mod props {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        // Arbitrary member names never produce a file outside the root and
        // never panic (ST-048 property form).
        #[test]
        fn arbitrary_names_confined(names in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..60), 1..8)) {
            let e = env();
            let root = e.root(RootPolicy::Scratch);
            let ents: Vec<Z<'_>> = names.iter().map(|n| z(n, b"x")).collect();
            let _ = extract_zip(Cursor::new(zip(&ents)), &root, &opts());
            let mut t = TarBuf::new();
            for n in &names { t.entry(n, b'0', b"x"); }
            let _ = extract_tar(Cursor::new(t.finish()), &root, &opts());
            prop_assert!(e.files_outside_root().is_empty());
        }

        #[test]
        fn random_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let e = env();
            let root = e.root(RootPolicy::Scratch);
            let _ = extract_zip(Cursor::new(data.clone()), &root, &opts());
            let _ = extract_tar(Cursor::new(data.clone()), &root, &opts());
            let _ = extract_tar_gz(Cursor::new(data.clone()), &root, &opts());
            let _ = extract_gzip(Cursor::new(data), &root, &opts());
            prop_assert!(e.files_outside_root().is_empty());
        }
    }
}

// AUD-RM1-SFS-06 regression: the extension-header cap is archive-wide (it
// used to reset at every real entry), and a second local pax header for the
// same entry is refused.
#[test]
fn tar_extension_header_cap_is_archive_wide() {
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let comment = "16 comment=abcd\n"; // one valid 16-byte pax record
    let mut t = TarBuf::new();
    for i in 0..2 {
        // 12 global headers per entry: 24 in total > 3 * 2 + 16 = 22.
        for _ in 0..12 {
            t.entry(b"GlobalHead", b'g', comment.as_bytes());
        }
        t.entry(format!("f{i}").as_bytes(), b'0', b"x");
    }
    let mut o = opts();
    o.limits.max_entries = 2;
    assert!(matches!(
        extract_tar(Cursor::new(t.finish()), &root, &o),
        Err(ArchiveError::LimitHit(LimitKind::Entries))
    ));
    assert!(root.list().unwrap().is_empty());
    let mut t = TarBuf::new();
    t.pax(&[("comment", "a")])
        .pax(&[("comment", "b")])
        .entry(b"f", b'0', b"abc");
    assert!(matches!(
        extract_tar(Cursor::new(t.finish()), &root, &opts()),
        Err(ArchiveError::Malformed(_))
    ));
}

// AUD-RM1-SFS-04: Debug output of reports carries no sizes.
#[test]
fn report_debug_has_no_sizes() {
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let mut t = TarBuf::new();
    t.entry(b"f", b'0', &[7u8; 12345]);
    let r = extract_tar(Cursor::new(t.finish()), &root, &opts()).unwrap();
    assert_eq!(r.total_bytes, 12345);
    let d = format!("{r:?}");
    assert!(
        !d.contains("12345") && !d.contains("size") && !d.contains("total_bytes"),
        "{d}"
    );
}

// AUD-RM1-SFS-09: local headers must agree with the central directory on
// method, encryption flag, CRC and sizes.
#[test]
fn zip_local_central_field_mismatch_rejected() {
    let e = env();
    let root = e.root(RootPolicy::Scratch);
    let good = zip(&[z(b"a.txt", b"hello")]);
    assert!(extract_zip(Cursor::new(good.clone()), &root, &opts()).is_ok());
    for (off, val) in [(8usize, 8u8), (6, 1), (14, 0xAA), (22, 0x77)] {
        let mut bad = good.clone();
        bad[off] ^= val;
        let root = e.root(RootPolicy::Scratch);
        assert!(
            matches!(
                extract_zip(Cursor::new(bad), &root, &opts()),
                Err(ArchiveError::Malformed(_))
            ),
            "offset {off}"
        );
    }
}
