// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Store confinement tests (BE-009, DB-028, ST-080, ST-086; CVE-2026-54706,
//! CVE-2025-24888, TOB-SDW-012).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod common;
use candor_safefs::{ContentKey, ObjectId, RootPolicy, SafeFsError, SafeRoot, SlotTime};
use common::*;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::time::Duration;

fn shard_path(e: &Env, id: &ObjectId) -> std::path::PathBuf {
    e.root_path.join(&id.to_name()[..2])
}

#[test]
fn roundtrip_mode_layout_and_slot_times() {
    // DB-028: mode 0600, mtime/atime = slot; ADR-038(1): directory times too.
    let e = env();
    let r = e.root(RootPolicy::BlobStore);
    let id = r.put_random(b"ciphertext", slot()).unwrap();
    let p = shard_path(&e, &id).join(id.to_name());
    let md = std::fs::symlink_metadata(&p).unwrap();
    assert!(md.is_file());
    assert_eq!(md.mode() & 0o777, 0o600);
    assert_eq!(md.mtime() as u64, SLOT);
    assert_eq!(md.atime() as u64, SLOT);
    let smd = std::fs::metadata(shard_path(&e, &id)).unwrap();
    assert_eq!(smd.mode() & 0o777, 0o700);
    assert_eq!(smd.mtime() as u64, SLOT);
    assert_eq!(
        std::fs::metadata(&e.root_path).unwrap().mtime() as u64,
        SLOT
    );
    let mut v = Vec::new();
    r.open_read(&id).unwrap().read_to_end(&mut v).unwrap();
    assert_eq!(v, b"ciphertext");
    assert_eq!(r.list().unwrap(), vec![id]);
    assert!(r.exists(&id).unwrap());
    r.remove(&id, slot()).unwrap();
    assert!(!r.exists(&id).unwrap());
    assert!(matches!(r.open_read(&id), Err(SafeFsError::NotFound)));
    assert!(e.files_outside_root().is_empty());
}

#[test]
fn staging_is_flat() {
    let e = env();
    let r = e.root(RootPolicy::Staging);
    let id = r.put_random(b"x", slot()).unwrap();
    assert!(e.root_path.join(id.to_name()).is_file());
}

#[test]
fn content_addressed_dedup_and_keyed() {
    let e = env();
    let r = e.root(RootPolicy::BlobStore);
    let k = ContentKey::from_bytes([1; 32]);
    let put = |data: &[u8]| {
        let mut w = r.create_content_addressed(&k).unwrap();
        w.write_all(data).unwrap();
        w.commit(slot()).unwrap()
    };
    let a = put(b"same");
    let b = put(b"same");
    assert_eq!(a, b);
    assert_eq!(a, k.object_id(b"same"));
    assert_ne!(put(b"other"), a);
    assert_eq!(r.list().unwrap().len(), 2);
    // FILE-005: the name is not the plain BLAKE3 of the content.
    let plain = blake3::hash(b"same");
    assert_ne!(&plain.as_bytes()[..16], a.as_bytes());
}

#[test]
fn fixed_id_never_replaces() {
    let e = env();
    let r = e.root(RootPolicy::BlobStore);
    let id = ObjectId::random().unwrap();
    let mut w = r.create_new(&id).unwrap();
    w.write_all(b"first").unwrap();
    w.commit(slot()).unwrap();
    let mut w = r.create_new(&id).unwrap();
    w.write_all(b"second").unwrap();
    assert!(matches!(w.commit(slot()), Err(SafeFsError::AlreadyExists)));
    assert_eq!(r.read_to_vec(&id, 100).unwrap(), b"first");
    // No temp residue.
    assert_eq!(std::fs::read_dir(&e.root_path).unwrap().count(), 1);
}

#[test]
fn uncommitted_write_leaves_nothing_and_purge() {
    let e = env();
    let r = e.root(RootPolicy::BlobStore);
    {
        let mut w = r.create_random().unwrap();
        w.write_all(b"partial").unwrap();
    }
    assert_eq!(std::fs::read_dir(&e.root_path).unwrap().count(), 0);
    // Simulate a crash residue.
    let stale = format!(".tmp-{}", ObjectId::random().unwrap());
    std::fs::write(e.root_path.join(&stale), b"x").unwrap();
    assert_eq!(r.purge_incomplete(slot()).unwrap(), 1);
    assert_eq!(std::fs::read_dir(&e.root_path).unwrap().count(), 0);
}

#[test]
fn size_limit() {
    let e = env();
    let r = SafeRoot::open(&e.root_path, RootPolicy::BlobStore)
        .unwrap()
        .with_max_object_bytes(4);
    let mut w = r.create_random().unwrap();
    assert!(w.write_all(b"12345").is_err());
}

#[test]
fn root_policy_checks() {
    let e = env();
    let base = std::fs::canonicalize(e.tmp.path()).unwrap();
    // Relative and non-normalized paths.
    assert!(SafeRoot::open(std::path::Path::new("root"), RootPolicy::BlobStore).is_err());
    assert!(SafeRoot::open(&base.join("outside/../root"), RootPolicy::BlobStore).is_err());
    // Symlink as the root itself.
    let link = base.join("link-root");
    symlink(&e.root_path, &link).unwrap();
    assert!(matches!(
        SafeRoot::open(&link, RootPolicy::BlobStore),
        Err(SafeFsError::RootPolicy(_))
    ));
    // Symlinked ancestor component.
    let real_parent = base.join("realparent");
    std::fs::create_dir(&real_parent).unwrap();
    mkdir_0700(&real_parent.join("r"));
    let link_parent = base.join("linkparent");
    symlink(&real_parent, &link_parent).unwrap();
    assert!(SafeRoot::open(&real_parent.join("r"), RootPolicy::BlobStore).is_ok());
    assert!(matches!(
        SafeRoot::open(&link_parent.join("r"), RootPolicy::BlobStore),
        Err(SafeFsError::RootPolicy(_))
    ));
    // Group/world-accessible root.
    std::fs::set_permissions(&e.root_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        SafeRoot::open(&e.root_path, RootPolicy::BlobStore),
        Err(SafeFsError::RootPolicy(_))
    ));
    // A file is not a root.
    std::fs::write(base.join("f"), b"").unwrap();
    assert!(SafeRoot::open(&base.join("f"), RootPolicy::BlobStore).is_err());
}

#[test]
fn symlinked_shard_dir_is_refused() {
    // An attacker with write access to the root replaces a shard directory
    // with a symlink to elsewhere: writes and reads must not follow it.
    let e = env();
    let r = e.root(RootPolicy::BlobStore);
    let id = ObjectId::random().unwrap();
    symlink(&e.outside, shard_path(&e, &id)).unwrap();
    let mut w = r.create_new(&id).unwrap();
    w.write_all(b"secret").unwrap();
    assert!(matches!(
        w.commit(slot()),
        Err(SafeFsError::UnsafeObject(_))
    ));
    assert!(matches!(
        r.open_read(&id),
        Err(SafeFsError::UnsafeObject(_))
    ));
    assert_eq!(std::fs::read_dir(&e.outside).unwrap().count(), 0);
    // Temp file cleaned up after the failed commit.
    let names: Vec<_> = std::fs::read_dir(&e.root_path)
        .unwrap()
        .map(|d| d.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 1, "{names:?}");
}

#[test]
fn shard_dir_with_wrong_mode_is_refused() {
    let e = env();
    let r = e.root(RootPolicy::BlobStore);
    let id = ObjectId::random().unwrap();
    std::fs::create_dir(shard_path(&e, &id)).unwrap();
    std::fs::set_permissions(shard_path(&e, &id), std::fs::Permissions::from_mode(0o777)).unwrap();
    let mut w = r.create_new(&id).unwrap();
    w.write_all(b"x").unwrap();
    assert!(matches!(
        w.commit(slot()),
        Err(SafeFsError::UnsafeObject(_))
    ));
}

#[test]
fn symlinked_object_is_refused_and_remove_only_unlinks() {
    let e = env();
    let r = e.root(RootPolicy::BlobStore);
    let id = r.put_random(b"x", slot()).unwrap();
    let p = shard_path(&e, &id).join(id.to_name());
    let secret = e.outside.join("secret");
    std::fs::write(&secret, b"top secret").unwrap();
    std::fs::remove_file(&p).unwrap();
    symlink(&secret, &p).unwrap();
    assert!(matches!(
        r.open_read(&id),
        Err(SafeFsError::UnsafeObject(_))
    ));
    r.remove(&id, slot()).unwrap();
    assert_eq!(std::fs::read(&secret).unwrap(), b"top secret");
}

#[test]
fn hardlinked_object_is_refused() {
    let e = env();
    let r = e.root(RootPolicy::BlobStore);
    let id = r.put_random(b"x", slot()).unwrap();
    let p = shard_path(&e, &id).join(id.to_name());
    std::fs::hard_link(&p, e.outside.join("alias")).unwrap();
    assert!(matches!(
        r.open_read(&id),
        Err(SafeFsError::UnsafeObject(_))
    ));
}

#[test]
fn fifo_and_dir_objects_are_refused_without_blocking() {
    let e = env();
    let r = e.root(RootPolicy::Staging);
    let id = ObjectId::random().unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        e.root_path.join(id.to_name()),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let path = e.root_path.clone();
    std::thread::spawn(move || {
        let r = SafeRoot::open(&path, RootPolicy::Staging).unwrap();
        let _ = tx.send(matches!(
            r.open_read(&id),
            Err(SafeFsError::UnsafeObject(_))
        ));
    });
    assert!(
        rx.recv_timeout(Duration::from_secs(10)).unwrap(),
        "FIFO not refused"
    );
    let id2 = ObjectId::random().unwrap();
    std::fs::create_dir(e.root_path.join(id2.to_name())).unwrap();
    assert!(r.open_read(&id2).is_err());
}

#[test]
fn group_readable_object_is_refused() {
    let e = env();
    let r = e.root(RootPolicy::Staging);
    let id = r.put_random(b"x", slot()).unwrap();
    std::fs::set_permissions(
        e.root_path.join(id.to_name()),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(matches!(
        r.open_read(&id),
        Err(SafeFsError::UnsafeObject(_))
    ));
}

#[test]
fn list_ignores_foreign_entries() {
    let e = env();
    let r = e.root(RootPolicy::Staging);
    let id = r.put_random(b"x", slot()).unwrap();
    std::fs::write(e.root_path.join("..evil"), b"").unwrap();
    std::fs::write(e.root_path.join("README"), b"").unwrap();
    assert_eq!(r.list().unwrap(), vec![id]);
}

#[test]
fn slot_time_must_be_normalized() {
    assert!(SlotTime::from_unix_secs(SLOT + 1).is_err());
}

mod props {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn store_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..10_000)) {
            let e = env();
            let r = e.root(RootPolicy::BlobStore);
            let id = r.put_random(&data, slot()).unwrap();
            prop_assert_eq!(r.read_to_vec(&id, 20_000).unwrap(), data);
            prop_assert!(e.files_outside_root().is_empty());
        }
    }
}

// AUD-RM1-SFS-03 regression: an abandoned write leaves the root directory
// times at their slot value, not at the real time of the abort.
#[test]
fn dropped_pending_object_restores_root_times() {
    let e = env();
    let r = e.root(RootPolicy::Staging);
    r.put_random(b"x", slot()).unwrap();
    let before = std::fs::metadata(&e.root_path).unwrap();
    assert_eq!(before.mtime() as u64, SLOT);
    std::thread::sleep(Duration::from_millis(20));
    {
        let mut w = r.create_random().unwrap();
        w.write_all(b"partial plaintext").unwrap();
        // dropped without commit
    }
    let after = std::fs::metadata(&e.root_path).unwrap();
    assert_eq!(after.mtime() as u64, SLOT);
    assert_eq!(after.mtime_nsec(), before.mtime_nsec());
    assert_eq!(r.purge_incomplete(slot()).unwrap(), 0);
}

// AUD-RM1-SFS-04: Debug of readers/writers shows no path, size or fd.
#[test]
fn debug_output_has_no_path_or_size() {
    let e = env();
    let r = e.root(RootPolicy::BlobStore);
    let id = r.put_random(&[1u8; 4321], slot()).unwrap();
    let rd = r.open_read(&id).unwrap();
    let d = format!("{rd:?}");
    assert!(
        !d.contains("4321") && !d.contains('/') && !d.contains("path"),
        "{d}"
    );
    let mut w = r.create_random().unwrap();
    w.write_all(&[0u8; 4321]).unwrap();
    let d = format!("{w:?}");
    assert!(!d.contains("4321"), "{d}");
}
