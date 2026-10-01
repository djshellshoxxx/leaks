// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Capability-confined, content-addressed object store (07 §10, BE-009).

use crate::id::{ID_LEN, id_from_hasher};
use crate::{ContentKey, ObjectId, SafeFsError, SlotTime};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, DirBuilder, DirBuilderExt, OpenOptions, OpenOptionsExt};
use rustix::fs::{FileType, Stat};
use std::fmt;
use std::fs::{File, FileTimes};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsFd;
use std::path::{Component, Path};

const TMP_PREFIX: &str = ".tmp-";
/// Default per-object size cap (07 §4 "Max single object 4 GiB").
pub const DEFAULT_MAX_OBJECT_BYTES: u64 = 4 << 30;

/// Directory layout and purpose of a root (07 §4, §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RootPolicy {
    /// Blob store: `<root>/<2-char shard>/<26-char id>`.
    BlobStore,
    /// Staging area (tmpfs): flat `<root>/<26-char id>`.
    Staging,
    /// Extraction scratch area inside the viewer VM: flat.
    Scratch,
}

impl RootPolicy {
    fn sharded(self) -> bool {
        matches!(self, Self::BlobStore)
    }
}

/// A capability handle on one storage root. All operations resolve single
/// path components relative to this handle; no path string is ever composed
/// from input.
pub struct SafeRoot {
    dir: Dir,
    policy: RootPolicy,
    dev: u64,
    uid: u32,
    max_object_bytes: u64,
}

impl fmt::Debug for SafeRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SafeRoot")
            .field("policy", &self.policy)
            .field("max_object_bytes", &self.max_object_bytes)
            .finish_non_exhaustive()
    }
}

fn fstat(fd: impl AsFd) -> Result<Stat, SafeFsError> {
    rustix::fs::fstat(fd).map_err(|e| SafeFsError::from(io::Error::from(e)))
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn check_private_dir(st: &Stat, uid: u32, dev: Option<u64>) -> Result<(), SafeFsError> {
    if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
        return Err(SafeFsError::UnsafeObject("not a directory"));
    }
    if st.st_uid != uid {
        return Err(SafeFsError::UnsafeObject("directory owner"));
    }
    if st.st_mode & 0o077 != 0 {
        return Err(SafeFsError::UnsafeObject("directory mode not 0700"));
    }
    if let Some(d) = dev {
        if st.st_dev != d {
            return Err(SafeFsError::UnsafeObject("cross-device"));
        }
    }
    Ok(())
}

fn check_plain_file(st: &Stat, uid: u32, dev: u64) -> Result<(), SafeFsError> {
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(SafeFsError::UnsafeObject("not a regular file"));
    }
    if st.st_nlink != 1 {
        return Err(SafeFsError::UnsafeObject("hardlinked file"));
    }
    if st.st_uid != uid {
        return Err(SafeFsError::UnsafeObject("file owner"));
    }
    if st.st_mode & 0o077 != 0 {
        return Err(SafeFsError::UnsafeObject("file mode not 0600"));
    }
    if st.st_dev != dev {
        return Err(SafeFsError::UnsafeObject("cross-device"));
    }
    Ok(())
}

fn nonblock_noctty() -> i32 {
    // Opening a planted FIFO must not block; NOCTTY for planted ttys.
    // Bit patterns are small positive values; fall back to 0 if not.
    i32::try_from((rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOCTTY).bits()).unwrap_or(0)
}

fn set_times(f: &File, slot: SlotTime) -> io::Result<()> {
    let t = slot.system_time();
    f.set_times(FileTimes::new().set_accessed(t).set_modified(t))
}

/// Normalizes a directory's atime/mtime to the slot and fsyncs it.
fn settle_dir(dir: &Dir, slot: SlotTime) -> Result<(), SafeFsError> {
    let f = dir.open_dir_nofollow(".")?.into_std_file();
    set_times(&f, slot)?;
    f.sync_all()?;
    Ok(())
}

impl SafeRoot {
    /// Opens a storage root.
    ///
    /// The path must be absolute, every component must be a real directory
    /// (no symlinked component anywhere, CVE-2026-54706 class), and the root
    /// must be owned by the effective uid with mode 0700. The opened handle
    /// is re-checked (device + inode) against the walked path.
    pub fn open(path: &Path, policy: RootPolicy) -> Result<Self, SafeFsError> {
        if !path.is_absolute() {
            return Err(SafeFsError::RootPolicy("path not absolute"));
        }
        if path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(SafeFsError::RootPolicy("path not normalized"));
        }
        let mut last = None;
        for anc in path.ancestors() {
            let md = std::fs::symlink_metadata(anc)?;
            if md.file_type().is_symlink() {
                return Err(SafeFsError::RootPolicy("symlinked path component"));
            }
            if !md.is_dir() {
                return Err(SafeFsError::RootPolicy("component not a directory"));
            }
            if last.is_none() {
                last = Some(md);
            }
        }
        let walked = last.ok_or(SafeFsError::RootPolicy("empty path"))?;
        let dir = Dir::open_ambient_dir(path, cap_std::ambient_authority())?;
        let st = fstat(&dir)?;
        {
            use std::os::unix::fs::MetadataExt;
            if st.st_dev != walked.dev() || st.st_ino != walked.ino() {
                return Err(SafeFsError::RootPolicy("root changed while opening"));
            }
        }
        let uid = euid();
        check_private_dir(&st, uid, None)
            .map_err(|_| SafeFsError::RootPolicy("root must be a 0700 directory owned by the service user"))?;
        Ok(Self {
            dir,
            policy,
            dev: st.st_dev,
            uid,
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
        })
    }

    /// Sets the per-object size cap (writes beyond it fail with `TooLarge`).
    pub fn with_max_object_bytes(mut self, n: u64) -> Self {
        self.max_object_bytes = n;
        self
    }

    /// The root's policy.
    pub fn policy(&self) -> RootPolicy {
        self.policy
    }

    /// Starts writing a new object under a pre-chosen random id
    /// (`O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600, in a temp name).
    pub fn create_new(&self, id: &ObjectId) -> Result<PendingObject<'_>, SafeFsError> {
        self.pending(Naming::Fixed(*id))
    }

    /// Starts writing a new object with a fresh random id.
    pub fn create_random(&self) -> Result<PendingObject<'_>, SafeFsError> {
        self.pending(Naming::Fixed(ObjectId::random()?))
    }

    /// Starts writing a content-addressed object; the id
    /// (`BLAKE3-keyed(key, content)[..16]`) is known at commit. Storing the
    /// same content twice yields the same id and keeps one copy.
    pub fn create_content_addressed(
        &self,
        key: &ContentKey,
    ) -> Result<PendingObject<'_>, SafeFsError> {
        self.pending(Naming::Keyed(Box::new(key.hasher())))
    }

    /// Convenience: writes `data` atomically under a fresh random id.
    pub fn put_random(&self, data: &[u8], slot: SlotTime) -> Result<ObjectId, SafeFsError> {
        let mut w = self.create_random()?;
        w.write_all(data)?;
        w.commit(slot)
    }

    fn pending(&self, naming: Naming) -> Result<PendingObject<'_>, SafeFsError> {
        let tmp_name = format!("{TMP_PREFIX}{}", ObjectId::random()?.to_name());
        let mut opts = OpenOptions::new();
        opts.write(true)
            .create_new(true)
            .mode(0o600)
            .follow(FollowSymlinks::No)
            .custom_flags(nonblock_noctty());
        let file = self.dir.open_with(&tmp_name, &opts)?.into_std();
        let pending = PendingObject {
            root: self,
            file: Some(file),
            tmp_name,
            naming,
            written: 0,
        };
        if let Some(f) = pending.file.as_ref() {
            check_plain_file(&fstat(f)?, self.uid, self.dev)?;
        }
        Ok(pending)
    }

    fn shard_dir(&self, id: &ObjectId, create: Option<SlotTime>) -> Result<Dir, SafeFsError> {
        if !self.policy.sharded() {
            return Ok(self.dir.try_clone()?);
        }
        let name = id.shard();
        let dir = match self.dir.open_dir_nofollow(&name) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let Some(slot) = create else {
                    return Err(SafeFsError::NotFound);
                };
                let mut b = DirBuilder::new();
                b.mode(0o700);
                match self.dir.create_dir_with(&name, &b) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e.into()),
                }
                let d = self.dir.open_dir_nofollow(&name)?;
                settle_dir(&self.dir, slot)?;
                d
            }
            Err(e) => return Err(map_nofollow_err(e)),
        };
        check_private_dir(&fstat(&dir)?, self.uid, Some(self.dev))?;
        Ok(dir)
    }

    /// Opens an object for reading. Refuses symlinks (at the shard and the
    /// object), hardlinked files, FIFOs, devices, directories, files with
    /// group/other permissions and files on another device.
    pub fn open_read(&self, id: &ObjectId) -> Result<ObjectReader, SafeFsError> {
        let shard = self.shard_dir(id, None)?;
        let mut opts = OpenOptions::new();
        opts.read(true)
            .follow(FollowSymlinks::No)
            .custom_flags(nonblock_noctty());
        let file = shard
            .open_with(id.to_name(), &opts)
            .map_err(map_nofollow_err)?
            .into_std();
        let st = fstat(&file)?;
        check_plain_file(&st, self.uid, self.dev)?;
        let len = u64::try_from(st.st_size).map_err(|_| SafeFsError::UnsafeObject("size"))?;
        Ok(ObjectReader { file, len })
    }

    /// Reads a whole object into memory, bounded by `max` bytes.
    pub fn read_to_vec(&self, id: &ObjectId, max: u64) -> Result<Vec<u8>, SafeFsError> {
        let r = self.open_read(id)?;
        if r.len() > max {
            return Err(SafeFsError::TooLarge);
        }
        let mut v = Vec::new();
        r.take(max).read_to_end(&mut v)?;
        Ok(v)
    }

    /// Whether an object exists (as any directory entry).
    pub fn exists(&self, id: &ObjectId) -> Result<bool, SafeFsError> {
        let shard = match self.shard_dir(id, None) {
            Ok(s) => s,
            Err(SafeFsError::NotFound) => return Ok(false),
            Err(e) => return Err(e),
        };
        match shard.symlink_metadata(id.to_name()) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Removes an object (unlinks the entry; never follows a symlink), then
    /// normalizes the containing directory's times to `slot` and fsyncs it.
    /// Plaintext-free by design: callers store ciphertext and rely on
    /// crypto-erasure (ADR-025), not overwriting.
    pub fn remove(&self, id: &ObjectId, slot: SlotTime) -> Result<(), SafeFsError> {
        let shard = self.shard_dir(id, None)?;
        shard.remove_file(id.to_name())?;
        settle_dir(&shard, slot)
    }

    /// Removes leftover temp files from interrupted writes (call at
    /// start-up). Returns how many were removed.
    pub fn purge_incomplete(&self, slot: SlotTime) -> Result<usize, SafeFsError> {
        let mut names = Vec::new();
        for ent in self.dir.entries()? {
            let ent = ent?;
            let name = ent.file_name();
            if let Some(n) = name.to_str() {
                if n.starts_with(TMP_PREFIX)
                    && ObjectId::parse(n.get(TMP_PREFIX.len()..).unwrap_or("")).is_ok()
                {
                    names.push(n.to_owned());
                }
            }
        }
        for n in &names {
            self.dir.remove_file(n)?;
        }
        if !names.is_empty() {
            settle_dir(&self.dir, slot)?;
        }
        Ok(names.len())
    }

    /// Lists committed object ids (entries that are not canonical ids are
    /// skipped, never interpreted).
    pub fn list(&self) -> Result<Vec<ObjectId>, SafeFsError> {
        let mut out = Vec::new();
        if self.policy.sharded() {
            for ent in self.dir.entries()? {
                let ent = ent?;
                let name = ent.file_name();
                let Some(n) = name.to_str() else { continue };
                if n.len() != 2 || !n.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)) {
                    continue;
                }
                let shard = self.dir.open_dir_nofollow(n).map_err(map_nofollow_err)?;
                check_private_dir(&fstat(&shard)?, self.uid, Some(self.dev))?;
                collect_ids(&shard, &mut out)?;
            }
        } else {
            collect_ids(&self.dir, &mut out)?;
        }
        out.sort();
        Ok(out)
    }
}

fn collect_ids(dir: &Dir, out: &mut Vec<ObjectId>) -> Result<(), SafeFsError> {
    for ent in dir.entries()? {
        let ent = ent?;
        let name = ent.file_name();
        if let Some(n) = name.to_str() {
            if n.len() == ID_LEN {
                if let Ok(id) = ObjectId::parse(n) {
                    out.push(id);
                }
            }
        }
    }
    Ok(())
}

fn map_nofollow_err(e: io::Error) -> SafeFsError {
    match e.raw_os_error() {
        Some(c) if c == rustix::io::Errno::NOTDIR.raw_os_error() => {
            SafeFsError::UnsafeObject("not a directory or symlink")
        }
        _ => e.into(),
    }
}

enum Naming {
    Fixed(ObjectId),
    Keyed(Box<blake3::Hasher>),
}

/// An object being written. Nothing is visible under the final name until
/// [`PendingObject::commit`]; dropping without commit removes the temp file.
pub struct PendingObject<'a> {
    root: &'a SafeRoot,
    file: Option<File>,
    tmp_name: String,
    naming: Naming,
    written: u64,
}

impl fmt::Debug for PendingObject<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingObject")
            .field("written", &self.written)
            .finish_non_exhaustive()
    }
}

impl Write for PendingObject<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = u64::try_from(buf.len()).map_err(|_| io::Error::from(SafeFsError::TooLarge))?;
        let total = self
            .written
            .checked_add(n)
            .filter(|t| *t <= self.root.max_object_bytes)
            .ok_or_else(|| io::Error::from(SafeFsError::TooLarge))?;
        let f = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        f.write_all(buf)?;
        if let Naming::Keyed(h) = &mut self.naming {
            h.update(buf);
        }
        self.written = total;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.file.as_mut() {
            Some(f) => f.flush(),
            None => Ok(()),
        }
    }
}

impl PendingObject<'_> {
    /// Bytes written so far.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Commits atomically: set atime/mtime to `slot`, fsync the file,
    /// rename into place without replacing (`renameat2(RENAME_NOREPLACE)`,
    /// fallback `linkat`+`unlinkat`), normalize directory times to `slot`
    /// and fsync the directories.
    pub fn commit(mut self, slot: SlotTime) -> Result<ObjectId, SafeFsError> {
        let file = self.file.take().ok_or(SafeFsError::Io(io::ErrorKind::BrokenPipe))?;
        set_times(&file, slot)?;
        file.sync_all()?;
        drop(file);
        let (id, dedup) = match &self.naming {
            Naming::Fixed(id) => (*id, false),
            Naming::Keyed(h) => (id_from_hasher(h), true),
        };
        let root = self.root;
        let shard = root.shard_dir(&id, Some(slot))?;
        let res = rename_noreplace(&root.dir, &self.tmp_name, &shard, &id.to_name());
        match res {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                root.dir.remove_file(&self.tmp_name)?;
                self.tmp_name.clear();
                settle_dir(&root.dir, slot)?;
                return if dedup {
                    Ok(id)
                } else {
                    Err(SafeFsError::AlreadyExists)
                };
            }
            Err(e) => return Err(e.into()),
        }
        self.tmp_name.clear();
        settle_dir(&shard, slot)?;
        if root.policy.sharded() {
            settle_dir(&root.dir, slot)?;
        }
        Ok(id)
    }
}

impl Drop for PendingObject<'_> {
    fn drop(&mut self) {
        self.file = None;
        if !self.tmp_name.is_empty() {
            // Best effort: purge_incomplete() handles crashes.
            let _ = self.root.dir.remove_file(&self.tmp_name);
        }
    }
}

fn rename_noreplace(from: &Dir, old: &str, to: &Dir, new: &str) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        match rustix::fs::renameat_with(from, old, to, new, rustix::fs::RenameFlags::NOREPLACE) {
            Ok(()) => return Ok(()),
            Err(e) if e == rustix::io::Errno::INVAL || e == rustix::io::Errno::NOSYS => {}
            Err(e) => return Err(e.into()),
        }
    }
    // Portable atomic no-replace: link (fails if `new` exists), then unlink.
    rustix::fs::linkat(from, old, to, new, rustix::fs::AtFlags::empty())?;
    rustix::fs::unlinkat(from, old, rustix::fs::AtFlags::empty())?;
    Ok(())
}

/// A read handle on a committed object (verified plain regular file).
#[derive(Debug)]
pub struct ObjectReader {
    file: File,
    len: u64,
}

impl ObjectReader {
    /// Size in bytes at open time.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the object is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Read for ObjectReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Seek for ObjectReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}
