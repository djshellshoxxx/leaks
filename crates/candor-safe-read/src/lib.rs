// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Race-free, size-capped reader for `deploy/tools/config-check.sh` inputs (AUD-RM2-DEP-24;
//! compiled per ADR-055(3) / AUD-RM2-DEP-26, replacing `safe-read.py`).
//!
//! Resolution starts at `/`. The parent directory is opened with
//! `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_BENEATH)` (fallback when the
//! kernel lacks `openat2`: a component walk with `O_PATH | O_DIRECTORY | O_NOFOLLOW`), so a
//! component swapped for a symlink fails with `ELOOP`/`ENOTDIR` instead of being followed. The
//! leaf is checked with `fstatat(AT_SYMLINK_NOFOLLOW)` before it is opened (a FIFO or device node
//! is never opened on purpose), opened `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY` (a FIFO
//! swapped in at the last moment cannot block), and the descriptor is `fstat`-checked: regular
//! file, same inode as pre-checked, one link, owner allowed, no denied mode bit, size within the
//! cap. Reads stop at cap + 1 bytes. Content is never printed.

#![allow(
    clippy::disallowed_methods,
    reason = "this tool is a safe-path reader itself: openat2(RESOLVE_NO_SYMLINKS|BENEATH) + O_NOFOLLOW, reviewed (AUD-RM2-DEP-24/26)"
)] // safefs-lint: allow(compiled config-check reader, ADR-055(3), same rules as candor-safefs)

use md5::{Digest, Md5};
use rustix::fs::{
    AtFlags, CWD, FileType, Mode, OFlags, ResolveFlags, Stat, fstat, openat, openat2, statat,
};
use rustix::io::Errno;
use std::os::fd::{AsFd, OwnedFd};

/// Exit / per-file status codes (identical to the former `safe-read.py`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    /// Copied (or digested).
    Ok = 0,
    /// Usage error.
    Usage = 2,
    /// Symlinked, swapped or `.`/`..` path component.
    Link = 10,
    /// Missing.
    Missing = 11,
    /// Not a regular file (FIFO, device, directory, ...).
    NotRegular = 12,
    /// Owner, mode or link count not allowed.
    Policy = 13,
    /// Larger than the cap.
    TooLarge = 14,
    /// Read/write error.
    Io = 15,
}

impl Status {
    /// Process exit code.
    #[must_use]
    pub fn code(self) -> u8 {
        self as u8
    }
}

/// What an input must satisfy.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Size cap in bytes.
    pub max_bytes: u64,
    /// Allowed owner uids.
    pub owners: Vec<u32>,
    /// Permission bits the file must not have.
    pub deny_mode: u32,
}

impl Policy {
    /// Parse `MAX-BYTES OWNERS(comma list) DENY-MODE(octal)`.
    ///
    /// # Errors
    /// [`Status::Usage`] on any malformed field or an empty owner list.
    pub fn parse(max: &str, owners: &str, deny: &str) -> Result<Self, Status> {
        let max_bytes = max.parse::<u64>().map_err(|_| Status::Usage)?;
        let mut list = Vec::new();
        for u in owners.split(',').filter(|u| !u.is_empty()) {
            list.push(u.parse::<u32>().map_err(|_| Status::Usage)?);
        }
        let deny_mode = u32::from_str_radix(deny, 8).map_err(|_| Status::Usage)?;
        if list.is_empty() || deny_mode > 0o7777 {
            return Err(Status::Usage);
        }
        Ok(Self {
            max_bytes,
            owners: list,
            deny_mode,
        })
    }
}

fn components(path: &str) -> Result<Vec<&str>, Status> {
    if !path.starts_with('/') {
        return Err(Status::Usage);
    }
    let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    if comps.is_empty() || comps.iter().any(|c| *c == "." || *c == "..") {
        return Err(Status::Link);
    }
    Ok(comps)
}

fn dir_errno(e: Errno) -> Status {
    if e == Errno::NOENT {
        Status::Missing
    } else {
        Status::Link
    }
}

/// Open the parent directory of `comps` (all but the last) without following any symlink.
fn open_parent(root: &OwnedFd, dirs: &[&str]) -> Result<OwnedFd, Status> {
    let dflags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let rel = if dirs.is_empty() {
        ".".to_string()
    } else {
        dirs.join("/")
    };
    let resolve = ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS | ResolveFlags::BENEATH;
    match openat2(root, rel.as_str(), dflags, Mode::empty(), resolve) {
        Ok(fd) => return Ok(fd),
        Err(e) if e != Errno::NOSYS => return Err(dir_errno(e)),
        Err(_) => {}
    }
    // Kernel without openat2 (< 5.6): walk component by component, never following.
    let mut cur = openat(root, ".", dflags, Mode::empty()).map_err(|_| Status::Io)?;
    for c in dirs {
        cur = openat(&cur, *c, dflags, Mode::empty()).map_err(dir_errno)?;
    }
    Ok(cur)
}

fn same_inode(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}

/// Read `path` under `policy`.
///
/// # Errors
/// The [`Status`] explaining why the input was refused.
pub fn read_checked(path: &str, policy: &Policy) -> Result<Vec<u8>, Status> {
    let comps = components(path)?;
    let (name, dirs) = comps.split_last().ok_or(Status::Link)?;
    let root = openat(
        CWD,
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Status::Io)?;
    let parent = open_parent(&root, dirs)?;
    let pre = statat(&parent, *name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| {
        if e == Errno::NOENT {
            Status::Missing
        } else {
            Status::Io
        }
    })?;
    match FileType::from_raw_mode(pre.st_mode) {
        FileType::Symlink => return Err(Status::Link),
        FileType::RegularFile => {}
        _ => return Err(Status::NotRegular),
    }
    let oflags =
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    let resolve = ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS | ResolveFlags::BENEATH;
    let fd = match openat2(&parent, *name, oflags, Mode::empty(), resolve) {
        Err(e) if e == Errno::NOSYS => openat(&parent, *name, oflags, Mode::empty()),
        r => r,
    }
    .map_err(|e| match e {
        Errno::NOENT => Status::Missing,
        Errno::LOOP | Errno::NOTDIR | Errno::XDEV => Status::Link,
        _ => Status::Io,
    })?;
    let st = fstat(&fd).map_err(|_| Status::Io)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(Status::NotRegular);
    }
    if !same_inode(&pre, &st) {
        return Err(Status::Link);
    }
    let mode = st.st_mode & 0o7777;
    if st.st_nlink != 1 || !policy.owners.contains(&st.st_uid) || mode & policy.deny_mode != 0 {
        return Err(Status::Policy);
    }
    let size = u64::try_from(st.st_size).map_err(|_| Status::Io)?;
    if size > policy.max_bytes {
        return Err(Status::TooLarge);
    }
    read_capped(&fd, policy.max_bytes)
}

fn read_capped<Fd: AsFd>(fd: Fd, max_bytes: u64) -> Result<Vec<u8>, Status> {
    let mut out = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = match rustix::io::read(&fd, &mut buf) {
            Ok(n) => n,
            Err(Errno::INTR) => continue,
            Err(Errno::AGAIN) => return Err(Status::NotRegular),
            Err(_) => return Err(Status::Io),
        };
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(buf.get(..n).ok_or(Status::Io)?);
        if u64::try_from(out.len()).map_err(|_| Status::Io)? > max_bytes {
            return Err(Status::TooLarge);
        }
    }
}

/// Write `data` to `out` (absolute; created 0600, never through a symlink, truncated).
fn write_out(out: &str, data: &[u8]) -> Result<(), Status> {
    if !out.starts_with('/') {
        return Err(Status::Usage);
    }
    let ofd = openat(
        CWD,
        out,
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| Status::Io)?;
    let mut rest = data;
    while !rest.is_empty() {
        match rustix::io::write(&ofd, rest) {
            Ok(0) => return Err(Status::Io),
            Ok(n) => rest = rest.get(n..).ok_or(Status::Io)?,
            Err(Errno::INTR) => {}
            Err(_) => return Err(Status::Io),
        }
    }
    Ok(())
}

/// Copy `path` to `out` (created 0600, never through a symlink, truncated).
///
/// # Errors
/// The [`Status`] of the refusal; `out` is not created when the input is refused.
pub fn copy(path: &str, out: &str, policy: &Policy) -> Result<(), Status> {
    if !out.starts_with('/') {
        return Err(Status::Usage);
    }
    let data = read_checked(path, policy)?;
    write_out(out, &data)
}

/// `--md5` mode: write one [`md5_line`] per path, in order, to `out`.
///
/// # Errors
/// [`Status::Usage`] / [`Status::Io`] when `out` cannot be written.
pub fn write_md5_report(out: &str, paths: &[String], policy: &Policy) -> Result<(), Status> {
    let mut report = String::new();
    for p in paths {
        report.push_str(&md5_line(p, policy));
        report.push('\n');
    }
    write_out(out, report.as_bytes())
}

/// One `--md5` result line: `OK <hex>` or `ERR <status>` (no path, no content).
#[must_use]
pub fn md5_line(path: &str, policy: &Policy) -> String {
    match read_checked(path, policy) {
        Ok(data) => {
            let d = Md5::digest(&data);
            let mut s = String::from("OK ");
            for b in d.iter() {
                s.push_str(&format!("{b:02x}"));
            }
            s
        }
        Err(st) => format!("ERR {}", st.code()),
    }
}
