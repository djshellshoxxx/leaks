// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Test helpers: hand-built hostile archives (no extraction library is used
//! to build them, so the fixtures can violate every rule).
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::panic)]

use candor_safefs::{RootPolicy, SafeRoot, SlotTime};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const SLOT: u64 = 1_790_000_100 - (1_790_000_100 % 900);

pub fn slot() -> SlotTime {
    SlotTime::from_unix_secs(SLOT).unwrap()
}

/// Temp dir layout: `<tmp>/outside` (canary area) and `<tmp>/root` (0700).
pub struct Env {
    pub tmp: tempfile::TempDir,
    pub root_path: PathBuf,
    pub outside: PathBuf,
}

pub fn env() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(tmp.path()).unwrap();
    let root_path = base.join("root");
    let outside = base.join("outside");
    std::fs::create_dir(&outside).unwrap();
    mkdir_0700(&root_path);
    Env { tmp, root_path, outside }
}

pub fn mkdir_0700(p: &Path) {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(p).unwrap();
}

impl Env {
    pub fn root(&self, policy: RootPolicy) -> SafeRoot {
        SafeRoot::open(&self.root_path, policy).unwrap()
    }
    /// Every file anywhere under the temp base except inside the root.
    pub fn files_outside_root(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        walk(&std::fs::canonicalize(self.tmp.path()).unwrap(), &self.root_path, &mut out);
        out
    }
}

fn walk(dir: &Path, skip: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p == skip {
            continue;
        }
        let md = std::fs::symlink_metadata(&p).unwrap();
        if md.is_dir() {
            walk(&p, skip, out);
        } else {
            out.push(p);
        }
    }
}

pub fn crc(data: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(data);
    c.sum()
}

pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// One central-directory record.
#[derive(Clone)]
pub struct Cd {
    pub name: Vec<u8>,
    pub method: u16,
    pub flags: u16,
    pub crc: u32,
    pub csize: u32,
    pub usize: u32,
    pub offset: u32,
    pub unix_mode: Option<u32>,
}

pub fn local_header(name: &[u8], method: u16, flags: u16, crc: u32, csize: u32, usize: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    v.extend_from_slice(&20u16.to_le_bytes());
    v.extend_from_slice(&flags.to_le_bytes());
    v.extend_from_slice(&method.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes()); // time
    v.extend_from_slice(&0x21u16.to_le_bytes()); // date 1980-01-01
    v.extend_from_slice(&crc.to_le_bytes());
    v.extend_from_slice(&csize.to_le_bytes());
    v.extend_from_slice(&usize.to_le_bytes());
    v.extend_from_slice(&(name.len() as u16).to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(name);
    v
}

/// Appends central directory + EOCD for `cds` to `body`.
pub fn finish_zip(mut body: Vec<u8>, cds: &[Cd]) -> Vec<u8> {
    let cd_start = body.len() as u32;
    for c in cds {
        let (made_by, ext) = match c.unix_mode {
            Some(m) => ((3u16 << 8) | 20, m << 16),
            None => (20u16, 0u32),
        };
        body.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        body.extend_from_slice(&made_by.to_le_bytes());
        body.extend_from_slice(&20u16.to_le_bytes());
        body.extend_from_slice(&c.flags.to_le_bytes());
        body.extend_from_slice(&c.method.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0x21u16.to_le_bytes());
        body.extend_from_slice(&c.crc.to_le_bytes());
        body.extend_from_slice(&c.csize.to_le_bytes());
        body.extend_from_slice(&c.usize.to_le_bytes());
        body.extend_from_slice(&(c.name.len() as u16).to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // extra
        body.extend_from_slice(&0u16.to_le_bytes()); // comment
        body.extend_from_slice(&0u16.to_le_bytes()); // disk
        body.extend_from_slice(&0u16.to_le_bytes()); // int attr
        body.extend_from_slice(&ext.to_le_bytes());
        body.extend_from_slice(&c.offset.to_le_bytes());
        body.extend_from_slice(&c.name);
    }
    let cd_size = body.len() as u32 - cd_start;
    body.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&(cds.len() as u16).to_le_bytes());
    body.extend_from_slice(&(cds.len() as u16).to_le_bytes());
    body.extend_from_slice(&cd_size.to_le_bytes());
    body.extend_from_slice(&cd_start.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body
}

/// Spec for a well-formed zip member.
pub struct Z<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
    pub unix_mode: Option<u32>,
    pub deflate: bool,
    pub flags: u16,
    pub method_override: Option<u16>,
}

pub fn z<'a>(name: &'a [u8], data: &'a [u8]) -> Z<'a> {
    Z { name, data, unix_mode: None, deflate: false, flags: 0, method_override: None }
}

pub fn zip(entries: &[Z<'_>]) -> Vec<u8> {
    let mut body = Vec::new();
    let mut cds = Vec::new();
    for e in entries {
        let (method, payload) = if e.deflate { (8u16, deflate(e.data)) } else { (0u16, e.data.to_vec()) };
        let method = e.method_override.unwrap_or(method);
        let c = crc(e.data);
        let offset = body.len() as u32;
        body.extend(local_header(e.name, method, e.flags, c, payload.len() as u32, e.data.len() as u32));
        body.extend_from_slice(&payload);
        cds.push(Cd {
            name: e.name.to_vec(),
            method,
            flags: e.flags,
            crc: c,
            csize: payload.len() as u32,
            usize: e.data.len() as u32,
            offset,
            unix_mode: e.unix_mode,
        });
    }
    finish_zip(body, &cds)
}

/// A raw ustar header block.
pub fn tar_header(name: &[u8], size: u64, typeflag: u8, linkname: &[u8]) -> [u8; 512] {
    let mut h = [0u8; 512];
    let n = name.len().min(100);
    h[..n].copy_from_slice(&name[..n]);
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    h[136..148].copy_from_slice(b"00000000000\0");
    h[156] = typeflag;
    let l = linkname.len().min(100);
    h[157..157 + l].copy_from_slice(&linkname[..l]);
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

pub struct TarBuf(pub Vec<u8>);

impl TarBuf {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn entry(&mut self, name: &[u8], typeflag: u8, data: &[u8]) -> &mut Self {
        self.entry_link(name, typeflag, data, b"")
    }
    pub fn entry_link(&mut self, name: &[u8], typeflag: u8, data: &[u8], link: &[u8]) -> &mut Self {
        self.0.extend_from_slice(&tar_header(name, data.len() as u64, typeflag, link));
        self.0.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        self.0.extend(std::iter::repeat_n(0u8, pad));
        self
    }
    pub fn pax(&mut self, records: &[(&str, &str)]) -> &mut Self {
        let mut body = Vec::new();
        for (k, v) in records {
            let base = k.len() + v.len() + 3; // ' ' '=' '\n'
            let mut len = base + 1;
            while format!("{len}").len() + base != len {
                len += 1;
            }
            body.extend_from_slice(format!("{len} {k}={v}\n").as_bytes());
        }
        self.entry(b"PaxHeader", b'x', &body)
    }
    pub fn finish(mut self) -> Vec<u8> {
        self.0.extend(std::iter::repeat_n(0u8, 1024));
        self.0
    }
}

pub fn gzip(data: &[u8], fname: Option<&[u8]>) -> Vec<u8> {
    let mut b = flate2::GzBuilder::new();
    if let Some(f) = fname {
        b = b.filename(f);
    }
    let mut e = b.write(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}
