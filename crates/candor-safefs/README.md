# candor-safefs

Licence: Apache-2.0 OR MIT (ADR-031). Trust tier T0 (27 §4); on the audit list.

This crate is Candor's single audited safe-path API (ADR-027). Every filesystem
read or write of an object that exists because of source, recipient or server
input must go through it: blobs, staging parts, extraction scratch and export
packages. `scripts/lint-safefs.sh` fails CI when any other crate uses direct
filesystem path APIs, path joins or archive extraction (ST-005, SDL-030,
BE-009).

## Why

SecureDrop has had server-controlled path traversal three times: TOB-SDW-012 in
2020, CVE-2025-24888 in 2025 and CVE-2026-35465 in 2026, the last one through
an absolute path in the gzip FNAME header. OnionShare CVE-2026-54706 followed
symlinks out of the shared directory. Each fix was a check at one call site, so
the bug came back in the next parser. This crate removes the whole class
instead:

- Names come only from `ObjectId` (128-bit random, or a keyed BLAKE3 content
  hash), shown as `[a-z2-7]{26}`. No API takes a `&str` or `Path` name.
- Every open is one path component relative to a `cap-std` directory handle.
  On Linux that handle uses `openat2(RESOLVE_BENEATH)`. The crate adds
  `O_NOFOLLOW` on every component and checks the inode type, owner, mode,
  link count and device with `fstat` after each open.
- Display names (`DisplayName`) are metadata only and are sanitized. They can
  never be passed back into the store.

## API

```rust
use candor_safefs::{SafeRoot, RootPolicy, SlotTime, ObjectId, ContentKey, DisplayName};
use std::io::Write;

let root = SafeRoot::open(Path::new("/var/lib/candor/intake/blobs"), RootPolicy::BlobStore)?;
let slot = SlotTime::from_unix_secs(import_slot_start)?;   // must be 15-min aligned (ADR-038(1))

let mut w = root.create_random()?;            // or create_new(&id), create_content_addressed(&key)
w.write_all(ciphertext)?;
let id: ObjectId = w.commit(slot)?;           // atime/mtime=slot, fsync, renameat2(NOREPLACE), dir fsync

let r = root.open_read(&id)?;                 // refuses symlink / hardlink / FIFO / device / wrong mode
root.remove(&id, slot)?;
root.purge_incomplete(slot)?;                 // start-up: delete temp files left by a crash

let name = DisplayName::sanitize(declared_name);   // plain-text rendering only
```

Archive extraction runs only in the L1 viewer VM (FILE-019):

```rust
use candor_safefs::archive::{extract_zip, extract_tar, extract_tar_gz, extract_gzip, ExtractOptions};
let report = extract_zip(file, &scratch_root, &ExtractOptions::new(slot))?;
for m in &report.members { /* m.id, m.display_name, m.size, m.nested_archive */ }
for r in &report.rejected { /* r.reason → flag */ }
```

### Root layout

| Policy | Layout | Use |
|---|---|---|
| `BlobStore` | `<root>/<2-char shard>/<26-char id>` | intake and core blobs (07 §4) |
| `Staging` | `<root>/<26-char id>` | Tier W tmpfs staging (ADR-034) |
| `Scratch` | `<root>/<26-char id>` | extraction inside the viewer VM |

The root must be an absolute, normalized path. No component may be a symlink.
The root must be owned by the effective uid and have mode 0700. Shard
directories are created with mode 0700 and objects with mode 0600.

### Guarantees

| Property | Mechanism | Tests |
|---|---|---|
| No write or read outside the root | cap-std `RESOLVE_BENEATH`; one component per open; `O_NOFOLLOW`; `open_dir_nofollow` for shards; same-device check | `tests/store.rs` symlinked shard/object/root, proptest |
| Atomic, durable, never replaces | temp file opened `O_CREAT\|O_EXCL\|O_NOFOLLOW` with mode 0600, then `fsync`, then `renameat2(RENAME_NOREPLACE)` (fallback `linkat` + `unlinkat`), then directory `fsync` | `fixed_id_never_replaces`, `uncommitted_write_leaves_nothing_and_purge` |
| Timestamps show only the slot | file, shard and root atime/mtime set to `SlotTime` | `roundtrip_mode_layout_and_slot_times` |
| Special files refused | `fstat`: regular file, `nlink == 1`, owner, mode, device; `O_NONBLOCK` so a FIFO cannot block the open | `fifo_and_dir_objects…`, `hardlinked_object…` |
| No content confirmation from names | content ids are **keyed** BLAKE3 (FILE-005) | `content_addressed_dedup_and_keyed` |

### Archive limits (10 §10, `LP-DEFAULT` / hard ceiling)

entries 10,000 / 100,000 · total 4 GiB / 32 GiB · ratio 100:1 / 1000:1 ·
nesting 3 / 5 · path 1024 bytes / 32 components. The per-entry size limit
defaults to the total. Every limit is enforced on bytes the decompressor
actually produced. Declared sizes are never trusted.

**Whole archive refused:** any limit is hit; ZIP local-header or data ranges
overlap (Fifield); the zip crate collapsed duplicate central-directory
records; the central and local header disagree on name or offset; data
precedes the first header; the CRC is wrong; a tar pax `size` override is
present; a pax header is over 64 KiB. After any of these, every member already
written is removed.

**Member rejected and flagged:** absolute path, drive letter or UNC prefix;
`..`; NUL byte; name too long or too deep; symlink; hardlink; device, FIFO or
socket; sparse file; duplicate name after NFC; encrypted member; compression
other than stored or deflate.

The gzip FNAME, FCOMMENT and FEXTRA header fields are never read. Extraction
is never recursive. A member that looks like an archive is flagged with
`nested_archive`, and the caller must extract it explicitly at
`nesting_level + 1`.

## Lint

```sh
crates/candor-safefs/scripts/lint-safefs.sh                 # src/ and build.rs of every other crate
crates/candor-safefs/scripts/lint-safefs.sh --include-tests # also tests/, benches/, examples/
```

To exempt a line, add `// safefs-lint: allow(<reason>)`. The reason must not be
empty. The primary gate is the workspace `clippy.toml` (`disallowed-methods`
for `std::fs::*`, `Path::join`, `rustix::fs`/`libc`/`nix` file calls,
`disallowed-types` for `tar::Archive`/`zip::ZipArchive`), enforced by the CI
clippy job; only this crate opts out, per module with a reasoned `allow`. The
script covers what clippy cannot: banned dependencies (also renamed or
table-form, via `cargo metadata`), `allow(clippy::disallowed_*)` elsewhere,
crate-local `clippy.toml` files, plus a grep layer. It fails closed (exit 2) if
grep, cargo or jq fail, and runs on the real workspace in CI (`repo-lints`).

## Testing

```sh
cargo test -p candor-safefs
```

The suite has 69 tests: unit tests, property tests (name sanitizer, id
round-trip, store round-trip, arbitrary archive names, random bytes into every
extractor), store confinement tests and a malicious-archive suite. The
malicious archives are built by hand in `tests/common`: zip slip, symlinks,
devices, absolute paths, ratio bombs, Fifield shared-header and
quoted-overlap bombs, central/local name mismatch, lying declared sizes, NFC
duplicates, nesting, GNU long-name and pax traversal, pax size override, gzip
FNAME injection and tar.gz bombs.
