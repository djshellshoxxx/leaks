# candor-safefs — spec notes

Sources: ADR-027, ADR-031, ADR-038(1); 07 §4 and §10 (BE-008, BE-009);
09 DB-028; 10 §9, §10 and H7 (FILE-005, FILE-019, FILE-020); 27 SDL-030;
29 ST-005, ST-048, ST-080, ST-081 and ST-086; R1 I-1, I-2, I-8 and I-9;
R5 B-CR-52.

## Implementation decisions

1. **cap-std instead of hand-written `openat2` (07 §64, BE-009).** 07 lets
   this crate use `unsafe` for `openat2`. The workspace forbids `unsafe_code`,
   and the assignment asks for `cap-std`, so the crate has **no `unsafe`**.
   cap-std (via rustix) uses `openat2(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)`
   when the kernel has it, and otherwise falls back to its own checked
   component-by-component resolution. `RESOLVE_NO_SYMLINKS` and
   `RESOLVE_NO_XDEV` are reproduced on top of it as follows:
   - every open is one component relative to a directory handle, with
     `O_NOFOLLOW` (`FollowSymlinks::No`, `open_dir_nofollow`);
   - after each open, `fstat` checks the type, owner (euid), mode (no
     group/other bits), `nlink == 1` for files, and `st_dev == root st_dev`.
2. **Root opening.** The root path is operator configuration, so it is
   resolved with ambient authority. To make that safe: the path must be
   absolute and must not contain `.` or `..`; every ancestor is `lstat`ed and
   **any symlinked component is refused**, which is stricter than 07 asks
   (CVE-2026-54706 class); and the opened handle's dev and inode must match
   the walked path. If a deployment has a symlinked prefix (for example
   `/var -> /private/var` on macOS), the operator must configure the
   canonical path.
3. **Renames never replace.** On Linux, commit uses
   `renameat2(RENAME_NOREPLACE)`. If that returns `EINVAL` or `ENOSYS`, and on
   other unixes, it uses `linkat` + `unlinkat`. Both are atomic and never
   replace an existing object. Content-addressed duplicates are deduplicated:
   the existing object is kept and the temp file is removed. A collision on a
   fixed id returns `AlreadyExists`.
4. **fsync.** 07 says `fdatasync`. We use `fsync` (`sync_all`) because the
   normalized timestamps are metadata and must be durable as well.
5. **Slot time (ADR-038(1), DB-028).** `SlotTime` must be a multiple of
   15 minutes, so a raw "now" cannot be passed by mistake. Fixed import slots
   and `utc_day_start` both satisfy this. atime and mtime are set on the
   object and on every directory a commit or remove modifies (shard, and root
   when a shard is created), because directory mtimes would otherwise reveal
   event times. **Residual:** ctime cannot be set from userspace and records
   the real change time. A `noatime` mount and the fixed import schedule
   (ADR-038) remain necessary.
6. **Content-addressed names use keyed hashes.** The assignment allows names
   derived from a content hash. FILE-005 forbids plaintext hashes in blob
   names because of the confirmation attack. Content ids are therefore
   `BLAKE3-keyed(ContentKey, content)[..16]`. `ContentKey` is zeroized and
   redacted in `Debug`. Random ids remain the default.
7. **Directory fds.** cap-std directory handles are `O_PATH` on Linux, so
   `futimens` and `fsync` fail with `EBADF`. To normalize and sync a directory,
   the crate opens `"."` relative to the handle with
   `O_RDONLY|O_DIRECTORY|O_NOFOLLOW`. This cannot leave the handle.
8. **Opens never block.** Reads and creates use `O_NONBLOCK|O_NOCTTY`, so a
   planted FIFO or tty is refused instead of hanging the open.
9. **Display names.** The assignment requires stripping C0, DEL and C1
   control characters and the bidi overrides U+202A..E and U+2066..9, plus a
   255-byte limit. We also strip U+061C, U+200E, U+200F (bidi marks) and
   U+2028/2029. As defense in depth, `/`, `\` and `:` are replaced by
   look-alike characters (U+2215, U+29F5, U+2236), and an all-dots name
   becomes U+2024 characters, so even a misused display name is one harmless
   path component. The name is NFC-normalized. Truncation is on a char
   boundary and appends `…`. An empty name becomes `(unnamed)`. `Debug` prints
   only the length (EVID-008). The type implements neither `AsRef<Path>` nor
   `AsRef<OsStr>`.
10. **Ratio limits.** 10 §10 says "100:1 per member and total". For ZIP, the
    per-member ratio uses the central-directory compressed size. The zip
    crate never reads more compressed bytes than that, so this bounds real
    work. The total ratio is produced bytes against the archive length.
    gzip compresses the whole tar.gz stream as one, so a per-member ratio is
    not defined there. tar.gz and gzip get a **running total ratio**: bytes
    out of the decompressor against compressed bytes consumed, which includes
    tar headers and the data of skipped members. The decoder reads ahead
    (≤ 32 KiB), so the running check can lag by at most read-ahead × ratio.
    That is bounded and still under the total limit. A strict reading means
    small, very compressible benign files (for example 2 KiB of zeros) are
    refused. That fails closed and was kept on purpose.
11. **Per-entry size limit.** 10 §10 does not name one. The default is the
    total limit (4 GiB, matching the 4 GiB ORIGINAL cap) and it is
    configurable within the 32 GiB ceiling.
12. **Nesting.** Extraction is never recursive (assignment, ADR-012). 10 §9
    says "processed recursively (depth ≤ 3)". Here the caller drives each
    level explicitly with `ExtractOptions::nesting_level`, which is 1 for an
    ORIGINAL. A level above `max_nesting_depth` is refused with
    `LimitHit(NestingDepth)`. Nested archives are detected by magic bytes:
    zip, gzip, bzip2, xz, zstd, 7z, rar, cab, arj, lzip, and `ustar` at
    offset 257.
13. **Rejection granularity.** 10 §10 says "reject member (flag)". These cases
    are rejected per member: traversal, absolute paths, links, devices,
    duplicates, encrypted members, unsupported methods and sparse files.
    Constructs that show the archive itself is hostile or ambiguous reject
    the **whole archive**, which is stricter: overlapping ZIP ranges
    (Fifield), duplicate central records collapsed by the zip crate,
    central/local header disagreement, data before the first local header,
    pax `size` override, an oversized pax header, and repeated long-name
    headers. Any archive-level failure removes every member already written.
14. **zip parser differentials found and closed.**
    (a) zip 4.6.1 keys entries by name and silently drops duplicate
    central-directory names. The crate counts the central records itself and
    requires the count to match.
    (b) The local header name is compared byte-for-byte with the central name,
    and the data offset is recomputed.
    (c) Archives with a non-zero prefix offset (SFX or polyglot) are refused.
    Stage 0 is responsible for polyglots (FILE-018).
15. **tar parsed in raw mode.** tar 0.4.46 (`Entry::read_all`) buffers GNU
    long-name and pax headers without any size bound, which allows a memory
    bomb. The crate therefore iterates in raw mode and reads these headers
    itself with bounds: long names ≤ `max_path_bytes + 1`, pax ≤ 64 KiB, and
    extension headers ≤ 3 × `max_entries` + 16. Pax `size` is refused
    (in raw mode the crate would not apply it, creating a parser differential with GNU tar).
    A pax global `path` is refused. `GNU.sparse.*` marks the member as sparse,
    which is rejected. Contiguous files (`'7'`) are treated as regular files.
    Directories are counted and checked but never created.
16. **Compression methods.** ZIP members may be stored or deflate only
    (minimal dependency surface). Other methods are flagged
    `UnsupportedCompression`. Encrypted members are flagged, never decrypted:
    passwords are handled only inside L2 (10 §9.5).
17. **Duplicate key.** Duplicates are detected after NFC, with `/` and `\`
    treated as the same separator and empty and `.` components dropped.
    Case-insensitive collisions are not treated as duplicates: names are
    never paths, and 10 §10 specifies NFC only.
18. **Platform.** The crate is unix-only for now and fails at compile time
    otherwise. Windows Desk (Tier 2, ADR-042) needs a separate audited
    backend, so it is left as a TODO rather than a silent weakening.
19. **Lint scope.** `scripts/lint-safefs.sh` scans `crates/*/src/**` and
    `build.rs` by default; `--include-tests` adds `tests/`, `benches/` and
    `examples/`. It also bans `tar`, `zip`, `cap-std` and related
    dependencies in other crates' manifests. The path-join rule is a
    heuristic: it flags `.join(` and `.push(` on receivers whose names
    contain path, dir, root, base, dest, dst, target or folder. False
    positives need an `allow(<reason>)` marker. Semgrep taint rules and clippy
    `disallowed-methods` (07 §10, ST-005) live in workspace configuration,
    which this crate cannot edit.

## Spec feedback

- 07 §64 lists `candor-safefs` among the crates allowed `unsafe`. It is not
  needed (decision 1). Suggest removing it from that list.
- 07 §10 example `w.commit()` takes no time argument. DB-028 and ADR-038(1)
  require timestamp normalization, so `commit(slot)` should be the spec'd
  signature.
- 10 §10 "ratio per member and total" is undefined for stream-compressed tar
  formats (decision 10). Suggest wording: "per member where the container
  records per-member compressed sizes; otherwise running total".
- 10 §9 "processed recursively" conflicts with the non-recursive default.
  Suggest "each nesting level is extracted by an explicit job".
- FILE-005 vs "content-addressed storage" in ADR-027: suggest saying
  explicitly that content addressing must be keyed.

## Dependencies (exact pins)

| Crate | Version | Why |
|---|---|---|
| cap-std | =3.4.5 | capability directory handles, `RESOLVE_BENEATH` confinement (assignment, BE-009) |
| cap-fs-ext | =3.4.5 | `open_dir_nofollow`, `FollowSymlinks::No` |
| rustix | =1.1.2 | safe `fstat`, `renameat2(NOREPLACE)`, `linkat`, `openat`, `geteuid` without `unsafe` (already a cap-std dependency) |
| getrandom | =0.4.3 | OS CSPRNG for 128-bit object ids and temp names |
| blake3 | =1.8.2 | keyed content hash for content-addressed ids (FILE-005) |
| zeroize | =1.8.2 | wipe `ContentKey` on drop |
| unicode-normalization | =0.1.24 | NFC for display names and duplicate detection (10 §10) |
| zip | =4.6.1 | ZIP central-directory parsing and deflate decoding; limits enforced here |
| tar | =0.4.46 | tar header parsing in raw mode (latest release, past RUSTSEC-2026-0068) |
| flate2 | =1.1.5 | gzip/deflate decoding (zlib-rs backend: no C, no `unsafe` FFI) |
| proptest (dev) | =1.11.0 | property tests (workspace pin) |
| tempfile (dev) | =3.23.0 | test roots |

## Test map

| ID | Tests |
|---|---|
| ST-005 / SDL-030 | `tests/lint.rs` |
| ST-048 (property form + cargo-fuzz targets in fuzz/: fuzz_safefs_names, fuzz_archive_{zip,tar,tar_gz}) | `id::tests::*`, `display::tests::*`, `archives::props::*`, `store::props::*` |
| ST-080 | `display::tests::st080_corpus`, `zip_slip_*`, `tar_traversal_*` |
| ST-081 / FILE-019 | `tests/archives.rs` (all) |
| ST-086 / CVE-2026-54706 | `symlinked_shard_dir_is_refused`, `symlinked_object_is_refused…`, `root_policy_checks`, `zip_symlink_*`, `tar_traversal_links_devices` |
| FILE-020 (in-process half) | `*_bomb*`, `*_limits`, `zip_lying_declared_size_counts_real_bytes` |
| CVE-2026-35465 | `gzip_fname_injection_and_bomb`, `tar_gz_header_filename_ignored` |
| DB-028 / ADR-038(1) | `roundtrip_mode_layout_and_slot_times` |
| FILE-005 | `content_addressed_dedup_and_keyed` |

## Open items

- RESOLVED: cargo-fuzz targets `fuzz_safefs_names` (ST-048) and
  `fuzz_archive_{zip,tar,tar_gz}` (ST-049) live in `fuzz/`, with committed
  seeds in `fuzz/seeds/<target>/` (nightly cargo-fuzz runs pending in CI).
- Host-side enforcement for FILE-020 (cgroups, VM memory, timers) is in C-17,
  not here. The wall-clock limit is also C-17's job.
- RESOLVED: CI job `test-nonroot` runs the workspace tests as an unprivileged user,
  so the foreign-owner refusal path is exercised.

## Fixes for AUD-RM1-SFS (audit `process/audits/AUDIT-RM1-safefs-log.md`)

| Finding | Fix | Regression test |
|---|---|---|
| SFS-01 (M) lint bypassable / not in CI | Workspace `clippy.toml` now bans `std::fs::*` path APIs, `File::open/create/options`, `OpenOptions::open`, `DirBuilder::create`, `Path::join`/`PathBuf::push`, `rustix::fs`/`libc`/`nix` open/rename/link/unlink families (`disallowed-methods`) and `tar::Archive`/`zip::ZipArchive` (`disallowed-types`); type-resolved, so `extern crate std as s; s::fs::write` is caught. This crate opts out per module (`store`, `archive/*`) with a reasoned `#![allow]`. `lint-safefs.sh` now: no `^\*` comment skip, no `[^:]` exclusion, extra rustix/libc/nix/`extern crate std as` patterns, rejects `allow(clippy::disallowed_*)` outside this crate and any crate-local `clippy.toml` (it would replace the workspace bans), parses table-form/renamed deps and resolves deps with `cargo metadata` + `jq` when a workspace manifest exists, and fails closed (exit 2) on any grep/cargo/jq error (command substitution, not process substitution). CI job `repo-lints` runs it on the real tree. | `tests/lint.rs::audit_bypasses_are_caught`, `renamed_dependency_resolved_through_cargo_metadata` |
| SFS-02 (M) invisible/format chars, confusable dots | `DisplayName` removes every `Default_Ignorable_Code_Point` (zero-width chars, U+FEFF, soft hyphen, CGJ, variation selectors, Mongolian FVS, tag/ignorable block U+E0000–E0FFF, Hangul fillers U+115F/1160/3164/FFA0, …), all other `Cf`, private use, noncharacters and the braille blank U+2800; whitespace runs collapse to one ASCII space and are trimmed; the all-dots check runs on NFKC (fullwidth `．．` → U+2024 U+2024); over-long names are truncated in the middle keeping the final extension visible (`head…ext`). The DI table is hand-written from Unicode 16 DerivedCoreProperties (no new dependency); unassigned (`Cn`) code points are not tracked (would need a Unicode data dependency) — residual. | `display::tests::invisible_and_filler_characters_removed`, `truncation_keeps_extension_visible`, proptests `fillers_never_survive`, `invariants`; fuzz oracle extended |
| SFS-03 (L) aborted write leaves root mtime | `PendingObject` records the root's atime/mtime before creating its temp file and restores them (futimens + fsync) when dropped without commit. ctime still changes (documented residual, unchanged). | `tests/store.rs::dropped_pending_object_restores_root_times` |
| SFS-04 (L) Debug leaks path/sizes | Manual `Debug` for `ObjectReader` (nothing), `PendingObject` (poisoned flag only), `ExtractedMember` (no size), `ExtractionReport` (no `total_bytes`). | `debug_output_has_no_path_or_size`, `report_debug_has_no_sizes` |
| SFS-05 (L) best-effort rollback | `finish` returns `ArchiveError::RollbackIncomplete(Vec<ObjectId>)` when any stored member cannot be removed (NotFound counts as removed); callers must remove them or destroy the scratch root. | `archive::tests::incomplete_rollback_is_reported` |
| SFS-06 (L) per-entry extension cap | The extension-header counter is archive-wide; a second local pax header for one entry is `Malformed`. | `tar_extension_header_cap_is_archive_wide` |
| SFS-07 (L) writes after failure | Any failed write poisons the `PendingObject`; later writes and `commit` fail. | `store::tests::failed_write_poisons_pending_object` |
| SFS-08 (I) | `ContentKey` no longer `Clone`. Fuzz seed corpora committed (`fuzz/seeds/`, from small ustar/GNU/pax tars, tar.gz, stored/deflate zips, hostile names): 30 s smoke runs reach cov 1114–1795 on the archive targets (was 160–273). **Deferred (justified):** `O_TMPFILE` + `linkat(AT_EMPTY_PATH)` needs `CAP_DAC_READ_SEARCH` or `/proc` access, which conflicts with the confinement profile — the named temp file plus SFS-03 time restore and `purge_incomplete` stay; the inotify "no inode outside root" test needs a new dependency and is left to the C-17 integration suite; the nightly fuzz CI job is left to the lead (ci.yml was limited to one additive job). | — |
| SFS-09 (I) local/central cross-check | Local header method, encryption flag and (without data descriptor) CRC and sizes must equal the central directory; every member range must end before the central directory. | `zip_local_central_field_mismatch_rejected` |

### Security self-review (this pass)

Re-read as an attacker: no new path composition (the time restore uses the
root handle and "."), no new allocation driven by input, no new panics
(`as _` only widens `st_*time_nsec` into `Timespec`), errors still carry no
names/paths (RollbackIncomplete prints a count; its ids are random storage
ids). Residuals: ctime of the root still records abort time; display-name
`Cn` code points survive; the grep layer remains a heuristic behind clippy.
