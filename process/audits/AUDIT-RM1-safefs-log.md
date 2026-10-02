# AUDIT-RM1-safefs-log — Independent secure-code audit of `crates/candor-safefs` and `crates/candor-log`

| Field | Value |
|---|---|
| Step | RM-1 (IMPL-RM1 §1.6 `candor-safefs` T0, §1.7 `candor-log` T1) |
| Audited commit | `60e732f9dab712cf23c1335321edac15b9ba6fc9` (both crates clean in the working tree at audit time) |
| Scope | `crates/candor-safefs/{Cargo.toml, src/**/*.rs (8 files, 2,207 lines), tests/*, fuzz/**, scripts/lint-safefs.sh}`; `crates/candor-log/{Cargo.toml, clippy.toml, src/*.rs (15 files, 5,834 lines), tests/**, audit/schema.yaml, scripts/lint-logging.*}` |
| Auditor | Independent auditor helper (did not write this code) |
| Date | 2026-10-01 |
| Method | `process/AUDIT-CHECKLIST.md` v1.0 (A1–A5, B1–B12, C, D, E), `research/R9-secure-code-audit.md`, BUILD-BRIEF "Security and OPSEC bar", IMPL-RM1 §4 (A7, A11, A12, A14, A15) |
| Spec basis | ADR-016, ADR-027, ADR-037(3), ADR-038(1), ADR-046(5); 10 §9–§10; 20 (all, esp. §4, §6, §7, §8, §12, §13); 24 §TEL / §9.3–§9.6 (TEL-010/011/015/016); IMPL-RM1 §1.6, §1.7, §9.1 |

## Summary

| Severity | Count | Open |
|---|---|---|
| Critical | 0 | 0 |
| High | 2 | 2 |
| Medium | 10 | 10 |
| Low | 8 | 8 |
| Info | 4 | 4 |

By crate: candor-safefs: 0 H / 2 M / 5 L / 2 I. candor-log: 2 H / 8 M / 3 L / 2 I.

**Gate status: FAIL.** Two High findings are open in `candor-log`, and both must be fixed and re-tested (§F.1):
- **AUD-RM1-LOG-01**: the verifier accepts a redacted stub for any record in any stream, with no tombstone binding. An insider can erase the content of any SECURITY/SYSTEM event and `verify_stream` still passes.
- **AUD-RM1-LOG-02**: checkpoints are emitted only when something is pending, and they carry an exact `signed_at` and a seq range. This lets the external witness, and anyone else holding checkpoints, recover the time and count of date-only events (`case.imported`, `evidence.imported`) to within a tick. That defeats ADR-038(1)/P-17 and the Z-INTAKE hour truncation.

`candor-safefs` is solid. The confinement design holds: cap-std handles, single-component opens with `O_NOFOLLOW`, fstat type/owner/mode/nlink/dev checks, no-replace rename, keyed content ids and no name→path API. The archive readers enforce limits on bytes actually produced, refuse zip duplicate and overlap differentials, and parse tar extension headers with bounds of their own. I found no confinement escape, no bomb bypass and no panic. Its findings are about the enforcement lint, display-name Unicode hygiene, and minor metadata and cleanup gaps.

## Time per phase (approximate)

A1 10 % · A2 10 % · A3 manual review 50 % · A4 tools + PoCs 25 % · A5 report 5 %.

## A1. Tier classification

| File | Tier | Depth |
|---|---|---|
| safefs `store.rs`, `id.rs`, `time.rs`, `error.rs`, `display.rs`, `archive/{mod,zip_impl,tar_impl}.rs` | T0 (IMPL §1.6) | every line |
| safefs `scripts/lint-safefs.sh`, `tests/*`, `fuzz/fuzz_targets/*` | T2 (evidence / gate) | read in full |
| log `chain.rs`, `verify.rs`, `cbor.rs`, `envelope.rs`, `field.rs`, `ids.rs`, `sensitive.rs`, `diag.rs`, `sink.rs`, `metrics.rs`, `export.rs`, `retention.rs`, `codes.rs` (API surface), `event.rs` (catalog + time policy) | T1 | every line (`codes.rs`/`event.rs`: macros, constructors and time policy; catalog skimmed against 20 §5 and `audit/schema.yaml`) |
| log `scripts/lint-logging.sh`, `tests/**` | T2 | read |

## A2. Threat model

**Inputs and trust boundaries.**
- *safefs:* hostile archive bytes and member names from sources. They arrive over Tor and Stage 0, and are extracted in the viewer VM Scratch root (ADV source-attacker). Operator-configured root paths. A same-uid local process is out of scope (it could do anything the service can).
- *log:* developer/caller code in trust-path crates, which may misuse the API or launder data. Stored JSONL/DB records read back by the verifier (ADV insider/admin with DB write, ADV-compromised host). Checkpoints handed to an external witness. Published §TEL tables read by M2/M3 audiences (ADV statistical attacker).

| # | Attacker goal | Result |
|---|---|---|
| G1 | Write or read outside a SafeRoot via a member name (`..`, absolute, NUL, Unicode dots, symlink/hardlink entries) | **Refuted.** Names never become paths (random `ObjectId`); `check_member_path` flags; store opens single components with `O_NOFOLLOW` + fstat checks (store.rs:222-289); fuzz `fuzz_safefs_names` |
| G2 | Archive bomb (ratio, declared-size lie, overlapping zip, pax/long-name memory bomb) | **Refuted.** Limits on produced bytes (mod.rs:383-418), Fifield overlap + CD-count + local/central cross-check (zip_impl.rs:90-191), raw-mode tar with bounded extension reads (tar_impl.rs:189-322); minor per-entry header cap bug → SFS-06 (Low) |
| G3 | Leave partial plaintext/orphans on failure | Mostly refuted (Drop + `finish` rollback); best-effort cleanup → **SFS-05** (Low) |
| G4 | Leak exact event time via file/dir timestamps | File/dir mtimes normalized on commit; aborted writes leave root mtime → **SFS-03** (Low; ctime residual documented) |
| G5 | Get a non-safefs filesystem call merged unnoticed | **Finding SFS-01** (lint bypassable, not run in CI) |
| G6 | Spoof a display name shown to recipients | **Finding SFS-02** |
| G7 | Log prohibited data (IP/UA/filename/size/time/free text) through candor-log | **Findings LOG-03, LOG-04, LOG-09** (laundering via public constructors, `diag!` internals, lint bypass). Free-text `String`/`IpAddr` fields: refuted (sealed trait, trybuild tests) |
| G8 | Delete or alter audit content undetected | **Finding LOG-01** (High). Reorder/modify/truncate/rollback/re-sign: refuted (verify.rs, tests/chain.rs) |
| G9 | Recover source-event time finer than the date from the audit system | **Finding LOG-02** (High) |
| G10 | Recover a suppressed small cell or a single case's value from §TEL releases | **Findings LOG-05, LOG-06** |
| G11 | Inject lines or fields into JSONL/SIEM output | **Refuted.** Records are hex + static codes (sink.rs:216-255); SIEM uses `serde_json` escaping |
| G12 | Crash or exhaust the verifier/reader with hostile stored data | Refuted for panics (no reachable panic found; Miri/careful runs per R9). Memory amplification → **LOG-11** (Low); no fuzz target → **LOG-10** |
| G13 | Break the chain through operational faults (sink errors) | **Finding LOG-07** |
| G14 | Re-identify redacted (disposed) case activity | **Finding LOG-08** |

## A3/B summary of checklist items not raising findings

- B1.1/B1.8: no network, IP, UA or circuit APIs in either crate. B1.11: no temp_dir in `src` (tests/fuzz only).
- B1.5: all error `Display` strings are static. `SafeFsError`/`ArchiveError`/`LogError`/`CborError`/`VerifyError` echo no input.
- B2.1/B2.2: no `unwrap`/`expect`/indexing on input in `src`. The only `as` cast is a masked `as u8` (safefs id.rs:60; FP). Arithmetic is checked or saturating. In `ids.rs` the civil-date math is bounded (u32/i32 inputs).
- B2.4: `sink::Line` has `deny_unknown_fields`. CBOR is strict: canonical heads, sorted and unique keys, no tags or floats, trailing bytes rejected, depth ≤ 16.
- B2.8: no `unpack`/`extract`. gzip FNAME is never parsed into a name.
- B3/B4 (log): `SoftwareSigner`/`SiemKey`/`DaySalt`/`ContentKey` are zeroized and Debug is redacted. Ed25519 `verify_strict`. The chain, genesis and Merkle hashes are domain-separated and tenant/stream-bound (see LOG-12 for label prefixes).
- B6 (safefs): `O_CREAT|O_EXCL`, mode 0600/0700 set at creation, fsync of file and directories, `renameat2(NOREPLACE)` with a link+unlink fallback, foreign-owner/mode/nlink/dev refusal, FIFO open is non-blocking.
- P-16/ADR-037(3): no COI-distinguishing codes (tested). For the correlation residual, see LOG-14.

---

## Findings — candor-safefs

### AUD-RM1-SFS-01 — safefs-lint (ST-005) is bypassable and is not run on the real workspace
- Severity: Medium
- Location: crates/candor-safefs/scripts/lint-safefs.sh:37-95; .github/workflows/ci.yml (no invocation) (commit 60e732f)
- Category: B6.1, B11 (CWE-22/59 control gap)
- Description: The script is the only enforcement of ADR-027 outside this crate: workspace `clippy.toml` has no `disallowed-methods`, and Semgrep rules do not exist yet. A fixture showed that these all pass:
  - `extern crate std as s; s::fs::write(p, ..)`. The `fs::` rule excludes a preceding `:`.
  - any line starting with `*`, e.g. `*v = s::fs::read(p)…`. It is skipped as a "comment" (line 84).
  - `p.join(name)`, where the receiver name lacks path/dir/root… (a known heuristic).
  - `[dependencies.tar]` table form and `arc = { package = "zip", … }` renames (toml_pattern line 53).
  - direct `rustix::fs`/`libc`/`nix` `open*`/`rename*` calls, which are not banned at all.

  `grep … 2>/dev/null || true` (line 87) also fails open: if grep errors, for example on E2BIG with a very large file list, the script reports OK. `cargo test` only runs the script on temporary fixtures (`tests/lint.rs`). No CI job runs it on the real tree. (It does pass today: 74 files, 5 manifests, all clean.)
- Exploit scenario: A careless or malicious contributor to an intake crate adds a `std::fs`/`rustix` write with an input-derived path. CI passes, and a traversal/symlink-following write (INC-108 class) ships. Precondition: code review misses it.
- Fix recommendation: Add a CI step `bash crates/candor-safefs/scripts/lint-safefs.sh`. Add a workspace `clippy.toml` `disallowed-methods`/`disallowed-types` set (`std::fs::*`, `std::path::Path::join`, `rustix::fs::*`, `tar::*`, `zip::*`) with per-crate allow only in candor-safefs. Parse manifests with `cargo metadata` instead of regex, so that renamed and table-form dependencies are covered. Drop the `^\*` comment skip, or only apply it inside `/* */` blocks. Remove `|| true` and check the grep exit code (≥ 2 = error). Add fixtures for each bypass above (SG-21).
- Spec / requirement reference: ADR-027, ST-005, SDL-030, IMPL-RM1 §1.6 Verify, BUILD-BRIEF "Least privilege / Input handling".
- Status: Open

### AUD-RM1-SFS-02 — DisplayName keeps invisible/format characters and confusable dots
- Severity: Medium
- Location: crates/candor-safefs/src/display.rs:69-83 (commit 60e732f)
- Category: B2.10 (CWE-176, CWE-451)
- Description: `map_char` removes C0/C1/DEL, the listed bidi controls and U+2028/9 only. PoC: `sanitize("invoice\u{200B}\u{FEFF}\u{E0041}\u{00AD}.pdf\u{2800}\u{3164}.exe")` keeps U+200B, U+FEFF, U+E0041 (a TAG character), U+00AD, U+2800 (braille blank) and U+3164 (Hangul filler). Fullwidth `"．．"` (U+FF0E) is kept unchanged, and NFKC would map it to `..`. Other `Cf` characters such as U+2060–2064, U+206A–206F and U+FFF9–FFFB are not handled either, and nothing removes long whitespace runs.
- Exploit scenario: A source names an archive member `report.pdf` followed by blank-looking filler characters and then `.exe`. Truncation and the ellipsis hide the real extension, so a recipient sees `report.pdf…`. Alternatively, tag characters carry invisible instructions into a staff tool or LLM summariser that reads display names. Impact: social engineering of recipients (malware opened outside the viewer). Precondition: a UI renders the name or a tool consumes it.
- Fix recommendation: Remove every General_Category `Cf`, `Co`, `Cn` and `Zl`/`Zp` character, the variation selectors, U+E0000–E007F, U+115F/U+1160/U+3164/U+FFA0/U+2800 and other default-ignorable code points. Collapse whitespace runs. Do the all-dots check after NFKC, or on a confusable skeleton. Keep the final extension visible when truncating (truncate the middle). Add these to `st080_corpus` and the `fuzz_safefs_names` oracle.
- Spec / requirement reference: ADR-027, ADR-042 (plain-text rendering), 10 `declared_name`, ST-048/ST-080, IMPL-RM1 §4 A11 ("Unicode-dot names").
- Status: Open

### AUD-RM1-SFS-03 — Aborted writes leave the root directory mtime at the real event time
- Severity: Low
- Location: crates/candor-safefs/src/store.rs:222-241, 499-506 (commit 60e732f)
- Category: B1.2 (CWE-200)
- Description: `pending()` creates `.tmp-<id>` in the root, which updates the root mtime. `Drop` (on abort, error, or archive member error) unlinks it without calling `settle_dir`, so the root mtime stays at the real time of the abort. SPEC-NOTES decision 5 promises normalized directory times. The same timestamp is already exposed through ctime, which is a documented residual. That is why this is Low.
- Exploit scenario: Someone who seizes the disk reads `stat` on the staging root and learns the exact time of the last aborted upload or extraction.
- Fix recommendation: In `Drop` (and on `commit` error paths), call `settle_dir(&root.dir, slot)` best-effort. That needs the slot to be carried in `PendingObject`, or the type could use `O_TMPFILE` + `linkat` (see SFS-08) so the directory is never modified before commit. Add a test that asserts root mtime == slot after a dropped `PendingObject`.
- Spec / requirement reference: ADR-038(1), DB-028, SPEC-NOTES decision 5.
- Status: Open

### AUD-RM1-SFS-04 — Debug output exposes storage paths and sizes
- Severity: Low
- Location: crates/candor-safefs/src/store.rs:415-421, 524-529; src/archive/mod.rs:221-257 (commit 60e732f)
- Category: B1.3 (CWE-532)
- Description: `ObjectReader` derives `Debug` over `std::fs::File`. On Linux that impl prints `path` (readlink of `/proc/self/fd/N`, i.e., root path + shard + object id) and the open mode, plus `len`. `PendingObject` Debug prints `written`. `ExtractedMember`/`ExtractionReport` Debug print member `size` and `total_bytes` (P-07).
- Exploit scenario: A `{:?}` in a panic or error path of a caller (P-13) puts exact sizes and storage locations in a crash log.
- Fix recommendation: Write manual `Debug` impls that omit `file`, `len`, `written`, `size` and `total_bytes`, or print them as `<redacted>`. Add a unit test on the formatted output.
- Spec / requirement reference: 20 §6.1 P-07/P-13, BUILD-BRIEF "Metadata".
- Status: Open

### AUD-RM1-SFS-05 — Rollback of a failed extraction is best-effort and leaves unreferenced plaintext members
- Severity: Low
- Location: crates/candor-safefs/src/archive/mod.rs:432-445 (commit 60e732f)
- Category: B6.4 (CWE-459)
- Description: `finish` does `let _ = self.root.remove(&m.id, slot)` and then returns only the archive error. If a remove fails (EIO, or the shard was made non-0700), the committed member objects stay on disk. Their ids are lost to the caller, and `purge_incomplete` removes only `.tmp-*` names.
- Exploit scenario: A hostile archive triggers a late failure while the store is degraded. Decrypted members then stay in Scratch with no record, which breaks the "all-or-nothing" claim.
- Fix recommendation: On cleanup failure, return a distinct error (e.g. `ArchiveError::RollbackIncomplete`) that carries the leftover ids, or record them in a journal for `purge_*`. Treat Scratch as disposable: the caller destroys the VM disk on that error.
- Spec / requirement reference: 10 §10 "reject archive", BUILD-BRIEF "Fail closed".
- Status: Open

### AUD-RM1-SFS-06 — tar extension-header cap is per entry, not per archive
- Severity: Low
- Location: crates/candor-safefs/src/archive/tar_impl.rs:258-284, 328 (commit 60e732f)
- Category: B2.3 (CWE-400)
- Description: `pending.ext_headers` lives in `Pending`, which is reset by `std::mem::take` at every real entry. The cap of `3×max_entries+16` (30,016 by default) is therefore per entry, not per archive as SPEC-NOTES decision 15 states. Repeated pax `x`/`g` headers without `path` are also not refused. The only remaining bound is the stream cap (≈4.04 GiB of headers, each ≤ 64 KiB parsed into a `Vec`).
- Exploit scenario: A tar.gz at the 100:1 ratio that holds about 40 MiB of compressed pax headers makes the extractor parse about 4 GiB of headers. That wastes CPU in the viewer VM but cannot cause a memory bomb.
- Fix recommendation: Keep `ext_headers` in the `Session` (archive-wide), and refuse more than one local pax header per entry. Add a regression test.
- Spec / requirement reference: 10 §10, SPEC-NOTES decision 15, FILE-020.
- Status: Open

### AUD-RM1-SFS-07 — PendingObject keeps accepting writes after a failed write
- Severity: Low
- Location: crates/candor-safefs/src/store.rs:423-441 (commit 60e732f)
- Category: B6.4 (CWE-354)
- Description: If `f.write_all(buf)` fails partway (ENOSPC/EIO), some bytes are on disk, but the keyed hash and `written` are not updated. Later writes and `commit` still succeed, so a content-addressed object can be committed under an id that does not match its content. Dedup would then treat different content as identical.
- Exploit scenario: A caller loop that retries after an I/O error (e.g. `io::copy` with `Interrupted` handling in a wrapper) stores a corrupt object. A later identical upload is "deduplicated" to the corrupt bytes.
- Fix recommendation: Poison the `PendingObject` on any write error (set `file = None`), so `commit` returns an error. Add a test with a failing writer.
- Spec / requirement reference: FILE-005, ADR-027 (atomic write).
- Status: Open

### AUD-RM1-SFS-08 — IMPL §1.6 items not implemented: O_TMPFILE validate-then-link, inotify no-inode test, fuzz in CI
- Severity: Info
- Location: crates/candor-safefs/src/store.rs:222-241; SPEC-NOTES "Open items" (commit 60e732f)
- Category: B12.1, B2.9
- Description: Writes use named `.tmp-<random>` files in the root instead of `O_TMPFILE`, so the inode is visible before validation (SL-R-001). The inotify "no inode outside root" test is absent. The four fuzz targets exist but are not run in CI. They also have no seed corpus or dictionary, so the 60 s smoke run reached only cov 160–273 on the archive targets (see §C). `ContentKey` derives `Clone` (B3.1: only if needed).
- Fix recommendation: Implement `O_TMPFILE` + `linkat(AT_EMPTY_PATH)` on Linux, with a fallback to the current path. Add the inotify test. Add a nightly fuzz job with seed corpora (the `tests/archives.rs` fixtures) and a tar/zip dictionary. Drop `Clone` from `ContentKey` if it is unused.
- Spec / requirement reference: IMPL-RM1 §1.6 Build/Verify, §9.1.
- Status: Open

### AUD-RM1-SFS-09 — ZIP cross-checks do not cover local-header method/flags/sizes or the central-directory region
- Severity: Info
- Location: crates/candor-safefs/src/archive/zip_impl.rs:131-191 (commit 60e732f)
- Category: B2.8 (parser differential)
- Description: Pass 3 compares the name and data offset only. The local header's method, flags (including the encryption bit) and sizes are not compared with the central directory, and member ranges are not checked against `[cd_start, EOF)`. Extraction uses central values consistently, so there is no exploit in this extractor. The differential matters if any later component (a nested-archive tool in the viewer) re-parses the bytes using local headers.
- Fix recommendation: Reject local/central disagreement on method, general-purpose flags and (when bit 3 is clear) sizes and CRC, and require every member range to end at or before `cd_start`.
- Spec / requirement reference: RUSTSEC-2025-0168 class, FILE-019.
- Status: Open

---

## Findings — candor-log

### AUD-RM1-LOG-01 — Verifier accepts redacted stubs anywhere, with no tombstone binding (undetected content deletion)
- Severity: High
- Location: crates/candor-log/src/verify.rs:121-138, 228-251; src/sink.rs:396-401 (commit 60e732f)
- Category: B4.3/B12 (CWE-354, CWE-345)
- Description: `ChainRecord::Redacted {seq, prev, leaf, hash}` is accepted at any position of any stream (`sec`, `sys`, `case`). Its `hash` and `leaf` are taken on trust. Nothing checks that the stream is `case`, that a `case.disposed` tombstone exists and lists this record, or that the number of redacted records matches `removed_event_count`. The stub fields can be computed from the original record (`leaf_hash(bytes)`, `chain_hash(prev, bytes)`), so anyone with write access to the store can swap any full record for a stub. The chain, Merkle root and witness checks all still pass. PoC (scratch crate against the public API): emit `cfg.dangerous_enabled` + `auth.logout` in `sec`, checkpoint, replace record 0 with `to_redacted()`, then `verify_stream(.., trusted_latest = witness cp)` returns `Ok(records=2, redacted=1)`. In the same way, `allow_pruned_prefix = true` accepts deletion of any whole-interval prefix without checking for a matching `audit.retention_tombstone` in `sec`, or that the deleted intervals are older than the retention period.
- Exploit scenario: ADV insider (an admin with DB/file write, or the retention job role) erases the evidence of a misuse event, such as enabling a DANGEROUS config or a break-glass or export action. Verification, OVERSIGHT daily verification (AUD-014) and the witness comparison all pass. Impact: the audit record is no longer tamper-evident against the people it exists to watch (THR-037/THR-018).
- Fix recommendation: (1) Refuse `Redacted` outside `StreamId::Case`. (2) Require every redacted run to be covered by a later `case.disposed` in the verified records whose `case` matches. This needs the disposed CaseRef bound to the stubs: either keep the `case` field (or a keyed tag of it) in the stub and in the leaf preimage, or include in the tombstone a hash over the redacted seq list. Check `removed_event_count` == number of stubs for that case. (3) For pruned prefixes, require an `audit.retention_tombstone` (in `sec`) whose `seq_range` and `last_deleted_checkpoint_root` match the anchor checkpoint, and whose deleted checkpoints' `signed_at` is older than the retention period. (4) Add tamper tests: a stub in `sec`/`sys`, a stub without a tombstone, a count mismatch, and a prefix pruned without a tombstone.
- Spec / requirement reference: 20 §8, §12; AUD-004, AUD-005, AUD-012; IMPL-RM1 §4 A12 ("chain verify detects every tamper class").
- Status: Open

### AUD-RM1-LOG-02 — Checkpoint emission reveals the time and count of date-only (source/import-caused) events
- Severity: High
- Location: crates/candor-log/src/chain.rs:571-639 (`emit` count trigger, `tick`, `checkpoint_stream`), 208-232 (`signed_at`) (commit 60e732f)
- Category: B1.2 (CWE-208/CWE-359)
- Description: Checkpoints are produced (a) when a stream's pending count reaches `max_events`, and (b) on `tick` only when `pending` is non-empty and 5 min have passed since the last checkpoint. Each carries the exact `signed_at` (ms) and `first_seq..last_seq`. On a quiet stream, the checkpoint therefore follows the first event within one tick. PoC: on a CASE stream that has been idle for more than 5 min, a system `case.imported` is emitted. Its record `ts` = 1790812800000 (day-truncated), but `tick()` one second later returns a checkpoint with `signed_at` = 1790862227444 and `seq 0..0`. That gives the import time to the second and the number of imported items (P-17 "per-slot arrival counts or arrival indicators"). The same applies to `evidence.imported`, `case.envelope_rejected`, `case.canary_escalated`, `sys.relay_*` and source-load `sys.health`. On Z-INTAKE, the hour truncation (LOG-004) is defeated the same way. Checkpoints go to the external witness (AUD-003), which holds them for 7 years. In addition, date-only events share a seq-ordered chain with ms-precision staff events in the same stream, so neighbouring records bound their time.
- Exploit scenario: The witness operator, or anyone given checkpoint snapshots (OVERSIGHT Desk, auditors, a seized backup), correlates checkpoint `signed_at`/seq ranges with relay or import activity. They learn when something arrived and how many evidence items arrived, which narrows the anonymity set of sources in time (ADR-038(1)).
- Fix recommendation: Make the checkpoint cadence data-independent. Emit a checkpoint for every stream at every fixed 5-min boundary, even when empty (an empty-interval checkpoint with the same `first_seq`/root semantics, or a "heartbeat" body). Set `signed_at` to the boundary, not the clock reading, and drop the count trigger for streams that carry date-only events (or cap it so it only fires at slot boundaries). Separately, emit date-only events in a once-per-day batch at day close, in randomized order, with a fixed `ts`, or put them in a dedicated date-only stream checkpointed once per day. Add a test asserting that checkpoint timing and seq ranges are independent of when date-only events occur. Raise this as spec feedback on 20 §8 ("5 min or 1,000 events").
- Spec / requirement reference: ADR-038(1), ADR-010, 20 §4, §6.1 P-03/P-17, §6.2 LOG-004, §8, AUD-002/003.
- Status: Open

### AUD-RM1-LOG-03 — Type laundering: AuditField/DiagCode types have unrestricted public constructors
- Severity: Medium
- Location: crates/candor-log/src/codes.rs:68-79 (`Code::new(u16)`), src/ids.rs:59-61 (`from_bytes` on all opaque ids), 147-152 (`Hash32::digest`, unkeyed SHA-256), src/field.rs:145-189 (`Count(pub u32)`, `Seq(pub u64)` …), 136 (`StaffTimer(pub UtcMillis)`) (commit 60e732f)
- Category: B1.4 (CWE-532)
- Description: The sealed trait blocks `String`/`IpAddr`, but every field type can carry arbitrary caller data:
  - `Code::<S>::new(n)` accepts any `u16`, with no registry validation. Four codes in `diag!` carry 64 bits, which is enough for an IPv4 address and port.
  - `Hash32::digest(x)` is a public unkeyed hash, and the catalog uses `Hash32` for `query_hash`, `old_value_hash` and `policy_hash`. An unkeyed hash of a search term or filename can be confirmed by dictionary (P-05/P-07 "content hashes").
  - `CaseRef::from_bytes(ipv6.octets())` compiles.
  - `Count(size as u32)` and `StaffTimer(source_time)` give a size and a minute-precision time.

  PoC compiled: `diag!(Warn, "x", Code::<ConfigKey>::new(ip_hi), Code::<ConfigKey>::new(ip_lo))`, `Hash32::digest(b"203.0.113.7")`, `CaseRef::from_bytes(<IPv6>)`. The module doc's claim "Numeric codes cannot carry request data" (codes.rs:67) is false.
- Exploit scenario: A trust-path developer "temporarily" logs a peer address or a file size via a code or count to debug an incident. It compiles, passes the lint and code review, and persists in the hash-chained log for years (INC-03/INC-60 class).
- Fix recommendation: Make `Code::new` `const`-only via per-space registries (closed enums or a `const` table checked at compile time). Replace `Hash32::digest` with a keyed, domain-separated `ValueHash::new(&HashKey, label, data)` and make `Hash32` constructible only inside the crate. Mint ids through owner-crate constructors that take a random source rather than raw bytes, or at least `#[doc(hidden)]` plus a clippy `disallowed-methods` entry outside owner crates. Make the counter tuple fields private, with bounded constructors. Add trybuild tests for each case.
- Spec / requirement reference: 20 §6.1 P-01/P-05/P-07/P-12, §7, LOG-001/002/003, IMPL-RM1 §1.7 ("no impls for raw integers"), §4 A12.
- Status: Open

### AUD-RM1-LOG-04 — `diag!` contract bypass through public hidden internals
- Severity: Medium
- Location: crates/candor-log/src/diag.rs:55-66, 89-108, 176-182 (commit 60e732f)
- Category: B1.3/B1.4 (CWE-532, CWE-117)
- Description: The compile-time checks run only inside the macro. `DiagRecord::__new(level, module, line, message: &'static str, codes: &[DiagCodeValue])` and `diag::__emit` are `pub`, and `DiagCodeValue::Code(&'static str)` is a public variant. Any runtime string can reach the process-wide sink via `Box::leak(format!(..).into_boxed_str())`, with no printable-ASCII or length check, so newlines are allowed as well. PoC compiled and emitted `"203.0.113.7 /home/src/leak.pdf"`.
- Exploit scenario: Same as LOG-03, with free text. Ring-buffer contents end up in support artefacts (INC-56).
- Fix recommendation: Put the constructor behind a token type that only the macro can name (a `pub` struct in a `#[doc(hidden)] mod __private` whose field is private and created by a `const fn` the macro calls with `$msg`). Re-validate `message` with `__message_ok` at runtime in `__new`, and drop records that fail. Make `DiagCodeValue` fields private, with construction only through `DiagCode`. Add a trybuild test that calling `__new` with a non-literal fails.
- Spec / requirement reference: 20 §7, LOG-001, P-12.
- Status: Open

### AUD-RM1-LOG-05 — Suppression audit ignores public knowledge of primary (<k) and complementary (≥k) cells; complementary cells labelled "0–9"
- Severity: Medium
- Location: crates/candor-log/src/metrics.rs:326-384 (greedy), 510-608 (audit), 241-260 (display) (commit 60e732f)
- Category: B1.7 (statistical disclosure; THR-039)
- Description: The audit checks only exact linear derivability and exact pinning under non-negativity, with bounds of 0..∞. An attacker also knows that every primary-suppressed cell is < k and that every complementary cell (the next-smallest unsuppressed cell) is ≥ k. On top of that, `Published::Suppressed` shows "0–9" for complementary cells too. PoC with `suppress(2×3 [[0,10,100],[50,60,70]], k=10)`: cells (0,0),(0,1),(1,0),(1,1) are suppressed, and the row/column/grand totals are published (110, 180; 50, 70, 170; 290). The audit passes (t ∈ [0,10]). Under the attacker's knowledge, row 0's suppressed pair sums to 10 and contains one cell < 10 and one ≥ 10, which forces the values {0, 10}. The small cell's exact value is disclosed, with only a 2-way position ambiguity. Meanwhile cells with true values 50 and 60 are published as "0–9", which is false.
- Exploit scenario: An M2/M3 recipient (funder, public) works out that a given channel had exactly 0 (or, in similar layouts, exactly 1–3) account deletions or submissions in a month, contrary to TEL-010 / AT-065/066.
- Fix recommendation: In the audit, start primary cells at `hi = k-1` and complementary cells at `lo = k`. Require a protection interval (for example, the feasible range of each primary cell must cover at least `[0, k-1]` or have width ≥ k), not just "not pinned". Show complementary cells as a distinct "suppressed" mark ("—"), never "0–9". Extend `tests/suppression.rs::pinned_cells` with the attacker's prior knowledge, and add this table as a regression.
- Spec / requirement reference: 24 §9.3–§9.6, TEL-010, ADR-046(5), AT-065/066.
- Status: Open

### AUD-RM1-LOG-06 — Differencing defence is not persistable, and magnitude statistics bypass it
- Severity: Medium
- Location: crates/candor-log/src/metrics.rs:808-848 (`PeriodRegistry`), 1036-1076 (magnitude functions) (commit 60e732f)
- Category: B1.7 (THR-039)
- Description: `PeriodRegistry` (frozen periods plus the joint audit of all facts released for a period) lives only in memory. It has no serialization or restore API, so a process restart lets the same period be released again, with a different table shape, without the prior facts. `median`/`percentile`/`mean`/`ratio_permille` are free functions that never touch the registry. `percentile(v, 0|100, k)` returns a single case's exact value (min/max). Means over populations n and n+1 released in different reports reveal one value exactly.
- Exploit scenario: An M2 consumer requests the KPI report (mean duration over 10 cases) and later the same report over 11 cases. The difference gives one case's exact duration, which is a single-case reconstruction (24 line 293). After a restart, a second release of a month with a different grouping completes a subtraction attack.
- Fix recommendation: Persist `PeriodState` (canonical, append-only, in the C-10 DB) and refuse release when it is missing. Route magnitude statistics through the registry, as facts with a dominance/p% rule, and restrict percentiles to `p ∈ [10,90]` with n ≥ k on each side. Add tests for restart and for the mean differencing.
- Spec / requirement reference: 24 §9.5–§9.6, TEL-010/015/020, LOG-011.
- Status: Open

### AUD-RM1-LOG-07 — Partial sink failure forks the chain; signer failure after commit misreports
- Severity: Medium
- Location: crates/candor-log/src/chain.rs:571-588, 652-660 (commit 60e732f)
- Category: B7.1 analogue (CWE-662, partial state)
- Description: `emit` writes the record to each sink in turn and advances the stream state only if all of them succeed. If sink 1 succeeds and sink 2 fails, the next `emit` reuses the same `seq` and `prev`, so sink 1 now holds two different records with the same seq. `verify_stream` then fails (`SequenceOrder`/`ChainMismatch`). That is a false tamper alarm, and the stream can no longer be verified. `checkpoint_stream` has the same problem. Conversely, when the event-count checkpoint fails to sign (`LogError::Signer`), the record has already been committed and the state advanced, but `emit` returns `Err`. A caller that retries logs the event twice.
- Exploit scenario: A transient I/O fault, or a disk-full condition on a secondary sink caused by an attacker, makes the primary audit chain permanently fail verification. That masks real tampering (alarm fatigue) and breaks `resume`.
- Fix recommendation: Use a single primary durable sink as the commit point, and feed secondaries from it asynchronously (outbox). On secondary failure, never re-issue the seq. Return `Emitted { checkpoint_error }` instead of `Err` once the record is committed. Add tests with a failing second sink and a failing signer.
- Spec / requirement reference: 20 §8, AUD-001/004, BUILD-BRIEF "Fail closed".
- Status: Open

### AUD-RM1-LOG-08 — Redacted leaves are unsalted hashes of low-entropy records (confirmation of disposed case activity)
- Severity: Medium
- Location: crates/candor-log/src/chain.rs:84-90, 400-409 (commit 60e732f)
- Category: B4.3 (CWE-759/CWE-916 analogue; confirmation attack)
- Description: After disposal, a stub keeps `leaf = SHA-256(0x00 ‖ canonical_bytes)` and `hash = SHA-256(label ‖ prev ‖ canonical_bytes)`. The redacted record's preimage is mostly guessable: tenant, stream, seq and prev are known; the type comes from a small catalog; the actor is one of a small set of staff UserRefs; ts is in ms within a known window; the case is known from the `case.disposed` tombstone; and payload ids are often known. Brute force of about 10^10–10^11 SHA-256 operations confirms "user U opened or exported case C at time T".
- Exploit scenario: After disposal, someone with the audit store or a backup reconstructs who worked on a disposed case and when. That defeats the purpose of AUD-012 / ADR-025 erasure.
- Fix recommendation: Commit each record with a per-record random 32-byte salt: `leaf = H(0x00 ‖ salt ‖ bytes)` and chain over the same. Store the salt with the record and delete it on redaction. Document this in SPEC-NOTES, and add a test that a stub reveals nothing without the salt.
- Spec / requirement reference: 20 §12, AUD-012, ADR-025.
- Status: Open

### AUD-RM1-LOG-09 — deny-free-text-logging lint (LOG-001) is bypassable and not run in CI; disallowed-macros applies only to candor-log
- Severity: Medium
- Location: crates/candor-log/scripts/lint-logging.sh:59-112; crates/candor-log/clippy.toml (commit 60e732f)
- Category: B1.3/B1.4 (CWE-532)
- Description: A fixture crate passed the lint with:
  - `let _u = "//"; println!("{ip}");`. The `sed 's://.*$::'` strips everything after a `//` inside a string.
  - `lg::log!(Level::Warn, "{}", ip)` with `lg = { package = "log" }`. Neither the rename nor the `log!` macro is covered.
  - `writeln!(std::io::stderr(), "{ip}")`.
  - `panic!("bad peer {ip}")`, i.e. P-13 values in panic messages.
  - `[dependencies.log]` table form.

  The crate-local `clippy.toml` `disallowed-macros` only applies when linting candor-log itself. The workspace `clippy.toml` bans only `dbg!`. No CI job runs the script on the real tree (the only test is a fixture self-test). It passes today (83 files).
- Exploit scenario: Like SFS-01. A trust-path crate prints a client header or filename to stderr, journald stores it, and the canary suite (LOG-003) is the last line of defence.
- Fix recommendation: Move `disallowed-macros` (`std::println`, `eprintln`, `print`, `eprint`, `dbg`, `std::writeln` to stdio, `log::*`, `tracing::*`) into the workspace `clippy.toml`, and allow-list it per non-trust-path crate. Add `clippy::panic`-adjacent rules (`panic!`/`expect` messages with format args) via a Semgrep rule. Run the script in CI. Strip comments with a lexer-aware tool (e.g. `rustc -Zunpretty` or Semgrep) instead of sed. Detect renamed dependencies via `cargo metadata`.
- Spec / requirement reference: 20 §7, §14, LOG-001, P-12/P-13, IMPL-RM1 §9.1 ("crate-local clippy.toml overrides").
- Status: Open

### AUD-RM1-LOG-10 — No fuzz target for the CBOR decoder, JSONL reader or verifier (ST-051)
- Severity: Medium
- Location: crates/candor-log (no `fuzz/`) (commit 60e732f)
- Category: B2.9
- Description: `cbor::decode`, `sink::read_stream`, `SignedCheckpoint::from_parts` and `verify_stream` all parse attacker-influenced stored data. They have proptests only; there is no cargo-fuzz target. IMPL §1.7 requires `fuzz_audit_log_verify` (ST-051).
- Fix recommendation: Add `fuzz_cbor_decode` (with an encode/decode round-trip oracle), `fuzz_jsonl_read_verify` (no panic, bounded RSS) and `fuzz_checkpoint_parse`, and run them in the nightly job.
- Spec / requirement reference: ST-051, IMPL-RM1 §1.7 Verify, BUILD-BRIEF "Input handling".
- Status: Open

### AUD-RM1-LOG-11 — CBOR decoder pre-allocation amplifies memory up to ~32–64× per nesting level
- Severity: Low
- Location: crates/candor-log/src/cbor.rs:239-266 (commit 60e732f)
- Category: B2.3 (CWE-770)
- Description: For arrays and maps, `Vec::with_capacity(n)` uses `n ≤ remaining bytes`. Each `Value` is about 32 B, and each map entry about 64 B. Nested declarations at depth ≤ 16, each claiming the remaining length, hold all of these allocations at once. A 512 KiB record (a 1 MiB hex line) can therefore make the verifier allocate hundreds of MiB before it fails with `Truncated`.
- Exploit scenario: An insider plants a few hostile lines, so `candorctl audit verify` or the OVERSIGHT verifier runs out of memory (it is denied service).
- Fix recommendation: Cap the pre-allocation (e.g. `min(n, 1024)`) and grow on push. Optionally cap the total decoded nodes per record.
- Spec / requirement reference: BUILD-BRIEF "no unbounded allocation".
- Status: Open

### AUD-RM1-LOG-12 — Domain-separation labels are not prefix-free; signer trait signs arbitrary messages
- Severity: Info
- Location: crates/candor-log/src/chain.rs:31-41, 156-162 (commit 60e732f)
- Category: B4.3
- Description: `candor/v1/audit/checkpoint` is a prefix of `…/checkpoint-sig` and `…/checkpoint-genesis`. That is not exploitable today, because the checkpoint bytes start with the CBOR map head 0xab, which is not `-`. It does rely on that encoding fact. `CheckpointSigner::sign(msg)` accepts any message, so a TPM key shared with another purpose could be used as a cross-protocol oracle.
- Fix recommendation: Use NUL-terminated or length-prefixed labels, register them in the core label registry, and have the signer add the context itself (`sign_checkpoint(bytes)`).
- Spec / requirement reference: IMPL-RM1 §4 A5 (prefix-free labels, by analogy).
- Status: Open

### AUD-RM1-LOG-13 — JSONL metadata fields are not cross-checked; reader loads whole files
- Severity: Low
- Location: crates/candor-log/src/sink.rs:325-401 (commit 60e732f)
- Category: B2.4/B2.3
- Description: `read_stream` ignores the line's `type` and `seq` (on `rec`) and `last_seq` (on `cp`), so they can disagree with the CBOR. Tools or reviewers that grep `"type":` can be misled while the verifier still passes. `read_lines` collects all lines into memory without a count limit.
- Fix recommendation: Decode the CBOR and require `type`, `seq` and `last_seq` to match, and reject otherwise. Stream the verification instead of collecting.
- Spec / requirement reference: AUD-004.
- Status: Open

### AUD-RM1-LOG-14 — COI linkage via event adjacency is not mitigated
- Severity: Low
- Location: crates/candor-log/src/event.rs:225-234 (catalog), src/chain.rs (single ordered CASE stream) (commit 60e732f)
- Category: B1 (P-16)
- Description: The codes never say COI. But `case.coi_tags_updated {case}` followed in the same CASE stream (adjacent seq, ms ts for staff) by `case.member_removed {case, target, REMOVED}` links the target's removal to a COI exclusion. The library offers no batching or decorrelation helper, and the residual is not documented in SPEC-NOTES.
- Fix recommendation: Document it as a residual and as spec feedback. Provide a decorrelation option: emit membership changes caused by COI in a daily batch, with date-only ts, mixed with other removals.
- Spec / requirement reference: 20 §6.1 P-16, ADR-037(3), LOG-020.
- Status: Open

### AUD-RM1-LOG-15 — `Sensitive<T>` only blocks the candor-log paths
- Severity: Info
- Location: crates/candor-log/src/sensitive.rs:22-25 (commit 60e732f)
- Category: B1.3
- Description: `expose()` returns `&T`, so `format!("{}", s.expose())` / `eprintln!` compile in any crate. The wrapper prevents only `Debug`/`Display`/`Serialize`/`AuditField`. The README and the doc wording ("no formatting or logging path compiles") overstate this.
- Fix recommendation: Correct the documentation. Optionally return a non-`Display` view type (`ExposeGuard<'_, T>` with `as_bytes()`/`as_str()` only), and add a Semgrep rule flagging `expose()` inside format/print macros.
- Spec / requirement reference: 20 §7, LOG-002.
- Status: Open

---

## C. Tool runs (audited commit; toolchain 1.94.1; nightly-2026-09-28)

| Tool | Command | Result / triage |
|---|---|---|
| clippy (deny set) | `cargo clippy -p candor-safefs -p candor-log --all-targets --all-features -- -D warnings` | clean (rc 0) |
| clippy (audit extras) | `cargo clippy -p candor-safefs -p candor-log --all-features -- -W clippy::as_conversions … -W clippy::todo` (§C list) | 25 warnings: 21 `integer_division` (log ids.rs civil-date math, export.rs time formatting, metrics.rs percentile/mean: all intended floor division, FP), 2 `as_conversions` + 1 `cast_possible_truncation` (log cbor.rs:96 `n as u8` guarded by `n < 24`; safefs id.rs:60 masked `& 0xff`: FP) |
| tests | `cargo test -p candor-safefs -p candor-log --locked` | all pass (16 binaries; 0 failed) |
| cargo-deny 0.20.2 | `cargo deny --offline check advisories bans licenses sources` | advisories ok, licenses ok, sources ok; **bans FAILED** on duplicate `sha2` 0.10.9 (via `sqlx-core`, out of scope) vs 0.11.0. Not caused by these crates; forwarded to the RM-2 intake-store audit |
| cargo-audit 0.22.1 | `cargo audit --db ~/.cargo/advisory-dbs/advisory-db-3157b0e258782691 --no-fetch --deny warnings` (DB commit `9b3a3b73`, 2026-09-30) | 0 vulnerabilities/warnings (300 crates; tar 0.4.46, zip 4.6.1, flate2 1.1.5 clean) |
| cargo-vet 0.10.2 | `cargo vet --locked` | fails on unvetted workspace deps (yoke, zerovec-derive, … `safe-to-deploy` missing). Workspace-wide supply-chain gap, not specific to these crates; tracked by the RM-0 gate |
| cargo-geiger 0.13.0 | `cargo geiger --manifest-path $PWD/crates/<c>/Cargo.toml --all-features --output-format Ratio` | Both crates have 0 `unsafe` (workspace `forbid(unsafe_code)`). Dependency ratios (functions safe/total): safefs 4217/5066, expressions 145322/184883 (cap-std/rustix/zlib-rs/blake3 carry the `unsafe`); log 1826/1914, expressions 94814/100720 (sha2/ed25519/serde_json). No new baseline exists yet to compare against (B11.4 will be tracked from this run) |
| Miri | `cargo +nightly-2026-09-28 miri test -p candor-log --lib` | `test result: ok. 21 passed; 0 failed` (no UB) |
| cargo-fuzz | `cargo +nightly-2026-09-28 fuzz run <t> -- -max_total_time=60 -rss_limit_mb=2048 -timeout=10` for the 4 safefs targets | No crashes, timeouts or OOM. names: 399,292 runs, cov 769; zip: 46,928 runs, cov 205; tar: 104,949 runs, cov 160 (corpus 2 inputs); tar_gz: 65,902 runs, cov 273. The archive targets have no seed corpus or dictionary, so 60 s barely gets past the header checks (low coverage). See SFS-08 |
| shellcheck 0.9.0 | `shellcheck -S style` on both lint scripts | clean |
| repo lints | `lint-safefs.sh`, `lint-logging.sh` on the real tree | both OK (74/83 files). Bypasses: SFS-01, LOG-09 |
| semgrep / zizmor / systemd-analyze | — | not applicable (no custom rules yet; no workflows/units in scope) |
| PoCs | scratch crate depending on both crates by path (not committed) | confirmed LOG-01, LOG-02, LOG-03, LOG-04, LOG-05 and SFS-02 as described |

## B12. Test assessment

The tests are strong on the happy and negative paths for limits, traversal, bombs, CBOR canonicality, chain tamper (modify, reorder, delete, truncate, rollback) and suppression pinning. Missing negative tests: redacted stubs outside CASE or without a tombstone (LOG-01); checkpoint timing independence (LOG-02); attacker prior knowledge in the suppression oracle (LOG-05); partial sink failure (LOG-07); lint bypass fixtures (SFS-01, LOG-09); display invisible characters (SFS-02).

## Gate

Gate: **FAIL** 2026-10-01 60e732f9 (2 High open: LOG-01, LOG-02; 10 Medium need a fix or written acceptance).

---

## Re-test (round 2)

| Field | Value |
|---|---|
| Re-tested commit | `fc64069` ("candor-safefs/candor-log audit fixes"). `crates/candor-safefs` and `crates/candor-log` are clean in the working tree |
| Procedure | AUDIT-CHECKLIST §G: fix verification, regression tests, variant hunt, delta review of all changed lines in both crates (≈5.7 k lines added), full §C re-run. The PoCs were re-run from a private scratch crate (not committed) |
| Date | 2026-10-01 |

### G5. Tool re-run (fc64069)

| Tool | Result |
|---|---|
| `cargo clippy -p candor-safefs -p candor-log --all-targets --all-features -- -D warnings` | clean |
| `cargo test -p candor-safefs -p candor-log --locked` | all pass (incl. new trybuild UI cases `diag_forged_internals`, `launder_raw_id`, `launder_code_counter`) |
| Miri `-p candor-log --lib` | 22/22 pass |
| `lint-safefs.sh` / `lint-logging.sh` (real tree) | OK (76 / 85 files); both run in CI job `repo-lints` |
| Round-1 bypass fixture against the new scripts | all round-1 bypasses are reported (`s::fs::write`, `*v = s::fs::read`, `[dependencies.tar]`, `package = "zip"`, `"//"`-string + `println!`, `lg::log!`, `writeln!(stderr)`, `panic!("{ip}")`, renamed `log`) |
| Workspace `clippy.toml` on a fixture crate (`CLIPPY_CONF_DIR`) | type-resolved bans fire for `s::fs::write/read`, `p.join`, `File::open/options`, `OpenOptions::open`, `std::io::stderr`, `println!`. Not covered: see SFS-11/LOG-21 |
| cargo-fuzz (nightly-2026-09-28, 46–61 s each, seeded) | no crash/OOM/timeout. log: cbor_decode cov 384, checkpoint_parse 1061, jsonl_read_verify 2574, audit_log_verify 1157. safefs: zip 1784, tar 1095, tar_gz 1775, names 913 (round 1: 160–273). *Process note:* these runs used the committed seed dirs as the corpus, so libFuzzer added files there. When the runs finished I restored them with `git checkout -- …/fuzz/seeds && git clean -fd …/fuzz/seeds` (both crates). The repo is unchanged |

### Per-finding status

| Finding | Status | Evidence / remark |
|---|---|---|
| SFS-01 (M) | **Fixed** | Workspace `clippy.toml` `disallowed-methods/types` (type-resolved). The script rejects `allow(clippy::disallowed_*)` and crate-local `clippy.toml`, resolves dependencies via `cargo metadata` and fails closed. CI `repo-lints`. `tests/lint.rs::audit_bypasses_are_caught` passes; the round-1 fixture is caught. Residual variants: SFS-11 |
| SFS-02 (M) | **Fixed** | `is_invisible` covers the DI/Cf/PUA/noncharacter/filler set. Whitespace collapse, NFKC all-dots check, middle truncation that keeps the extension. Round-1 PoC string → `"invoice.pdf.exe"`. Residual (accepted in notes): unassigned `Cn` code points survive (Info) |
| SFS-03 (L) | **Fixed for a single writer; variant open** | `dropped_pending_object_restores_root_times` passes. Concurrent writers re-introduce the leak: SFS-10 |
| SFS-04 (L) | **Fixed** | Manual `Debug` impls. Tests `debug_output_has_no_path_or_size`, `report_debug_has_no_sizes` |
| SFS-05 (L) | **Fixed** | `ArchiveError::RollbackIncomplete(ids)`. Display prints a count only. Test `incomplete_rollback_is_reported` |
| SFS-06 (L) | **Fixed** | Archive-wide counter; a repeated local pax header is `Malformed`. Test `tar_extension_header_cap_is_archive_wide` |
| SFS-07 (L) | **Fixed** | `poisoned` flag blocks further writes and `commit`. Test `failed_write_poisons_pending_object` |
| SFS-08 (I) | **Partially fixed; deferrals assessed below** | `ContentKey` no longer `Clone`. Seeds committed (coverage confirmed above) |
| SFS-09 (I) | **Fixed** (residual SFS-12) | Method, encryption flag, CRC and sizes cross-checked. Members must end before the CD. Test `zip_local_central_field_mismatch_rejected` |
| LOG-01 (H) | **Fixed as reported; bypassed by a new variant → LOG-16 (High)** | Stubs outside CASE give `UnboundRedaction` (round-1 PoC is now the test `stub_in_security_stream_rejected`). Stub hash/leaf are recomputed from `commit`. Unbound, count-mismatched and set-mismatched stubs are rejected. The tombstone must be checkpointed. Pruning needs a same-stream, checkpointed retention tombstone with the anchor root and a minimum age. Replaying an existing tombstone for other seqs fails (the set hash commits to (seq, commit)). **But** a caller can forge the tombstone's `redacted_set`. See LOG-16 |
| LOG-02 (H) | **Partially fixed — remains Open (High)** | The checkpoint channel is fixed: `signed_at` = slot boundary, empty intervals are checkpointed, no count trigger, CASE/SYS daily. Test `checkpoint_timing_independent_of_date_only_events` passes. **Still open:** the record-order channel named in the original finding ("date-only events share a seq-ordered chain with ms-precision staff events in the same stream"). It is not addressed and is not listed as a residual. In CASE, `case.imported`/`evidence.imported` (date-only) sit between staff events with ms `ts` (e.g. `case.opened`), so anyone who reads CASE records (admins, OVERSIGHT, audit exports) can bound each import to the gap between neighbouring staff events, i.e. which import slot it arrived in (P-17). In SYS, date-only `sys.relay_*` and source-load `sys.health` sit between second-precision `sys.clock`/`sys.job` records, which bounds source-load detections to minutes for SYS_ADMIN/SOC readers (TEL-018). Fix: put date-only events in a separate stream (checkpointed daily), or buffer them and emit at day close in randomized order. Add a test that no date-only record has a finer-precision neighbour in its stream |
| LOG-03 (M) | **Partially fixed → LOG-17 (M)** | Raw `from_bytes`, `Code::new`, `Hash32::digest` and the public counter fields are gone (trybuild). New laundering paths remain: LOG-17 |
| LOG-04 (M) | **Fixed** | `DiagCodeValue` is opaque. The const-only `Site` + `const {}` assert and a runtime re-check. The round-1 PoC (`Box::leak` message, forged `DiagCodeValue::Code`) no longer compiles (`tests/ui/diag_forged_internals.rs`). Residual: Info LOG-23 |
| LOG-05 (M) | **Fixed** | Exact simplex with attacker priors (primary ∈ [0,k−1], complementary ≥ k) and a ≥ k−1 range requirement. Hidden cells display "suppressed". Round-1 PoC table: all six cells suppressed with margins 110/180, 50/70/170, 290. I checked by hand that the primary cell keeps its full [0,9] feasible range under the priors (e.g. x00=9: x10=41, x01=10, x11=60, x02=91, x12=79). Test `primary_cell_not_narrowed_by_attacker_priors`. LP relaxation residual: LOG-22 |
| LOG-06 (M) | **Partially fixed → LOG-18 (M)** | The durable `ReleaseHistory` fails closed (tests `differencing_blocked_across_restart`, `history_errors_fail_closed`). Percentiles are limited to 10..=90 and magnitude releases need pairwise population differences ≥ k. That pairwise check does not stop linear combinations: LOG-18 |
| LOG-07 (M) | **Fixed** | A single primary commit point, secondaries fed from outboxes, the slot-close signer failure happens before any write. Tests `failing_secondary_does_not_fork_chain`, `failing_primary_commits_nothing`, `signer_failure_writes_nothing` |
| LOG-08 (M) | **Fixed** | `c_i = H(label‖salt_i‖bytes)` with a per-case HMAC-derived salt, dropped on redaction. Missing key → `CaseKeyUnavailable`. Test `redacted_stub_reveals_nothing_without_case_key` |
| LOG-09 (M) | **Fixed** (residual LOG-21) | Bans are in the workspace `clippy.toml`, the crate-local file is removed, the lexer-aware script runs in CI, and the round-1 fixture is caught |
| LOG-10 (M) | **Fixed** | Four seeded targets. Smoke runs clean (above). CI scheduling is deferred (see below) |
| LOG-11 (L) | **Fixed** | Pre-allocation capped at 64 |
| LOG-12 (I) | **Fixed** | NUL-terminated labels, `sign_checkpoint(bytes)`. Test `labels_are_prefix_free` |
| LOG-13 (L) | **Fixed** | `MetadataMismatch` on `seq`/`type`/`end_seq`, foreign fields rejected, `MAX_LINES` 4 Mi |
| LOG-14 (L) | **Accepted residual (documented) — needs the lead auditor's written acceptance** | Documented with the system-actor/daily-batch decorrelation option. Low, so it does not block |
| LOG-15 (I) | **Fixed** | Documentation corrected |

### New findings (round 2)

### AUD-RM1-SFS-10 — Concurrent pending objects restore a real timestamp onto the root
- Severity: Low
- Location: crates/candor-safefs/src/store.rs `pending()` (root time capture), `Drop for PendingObject` / `restore_dir_times` (fc64069)
- Category: B1.2 (CWE-200)
- Description: `pending()` saves the root's atime/mtime *at temp-file creation*. If another `PendingObject` already has an uncommitted temp file, the root mtime at that moment is the real creation time of that other file. When the second object is dropped, `restore_dir_times` writes that real timestamp back, so the SFS-03 leak returns under any concurrency (parallel uploads or extractions). Drops that run out of order can also roll the root back to an older value.
- Exploit scenario: Same as SFS-03 (disk seizure reads the root mtime). Preconditions: concurrent writers. ctime remains the documented residual.
- Fix recommendation: Don't restore a captured value. Carry a `SlotTime` (or a root-wide "last settled slot" kept in `SafeRoot`) and normalize to it, or use `O_TMPFILE` so the directory is never touched before commit. Add a test with two overlapping `PendingObject`s.
- Spec / requirement reference: ADR-038(1), DB-028, SPEC-NOTES decision 5.
- Status: Open

### AUD-RM1-SFS-11 — Remaining gaps in the filesystem bans
- Severity: Low
- Location: clippy.toml `disallowed-methods`; crates/candor-safefs/scripts/lint-safefs.sh (fc64069)
- Category: B6.1/B6.2, B1.11
- Description: A fixture passed both clippy and the script with these: `std::env::temp_dir()` followed by `PathBuf::extend([name])` (path composition from input without `join`/`push`); `std::process::Command::new(..)` (`rm`, `tar`, `unzip` with input paths); and the `tempfile` crate, which is neither banned nor listed. None of these reaches a disk write without a further banned call except `Command`, so this is Low.
- Fix recommendation: Add `std::env::temp_dir`, `std::path::PathBuf::extend`, `std::path::PathBuf::set_file_name`, `std::process::Command::new` (allow-listed per crate with a reason) and `tempfile::*` (non-test) to the workspace bans. Add fixtures to `tests/lint.rs`.
- Spec / requirement reference: ADR-027, ST-005, B1.11.
- Status: Open

### AUD-RM1-SFS-12 — ZIP data-descriptor flag is not cross-checked, so the CRC/size cross-check can be skipped
- Severity: Info
- Location: crates/candor-safefs/src/archive/zip_impl.rs (pass 3) (fc64069)
- Category: B2.8
- Description: The CRC/size comparison runs only when the *local* bit 3 is clear, and local bit 3 is not compared with central bit 3. Setting it locally skips the new check. The local zip64 extra sizes are also not compared. There is no impact on this extractor (it uses central values). The gap matters only if a later local-header parser is used.
- Fix recommendation: Require local flags == central flags, apart from bits a spec allows to differ, and compare the zip64 local extra when sizes are `0xFFFFFFFF`.
- Status: Open

### AUD-RM1-LOG-16 — Forged `case.disposed` tombstone redacts arbitrary CASE records; verifier passes
- Severity: High
- Location: crates/candor-log/src/ids.rs `Hash32::checkpoint_root` (verifies under a caller-supplied key); src/chain.rs `pub fn redaction_set_hash`; src/event.rs `CaseDisposed { .., removed_event_count: Count, redacted_set: Hash32 }` (public variant); src/verify.rs step 5a (fc64069)
- Category: B4.3/B12 (CWE-345, CWE-354)
- Description: The verifier binds stubs to a `case.disposed` tombstone by `(count, redacted_set)`, but any code that can call `AuditLog::emit` can build that tombstone with values of its choosing:
  - `redacted_set` comes from `Hash32::checkpoint_root(cp, key)`, which accepts a checkpoint signed by *any* key the caller supplies. A self-made `SoftwareSigner` plus a re-encoded checkpoint whose `merkle_root` is set to 32 chosen bytes yields an arbitrary `Hash32`.
  - `redaction_set_hash` is public.
  - `Count::new(n)` is public.
  - `CaseDisposed` is a public variant, so nothing forces it to come from a `RedactionPlan`.

  PoC (`auditlog-r2-poc/src/bin/forge.rs`): an investigator emits `case.opened` for a victim case. The insider launders `redaction_set_hash([(seq, commit)])` into a `Hash32`, emits `case.disposed` for an unrelated or fake case with count 1, waits for the daily checkpoint, and replaces the victim record with a stub bound to that tombstone. `verify_stream(.., trusted_latest = latest cp)` returns `Ok(records=2, redacted=1)`. The stub belongs to a case other than the one named in the tombstone, and the verifier cannot tell.
- Exploit scenario: ADV insider with code execution in the C-24 writer process (or anything linking candor-log with the instance's sink/signer, e.g. root on the audit host) plus store write. They retroactively erase who opened, exported or decrypted any case. The remaining trace is a plausible-looking `case.disposed` of some case, and the witness and OVERSIGHT verification still pass. This is the attack LOG-01 was meant to close, now one precondition further away. Severity stays High because the verifier's tamper-evidence guarantee (AUD-004/AUD-012) is defeated and the root cause is easy to fix.
- Fix recommendation: (1) Make `case.disposed` constructible only from `RedactionPlan::tombstone` (e.g. a private-field payload struct, or a sealed `DisposalToken`), and make `RedactionPlan` buildable from any `CaseRecordSource` trait so production stores can use it (today only `MemoryStore` can build it; see LOG-23). (2) Make `Hash32::checkpoint_root` (and `Seq::checkpoint_end`, `SeqRange::of_checkpoint`, see LOG-17) accept only checkpoints produced by *this* log, e.g. as methods on `AuditLog` that verify against `self.verifying_key()`. (3) Defence in depth: bind each stub to its case through a keyed case tag kept in the stub (`HMAC(K_tenant, case)`), committed in the leaf preimage, and have the verifier require stub tag == tombstone case tag. (4) Add the PoC as a regression test.
- Spec / requirement reference: 20 §8, §12, AUD-004, AUD-012, IMPL-RM1 §4 A12.
- Status: Open

### AUD-RM1-LOG-17 — Laundering paths remain after the LOG-03 fix
- Severity: Medium
- Location: crates/candor-log/src/ids.rs `Hash32::checkpoint_root`, `X::derive(&AuditIdKey, raw)`; src/field.rs `Seq::checkpoint_end`, `SeqRange::of_checkpoint` (fc64069)
- Category: B1.4 (CWE-532)
- Description: PoC (`auditlog-r2-poc/src/main.rs`):
  - `Hash32::checkpoint_root(self_signed_cp, own_key)` → `20010db8…0007…` (an IPv6 address carried in 32 chosen bytes), then used as `records.search_performed.query_hash`. Compiled and ran.
  - `Seq::checkpoint_end(&forged)` → `0xcb007107000001bb` (IPv4 203.0.113.7 with port 443 packed into 64 bits). It does not even check a signature. `SeqRange::of_checkpoint` carries 128 bits the same way.
  - `CaseRef::derive(&key, ip.octets())` and `Hash32::derive(&key, Query, ip)` compile and give a *linkable, keyed pseudonym* of any input. The writer holds the key, so it can reverse IPv4 in about 2³² HMACs. P-01 forbids IP data in any form.
- Exploit scenario: As in LOG-03: a trust-path developer can still record a peer address or filename with code that passes review and the type system.
- Fix recommendation: Use the LOG-16 fix (2) for checkpoint-derived values. Make `derive` take typed inputs (`&Uuid`-like random id types from the owner crates, or `ResourceId` newtypes that can only be minted from a CSPRNG), not `&[u8]`. Restrict `Hash32::derive(Query, ..)` to a `QueryText` newtype that only the search component creates. Add trybuild cases.
- Spec / requirement reference: 20 §6.1 P-01/P-05/P-07, LOG-001/003, IMPL-RM1 §4 A12.
- Status: Open

### AUD-RM1-LOG-18 — Magnitude differencing through linear combinations of releases
- Severity: Medium
- Location: crates/candor-log/src/metrics.rs `PeriodRegistry::release_magnitude` (fc64069)
- Category: B1.7 (THR-039)
- Description: Populations are compared only pairwise (|ΔA,B| = 0 or ≥ k). PoC with k = 10: A = X∪P (30 cases), B = X∪Q (30), C = X∪P∪Q∪{r} (41), D = X (20). Every pair differs by ≥ 10, and all four means were released (201, 224, 280, 166). Then S_C − S_A − S_B + S_D = x_r: one case's value, exact when sums are exact, and within about ±121 here because means are floored (the target value 2027 stands out against 100–380). A mean is a linear fact, but those facts never enter the LP disclosure audit used for tables. Also, `Percentile(10)` with n = 10 returns the minimum (PoC: 1000), which is one case's exact extreme value.
- Exploit scenario: An M2 consumer combines the fixed catalog's magnitude reports (per channel, per group, overall) for one month and recovers a single case's duration or size class (24 line 293, "reconstruction … through magnitude statistics").
- Fix recommendation: Record each mean as a linear fact (Σ members = n·mean ± rounding interval) in the period's disclosure state, and run it through the same simplex audit, with every individual micro-value as a protected quantity (range ≥ some width). For percentiles, require at least k values strictly below and at least k strictly above the reported rank (n ≥ k / min(p, 100−p) × 100). Add the PoC as a regression.
- Spec / requirement reference: 24 §9.5–§9.6, TEL-015, ADR-046(5).
- Status: Open

### AUD-RM1-LOG-19 — Up to 24 h of CASE/SYSTEM events are unattested (tail truncation undetectable)
- Severity: Medium
- Location: crates/candor-log/src/chain.rs `CheckpointPolicy::slot_ms` (CASE/SYS daily) (fc64069)
- Category: B12 / integrity trade-off (CWE-354)
- Description: The LOG-02 fix checkpoints CASE and SYSTEM once per UTC day, so the witness learns a CASE/SYS head only daily. An insider who truncates the store tail removes up to 24 h of CASE events (who opened, exported or decrypted what) without detection. Before the fix this window was 5 min. SPEC-NOTES says this was "accepted per lead decision", but §F.2 requires a written lead-auditor acceptance in this report (risk statement, compensating controls, expiry ≤ 90 days).
- Fix recommendation: Keep the timing protection and restore freshness with blinded head commitments. Each SECURITY slot checkpoint (5 min) also carries `H("candor/v1/audit/head-commit\0" ‖ r_slot ‖ case_head ‖ case_end_seq)` with a fresh random `r_slot`, and the openings are stored locally. The commitment reveals nothing about whether CASE changed. At the daily checkpoint (or on audit) the openings let the verifier check that the CASE chain at each 5-min slot is a prefix of the attested chain. Alternatively accept it formally. Add a truncation test.
- Spec / requirement reference: 20 §8, AUD-002/003/004, THR-037.
- Status: Open (needs a fix or written acceptance)

### AUD-RM1-LOG-20 — Verifier enforces only the minimum retention bound
- Severity: Low
- Location: crates/candor-log/src/verify.rs `min_retention_ms` (fc64069)
- Category: B12 (CWE-354)
- Description: The prune check allows deletion once the anchor is 90 days old (SECURITY) or 7 days old (SYSTEM), even when the deployment policy is 400 days or 7 years. An insider who can emit `audit.retention_tombstone` can therefore delete SECURITY history early, and verification still passes. The tombstone is visible, which is why this is Low.
- Fix recommendation: Add `min_retention_days` to `VerifyParams` (from the signed, configured policy), and have OVERSIGHT verification pass the configured value.
- Status: Open

### AUD-RM1-LOG-21 — Free-text lint misses panic-message variants and process logging
- Severity: Low
- Location: crates/candor-log/scripts/lint-logging.sh; clippy.toml (fc64069)
- Category: B1.3 (P-13)
- Description: These pass both the lint and clippy: `assert!(ok, "peer {ip}")`, `assert_eq!(x, y, "{}", ip)`, `r.expect(&format!("peer {ip}"))`, `std::panic::panic_any(ip)` and `Command::new("logger").arg(ip)`. With `panic = "abort"`, the message still goes to stderr and then journald.
- Fix recommendation: Extend the panic pattern to `assert*!`/`debug_assert*!` messages with format arguments and to `expect(&format!` / `expect(format!(`. Ban `std::panic::panic_any` and `std::process::Command::new` (allow-list per crate). Add fixtures.
- Status: Open

### AUD-RM1-LOG-22 — Suppression audit relies on the LP relaxation (integer attacker may be stronger)
- Severity: Low
- Location: crates/candor-log/src/metrics.rs (simplex audit) (fc64069)
- Category: B1.7
- Description: Feasible ranges are computed over the reals. With priors on cell *sums*, folded-channel protections and facts from several releases, the constraint matrix is not totally unimodular, so the integer feasible range can be narrower than the LP range. The audit could then pass a table that pins a cell for an integer attacker. The builder records this as a residual covered by brute-force tests only.
- Fix recommendation: Shrink each LP bound to an integer (ceil for lower, floor for upper) and require the range to be ≥ k−1 on those integer bounds. For tables of practical size (≤ a few hundred unknowns) add an exact integer check (branch and bound on the two extreme objectives), failing closed past a budget.
- Status: Open

### AUD-RM1-LOG-23 — API observations (production redaction path; Site trait)
- Severity: Info
- Location: crates/candor-log/src/sink.rs `RedactionPlan` (only built by `MemoryStore::plan_case_redaction`); src/diag.rs `__private::Site` (fc64069)
- Description: (a) A production C-24 store (PostgreSQL) cannot build a `RedactionPlan`, so disposal needs crate changes. When that API is added, make sure it does not reopen LOG-16. (b) A hand-written `Site` impl can call `__private::emit` directly, which bypasses the `Info`/`Trace` release ceiling. Its `MODULE` constant is not validated. Everything stays compile-time constant, so this has no data-leak impact.
- Status: Open

### Assessment of the builder's deferrals (SFS-08)

| Deferral | Assessment |
|---|---|
| `O_TMPFILE` + link | **Acceptable as a tracked deferral (Info), but the justification is inaccurate.** `linkat(AT_FDCWD, "/proc/self/fd/N", dirfd, name, AT_SYMLINK_FOLLOW)` needs no capability, only procfs. Access to the process's own fds survives `ProtectProc=invisible`. `CAP_DAC_READ_SEARCH` is needed only for the `AT_EMPTY_PATH` form. Because `O_TMPFILE` would also fix SFS-10, it should be scheduled before RM-2 intake goes live. Track it under SL-R-001 |
| inotify "no inode outside root" test | **Acceptable** as a deferral to the C-17 integration suite. It remains an IMPL-RM1 §1.6 Verify item and must be ticked before the RM-1 exit (§7) |
| Nightly fuzz CI job (both crates) | **Acceptable short-term only.** Targets and seeds exist and the smoke runs are clean. ST-048/049/051 require them to run in CI, so the job must land before the RM-1 exit. Add `-seed_inputs`/a scratch corpus dir so that CI never writes into `fuzz/seeds/` |

### Summary (round 2)

| Severity | Open (new + carried) |
|---|---|
| Critical | 0 |
| High | 2 (LOG-02 record-order channel; LOG-16 tombstone forgery) |
| Medium | 3 (LOG-17, LOG-18, LOG-19) |
| Low | 6 (SFS-10, SFS-11, LOG-20, LOG-21, LOG-22; LOG-14 accepted-residual pending signature) |
| Info | 3 (SFS-08 deferrals, SFS-12, LOG-23) |

Fixed and verified: SFS-01, 02, 04, 05, 06, 07, 09; LOG-04, 05, 07, 08, 09, 10, 11, 12, 13, 15. Fixed with variants tracked under new IDs: SFS-03, LOG-01, LOG-03, LOG-06.

`candor-safefs` has no open Critical, High or Medium findings, so it meets the gate (§F) once the lead tracks the Lows and Infos.

Gate: **FAIL** 2026-10-01 fc64069. `candor-log` has 2 open High (LOG-02 residual channel, LOG-16), and 3 Medium need a fix or written acceptance (LOG-17, LOG-18, LOG-19).

---

## Re-test (round 3)

Re-tested HEAD `8163ede` (WIP 422fbbb/5b05257/8163ede) plus the uncommitted tree, 2026-10-01. Procedure §G, focused on the round-2 findings and variants.

**Tools:**
- `clippy -D warnings` (both crates): clean.
- `cargo test -p candor-safefs -p candor-log`: all pass, including the new UI tests `forge_tombstone` and `no_magnitude_api` and the inotify test.
- Miri (candor-log lib): 28/28.
- `lint-logging.sh`: OK (90 files). The round-2 lint fixture (panic_any, Command, assert/expect messages, temp_dir+extend) is now fully reported.
- cargo-fuzz: 8 targets, 46 s each, run in **scratch corpus dirs** (seeds read-only). No crash/OOM/timeout. Coverage: log verify 1494, jsonl 2987, checkpoint 1062, cbor 384; zip 1802, tar 1269, tar_gz 1923, names 927.
- `git status` of both crates: unchanged.

**Out-of-scope lint-safefs hits (listed only):** `crates/candor-sealer/src/server/handover.rs:32,129,142,146` (`rustix::fs` memfd/seal/fstat). No hits remain in core `vectors.rs` or intake-store `staged.rs` on this tree.

| Finding | Status | Evidence / remark |
|---|---|---|
| LOG-02 (H) | **Fixed** | Date-only events go to the `case-slot`/`sys-slot` streams. They are staged and written only at import-slot boundaries, Fisher–Yates shuffled with rejection-sampled CSPRNG (code read OK). CASE/SYS are back to the data-independent 5-min schedule. Tests `date_only_events_never_neighbour_exact_time_events` and `checkpoint_timing_independent_of_date_only_events`. The per-slot count is visible to the witness, which is accepted (ADR-038(1) slot granularity) |
| LOG-16 (H) | **Fixed** | Tombstones are built only via `emit_case_disposal`/`emit_retention_tombstone` (private payloads; `emit` → `TombstoneViaApi`; UI test `forge_tombstone`). `ApproverKeys::verify` requires 2 distinct pinned keys and strict Ed25519 over a domain-separated canonical request. The verifier uses its own pinned `approver_keys`. Stubs carry `case`, which is bound into `c_i` and must equal the tombstone's case. The round-2 forge PoC no longer compiles (`checkpoint_root`, `redaction_set_hash` and the variant are gone). The retention authorization is a standing (replayable) policy grant, acceptable because the age is checked per prune |
| LOG-17 (M) | **Partially fixed → LOG-24 (M)** | Random-only ids, MAC-sealed `IdToken` (constant-time), randomized value commitments, origin-bound checkpoint values, `ForeignArtefact` check: all verified. The new variant is LOG-24 |
| LOG-18 (M) | **Fixed** | Magnitude/ratio API removed (`no_magnitude_api`). A v1 history is refused |
| LOG-19 (M) | **Fixed** | 5-min CASE/SYS checkpoints plus an hourly/per-slot witness feed that includes empty ticks. The verifier gives `TRUNCATED`/`ROLLBACK` against the witnessed head (test `witness_ticks_and_truncation_beyond_witnessed_head`). Residual ≤ 1 tick, conditional on the witness alarming on missed ticks (operations requirement for C-24/witness) |
| LOG-20 (L) | **Fixed** | Dual-approved `retention_days`, verified against `max(§12 minimum, min_retention_days)` |
| LOG-21 (L) | **Fixed** | Fixture re-run above. Clippy bans `panic_any`/`resume_unwind`/`Command::new` |
| LOG-22 (L) | **Fixed** | Integer branch and bound after the exact simplex, failing closed at 4096 nodes. Test `integer_attacker_narrower_than_lp_is_caught` |
| LOG-23 (I) | **Fixed** | `RedactionPlan::build(&impl CaseRecordSource)`; the diag `MODULE` is checked; the release ceiling is enforced in `emit`. Residual: a hand-written `Site` can claim `DEBUG_ASSERTIONS = true` (static text only, Info) |
| LOG-14 (L) | **Ruling: residual acceptable** | Both `coi_tags_updated` and system-actor COI removals are now date-only, shuffled within a slot, and never adjacent to each other. The residual (co-occurrence for one case within one slot window, the granularity imports already have) is at most Low. **Recommend lead acceptance** for 90 days, on this condition: C-22 must emit *every* COI-caused removal with a system actor. A staff-actor COI removal in the exact-time CASE stream, close in time to a tags update, would reintroduce linkage. Add a C-22 test when that crate lands |
| SFS-10 (L) | **Fixed** | Root mtime is settled to a monotonic `fetch_max` slot; abandoned writes write that slot, never a captured time. Test `overlapping_pending_objects_leave_root_at_slot_time`. Note: before the first commit, the fallback is the root's open-time mtime floored to 15 min (no finer than the slot grid) |
| SFS-11 (L) | **Fixed** | clippy and script bans (temp_dir, set_extension, Command, panic_any, tempfile non-dev). The round-2 fixture is caught. `workspace_clippy_bans_fire_on_fixture` |
| SFS-12 (I) | **Fixed** | Local flags == central flags; CRC/sizes always compared; bounded zip64 local-extra parse. Test `zip_local_flag_and_zip64_mismatch_rejected`; zip fuzz clean |
| SFS-08 deferrals | **Accepted** | inotify test **done** (`no_inode_activity_outside_root_inotify`). O_TMPFILE rationale corrected and tracked (SL-R-001, before RM-2 go-live). The nightly fuzz job is specified in SPEC-NOTES but **not yet in ci.yml**: the lead must add it before RM-1 exit (it writes only to a scratch corpus, which is correct) |

### AUD-RM1-LOG-24 — `Seq::of_failure` launders 64 caller-chosen bits via a crafted verification failure
- Severity: Medium
- Location: crates/candor-log/src/field.rs `Seq::of_failure`; src/verify.rs (failure seq read from record CBOR / `ChainRecord::Redacted.seq`)
- Category: B1.4 (CWE-532)
- Description: `verify_stream` can be run by anyone with the writer's **public** checkpoint key over caller-built records. A `ChainRecord::Redacted { seq: X, .. }` in the SEC stream (or a Full record whose CBOR `seq` = X with a mismatched tenant) fails with `seq = X` and `origin = writer key`. `Seq::of_failure` then yields a `Seq` that `emit` accepts (origin matches). PoC (scratch `auditlog-r2-poc/src/bin/r3seq.rs`): X = `0xcb007107000001bb` (IPv4 203.0.113.7:443) goes into `audit.verification_failed.seq` and `emit` returns Ok.
- Exploit scenario: Same as LOG-03/17. A trust-path developer can log 64 bits (an IP and port) with code that passes review and the type system.
- Fix recommendation: In `emit`, require every `Seq`/`SeqRange` to lie within the writer's own state for the named stream (`< next_seq`). Or clamp the failure seq in `verify_inner` to `min(seq, expected)` (it never needs to exceed the walked position), and drop the attacker-controlled `seq` in the `EnvelopeMismatch`/`UnboundRedaction` paths in favour of `expected`. Add the PoC as a test.
- Status: Open

### AUD-RM1-LOG-25 — Staged date-only events are lost on a crash (suppression of import/canary audit records)
- Severity: Low
- Location: crates/candor-log/src/chain.rs staging (`StreamState::staged`, `MAX_STAGED_PER_SLOT`)
- Category: B12 / integrity (CWE-778)
- Description: Date-only events sit in memory for up to one import slot (default 6 h). A process abort (panic=abort, OOM, kill) drops them silently, including `case.canary_escalated` and `case.imported`. The builder documents this as a residual. The only trace is `sys.service_started`. Overflow beyond `MAX_STAGED_PER_SLOT` returns `SeqOverflow`, a misleading code (it fails closed, which is correct).
- Fix recommendation: Durable stage: append each staged event, AEAD-sealed under a per-slot ephemeral key held in memory, to a preallocated fixed-size staging file (no growth, no per-event mtime meaning), or into the C-24 DB as an unordered encrypted blob. On restart, emit a `sys.stage_lost {count bucket}` event if the key is gone. At minimum, record a staged-count high-water mark so that a restart reveals the loss. Use a distinct `StageFull` error.
- Status: Open (Low; needs a fix or lead acceptance)

### Summary (round 3)

| Severity | Open |
|---|---|
| Critical / High | 0 / 0 |
| Medium | 1 (LOG-24) |
| Low | 2 (LOG-25; LOG-14 pending the lead's signature per ruling above) |
| Info | LOG-23 residual (Site claims) |

**candor-safefs: Gate PASS 2026-10-01 8163ede** (no open C/H/M). Pending lead items: add the fuzz-nightly job, track O_TMPFILE.

**candor-log: Gate NOT YET PASS.** There are no open Critical or High findings. LOG-24 (Medium) needs a fix (small) or the lead's written acceptance. Then LOG-25/LOG-14 need acceptance or a fix, which does not block.

## Lead dispositions after round 3 (2026-10-01)
- **candor-safefs: gate PASS.**
- **LOG-14 (Low residual): accepted for 90 days** (review by 2026-12-30), on condition that C-22 emits every COI-caused removal with a system actor; tracked for the C-22 build.
- **LOG-24 (Medium): sent to the fixer**; the gate stays closed until it is re-tested.
- **LOG-25 (Low): sent to the fixer** (crash-loss marker for staged slot events).
- **Nightly fuzz job:** added as `.github/workflows/fuzz-nightly.yml`, covering every target in core, safefs, log and sealer.
- **O_TMPFILE wording:** tracked before RM-2 go-live.

---

## Re-test (round 4, candor-log delta)

Commit `8517304`; candor-log clean in the working tree. Clippy `-D warnings` is clean. `cargo test -p candor-log`: 102 passed, 0 failed (incl. `crafted_failure_seq_cannot_be_logged`). Scratch-corpus fuzz smoke runs (`fuzz_audit_log_verify` cov 1486, `fuzz_jsonl_read_verify` cov 2976, 40 s each): clean. The repo is unchanged.

| Finding | Status | Evidence / remark |
|---|---|---|
| LOG-24 (M) | **Fixed** | `origin_ok(key, max_seq)`: a `Seq` must be ≤ the writer's largest `next_seq`, and a `SeqRange` must satisfy `first ≤ last < max_seq`. My round-3 PoC (`r3seq`, `0xcb007107000001bb`) now gets `emit` → `Err(ForeignArtefact)` |
| LOG-24 residual | **Rated Low** (new ID LOG-26) | See below |
| LOG-25 (L) | **Fixed** | `note_restart()` stages a date-only `sys.stage_lost {stream}` per slot stream, written to `sys-slot` at the next boundary (no finer time). A full stage returns `StageFull`. Effectiveness depends on C-24 calling it at every start-up; the doc comment says so. Track it as a C-24 integration test |
| Lead dispositions after round 3 | **Reviewed: consistent** | safefs PASS; LOG-14 accepted for 90 days with the C-22 system-actor condition (matches the round-3 ruling); fuzz-nightly workflow added (closes the SFS-08/LOG-10 CI deferral); O_TMPFILE tracked before RM-2 |

### AUD-RM1-LOG-26 — Counter-bounded sequence fields still carry ≈log2(next_seq) bits
- Severity: Low
- Location: crates/candor-log/src/field.rs `Seq`/`SeqRange::origin_ok`; producers `Seq::of_failure`, `SeqRange::within`
- Description: Through a crafted verification failure a caller can still choose any value below the counter. Once a stream holds n events, that is ≈log2 n bits per `Seq`, and ≈2·log2 n bits per `SeqRange`. A `SeqRange` carries an IPv4 address once the largest stream exceeds about 92 k events, which is realistic within weeks. The bound is also taken over the *largest* stream, not the stream the field names. Exploitation still needs a deliberate covert encoding by a developer, the producing APIs are limited to verification tooling, and capacity has dropped from 64 caller bits to a counter-bounded value. Low.
- Fix recommendation: Bound against the named stream's `next_seq`. Add workspace `disallowed-methods` for `Seq::of_failure` and `SeqRange::within` outside the audit-tooling crate(s), with a reasoned allow at the legitimate call sites, so code review sees every producer. Optionally, clamp failure seqs in `verify_inner` to the walked position.
- Status: Open (Low; does not block)

**candor-log: Gate PASS 2026-10-01 8517304.** There are no open Critical, High or Medium findings. Open Lows (LOG-25 C-24 call-site test, LOG-26) and the accepted LOG-14 are tracked. **candor-safefs: PASS** (unchanged).

## Lead dispositions after round 4 (2026-10-01)
- **candor-log: gate PASS (8517304).**
- **LOG-26 (Low):** fix assigned (bound against the named stream's counter; clippy bans on `Seq::of_failure` / `SeqRange::within` outside the audit tooling).
- **LOG-25 call site:** C-24 must call `AuditLog::note_restart()` at every start-up, with an integration test; tracked for C-24.
