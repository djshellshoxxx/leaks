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
- Description: Writes use named `.tmp-<random>` files in the root instead of `O_TMPFILE`, so the inode is visible before validation (SL-R-001). The inotify "no inode outside root" test is absent. The four fuzz targets exist but are not run in CI (the smoke results are below). `ContentKey` derives `Clone` (B3.1: only if needed).
- Fix recommendation: Implement `O_TMPFILE` + `linkat(AT_EMPTY_PATH)` on Linux, with a fallback to the current path. Add the inotify test. Add a nightly fuzz job. Drop `Clone` from `ContentKey` if it is unused.
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
| Miri | `cargo +nightly-2026-09-28 miri test -p candor-log --lib` | MIRI_RESULT |
| cargo-fuzz | `cargo +nightly-2026-09-28 fuzz run <t> -- -max_total_time=60 -rss_limit_mb=2048 -timeout=10` for the 4 safefs targets | FUZZ_RESULT |
| shellcheck 0.9.0 | `shellcheck -S style` on both lint scripts | clean |
| repo lints | `lint-safefs.sh`, `lint-logging.sh` on the real tree | both OK (74/83 files). Bypasses: SFS-01, LOG-09 |
| semgrep / zizmor / systemd-analyze | — | not applicable (no custom rules yet; no workflows/units in scope) |
| PoCs | scratch crate depending on both crates by path (not committed) | confirmed LOG-01, LOG-02, LOG-03, LOG-04, LOG-05 and SFS-02 as described |

## B12. Test assessment

The tests are strong on the happy and negative paths for limits, traversal, bombs, CBOR canonicality, chain tamper (modify, reorder, delete, truncate, rollback) and suppression pinning. Missing negative tests: redacted stubs outside CASE or without a tombstone (LOG-01); checkpoint timing independence (LOG-02); attacker prior knowledge in the suppression oracle (LOG-05); partial sink failure (LOG-07); lint bypass fixtures (SFS-01, LOG-09); display invisible characters (SFS-02).

## Gate

Gate: **FAIL** 2026-10-01 60e732f9 (2 High open: LOG-01, LOG-02; 10 Medium need a fix or written acceptance).
