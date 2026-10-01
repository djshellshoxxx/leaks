<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-sealer — spec notes

Scope: C-07 Intake Sealer. Sources: 04 §9.13, §11, §12.1–12.7, §13.4 (with §13.5 for replies); 07 §4.3–4.4, §5.2, §5.2a, §5.3, §11, BE-003/005/006/047/051/052/055/056/060/072/075; 08 SW-02…SW-28; ADR-004/005/030/033/034/035/036(6,7)/037/038(4)/046(7)/047(3,4,5,6)/050; R7 §A/§B.

## Spec findings that need an amendment

1. **Draft size and the SUBMISSION bucket.** 07 §5.2 allows `DRAFT_SET` text up to 96 KiB. A SUBMISSION is at most 64 KiB (§13.6), and its inner map also carries the Recipient Lists, the manifest and the signatures (about 20 KiB in the worst case).
   **Implementation decision:** `MAX_DRAFT_TEXT = 40 KiB` (message plus answers), checked when the request is decoded. If an envelope still does not fit at seal time, the sealer returns `LIMIT` and seals nothing.
2. **Recipient List entries for the bundle and identity slots (ADR-050(3)).** Full slot verification needs `{slot_index, key_id, enc_rand}` for *every* intake object. §13.4 has a place only for the SUBMISSION's own slots.
   **Implementation decision:** SUBMISSION key 16 (and SOURCE_MESSAGE key 8) carries key 1000 for the ATTACHMENT_BUNDLE entries and key 1001 for the IDENTITY entries. Keys of 1000 and above are the §13 forward-compatible range.
3. **Key 16.2 format.** §13.4 says "[MEK key_id …] sorted". ADR-050(3) replaces this with entries.
   **Implementation decision:** an array of 97-byte `RecipientListEntry` wire forms (`u8 slot_index ‖ key_id ‖ enc_rand`), sorted by `key_id`.
4. **Categories.** SW-02/07 accept up to 8 categories, but §13.4 key 17 is a single uint.
   **Implementation decision:**
   - the COI filter removes the union of the exclusions of all selected categories (the safest reading);
   - key 17 holds the first category;
   - key 1000 holds the full list when more than one is selected;
   - key 17 is omitted when none is selected.
5. **`prefs_ct` lacks two fields that Tier W needs.** The channel is needed because the reply stanza `info` binds the channel and REPLY headers carry no channel (§13.5). The initial SUBMISSION's `object_hash` is needed for SOURCE_MESSAGE key 9.
   **Implementation decision:** each report entry adds key 1000 (`channel_id`) and key 1001 (`original_submission_hash`). The prefs plaintext is `{1: format=1, 2: kdf_version=1, 3: [reports], 4: {}}`. It is sealed with the §13.8 record under `K_prefs`, with AAD `SourcePrefs{tenant, lookup_tag, prefs_version = 1}`. The AAD binds `prefs_ct` to the account, so the store cannot substitute another account's prefs.
6. **Auth signature form.** 07 §5.2 `LOGIN_SIGN` says `"candor-src-auth-v1" ‖ tenant_id ‖ challenge`. 04 §11.5 (canonical) says `"candor/v1/source-auth" ‖ challenge ‖ tenant_id ‖ audience`.
   **Implementation decision:** the 04 form (`candor-core`), with audience `b"source-web"` (`AUTH_AUDIENCE`). The store must verify with the same audience.
7. **Who writes the staging area.** In 07 §5.2/§5.3, `SEAL_CHUNK` returns ciphertext and the *web* stages it through the store. The build assignment says the sealer writes staged parts itself, through `candor-safefs`, into a tmpfs root.
   **Implementation decision:** the assignment's model. One consequence: the 07 §4.3 seccomp allow-list (no `openat`) cannot hold. The filter must also allow `openat`, `unlinkat`, `renameat2`, `linkat`, `fsync`, `fdatasync`, `fchmod` and `utimensat`. Landlock confines all of these to the staging root.
   The sealed ATTACHMENT_BUNDLE is also written to staging (`Blob::Staged`), so the store moves ciphertext and never receives the bundle over IPC.
8. **Padding before STREAM when the length is unknown.** §9.13 / ADR-038(5) require padding to the bucket *before* STREAM encryption, and STREAM must know the total length up front. A no-JS multipart upload is streamed without knowing the part length in advance.
   **Implementation decision:** `PART_BEGIN` carries `declared_len`, an upper bound that the web takes from the request `Content-Length`. The part is padded to `bucket_for(declared_len)`. Data beyond `declared_len` aborts the part (`LIMIT`). The real length and the evidence hashes stay in sealer RAM.
9. **Transport.** 07 §5.2 specifies `SOCK_SEQPACKET`. The assignment asks for length-prefixed framing.
   **Implementation decision:** `u32be` length prefix over a stream socket, with the same 128 KiB limit, the same `{"v","op","rid","body"}` envelope and the same strict decoding.
   Because of that limit, `OPEN_REPLIES` (up to 64 × 70,000 B) cannot fit one frame. It became `OPEN_REPLY`, one entry per request. Rotation sends `(object_hash, stanza)` pairs (≤ 64 × ~1.3 KiB) instead of whole replies.
10. **Operation set.** The table in 07 §5.2 changes as follows:
    - Withdrawn: `SEAL_CHUNK` (see 7).
    - Redefined: `PART_BEGIN` 0x20 now carries `declared_len`, the display name and the media type. Display names move out of `SEAL_FINISH`.
    - New: `PART_CHUNK` 0x21, which stages internally and returns `{}`.
    - New: `ROTATE_FINISH` 0x16. 07 overloads `ROTATE_PASSPHRASE` with an "after confirmation" response; this op separates the two steps.
    - New: `TOUCH` 0x41 (SW-21).
    - New error codes: `BAD_STATE` and `UNAVAILABLE` (04 §12.6 outage). Both carry `alternative_channel_id` where one exists.

    **Not implemented, follow-on work:**
    - `SEAL_SIGNAL` 0x26: it needs MEKs for the epoch of the release day (BE-078).
    - `STATUS.pool_free_band`: the slab pool does not exist (item 15); the band is fixed at 4.
    - More than one report per passphrase (§11.6): v1 Tier W uses report index 0.
11. **The chaff bucket distributions (`CHAFF_BUCKETS_*`) are not in the 39 registry.**
    **Implementation decision:** these provisional public defaults (`ChaffBuckets::default`), which the config can override and which are validated at start:

    | Object | Distribution |
    |---|---|
    | SUBMISSION, SOURCE_MESSAGE | always 64 KiB (maximum bucket, ADR-052(1)) |
    | IDENTITY | always 16 KiB (maximum bucket, ADR-052(1)) |
    | ATTACHMENT_BUNDLE | file buckets ≤ 8 MiB, weighted toward the empty-bundle bucket (256 KiB); configurable (`ChaffBuckets::bundle`), must include 256 KiB |
12. **Epoch numbering is not defined.**
    **Implementation decision:**
    - the snapshot carries `epoch_origin_day`, and `epoch = (today − origin) / 7`;
    - a member's MEK is used only if its `epoch_id` equals the current epoch and `valid_from ≤ today < valid_until`, and it is neither revoked nor ambiguous (two valid entries count as none);
    - BE-032's ±1-day tolerance is *not* applied. Strictness only shrinks the recipient set and can fail closed; it never widens it.
13. **The IDENTITY inner format is undefined.**
    **Implementation decision:** `u32be(len) ‖ {1: format=1, 2: text}` padded to the maximum IDENTITY bucket (16 KiB, ADR-052(1)). ANONYMOUS mode, follow-ups and key rotations seal an empty text.
    The IDENTITY object always goes to K13 (one real slot), so its shape does not reveal the mode. Chaff identities have 16 dummy slots (§12.7).
14. **Reply verification (§13.5).**
    - REPLY `format` = 1.
    - The signer is resolved through the snapshot's USER_KEYS entry (inner key 6) and must be a member of the channel's roster in the *current* snapshot. The roster in force on the reply's `day` is not available to the sealer.
    - Monotonic `reply_seq` is enforced as replay rejection per session: a repeated `(mailbox, seq)` renders as "not verified".
15. **Locked slab pool (BE-047) and `madvise` (07 §4.4).** Neither is implemented. `mlockall(MCL_CURRENT|MCL_FUTURE)` locks every allocation.
    Secret buffers are allocated once at their final size so they never reallocate (R7 SI-A-05): frames, CBOR encoders, chunk buffers, NFC output and lossy UTF-8.
    `MADV_DONTDUMP` / `MADV_WIPEONFORK` need `unsafe`. Instead the crate relies on `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0` and the systemd `LimitCORE=0`; the sealer never forks.
16. **Snapshot freshness at day resolution.** BE-031 limits the sealer to day-resolution time. The sealer refuses when `today − issued_day ≥ 7`, which is conservative: a checkpoint that *may* be more than 7 days old is refused. A checkpoint dated more than one day in the future is refused too.
17. **Chaff cancellation.** Each real commit (`SEAL_FINISH`, `ROTATE_FINISH`, `NOTE_REAL`) cancels the next scheduled event for its channel. Pending cancellations are capped at 64 per channel.
18. **Confirmation failures during rotation.** After 5 failures only the pending rotation passphrase is dropped. The authenticated session stays.

## Implementation decisions (other)

- **Directory snapshot.** The sealer seals only against a `VerifiedSnapshot` (ADR-052(6)), which it *derives* from the complete Key Directory log (SEA-19, see "Key Directory verification" below). No free-standing view can be installed.
  The sealer itself enforces:
  - checkpoint signature, witness cosignature policy, RFC 9162 consistency from the persisted high-water mark `(tree_size, root_hash, issued_hour)`, and view invariants;
  - suite equality;
  - freshness;
  - `effective_day` time locks on roster members and COI policies;
  - the Triage Set (`read_intake`) and its ≤ 16 invariant;
  - MEK windows.
- **Independent time.** This is the integrator's `Clock::today()`: Tor consensus plus Roughtime, 16 §14.3. On any error the sealer fails closed with `UNAVAILABLE`. Timers use the monotonic tokio clock only. No sub-day time is ever written: staging files carry the UTC day start.
- **`IntakeStore`.** The sealer defines `server::sink::EnvelopeSink` with two methods shaped after ADR-052(2): `commit_envelope_group(group, epoch_id, received_day, release_offset_days)` (no account reference) and `upsert_account(AccountUpsert { replaces, account, rewrapped_replies })`.
  **Integration:** implement it over the store client (the intake-store fixer is changing `IntakeStore` the same way: envelope commit without `AccountLink`, separate account create/replace). On `Ok`, the sink owns the staged bundle file; on `Err`, the sealer deletes it.
- **Recipient selection order.** Selection runs first and is cheap; Argon2id runs after it.
  - Fail-closed refusals never consume the confirmed passphrase.
  - A store failure after derivation discards the derived keys. Nothing was committed, so the source restarts (§11.1).
- **Login uniformity.** `LOGIN_DERIVE` does the same work for every input, including invalid UTF-8, which goes through lossy decoding. The sealer has no account knowledge, so it cannot be an existence oracle.
  Floor latency and the uniform challenge belong to C-06 and C-08 (SW-10, API-056).
  All Argon2id overload states map to the same `BUSY`.
- **Sessions.**
  - At most 64.
  - Each session has its own `tokio::sync::Mutex`, and the table holds only the handle → session map plus timestamps.
  - Expiry is checked on every access and by a 10 s reaper.
  - Dropping a session zeroizes K36, the draft, the passphrase and the derived keys, and unlinks the staged files.
  - A successful submission replaces K36 and drops the draft and the staged parts.
- **Hardening.** The crate enforces Landlock in-process: filesystem access only beneath the staging root, and no TCP bind/connect at ABI ≥ 4. `harden_process` refuses unless it runs on the main thread outside any tokio runtime; the sealer then serves on `hardening::confined_runtime()`, whose threads are recorded as confined. `Sealer::serve` refuses unless `hardening::self_check()` passes on the serving thread, and in serve mode every request, frame and blocking job re-checks its thread (SEA-06, SEA-20).
  seccomp is delegated to systemd `SystemCallFilter=` (explicit allow-list, see SEA-06). In-process seccompiler would need a hand-maintained tokio/safefs allow-list, and 07 §4.3 conflicts with item 7.
  See the README for the unit file.
- **K35 (sealer signing key).** It is passed in by the integrator, never read from the environment. The integrator loads it from a `LoadCredentialEncrypted=` credential (R7). `sealer_sig` is added to SUBMISSION (key 19) and SOURCE_MESSAGE (key 12).
- **Logging.** The sealer emits no logs. The only audit event it emits is the `sys.health{service=upload, DEGRADED, READINESS}` record that `InsecureDevMode::acknowledge` writes through the integrator's `candor_log::AuditLog` (SEA-06). candor-log has no dedicated code for it yet (coordination item C-2 below); the event kind and codes are two constants in `hardening.rs`. Lifecycle `sys.*` events belong to the integrating binary. The listener counts survived `accept()` errors (`Sealer::accept_errors()`) for the integrator's health reporting.

## Dependencies

| Crate | Version | Why |
|---|---|---|
| `zeroize` | =1.8.2 | Zeroizing buffers in `proto` (the only proto dependency). |
| `candor-core` | path | All cryptography and formats (C-11): source keys, slots, objects, STREAM, records, stanzas, KATs. |
| `candor-safefs` | path | The single audited filesystem API for the tmpfs staging root (ADR-027). |
| `tokio` | =1.48.0 (`rt`, `rt-multi-thread`, `net`, `sync`, `time`, `io-util`) | Unix-socket listener, the per-session async mutex, the Argon2id semaphore, timers and `spawn_blocking`; `rt-multi-thread` for `confined_runtime` (SEA-20); `signal` for the SIGTERM batch flush (SEA-28(c)). Same pin as the store. |
| `rustix` | =1.1.2 (`fs`, `mm`, `net`, `process`, `thread`) | Safe `mlockall`, `prctl(PR_SET_DUMPABLE)`, `setrlimit(RLIMIT_CORE)`; `gettid` (main-thread check, SEA-20); `memfd_create`/`fcntl_add_seals`/`fstat`/`pread` on the anonymous bundle file and `sendmsg`/`recvmsg` with `SCM_RIGHTS` (hand-over, SEA-16). No path is opened. Same pin as safefs and the store. |
| `landlock` | =0.4.7 | In-process filesystem and TCP confinement (R7 SI-B-03). Safe API. |
| `ml-dsa` | =0.1.1 (no default features) | Verification of the ML-DSA-65 half of hybrid K01 signatures on KD entries (FIPS 204, RustCrypto; AUD-RM2-SEA-27). candor-core has no ML-DSA; only its already-locked dependencies (signature, hybrid-array, shake, module-lattice, ctutils) are added. Migrate into candor-core with C-1. |
| `candor-log` | path | Typed audit event for the developer override (ADR-052(5), SEA-06); no free-text logging. |
| `hkdf`, `sha2` | =0.13.0, =0.11.0 | Chaff CK derivation `HKDF(chaff_seed, u64 counter, "candor/v1/chaff/seed")` (§12.7); SHA-256 of the handed-over bundle (store header). candor-core exposes no generic HKDF and no streaming SHA-256. Pins match core. |
| `subtle` | =2.6.1 | Constant-time word-index mapping. |
| `unicode-normalization` | =0.1.24 | NFC of the message (§13.4 key 13). Pin matches core. |
| `proptest`, `tempfile`, `tokio[test-util,macros,rt-multi-thread]` | dev | Property tests, temporary roots, paused-time tests. |

## Tests and requirement mapping

| Test | Covers |
|---|---|
| `tests/flow.rs::full_tier_w_flow` | ST-025, 04 §12.3/§13.4. The full flow: open → draft → stage → COI → passphrase → wrong and right confirmation → seal with delay → recipient-side trial open. Then: full ADR-050 slot verification of all 3 objects; `source_sig` and `sealer_sig`; bundle bytes, manifest and SHA-256; IDENTITY to K13 only; real disposition kind; login (uppercase input, NFKC/lowercase); `LOGIN_SIGN` verification; `LOAD_PREFS`; reply decrypt and verify; replay and spoofed signer rejected; follow-up sealed only to the original eligible set while a later-added member gets no slot (BE-052); rotation with `NOT_CONFIRMED`, re-wrapped reply readable with the new passphrase, KEY_ROTATION signed by the old and new keys, and the old prefs unusable (BE-072, API-050). |
| `tests/fail_closed.rs` | API-036/058 COI excluding everyone → `NO_ELIGIBLE_TRIAGE` plus the alternative channel; no valid MEK; stale snapshot (7 days) versus 6 days; clock failure; rollback and suite mismatch (BE-060); `NOT_CONFIRMED` (BE-056, API-039); 5 failures zeroize the session; regeneration limit; store failure leaves no envelope and no sealed bundle; unknown or disabled channel; bad states; oversize parts; session capacity → `BUSY`. |
| `tests/hygiene.rs` | BE-005/055: 20 min idle and 2 h absolute expiry (paused clock) zeroize and unlink; `PART_DROP` / `SEAL_ABORT` / `ZEROIZE`; size bucket only in `DRAFT_GET`. **No plaintext on disk:** a run-unique marker in the message, answers, identity, filename and attachment is absent from staging, the fixture tempdir, freshly written files in `$TMPDIR` and all store inputs; the passphrase is absent from disk and from store inputs. |
| `tests/chaff.rs` | BE-075 / §12.7: a chaff triple is structurally identical to a real anonymous submission (types, tenant, channel, epoch, slot block size, legal buckets, exact lengths, `disposition_ct` size); no member or custodian opens any chaff slot; K41 tells kinds 0 and 1 apart; the follow-up shape; fail-closed chaff (no time, unknown channel, sink failure leaves nothing staged); the Poisson schedule under a paused clock; `NOTE_REAL` cancellations suppress events. |
| `tests/ipc.rs` | BE-006: socket round trip, `HELLO` first, second `HELLO`, oversize prefix, garbage body and wrong version all give `BAD_FRAME` and a close; a wrong SO_PEERCRED UID is disconnected without a byte. |
| `tests/proto_props.rs` | ST-040/041 decoder robustness: arbitrary bytes never panic for any op; request round trips; **canonicity** (any mutated frame that decodes re-encodes byte-identically); frame-length bounds; response round trips; draft-text bound. |
| `tests/hardening.rs` | BE-003 / SEA-20 (`harness = false`): `RLIMIT_CORE = 0`, not dumpable, Landlock enforced (outside paths unreadable, TCP bind denied), main-thread-only hardening, per-thread confinement of `confined_runtime` threads, pre-hardening threads and runtimes refused. |
| `tests/directory.rs` | SEA-19 / VR-1..VR-6, VR-11, §14.4: the sealer's view is the verified log (see "Key Directory verification"). |
| `tests/handover.rs` | deploy D-33 / SEA-16: sealed-bundle descriptor hand-over and its fail-closed acknowledgement. |
| unit (`src/`) | Strict CBOR (non-canonical, indefinite, tags, floats, negatives, key order, duplicates, limits); BE-051 COI matrix over all flag × category combinations; time locks; revoked or duplicate MEK; follow-up intersection; > 16 Triage Set; prefs round trip and strictness; identity dummy bucket; rejection-sampling helpers; lossy UTF-8 without reallocation; word-index mapping. |

## Security self-review (ASVS 5.0 L3 mindset)

Checked:
- **No plaintext persistence.**
  - Draft text, identity, COI ticks, filenames, passphrases, seeds and keys live only in session RAM (`Zeroizing` / `Secret32` / `SourceKeys`).
  - Attachments reach tmpfs only as STREAM ciphertext under `K_stage`, padded to buckets.
  - The bundle is re-encrypted chunk by chunk.
  - Tests scan for markers.
  - No temp files.
  - No logging (no `println!`/`tracing`; lint-logging passes).
  - Error types are static and carry no input bytes.
- **Debug redaction.** `SessionHandle`, `SecretBytes`/`SecretText`/`SecretWords`, `Coi`, `Value`, `Prefs`, `ReportPrefs` and `Sealer` are redacted; `Session`, `Upload` and `State` have no `Debug`.
- **Strict input handling.**
  - Every IPC field has an explicit maximum, checked before any allocation.
  - Deterministic CBOR only. Unknown, duplicate or misordered keys and trailing bytes are rejected.
  - An item budget bounds the work.
  - Decoding is schema-driven, so there is no recursion on attacker-controlled depth.
  - Frames are 1..=128 KiB.
  - `BAD_FRAME` closes the connection.
  - Proptests cover arbitrary and mutated frames.
- **Fail closed on every privacy path.** Missing, stale, rolled-back, forked, unsigned or wrong-suite snapshot; a log whose entries do not recompute the signed root or that contains any entry failing its format, continuity or signature rule (SEA-19); clock failure; invalid K13 or K41; no eligible Triage Set member; > 16 persons; ambiguous COI_POLICY; store failure (staged output deleted); CSPRNG failure (propagated; never a fixed key). Chaff skips its write on the same conditions (SEA-15). Unhardened processes do not serve (SEA-06). There is no unsealed fallback.
- **Recipient set.** COI is applied in RAM at Submit only, on the Triage Set only, with time locks, and nothing is wrapped before Submit (RVW-A-07). Follow-ups are limited to the original eligible set. The source's COI ticks are never put into `prefs_ct`. The test asserts that a non-triage member, an excluded member and a later-added member hold no slot.
- **Secrets.**
  - Zeroize on drop; minimal lifetime (the passphrase is dropped after derivation, and after 5 failed confirmations).
  - Constant-time compares for confirmation words and the word-index mapping (`subtle`).
  - Signing and K35 handling stay inside candor-core types.
  - Pre-sized buffers (R7 SI-A-05).
- **Side channels.** Login does uniform work. All overload causes return the same `BUSY`. `STATUS` reports only coarse bands. `DRAFT_GET` exposes buckets, not sizes. Undecryptable, foreign, replayed and unverifiable replies return the same `null`.
- **Least privilege.**
  - Peer UID check on accept.
  - No network sockets; Landlock denies TCP.
  - Landlock confines filesystem access to staging.
  - Non-dumpable, `RLIMIT_CORE=0`, `mlockall`.
  - systemd unit in the README: `PrivateNetwork`, `RestrictAddressFamilies=AF_UNIX`, `MemorySwapMax=0`, `SystemCallFilter`, and K35 via `LoadCredentialEncrypted`.
- **Panics.** clippy denies `unwrap`/`expect`/`panic`/indexing and lints arithmetic; all arithmetic is checked or saturating; there is no `unsafe`. In release builds (`panic = "abort"`), a panic kills the process and loses all sessions, which is the fail-closed outcome.

Residual risks:
- A live root or memory-capture compromise of the intake host sees Tier W plaintext and passphrases (ADR-004, 06 R-1, honest statement ADR-035(5)). A compromise *during* rotation sees both passphrases.
- `zeroize` cannot remove copies made by moves, stack spills, kernel socket buffers or the tokio and hyper layers in C-06 (R7 SI-A-05 item 4). Process restarts bound this.
- The plaintext path through C-06 into the IPC socket is outside this crate.
- seccomp and the slab pool are not enforced in-process.
- `madvise(DONTDUMP)` is not applied (mitigated by non-dumpable and `LimitCORE=0`).
- Directory: the time lock of loosening entries is checked against `not_before_day` and the sealer's own high-water-mark day, not the true inclusion day (not carried per leaf).
- Account batching (SEA-21/28): an account write is durable only after the next batch (≤ `account_flush_interval`, default 15 min) or the SIGTERM flush. A crash or kill in between loses queued creates (the envelope is committed, but the new passphrase never logs in) and queued rotations (the *old* passphrase works again after the restart). **Source-UI notice (for 11a, SEA-28(d)):** after submitting or changing the passphrase, the source is told that the passphrase becomes usable for logging in after a short delay (up to about 15 minutes) and that, in the rare event of a service restart within that delay, a new passphrase may not work and the report's replies must then be requested through a new report. Store-side activity marks (login, inactivity purge) of real accounts are outside the sealer and must be uniform in the store.
- Attachment memory (SEA-26): admission is by declared sizes; a session's reservation is released only with its draft, so idle large drafts hold budget until the 20 min idle / 2 h absolute expiry (others get BUSY meanwhile). A failed seal after the bundle was built loses the staged attachments (they were freed while writing); `SEAL_FINISH` is refused until the source has seen the draft again.
- The chaff bundle distribution is provisional (item 11). Bundles larger than 8 MiB (or in buckets the configured distribution does not cover), and real traffic above the chaff rate, are distinguishable (honest limit, §12.7, ADR-052(1)). Dummy accounts are rotated at `dummy_rotation_permille` (SEA-21; provisional default 50 ‰, to be set by policy to the published real share). The K13 holder can classify every group as real or chaff by trial-decrypting its IDENTITY (real groups, follow-ups included, carry one K13 slot; chaff IDENTITY slots are all dummies) — consistent with §12.7 (chaff = all-dummy slots) but to be listed among the §12.7 honest limits (SEA-24(b)).
- The tmpfs staging area reveals bucket-sized ciphertext files and their count per day (ADR-034 accepted).
- **Padding cost.** A part declared large but sent small still costs encrypting zero padding up to its bucket, at most `max_file_bytes`. Staging capacity bounds this (a full tmpfs gives `BUSY`), and so do the C-06 per-circuit rate limits (SW-06: 30/h).
- **Socket permissions.** The socket's file mode and directory (a 0700 RuntimeDirectory) are set by the systemd unit or the integrator. SO_PEERCRED is checked regardless.

## Fixes for AUD-RM2-SEA (2026-10-01; ADR-052)

| Finding | Change | Test |
|---|---|---|
| SEA-01 (High) size/shape distinguishers | ADR-052(1): every group is main + ATTACHMENT_BUNDLE + IDENTITY (`sink::EnvelopeGroup`). SUBMISSION/SOURCE_MESSAGE always 64 KiB, IDENTITY always 16 KiB (`inner::length_prefixed_pad` pads to `max_bucket`; the dry-run sizing pass is gone). Real groups without attachments carry an empty bundle (256 KiB); follow-ups and KEY_ROTATIONs carry an empty IDENTITY sealed to K13 (SOURCE_MESSAGE key 11 = bundle hash, key 1000 = identity hash, Recipient List key 1001 = identity entries). Chaff builds the same three objects; `ChaffBuckets` keeps only the configurable bundle distribution (must include 256 KiB). | `tests/shape.rs` (auditor PoC: 40 KiB message, 4,090-byte identity, follow-ups with/without attachment vs 40 chaff: object count/order, per-object size, total size, bundle in chaff support); `chaff.rs`; `inner.rs::text_objects_use_max_bucket` |
| SEA-02 (High) account linkage, release offset | ADR-052(2): `EnvelopeSink::commit_envelope_group(group, epoch, day, delay)` has no account field; accounts go through `upsert_account`. Initial-shaped chaff writes a dummy account (random `lookup_tag`/mailbox, real Ed25519 `auth_pk`, `prefs_ct` of the same fixed length under a discarded random key; prefs plaintext is now padded to 2,048 B). Chaff delays: `ChaffConfig::delayed_share_permille` (set to the observed opt-in share) × U{1,2,3}. Op order: real initial and chaff initial `A,G`; follow-ups `G`; rotation `G…,A`. | `shape.rs` (op sequence, account shape), `chaff.rs::chaff_triple_…`, `chaff_delay_follows_real_distribution`, `flow.rs` |
| SEA-03 (High) COI per roster entry | ADR-052(3): `select` excludes a user if any of their roster entries (any state) carries an excluded label; Triage Set and the ≤ 16 limit count distinct persons. | `select.rs::coi_applies_per_person_not_per_roster_entry`; `fail_closed.rs::coi_excluded_person_listed_under_two_labels_gets_no_slot` (auditor PoC) |
| SEA-04 (High) listener | ADR-052(4): connection cap (`Limits::max_connections`, 128; over cap → one non-blocking `ERR{BUSY}` + close), handshake / frame / idle / write timeouts (5 s / 5 s / 120 s / 5 s), frames ≤ 256 B before `HELLO` (no 128 KiB buffer for unauthenticated or idle peers), `accept()` errors counted + back-off 10 ms→1 s, loop never returns. | `tests/listener.rs` (cap/BUSY, stalled prefix, handshake and idle timeouts, pre-HELLO size); `tests/listener_emfile.rs` (auditor PoC: EMFILE survived, later connects served) |
| SEA-05 (Med) zero K36 | No fixed key anywhere: after a commit, CSPRNG failure clears the draft and removes the session (response still `Sealed`; `rekey_after_commit`); `SEAL_ABORT` likewise. | `mod.rs::rng_failure_after_commit_never_installs_a_fixed_key` (failure injected); no `from_bytes([0…` in non-test `src` |
| SEA-06 (Med) hardening not enforced | `hardening::harden_process` records a `HardeningReport`; `self_check()` re-verifies dumpable/core limit; `Sealer::serve` refuses (`PermissionDenied`) unless it passes with Landlock fully enforced and the peer UID ≠ 0/own UID, or `SealerConfig::insecure_dev` holds an `InsecureDevMode` token, obtainable only via `acknowledge(&mut AuditLog)` which emits `sys.health{service=upload, DEGRADED, READINESS}` (candor-log has no `Service::Sealer` / hardening check code: **spec/log-owner item**). Disabled chaff also needs the token. Unit: explicit syscall allow-list as `@system-service` minus all other calls (config-check.sh requires the `@system-service` first line), `connect`/`socket` AF_UNIX only (ADR-052(10)). | `tests/hardening.rs` (fails when hardening cannot apply; unhardened/uid-0/own-uid refused; hardened serves; override audit-logged, refused without a sink); `config-check.sh` 635/635 OK |
| SEA-07 (Med) unverified snapshot | ADR-052(6): `directory::VerifiedSnapshot` (private fields, only `verify`): LOG_KEY Ed25519 signature over the §14.3 note body (rebuilt from structured fields; no text/base64 parsing), C2SP cosignatures vs pinned `DirectoryTrust` (`w_total`, `w_external`, distinct witnesses), view bound to checkpoint, RFC 9162 consistency proof from the HWM (`merkle`, SHA-256 from candor-core), equal size ⇒ equal root, invariants (unique channels, ≤ 16 Triage persons, ≤ 1 COI_POLICY per day). `install_snapshot(bundle, persist)` verifies under the HWM lock, persists the new mark first, then swaps the `Arc` (sessions survive). Ambiguous active COI policy fails closed in `select`. | `fail_closed.rs::snapshot_rollback_fork_signature_and_invariants_rejected`, `witness_cosignature_policy_enforced`; `directory.rs` unit tests (proofs for all m ≤ n ≤ 40, tampering, note body, RFC 4648 vectors) |
| SEA-08 (Med) COI ticks not zeroized | `Value` wipes integers on drop; inner maps are pre-sized (no realloc copies); `concerns`, `excluded`, `excluded_users`, `triage`, `eligible`, `Selection::eligible_user_ids`, `ReportPrefs::{original_eligible, categories}` are `Zeroizing`; `Selection`/`Recipient` lost `Debug`. CORE-03 (normalize realloc) remains with candor-core. | unit tests + review |
| SEA-09 (Med) no fuzz target | `fuzz/fuzz_targets/fuzz_sealer_ipc.rs` (cargo-fuzz layout as candor-core): decoders + canonical re-encode, then a `Sealer::handle` state-machine driver (Argon2id ops skipped). | built with nightly-2026-09-28; 600 s run at `-rss_limit_mb=2048`: 26,971,343 execs, no crash/leak/OOM |
| SEA-10 (Low) follow-up COI | Report categories kept in `prefs_ct` (report key 1002); follow-ups and rotations re-apply the active COI_POLICY within the original eligible set. | `fail_closed.rs::follow_up_reapplies_tightened_coi_policy` |
| SEA-11 (Low) secret wrappers | `SecretBytes/Text/Words`, `Coi`: hand-written constant-time `PartialEq` (Clone kept: copies are `Zeroizing`); `Request` `Debug` prints only the op, `Response` only the variant (+ error code), `DraftSet/DraftView/PendingReply/ReplyView` and sink types redacted. | `proto_props.rs` (round trips still compare) |
| SEA-12 (Low) NOTE_REAL | Off unless `SealerConfig::enable_note_real` (Tier V, RM-8); returns `BAD_STATE`. Counting against store commits deferred to RM-8. | `chaff.rs::note_real_disabled_by_default` |
| SEA-13 (Low) orphans, unlink under lock | Staging files are created under a caller-chosen `ObjectId` (`seal::stage_create`), and a failed `commit` removes that id (parts, bundles, chaff bundles). The reaper takes expired sessions out under the lock and drops them after; the background reaper runs it via `spawn_blocking`. | hygiene/fail_closed suites |
| SEA-14 (Low) rotation blocked | Unopenable pending replies are skipped (they stay unreadable); rotation proceeds. | `flow.rs` (bogus entry + real entry → 1 re-wrapped) |
| SEA-15 (Info) chaff gating | `chaff_event` refuses on disabled channel and stale snapshot too (same conditions as real); `enabled = false` needs the dev token. | `chaff.rs::chaff_gated_like_real_sealing` |
| SEA-16 (Info) unit mismatch | **Not changed** (outside the allowed edit scope beyond the syscall list): the shipped unit still provides `ListenSequentialPacket`, hides `/run/candor/staging` and names credentials differently from the README. Integration item for the deploy owner. | — |
| SEA-17 (Info) supply chain | No new third-party dependency (candor-log is a workspace crate). Vet/deny gates are workspace-level (ADR-052(7)/(8)). | — |
| SEA-18 (Info) residual metadata | Peer UID 0 / own UID refused at `serve` (self-check). tmpfs ctime/birth time of staged ciphertext: residual, for the 09 list. Session-handle lookup timing: web peer only, accepted. | `hardening.rs` |

Integration notes:
- **AUD-RM1-CORE-04 (STREAM constructors).** All raw-key STREAM construction is isolated in `seal::{staged_part_encryptor, staged_part_decryptor, payload_encryptor}`; switching to `StreamEncryptor::for_staged_part(k36, part_id)` (and the decryptor / payload counterparts) is a one-line change in each.
- **Store trait (ADR-052(2)).** Map `commit_envelope_group` to the store's account-free envelope commit and `upsert_account` to its separate create/replace operation; `received_day` is the sealer's `Clock::today()`.
- **High-water mark.** Persist the `HighWaterMark` passed to the `install_snapshot` hook (tree size, root hash, issued hour) and restore it with `set_high_water_mark` before the first install.
- **candor-log.** Please add `Service::Sealer` and a hardening/override check code; the sealer then switches the `sys.health` fields.

Check results (round 1, 2026-10-01): 63 tests pass; see round 2 below for the current state.

## Key Directory verification (AUD-RM2-SEA-19; 04 §14.2–§14.5)

**Implementation decision — content binding by full-tree recomputation (VR-4).** The `SnapshotBundle` carries every SignedKDEntry of the log in leaf order (04 §14.3 already has C-09 push "all entries"; O(10^4) entries). `VerifiedSnapshot::verify` recomputes the RFC 9162 root over `H(0x00 ‖ SignedKDEntry)` (iterative, `merkle::root_of`) and requires it to equal the signed checkpoint's root and the entry count to equal its tree size. VR-4 allows "inclusion proof or full-tree recomputation"; recomputation is chosen because it also proves **absence**: a newer roster, a REVOCATION or an OBJECTION cannot be withheld, and "latest active entry" is well defined — per-entry inclusion proofs cannot show either. `merkle::{inclusion_proof, verify_inclusion}` (RFC 9162 §2.1.3, RFC 6962 reference vectors) are provided for Desk / Tier V / core migration. Bounds (VR-12): ≤ 10^6 entries, ≤ 512 MiB in total, entry bytes ≤ 64 KiB, SignedKDEntry ≤ 128 KiB, ≤ 8 signatures.

**Order of checks (nothing is trusted before all pass):** sizes → rollback (tree size and issued hour vs the high-water mark) → root recomputation → every entry in leaf order (`kd`) → checkpoint signature by the log's LOG_KEY entry → witness cosignatures (witness keys and `w_total`/`w_external` from the ORG_ROOT entry, never below the pinned `DirectoryTrust` floors; watchers do not count; one per witness) → consistency proof from the high-water mark → view.

**Per-entry rules (`kd.rs`, leaf order, against keys from earlier leaves).** Every entry: canonical CBOR, version 1, the pinned tenant, subject of 16 or 32 bytes, continuity per `(entry_type, subject_id)` (`subject_seq` +1, `prev_subject_entry_hash` = previous entry hash), every Ed25519 signature valid (an invalid one anywhere is fatal). Required signers:

| Entry | Signers (Ed25519 halves) | Further checks |
|---|---|---|
| ORG_ROOT | self; seq > 1 also the previous K01 | the pinned K01 is in the chain (VR-1); `deployment_salt` = the sealer's; allowed suites contain the sealer's |
| LOG_KEY, KEY_ADMIN, CUSTODIAN_GROUP, DISPOSITION_KEY, GOVERNANCE_ROLES | current, unrevoked K01 | GOVERNANCE_ROLES lists ≥ 1 OVERSIGHT member; time locks floored at 3 / 7 days |
| USER_KEYS | own K08 + 1 K15 + the out-of-band verifier's current K08 (a different user, not that K15 holder) — or K01 (bootstrap of the first users) | `authenticator_count ≥ 2` |
| CHANNEL_IDENTITY | seq 1: a user K08 (creator) + 2 distinct K15 + 1 OVERSIGHT K08; seq > 1: previous CIK + 1 K15; orphan: K01 + 2 K15 + 1 OVERSIGHT K08 | orphan: 7-day time lock; entries signed under a pending orphan CIK activate no earlier |
| CHANNEL_ROSTER, COI_POLICY | the channel's current CIK + 1 K15 | change class **recomputed** (any added (user, label) pair, `read_intake`/`channel_admin` grant or changed `independent_route`; any category's exclusions not a superset, a category or selectable role removed); a "tightening" that loosens is invalid; loosening needs an independent-role approver (OVERSIGHT or GOVERNANCE_ROLES independent member) other than the K15 holder, and `activation ≥ not_before + D` and, for leaves after the high-water mark, `activation ≥ hwm_day + D`; roster: 2..16 Triage Set persons, every member's `user_keys_entry_hash` names a USER_KEYS entry of that user, every Triage Set member's `role_label_cert_hash` names a ROLE_LABEL_CERT of that (channel, label); `roster_version` increases |
| MEMBER_EPOCH | the member's current, unrevoked K08 | subject = `H(label ‖ channel ‖ user ‖ epoch)`; `key_id = key_id(suite, MEK, pk)`; `user_keys_entry_hash` names that user; `valid_from < valid_until` |
| ROLE_LABEL_CERT | an OVERSIGHT member's current K08 | subject = `H(label ‖ channel ‖ u16 label)` |
| OBJECTION | the K08 of a member of the channel's latest roster or of an OVERSIGHT member; resolution (`resolved = true`): 2 distinct OVERSIGHT K08 | an unresolved objection blocks the referenced loosening entry (and entries under an objected orphan CIK) |
| REVOCATION | K01 for any key; a MEK: its member's current K08 or the channel CIK + 1 K15; a user's K08 or key id: that K08 itself or 1 K15 + 1 OVERSIGHT K08; a K15 or CIK key: itself; anything else (LOG_KEY, K01, unknown keys): K01 only (SEA-25) | revoked key id = subject; a key revoked at leaf r cannot sign entries after r |
| any other type 0x01..0x1B | — | header and continuity checked, body skipped (`Dec::skip`, iterative, item budget) |

**Derived view.** Rosters and COI policies are kept as verified versions; the active one at `today` is the latest with `activation_day ≤ today` (tightening: active on inclusion). A Triage Set member is eligible only while the latest ROLE_LABEL_CERT of its label is independent and `today ≤ valid_until_day` (ADR-036(3), §14.4 rule 5). A MEK is usable only while signed by the member's *current* unrevoked K08, itself unrevoked, of the tenant suite, and unique per (channel, member, epoch) — two live entries make both unusable (§14.4 rule 5). K13 and K41 come from the latest CUSTODIAN_GROUP / DISPOSITION_KEY of the tenant suite. The operator may only *disable* channels (`disabled_channels`). The Recipient List checkpoint field (§13.4 key 16.5) and SUBMISSION key 7 carry the verified `(tree_size, root_hash)`, key 6 the active roster's entry hash, key 16.4 the COI_POLICY entry hash: each is a leaf hash in the committed tree.

**Implementation decisions (spec amendment requested for 04 §14.2).** 04 names the body fields but not their CBOR keys, the signer key id or the subject derivations. The sealer uses:
- entry hash = Merkle leaf hash `H(0x00 ‖ SignedKDEntry)`; `signer_key_id` (32 bytes, no truncation; ADR-055(2)) of an Ed25519 signature = the public key, of an ML-DSA-65 signature = SHA-256 of the encoded verifying key; ML-DSA is pure FIPS 204 with an empty context over the same `"candor/v1/kd-entry\0" ‖ entry_bytes` message; K01 signatures require **both** halves, every ML-DSA half present must verify against a known key, and `alg` 3 (ECDSA-P384) is refused (SEA-27);
- body keys numbered in the order 04 §14.2 lists the fields, e.g. ORG_ROOT `{1 ed25519_pk, 2 mldsa_pk, 3 [suite], 4 deployment_salt, 5 kdf_version, 6 [{1 name, 2 pk, 3 role (0 witness, 1 watcher), 4 external_org, 5 external_jurisdiction, 6 endpoint}], 7 w_total, 8 w_external, 9 flags}`; LOG_KEY `{1 pk, 2 origin}`; KEY_ADMIN `{1 pk, 2 role_label}`; USER_KEYS `{1 k08, 2 k09, 3 [key_id], 4 label, 5 device_count, 6 authenticator_count, 7 [att_hash], 8 device_custody, 9 oob_verified_by}`; CHANNEL_IDENTITY `{1 cik, 2 orphan, 3 activation_day}`; CHANNEL_ROSTER `{1 roster_version, 2 activation_day, 3 change_class (0 tightening, 1 loosening), 4 [{1 user_id, 2 user_keys_entry_hash, 3 role_label, 4 role_label_cert_hash, 5 caps (bit 0 read_intake, 1 channel_admin, 2 investigate), 6 member_since_day}], 5 channel_type, 6 independent_route|null, 7 {1 enabled, 2 quorum_entry_hash|null, 3 [holder_label]}, 8 custodian_entry_hash, 9 names_published}`; MEMBER_EPOCH `{1 channel, 2 user, 3 role_label, 4 epoch, 5 pk, 6 key_id, 7 valid_from_day, 8 valid_until_day, 9 user_keys_entry_hash}`; COI_POLICY `{1 version, 2 activation_day, 3 change_class, 4 [{1 category_id, 2 label, 3 [excluded_label]}], 5 [selectable_role]}`; CUSTODIAN_GROUP `{1 pk, 2 key_id, 3 [label], 4 count}`; DISPOSITION_KEY `{1 pk, 2 key_id, 3 suite}`; REVOCATION `{1 key_id, 2 reason, 3 effective_day}`; ROLE_LABEL_CERT `{1 channel, 2 role_label, 3 independent, 4 body_type, 5 valid_until_day}`; GOVERNANCE_ROLES `{1 [oversight user_keys hash], 2 [independent hash], 3 {1 k, 2 [{1 hash, 2 independent}]}, 4 small_org_mode, 5 external_label|null, 6 timelock_days, 7 orphan_timelock_days}`; OBJECTION `{1 channel, 2 objected_hash, 3 reason, 4 resolved}`;
- subject ids of composite subjects: `SHA-256("candor/v1/kd-subject/member-epoch" ‖ channel ‖ user ‖ u32be epoch)`, `…/role-label" ‖ channel ‖ u16be label`, `…/objection" ‖ channel ‖ objected_hash` (labels to be added to the 39 registry / candor-core `labels`);
- the epoch origin is pinned in `DirectoryTrust` (not a directory field, item 12);
- USER_KEYS bootstrap: the first users of a tenant cannot have an earlier user as out-of-band verifier; K01 stands in.

**Migration.** `merkle.rs` depends only on `candor_core::hash::sha256` and `kdf::ct_eq` and is meant to move into candor-core with its vectors (coordination item C-1).

## Fixes for AUD-RM2-SEA round 2 (2026-10-01; process/audits/AUDIT-RM2-sealer.md "Re-test (round 2)")

| Finding | Change | Test |
|---|---|---|
| SEA-19 (High) view not bound to the checkpoint | `VerifiedSnapshot` is derived from the complete log (above): root recomputation, every entry's continuity and signers per §14.2/§14.4 (member K08 signs MEKs, OVERSIGHT certifies labels, CIK signs rosters/COI, K01 tenant keys), recomputed change class, time locks, objections, revocations, witness policy from ORG_ROOT, pinned K01, salt, suite; selection uses the active roster version, current independent label certificates and current-K08 MEKs; the Recipient List / SUBMISSION checkpoint fields are the verified checkpoint. New errors `SnapshotError::{Inclusion, Entry}`. RFC 6962/9162 Merkle module with vectors. | `tests/directory.rs`: auditor PoC (genuine checkpoint + attacker MEK: substituted, added, removed, reordered entries → `Inclusion`; sealing still opens only for real MEKs), compromised LOG_KEY (attacker-signed / other member's MEK, wrong key id, attacker CIK relabel, tightening-that-loosens, no independent approver, inside time lock, COI loosening without CIK or declared tightening, cert not by OVERSIGHT, bit flip, broken continuity, garbage, unknown type → `Entry`; controls verify), revocation / K08 rotation / objection effects; `fail_closed.rs` rollback, fork, suite, salt, pinned K01, LOG_KEY, > 16 Triage persons, witness policy; `flow.rs` checks keys 6/7/16.4/16.5; `merkle.rs` RFC 6962 vectors, inclusion/consistency round trips and tampering; `select.rs` version/cert rules |
| SEA-20 (Med) self-check trusts a global record | `harden_process` refuses unless on the main thread outside a runtime; the sealer serves on `confined_runtime()` (built only after hardening; `on_thread_start` records each thread as confined); `self_check` requires the calling thread to be recorded; in serve mode every request (`handle`), frame (listener) and blocking job (`blocking`) calls `guard()`, and one unconfined thread poisons the sealer (refuses all work, listener stops). No `/proc` read in `src` (ADR-027), so `VmLck` is asserted by the test. | `tests/hardening.rs` (`harness = false`, main thread): helper-thread and in-runtime hardening refused and nothing recorded; threads and a runtime created before hardening are unconfined and a production sealer on that runtime refuses to serve (auditor PoC); a hand-built post-hardening runtime is not trusted; `confined_runtime` workers and blocking threads are confined and pass `self_check`; Landlock denies outside reads and TCP bind; `hardening.rs` unit test of the poisoning guard |
| SEA-21 (Low) account ↔ envelope adjacency, dummy lifecycle | Account writes (real initial, real rotation, chaff dummy, dummy rotation) are queued in RAM and written as one batch at a fixed interval (`ChaffConfig::account_flush_interval`, default 15 min; `Sealer::flush_accounts`), creates shuffled with a CSPRNG Fisher–Yates, replacements after them; a replacement of a still-queued account is merged into its entry; store errors re-queue in order; queue bounded (`MAX_QUEUED_ACCOUNTS`, `BUSY` before commit when full). Chaff rotates dummy accounts at `dummy_rotation_permille` (same store operation as a real rotation). Delay share stays a published policy value (`delayed_share_permille`). Residuals: crash window, store-side activity marks (Security self-review). | `chaff.rs::accounts_are_batched_and_dummies_rotate`, `chaff_triple_is_structurally_identical_to_a_real_submission` (ops `GG` then `GGAA`), `chaff_fails_closed_…` (flush failure re-queues); `shape.rs` (no `A` between groups; one batch); `flow.rs`; unit `account_batches_are_shuffled_creates_then_replacements` |
| SEA-22 (Low) NFC over-limit after Argon2 | `DRAFT_SET` checks the NFC length of the message plus the answers against `MAX_DRAFT_TEXT` and the NFC identity against `MAX_IDENTITY_LEN` (streaming count, capped) and returns `LIMIT` before anything is stored; the confirmed passphrase stays pending until the commit succeeds. | `fail_closed.rs::nfc_expanding_draft_is_refused_at_draft_set` (auditor PoC 13,653 × U+0958, answers interplay, composing text, identity); `store_failure_…` now retries `SEAL_FINISH` without a new passphrase |
| SEA-23 (Low) shallow fuzzing | `fuzz_sealer_ipc` has four modes: decoders, raw frames, and a structure-aware stateful generator (`arbitrary::Unstructured` from libfuzzer-sys: drafts with NFC-expanding text, COI, uploads, real confirmation words, sealing, account flushes, login, prefs, replies, rotation; encode → decode round trip → `handle`), with one real-cost Argon2id op per mode-3 input (candor-core exposes no cheaper parameters, CRYPTO-043). The directory is a real signed KD log. Seed corpus `fuzz/seeds/fuzz_sealer_ipc/` (73 files, `gen_seeds`). | see "Check results (round 2)" |
| SEA-24 (Info) | (a) Dev-mode event: candor-log still lacks a distinct code — coordination item C-2; the codes are two constants. (b) K13 trial-decryption real/chaff split documented (Security self-review). (c) Test fixtures: module-level `#![allow(clippy::disallowed_methods)]` with `// safefs-lint: allow(<reason>)` markers; `clippy --all-targets` clean. (d) `select` pre-sizes the exclusion list for flags plus every policy label (no `reserve`). | clippy, lint-safefs |
| SEA-06 / SEA-07 (partial) | Closed through SEA-20 / SEA-19. | as above |
| SEA-16 (deploy D-33) | Sealed bundles are anonymous `memfd`s sealed `WRITE|GROW|SHRINK|SEAL` (`sink::Blob::Staged(StagedBundle)`); `handover::{send, await_ack, hand_over}` pass the descriptor over `istore.sock` with `SCM_RIGHTS` (safe rustix `sendmsg`/`recvmsg`) in the 41-byte format of `candor-intake-store::staged` and return `Ok` only on the commit byte `0x01`; refusals, other bytes, extra bytes, returned descriptors and EOF fail. **Implementation decision:** a memfd instead of a staging-dir file, because candor-safefs exposes no descriptor of a staged object and a sealed memfd is immutable for both sides during the store's copy and vanishes with its last descriptor (nothing to delete after the acknowledgement, nothing left after a crash). Upload parts stay in the staging tmpfs. | `tests/handover.rs` (socketpair SEQPACKET: header, one fd, regular file, size, seals, write/truncate refused, hash; refused / unknown / long ack, fd sent back, peer gone, closed peer) |
| AUD-RM1-CORE migration | Live candor-core API: `StreamEncryptor::for_payload` (nonce drawn by core) / `for_staged_part(SessionKey, PartId)`, `StreamDecryptor::for_staged_part`, K36 as `SessionKey`, `seal` → `(SealSecrets, SealedObject)`, `RecipientList`, zeroizing entry wire forms. No raw-key STREAM call remains. | whole suite |

Coordination items:
- **C-1 (candor-core owner):** move `server/merkle.rs` (RFC 9162 root/inclusion/consistency + vectors) into candor-core; add the three `kd-subject` labels to `labels`.
- **C-2 (candor-log owner):** add `Service::Sealer` and a `HealthCheck` (or dedicated event) for the insecure developer override, so a monitor can tell it from an ordinary readiness degradation.
- **C-3 (spec owner, 04 §14.2 / 09):** body key numbering, `signer_key_id` form and composite subject derivations above; per-leaf inclusion day for exact time-lock checks.
- **C-4 (deploy owner):** the sealer's syscall set gains `memfd_create` (bundle files); `fcntl`, `sendmsg`, `recvmsg`, `pread64` are already listed. The store's receiver must accept a sealed memfd (regular file; it already reads with `pread`).
- **C-5 (store / integration):** `EnvelopeSink::commit_envelope_group` over the store client calls `handover::hand_over` for `Blob::Staged` and returns `Ok` only after the store's acknowledgement; account rows arrive in batches (`upsert_account`) independent of envelope commits.

Check results (round 2, 2026-10-01, live tree): see the final section.

### Check results (round 2, 2026-10-01, live tree incl. migrated candor-core)
- `cargo fmt -p candor-sealer`: applied.
- `cargo clippy -p candor-sealer --all-targets --all-features -- -D warnings` and `--no-default-features --lib`: clean.
- `cargo test -p candor-sealer`: 72 pass (28 unit + 44 integration in 12 binaries) plus the `harness = false` hardening binary (2 scenarios, exit 0).
- `lint-safefs.sh --include-tests`: no sealer findings; `lint-logging.sh`: ok.
- `fuzz_sealer_ipc` (nightly-2026-09-28, seeds + fresh corpus, `-max_total_time=150 -rss_limit_mb=2048`): 4,045 runs, no crash, leak or OOM; **cov 10,569**, ft 25,705, corpus 518 (round 1: cov 154). Throughput is ~30 exec/s because mode-3 inputs run a real 64 MiB Argon2id and modes 2/3 seal real envelopes.

## Fixes for AUD-RM2-SEA round 3 (2026-10-01; lead decisions binding)

| Finding | Change | Test |
|---|---|---|
| SEA-26 (High) memfd doubles attachment memory | Each staged part is removed from tmpfs as soon as its plaintext has been re-encrypted into the bundle memfd (`seal_bundle`), so the peak is the bundle plus at most the part being copied. Sealer-wide admission (`budget.rs`): at every `PART_BEGIN` a session reserves the ciphertext of all its declared parts plus the bundle bucket for the declared total against `Limits::memory_budget_bytes` (default 3,840 MiB, below `MemoryMax`); no fit → the uniform `BUSY`. Sealing needs no reservation and is never refused for memory; the reservation is released with the draft. A failed seal that consumed the parts sets `parts_lost`: `SEAL_FINISH` is refused (`BAD_STATE`) until `DRAFT_GET`, `PART_BEGIN` or `SEAL_ABORT`. | `tests/budget.rs` (16 concurrent 2 MiB sessions against 12 MiB: reserved ≤ budget at every point, some granted, some BUSY, release on abort admits a waiting one, oversize single upload BUSY, zeroize returns to 0; sealing frees the part and the reservation); `budget.rs` unit; `fail_closed.rs::store_failure_…` (parts freed, no silent retry without the attachment) |
| SEA-25 (Med) unsigned REVOCATION / OBJECTION honoured | Both now need an authorised signer per 04 §14.2 (table above); an unauthorised one makes the snapshot invalid (`Entry`). | `directory.rs::revocations_rotations_and_objections_…` (auditor PoC: attacker, K15-alone and other-member revocations → `Entry`; member K08, CIK + K15, K01 accepted; K08 self / K15 + OVERSIGHT; LOG_KEY needs K01; attacker objection → `Entry`) |
| SEA-27 (Low) PQ half not verified | ML-DSA-65 verification (`ml-dsa` crate); K01 needs both halves (ORG_ROOT self and rotation, every K01-signed entry); every ML-DSA half must verify; ECDSA refused. | `directory.rs::k01_entries_need_both_signature_halves` (Ed25519 only, PQ half over another message, unknown PQ key, ECDSA → `Entry`; both halves → ok) |
| SEA-28 (Med) queued account writes | (a) `LOGIN_DERIVE` consults the queue (and the batch in flight): a passphrase whose account has a pending replacement gets a random locator, as a wrong passphrase does. (b) A rotation inside the window re-wraps from the latest queued stanzas (including ones the caller did not resend); merges are by object hash, newer wrap wins; `OPEN_REPLY` uses a queued re-wrap for the session's account. (c) `Sealer::spawn_sigterm_flush` / `shutdown_flush`: on SIGTERM, 1–4 dummy creates are queued and everything is written as one shuffled batch. (d) Residual and source-UI wording in the Security self-review. | `flow.rs::double_rotation_keeps_replies_readable` (old passphrase blocked at once, reply readable between and after two rotations, one coalesced replacement); `tests/shutdown.rs` (real SIGTERM: real + dummy creates in one batch) |
| Info: `await_ack` | `SO_RCVTIMEO` bound (`ACK_TIMEOUT` 60 s; `await_ack_within`). | `handover.rs` (silent store → error within the bound) |
| C-2 | `InsecureDevMode::acknowledge` emits `sys.health{service=sealer, DEGRADED, INSECURE_DEV_OVERRIDE}`. | `hardening.rs` binary |

Check results (round 3, live tree): fmt applied; clippy `--all-targets --all-features` and `--no-default-features --lib` with `-D warnings` clean; `cargo test -p candor-sealer` 78 pass (29 unit + 49 integration in 14 binaries) plus the `harness = false` hardening binary (exit 0); lint-safefs (`--include-tests`) no sealer findings; lint-logging ok. Fuzz: see the final line.
