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
    | SUBMISSION | 4/8/12/16 KiB at 50/25/15/10 % |
    | SOURCE_MESSAGE | 4/8/12 KiB at 70/20/10 % |
    | ATTACHMENT_BUNDLE | file buckets ≤ 8 MiB, weighted toward the empty-bundle bucket (256 KiB) |
    | IDENTITY | 4 KiB |
12. **Epoch numbering is not defined.**
    **Implementation decision:**
    - the snapshot carries `epoch_origin_day`, and `epoch = (today − origin) / 7`;
    - a member's MEK is used only if its `epoch_id` equals the current epoch and `valid_from ≤ today < valid_until`, and it is neither revoked nor ambiguous (two valid entries count as none);
    - BE-032's ±1-day tolerance is *not* applied. Strictness only shrinks the recipient set and can fail closed; it never widens it.
13. **The IDENTITY inner format is undefined.**
    **Implementation decision:** `u32be(len) ‖ {1: format=1, 2: text}` padded to the IDENTITY bucket. ANONYMOUS mode seals an empty text, which lands in bucket k = 1.
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

- **Directory snapshot.** No C-14 verifier crate exists yet. The integrator verifies checkpoints, witnesses, consistency, roster and COI_POLICY signatures, then hands the sealer the typed `DirectorySnapshot`.
  The sealer itself enforces:
  - the high-water mark (`install_snapshot` rejects any tree size or issued hour below the mark; `set_high_water_mark` restores the persisted value);
  - suite equality;
  - freshness;
  - `effective_day` time locks on roster members and COI policies;
  - the Triage Set (`read_intake`) and its ≤ 16 invariant;
  - MEK windows.
- **Independent time.** This is the integrator's `Clock::today()`: Tor consensus plus Roughtime, 16 §14.3. On any error the sealer fails closed with `UNAVAILABLE`. Timers use the monotonic tokio clock only. No sub-day time is ever written: staging files carry the UTC day start.
- **`IntakeStore`.** `candor-intake-store`'s trait was not available, so the sealer defines `server::sink::EnvelopeSink` with two methods, `commit` (COMMIT_ENVELOPE) and `rotate_account` (ACCOUNT_ROTATE).
  **Integration:** implement it over the store client, or replace it with the store's trait.
  On `Ok`, the sink owns any `Blob::Staged` file. On `Err`, the sealer deletes it.
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
- **Hardening.** The crate enforces Landlock in-process: filesystem access only beneath the staging root, and no TCP bind/connect at ABI ≥ 4. `harden_process` must run on the main thread before the tokio runtime starts.
  seccomp is delegated to systemd `SystemCallFilter=`. In-process seccompiler would need a hand-maintained tokio/safefs allow-list, and 07 §4.3 conflicts with item 7.
  See the README for the unit file.
- **K35 (sealer signing key).** It is passed in by the integrator, never read from the environment. The integrator loads it from a `LoadCredentialEncrypted=` credential (R7). `sealer_sig` is added to SUBMISSION (key 19) and SOURCE_MESSAGE (key 12).
- **Logging.** The sealer emits no logs or audit events. Nothing it handles is loggable, and `candor-log` has no `Service::Sealer` code yet. Lifecycle `sys.*` events belong to the integrating binary.

## Dependencies

| Crate | Version | Why |
|---|---|---|
| `zeroize` | =1.8.2 | Zeroizing buffers in `proto` (the only proto dependency). |
| `candor-core` | path | All cryptography and formats (C-11): source keys, slots, objects, STREAM, records, stanzas, KATs. |
| `candor-safefs` | path | The single audited filesystem API for the tmpfs staging root (ADR-027). |
| `tokio` | =1.48.0 (`rt`, `net`, `sync`, `time`, `io-util`) | Unix-socket listener, the per-session async mutex, the Argon2id semaphore, timers and `spawn_blocking`. Same pin as the store. |
| `rustix` | =1.1.2 (`mm`, `process`) | Safe `mlockall`, `prctl(PR_SET_DUMPABLE)` and `setrlimit(RLIMIT_CORE)`. Same pin as safefs. |
| `landlock` | =0.4.7 | In-process filesystem and TCP confinement (R7 SI-B-03). Safe API. |
| `hkdf`, `sha2` | =0.13.0, =0.11.0 | Chaff CK derivation `HKDF(chaff_seed, u64 counter, "candor/v1/chaff/seed")` (§12.7). candor-core exposes no generic HKDF. Pins match core. |
| `subtle` | =2.6.1 | Constant-time word-index mapping. |
| `unicode-normalization` | =0.1.24 | NFC of the message (§13.4 key 13). Pin matches core. |
| `proptest`, `tempfile`, `tokio[test-util,macros,rt-multi-thread]` | dev | Property tests, temporary roots, paused-time tests. |

## Tests (45) and requirement mapping

| Test | Covers |
|---|---|
| `tests/flow.rs::full_tier_w_flow` | ST-025, 04 §12.3/§13.4. The full flow: open → draft → stage → COI → passphrase → wrong and right confirmation → seal with delay → recipient-side trial open. Then: full ADR-050 slot verification of all 3 objects; `source_sig` and `sealer_sig`; bundle bytes, manifest and SHA-256; IDENTITY to K13 only; real disposition kind; login (uppercase input, NFKC/lowercase); `LOGIN_SIGN` verification; `LOAD_PREFS`; reply decrypt and verify; replay and spoofed signer rejected; follow-up sealed only to the original eligible set while a later-added member gets no slot (BE-052); rotation with `NOT_CONFIRMED`, re-wrapped reply readable with the new passphrase, KEY_ROTATION signed by the old and new keys, and the old prefs unusable (BE-072, API-050). |
| `tests/fail_closed.rs` | API-036/058 COI excluding everyone → `NO_ELIGIBLE_TRIAGE` plus the alternative channel; no valid MEK; stale snapshot (7 days) versus 6 days; clock failure; rollback and suite mismatch (BE-060); `NOT_CONFIRMED` (BE-056, API-039); 5 failures zeroize the session; regeneration limit; store failure leaves no envelope and no sealed bundle; unknown or disabled channel; bad states; oversize parts; session capacity → `BUSY`. |
| `tests/hygiene.rs` | BE-005/055: 20 min idle and 2 h absolute expiry (paused clock) zeroize and unlink; `PART_DROP` / `SEAL_ABORT` / `ZEROIZE`; size bucket only in `DRAFT_GET`. **No plaintext on disk:** a run-unique marker in the message, answers, identity, filename and attachment is absent from staging, the fixture tempdir, freshly written files in `$TMPDIR` and all store inputs; the passphrase is absent from disk and from store inputs. |
| `tests/chaff.rs` | BE-075 / §12.7: a chaff triple is structurally identical to a real anonymous submission (types, tenant, channel, epoch, slot block size, legal buckets, exact lengths, `disposition_ct` size); no member or custodian opens any chaff slot; K41 tells kinds 0 and 1 apart; the follow-up shape; fail-closed chaff (no time, unknown channel, sink failure leaves nothing staged); the Poisson schedule under a paused clock; `NOTE_REAL` cancellations suppress events. |
| `tests/ipc.rs` | BE-006: socket round trip, `HELLO` first, second `HELLO`, oversize prefix, garbage body and wrong version all give `BAD_FRAME` and a close; a wrong SO_PEERCRED UID is disconnected without a byte. |
| `tests/proto_props.rs` | ST-040/041 decoder robustness: arbitrary bytes never panic for any op; request round trips; **canonicity** (any mutated frame that decodes re-encodes byte-identically); frame-length bounds; response round trips; draft-text bound. |
| `tests/hardening.rs` | BE-003: `RLIMIT_CORE = 0`, not dumpable, `mlockall` (VmLck > 0), Landlock enforced (outside paths unreadable, staging writable). |
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
- **Fail closed on every privacy path.** Missing, stale, rolled-back or wrong-suite snapshot; clock failure; invalid K13 or K41; no eligible Triage Set member; > 16 members; store failure (staged output deleted); CSPRNG failure (propagated). Chaff skips its write on the same conditions. There is no unsealed fallback.
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
- The directory snapshot's authenticity rests on the integrator's C-14 verification.
- The chaff distributions are provisional (item 11). Bundles larger than 8 MiB, and real traffic above the chaff rate, are distinguishable (honest limit, §12.7).
- The tmpfs staging area reveals bucket-sized ciphertext files and their count per day (ADR-034 accepted).
- **Padding cost.** A part declared large but sent small still costs encrypting zero padding up to its bucket, at most `max_file_bytes`. Staging capacity bounds this (a full tmpfs gives `BUSY`), and so do the C-06 per-circuit rate limits (SW-06: 30/h).
- **Socket permissions.** The socket's file mode and directory (a 0700 RuntimeDirectory) are set by the systemd unit or the integrator. SO_PEERCRED is checked regardless.
