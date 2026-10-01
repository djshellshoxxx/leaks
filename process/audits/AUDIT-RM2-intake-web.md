# AUDIT-RM2 — candor-intake-web (C-06 Source Web Service) and STO-29 handover protocol 2

| Item | Value |
|---|---|
| Step | RM-2 (intake zone): component C-06, plus the AUD-RM2-STO-29 / C-5 hand-over changes in C-07 and C-08 |
| Audited commit | `6c03b66a847cc789ba9d52d631b295bed61cee6c` (working tree clean for the files in scope) |
| Scope | `crates/candor-intake-web/{src/*.rs, tests/*, fuzz/*, Cargo.toml, README.md, SPEC-NOTES.md}` (≈10,300 lines); `crates/candor-sealer/src/server/handover.rs` and `tests/handover.rs`; `crates/candor-intake-store/src/staged.rs` and `tests/staged.rs`, `tests/pg.rs` (`pg_staged_*`); `crates/candor-intake-web/tests/sto29_handover.rs` |
| Tiering (27 §4) | T1: every file in `candor-intake-web/src` (source-facing over Tor), `staged.rs`. T0-adjacent: `handover.rs` (sealer process). T2: tests, fuzz harnesses |
| Auditor | Independent security auditor (did not write this code) |
| Date | 2026-10-01 |
| Inputs read | AUDIT-CHECKLIST; R9; BUILD-BRIEF "Security and OPSEC bar", RM-2 addendum and audit gate; crate README and SPEC-NOTES (incl. "Security self-review"); 08 §3.7, §3.10, SW-xx, SW-16; 11 §5.3–§5.7, Leave page, SUI-013/036; 07 §5.1, §11 limits table; ADR-010/016/038/047(3)/052/053/055/056 (as cited by the crate) |
| Lead decisions taken as given | (a) httparse `=1.10.1` + strict subset + fixed 2,048-byte head; (b) `Origin: null` only with `Sec-Fetch-Site: same-origin`, csrf always required; (c) one CSRF token per session, rotated at login, logout, passphrase rotation and mode change. Verified as implemented, not relitigated |
| Time per phase | A1 ≈ 10 %, A2 ≈ 10 %, A3 ≈ 55 % (every line of `server.rs`, `http.rs`, `proxy.rs`, `form.rs`, `multipart.rs`, `token.rs`, `session.rs`, `ratelimit.rs`, `app.rs`, `sealer.rs`, `handover.rs`, `staged.rs`; `flows.rs` on every input-to-sink path), A4 ≈ 20 % (tests, PG suite, PoCs, tools), A5 ≈ 5 % |

## Summary

| Severity | Count | IDs |
|---|---|---|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 2 | WEB-01, WEB-02 |
| Low | 6 | WEB-03 … WEB-07, SEA-01 |
| Info | 4 | WEB-08, WEB-09, STO-30, WEB-10 |

**Gate: FAIL (conditional).** There is no Critical and no High finding. The gate passes once WEB-01 and WEB-02 are fixed and re-tested, or accepted in writing by the lead, **and** the three fuzz targets have been run (§C tool requirement; they could not be built here, see A4).

The HTTP layer is well built. httparse tokenizes the head, and a raw CRLF/obs-fold/request-line pre-check sits in front of it. The service refuses TE, CL duplicates, Expect, Upgrade and trailing bytes beyond `Content-Length`, and serves one request per connection, so it has no smuggling or desync surface. The response head is a constant 2,048 bytes and carries no `Date` or `Server`. CSRF and Origin are checked before any body is read or any state changes, and tokens are compared in constant time. Session ids are fresh at `/new` and at login, and the previous session is ended (no fixation). Login runs the same sealer and store work for unknown locators against a dummy key. Every dependency failure gives the busy page, so the service fails closed. STO-29 is sound: the hash binding is checked on both sides, and a late ack cannot be credited to another bundle.

The open problems are these:
- plaintext that is not zeroized in the view models;
- a quadratic multipart scan;
- several Low robustness and side-channel gaps, including the ruling below on the stateless leave token.

## Ruling requested by the builder: the stateless leave token

Construction (`token.rs:173-187`): `HMAC-SHA256(K_pre, "candor/web/leave" ‖ "" ‖ u64be(epoch5min))`, 64 hex. `K_pre` is 256 bits from the CSPRNG, per process. The token is valid for the current epoch and the two before it, and `ct_eq` compares it. It is accepted only for `POST /leave` with neither `__Host-cs` nor `__Host-cpre` (`app.rs:667-673`). Origin and Sec-Fetch-Site are checked first.

| Question | Ruling | Evidence |
|---|---|---|
| Forgeable? | **No.** Forging it means forging HMAC-SHA256 under a 256-bit key that lives only in RAM. The domain separation from the pre-session token is injective: the labels differ, the pre-session input always carries a 64-hex `cpre`, and the leave input carries none, so the input lengths differ. The token is refused on every route except `/leave` | `flow::cookieless_leave_needs_the_leave_token`; code read |
| Replayable? | **Yes, by anyone, for 10–15 min.** The impact is nil: a cookieless `/leave` changes no state and only renders the Leave page | PoC `poc_leave_token_is_global_per_epoch` (third-party replay on another circuit → 200) |
| Links sessions? | **No.** The token is identical for every client in the same 5-minute epoch, so it carries no per-session or per-person value | PoC: tokens of two separate discarded sessions and of a cookieless visitor are byte-identical |
| Leaks anything? | **Yes, a 5-minute time beacon (Low, WEB-04).** Any visitor can enumerate the token sequence by fetching a cookie-clearing page every ≤ 5 min; a forged `__Host-cs` reaches the signed-out page. The token is also embedded in S10s ("Your report was sent"). Anyone who later sees a source's S10s page can map its token to the 5-minute window of the submission: a seized device, a screenshot or session-restore data. The design shows the send time only at day granularity (ADR-010) | PoC; `app.rs:378-383` |

**Verdict:** acceptable in principle. Make it unlinkable to time with the fix in WEB-04: a randomized stateless token `r ‖ HMAC(K, label ‖ r ‖ epoch)[..16]`, same length. It can then be neither enumerated nor mapped to an epoch without `K_pre`.

## A2 — Threat model and attacker goals

Trust boundaries:
- a source or attacker over Tor (any number of circuits, any bytes) → C-06 over the Unix socket, with tor's PROXY line;
- C-06 ↔ C-07 sealer IPC (C-06 holds no keys);
- C-06 → store reads;
- C-07 → C-08 over `istore.sock` (SEQPACKET, `SCM_RIGHTS`, `SO_PEERCRED`);
- a later device seizure of a source, and server-RAM disclosure.

The relevant adversaries in 02 §6 are the network/Tor-level attacker, a malicious visitor, a cross-site web attacker, the server operator and device seizure.

| # | Attacker goal | Result |
|---|---|---|
| G1 | Smuggle or desync requests (CL/TE, duplicates, obs-fold, bare CR/LF, pipelining, leading CRLF, absolute-form) | **Refuted.** `raw_line_discipline` and the httparse default config run before policy. TE, Content-Encoding, Expect, Upgrade, TE and Trailer are refused. Duplicate Host, CL, CT, Cookie, Origin and SFS are refused. CL is digits only, at most 19 digits, and required on POST. Bytes beyond CL are refused (`server.rs`, `bad_framing`), and the service serves one request per connection. Covered by the smuggling corpus, proptests and the code read |
| G2 | Slowloris on the head or body | **Refuted** for unbounded holding: head 10 s from accept, body idle 60 s, form total 120 s, upload 4 h, write 120 s, linger 2 s / 1 MiB. Residual slot pinning → WEB-07 |
| G3 | Crash the service (panic, OOM) with hostile input | **Refuted.** No indexing or unchecked arithmetic on input (clippy deny set plus the audit extras: one false positive). Every buffer is sized from a bound checked first (head ≤ 16 KiB + 107, form ≤ 112 KiB, multipart buffer fixed, chunks ≤ 64 KiB). Proptests and the 200-garbage-request test pass. The fuzz campaign was not run (A4) |
| G4 | Burn CPU cheaply | **Finding** WEB-02 |
| G5 | Bypass CSRF (cross-site form, `null` origin, missing token, other session's token, pre-login token after login, multipart file before token) | **Refuted.** `origin_ok` matches lead decision (b), and a token is always required. Constant-time compare. Multipart requires `csrf` as the first part, checked at its `PartEnd` before any `PART_BEGIN`. `csrf_matrix`, `pre_login_token_invalid_after_login` |
| G6 | Session fixation or hijack through cookie handling | **Refuted.** `__Host-` with `Path=/; Secure; HttpOnly; SameSite=Strict`, no Domain, no expiry. The server makes a fresh `cs` at `/new` and at login, removes the old live session, and stores only `SHA-256(HKDF(cs))`. Constant 2,048-byte head (`wire_bytes`) |
| G7 | Learn whether an account exists, or tell login success from failure, from status, size or time | **Refuted** across users. Same calls with a dummy key; floor plus jitter on every outcome, incl. CSRF failure, rate limit and BUSY; same size class. The locator is derived from the passphrase, so "exists" equals "correct passphrase". Floor anchoring deviation → WEB-06 |
| G8 | Get IP, UA, exact time, filename, size, passphrase or body into logs, errors, panics or headers | **Refuted.** No per-request output. Only the static panic-hook `diag!`. Error types are code-only and `Debug` is redacted. UA and Accept-Language are dropped unread. No `Date` header. Filenames go only to the sealer. The circuit id is HMAC'd at once. Tests: `no_reflection_of_input`, `hygiene::*`. safefs-lint and logging-lint are clean. Time beacon → WEB-04 |
| G9 | Make the service degrade (store unsealed, skip the sealer) when a dependency is down | **Refuted.** Sealer unavailable, BUSY, store errors and an insane clock all map to the busy page, and nothing is stored locally (`fail_closed_dependencies`) |
| G10 | Recover plaintext or passphrases from C-06 memory after use | **Finding** WEB-01 |
| G11 | Credit a late or foreign ack to the wrong bundle (STO-29) | **Refuted.** Any failure closes the connection (`self.sock = None`), and every ack echoes SHA-256(bundle), compared in constant time. Tests `hand_over_fails_closed_without_a_commit_ack` (wrong hash in either phase, late ack on a closed socket) |
| G12 | Get a commit ack without a commit, or a commit on a corrupt copy | **Refuted.** `0x01` needs a `CommittedStaged`, which only `commit_staged` creates after `commit_envelope` returns. The store hashes its copy and checks it against the header before `0x02` (`copy_verified`). Unknown outcome → SEA-01 |
| G13 | Leave orphans or a partial blob after interim ack without commit, a timeout or a crash | **Refuted.** A `StagedBlob` drop becomes an orphan. `CommitGuard` handles cancellation. The sweep deletes only blobs that are unregistered and unreferenced, and fails closed on error. PG tests `pg_staged_*`. Capacity note → STO-30 |
| G14 | Abuse rate limiting to deny service globally | **Finding** WEB-05 (bucket starvation). The global session cap is exhaustible by design (ADR-038) |

## A4 — Tool runs (versions and triage)

| Tool | Version / pin | Command | Result | Triage |
|---|---|---|---|---|
| Crate tests | 1.94.1 | `cargo test -p candor-intake-web --locked` | 48 + 11 + 9 + 3 + 3 + 4 pass, `hardening` harness passes | — |
| Store tests with PG | PG 16 via `scripts/pg-test.sh` | `pg-test.sh cargo test -p candor-intake-store --locked` | 33 + 18 + 37 (PG enabled, incl. `pg_staged_ack_after_commit`, `pg_staged_crash_between_copy_and_commit`, `pg_staged_stalled_commit_refused`) + 6 + 22 pass | — |
| Sealer tests (root) | 1.94.1 | `cargo test -p candor-sealer --locked` (as root; `ulimit -l` could not be raised in this sandbox, the existing limit sufficed) | all suites pass incl. `handover` (3) and the `hardening` harness | — |
| Auditor PoCs | scratch crate `c06-audit/poc` (path deps on the audited crates; built into the shared target cache because the host had < 600 MB free, artefacts deleted afterwards) | `cargo test --test audit_poc -- --nocapture` | 5/5 confirm findings (outputs quoted below) | WEB-02/03/04/05/06 |
| clippy deny set | 1.94.1 | `cargo clippy -p candor-intake-web --all-targets -- -D warnings` | clean | — |
| clippy audit extras | 1.94.1 | §C list | 1 hit in crate: `integer_division` `multipart.rs:310` (`UPLOAD_CHUNK / 2`, a constant) | false positive |
| safefs-lint / logging-lint | in-repo | `lint-safefs.sh`, `lint-logging.sh` | OK (100 files) / ok (109 files) | — |
| constants lint | in-repo | `python3 tools/constants_lint.py` | 46 constants, 0 conflicts | — |
| cargo-deny | 0.20.2 `--offline` | `cargo deny --offline check` | advisories ok, bans ok, licenses ok, sources ok (duplicate warnings for 7 crates, pre-existing) | — |
| cargo-audit | 0.22.1, advisory-db `3461c0d` (2026-10-01), 1,278 advisories | `--no-fetch --deny warnings` | 305 crates, no findings | — |
| cargo-vet | 0.10.2 | `cargo vet --locked` | succeeded (httparse via dated exemption, expires 2027-03-30) | WEB-10 |
| **cargo-fuzz** (3 targets × 120 s) | 0.13.1, nightly-2026-09-28 | `cargo fuzz build --target-dir <scratch>` | **NOT RUN.** The build needs more than the ≈ 0.5 GB free on the host disk (95–100 % full, 20 GB of it the existing `target/`); a disk guard stopped it at 514 MB, and the scratch build was deleted | **Gate item open**: run `fuzz_http_request`, `fuzz_form_urlencoded`, `fuzz_multipart_intake` for ≥ 120 s each after freeing disk. Proptests for all three parsers pass |
| httparse build script | 1.10.1 | read `build.rs`; `cargo tree -i httparse -e features` | runs only `$RUSTC --version`, reads `CARGO_CFG_*`, emits cfgs; no network or file writes. The only dependent is candor-intake-web, with no `std` feature, so the SIMD path is compiled out | WEB-10 |

## Findings

### AUD-RM2-WEB-01 — Draft plaintext, identity block and reply bodies are copied into view-model strings that are not zeroized
- Severity: Medium
- Location: `crates/candor-intake-web/src/flows.rs:204-216` (`identity_data`: full name, role, contact → `String`), `:305-322` (`step_questions`: questionnaire answers → `Vec<String>`), `:325-340` (`files_of`: file descriptions), `:640-642` (`messages`: recipient reply body and sender label → `InboxMessage.text: String`), `:2041` (`conversation` draft → `draft_text: String`); the target types are `candor-source-ui/src/model.rs:538, 745-751, 780` (commit 6c03b66)
- Category: B3.2 (CWE-226/244)
- Description: The sealer returns these values as zeroizing `SecretText`. C-06 then calls `.expose().to_owned()` into plain `String`s of the `ViewModel`. The model is dropped after `ui::render` without wiping, so every render leaves:
  - the source's report text;
  - in Identified/Confidential mode, their real name and contact;
  - the team's replies

  in freed heap of the network-facing process. The S10 words (`Vec<Zeroizing<String>>`) and the page body are handled correctly, which shows the gap is only in these fields. SPEC-NOTES "Secrets" says these values live only in zeroizing buffers. AUD-RM1-SUI-03 asked C-06 to hold the view model in zeroizing storage.
- Exploit scenario: A later memory disclosure in C-06 (a bug in a dependency, `/proc/<pid>/mem` access by a compromised co-tenant uid, a hypervisor snapshot) recovers plaintext and identity data long after the session ended. 07 §5 BE-055 places draft text and identity blocks "only in sealer mlocked RAM". `mlockall` and no core dumps reduce the risk (no swap, no core) but do not remove it. Precondition: process-memory access. That is why this is Medium and not High.
- Fix recommendation: Make the source-ui model fields that carry source or recipient text `Zeroizing<String>`, or implement `Zeroize`/`Drop` for `ViewModel` (owner: source-ui, coordinated change). Fill them without intermediate `String`s. Regression test: a test-only allocator or a `Drop` probe asserting that these fields are wiped, or a grep lint banning `.expose().to_owned()` in `flows.rs`.
- Spec / requirement reference: BUILD-BRIEF Secrets bullet; 27 §12.3; 07 BE-055; AUD-RM1-SUI-03 (contract item for C-06)
- Status: Open

### AUD-RM2-WEB-02 — Multipart delimiter search rescans the whole buffer after every feed (quadratic CPU on small reads)
- Severity: Medium
- Location: `crates/candor-intake-web/src/multipart.rs:286-315` (`State::Body`), driven by `flows.rs:2222-2232`
- Category: B2.3 / R9 §6.1 resource exhaustion (CWE-407/400)
- Description: For file parts the parser holds data back until a full 64 KiB chunk is available or the buffer is half full. On every `next_event` it runs `self.buf.windows(dl).position(..)` over the **whole** buffer, which can reach ≈ 34 KB. The server feeds whatever one socket `read` returns. With tiny reads the total work is Σ L·dl ≈ O(n²·dl), and near-delimiter content (`\r\n--BBB…B` repeated) makes each window comparison run the full delimiter length.
- Evidence (PoC `poc_multipart_small_feeds_quadratic`, debug build, 33 KB of near-delimiter file data, 70-byte boundary):

  | Feeding | Time |
  |---|---|
  | one feed | 1.5 ms |
  | 498-byte feeds (one Tor cell) | 32 ms |
  | 1-byte feeds | **12.98 s** |

- Exploit scenario: A source-side attacker (ADV malicious visitor) holds a session; sessions are cheap. On each of many circuits it uploads a file whose bytes trickle in 1-byte RELAY cells. Each 33 KB costs the server seconds of CPU on a tokio worker thread, synchronously, so it blocks other requests on that worker. Upload limits (30/h per circuit) do not bound bytes per upload. Reads coalesce once the server falls behind, which caps the damage per connection, but a few dozen such uploads can saturate the runtime's workers. The result is an availability loss and timing degradation for all sources.
- Fix recommendation: Keep a scan offset: search only the bytes added since the last scan plus `dl − 1` bytes of overlap, so the scan is linear. Optionally use a `memchr`-style first-byte skip. In `upload_inner`, coalesce socket reads until `room()` or 64 KiB before feeding. Regression test: bounded time (or a comparison counter) for 1-byte feeds of 64 KiB.
- Spec / requirement reference: BUILD-BRIEF "Input handling"; 07 §5.1 multipart parser; ST-043
- Status: Open

### AUD-RM2-WEB-03 — Leave fails (500, no Clear-Site-Data) when the browser still holds a stale session cookie and no pre-session cookie
- Severity: Low
- Location: `crates/candor-intake-web/src/app.rs:659-684` (`check_csrf`, `PostAuth::Leave` arm), `flows.rs:719-726`
- Category: B5 robustness of a safety control (11 Leave page, 11a)
- Description: The cookieless leave-token arm runs only when **no** `__Host-cs` is present. A stale `cs` can be present because the session idled out after 20 min, or because S10s's `Clear-Site-Data` was not honoured; the session is still kept for idempotent `/submit`. With a stale `cs` and no `cpre` (`cpre` expires after 15 min), the request falls to the `PreOrSession | Leave` arm and gets `Fail::Error`. Every other session route answers `Gone`, the signed-out page with Clear-Site-Data.
- Evidence: PoC `poc_leave_with_stale_session_cookie_fails`: `POST /leave` with a stale cookie and the page's token → **500, no `Clear-Site-Data`**; `POST /extend` with the same cookie → 200 + `Clear-Site-Data`.
- Exploit scenario: There is no attacker. A source who has idled on a page presses Leave, the panic button. The source gets a "something went wrong" page instead of the "You have left / New Identity" guidance, and the stale cookie stays in the browser.
- Fix recommendation: For `PostAuth::Leave` with a non-live session, accept the leave token, or render the Leave page anyway, since Leave changes nothing without a live session. Never answer an error to Leave. Regression test: a stale cookie with each token kind gives 200 + `Clear-Site-Data`.
- Spec / requirement reference: 11 §7 Leave page; SUI-036; 08 SW-16
- Status: Open

### AUD-RM2-WEB-04 — The stateless leave token is a global per-epoch value (5-minute time beacon)
- Severity: Low
- Location: `crates/candor-intake-web/src/token.rs:173-187`, `app.rs:378-383`
- Category: B1.2 / B1.7 (CWE-200)
- Description and evidence: See the ruling above. The PoC `poc_leave_token_is_global_per_epoch` shows identical tokens for two discarded sessions and for a visitor who never had a session. That visitor reached the signed-out page with a made-up `__Host-cs`.
- Exploit scenario: An adversary polls a cookie-clearing page every few minutes and records (time, token). Later, the adversary sees a source's S10s page, for example on a seized device or in a screenshot. The adversary then learns the submission time to 5 minutes, although the system shows and stores only the day (ADR-010).
- Fix recommendation: `token = r(16 B) ‖ HMAC-SHA256(K_pre, "candor/web/leave" ‖ r ‖ epoch)[..16]`, with fresh `r` per render. It keeps the same 64-hex length and size class, stays stateless, and is verified over the same three epochs. Regression test: two renders in the same epoch differ, and both verify.
- Spec / requirement reference: ADR-010/016 (no exact timestamps); SPEC-NOTES decision 5
- Status: Open

### AUD-RM2-WEB-05 — Token buckets discard fractional refill; a steady trickle pins the global new-session bucket at zero
- Severity: Low
- Location: `crates/candor-intake-web/src/ratelimit.rs:114-128` (`Bucket::take`)
- Category: B2.6 / availability (CWE-682)
- Description: `refill = el·max / per` is truncated, and `self.at = now` then throws away the remainder. This happens on every call, including refused ones. For the global session bucket (600 per hour), `max / per` = 0.167 milli-tokens per ms, so calls spaced < 6 ms apart never refill it. The global check runs before the per-circuit check, so refused requests on any circuit keep the bucket starved.
- Evidence: PoC `poc_global_session_bucket_never_refills_under_trickle`. After the burst, 10 minutes of attempts every 5 ms grant **0** sessions (the intended rate gives ≈ 100). At 10 ms spacing, 60 are granted.
- Exploit scenario: About 170 POST `/new` per second across enough circuits (each within its 1/s request bucket) keeps "start a report" busy for everyone for as long as the trickle lasts. The 600/h cap can also be drained directly (ADR-038 accepts this), but the bug turns a cap into a lock that also holds at low cost after draining. Login and the per-circuit hourly classes have the same truncation, but only the client's own traffic affects them.
- Fix recommendation: Advance `at` only by the time actually converted (`at += refill·per/max`), or keep sub-milli remainders. Regression test: the PoC above, expecting ≈ the nominal rate.
- Spec / requirement reference: 07 §11 / 08 §4 rate limits; ADR-038
- Status: Open

### AUD-RM2-WEB-06 — Login floor is anchored at accept, and jitter is dropped once elapsed ≥ floor
- Severity: Low
- Location: `crates/candor-intake-web/src/app.rs:735-750`, `app.rs:527-536`; `received` is set in `server.rs` before the head is read
- Category: B1.7 (CWE-208)
- Description: The release time is `received + floor + U(0, 250 ms)`, which is a no-op when the work already ran past it. The README and 07 §11 specify `max(elapsed, floor) + U(0, 250 ms)`. Also, `received` is the accept time, so a client that spends up to 10 s sending its head shrinks its own floor.
- Evidence: PoC `poc_login_floor_from_accept`. The head was completed 2.9 s after connect, and the response arrived **200–340 ms** after the request completed (the floor is 3 s).
- Exploit scenario: No cross-user existence oracle was found: the locator is the passphrase, and the work is uniform with a dummy key. Two residual effects remain:
  1. when Argon2 queueing in the sealer pushes elapsed past the floor, the un-jittered release time reveals the sealer's queue length, a measure of other sources' activity, to any visitor;
  2. a client can measure its own login work precisely, which weakens the floor as defence in depth if work ever becomes account-dependent.
- Fix recommendation: `sleep_until(max(now_after_work, received + floor))` and then add the jitter unconditionally. Consider anchoring `received` at head completion. Regression test: the PoC asserting ≥ floor from head completion, and a jitter present when the work exceeds the floor.
- Spec / requirement reference: 07 §11 `intake.login_floor`; 11 §5.4 rule 7; AT-042
- Status: Open

### AUD-RM2-WEB-07 — Connection slots can be pinned cheaply: no per-session concurrent-upload cap and no minimum data rate
- Severity: Low
- Location: `crates/candor-intake-web/src/flows.rs:2058-2085` (`upload`), `server.rs` (`BodyReader::next`, `UPLOAD_TOTAL_TIMEOUT` 4 h, `BODY_IDLE_TIMEOUT` 60 s); `limits.rs:62-80`
- Category: B5.8 / R9 §6.1 slowloris
- Description: One session can run any number of uploads at once on different circuits, limited only by 30/h per circuit. Each upload may trickle one byte per 59 s for 4 h. 512 such uploads hold every serving slot, so all other visitors get the busy page. Without a session, unfinished heads also hold a slot for 10 s, and no limiter applies to them, because the limiter runs after head parsing. This is within the 07 §11 timeouts, so it is partly a spec gap.
- Exploit scenario: The adversary needs about 20 circuits and a handful of sessions to deny intake for hours.
- Fix recommendation: Allow at most one in-flight upload per session (a flag in `WebSession`). Add a minimum average rate after a grace period (for example ≥ 1 KiB/s averaged over 60 s). Deploy: confirm `HiddenServiceMaxStreams` and PoW defences in the torrc (16). Spec feedback to 07 §11.
- Spec / requirement reference: 07 §11 timeouts and connection cap; ADR-038
- Status: Open

### AUD-RM2-SEA-01 — STO-29 unknown outcome: the store can commit after the sealer gave up, and a retry is not idempotent
- Severity: Low
- Location: `crates/candor-sealer/src/server/handover.rs:398-420` (`hand_over`), `crates/candor-intake-store/src/staged.rs:464-517, 545-599` (`receive_inner`, `commit_staged`, `acknowledge`); `crates/candor-intake-web/src/flows.rs:1732-1740` (`SEALER_SEAL_TIMEOUT` → busy "not sent yet")
- Category: B7.1 / integrity of the submission outcome
- Description: The sealer fails if `0x02` is not received within `copy_deadline(len)` or `0x01` within 60 s. The store, however, keeps going in two cases:
  - **Late copy ack.** If the sealer timed out just after the store's `0x02` was queued, the store has a live `StagedBlob` and may commit.
  - **Slow commit.** `commit_staged` has no deadline tied to the sealer's 60 s, so it can commit after the sealer gave up.

  A failed `acknowledge` does not undo the commit. The sealer then reports failure, and C-06 shows "not sent" or busy. Re-handing over the same group is not treated as success: the duplicate group makes the blob an orphan, and the store refuses. The result is either a report that was delivered but shown to the source as not sent, or a duplicate report if the draft is re-sealed. Confidentiality is not affected. The "interim ack without commit" path itself is safe: the sealer fails at 60 s, and the store's orphan or uncertain handling cleans up (G12/G13).
- Fix recommendation (O-2 wiring):
  - Make the outcome idempotent: on a retry with the same bundle hash and group, the store answers `0x01 ‖ h` if that group is already committed.
  - The sealer retries the same sealed bundle on a fresh connection before reporting failure.
  - Bound the store's commit by the sealer's remaining budget (a statement timeout below 60 s).
  - C-06 wording for a timed-out `SEAL_FINISH`: "we could not confirm whether it was sent; log in to check" rather than "not sent".

  Test: commit at 59.9 s and ack at 60.1 s, then a retry, gives exactly one envelope and success.
- Spec / requirement reference: 08 API-053 ("lost SW-26 response leaves no envelope" / idempotency, SUI-013); AUD-RM2-STO-29; ADR-046(1)
- Status: Open

### AUD-RM2-WEB-08 — Upload "too large" is answered before the CSRF token is checked
- Severity: Info
- Location: `crates/candor-intake-web/src/flows.rs:2121-2130`
- Description: An upload whose `Content-Length` is over the limit renders the session's Files page (file list, session token) before the `csrf` part is read. A cross-site request carries no cookie (`SameSite=Strict`) and fails the Origin/SFS check, and a cross-origin page cannot read the response, so this has no impact. The rule "no session-dependent output before CSRF" is still bent.
- Fix recommendation: Answer the uniform error, or parse the `csrf` part first and then report the size.
- Status: Open

### AUD-RM2-STO-30 — Orphan and uncertain blobs count against `STAGED_MAX_IN_FLIGHT` until the next slot sweep
- Severity: Info
- Location: `crates/candor-intake-store/src/staged.rs:479-486`
- Description: The 64-entry in-flight cap includes `Orphan` and `Uncertain` entries, which are cleared only by the sweep at the next 15-minute slot boundary. If 64 hand-overs fail within one slot, for example on a blob volume below `MIN_COPY_RATE` (open item O-6) with large uploads, later receives are refused with `Capacity`. This fails closed (busy). It is noted for O-6 and for the deploy owner.
- Fix recommendation: Count only `Receiving`, `Live` and `Committing` toward the cap, with a separate bound for orphans, or trigger an early sweep when the cap is hit.
- Status: Open

### AUD-RM2-WEB-09 — Lead decisions (a)–(c) verified as implemented
- Severity: Info
- Description:
  - (a) httparse runs with the default config. `raw_line_discipline` covers what httparse tolerates: bare LF, leading empty lines and obs-fold. The whole buffer must be exactly one head. The 2,048-byte head is checked at render time (`serialize_head` refuses any other length), and only page headers are written.
  - (b) `origin_ok` implements the stated matrix, and every POST route reaches `check_csrf`; Leave too, through the leave token.
  - (c) The token rotates at login (new session), at logout, Leave and discard (session removed), at passphrase rotation (`flows.rs:1903`) and at a mode change (`:1238`, `:1261`). A CSPRNG failure while rotating ends the session.
- Status: Info

### AUD-RM2-WEB-10 — New dependency `httparse =1.10.1`
- Severity: Info
- Description:
  - Its build script only probes `rustc --version`. It contains an `expect`, so a failure fails the build.
  - `default-features = false`, and candor-intake-web is the only dependent, so `std` and SIMD are off. The fuzz lockfile pins the same version.
  - The core cursor code still contains `unsafe` (pointer bumping in `iter.rs`), and it sits on the source-facing path. It is covered only by a dated vet exemption (2027-03-30). Do a cargo-vet audit of 1.10.1 before the exemption expires.
  - Add `httparse` to the geiger baseline (B11.4); geiger was not run here.
- Status: Info

## Regression-test map for fixes (SG-21)

| Finding | Test to add |
|---|---|
| WEB-01 | Drop probe or lint for zeroizing view-model text fields |
| WEB-02 | 1-byte-feed timing or comparison-count bound in `multipart::tests` |
| WEB-03 | `flow::leave_with_stale_cookie_is_the_leave_page` |
| WEB-04 | `token::tests::leave_tokens_are_unlinkable` |
| WEB-05 | `ratelimit::tests::trickle_does_not_starve_refill` (PoC) |
| WEB-06 | `flow::login_floor_from_head_completion_with_jitter` (PoC) |
| WEB-07 | `flow::one_upload_per_session` |
| SEA-01 | sealer/store cross test: commit lands after the sealer deadline, retry → one envelope, success |

## Gate verdict

- Critical: 0. High: 0.
- Medium open: **WEB-01, WEB-02**. Each must be fixed and re-tested, or accepted in writing by the lead.
- Tool requirement open: the three fuzz targets did not run on this host (disk full). Run them for ≥ 120 s each on the audited or fixed commit.
- Low/Info: tracked, not blocking.

**Gate: FAIL (conditional)** for commit `6c03b66`. It becomes PASS when both Mediums are closed (fixed or accepted) and the fuzz runs are clean. No re-audit of other areas is needed unless the fixes touch more than the named functions.
