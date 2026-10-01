<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-intake-web — spec notes

Scope: C-06 Source Web Service. Sources:
- 07 §4.1/§4.2/§4.4, §5.1, §5.2 (client side), §8, §11, §12, §13;
- 08 §3.3–§3.10 and §4 (SW-01..SW-30);
- 11 §5–§7; 11a;
- 16 §6.1, §7.1, §13, §14;
- IMPL-00; IMPL-RM2 §2.6–§2.8;
- ADR-010/016/026/029/034/038/047(3)/051(4)/052/053/055/056.

It also covers the C-5 wiring and AUD-RM2-STO-29 in `candor-sealer::server::handover` and `candor-intake-store::staged`.

## Design

**Interfaces.**
- `Web<S: StoreReads>` is built by `Web::new(WebConfig, SealerClient, S, Arc<dyn DayClock>)`.
- `serve(Arc<Web<S>>, tokio::net::UnixListener)` is the server. `install_panic_hook()` and `hardening::harden_process()` go with it.
- `StoreReads` is the store seam. It is read-only and implemented for every `IntakeStore`.
- The sealer is reached only through `candor_sealer::proto`, the owner's types, built without the `server` feature.

**Invariants.**
- One request per connection.
- Every response head is 2,048 bytes and every body is exactly P1 or P2. The size class depends only on the method and whether a `__Host-cs` cookie is present.
- At most one `Set-Cookie` per response.
- No state change happens before the `Origin`, `Sec-Fetch-Site` and CSRF checks.
- GET is side-effect-free.
- The web never stores `cs`, a passphrase, a draft, a filename or a key. Passphrase words exist only in zeroizing buffers while S10 is rendered.
- Time comes only from the monotonic clock; days come from `DayClock`.
- No per-request output of any kind.

**Input limits.** All are named constants in `src/limits.rs`:

| Input | Limit |
|---|---|
| PROXY line | ≤ 107 B |
| Request line | ≤ 4 KiB |
| Head | ≤ 16 KiB, ≤ 50 fields |
| Path | ≤ 64 B, `[A-Za-z0-9/._-]` |
| Form body | ≤ 112 KiB, ≤ 128 fields |
| Short text | ≤ 500 chars |
| Long text | ≤ 60,000 chars / 65,536 B |
| Name | ≤ 200 chars |
| Passphrase | ≤ 256 B |
| Word | ≤ 64 B |
| Token | ≤ 160 B |
| Multipart | ≤ 4 parts, part head ≤ 1 KiB, filename ≤ 255 B, media type ≤ 127 B, value ≤ 160 B, boundary ≤ 70 |
| File | ≤ `max_file_bytes` (≤ 4 GiB), in ≤ 64 KiB chunks |
| Upload time | 30 s grace + `Content-Length` at 1 KiB/s (≤ 4 h); average rate ≥ 1 KiB/s after the grace (AUD-RM2-WEB-07) |
| Uploads in progress | 128 service-wide, 1 per session (AUD-RM2-WEB-07) |
| Multipart parse work | ≤ 4 window checks per fed byte + 64 Ki per request (AUD-RM2-WEB-02) |
| Leave tokens remembered | 65,536, 15 min each (AUD-RM2-WEB-04) |
| Connections | 512 served + 512 answered busy |
| Sessions | 10,000 |
| Circuit entries | 65,536 |

**Fail-closed table.**

| Failure | Result |
|---|---|
| Sealer socket down, deadline, framing or version | busy page (S90, 429); `Health.sealer_up = false` |
| Sealer `BUSY` | busy page |
| Sealer `UNKNOWN_SESSION` | signed-out page (S94); web session removed |
| Sealer `NO_ELIGIBLE_TRIAGE` / `UNAVAILABLE` | S04b-X with the alternative channel; nothing sealed |
| Sealer `LIMIT` | field error (draft too long); nothing stored |
| Other sealer error | S92 (500), "not sent" |
| Store down or restore-pending | busy page; no session is created |
| `DayClock` insane at submit | busy page "not sent yet"; no `SEAL_FINISH` |
| Malformed request, CSRF/Origin/Sec-Fetch-Site failure, oversize | S92, uniform |
| Unknown route | S91 (404) |
| Render or header failure | pre-rendered S92 of the class (start-time checked) |
| Handler panic | S92 (unwinding builds); abort (release) |
| CSPRNG failure | S92 |

**Secrets and their lifetime.**
- **Session CSRF token.** Lives in a zeroizing string for the session's lifetime. It is rotated at login, passphrase rotation and disclosure-mode changes, and removed at logout, Leave and discard (decision 4).
- **Piece key.** Lives for the session's lifetime.
- **Pre-session MAC key, leave-token key and limiter key.** Random per process. Issued leave-token nonces are kept in RAM for 15 min (decision 5).
- **Source text, identity data, file descriptions and team replies in view models.** Only in `Zeroizing<String>` fields of the source-ui model, filled straight from the sealer's `SecretText`; the rendered body is zeroizing too and is dropped (wiped) once the response is written (AUD-RM2-WEB-01).
- **Login passphrase.** Lives in zeroizing buffers for the duration of one request and is forwarded to the sealer.
- **S10 words.** Live in zeroizing strings for one render.

## Implementation decisions

1. **Request heads are parsed with `httparse`; responses use the in-crate fixed-size writer** (lead decision, 2026-10-01). hyper is not used.
   - `httparse =1.10.1`, `default-features = false` (no_std, no SIMD, no dependencies) tokenizes the request line and fields (`http::parse_head`). Its `build.rs` only runs `$RUSTC --version` and reads `CARGO_CFG_*`. It is in `deny.toml` `allow-build-scripts` with a comment citing this decision, and has a cargo-vet exemption (expires 2027-03-30).
   - The strict-subset policy sits on top:
     - raw-byte checks before httparse, which tolerates bare LF and leading empty lines: CRLF only, no bare CR or LF, no empty line before the request line, no obs-fold, request line ≤ 4 KiB, head ≤ 16 KiB;
     - httparse's default config: single spaces in the request line, invalid field lines are errors, obs-fold refused, at most 50 fields (`TooManyHeaders`);
     - the whole buffer must be exactly one complete head;
     - HTTP/1.1 only, origin-form visible-ASCII targets;
     - `Transfer-Encoding`, `Content-Encoding`, `Expect`, `Upgrade`, `TE`, `HTTP2-Settings` and `Trailer` are refused;
     - duplicate `Host`, `Content-Length`, `Content-Type`, `Cookie`, `Origin`, `Sec-Fetch-Site` and duplicate own cookies are refused;
     - `Content-Length` is digits only and **required on every POST**;
     - one request per connection, and bytes beyond `Content-Length` are refused (`server.rs`).
   - Responses keep the fixed-size writer (`serialize_head`): hyper would add `Date` and `Connection` and answer HTTP/1.0 with HTTP/1.0 status lines, which breaks the 2,048-byte head contract (AUD-RM1-SUI-05 item 7).
   - When a head is too broken to tokenize, the size class of the error page is a best-effort guess (`POST `/`HEAD ` prefix, `__Host-cs=` present) and is never used to accept anything.
   - Unchanged tests: the unit and proptest suite, the smuggling corpus, `oversize_heads` and the three fuzz targets.
2. **`Origin: null` only with `Sec-Fetch-Site: same-origin`** (lead decision, 2026-10-01). Browsers send `null` for every POST under `Referrer-Policy: no-referrer` (11 §5.3), so `null` cannot be refused outright.
   - `token::origin_ok` rules:

     | `Origin` | Accepted `Sec-Fetch-Site` |
     |---|---|
     | `null` | `same-origin` only |
     | absent | absent or `same-origin` |
     | the exact onion origin | absent or `same-origin` |

     Everything else is refused, including `null` without `Sec-Fetch-Site`.
   - 08 §3.7 says nothing about `Sec-Fetch-Site`, so `none` is not allowed (it is refused with any `Origin`).
   - A valid CSRF token is always required as well (decisions 4 and 5). Tor Browser sends `Origin: null` with `Sec-Fetch-Site: same-origin` for these forms.
   - Tests: `token::tests::origin_matrix`; `http_security::csrf_matrix` covers null with cross-site, same-site or none, null without `Sec-Fetch-Site`, a foreign origin without `Sec-Fetch-Site`, null and same-origin with a wrong token (refused), and null and same-origin with a valid token (accepted).
3. **`Sec-Fetch-Site` must be absent or `same-origin`**, and must be `same-origin` with `Origin: null`. `none`, `same-site`, `cross-site` and any other value are refused (the IMPL-RM2 tightening).
4. **CSRF tokens: one per session** (lead decision, 2026-10-01: accepted in place of 11 §5.7's single-use tokens, with the conditions below).
   - A session token is 256 bits from the CSPRNG and is stored only in the session's `WebSession` (bound to that session). It is compared in constant time (`subtle`) and travels only as a hidden form field in POST bodies, never in a URL.
   - It is **rotated** at:
     - login (a new session and a new token);
     - logout, Leave and discard (the session and its token are removed);
     - passphrase rotation (new authority);
     - a disclosure-mode change in either direction (S05b identity added, declined or removed).

     A CSPRNG failure while rotating ends the session (fail closed: the old token never stays valid).
   - It is **not** rotated when a report is submitted. `Submitted` grants the session nothing new: it can only re-render S10s, and the inbox needs a login, which makes a new session. Keeping the token keeps a retried `/submit` after a lost response idempotent: it re-renders S10s and nothing is sealed twice.
   - Pre-session tokens (S01–S04, login, error pages) are stateless: `HMAC-SHA256(K_pre, "candor/web/pre" ‖ cpre ‖ epoch5min)`, valid for the current and the two previous epochs (10–15 min, within the 15-min `__Host-cpre` lifetime, AUD-RM1-SUI-06). They are bound to `__Host-cpre`. Once a live session exists only the session token is accepted, so the pre-login token is dead after login.
   - Tests: `flow::pre_login_token_invalid_after_login` (pre-login token refused with the session cookie, with and without the old `__Host-cpre`; another session's token refused; nothing in a URL; token dead after logout); `flow::extend_identity_and_discard` (rotation at a mode change); `passphrase_rotation`.
5. **Leave always needs a valid token** (lead decision 2: "a valid csrf token is always required"; replaces the earlier no-token exception).
   - With a live session, the session token is required. With only `__Host-cpre`, the pre-session token is required.
   - With no cookie at all, the **leave token** is required. The cookie-clearing screens (S10s, discarded, closed, signed out) send `Clear-Site-Data`, so the Leave form they render can carry nothing but this token. `App::page` issues one in place of the page token on exactly those screens (the Leave page itself has no form); it has the same 64-hex length, so sizes do not change.
   - **Construction (AUD-RM2-WEB-04, lead decision):** `nonce(16 B) ‖ HMAC-SHA256(K_leave, "candor/web/leave" ‖ nonce)[..16]`, a fresh random nonce per render. It contains no time and no epoch, so it can neither be enumerated nor mapped to when a page was shown. Validity is bounded by a server-side set of issued nonces (RAM, monotonic clock): 15 min each, at most 65,536, the oldest forgotten first. Verification checks the MAC in constant time and that the nonce is remembered. A token may be used again within its 15 min (back button); it authorises nothing else.
   - **Stale session cookie (AUD-RM2-WEB-03):** a Leave carrying a `__Host-cs` that is not a live session (idle expiry, ended session, `Clear-Site-Data` not honoured, a forged value) always renders the Leave page with `Clear-Site-Data`, whatever token the form carried: the session token is gone, and without a live session Leave changes no state. `Origin` and `Sec-Fetch-Site` are still checked first.
   - The leave token authorises only `/leave`, which with no cookie changes no state. `Origin` and `Sec-Fetch-Site` are checked as for every POST.
   - Tests: `flow::cookieless_leave_needs_the_leave_token`, `flow::leave_with_stale_cookie_is_the_leave_page`, `token::tests::leave_tokens_are_unlinkable`.
6. **Error pages.** source-ui has no 400 or 413 screen, so the mapping is:
   - malformed request, CSRF failure or oversize: S92 (500);
   - unknown route: S91 (404);
   - every capacity, rate, sealer, store, restore and clock condition: S90 (429), byte-identical across causes for the same request context;
   - other methods: 405.

   For field-level limits (text too long, file too large, too many files, empty file) the page is re-rendered with the inline error (11 §5.7).
7. **Login floor scope.** The floor applies to every POST to `/login`, `/inbox` (SW-22 is a POST `/inbox` action) and `/rotate/confirm`. That includes CSRF failures, rate limits, busy and malformed forms. Inbox part navigation therefore also waits for the floor; this is rare and accepted.
   - **Anchor and jitter (AUD-RM2-WEB-06):** the body of these routes (≤ 112 KiB) is read in full first, and the floor runs from that moment, the end of the full request; a slow head or body no longer shortens it. Release is `max(complete + floor, work done) + U(0, 250 ms)`: the jitter is added also when the work ran past the floor (`app::floor_release`). Tests: `flow::login_floor_from_full_request`, `app::floor_tests::floor_then_jitter_on_every_path`.
8. **Uniform login work.** The sequence is always LOGIN_DERIVE → store lookup → random challenge → LOGIN_SIGN → strict Ed25519 verification against the account's `auth_pk`, or a per-process dummy key. Unknown and known locators make the same calls, and the floor hides the rest. Word-count and word-list pre-checks (11 S11 messages) run before Argon2id; they do not depend on any account.
9. **PROXY protocol.** tor emits **PROXY v1 text** (`PROXY TCP6 fc00:dead:beef:4dad::HHHH:LLLL ::1 sport vport`), not v2 as IMPL-RM2 §2.6 says.
   - The parser accepts exactly that shape and keeps only the 32-bit circuit id, which becomes `HMAC(K_rl, id)[..16]` at once.
   - The line is required: a stream without it is closed unanswered. This is fail closed, and it also enforces "only reachable through the onion" (NET-012, 16 §6.1). 16 OI-1 must confirm in integration that tor writes the line on Unix-socket targets.
10. **Rate limits.**

    | Limit | Value |
    |---|---|
    | Requests | 60/min, burst 20, per circuit |
    | Login | 5/10 min |
    | New session | 6/10 min |
    | Upload | 30/h |
    | Review | 10/h |
    | Submit | 10/h |
    | Message | 20/h |
    | Extend | 12/h |
    | Rotate | 3/day |
    | End | 3/h |
    | New passphrase | 5 per 2 h |
    | Global requests | 600/s |
    | Global new sessions | 600/h |

    Entries are evicted after 10 min idle (NET-013), so windows longer than 10 min hold only while the circuit stays active. Privacy wins over precision, and the global buckets carry the real protection.

    **Token buckets (AUD-RM2-WEB-05):** refill carries its remainder (the bucket's clock advances only by the time converted into whole milli-tokens, in nanoseconds), so a steady trickle of requests cannot hold a bucket at zero. A request is granted only if both the global and the circuit bucket have a token, and only then are both spent; a refused request costs nothing anywhere. Tests: `ratelimit::tests::trickle_does_not_starve_refill` (≈ 100 sessions in 10 min under a 5 ms trickle, nominal rate), `refusal_spends_nothing_globally`.
11. **Socket activation.** The library takes a `tokio::net::UnixListener`. Taking fd 3 from `LISTEN_FDS` needs `OwnedFd::from_raw_fd`, which is `unsafe` (forbidden here; allow-listed only in `candor-memlock`). The binary glue belongs to the integration step (open item O-3), as for the sealer.
12. **Logging.** There is no per-request event of any kind. The only output is the panic hook's static `diag!` (no payload, location or codes). `Web::health()` gives two booleans for the integrator's daily health band. The `CTR:submissions_received` counters of 08 belong where the commit is known (sealer/store, ADR-047(3): chaff is never counted). They are not emitted here.
13. **Sessions.**
    - The table key is `SHA-256(h)` and the sealer handle is `h[..16]`, with `h = HKDF-SHA256(cs, "candor/src/handle")` (11 §5.6).
    - Eviction at capacity (oldest idle) and expiry do not send `ZEROIZE`, because the web does not keep the handle. The sealer's identical 20 min / 2 h timers end its record.
    - Logout, discard, leave and S10s send `ZEROIZE` explicitly.
14. **Draft encoding in the sealer.**
    - Questionnaire field ids are 1–9: category, what, when, where, who, how_know, people_know, reported_before, anything_else. S06 descriptions use `100 + n`.
    - Multi-choice values and month/year (`month\nyear\n[ongoing]\n[unsure]`) are `\n`-joined.
    - The identity block is `name\nrole\nmailbox|other\ncontact`.
    - The S05 step-3 category is mapped to the channel's category id in the COI `categories`. S04b ticks are mapped from index to role-label id (`ChannelConfig::roles`).
    - The mode chosen at S04 stays in the web session until S05b confirms it. The sealer draft stays ANONYMOUS until then (11 S05b).
15. **The web never sees filenames.** They go to the sealer as encrypted metadata only. S06 lists files as "#n" with the padded size bucket (08 SW-06 "File (size bucket)").
16. **Multipart: 4 parts.** The S06/S12 forms send `csrf`, `file`, `neutral_names` and `action`; 07 §5.1 says 3. `csrf` must be first. `PART_BEGIN` waits for the first file byte, so an empty file never reaches the sealer, and is declared with the request `Content-Length` (sealer decision 8). The last chunk is held back one step so `last = true` is exact. Any failure after `PART_BEGIN` sends `PART_DROP`.
    - **Linear parsing (AUD-RM2-WEB-02):** the delimiter and blank-line searches carry a scan offset (no match starts before it), adjusted when bytes are consumed and reset on state changes, so each fed byte is examined about once per pattern whatever the read sizes. A per-request CPU budget fails closed (`MultipartError::Budget`) if the parser ever examines more than 4 positions per fed byte plus 64 Ki. The request-head reader uses the same carried offset. The auditor's PoC (33 KB of near-delimiter content, 70-byte boundary, 1-byte feeds) went from ≈ 13 s to 0.6 ms (release), 11 ms (debug). Tests: `multipart::tests::one_byte_feeds_are_linear`, `work_budget_fails_closed`.
    - **Slot pinning (AUD-RM2-WEB-07):** at most 128 uploads in progress service-wide (of the 512 serving slots) and one per session (a flag cleared on every exit path); either limit gives the busy page. An upload's deadline is 30 s + `Content-Length` at 1 KiB/s (≤ 4 h), and after the 30 s grace every read must keep the average rate since the start at ≥ 1 KiB/s, so a trickle cannot hold a slot. Tests: `flow::one_upload_per_session`, `server::tests::upload_deadlines_follow_the_minimum_rate`.
    - **Size after the token (AUD-RM2-WEB-08):** an over-size `Content-Length` is reported (inline, on the Files page) only after the `csrf` part has been checked; with a bad token it is the uniform error. Test: `flow::oversize_upload_reported_after_csrf`.
17. **Grapheme counts.** The service counts Unicode scalar values after NFC. This is an upper bound of the grapheme count and matches the browser's `maxlength`. No segmentation dependency is needed.
18. **Inbox (08 §3.8 `N_fixed = 32`).** Every render makes exactly 32 `OPEN_REPLY` calls: the real entries (`u32be(len) ‖ SealedObject ‖ stanza`) first, then random 1,024-byte dummies.
19. **S10c attempts.** After 3 mismatches the web stops forwarding words: only "Get a new passphrase" (which resets the count) and "Discard" remain (11 S10c). The sealer's own limit of 5 (07 §5.2) stays as a second line. If it is ever reached, the draft is erased and the source sees the "discarded" page.
20. **S13.**
    - Discard is implemented: SEAL_ABORT, ZEROIZE, `Clear-Site-Data`.
    - "Ask the team to delete my report" is a sealed follow-up with a fixed text (11 S13 variant 3).
    - **Close mailbox (SW-15) and reply deletion (SW-14) are refused with the uniform error.** They need `SEAL_SIGNAL` (not implemented in the sealer, its decision 10) and a K31-signed store deletion. The web holds no K31 and `StoreReads` is read-only. See O-1.
21. **Not implemented:**
    - S08 "normalize/keep invisible characters" and the identity hints (they only re-render S08);
    - the 11 §5.6 draft-preserving re-authentication;
    - the 11 §S11 HIGH-profile rotation offer flag, which is rendered but not tracked per login.
22. **The manifest (SW-23)** is served byte-exact with a minimal fixed header set and no padding, as 11 §5.5 says. `/.well-known/candor/health` (16 §15) renders the landing page without session context and never touches the sealer or the store.
23. **`Host`** must equal the configured onion host exactly (ASCII case-insensitive, no port).
24. **Process hardening.** `harden_process` uses rustix and landlock, the same safe wrappers as the sealer. It applies no-dump, `RLIMIT_CORE = 0`, `mlockall`, and Landlock at ABI 6 with no filesystem rights, no TCP and scoping. seccomp stays with systemd.
25. **C-5 / AUD-RM2-STO-29** (lead dispositions after round 6). Both sides now speak protocol version 2:
    - **Unknown outcome (AUD-RM2-SEA-01).** A store commit that lands after the sealer gave up is recognised, never committed twice: the sealer's `StoreConnection::hand_over_with_retry` re-sends the same sealed bundle once on a fresh connection, and the store's `commit_staged` treats `DuplicateEnvelope` as an idempotent success (`CommittedStaged::replayed`, `0x01 ‖ h`). The idempotency key is the group digest (unique in the store, over all three object hashes); a RAM record of recent commits additionally binds the bundle SHA-256 (a different bundle for a committed group is refused). C-06 shows "could not confirm, do not resend, log in later to check" (`sui-error-unconfirmed`) when `SEAL_FINISH` was sent but not answered in time (`SealerError::NoReply`), never "not sent"; a second submit cannot seal twice. Tests: `tests/sto29_handover.rs::late_commit_then_retry_is_one_envelope_and_success`, `tests/sealer_client.rs`, store `staged_duplicate_envelope_orphan_swept`, `staged_unknown_outcome_keeps_blob`, PG `pg_staged_ack_after_commit`.
    - **Hash echo.** Every acknowledgement is `u8 code ‖ SHA-256(bundle)` (33 B).
    - **Copied ack.** The store sends `0x02 ‖ h` once the copy is durable (after the safefs commit, inside `StagedReceiver::receive`). Then it sends `0x01 ‖ h` with the commit token, or `0x00 ‖ 0³²`.
    - **Deadlines.** The sealer waits for `0x02` within `copy_deadline(len) = 10 s + ⌈len / 50 MB/s⌉` and then for `0x01` within the fixed 60 s. A missing `0x02`, a wrong hash, an old one-byte ack or any other code fails and closes the connection.
    - **One cap.** `handover::MAX_BUNDLE_LEN` equals `staged::STAGED_MAX_BUNDLE_LEN` (4 GiB). The sealer refuses an oversize bundle before sending; the store clamps `max_len` to the cap.
    - **Group helper.** `StoreConnection::hand_over_group_bundle(&EnvelopeGroup)` hands over the ATTACHMENT_BUNDLE of a group, which is the seal-path call an `EnvelopeSink` makes.
    - **Test constructor.** `StagedBundle::from_bytes` seals bytes with the sealer's own writer, for tests and in-process tooling.
    - **Deploy requirement.** The blob volume must sustain ≥ 50 MB/s (`MIN_COPY_RATE`). Nothing checks this yet (open item O-6).

## Spec feedback

- 07 §5.1 / IMPL-RM2 §2.6 say hyper. The lead chose httparse plus the fixed-size response writer (decision 1); 07 should say so.
- 11 §5.7 says a missing or `null` `Origin` is rejected, while 08 §3.7 says it is accepted. 11 and 08 should both state the lead's rule: `null` only with `Sec-Fetch-Site: same-origin` (decision 2). 08 §3.7 should also name the `Sec-Fetch-Site` rule.
- 11 §5.7 says "128-bit single-use" and 08 §3.7 says "256-bit per session and per form". Align both on the lead's per-session rule and its rotation points (decision 4).
- IMPL-RM2 §2.6 says "PROXY-v2". tor emits v1 text (decision 9).
- 07 §5.1 allows 3 multipart parts, but the 11 S06 form needs 4 (decision 16).
- source-ui has no 400 or 413 screens. 07 §8 lists 400 and 413 pages (decision 6).
- 08 SW-03 says pre-session tokens are valid for 10 min; 11 §5.6 gives the cookie 15 min. Implemented as 10–15 min (decision 4).
- 16 §13 L4 says 20/min burst 40; 07 §11 / 08 §4 say 60/min burst 20. 07/08 is implemented.
- NET-013's 10-minute eviction contradicts per-hour and per-day per-circuit limits (decision 10).

## Dependencies

One new third-party crate, `httparse` (lead decision 1). Everything else was already in the workspace lockfile.
- `candor-source-ui`, `candor-sealer` (no default features: `proto` only), `candor-intake-store` (trait and types), `candor-core` (CSPRNG, strict Ed25519 verify, wordlist, passphrase normalisation, object parsing), `candor-log` (`diag!` in the panic hook): path dependencies. The RM-2 addendum requires them.
- `httparse =1.10.1` (`default-features = false`): the request-head tokenizer (decision 1). It has no dependencies, and its build script only probes `rustc --version`. It is in `deny.toml` `allow-build-scripts` and has a vet exemption (2027-03-30).
- `tokio =1.48.0` (`rt`, `net`, `time`, `sync`, `io-util`): async Unix sockets and timers. It is the workspace pin, already used by the sealer and the store.
- `zeroize =1.8.2`: zeroizing buffers for every request, page and secret (workspace pin).
- `subtle =2.6.1`: constant-time token comparison (workspace pin).
- `sha2 =0.11.0`, `hmac =0.13.0`, `hkdf =0.13.0`: the session table key, the handle derivation, pre-session tokens and circuit tokens. These are RustCrypto crates and are already workspace pins.
- `unicode-normalization =0.1.24`: NFC of form text (workspace pin, used by core and the sealer).
- `rustix =1.1.2` (`mm`, `process`, `thread`): safe `prctl`, `setrlimit`, `mlockall` and `gettid` for hardening (workspace pin).
- `landlock =0.4.7`: Landlock ruleset (workspace pin, used by the sealer).
- Dev: `proptest =1.11.0`; `tokio` with `macros` and `rt-multi-thread`; `rustix` (`fs`, `net`); `candor-sealer` with `server` (STO-29 cross test); `candor-safefs`; `tempfile =3.23.0` (socket paths and the blob root in private temp dirs).
- Fuzz (own workspace, never built by the main workspace): `libfuzzer-sys =0.4.10`, the same pin as the other fuzz crates.

## Test map

| ID | Tests |
|---|---|
| AUD-RM1-SUI-14, ST-074, IMPL-RM2-016 | `tests/wire_bytes.rs`: exact head bytes, header set and order, cookie forms, P1/P2, HEAD, robots, error, busy, leave |
| ST-044, ST-075, IMPL-RM2-012 | `http::tests::*` (proptest, httparse-backed parser), `tests/http_security.rs::smuggling_corpus`, `oversize_heads`; fuzz `fuzz_http_request` |
| ST-054 | `form::tests::*` (proptest), fuzz `fuzz_form_urlencoded` |
| ST-043, ST-082, IMPL-RM2-015 | `multipart::tests::*` (proptest), `tests/flow.rs::upload_attacks`, `full_report_flow`; fuzz `fuzz_multipart_intake` |
| ST-071, IMPL-RM2-013 | `token::tests::origin_matrix`, `tests/http_security.rs::csrf_matrix` (incl. lead decision 2), `flow::pre_login_token_invalid_after_login`, `flow::cookieless_leave_needs_the_leave_token` |
| ST-065, IMPL-RM2-013 | `routes::tests::registry_complete_and_consistent`, `unknown_paths_are_not_routes`, `field_allow_lists`; `route_registry_deny_by_default` |
| ST-066, IMPL-RM2-014 | `session::tests::timers`, `capacity_evicts_longest_idle`; `token::tests::cookies_have_the_contract_attributes`; `wire_bytes::session_cookie_exact_wire_bytes` |
| ST-079, IMPL-RM2-017 | `ratelimit::tests::*`, `http_security::login_rate_limit_per_circuit` |
| ST-101 | `http_security::slowloris_head_deadline` |
| AT-042, IMPL-RM2-011 | `flow::login_uniform_status_size_and_floor` |
| AT-017, AT-018, A1 | `http_security::no_reflection_of_input`, `hygiene::handler_panic_is_the_fixed_500_page_and_logs_no_payload`, `form::tests::debug_is_redacted`, `hygiene::debug_is_redacted` |
| NET-012, NET-001 | `proxy::tests::*`, `http_security::proxy_line_required` |
| ST-003-like, SW-02..SW-26 | `flow::full_report_flow`, `extend_identity_and_discard`, `confirmation_attempt_limit` |
| SW-10..SW-12, SW-16 | `flow::login_inbox_and_leave` |
| SW-22, SW-27, SW-28 | `flow::passphrase_rotation` |
| 07 §13, A13, IMPL-RM2-020 | `flow::fail_closed_dependencies` |
| SW-30, 11a | `flow::safety_tips_and_static_pages` |
| IMPL-STD-007/013, ST-110 (part) | `tests/hardening.rs`, `hardening::tests::refuses_off_the_main_thread` |
| C-5, AUD-RM2-STO-29 | `tests/sto29_handover.rs`; sealer `tests/handover.rs` (`hand_over_fails_closed_without_a_commit_ack`, `copy_deadline_and_bundle_cap`), `handover::tests::*`; store `tests/staged.rs` (`staged_bundle_handover_roundtrip`, `staged_protocol_v2_and_shared_cap`, `staged_copied_ack_after_durable_copy`), `staged::tests::ack_encoding`; store `tests/pg.rs` (`pg_staged_ack_after_commit`, `pg_staged_stalled_commit_refused`, under `pg-test.sh`) |

## Required privileges (for the deploy owner)

**OS user and identity.**
- The service runs as `candor-web`, in its own uid (07 §4.1), with supplementary group membership as in `deploy/intake/systemd/candor-intake-web.service`.

**Files and sockets.**
- No file is opened after start. No writable path is needed. Landlock denies all filesystem access.
- Sockets:
  - `/run/candor/source-web/http.sock` is inherited from systemd (`FileDescriptorName=http`).
  - The service connects to `/run/candor/sealer/seal.sock` (group `candor-web`).
  - The store is reached through an `IntakeStore` client. The PG pool is 0 for the web (07 §11). The store IPC client is open item O-2.

**Network.**
- None: `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`, `IPAddressDeny=any`, `SocketBindDeny=any`.

**Memory.**
- `LimitMEMLOCK` ≥ the working set, `MemoryMax=1G`, `MemorySwapMax=0`, `LimitCORE=0`.

**Process setup.**
- `harden_process` needs `prctl`, `prlimit64`, `mlockall` and the three `landlock_*` calls. The shipped unit already allows them (`SystemCallFilter=seccomp landlock_*`).

**Syscalls used at run time** (tokio on Linux, x86_64/aarch64):

| Group | Syscalls |
|---|---|
| Sockets | `accept4`, `connect`, `socket` (AF_UNIX only), `shutdown`, `getsockopt`, `setsockopt` |
| I/O | `read`, `write`, `readv`, `writev`, `recvfrom`, `sendto`, `recvmsg`, `sendmsg`, `close`, `fcntl`, `ioctl` (FIONBIO) |
| Event loop and threads | `epoll_create1`, `epoll_ctl`, `epoll_wait`/`epoll_pwait`, `eventfd2`, `futex`, `sched_yield`, `nanosleep`, `clock_nanosleep`, `clone3`/`clone`, `set_robust_list`, `rseq`, `exit`, `exit_group` |
| Time and randomness | `clock_gettime`, `getrandom` |
| Memory | `mmap`, `munmap`, `mremap`, `madvise`, `mprotect` (no `PROT_EXEC`), `brk` |
| Signals | `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `sigaltstack` |
| Ids | `gettid`, `getpid` |

The baseline `@system-service` minus the listed groups in the shipped unit covers these.
- `execve`, `ptrace`, `socket(AF_INET*)`, `open*` (after start) and `bind` are never needed.

**Not needed.**
- No capabilities and no `/proc` access (`ProtectProc=invisible` is fine).
- No `RUST_BACKTRACE`. Release builds use `panic = "abort"`.

## Security self-review (working tree on f18422c + this change, 2026-10-01; OWASP ASVS 5.0 L3 mindset)

- **Metadata (A1).** Checked sinks: logs, errors, panics, metrics, Debug, temp files, fixtures and crash paths.
  - There is no log call except the panic hook's static `diag!`.
  - Error types are code-only (`Fail`, `FormError`, `MultipartError`, `HeadError`, `SealerError`, `ConfigError`). `Debug` of `Form`, `RequestHead`, `Reply`, `PartHeader`, `Event`, the sessions, keys and the limiter is redacted.
  - The `User-Agent`, `Accept-Language`, `Referer` and every unknown header are syntax-checked and dropped.
  - Paths are never echoed. The 404 page is static.
  - The circuit id is replaced by a keyed token at once.
  - Days come only from `DayClock`; there is no wall clock.
  - Tests: `no_reflection_of_input` (UA, path, header, cookie and field canaries); `handler_panic_is_the_fixed_500_page_and_logs_no_payload`.
- **Network.** The only runtime connections are the accepted Unix stream and the connect to the sealer's Unix socket. There is no TCP code path (the API takes a `UnixListener`), and Landlock denies TCP.
- **Fail-closed.** See the table above. A sealer or store error never leads to local storage, an alternative path or partial release. A seal error renders "not sent", and the draft stays in the sealer.
- **Input bounds.** Every input in the limits table is bounded before allocation:
  - the head buffer is pre-sized at 16 KiB plus the PROXY line;
  - the form body is checked against `Content-Length` and the limit before reading;
  - the multipart buffer has a fixed capacity, and `feed` refuses growth;
  - upload chunks are ≤ 64 KiB.

  The parsers do no recursion, use checked or saturating arithmetic and no indexing on input. Clippy runs with the workspace deny set, `arithmetic_side_effects` and `indexing_slicing` as errors. Coverage: property tests for every parser, three fuzz targets, the smuggling corpus, and 200 random garbage requests (`garbage_does_not_kill_the_service`).
- **Secrets.**
  - Kept only in zeroizing types: `cs`, `h`, session tokens, pre-session tokens, the piece key, passphrases and words.
  - Comparisons are constant-time (`subtle`, `ct_eq`).
  - Passphrases are forwarded once and dropped. S10 words are dropped after the render. Page bodies are zeroized on drop (source-ui).
  - `Debug` is redacted on every type that holds a secret.
  - **Residual:** tokio socket buffers, kernel buffers and moves are outside zeroize's reach (IMPL-00 §5); `mlockall` keeps them out of swap.
- **Privileges.** See the section above; it matches `deploy/intake/systemd/candor-intake-web.service` except for the open item on socket activation glue.
- **Side channels.**
  - Size: the class depends only on the method and the cookie, every response is exactly the class size, and the head is exactly 2,048 B (`wire_bytes`).
  - Timing: login, rotation and inbox POSTs use floor plus jitter on every outcome. Login does the same work for unknown accounts (dummy key). The inbox always opens 32 entries. All busy causes give the same page.
  - Existence: there is no account-existence branch before the floor.
  - **Residual:** GET `/inbox` and `/conversation` have no floor. Real versus dummy `OPEN_REPLY` work differs by HPKE decapsulation (tens of µs), which is far below Tor jitter.
- **Dependencies.** One is new: `httparse =1.10.1`, approved by the lead, with no dependencies of its own. It is covered by a deny allow-list entry and a vet exemption. Everything else is a workspace pin. A vet policy entry for this crate has been added.
- **IMPL-RM2 §4 checklist.**

  | Item | Status |
  |---|---|
  | A1 | above |
  | A2 | no outbound connection except the sealer socket |
  | A3 | no plaintext beyond request buffers |
  | A5 | uniform |
  | A6 | bounded, fuzzed |
  | A7 | one `__Host-` cookie, no expiry, `cs` never stored, new `cs` at login and new report |
  | A8 | CSRF on every POST, GET side-effect-free, registry complete (test) |
  | A9 | exact headers via source-ui, no script, no compression, no `Server` |
  | A13 | fail-closed |
  | A4, A10–A12, A14, A15 | other components (A14 partly: `harden_process`) |

- **Residual risks.**
  1. Tier W trusts the server (ADR-004).
  2. Per-circuit windows longer than 10 minutes are approximate.
  3. The pre-session token can be replayed within 15 min by someone holding the same `__Host-cpre`. A leave token can be replayed within 15 min, but it only renders the Leave page, without a cookie and without changing state.
  4. The fallback page has a fixed all-zero token, so its forms cannot succeed.
  5. A handler panic in a release build aborts the process, which systemd restarts. In-flight drafts survive in the sealer.
  6. An upload holds one connection slot only while it keeps ≥ 1 KiB/s on average after a 30 s grace; uploads can take at most 128 of the 512 slots, one per session. Unfinished request heads still hold a slot for up to 10 s each (07 §11 head timeout) before any limiter runs; tor's `HiddenServiceMaxStreams` and PoW defences (16) carry that.
  7. Leave tokens: a flood of more than about 73 cookie-clearing renders per second for 15 min evicts older nonces from the 65,536-entry set; an evicted source's cookieless Leave then gets the uniform error page (no state is involved). A Leave with any session cookie is unaffected (decision 5).
  8. The SEA-01 idempotency record lives in store RAM. After a store restart between a commit and the sealer's retry, the retry is still accepted on the group digest alone, without the extra bundle-hash binding.

## Fixes for AUD-RM2-WEB (C-06 audit, 2026-10-01; lead decisions binding)

| Finding | Fix | Tests |
|---|---|---|
| WEB-01 (Medium) plaintext in view models | Every source-ui model field carrying source or team text, identity data, file names or descriptions, or the form token is `Zeroizing<String>` (coordinated source-ui change); C-06 fills them straight from `SecretText` without plain copies; the rendered page body and the reply are zeroizing and dropped after the write. | source-ui `tests/zeroizing_fields.rs` (types pinned at compile time and in `model.rs`; all six screens render from them); `hygiene::exposed_secrets_are_copied_only_into_zeroizing_buffers` (source lint) |
| WEB-02 (Medium) quadratic multipart scan | Carried scan offset; per-request work budget; same for the head reader. Decision 16. | `multipart::tests::one_byte_feeds_are_linear` (PoC), `work_budget_fails_closed`; fuzz `fuzz_multipart_intake` |
| WEB-03 Leave with stale cookie → 500 | Leave page with `Clear-Site-Data`. Decision 5. | `flow::leave_with_stale_cookie_is_the_leave_page` |
| WEB-04 leave token = 5-min time beacon | Random nonce + MAC, bounded expiring server-side set, no time in the token. Decision 5. | `token::tests::leave_tokens_are_unlinkable` |
| WEB-05 starvable buckets | Remainder-carrying refill; spend only when all buckets allow. Decision 10. | `ratelimit::tests::trickle_does_not_starve_refill`, `refusal_spends_nothing_globally` |
| WEB-06 floor anchored at accept | Floor from the end of the full request; jitter always after `max(floor, work)`. Decision 7. | `flow::login_floor_from_full_request`, `app::floor_tests::*` |
| WEB-07 cheap slot pinning | Rate floor and size-scaled deadline for uploads; 128 uploads service-wide, 1 per session. Decision 16. | `flow::one_upload_per_session`, `server::tests::upload_deadlines_follow_the_minimum_rate` |
| SEA-01 unknown commit outcome | Sealer retry on a fresh connection; idempotent replay in the store; `NoReply` → "could not confirm" wording. Decision 25. | see decision 25 |
| WEB-08 (Info) size before CSRF | Reported after the token part. Decision 16. | `flow::oversize_upload_reported_after_csrf` |
| STO-30 (Info) orphans fill the in-flight cap | Active blobs (64) and blobs awaiting the sweep (256) are bounded separately (store `staged.rs`). | store `staged_orphans_do_not_block_new_hand_overs` |
| WEB-09 (Info) | Nothing to fix. | — |
| WEB-10 (Info) httparse | Documented: open item O-7. | — |

## Open items

Deferred by the lead to the **next build step**:
- **O-1.** SW-14 reply deletion and SW-15 close mailbox need `SEAL_SIGNAL` in the sealer and a store-side deletion op that holds K31 (an `istore` IPC op). Until both exist, both actions return the uniform error page and nothing is half-deleted.
- **O-2.** The `istore` IPC client: a production `StoreReads` over `istore.sock`, and the sealer's `EnvelopeSink` that carries the inline objects and rows next to `hand_over_group_bundle`. The store crate owns the protocol; this crate depends only on the trait.
- **O-3.** The systemd socket-activation binary: take the listener from `LISTEN_FDS` (needs `candor-memlock`, the only crate allowed `unsafe`), then call `install_panic_hook`, `harden_process(Required)` and a periodic `reap()`.

Still open:
- **O-4.** Not implemented: draft-preserving re-authentication (11 §5.6), S08 invisible-character normalisation, the HIGH-profile rotation offer per login, and pseudo-locales in production (only `en`).
- **O-6.** Deploy owner: nothing checks yet that the blob volume sustains `MIN_COPY_RATE` (50 MB/s), which the STO-29 copy deadline assumes (decision 25).

- **O-7.** `httparse` (AUD-RM2-WEB-10): a cargo-vet audit of 1.10.1 is due before its exemption expires on 2027-03-30; its parser core contains `unsafe` pointer code on the source-facing path. The repository has no cargo-geiger baseline yet; add `httparse` to it when one is created (release-supply-chain).

Resolved: O-5 (decisions 1, 2 and 4 were decided by the lead on 2026-10-01 and are implemented as described above).
