# 07 — Backend Services

Status: Draft v1.2 (round-3 consistency pass: ADR-047; revision round 2: ADR-034..046) · Edition applicability: both (EE-only items marked **EE**) · Owner: Backend team

## 1. Purpose and scope

This document specifies how the server-side Rust services defined in 06-SYSTEM-ARCHITECTURE.md are built and run. It covers:
- process model and OS sandboxing;
- modules and their internal protocols (sealer IPC, relay pull);
- job queues;
- the configuration model;
- error handling;
- the typed logging API;
- the safe-path API;
- resource limits;
- time handling;
- failure behavior.

Wire formats of the external APIs are in 08-API.md, and schemas in 09-DATABASE.md. Cryptographic constructions are referenced from 04-CRYPTOGRAPHY.md and not redefined here.

## 2. Context and dependencies

| Document | Relationship |
|---|---|
| DECISIONS.md ADR-004/005/009/010/016/019/026/027/028/029, ADR-033, and ADR-034..046 (revision ADRs; supersede conflicting earlier text) | Binding decisions implemented here |
| 11-FRONTEND-SOURCE.md §5.3–§5.6 | Canonical Source Web page contract (headers, P1/P2 size classes, cookie) implemented by `candor-web` |
| 24-LICENSING-BUSINESS-MODEL.md §TEL | Canonical metrics regime for SOURCE-SENSITIVE counters (§9.5) |
| 06-SYSTEM-ARCHITECTURE.md | Service boundaries §6, trust boundaries §7, segmentation §10 |
| 08-API.md | External contracts served by these modules |
| 09-DATABASE.md | Intake Store and Case DB schemas, job table, RLS |
| 04-CRYPTOGRAPHY.md | Envelope, STREAM, source KDF, signing formats (via C-11) |
| 15-AUTHENTICATION-AUTHORIZATION.md | Policy semantics evaluated by the C-22 integration |
| 20-LOGGING-AUDITING.md | Event classes, audit schema and prohibited fields |
| 32-OPERATIONS.md | CFG- identifiers and operational runbooks for configuration classes |
| 34-PERFORMANCE-SCALABILITY.md | Capacity targets behind §11 limits; FAIL- behaviors |

## 3. Workspace and crate layout

| Crate | Kind | Trust path | Purpose |
|---|---|---|---|
| `candor-core` (C-11) | lib | yes | HPKE/X-Wing, AEAD, STREAM, KDF, signatures, `Secret<T>` types |
| `candor-log` | lib | yes | Typed logging and event API (§9) |
| `candor-safefs` | lib | yes | Safe-path and file API (§10) |
| `candor-types` | lib | yes | ID newtypes (`OpaqueId<Kind>`), `EpochDay`, `SizeBucket`, error codes |
| `candor-ipc` | lib | yes | SEQPACKET framing, CBOR codecs, peer-credential checks |
| `candor-web` | bin | yes | C-06 |
| `candor-sealer` | bin | yes | C-07 |
| `candor-intake-store` | bin | yes | C-08 daemon and relay export endpoint |
| `candor-relay` | bin | yes | C-09 |
| `candor-case` | bin | yes | C-10 + C-22 + SLA engine + Desk/Admin/Export routers |
| `candor-auth` | bin | yes | C-21 |
| `candor-keydir` | bin | yes | C-14 |
| `candor-notify` | bin | yes (because it enforces content-free output) | C-23 |
| `candor-audit` | bin | yes | C-24 |
| `candor-worker` | bin | yes | Job runner for Z-CORE |
| `candor-health` | bin | yes | C-25 agent and collector |
| `candor-backup` | bin | yes | C-27 agent |
| `candorctl` | bin | yes | Admin CLI (C-19) |
| `candor-ee-siem`, `candor-ee-fleet-agent`, `candor-ee-connectors` | bin | **no** (EE, ADR-020) | May depend on `candor-types` and `candor-log` only. They MUST NOT depend on `candor-core` private-key APIs. |

Build profile for all trust-path binaries:
- `panic = "abort"`, `overflow-checks = true`, `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"` (split debug info kept offline for reproducibility checks);
- PIE, full RELRO, `-Z` flags not used (stable toolchain pinned in `rust-toolchain.toml`);
- `#![forbid(unsafe_code)]` in all crates except `candor-core` (FFI to `aws-lc-rs`), `candor-ipc` (`SO_PEERCRED`), `candor-safefs` (`openat2`) and `candor-sealer` (`mlockall`, `prctl`, `madvise`). Every `unsafe` block carries a `// SAFETY:` justification and is on the audit list (37-SECURITY-AUDIT-PLAN.md).

## 4. Process model

### 4.1 OS users and processes

| Service | OS user | Host | Groups / file access | Network | Memory lock | Core dumps |
|---|---|---|---|---|---|---|
| tor (C-05) | `debian-tor` | intake-gw | `/var/lib/tor` | Tor network egress | n/a | disabled |
| `candor-web` | `candor-web` | intake-gw | read: `/usr/share/candor/web` (templates, static), `/run/candor/config` (ro); socket dirs | **AF_UNIX only** | `mlockall` of heap (Tier W buffers) | disabled |
| `candor-sealer` | `candor-sealer` | intake-gw | read: `/run/candor/config` (ro), `/run/candor/directory` (ro); socket `/run/candor/sealer/seal.sock` | **none** (`PrivateNetwork=yes`) | `mlockall(MCL_CURRENT\|MCL_FUTURE)` | disabled + `PR_SET_DUMPABLE=0` |
| `candor-intake-store` | `candor-istore` | intake-gw | rw: `/var/lib/candor/intake/blobs`, `/run/candor/staging` (tmpfs, ADR-034); PG via Unix socket | TCP 7443 listen on relay interface only | no | disabled |
| PostgreSQL (intake) | `postgres` | intake-gw | `/var/lib/postgresql` | Unix socket only (`listen_addresses=''`) | no | disabled |
| `candor-relay` | `candor-relay` | core | PG role `candor_relay`; blob store write | TCP to intake 7443 only (nft `skuid`) | no | disabled |
| `candor-case` | `candor-case` | core | PG role `candor_case`; blob store rw | Unix listeners (desk.sock, admin.sock) or TCP 8443/9443 | no | disabled |
| `candor-auth` | `candor-auth` | core | PG role `candor_auth`; TPM/HSM access group | Unix socket only | yes (session signing keys) | disabled |
| `candor-keydir` | `candor-keydir` | core | PG role `candor_kd` (append-only) | Unix socket; outbound witness HTTPS (optional, via egress proxy) | no | disabled |
| `candor-notify` | `candor-notify` | core | PG role `candor_notify` | egress to allow-listed SMTP/HTTPS only | no | disabled |
| `candor-audit` | `candor-audit` | core | DB `candor_audit` role `candor_audit_w` (INSERT only); checkpoint key via TPM/HSM | Unix socket only | yes | disabled |
| `candor-ekv` | `candor-ekv` | core | rw `/var/lib/candor/ekv` (0700); TPM/HSM access for the Vault Master Key | Unix socket only (`/run/candor/ekv/ekv.sock`, peers `candor-case`, `candor-worker`) | yes | disabled |
| `candor-worker` | `candor-worker` | core | PG role `candor_worker` | calls local services via Unix sockets | no | disabled |
| `candor-health` agent | `candor-health` | all | read-only host facts; no application data dirs | TCP 8514 to the collector over the dedicated monitoring interface (the collector host has no clearnet egress; 06 §8.5) | no | disabled |
| `candor-backup` | `candor-backup` | core | read DB via `pg_basebackup` role `candor_backup`; read blobs | TCP 443/22 to backup store only | no | disabled |

Notes:
- Each binary runs as its own user. No two services share a UID, and no service runs as root after start.
- Socket permissions: each `/run/candor/<svc>/` directory is `0750`, owned by the server user, with group set to the single permitted client user.

### 4.2 systemd hardening baseline (all Candor units)

```ini
[Service]
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes
UMask=0077
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount @debug @cpu-emulation @obsolete @raw-io @reboot @swap @module
SystemCallErrorNumber=EPERM
LimitCORE=0
KeyringMode=private
DevicePolicy=closed
IPAddressDeny=any          # re-allowed per unit where a TCP peer is needed
StandardOutput=null        # trust-path output only via candor-log sink (§9)
StandardError=journal      # candor-log formatted codes only
```

Per-unit deltas:

| Unit | Additions |
|---|---|
| `candor-sealer` | `PrivateNetwork=yes`; `RestrictAddressFamilies=AF_UNIX`; `LimitMEMLOCK=2G`; `MemoryMax=2560M`; `MemorySwapMax=0`; `SystemCallFilter=` narrowed to the explicit allow-list in §4.3; `ReadOnlyPaths=/`; `ReadWritePaths=` (none); `InaccessiblePaths=/var/lib/candor /var/lib/postgresql /var/lib/tor` |
| `candor-web` | `RestrictAddressFamilies=AF_UNIX`; `MemoryMax=1G`; `MemorySwapMax=0`; `LimitMEMLOCK=1G`; `InaccessiblePaths=/var/lib/candor /var/lib/postgresql /var/lib/tor` |
| `candor-intake-store` | `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`; `IPAddressAllow=<core relay address>/32`; `ReadWritePaths=/var/lib/candor/intake` |
| `candor-relay` | `IPAddressAllow=<intake relay-link address>/32`; `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` |
| `candor-case` | `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` (RCP-LAN) or `AF_UNIX` (RCP-ONION) |
| `candor-auth`, `candor-audit` | `RestrictAddressFamilies=AF_UNIX`; `DeviceAllow=/dev/tpmrm0 rw` (when TPM-backed) |

### 4.3 Sealer seccomp allow-list

The sealer is additionally filtered by a `seccompiler` program installed in-process after initialization and before accepting the first connection. It allows only:

`read, write, recvmsg, sendmsg, accept4, close, epoll_wait, epoll_ctl, epoll_create1, futex, mmap (no PROT_EXEC), munmap, mremap, madvise, brk, rt_sigreturn, rt_sigprocmask, clock_gettime, getrandom, exit, exit_group, sched_yield, nanosleep, clock_nanosleep, restart_syscall, fstat, getsockopt (SO_PEERCRED only), mlock, munlock`

Any other syscall causes `SECCOMP_RET_KILL_PROCESS`. The kill is visible to the health agent as SYSTEM event `sealer.killed`. `openat` is absent: the sealer opens its config and directory snapshot files before the filter is installed and re-reads them only via restart on a config-change signal from systemd.

### 4.4 Memory handling and no-dump rules (C-07, C-06, C-21, C-24)

Host level (intake-gw, core):
- `kernel.core_pattern=|/bin/false`, `fs.suid_dumpable=0`, `kernel.yama.ptrace_scope=3` (intake-gw) or `2` (core);
- `systemd-coredump` masked; `vm.swappiness=0`.
- **Swap disabled on intake-gw.** On core, swap may exist only on dm-crypt with a random per-boot key.
- `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1`, `kernel.unprivileged_bpf_disabled=1`, `kernel.kexec_load_disabled=1`, `dev.tty.ldisc_autoload=0`.

Process level (sealer; web for its request buffers):
- `prctl(PR_SET_DUMPABLE, 0)` at start;
- `mlockall(MCL_CURRENT | MCL_FUTURE)`;
- `madvise(MADV_DONTDUMP | MADV_WIPEONFORK)` on secret arenas;
- secrets held only in `candor_core::Secret<T>` (heap, zeroize-on-drop, no `Clone`, `Debug` prints `[secret]`, no `Serialize`);
- plaintext stream buffers are fixed 64 KiB `SecretBuf` slabs from a pre-allocated locked pool of 4096 slabs (256 MiB). No growth beyond the pool, and requests wait or fail with `BUSY` when it is exhausted.

Session and draft material (ADR-034, single timer set):
- Tier W session material (draft text, identity block, per-session part key, part DEKs, derived source keys, seed) lives only in sealer mlocked RAM and is zeroized on logout, idle timeout (20 min), absolute timeout (2 h), discard, or sealer restart. The web service drops its session entry and tells the intake store to delete the session's staged parts at the same moment.
- A **login** passphrase is zeroized immediately after derivation.
- A **newly generated** passphrase (S10) is held in sealer RAM only between `GEN_ACCOUNT` and `CONFIRM_PASSPHRASE`/`SEAL_FINISH`, and is zeroized then. It is never persisted, never re-displayable after the session, and never written to C-08 (ADR-034; RVW-B-13).

### 4.5 Supervisor behavior

| Condition | Action |
|---|---|
| Crash of any intake process | systemd `Restart=on-failure`, `RestartSec=2s`, `StartLimitBurst=5/60s`. After the burst the unit stays failed and the health agent raises `SYSTEM:service_failed`. Restarting the sealer drops all in-RAM drafts and sessions; `candor-intake-store` then empties `/run/candor/staging`. Sources see a generic "please retry" page, and S04/S06 already state that a restart loses drafts (ADR-034, accepted residual). |
| Below the signed security floor or Platform Manifest mismatch | Trust-path services refuse to start; `SECURITY:platform_mismatch` (ADR-040; BE-067) |
| Config bundle signature invalid | Service refuses to start (§7.4) |
| Schema version mismatch | Service refuses to start |

## 5. Modules

### 5.1 Intake web (`candor-web`, C-06)

| Submodule | Specification |
|---|---|
| HTTP stack | `hyper` 1.x server (HTTP/1.1 only on the onion socket; HTTP/2 disabled to reduce parsing surface; no pipelining: one in-flight request per connection, `Connection: close` after error). Request line ≤ 4 KiB; total headers ≤ 16 KiB; ≤ 50 headers. No compression, either inbound (`Content-Encoding` rejected) or outbound. |
| Router | Deny-by-default registry. Each route is declared with `route!{ method, path, audience, auth, csrf, pad_class, body_limit, handler }`. A CI test (`route-registry-lint`) fails if any handler is reachable without a declaration, or if any declaration lacks `audience` or `auth` (ADR-029). The audience is `source-web` or `source-app`, and paths are prefixed `/app/v1/` for the latter. |
| Multipart parser | In-house streaming parser (no framework auto-parse; INC-107). Allowed part names come from the route declaration. The first unexpected part aborts with 400 before any byte is forwarded. Per-part header ≤ 1 KiB. Filename ≤ 255 bytes, UTF-8, NFC-normalized, and then treated as **encrypted metadata only** (never a path). Max parts per request: 3 (message text, one file, CSRF token). |
| Templates | `askama` compile-time templates with auto-escaping. There is no raw-HTML filter in the template set (a CI grep bans `|safe` and `PreEscaped`). There are no inline scripts. CSS is inline in one `<style>` element pinned by hash in the CSP (11 §5.3); there are no sub-resources (the former `/static/<sha256>.css` route is withdrawn, RVW-A-21). |
| Sessions | In-RAM map `SessionId(128-bit random) → SessionState`. Max 10,000 sessions. One timer set: idle 20 min, absolute 2 h (ADR-034). The cookie is `__Host-s` (Secure; HttpOnly; SameSite=Strict; Path=/), as defined in 11 §5.6. No persistent state. A restart logs everyone out. |
| CSRF | Synchronizer token (256-bit) per session per form, verified in constant time. Also: `Origin` must be absent, `null`, or equal to this onion origin. |
| Rate limiting | Token bucket keyed by `EphemeralCircuitToken` (06 §11), in RAM only, plus global buckets. Values in §11. |
| Padding | The response body is padded to the route's `pad_class` ∈ {P1 = 65,536, P2 = 131,072 bytes} exactly as 11 §5.4 defines. Headers are fixed-order, fixed-set. |
| Headers | Fixed set per 11 §5.3 (single CSP string). No `Server`, `Date`, `ETag` or `Last-Modified`. |
| Tier V validator | Validates canonical envelope CBOR (04-CRYPTOGRAPHY.md): exact field set and lengths, size bucket membership, and exactly 16 fixed-size anonymous recipient slots (ADR-030, ADR-033 §1). The server cannot and does not check recipients: slots carry no key IDs, and the signed recipient list is inside the AEAD payload. It never inspects ciphertext. |

### 5.2 Sealer IPC protocol (`candor-web` ↔ `candor-sealer`)

**Transport and framing:**
- `AF_UNIX`, `SOCK_SEQPACKET`; one datagram = one message; max datagram 128 KiB (fits a full `DRAFT_SET` of 96 KiB plus framing).
- The sealer checks `SO_PEERCRED.uid == uid(candor-web)` on accept and closes otherwise.
- Message = deterministic CBOR map `{ "v": 1, "op": u8, "rid": u32, "body": map }`.
- Responses echo `rid`.
- Unknown `op`, extra keys or oversize fields produce `ERR{code}` and close the connection.

**Operations** (revised for ADR-034, ADR-036(4), ADR-037, ADR-046(7)):

| op | Name | Request body | Response body | Limits / notes |
|---|---|---|---|---|
| 0x01 | `HELLO` | `{proto: 2}` | `{proto: 2, snapshot_version: u64}` | First message on every connection |
| 0x02 | `SESSION_OPEN` | `{sess: [u8;16], channel_id}` | `{}` | Creates a RAM-only drafting session and a random per-session part key `K_sp` (= 04-CRYPTOGRAPHY.md K36; never leaves the sealer). Nothing is written anywhere. |
| 0x03 | `DRAFT_SET` | `{sess, fields: map<u16, text> (≤ 96 KiB total), identity?: text ≤ 4 KiB, coi: {excluded_labels: [u16] ≤ 16, categories: [u16] ≤ 8} \| null, lang}` | `{}` | Replaces the RAM draft. Draft text, identity block and COI ticks live only here, including on every error path (ADR-034; RVW-A-02). `identity: null` zeroizes a previous identity block. |
| 0x04 | `DRAFT_GET` | `{sess}` | `{fields, identity?, coi, parts: [{part, size_bucket}]}` | For re-rendering forms; never includes staged ciphertext |
| 0x10 | `GEN_ACCOUNT` | `{sess}` | `{words: [u16;10], confirm_positions: [u8;3]}` (EFF large list indices) | Called at S09 Submit only (after drafting). Generates the seed with `getrandom`, keeps the words and seed in RAM until confirmation, and picks 3 random positions for the confirmation step (ADR-034). |
| 0x11 | `LOGIN_DERIVE` | `{sess, passphrase: bytes ≤ 256}` | `{locator_hash: [u8;32]}` | Argon2id (m = 64 MiB, t = 3, p = 1, per-deployment salt; FIPS profile PBKDF2-HMAC-SHA-512, 210,000 iterations; ADR-046(7)). Global concurrency 4 (semaphore). Queue ≤ 32. Queue wait ≤ 30 s, else `BUSY`. |
| 0x12 | `LOGIN_SIGN` | `{sess, challenge: [u8;32]}` | `{sig: [u8;64]}` | Ed25519 signature by the source auth key over `"candor-src-auth-v1" ‖ tenant_id ‖ challenge` |
| 0x13 | `LOAD_PREFS` | `{sess, prefs_ct: bytes ≤ 4 KiB}` | `{}` | After successful login. Decrypts the source's own preferences (fields of 04-CRYPTOGRAPHY.md §11.4: `kdf_version`, per-report `mailbox_id`, **original eligible set**, roster version, UI preferences; ADR-036(4)) under `K_prefs`, in RAM. `prefs_ct` never contains COI ticks (RVW-A-03) or the wordlist/UI language (ADR-047(6)). |
| 0x14 | `CONFIRM_PASSPHRASE` | `{sess, words: [u16;3]}` | `{ok: bool, confirm_positions?: [u8;3]}` | Constant-time compare against the 3 chosen positions. On failure, new positions are drawn; after 5 failures the draft and passphrase are zeroized. Success is required before `SEAL_FINISH` for a new account (ADR-034). |
| 0x15 | `ROTATE_PASSPHRASE` | `{sess}` (AUTHENTICATED, current passphrase re-verified by web via `LOGIN_DERIVE`) | `{words: [u16;10], confirm_positions}`; after `CONFIRM_PASSPHRASE`: `{account: {locator_hash, auth_pk, xwing_pk, prefs_ct}, reencrypted_replies: [bytes], key_update_envelope}` | ADR-046(7). Re-encrypts pending replies to the new X-Wing key in RAM and seals a key-update follow-up (new reply public key, signed by old and new `sign_sk`) to the original eligible set. Bounds past captures only; a live compromise sees both passphrases (06 R-1). |
| 0x20 | `PART_BEGIN` | `{sess, part_kind: message\|file}` | `{part: [u8;16]}` | Starts a part. Its DEK is derived as `HKDF(K_sp, part)` and kept in RAM. **No recipient wraps are created here** (RVW-A-07). |
| 0x21 | `SEAL_CHUNK` | `{part, data: bytes ≤ 65536, last: bool}` | `{ct: bytes}` | STREAM chunk encryption under the part DEK. Plaintext slab zeroized after encryption. The web forwards `ct` to the intake store's tmpfs staging (§5.3) after padding the final part to its ADR-011 bucket (ADR-038(5)). |
| 0x22 | `SEAL_FINISH` | `{sess, parts: [part], meta: {filenames: [text ≤ 255]}, delayed_delivery: bool}` | `{header_ct (16 anonymous fixed-size HPKE slots, random order, no key IDs), manifest_ct (per-part DEKs, display names, draft text as the message part, `thread_tag`, reply public key, signed recipient list of key IDs + directory tree head; 04-CRYPTOGRAPHY.md), message_part_ct (the RAM draft text and identity block, padded to its ADR-011 bucket and STREAM-encrypted; identity block sealed to Identity Custodian keys, ADR-014), release_offset_days: 0..3, account: {locator_hash, auth_pk, xwing_pk, prefs_ct} \| null}` | **The only step that seals to recipients** (ADR-034). Computes the eligible set from the verified snapshot **now**: (initial) the channel's **Triage Set** minus source-ticked role labels minus COI-map exclusions for the final category, restricted to entries whose `effective_day` ≤ today and to members with a Member Epoch Key valid today (ADR-030, ADR-036(2), ADR-037(1)); (follow-up) the original eligible set from `prefs_ct` ∩ current active members (ADR-036(4)). Generates the content key, wraps it into the 16 slots, and zeroizes `K_sp`, the DEKs and the draft. Refuses with `NO_ELIGIBLE_TRIAGE` (with the channel's `alternative_channel_id`) when fewer than 1 eligible Triage Set member remains. For a new account, requires a prior successful `CONFIRM_PASSPHRASE`. `account` is non-null only for a new account. The response also carries `disposition_ct` (real marker to K41, ADR-047(3)); a successful seal cancels the next scheduled chaff event of the channel (§5.2a). |
| 0x25 | `NOTE_REAL` | `{channel_id, first_object_hash}` | `{disposition_ct}` | Called by the web for every validated **Tier V** upload before `COMMIT_ENVELOPE`: returns the real-kind `disposition_ct` and cancels the next scheduled chaff event of the channel (ADR-047(3)) |
| 0x26 | `SEAL_SIGNAL` | `{sess (AUTHENTICATED), kind: no_response \| mailbox_closed}` | `{envelope (SOURCE_MESSAGE kind 2/3), disposition_ct, release_offset_days}` | C4 "no response" escalation (release U{1,2,3} days) and mailbox-closed signal (release U{3..21} days), sealed to the original eligible set's MEKs of the epoch containing the release day (04 §13.4; 14 CASE-017/CASE-035; RVW-B-26). `mailbox_closed` is sealed **before** the account deletion in SW-15. |
| 0x23 | `SEAL_ABORT` | `{sess}` | `{}` | Drops the draft, `K_sp` and part DEKs; the web deletes the staged parts |
| 0x24 | `PART_DROP` | `{sess, part}` | `{}` | Removes one part (SW-07); the web deletes its staged ciphertext |
| 0x30 | `OPEN_REPLIES` | `{sess, cts: [bytes ≤ 70000] ≤ 64}` | `{pts: [bytes]}` | Decrypts with the source X-Wing key. Plaintext returned for immediate rendering. |
| 0x31 | `SEAL_SOURCE_MESSAGE_ACK` | — | — | Reserved; not implemented (no read receipts, ADR-010) |
| 0x40 | `ZEROIZE` | `{sess}` | `{}` | Idempotent |
| 0x7F | `STATUS` | `{}` | `{sessions_band: u8, argon_queue_band: u8, pool_free_band: u8}` | SYSTEM metrics as coarse bands; exported off-host only as the global daily health band (ADR-038(5); BE-073) |

WITHDRAWN: `SEAL_BEGIN` (0x20 in v1), which computed the eligible set on the first part and sealed parts before the recipient set was final (RVW-A-07).

**Error codes:** `BAD_FRAME`, `UNKNOWN_SESSION`, `BUSY`, `NO_ELIGIBLE_TRIAGE`, `NOT_CONFIRMED`, `LIMIT`, `CRYPTO`, `INTERNAL`. Errors carry no other data except `alternative_channel_id` on `NO_ELIGIBLE_TRIAGE`.

**Session state machine (per `sess`):**

```
NONE -> DRAFTING (SESSION_OPEN) -> PENDING_CONFIRM (GEN_ACCOUNT) -> COMMITTED (CONFIRM_PASSPHRASE ok, SEAL_FINISH ok, COMMIT_ENVELOPE fsynced) -> AUTHENTICATED
NONE -> DERIVED (LOGIN_DERIVE) -> AUTHENTICATED (LOGIN_SIGN ok, confirmed by web) -> DRAFTING (follow-up) -> AUTHENTICATED
AUTHENTICATED -> PENDING_CONFIRM (ROTATE_PASSPHRASE) -> AUTHENTICATED (CONFIRM_PASSPHRASE ok)
any  -> NONE (ZEROIZE | SEAL_ABORT | idle 20 min | absolute 2 h | restart)
```

### 5.2a Chaff generator (in `candor-sealer`; ADR-047(3); 04-CRYPTOGRAPHY.md §12.7)

- One Poisson schedule per channel with mean `intake.chaff.mean_interval` (default 2 h), exponential inter-arrival times from the CSPRNG, kept only in sealer RAM on the monotonic clock; a restart draws a fresh schedule.
- At each event the sealer builds a chaff envelope with the same C-11 functions as a real one (shape: initial triple or follow-up with probability `intake.chaff.followup_share`, sizes from the fixed public chaff bucket distribution, 16 dummy slots, current epoch, chaff-kind `disposition_ct`) and commits it through the store's `COMMIT_ENVELOPE` over its own socket (`/run/candor/istore/istore-sealer.sock`, peer = `candor-sealer`), with `account = null` and `release_offset_days = 0`. The store treats both peers identically and writes nothing that records the peer.
- Every real commit (Tier W `SEAL_FINISH`/`SEAL_SIGNAL`, Tier V `NOTE_REAL`) cancels the channel's next scheduled chaff event, so the write process stays Poisson while real traffic is below the chaff rate.
- Chaff is never counted in `counter_month` (counters are incremented only on real commits) and never appears in `STATUS` bands.
- Staging and disk: chaff writes count against the intake disk reserve; if the reserve is reached, chaff pauses before real envelopes are refused (SYSTEM warn).

### 5.3 Intake store (`candor-intake-store`, C-08)

- **IPC to web** (`/run/candor/istore/istore.sock`, SEQPACKET, peer = `candor-web`). Operations:
  - `STAGE_PART(sess_ref, part, ct_chunk)`, `DROP_STAGED(sess_ref, part?)`: write or delete ciphertext in the tmpfs staging area (below);
  - `COMMIT_ENVELOPE(account?, envelope, disposition_ct, staged parts, release_offset_days)` (peers `candor-web` and, for chaff, `candor-sealer`): moves staged ciphertext into the blob directory, inserts rows, `fsync`s blobs, rows and directory entries, and only then returns `ok` so that the source is shown "received" (ADR-046(1));
  - `ACCOUNT_AUTH_CHALLENGE(locator_hash)`, `ACCOUNT_AUTH_VERIFY(locator_hash, challenge, sig)` (Tier W only);
  - `MAILBOX_LIST(account)`, `MAILBOX_GET`, `MAILBOX_DELETE`, `ACCOUNT_DELETE`, reply deletion (each appends a K31-signed entry to the intake **deletion list** in the same transaction; ADR-047(9); 09 `deletion_list`), `ACCOUNT_ROTATE` (Tier W only);
  - `REPLY_INDEX`, `REPLY_PAGE(n)` (fetch-all published set, ADR-039);
  - `UPLOAD_CREATE`, `UPLOAD_CHUNK`, `UPLOAD_STATUS` (Tier V; 08-API.md §5.1).
  - All take and return typed CBOR. The store never receives plaintext.
- **Staging area (ADR-034):** `/run/candor/staging` is a tmpfs (`mode=0700,uid=candor-istore,nosuid,nodev,noexec,size=${intake.tierw_staging_bytes}`; swap is disabled on intake-gw, BE-004). It holds only ciphertext under per-session keys that exist only in sealer RAM. Files are named by random 128-bit IDs via `candor-safefs` (`RootPolicy::Staging`). The session reference used to group them is a random value from the web session, not an account. Staged parts are deleted on `DROP_STAGED`, at session end (the web calls `DROP_STAGED` on logout, timeout or abort), and on restart (tmpfs is emptied). When the staging area is full, uploads get the busy page.
- **Uniform challenge:** `ACCOUNT_AUTH_CHALLENGE` returns a fresh 32-byte challenge whether or not the locator exists. For unknown locators, verification later fails with the same error and timing class (§11). This resists account enumeration.
- **Blob layout:**
  - `/var/lib/candor/intake/blobs/<2-char prefix>/<26-char base32 object id>`, created through `candor-safefs` with `O_CREAT|O_EXCL`, mode 0600.
  - Object IDs are random 128-bit. File names never derive from source input.
  - Blob files are written with `O_DIRECT` disabled but `fdatasync` on commit; mtime/atime set to 00:00 UTC of `received_date` (09 §5.1).
- **Delayed delivery (ADR-038(4)):** `COMMIT_ENVELOPE` sets `release_day = received_date + release_offset_days` (the sealer draws U{1,2,3} when the source opted in, else 0). The relay claim offers only envelopes with `release_day ≤ today`.
- **Published reply set (ADR-039):** `REPLY_INDEX` / `REPLY_PAGE` serve every non-expired reply (≤ 30 days) in pages of exactly 64 entries padded to 70,000 bytes, with the page count padded to the next power of two with dummy pages. Pages are rebuilt once per import slot (when replies arrive), so `set_version` changes only at slot times.
- **Relay export endpoint:** rustls TLS 1.3 server on the relay-link interface, TCP 7443. It requires a client certificate equal to the pinned relay certificate (SPKI SHA-256 pin from the signed config) and verifies Ed25519 request signatures (§5.4).
- **Routing key:** the Intake Routing Key private half is loaded from a systemd credential (`LoadCredentialEncrypted=`, TPM-sealed where available) and used only in `APPLY_REPLIES`. Replies whose account, mailbox or hash is in the deletion list are dropped.
- **Upload expiry:** Tier V uploads expire 24 h after creation, tracked in RAM with a monotonic clock (no time stored), and on restart (ADR-046(4)).
- **Local jobs:** the intake store runs its own job loop on the intake DB (§6.3).

### 5.4 Relay pull protocol (`candor-relay`, C-09 ↔ intake export)

**Authentication (each direction):**
- TLS 1.3 with mutually pinned Ed25519 certificates.
- Each request carries `Candor-Relay-Sig: ed25519(relay_key, method ‖ path ‖ sha256(body) ‖ req_counter)`.
- `req_counter` is a strictly increasing u64 persisted on both sides. Replays are rejected.

**Schedule (ADR-038(1); resolves RVW-A-09, RVW-B-06):** imports are **never event-driven**. The relay runs two in-process timers (no job rows):
- **Import slots** at fixed tenant-configured times (`relay.import_slots`, default 4×/day, e.g. 00:30, 06:30, 12:30, 18:30 UTC; HIGH/GOV profiles 1×/day). Only import slots claim envelopes, push replies and pull counters/backup snapshots.
- **Control cycle** hourly at a fixed minute: pushes directory snapshots and config bundles only (so that removals and revocations reach the sealer within ≤ 1 h, ADR-036(2)); it never claims.

**Import slot algorithm** (per intake instance; per tenant in EE):
```
at each fixed slot_start:
  1. GET  /relay/v1/health                     -> skip slot (retry at the next slot) if not "ok"
  2. POST /relay/v1/batches/claim {max_objects: 500, max_bytes: 2 GiB}   (repeat until empty or limits)
        -> {batch_no, objects:[{ref, channel_id, epoch_index, padded_size, sha256, disposition_ct}]}   (chaff and real identical)
  3. for each object: GET /relay/v1/batches/{batch_no}/objects/{ref}
        verify sha256 and canonical structure; stream blob to C-13 via candor-safefs;
        set blob mtime/atime = slot_start (utimensat); S3: versioning off
        stage import_envelope row with NEW random id (intake ref not stored),
        import_date = date(slot_start), epoch_index, import_batch_no; no kind, no received_date
  4. wait until slot_start + relay.slot_commit_offset (default 20 min), then COMMIT all staged rows of the slot
        in ONE transaction, together with the date-only automatic import audit events
        (if processing overran the offset: commit immediately and emit SYSTEM:relay_slot_overrun)
  5. POST /relay/v1/batches/{batch_no}/ack {sha256[] of committed envelopes}
  6. POST /relay/v1/replies           (≤ 500 sealed replies from reply_outbox per request, state→pushed on 200)
  7. GET  /relay/v1/counters          (first slot of a month: previous closed month, 24 §TEL)
  8. GET  /relay/v1/backup-snapshot   (first slot of the day: opaque blob encrypted to Backup Key)
  9. POST /relay/v1/deletions         (retention-driven reply purges only)
 10. GET  /relay/v1/deletion-list?after={seq}   (signed intake deletion list; verify chain + K31; insert into core.intake_deletion_list; ADR-047(9))
 11. after COMMIT: C-10 job `chaff_discard` opens `disposition_ct` of pending envelopes whose derived hold slot (1 + object_hash[0] mod 8) is this slot and deletes chaff rows and blobs (04 §12.7)
```
**Restore push-back (ADR-047(9)):** when an intake reports `restored` in RL-01 health (after a BS-INTAKE restore or an EE-HA failover to a recovered node), the relay pushes the Z-CORE copy of the deletion list (`POST /relay/v1/deletion-list`) in the next control cycle; the intake store refuses to serve source requests (C-06 shows the busy page) until the newest verified list has been applied (BE-074).
Consequence: Case DB WAL commit records, archived WAL, backups, C-13 blob mtimes and S3 `Last-Modified` reveal only the fixed slot, not arrival times (09 §8).

**Intake-supplied data is untrusted.** The relay accepts only:
- `channel_id` belonging to the intake's tenant;
- a header with exactly 16 fixed-size slots and no other cleartext recipient data;
- `epoch_index` within [current epoch − 3, current epoch] (14-day decrypt window plus the 3-day delayed-delivery maximum);
- `header_ct` ≤ 8 KiB, `manifest_ct` ≤ 64 KiB;
- parts ≤ 32, each padded size ∈ the bucket set.

Anything else is rejected, counted (SYSTEM) and left unacknowledged. After 3 failed slots it is quarantined.

**Idempotency:** a unique index on `import_envelope.header_digest` (SHA-256 of `header_ct`) prevents double import. The digest is retained ≤ 24 h and then nulled (ADR-039; 09-DATABASE.md).

**Backpressure:** if C-13 free space < 10 % or `import_envelope` pending > 50,000, the relay stops claiming and raises `SYSTEM:relay_backpressure`. Intake keeps buffering (06 R-8).

### 5.5 Case service (`candor-case`, C-10)

| Aspect | Specification |
|---|---|
| Routers | `desk`, `admin`, `export` (EE connector), each its own listener, audience and route registry (08-API.md) |
| Request pipeline | TLS/onion → audience + token verification (via `candor-auth` Unix call, cached ≤ 30 s per token) → tenant context bind (`SET LOCAL candor.tenant_id`, `candor.user_id`) → schema validation (serde `deny_unknown_fields`, explicit per-route DTOs, no generic "set attribute" operations; INC-112) → **authorization** (§5.6) → handler → audit emit (fail-closed) → response |
| Concurrency | Optimistic: every mutable row has `version BIGINT`. Mutations carry `If-Match: <version>`. A mismatch returns 409. |
| Idempotency | Mutating Desk endpoints take an `Idempotency-Key` (128-bit client-generated). Stored 24 h per user. A replay returns the stored status code. |
| Key-wrap verification | On case create, member add and re-key, the service verifies that the set of `recipient_key_id`s in the wraps is a subset of the candidate set returned by C-22 (DA-24) at that moment, covers ≥ `min_recipients` (default 2) distinct users (ADR-044(2)), and contains no user whose blinded COI tag the Desk-supplied tag check shows present (ADR-037(3)). Any extra wrap is rejected (THR-046). It verifies that each key is the current key-directory entry for the user. It cannot verify the ciphertext wraps themselves (no keys); Desk-side verification is in 12-FRONTEND-RECIPIENT.md. Before storing, each inner wrap is sealed under the case's Erasure Key by `candor-ekv` (§5.12; ADR-033 §3). On read, the caller's row is unsealed by `candor-ekv` and returned. |
| Blob I/O | Streaming to/from C-13 via `candor-safefs` (filesystem) or an S3 client (EE) with per-tenant prefix credentials. Max single object 4 GiB. |

### 5.6 Authorization engine integration (C-22)

- **Interface:** `fn authorize(p: &Principal, a: Action, r: &ResourceRef, ctx: &RequestCtx) -> Decision`.
  - `Decision = Permit { obligations: Vec<Obligation> } | Deny { reason: DenyCode }`.
  - `Obligation` examples: `RequireStepUp`, `RequireSecondApprover`, `AuditAs(CaseEventKind)`, `RedactField(FieldId)`.
- **Facts:** loaded per request inside the same DB transaction (role assignments, case ACL, Triage Set membership, blinded COI tag membership via `candor.coi_tag_present`, standing COI registry, grants, legal holds). C-22 never sees which user a case-level COI tag belongs to (ADR-037(3)). The engine is a pure function over `(facts, policy)`. The policy bundle is signed and versioned (15-AUTHENTICATION-AUTHORIZATION.md defines the language).
- **Route contract:** every route declares its `Action` and how the `ResourceRef` is derived (path parameter → loaded row → tenant, channel, case). The handler receives an `Authorized<T>` token type. Repository methods that return protected rows require `Authorized<T>`, so compile-time typing prevents unauthorized reads.
- **Deny mapping:** for resource-bound routes, `Deny` → **404 with uniform body** (08-API.md §3.4). For collection routes, the deny filters items. For actions on visible resources lacking a permission, 403 is returned only when the resource is already known to be visible to the caller. For example, a case member without export permission gets 403 on export.
- **Defense in depth:** Case DB RLS (tenant, plus case ACL for content-bearing tables) is enforced independently (09-DATABASE.md §6). Authorization does not depend on encryption state (INC-115).

### 5.7 SLA engine

- Timers are derived from the workflow definition (14-CASE-MANAGEMENT.md). Defaults for the EU channel template are acknowledgement ≤ 7 days and feedback ≤ 3 months (B-CO-02, Directive 2019/1937 Art. 9(1)(b),(f)).
- Timer fields: `kind`, `anchor_day` (EpochDay), `due_day` (EpochDay), `business_calendar_id`, `state ∈ {running, paused, met, breached, cancelled}`.
- The anchor for source-driven timers is `received_date` (day granularity; ADR-010).
- Evaluation job `sla_evaluate` runs daily at a fixed time (default 03:10 local), and on every staff workflow transition. A breach is surfaced in the Desk task list and in the next constant daily digest (§5.8), plus a CASE audit event; it never triggers an immediate message.

### 5.8 Notification service (C-23)

- Only template `T1` exists: "Candor: secure case-management action requires attention" + instance label (≤ 32 chars, admin-set, SAFE). No case ID, count, channel or time (ADR-017).
- Delivery modes (ADR-038(2); resolves RVW-A-19, RVW-B-05, RVW-C-02):
  - `daily_constant` (default in standard profiles): exactly one T1 message per subscribed staff member per day at the tenant's fixed time (`notify.daily_time`), **sent every day whether or not anything is pending**. The addressee set is every staff member subscribed on the tenant (not the channel roster), so neither the addressees nor the send time depend on imports or on which channel received a report.
  - `off` (default in HIGH/GOV): no external message; the Desk shows a badge when opened.
  - There is **no** event-driven or hourly mode. WITHDRAWN: `digest` (hourly) and `daily` (activity-dependent).
- Non-triage roles receive no signal about intake arrival (ADR-037(2)); what the Desk shows after login is governed by 12-FRONTEND-RECIPIENT.md.
- Channels: SMTP (TLS required, certificate verified), Matrix, generic webhook (HTTPS). Egress only to allow-listed hosts (SAFE list, changes ADVANCED).
- Retry policy: 5 attempts with exponential backoff, then drop plus a SYSTEM event. Failures never include the recipient address in logs, only `recipient_ref` (pseudonymous).
- **Never** sends anything to sources.

### 5.9 Audit service (C-24)

- **Append API:** Unix socket; `APPEND(class, event: TypedEvent)` → `{seq, hash}`.
  - `class` ∈ {SECURITY, CASE, SYSTEM}. SOURCE-SENSITIVE is never an event (ADR-016); only counters (§9.5).
- **Chain:** `hash_n = SHA-256("candor-audit-v1" ‖ class ‖ seq_n ‖ hash_{n−1} ‖ canonical_cbor(event))`, one chain per class per tenant.
- **Checkpoints:** every 1,000 events or 10 min, whichever first. A signed checkpoint `{class, tenant, seq, hash, time}` uses the Ed25519 audit key (TPM- or HSM-held).
  - Optional external witness anchoring posts the checkpoint hash to a witness or transparency service (20-LOGGING-AUDITING.md).
- **Fail-closed:** if append fails, the originating mutation is rolled back.
  - The audit write uses a separate DB and a two-phase pattern: audit INSERT first with `state=pending`, business transaction commit, then audit `state=committed`. A recovery job reconciles pending rows older than 5 min against business state.

### 5.10 Key directory service (C-14)

- **Log:** a Merkle tree (RFC 6962 hashing: leaf `0x00`, node `0x01`), with the checkpoint in C2SP signed-note format. [Knowledge (unverified): signed-note/tlog-checkpoint formats.]
- **Entry types:**
  - `USER_KEY` (identity + encryption public keys, device ID);
  - `USER_KEY_REVOKE`;
  - `CHANNEL_IDENTITY`;
  - `CHANNEL_ROSTER` (role labels ↔ member identity key IDs, Triage Set flag, `effective_day`; signed by the channel identity key, which only Triage Set members and OVERSIGHT hold, ADR-036(1));
  - `ROLE_LABEL_CERT` (role label certified by OVERSIGHT, ADR-036(3));
  - `MEMBER_EPOCH_KEY` (per member per channel per epoch, listed under the member's role label, signed by the member's identity key; ADR-030);
  - `COI_MAP` (category → excluded role labels; signed by the channel identity key);
  - `ROUTING_KEY` (intake routing public key);
  - `CONNECTOR_KEY` (**EE**, export connector encryption key);
  - `RECOVERY_QUORUM_STATE`;
  - `PROTECTION_STATEMENT`;
  - `OPERATOR_STATEMENT` (quorum-signed, including ≥ 1 independent role, renewed ≤ 30 days; ADR-035(2));
  - `INCIDENT_NOTICE` (ADR-035(4));
  - `SERVER_RELEASE` (running-manifest digest of intake and core, ADR-040; 08-API.md §7.1);
  - `CLIENT_RELEASE` (hash of Desk and Source App releases, copied from C-32);
  - `CONFIG_SIGNER` (admin signing keys).
- **Append:** only via `candor-case` after the approvals required by the entry type (e.g., `USER_KEY` needs admin approval plus a second admin for privileged roles; 15-AUTHENTICATION-AUTHORIZATION.md).
  - **Governance (ADR-036(2)):** `CHANNEL_ROSTER` additions, role-label changes, Triage Set changes and `COI_MAP` loosening are appended only after dual approval with ≥ 1 approver from an independent role (09 `roster_change`), carry `effective_day` = approval day + `kd.roster_timelock_days` (3; GOV/HIGH 7), and trigger a content-free notice to all current members and OVERSIGHT. Removals, `COI_MAP` tightening and revocations take effect immediately. A removal appends `USER_KEY_REVOKE`-equivalent revocation of the member's un-expired `MEMBER_EPOCH_KEY` entries in the same batch.
  - Entries are immutable. The PG role `candor_kd` has INSERT/SELECT only, and a trigger rejects UPDATE/DELETE.
- **Publication schedule (ADR-036(7); RVW-A-29):** `MEMBER_EPOCH_KEY` entries and time-locked governance entries are queued and appended only at the tenant's fixed weekly publication slot (`kd.publication_slot`, e.g. Monday 02:40 UTC). Checkpoints are signed at a **fixed hourly cadence** (hh:00 UTC, whether or not anything was appended; 04-CRYPTOGRAPHY.md §14.3, aligned in r3). Removals, revocations and `INCIDENT_NOTICE` are appended immediately and appear in the next hourly checkpoint (security exception; their hour is visible). Snapshot freshness: sealers refuse snapshots whose newest checkpoint is > 7 days old (ADR-047(4)).
- **Entry-type names:** the names used in this document and in 08 map to the canonical byte formats of 04-CRYPTOGRAPHY.md §14.2: `USER_KEY` = USER_KEYS (0x04), `MEMBER_EPOCH_KEY` = MEMBER_EPOCH (0x07), `COI_MAP` = COI_POLICY (0x0F), `RECOVERY_QUORUM_STATE` = RECOVERY_QUORUM (0x09), `SERVER_RELEASE` = RUNNING_MANIFEST (0x16), `USER_KEY_REVOKE` = REVOCATION (0x0C); additional types defined only in 04: GOVERNANCE_ROLES, OBJECTION, SEALER_ATTESTATION, SERVER_STATE (0x14), DISPOSITION_KEY (0x1A, chaff, ADR-047(3)), AUDIT_EXPORT_KEY (0x1B, MANAGED, ADR-047(10)). 04 is canonical where they differ.
  - Witnesses cosign each checkpoint. EE/GOV/MANAGED require ≥ 2 witness cosignatures with ≥ 1 witness outside the operating organisation; CE: recommended (ADR-036(5)). Desk and Source App refuse checkpoints that miss the required quorum (THR-046).
- **Snapshot for intake:** checkpoint + all current (non-revoked) entries needed by sources + consistency proof from the previous snapshot. Signed. Intake verifies signature, witness quorum and consistency **from its high-water mark** before exposing it at `/app/v1/directory/*` and to the sealer, and rejects any snapshot older or smaller than the high-water mark (ADR-036(6); 09 `intake_meta`).

### 5.11 Health agent (C-25)

- Checks (every 5 min ± 60 s):
  - secret placement manifest (ADR-028);
  - listener inventory;
  - nftables ruleset hash;
  - config bundle signature and version;
  - DB schema hash;
  - `core_pattern` and swap state;
  - journald storage mode (volatile on intake-gw);
  - access logs absent (tor `Log` settings, no web access log);
  - disk free;
  - Member Epoch Key runway (days of valid keys ahead per Triage Set member, alert < 14; channel alert, also to OVERSIGHT, when fewer than 2 Triage Set members would have valid keys; RVW-C-18);
  - relay slot success and overruns (no per-slot volume);
  - clock: offset against the independent time sources (§12);
  - TUF metadata expiry;
  - installed packages against the TUF-signed **Platform Manifest** and the signed **security floor** (ADR-040);
  - running manifest matches the installed release (ADR-035(1));
  - Erasure Key Vault backup age, DR replication lag and presence of the infrastructure-backup exclusion attestation (ADR-044(4));
  - backup age.
- Output: `HealthEvent{host_role, check_id, status ∈ {ok, warn, fail}, value_bucket}`. There are no free-text fields. Pushed to the collector (TCP 8514, mTLS). Source-influenced values (rate-limit hits, Argon2id queue, new-account cap, staging use, relay backlog) leave the host only as a global daily band (ADR-038(5), ADR-046(5); BE-073).

### 5.12 Erasure Key Vault (`candor-ekv`, ADR-033 §3)

- IPC ops: `CREATE(tenant, case)`, `SEAL(tenant, case, inner) → outer`, `UNSEAL(tenant, case, outer) → inner`, `META_SEAL` / `META_OPEN(tenant, case, column_id, row_version, …)` (per-case metadata under `K_meta` derived from the EK, `case_meta`; ADR-047(8); 04 §9.10a), `REKEY_MISSING(tenant, case)` (fresh EK for a case whose EK was lost or predates the restored vault backup, enabling dual-approved Desk re-wrap from case-key caches; ADR-047(7)), `DESTROY(tenant, case)` (also appends to the signed erasure log), `EXPORT_BACKUP` (EKs and erasure log re-encrypted to the offline Backup Public Key, restorable on new hardware; RVW-C-07), `REPLICATE` (EE-HA: to the standby and the DR-site vault within the HA RPO; ADR-044(4)), `ERASURE_LOG_EXPORT` (for restore tooling). The Erasure Key never leaves the process.
- AEAD: XChaCha20-Poly1305 (STD) or AES-256-GCM (FIPS), AAD = tenant ‖ case ‖ key_epoch ‖ recipient_key_id.
- Storage: 09-DATABASE.md §5.6 (host-local volume, never a DB schema). Excluded from routine and infrastructure-level backups (the latter by recorded attestation); own backup stream with ≤ 14-day retention. HIGH/GOV: VMK on physical TPM or HSM, never vTPM.
- **Restore rule:** `candorctl restore` applies the newest verified erasure log before any service starts serving (BE-066).
- Failure: if the vault is unavailable, case reads and writes that need key wraps fail closed (503). There is no fallback to storing unsealed wraps.

## 6. Queues and jobs

### 6.1 Mechanism
- Case DB table `job` (09-DATABASE.md). Claim:
```sql
WITH c AS (
  SELECT job_id FROM job
  WHERE state = 'ready' AND run_after <= now() AND kind = ANY($1)
  ORDER BY priority DESC, run_after
  FOR UPDATE SKIP LOCKED LIMIT $2)
UPDATE job SET state='running', locked_by=$3, lease_until=now()+interval '5 minutes', attempts=attempts+1
FROM c WHERE job.job_id = c.job_id RETURNING job.*;
```
- Lease 5 min, renewed every 60 s by the runner. An expired lease makes the job reclaimable.
- Backoff `min(2^attempts × 30 s, 6 h)` ± 20 % jitter. `max_attempts` per kind (default 8), then `dead`, which raises a SYSTEM alert.
- Payload: CBOR ≤ 4 KiB containing **only** opaque IDs, enums and day numbers. A schema per kind is enforced on insert (a DB CHECK on `kind` plus Rust type). No SOURCE-SENSITIVE data and no ciphertext in payloads.
- **No job is triggered by an import** (ADR-038(1)/(2)). Every job that could reflect source activity (notifications, escalations, SLA evaluation, counters) runs on a fixed schedule independent of arrivals, so job rows and their times carry no arrival information. WITHDRAWN: the v1 rule scheduling import-triggered jobs on hourly digest slots.

### 6.2 Z-CORE job types

| Kind | Runner service context | Trigger | Payload | Notes |
|---|---|---|---|---|
| (relay import slot / control cycle) | relay | in-process timers at fixed times (§5.4); **no job row** | — | ADR-038(1); avoids persisting pull times (ADR-033(4)) |
| `notify_intake_available` | — | WITHDRAWN (ADR-038(2); RVW-A-19, RVW-B-04, RVW-B-05, RVW-C-02) | — | Was event-driven, to the channel roster |
| `notify_daily_digest` | notify | daily at `notify.daily_time` (fixed) | `{}` | Creates one T1 row per `daily_constant` target, every day, regardless of activity (09 `notification_queue`) |
| `sla_evaluate` | case | daily at a fixed time + on staff transitions | `{case_id?}` | |
| `retention_evaluate` | case | daily | `{}` | Enqueues `crypto_erase_case` for due cases without legal hold |
| `crypto_erase_case` | case | retention / manual dual-approved | `{case_id}` | `candor-ekv` DESTROY of the case Erasure Key first, then deletes all `case_key_wrap` rows, then blobs, then rows (35-DATA-RETENTION-DELETION.md; ADR-033 §3) |
| `import_escalate` | case | daily at a fixed time | `{}` | Pending `import_envelope` rows older than 7 days: set `escalated_date` and send a content-free escalation to the channel's independent escalation role, **at most once per channel per 7 days** (ADR-038(6)). Rows pending > 14 days are marked `rejectable` for dual-approved rejection (DA-23/DA-25), after which row and blobs are deleted. There is **no** automatic expiry (ADR-033(2)). |
| `ekv_backup` | ekv | daily | `{}` | Encrypted vault backup to its own stream; the store enforces ≤ 14-day retention |
| `epoch_runway_check` | keydir | daily | `{}` | Alerts per member when < 14 days of future Member Epoch Keys exist; per channel when fewer than `min_recipients` members would have valid keys |
| `epoch_key_destroy` | keydir | daily | `{}` | Marks a Member Epoch Key `destroy_due` only when its decrypt window has passed **and** no envelope of its channel and epoch is `pending` (ADR-033 §2). Each Desk deletes its private key on sync and acknowledges (DA-15). No private epoch key material exists server-side (ADR-030). |
| `blob_gc` | case | daily | `{}` | Removes unreferenced blobs > 24 h old |
| `chaff_discard` | case | at every import slot, after the slot commit (fixed time; not triggered by arrivals) | `{}` | Opens `disposition_ct` (K41, TPM/HSM-sealed credential of `candor-case`) only for pending envelopes whose derived hold slot is the current slot; deletes chaff rows and blobs; emits the same content-free disposal record as other disposals; no chaff count anywhere (ADR-047(3); 04 §12.7) |
| `ek_rewrap_pending` | case | daily | `{}` | Lists cases marked `ek_missing` after a vault restore/loss to their holders' Desks for dual-approved re-wrap (ADR-047(7)) |
| `deletion_list_prune` | case | daily | `{}` | Deletes `intake_deletion_list` entries older than 35 days |
| `ekv_replicate` (EE-HA) | ekv | continuous, bounded by HA RPO | `{}` | Vault replication to standby and DR site (ADR-044(4)) |
| `kd_timelock_activate` | keydir | daily at a fixed time | `{}` | Moves `roster_change` rows whose `effective_day` has arrived to `effective`; the entries were already logged at the weekly slot with their `effective_day` (ADR-036(2)) |
| `kd_weekly_publish` | keydir | weekly at `kd.publication_slot` | `{}` | Appends queued `MEMBER_EPOCH_KEY` and time-locked governance entries, then checkpoints (ADR-036(7)) |
| `wrap_deletion_execute` | case | daily | `{}` | Executes approved `wrap_deletion_request`s whose `not_before_day` has passed and whose OVERSIGHT notice is recorded, unless execution would leave fewer than `min_recipients` holders (ADR-044(1)) |
| `records_grant_expire` | case | daily | `{}` | Revokes `records_grant` memberships at `valid_until_day` (ADR-044(5)) |
| `timestamp_retention` | auth | 15 min | `{}` | Deletes expired rows of the exact-timestamp tables (09 §8 L3) |
| `audit_checkpoint` | audit | 10 min | `{class}` | |
| `audit_anchor` | audit | hourly (if configured) | `{}` | |
| `audit_reconcile` | audit | 5 min | `{}` | §5.9 |
| `kd_checkpoint_publish` | keydir | hourly at hh:00 UTC (fixed cadence, 04 §14.3) | `{}` | ADR-036(7). WITHDRAWN: "on append ≤ 60 s" and the r2 daily cadence |
| `kd_witness_cosign` | keydir | on checkpoint | `{}` | Outbound to ≥ 2 witnesses (≥ 1 external) where required |
| `backup_run` | backup | daily (configurable) | `{}` | |
| `backup_verify` | backup | weekly | `{}` | Restore test into a scratch instance (19-BACKUPS-DR.md) |
| `session_gc` | auth | 15 min | `{}` | |
| `breakglass_expire` | case | 15 min | `{}` | |
| `breakglass_review_due` | case | daily | `{}` | Escalates overdue reviews |
| `export_delivery` (EE) | connector | on approval | `{export_id}` | |
| `export_expire` | case | daily | `{}` | Removes approved-but-undelivered package blobs after 7 days |
| `legal_hold_review` | case | monthly | `{}` | Reminder only |
| `counters_rollup` | case | monthly (after month close) | `{}` | Stores monthly inputs for the 24 §TEL regime (k = 10); no weekly or daily aggregates (ADR-046(5)) |
| `update_check` | health | 6 h | `{}` | TUF metadata freshness only |
| `idempotency_gc` | case | hourly | `{}` | |

### 6.3 Z-INTAKE local jobs (intake DB, same mechanism)

| Kind | Schedule | Action |
|---|---|---|
| `draft_gc` | WITHDRAWN (ADR-034) | There are no draft rows. Staged parts in tmpfs are deleted at session end by the web/store IPC and on restart; an in-RAM sweep (every 5 min, monotonic clock) removes staged parts whose session no longer exists. |
| `upload_gc` | daily | Backstop: delete Tier V uploads with `created_day` < today − 1 (the 24-h expiry itself runs in RAM, §5.3) |
| `reply_expiry` | daily | Delete replies older than `intake.reply_retention_days` (default and maximum 30, ADR-039) |
| `quota_reset` | daily | Reset `source_account.quota_bucket` to 0; no history (ADR-038(3)) |
| `tombstone_expiry` | WITHDRAWN (ADR-047(9)) | Replaced by `deletion_list_prune` |
| `deletion_list_prune` | daily | Delete `deletion_list` entries older than 35 days that the relay has acknowledged |
| `snapshot_backup` | daily at a fixed time | Encrypted snapshot (`source_account`, `deletion_list`, `intake_meta`) for relay pull; no envelopes or replies |
| `counters_rollup` | monthly | Close the previous `counter_month` for export (§9.5) |

## 7. Configuration model

### 7.1 Layers

| Layer | File | Signed | Contents | Change process |
|---|---|---|---|---|
| L0 bootstrap | `/etc/candor/<svc>/bootstrap.toml` (root:svc 0640) | no (install-time; hash recorded in the Secret Placement Manifest) | Socket paths, DB socket, pinned directory root key fingerprint, pinned config-signer set at install | Reinstall or `candorctl bootstrap` with console access |
| L1 signed bundle | `/run/candor/config/bundle.cbor` + `.sig` | **yes** | All behavior settings (§7.3) | Admin API change workflow (§7.2) |
| L2 secrets | systemd credentials (`LoadCredentialEncrypted=`, TPM2-sealed where available) | n/a | DB passwords/certs, relay TLS keys, routing key, onion key (tor) | `candorctl secrets` ceremony; manifest-checked |

**Bundle format:** deterministic CBOR `{schema: u16, version: u64, tenant_id, not_before_day, items: {key: value}, class_digest}`.
- Signatures are Ed25519 by keys listed as `CONFIG_SIGNER` in C-14.
- A service accepts a bundle iff:
  - the signatures are valid;
  - the signer count meets the highest class among items changed since the previous bundle;
  - `version > current_version` (rollback protection; a downgrade requires a DANGEROUS "rollback" item signed by 2);
  - `not_before_day ≤ today`.
- Unknown keys cause rejection.

### 7.2 Classification (CFG semantics; identifiers owned by 32-OPERATIONS.md)

| Class | Meaning | Approval | Effect delay | Visibility |
|---|---|---|---|---|
| SAFE | Cannot reduce source anonymity, confidentiality or audit | 1 admin | immediate | SECURITY audit event |
| ADVANCED | Can reduce availability or usability, or weaken a non-anonymity control within documented bounds | 1 admin + WebAuthn step-up + typed confirmation | immediate | SECURITY audit + notice to all admins |
| DANGEROUS | Can reduce source anonymity, confidentiality, integrity of evidence, or auditability | 2 distinct admins (distinct roles where configured) + step-up | **72 h** cool-off (cancellable by any admin or auditor) | SECURITY audit; content-free notice to all staff; **source-visible** protection statement update in C-14 where the item is source-affecting |

### 7.3 Configuration item catalog (excerpt; full catalog in 32-OPERATIONS.md)

| Key | Type / range | Default | Class |
|---|---|---|---|
| `intake.tier_w.enabled` | bool | true | ADVANCED |
| `intake.tier_v.webcat_bundle.enabled` | bool | false | ADVANCED |
| `intake.max_file_bytes` | 1 MiB – 4 GiB (standard); up to 16 GiB only in EE profiles (ADR-046(4)) | 4 GiB | SAFE |
| `intake.tierw_staging_bytes` | 1–64 GiB, ≤ 50 % of intake RAM | 8 GiB | SAFE (tmpfs staging capacity for Tier W parts, ADR-034) |
| `intake.max_files_per_envelope` | 1–32 | 20 | SAFE |
| `intake.reply_retention_days` | 7–30 | 30 | SAFE (ADR-039 fetch-all window) |
| `intake.delayed_delivery.enabled` | bool | true | SAFE (offers the ADR-038(4) option to sources) |
| `relay.import_slots` | 1–4 fixed times per day | 4 (standard); 1 (HIGH/GOV) | SAFE to reduce; ADVANCED to increase. Event-driven import does not exist (ADR-038(1)) |
| `relay.slot_commit_offset` | 5–60 min | 20 min | SAFE |
| `intake.chaff.mean_interval` | 15 min – 2 h per channel | 2 h (ADR-047(3)) | SAFE to lower (more chaff); raising above 2 h is not possible; chaff cannot be disabled |
| `intake.chaff.followup_share` | 0.1–0.5 | 0.3 | SAFE |
| `intake.login_floor` (`T_LOGIN_FLOOR`) | 2–10 s | 3 s | SAFE to raise; lowering below 2 s not possible |
| `intake.pow.app_level.enabled` | bool | false | SAFE |
| `tor.vanguards.full` | bool | profile | ADVANCED |
| `channel.<id>.mode` | ANONYMOUS/CONFIDENTIAL/IDENTIFIED | ANONYMOUS | DANGEROUS when moving away from ANONYMOUS |
| `clearnet_intake.enabled` (C-38) | bool | false | DANGEROUS |
| `recovery_quorum.enabled` | bool | false | DANGEROUS (ADR-013) |
| `logging.level` (trust path) | `codes` only; there is no debug level in release builds | codes | n/a (not configurable) |
| `audit.external_witness.url` | https URL | none | ADVANCED |
| `notify.mode` (tenant default) | daily_constant / off | daily_constant (standard); off (HIGH/GOV) | SAFE (ADR-038(2)) |
| `notify.daily_time` | HH:MM local | 08:47 | SAFE |
| `kd.roster_timelock_days` | 3–14 | 3 (standard); 7 (GOV/HIGH) | lowering below the profile default is not possible; raising SAFE (ADR-036(2)) |
| `kd.publication_slot` | weekday + HH:MM UTC | Monday 02:40 | SAFE (ADR-036(7)) |
| `update.desk_direct_vendor_mirror` | bool | false | ADVANCED (RVW-C-02, RVW-C-13) |
| `notify.allowlist_hosts` | list | [] | ADVANCED |
| `epoch.length_days` | 1–14 | 7 | ADVANCED |
| `channel.<id>.min_recipients` (minimum case-key holders) | 2–16; 1 only as DANGEROUS | 2 (ADR-044(2)) | raising SAFE; lowering to 1 DANGEROUS |
| `channel.<id>.alternative_channel_id` | channel ID | required for ANONYMOUS channels | ADVANCED (ADR-037(1)) |
| `envelope.recipient_slots` | 16 (fixed) | 16 | not configurable in v1: ADR-033(1) fixes exactly 16 slots (r3 consistency fix; the r2 "increase only" option is withdrawn) |
| `channel.<id>.roster_names_visible` | bool | false (role labels only) | ADVANCED |
| `epoch.decrypt_window_days` | epoch..28 | 14 | DANGEROUS if > 14 |
| `retention.default_days` | 30–3650 | 365 | ADVANCED |
| `breakglass.enabled` | bool | true | DANGEROUS to disable review; ADVANCED to disable feature |
| `siem.export.enabled` (EE) | bool | false | ADVANCED |
| `fleet.enabled` (EE) | bool | false | ADVANCED |
| `telemetry.enabled` | bool | false | DANGEROUS (ADR-023) |

There is intentionally **no** configuration item that enables access logs, IP logging, exact source timestamps or debug logging of request bodies on trust-path services. These behaviors do not exist in release builds (THR-035; INC-114).

## 8. Error handling

- **Error type:** `CandorError { code: ErrorCode, class: ErrorClass, retry: bool }`.
  - `ErrorCode` is a closed `#[repr(u16)]` enum. `ErrorClass` ∈ {Client, Auth, NotFound, Conflict, Limit, Unavailable, Internal}.
  - Errors carry **no strings**, no wrapped foreign errors in release builds, and no source-derived values (no IDs from source requests, no filenames, no sizes).
- **Conversion:** foreign errors (sqlx, hyper, io, rustls) are mapped at the boundary by `From` impls that keep only a code. `#[derive(Debug)]` on error types is replaced by a manual impl printing the code.
- **HTTP mapping:** fixed per audience (08-API.md §3.5). Source Web errors render one of 4 static padded pages (400, 404, 429/503 "busy", 500). All are identical in size class, with no code shown beyond a 4-digit support number that maps to `ErrorClass` only.
- **Panics:** `panic = "abort"`. A custom panic hook writes `candor-log` event `SYSTEM:panic{crate_id, code_site_id}` where `code_site_id` is a build-time constant. Panic messages and payloads are discarded, and `RUST_BACKTRACE` is forced off in units (`Environment=RUST_BACKTRACE=0`).
- **DB errors:** constraint names are mapped to codes. SQL text, parameters and row values are never surfaced or logged.
- **Tests:** `error-scrub` property test. It injects canary strings into every source input field and triggers every error path via fault injection, then asserts that the canary appears in no log, response or audit record.

## 9. Typed logging API (ADR-016)

### 9.1 API
```rust
candor_log::event!(SystemEvent::RelayCycle { outcome: Outcome::Ok, objects: CountBucket::from(n), lag: DurBucket::from(d) });
candor_log::security!(SecurityEvent::LoginFailed { principal: PseudoId<User>, method: AuthMethod::WebAuthn });
```
- Events are variants of closed enums (`SystemEvent`, `SecurityEvent`, `CaseEvent`) generated from the schema registry in 20-LOGGING-AUDITING.md. Each field has an allowed type:
  - `EnumCode`, `PseudoId<K>` (keyed-hash pseudonym, per-tenant key, rotates yearly), `CountBucket`, `SizeBucket`, `DurBucket`, `EpochDay`, `StaffTimestamp` (SECURITY/CASE only), `HostRole`, `CheckId`, `VersionTriple`.
- There is **no** `&str`/`String` field type. `format!`-style macros are not provided.
- A compile-time registry assigns each event a stable ID. `candor-log` refuses at startup to run with an unknown schema version.

### 9.2 Bans (CI-enforced)
- `clippy.toml` `disallowed-macros`: `println`, `eprintln`, `print`, `eprint`, `dbg`, `log::*`, `tracing::*` in trust-path crates.
- `disallowed-methods`: `std::io::stderr`, `std::io::stdout`.
- Dependency logs: the `log` and `tracing` facades are initialized with a **null subscriber** in trust-path binaries. A curated allow-list of dependency targets (e.g., `rustls` alerts, `sqlx::pool` saturation) is mapped by an adapter to fixed `SystemEvent` codes without message text.

### 9.3 Sinks

| Host | Sink | Retention |
|---|---|---|
| intake-gw | journald `Storage=volatile`, `RuntimeMaxUse=64M`; health agent forwards SYSTEM/SECURITY events to the monitor | RAM only on host |
| core | journald persistent (codes only) + `candor-audit` for SECURITY/CASE | 20-LOGGING-AUDITING.md |
| tor | `Log notice file /dev/null` equivalent; SafeLogging 1; no `HiddenServiceExportCircuitID` persistence | none |

### 9.4 Prohibited data (never in any event, including SYSTEM)
- IP addresses;
- user agents;
- onion circuit IDs;
- source account IDs;
- locator hashes;
- source-related exact timestamps;
- file names;
- message sizes other than buckets;
- ciphertext;
- key material;
- passphrase lengths;
- request paths containing IDs (route **names** only).

### 9.5 SOURCE-SENSITIVE counters
- The metrics regime is owned by 24 §TEL (ADR-046(5)): k = 10, minimum period one calendar month, complementary suppression, no medians/ratios/percentiles for cells < k, no per-channel metrics for channels with < 3 cases/month, and the SOC sees only global daily health bands.
- Counters (`submissions_received` (name per 20 §5.4), `accounts_created`, `account_deletions`) are accumulated per calendar month per channel in the intake DB (`counter_month`). WITHDRAWN (RVW-B-07, RVW-A-26): `tier_w_vs_v`, `followups`, `logins` and all daily counters.
- They are exported by the relay once, after the month closes, with suppression applied at the intake per 24 §TEL.

## 10. Safe-path API (ADR-027) — server side

`candor-safefs` is the only permitted filesystem write and read path for any object whose existence is caused by source or recipient input (blobs, drafts, snapshots, export packages).

```rust
let root = SafeRoot::open("/var/lib/candor/intake/blobs", RootPolicy::BlobStore)?;   // O_PATH|O_DIRECTORY, verifies owner+mode 0700
let id: ObjectId = ObjectId::random();                   // 128-bit, base32 lower, 26 chars
let mut w = root.create_new(&id)?;                       // openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV), O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600
w.write_all(ct)?; w.commit()?;                           // fdatasync + rename within root (renameat2 RENAME_NOREPLACE)
let r = root.open_read(&id)?;
root.remove(&id)?;
```

Rules:
- The only name type accepted is `ObjectId` (validated `[a-z2-7]{26}`) with a derived 2-char shard. No `&str` or `Path` inputs.
- No directory creation outside `SafeRoot::open` policies.
- No symlink or hardlink creation.
- No archive extraction on servers. Servers never unpack source archives (ADR-012).
- CI lint (`safefs-lint`, Semgrep and `clippy disallowed-methods`) bans `std::fs::*`, `tokio::fs::*`, `Path::join`, `PathBuf::push`, `tar::*`, `zip::*` in trust-path crates other than `candor-safefs`. `candor-safefs` itself is fuzzed (cargo-fuzz) and on the audit list.

## 11. Resource limits

| Limit | Value | Enforced in | On exceed |
|---|---|---|---|
| Onion PoW | tor `HiddenServicePoWDefensesEnabled 1`, `HiddenServicePoWQueueRate 250`, `HiddenServicePoWQueueBurst 2500` (tuned per 16-TOR-I2P.md) | C-05 | tor queueing |
| Concurrent connections from tor to web | 512 | web accept loop | 503 static padded page |
| Per-circuit request rate | 60 req/min, burst 20 | web | 429 page |
| Per-circuit login attempts | 5 / 10 min | web | 429 page |
| Global login (Argon2id, m = 64 MiB) concurrency | 4 active, 32 queued, 30 s wait (ADR-046(7)) | sealer | "busy" page |
| New Tier W sessions (global) | 600 / hour default (ADVANCED); sized so that it is reached only at ≥ 10× design peak (34) | web | "busy" page; SYSTEM alert |
| Tier W staging (tmpfs) | `intake.tierw_staging_bytes` total | istore | "busy" page for new uploads |
| Sealer sessions | 64 | sealer | `BUSY` |
| Web sessions | 10,000 | web | oldest idle evicted |
| Request body (message and questionnaire routes) | 112 KiB (≤ 96 KiB answers per 11 §5.7, or 64 KiB message text, + form overhead) | web parser | 413 page |
| Message text | 64 KiB after UTF-8 validation | web | 413 page |
| File per request (Tier W) | `intake.max_file_bytes` (≤ 4 GiB) and the free staging capacity; no resume | web streaming counter | 413 or busy; draft part discarded |
| Files per envelope | 20 (max 32) | web/sealer | 400 |
| Envelope total (Tier W / Tier V) | `intake.tierw_staging_bytes` / 4 GiB × files, padded (16 GiB per file only in EE profiles) | istore | 413 |
| Tier V upload chunk | 8 MiB (128 STREAM chunks), last chunk ≤ 8 MiB (08-API.md §5.1, ADR-046(4)) | web | 400 |
| Pending uploads (global) | 2,000; per upload ≤ 512 chunks (≤ 2,048 in EE profiles); expiry 24 h | istore | 503 |
| Intake disk reserve | refuse new envelopes when free < 15 % | istore | 503 "busy" |
| Relay batch | 500 objects / 2 GiB | relay | next cycle |
| Desk API request body (non-blob) | 1 MiB | case | 413 |
| Desk blob upload chunk | 8 MiB; object ≤ 4 GiB | case | 413 |
| Desk API rate per user | 600 req/min, burst 100 | case | 429 |
| Admin API rate per user | 120 req/min | case | 429 |
| DB pool | web 0 (no DB), istore 16, case 32, relay 4, worker 8 | services | queue ≤ 5 s then 503 |
| Timeouts | header read 10 s; body idle 60 s (Tor-friendly); total Tier W upload request 4 h; Desk request 120 s (non-blob) | services | connection closed |

**Timing uniformity for unauthenticated source endpoints:**
- The login response is sent only after `max(elapsed, T_LOGIN_FLOOR)` + U(0, 250 ms), `T_LOGIN_FLOOR` default **3 s** (`intake.login_floor`), for **successful and failed** logins alike, whether the account exists or not, and whether or not there are replies to decrypt (RVW-A-21; DISP-G4).
- `ACCOUNT_AUTH_VERIFY` compares in constant time.
- All "busy" responses (any limit above) are byte-identical, and global limits are sized so that they trigger only at attack-level load (≥ 10× design peak), so single probes do not reveal other sources' activity (ADR-038(5); RVW-A-27).

## 12. Time handling (ADR-010)

| Type | Resolution | Used for | Source |
|---|---|---|---|
| `EpochDay` (u32, days since 1970-01-01 UTC) | 1 day | All source events (received, reply available), SLA anchors, retention | `SourceClock::today()` |
| `BatchNo` (u64 monotonic) | n/a | Ordering of intake batches | intake DB sequence |
| `StaffTimestamp` (UTC, 1 s) | 1 s | Only the exact-timestamp tables enumerated in 09 §8 L3 (staff sessions and credentials, job leases, config cool-off, break-glass expiry) and staff-action audit events (ADR-046(11)) | `StaffClock::now()` |
| `Monotonic` | ns | Timeouts, rate limits (RAM only) | `Instant` |

Rules:
- Trust-path crates on intake-gw have **no** API returning wall-clock time finer than a day except `Monotonic`. `SourceClock` is the only wall-clock accessor there, enforced by lint banning `SystemTime::now`/`chrono::Utc::now` outside `candor-types::time`.
- The Case DB has `timestamptz` columns only in tables on the 09-DATABASE.md §8 allow-list.
- Staff-authored times shown in the Desk (e.g., note times) are carried **inside** encrypted payloads, not in cleartext columns.
- Member Epoch Key selection uses `today` in UTC.
  - The sealer and Tier V clients use keys valid for `today`. Intake cannot check key validity because slots are anonymous (ADR-033). The Desk checks the signed recipient list and flags envelopes encrypted to keys outside their validity (± 1 day tolerance).
- **Independent intake time (ADR-036(6); RVW-A-04):** intake-gw does not take time from Z-CORE. Its floor is the `valid-after` of the current signed Tor consensus held by C-05 (the host clock must never be earlier), its ceiling the consensus `valid-until` + 3 h, and it cross-checks ≥ 2 Roughtime servers queried over Tor through the update-tor client (16-TOR-I2P.md; Knowledge (unverified): Roughtime TCP transport per draft-ietf-ntp-roughtime). The chrony refclock fed by C-09 is withdrawn.
- **Clock sanity (THR-043):**
  - At start and hourly, services compare the wall clock with the independent sources above (intake-gw) or NTS (core).
  - If the intake clock is outside the consensus window, or disagrees with the Roughtime median by > 2 h, intake refuses new submissions (busy) and raises `SYSTEM:clock_insane`.
  - The sealer rejects any directory snapshot below the high-water mark and refuses to seal to a snapshot whose newest checkpoint is older than **7 days** by the independent clock (`KD_SNAPSHOT_MAX_AGE`, ADR-047(4); 04 VR-5); a checkpoint older than 24 h only raises `SYSTEM:kd_snapshot_stale`. In the Confidential-VM profile the sealer refreshes its attestation evidence at least every 24 h (ADR-047(4)).
  - Core refuses token issuance at > 120 s offset.

## 13. Graceful degradation and fail-closed behavior

| Failure | Behavior (never weaker protection) | User-visible | Alert |
|---|---|---|---|
| Sealer down or killed | Tier W submit and login unavailable. **No** fallback to writing plaintext or to a web-side encryptor. Tier V continues. | Tier W: static "temporarily unavailable, try later" page; no alternative channel suggested | SYSTEM fail |
| No eligible Triage Set member with a valid Member Epoch Key after the COI filter | Refuse the submission for that selection (ADR-030, ADR-037(1)). Never encrypt to other or fewer parties or to an expired, unsigned or unverified key. | Specific message naming the channel's alternative independent channel (RVW-C-18) | SYSTEM fail only when caused by key runway (content-free, no selection details); runway alerts at 14 days to the Channel Owner and OVERSIGHT |
| Tier W staging tmpfs full | New uploads refused; drafts in RAM kept | busy page | SYSTEM warn (daily band) |
| Sealer restart during drafting | Drafts, per-session keys and staged parts are lost (ADR-034) | "please start again" page | SYSTEM |
| Import slot missed (core down, relay failure) | Envelopes stay on intake until the next slot; no ad-hoc import outside slots | none | SYSTEM at 2 consecutive missed slots |
| Directory snapshot signature invalid | Keep the last valid snapshot while its keys remain valid and it is ≤ 7 days old, then refuse | as above | SECURITY |
| Directory snapshot older than 7 days (ADR-047(4)) | Refuse to seal for all channels (fail closed); logins and reply display continue | "channel temporarily unavailable" | SECURITY |
| Confidential-VM profile: attestation evidence > 24 h old | Sealer keeps running; Desks treat K35 as unattested and reject Tier W envelopes sealed in the gap (04 KEY-065) | none (Tier W); Desk warning | SECURITY |
| Intake store disk < 15 % | Refuse new envelopes. Replies still served. | busy page | SYSTEM warn at 25 %, fail at 15 % |
| Relay unreachable | Intake buffers. Replies delayed. | none | SYSTEM at 2 consecutive missed slots |
| Core DB unavailable | Desk/Admin API 503. Relay stops. | Desk offline banner | SYSTEM |
| Audit service unavailable | All mutating Desk/Admin operations fail (503). Reads of case content also fail because they require an access-audit event. | Desk error | SYSTEM + SECURITY |
| Authz engine error or policy bundle invalid | Deny all (404/403 per mapping) | Desk "access unavailable" | SECURITY |
| Auth service down | No new sessions. Existing tokens valid until expiry (≤ 15 min access tokens). | re-login fails | SYSTEM |
| Key directory inconsistency (split view, witness mismatch) | Desk refuses to wrap to affected keys. Source App refuses to submit. | explicit warning | SECURITY critical |
| Notification egress failure | Drop after retries. Never fall back to a different channel type. | none | SYSTEM |
| Clock insane | §12 | busy | SYSTEM |
| Config bundle invalid at start | Service does not start | outage | SECURITY |
| Tor down | Onion unreachable. No clearnet fallback (ADR-002). | outage page on C-37 (static, manual) | SYSTEM |
| Blob store write failure | Transaction aborted. No partial envelope visible. | retry | SYSTEM |

## 14. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| BE-001 | All trust-path server code SHALL be Rust, built with `panic=abort`, overflow checks on, and `#![forbid(unsafe_code)]` except in the four crates listed in §3, whose `unsafe` blocks SHALL be enumerated for audit. | ADR-019; INC-116 | THR-012; THR-014 | C-06..C-14; C-21..C-24 | TST: CI `unsafe-inventory`; AUD: unsafe review |
| BE-002 | Each service SHALL run under a dedicated OS user with the §4.2 systemd baseline and per-unit deltas. The self-test SHALL verify unit hardening via `systemd-analyze security` score ≤ 2.0 for every Candor unit. | B-GL-04; INC-109 | THR-014 | all server components | TST: `unit-hardening` self-test check |
| BE-003 | `candor-sealer` SHALL run with no network namespace access, the §4.3 seccomp allow-list, `mlockall`, `PR_SET_DUMPABLE=0`, `LimitCORE=0` and `MemorySwapMax=0`. | ADR-004; INC-58 | THR-014; THR-016 | C-07 | TST: seccomp violation test (kill observed); TST: `/proc/<pid>/status` VmLck and dumpable checks; TST (security, 29): gcore attempt fails |
| BE-004 | Intake-gw SHALL have swap disabled and `core_pattern=\|/bin/false`. Core hosts SHALL have swap disabled or encrypted with an ephemeral key. | INC-58 | THR-016 | C-05; C-39 | TST: health check `mem_hygiene` |
| BE-005 | Login passphrases SHALL be zeroized immediately after key derivation; newly generated passphrases SHALL be held only in sealer RAM until confirmation and then zeroized. Derived source keys and draft material SHALL be zeroized at logout, 20-min idle, 2-h absolute timeout, abort or restart. | ADR-005; ADR-034 | THR-014; THR-034 | C-07 | TST: memory scan test in the sealer harness after each state transition |
| BE-006 | The sealer SHALL accept IPC only from the `candor-web` UID (SO_PEERCRED) and only the operations in §5.2, with strict CBOR decoding (unknown keys and oversize fields rejected). | INC-103 | THR-014; THR-021 | C-07 | TST: IPC fuzzing (cargo-fuzz corpus) and wrong-UID connection test |
| BE-007 | The web multipart parser SHALL enforce allowed parts, per-part header limits and size limits before forwarding any byte, and SHALL never write request data to disk. | INC-107; B-OS-02 | THR-032; THR-014 | C-06 | TST: crafted multipart suite + fanotify zero-write assertion |
| BE-008 | Source-supplied filenames SHALL be carried only inside encrypted manifests and SHALL never influence any server filesystem path. | ADR-027; INC-101; INC-102 | THR-023 | C-06; C-07; C-08 | TST: path-injection corpus in filenames; `safefs-lint` |
| BE-009 | All server filesystem access to input-derived objects SHALL use `candor-safefs` (openat2 RESOLVE_BENEATH\|NO_SYMLINKS\|NO_MAGICLINKS\|NO_XDEV, O_EXCL, mode 0600, random 128-bit names). The CI lint SHALL fail on banned APIs in trust-path crates. | ADR-027; INC-108; INC-109 | THR-023; THR-014 | C-08; C-09; C-10; C-13 | TST: `safefs-lint`; cargo-fuzz on `candor-safefs` |
| BE-010 | `AUTH_CHALLENGE` SHALL return a challenge for unknown locators indistinguishable from known ones. (Amended r3) Login responses SHALL be delayed to `T_LOGIN_FLOOR` (default 3 s, never below 2 s) + U(0, 250 ms) regardless of outcome, including successful logins. | INC-112; B-GL-37 | THR-034; THR-021 | C-06; C-08 | TST: timing distribution test (KS test, p > 0.01, n = 10,000) known vs unknown |
| BE-011 | There SHALL be no per-account lockout for source logins. Brute-force resistance SHALL rely on passphrase entropy (≈129 bits) plus per-circuit and global Argon2id throttles. | ADR-005; ADR-026 | THR-034; THR-032 | C-06; C-07 | INSP: design review; TST: throttle tests |
| BE-012 | The relay SHALL authenticate the intake by pinned certificate and signed, counter-protected requests. It SHALL validate every intake-supplied field against §5.4 bounds and SHALL quarantine non-conforming objects. | ADR-009; INC-103 | THR-014; THR-037 | C-09 | TST: malicious-intake harness (oversize, wrong tenant, future day, replay counter) |
| BE-013 | The relay SHALL assign new random IDs on import and SHALL NOT persist intake object references. Header digests used for idempotency SHALL be nulled after 24 h. | ADR-010; ADR-039 | THR-015; THR-038 | C-09; C-12 | TST: post-import DB scan for intake refs; retention job test |
| BE-014 | The intake SHALL delete envelope rows and blobs within one relay cycle after a digest-verified ack. Unacked data SHALL be retained. | ADR-009; ADR-025 | THR-015; THR-017 | C-08 | TST: ack/nack scenarios; blob presence checks |
| BE-015 | The case service request pipeline SHALL perform audience verification, tenant binding, strict DTO validation (`deny_unknown_fields`, no generic attribute setters), authorization and audit in that order for every route. | ADR-029; INC-112; INC-114 | THR-021; THR-018 | C-10 | TST: route-registry lint; property-based mass-assignment fuzz per role |
| BE-016 | Repository methods returning protected rows SHALL require an `Authorized<T>` capability produced only by C-22. | INC-114; B-GL-37 | THR-021 | C-10; C-22 | TST: compile-fail tests; INSP |
| BE-017 | Authorization decisions SHALL NOT depend on whether the caller could decrypt data. The authz test suite SHALL pass with key material available to all test users. | INC-115 | THR-021 | C-22 | TST: "simulated key leak" authz suite |
| BE-018 | The case service SHALL reject case creation, member addition or re-key if the set of wrapped-to keys differs from the C-22 eligible set, or if any key is not the current key-directory entry. | ADR-015; INC-14 | THR-046; THR-020 | C-10; C-14 | TST: extra-wrap and stale-key injection tests |
| BE-019 | Mutable resources SHALL use optimistic concurrency (`version`, `If-Match`). Mutating Desk endpoints SHALL honor `Idempotency-Key` for 24 h. | Design | — | C-10 | TST: concurrent update tests |
| BE-020 | Job payloads SHALL contain only opaque IDs, enums and day numbers, validated by per-kind schema, and SHALL never contain ciphertext or SOURCE-SENSITIVE data. | ADR-016 | THR-016; THR-015 | C-10; C-12 | TST: job schema tests; DB lint on the `job.payload` CHECK |
| BE-021 | WITHDRAWN (ADR-038(1)/(2)): hourly-slot scheduling of import-triggered jobs. Replaced by BE-057 and BE-058: no job is triggered by an import. | ADR-038 | THR-011 | C-10; C-23 | TST: job table inspection after imports shows no import-triggered kinds |
| BE-022 | The job runner SHALL use `FOR UPDATE SKIP LOCKED` leases of 5 min with renewal, bounded retries with jittered exponential backoff, and a `dead` state that raises a SYSTEM alert. | ADR-019 | THR-042 | C-10 | TST: lease expiry and crash-recovery tests |
| BE-023 | Behavior configuration SHALL be loaded only from signed bundles meeting the signer threshold of the highest changed class, with monotonic versions and rejection of unknown keys. | INC-114; INC-106 | THR-035; THR-018 | all server components | TST: unsigned, under-signed, rollback and unknown-key bundles rejected |
| BE-024 | DANGEROUS configuration changes SHALL require two distinct admins with step-up, a 72-h cancellable cool-off, content-free notice to all staff, and a source-visible protection statement update when source-affecting. | ADR-013; INC-114 | THR-035; THR-018 | C-10; C-14; C-19 | TST: e2e: single approval stays pending; cancel works; statement entry appended |
| BE-025 | Release builds SHALL contain no configuration or code path that enables access logs, IP or user-agent capture, exact source timestamps, or request-body debug logging on trust-path services. | ADR-016; INC-60; INC-03 | THR-016; THR-035 | C-05; C-06; C-07; C-08 | TST: binary string scan + config schema test; INSP |
| BE-026 | Errors SHALL carry only closed codes. No error, panic or log path SHALL include source-derived data. The `error-scrub` canary test SHALL pass on every release. | ADR-016; INC-60; INC-56 | THR-016 | all | TST: `error-scrub` |
| BE-027 | The panic hook SHALL emit only `{crate_id, code_site_id}`, and `RUST_BACKTRACE` SHALL be disabled in production units. | INC-58 | THR-016 | all | TST: induced panic produces only a coded event |
| BE-028 | Trust-path logging SHALL use only `candor-log` typed events with the §9.1 field types. `println!`/`log`/`tracing` macros SHALL be banned by CI, and dependency logs SHALL go to a null subscriber except allow-listed mapped codes. | ADR-016 | THR-016; THR-038 | all | TST: clippy `disallowed-macros` in CI; runtime test that dependency log output is suppressed |
| BE-029 | Intake-gw journald SHALL be volatile. Tor logging SHALL be disabled or SafeLogging-only with no persistent file. The self-test SHALL verify both. | ADR-016; B-SD-21 | THR-016; THR-001 | C-05; C-25 | TST: health checks `journald_volatile`, `tor_log_off` |
| BE-030 | SOURCE-SENSITIVE counters SHALL be kept only per calendar month and exported once after month close under the 24 §TEL regime (k = 10, complementary suppression, no per-channel cells for channels with < 3 cases/month). | ADR-016; ADR-046(5); RVW-B-07 | THR-039 | C-08; C-09 | TST: counter export tests with small cells and complementary suppression; no daily export exists |
| BE-031 | Wall-clock access on intake-gw trust-path code SHALL be limited to `SourceClock::today()` (day resolution). A lint SHALL ban other wall-clock APIs there. | ADR-010 | THR-011 | C-06; C-07; C-08 | TST: `time-lint` |
| BE-032 | Services SHALL detect clock insanity (§12) and fail closed as specified. Epoch-key selection SHALL tolerate exactly one day of skew. | ADR-010 | THR-043 | C-07; C-08; C-21 | TST: clock-skew injection |
| BE-033 | Every failure listed in §13 SHALL produce the specified fail-closed behavior. No component SHALL fall back to plaintext storage, clearnet, unverified keys or an alternative notification channel. | ADR-002; ADR-004 | THR-040; THR-035 | all | TST: fault-injection suite (one test per §13 row) |
| BE-034 | The audit append SHALL precede business commit (two-phase with reconciliation). Failure to append SHALL abort the mutation. | ADR-016 | THR-037; THR-018 | C-24; C-10 | TST: audit outage makes mutations fail; reconciliation test |
| BE-035 | Audit chains SHALL be hash-chained per class per tenant and checkpoint-signed every ≤ 1,000 events or ≤ 10 min, with the signing key in TPM or HSM. | ADR-016 | THR-037 | C-24 | TST: chain verification tool; tamper detection test |
| BE-036 | The key directory store SHALL be append-only (DB privileges + trigger). Checkpoints SHALL be signed at the fixed daily time, at the weekly publication slot and immediately after removals/revocations, SHALL carry the witness quorum required by the profile, and SHALL be delivered to intake in signed snapshots with consistency proofs. | ADR-022; ADR-036(5)/(7); INC-14; RVW-A-29 | THR-046 | C-14 | TST: UPDATE/DELETE rejected; snapshot verification tests; split-view test with witnesses; checkpoint times match the schedule |
| BE-037 | The notification service SHALL send only template T1 with the instance label, only in `daily_constant` mode (one message per subscribed staff member per day at the fixed time, regardless of activity) or not at all (`off`), to allow-listed hosts, and SHALL never message sources. | ADR-017; ADR-038(2); INC-57; RVW-A-19; RVW-C-02 | THR-028; THR-011 | C-23 | TST: output golden test; egress allow-list test; send log identical on days with and without imports |
| BE-038 | The health agent SHALL run the §5.11 checks every 5 min ± 60 s and SHALL push only schema-fixed events. The monitor collector SHALL reject events that fail the schema. | ADR-028; INC-106 | THR-035; THR-016 | C-25 | TST: collector schema fuzzing; check coverage test |
| BE-039 | The resource limits in §11 SHALL be enforced at the stated layer, and exceeding them SHALL produce the stated response without crashing or leaking state. | ADR-026; INC-110 | THR-032; THR-033 | C-05..C-10 | TST: load and abuse suite (≥ 1,000 parallel anonymous uploads while a legitimate upload completes) |
| BE-040 | Circuit tokens used for rate limiting SHALL exist only in RAM and SHALL be dropped at connection close. | ADR-026 | THR-001 | C-06 | TST: compile-fail serialization test; heap scan after close |
| BE-041 | HTTP on the source socket SHALL be HTTP/1.1 only, with no pipelining, no compression, and header limits per §5.1. | INC-116; B-GL-40 | THR-032; THR-004 | C-06 | TST: request smuggling/pipelining conformance suite |
| BE-042 | Source Web templates SHALL auto-escape all output and SHALL contain no raw-HTML filters, inline scripts or inline styles. | INC-117; B-GL-39 | THR-008 | C-06 | TST: template lint; XSS polyglot corpus render test |
| BE-043 | The intake SHALL refuse new envelopes when free disk < 15 % while continuing to serve replies, and the relay SHALL stop claiming under core backpressure (§5.4). | ADR-026 | THR-032; THR-042 | C-08; C-09 | TST: disk-fill and backpressure tests |
| BE-044 | Secrets SHALL be provided only via systemd encrypted credentials (TPM2-sealed where available) and listed in the Secret Placement Manifest. There SHALL be no secrets in environment variables or bootstrap files. | ADR-028; INC-106 | THR-013 | all | TST: manifest checker; env scan |
| BE-045 | EE modules SHALL NOT link `candor-core` private-key APIs and SHALL NOT be loaded into trust-path processes. | ADR-020 | THR-027 | C-26; C-34; C-40 | TST: `cargo tree` dependency check `trust-path-deps` |
| BE-046 | The web service SHALL enforce one in-flight request per connection and close connections after any error response. | INC-116 | THR-021 | C-06 | TST: pipelining test |
| BE-047 | Sealer and web memory for plaintext SHALL be drawn from a pre-allocated locked slab pool (4,096 × 64 KiB). Exhaustion SHALL produce `BUSY`, never unlocked allocation. | ADR-004 | THR-014 | C-06; C-07 | TST: pool exhaustion test; VmLck assertion |
| BE-048 | The intake routing private key SHALL be used only for decrypting reply routing blobs in `candor-intake-store`, and SHALL be loaded only via encrypted credential. | ADR-028 | THR-013; THR-015 | C-08 | INSP; TST: manifest |
| BE-049 | Tier V envelopes SHALL be validated for canonical structure, size bucket membership and exactly 16 fixed-size anonymous slots with no cleartext recipient data. Invalid envelopes SHALL be rejected with no storage. | ADR-004; ADR-011; ADR-033; INC-117 | THR-012; THR-033 | C-06 | TST: envelope conformance corpus |
| BE-050 | Services SHALL refuse to start on DB schema hash mismatch, invalid config signature, or missing Secret Placement Manifest entries. | ADR-028 | THR-035 | all | TST: startup negative tests |
| BE-051 | The sealer SHALL apply the COI filter in RAM at `SEAL_FINISH` using only the verified directory snapshot, to the channel's **Triage Set** only, honouring `effective_day` time locks. It SHALL wrap the content key only to eligible Triage Set members in 16 anonymous slots (dummies for the rest, random order), put the signed recipient list inside the payload, and return `NO_ELIGIBLE_TRIAGE` with the alternative channel when no eligible Triage Set member remains. | ADR-030; ADR-033; ADR-015; ADR-036(2); ADR-037(1); INC-22 | THR-020; THR-046 | C-07 | TST: COI matrix tests on the sealer (all selections × rosters × time locks); TST: slot indistinguishability (size, order); TST: non-triage member never in a slot |
| BE-052 | A source's COI selection and the original eligible set SHALL persist only inside `prefs_ct`, encrypted to the source's own X-Wing key. Follow-ups SHALL be sealed only to members who were in the original eligible set **and** are still active members; members added later never receive follow-up slots. The intake store SHALL never hold either in cleartext. | ADR-030; ADR-010; ADR-036(4); RVW-A-06 | THR-020; THR-015 | C-07; C-08 | TST: intake DB inspection after a COI submission; TST: add a member after the first report, send a follow-up, verify no slot opens for the new member |
| BE-053 | `candor-ekv` SHALL run as its own OS user with the §4.2 baseline, `PrivateNetwork=yes` and memory locking. It SHALL expose only the §5.12 operations to the `candor-case` and `candor-worker` UIDs. | ADR-033; ADR-028 | THR-017; THR-013 | C-12 | TST: IPC peer tests; unit hardening check |
| BE-054 | The relay SHALL NOT persist pull timestamps (no job rows for slots; import rows carry the slot date and slot number only). No job SHALL be triggered by an import. | ADR-033(4); ADR-038(1) | THR-011 | C-09; C-10 | TST: DB and audit inspection after relay cycles |
| BE-055 | Tier W draft text, identity blocks and COI ticks SHALL exist only in sealer mlocked RAM keyed by the session handle, on every path including errors. Attachment parts SHALL be encrypted under a per-session key held only in sealer RAM and staged only as ciphertext in the tmpfs staging area. No content key SHALL be wrapped to any recipient before `SEAL_FINISH`. One timer set applies: idle 20 min, absolute 2 h; expiry zeroizes RAM state and deletes staged parts. | ADR-034; RVW-A-02; RVW-A-07; RVW-B-12 | THR-014; THR-011; THR-017 | C-06; C-07; C-08 | TST: fanotify zero-write on persistent filesystems during draft, abandon and error flows; AT (30): image C-08 disk, WAL and BS-INTAKE snapshot after those flows finds no draft ciphertext or sub-day time; TST: back-navigate after upload, change ticks, submit, and assert no slot for the excluded member in any object |
| BE-056 | A new Tier W account and its first envelope SHALL be committed only after `CONFIRM_PASSPHRASE` succeeds for 3 randomly chosen words. The passphrase SHALL never be persisted or re-displayable after the session. | ADR-034; RVW-B-13 | THR-034 | C-07; C-08 | TST: dropped S10 response leaves no account or envelope; memory and disk scans for the passphrase after commit |
| BE-057 | The relay SHALL import only at fixed configured slots (default 4×/day; HIGH/GOV 1×/day), SHALL commit all rows of a slot in one transaction at `slot_start + slot_commit_offset`, SHALL set C-13 blob mtime/atime to `slot_start`, SHALL keep S3 versioning off, and SHALL never import on arrival or on demand. | ADR-038(1); RVW-A-09; RVW-B-06; RVW-C-02 | THR-011; THR-017 | C-09; C-12; C-13 | TST: Poisson arrival simulation, then `pg_waldump`, blob `stat`, S3 metadata and backup inspection show only slot times; AT (30): timing-correlation audit |
| BE-058 | Staff notifications SHALL be constant-schedule: one content-free message per subscribed staff member per day at a fixed time regardless of activity, or none. Neither the addressee set nor the send time SHALL depend on imports or on the receiving channel. | ADR-038(2); ADR-017; RVW-A-19; RVW-B-05 | THR-028; THR-011 | C-23 | TST: χ² test over 1,000 randomized submissions shows send times and addressee sets independent of submissions and channels |
| BE-059 | The key directory service SHALL refuse to append roster additions, role-label changes, Triage Set changes and COI-map loosening without dual approval including an independent-role approver, SHALL set `effective_day` per `kd.roster_timelock_days`, and SHALL notify all current members and OVERSIGHT content-free; removals and tightening SHALL be immediate. | ADR-036(1)–(3); RVW-A-05; RVW-C-05 | THR-046; THR-020 | C-14; C-10 | TST: governance matrix tests; sealer ignores entries before `effective_day` |
| BE-060 | The intake SHALL take time only from the Tor consensus window and ≥ 2 Roughtime sources over Tor, never from Z-CORE, and SHALL reject directory snapshots below its persisted high-water mark and SHALL refuse to seal to snapshots whose newest checkpoint is older than 7 days by that clock (amended r3, ADR-047(4)). | ADR-036(6); RVW-A-04; RVW-A-23 | THR-043; THR-046 | C-05; C-07; C-08 | TST: frozen-snapshot and clock-skew injection from core; rollback snapshot rejected; restore keeps the high-water mark |
| BE-061 | `MEMBER_EPOCH_KEY` and time-locked governance entries SHALL be appended only at the weekly publication slot; checkpoints SHALL be issued at the fixed hourly cadence only (amended r3 to match 04-CRYPTOGRAPHY.md §14.3); removals, revocations and incident notices SHALL be appended immediately. | ADR-036(7); RVW-A-29 | THR-011; THR-046 | C-14 | TST: log inspection shows append days only on the slot weekday except security exceptions |
| BE-062 | Delayed-delivery envelopes SHALL be held on the intake until `release_day` = `received_date` + U{1,2,3} and SHALL be offered to the relay only from that day. | ADR-038(4); RVW-B-11 | THR-011 | C-07; C-08; C-09 | TST: claim tests; delay distribution test |
| BE-063 | The intake SHALL serve the published reply set (all non-expired replies, ≤ 30 days) in fixed pages of 64 entries padded to 70,000 bytes with a power-of-two page count, identical for every requester and rebuilt only at import slots, and SHALL record no per-mailbox access state. | ADR-039; RVW-A-10; RVW-A-26 | THR-011; THR-015 | C-08 | TST: byte-identical pages for two clients; no access columns; page-count padding test |
| BE-064 | Source quota SHALL be enforced per session in RAM plus a per-account counter for the current day only, reset daily, with no history. | ADR-038(3); RVW-A-26; RVW-B-11 | THR-011; THR-032 | C-06; C-08 | TST: quota reset job; DB inspection shows no history |
| BE-065 | SCIM/HR/IdP-driven changes SHALL only suspend server-side authorization. Case-key wrap rows SHALL be deleted only by case crypto-erasure or by an executed `wrap_deletion_request` after dual approval, a 7-day cooling-off and an OVERSIGHT notice, and never below `min_recipients` (default 2) holders. | ADR-044(1)/(2); RVW-C-03 | THR-020; THR-032 | C-10; C-21; C-22 | TST: deprovisioning leaves wraps; early execution refused; last-holder test |
| BE-066 | The Erasure Key Vault SHALL be replicated to the DR site within the HA RPO (EE-HA), SHALL export backups re-encrypted to the Backup Public Key, and every restore SHALL apply the newest verified erasure log before services serve requests. HIGH/GOV vaults SHALL use a physical TPM or HSM. | ADR-044(4); RVW-C-06; RVW-C-07 | THR-017; THR-031 | C-12; C-27 | TST: restore drill with a pre-erasure backup shows the erased case absent before first request; replacement-hardware vault restore drill; INSP: TPM type check in self-test |
| BE-067 | Trust-path services SHALL refuse to start when installed OS, tor or PostgreSQL packages differ from the TUF-signed Platform Manifest or when their release is below the signed security floor; Fleet policies SHALL NOT override this. | ADR-040; RVW-A-12; RVW-A-13 | THR-024; THR-025 | all server components; C-25 | TST: tampered package and below-floor startup tests; fleet policy override test |
| BE-068 | The intake SHALL produce and sign the running manifest (08-API.md §7.1) from the installed release, Platform Manifest and static assets at start and after every update, and SHALL append its digest to C-14 as `SERVER_RELEASE` via the relay. | ADR-035(1); ADR-040; RVW-A-01; RVW-A-13 | THR-007; THR-025 | C-06; C-07; C-14 | TST: manifest regenerated after update and matches TUF hashes; external-watcher harness |
| BE-069 | Envelopes pending > 14 days SHALL be offered for dual-approved rejection; rejected envelopes SHALL be deleted immediately; escalations SHALL be limited to one per channel per 7 days. | ADR-038(6); ADR-033(2); RVW-A-20 | THR-020; THR-033 | C-10; C-14 | TST: all-dummy envelope flood does not produce more than one escalation per week and does not pin keys after dual rejection |
| BE-070 | The intake SHALL implement the upload protocol of 08-API.md §5.1 exactly (8 MiB chunks, ≤ 512 chunks, ≤ 2,048 only in EE profiles, 24-h RAM-tracked expiry, no cross-session resume, no Tier W resume). | ADR-046(4) | THR-047; THR-032 | C-06; C-08 | TST: boundary and expiry tests |
| BE-071 | `COMMIT_ENVELOPE` SHALL return success only after rows and blobs are `fsync`ed locally; the intake DB SHALL NOT be replicated in any profile. | ADR-046(1); RVW-C-08 | THR-017 | C-08 | TST: power-cut fault injection; `pg_params` on EE-HA |
| BE-072 | The sealer SHALL support passphrase rotation from the Tier W inbox, re-encrypting pending replies in RAM and sealing a key-update follow-up to the original eligible set. | ADR-046(7); RVW-A-03 | THR-034 | C-07; C-08 | TST: rotation e2e; old passphrase rejected |
| BE-073 | No response to sources and no off-host export SHALL reveal Argon2id queue, rate-limit, new-account-cap, staging or relay-backlog state finer than a global daily health band; busy pages SHALL be identical for all causes. | ADR-038(5); ADR-046(5); RVW-A-27; RVW-B-07 | THR-011; THR-039 | C-06; C-07; C-25 | TST: collector payload inspection; busy-page byte-identity |
| BE-074 | (Amended r3, ADR-047(9)) Every source-initiated account, mailbox or reply deletion SHALL append a K31-signed entry to the intake deletion list in the same transaction; the relay SHALL copy the list to Z-CORE at every import slot; any intake restore or failover SHALL obtain the newest verified list (local or pushed back from Z-CORE) and apply it before serving; listed replies SHALL be dropped and never re-pushed. | RVW-A-28; ADR-025; ADR-047(9) | THR-017 | C-08; C-09 | TST: delete, restore older snapshot, re-push replies; account and replies absent before first request served |
| BE-075 | The sealer SHALL generate chaff envelopes per §5.2a (per-channel Poisson schedule in RAM, mean `intake.chaff.mean_interval` ≤ 2 h, identical format and write path, chaff-kind `disposition_ct`), SHALL cancel the next chaff event on each real commit, and SHALL exclude chaff from counters and status bands. | ADR-047(3); RVW-B-04; RVW-A-09 | THR-110; THR-011 | C-07; C-08 | TST: inter-commit times Poisson goodness-of-fit; byte-level comparison of chaff and real rows/blobs; counters exclude chaff; AT excluded-member inference (30) |
| BE-076 | The `chaff_discard` job SHALL open `disposition_ct` only at an envelope's derived hold slot, delete chaff rows and blobs at the fixed post-slot time, emit no chaff-specific event or count, and treat chaff as disposed for Member Epoch Key retirement. | ADR-047(3) | THR-110 | C-10; C-12 | TST: chaff removed within 8 slots; audit/event scan; epoch retirement not blocked |
| BE-077 | `candor-ekv` SHALL provide `META_SEAL`/`META_OPEN` under the EK-derived `K_meta` and `REKEY_MISSING` for dual-approved Desk re-wrap after vault restore or loss; C-10 SHALL store `case_meta` only via these operations. | ADR-047(7); ADR-047(8) | THR-017; THR-042 | C-10; C-12 | TST: DB contains only `meta_ct`; vault-restore drill re-wraps a post-backup case |
| BE-078 | Source signals (C4 "no response" escalation, mailbox-closed) SHALL be sealed as SOURCE_MESSAGE kinds 2/3 by `SEAL_SIGNAL` and committed with `release_day` offsets U{1,2,3} and U{3..21} days respectively, travelling the ordinary envelope path; no other intake-to-core signal path SHALL exist. | RVW-B-26; ADR-038(4) | THR-011; THR-019 | C-07; C-08; C-09 | TST: signal envelope structurally identical to follow-ups; release-day distribution; no signal route in RL-* |

## 15. Residual risks and limitations

- **Live-compromise exposure:** root on intake-gw can read the sealer's memory despite `mlock`/`dumpable=0`. This is unavoidable (06 R-1). The controls reduce *accidental* persistence (swap, dumps, logs), not active compromise.
- **Login throttles:** global Argon2id throttles enable a DoS against logins (THR-032). PoW and queueing reduce but do not remove this. Tier V clients do their own KDF and are unaffected.
- **Timing floor:** the `T_LOGIN_FLOOR` (3 s default) login floor hides existence only against request-level timing. It does not hide it against a network observer seeing follow-on page sizes. Pages are therefore padded to the same class for "wrong passphrase" and "inbox" responses (08-API.md).
- **Audit ordering:** the two-phase audit leaves a window in which a pending audit row exists for an aborted mutation. The reconciliation job marks it `aborted`, which is visible and not deleted.
- **systemd sandbox:** sandboxing depends on kernel correctness. A kernel exploit bypasses it.
- **Drafts lost on restart (accepted, ADR-034):** a sealer or intake-store restart, or 2 h of drafting, loses the source's draft; the UI states this.
- **Import latency (accepted, ADR-038):** envelopes wait on the intake until the next fixed slot (≤ 6 h default, ≤ 24 h HIGH) plus any delayed-delivery hold; more ciphertext therefore resides on the intake disk at any time. Slot identity (hours) remains visible in Z-CORE.
- **Slot overrun:** if processing a slot exceeds `slot_commit_offset`, the commit time reflects processing duration, which correlates weakly with batch volume; this is alerted and the offset is sized per 34-PERFORMANCE-SCALABILITY.md.
- **Removal timing:** removals and revocations are published immediately (ADR-036(2)), so their timing is visible in the directory (RVW-A-29 residual).
- **Independent time:** Roughtime over Tor depends on server availability and TCP transport support (Knowledge (unverified)); if unavailable, the Tor consensus window alone bounds the clock to about ±3 h, which is enough to block freeze attacks longer than the snapshot freshness bound but not shorter ones.
- **Tier W live compromise:** the controls above bound persistence, not live capture (ADR-035(5) honesty text applies).
- **Chaff limits (ADR-047(3)):** chaff hides arrival times on the intake disk only while a channel's real rate is below the chaff rate; intake RAM compromise reveals the schedule; C-10 learns which envelopes were chaff at the hold slot. Chaff adds intake disk and relay load (≈ 12 envelopes per channel per day, sized in 34).

## 16. Open issues

| # | Issue | Proposal |
|---|---|---|
| O-1 | ADR-019 names axum/hyper. Using raw hyper plus an in-house router for the source socket reduces surface but diverges from "axum". | Use axum for Desk/Admin routers and a minimal hyper service for `candor-web`. Record as a clarification in ADR-019. |
| O-2 | Resolved by ADR-046(7): Argon2id m = 64 MiB, t = 3, p = 1 with a concurrency semaphore of 4 plus PoW. | — |
| O-3 | The 72-h DANGEROUS cool-off may conflict with urgent incident response (e.g., disabling a compromised feature). | Allow *tightening* changes (disable features) as ADVANCED with no delay; only *loosening* changes are DANGEROUS. Confirm in 32-OPERATIONS.md. |
| O-4 | Resolved by ADR-046(12) for the Intake Routing Key and Connector Key; the Backup Key is owned by 19-BACKUPS-DR.md and 04. | — |

### Open Issues for ADR revision
- **ADR-019:** router library clarification (O-1).
- **ADR-008:** add Intake Routing Key and Backup Key — Resolved by ADR-046(12) (routing and connector keys).
