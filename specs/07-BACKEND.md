# 07 — Backend Services

Status: Draft v1.0 · Edition applicability: both (EE-only items marked **EE**) · Owner: Backend team

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
| DECISIONS.md ADR-004/005/009/010/016/019/026/027/028/029 | Binding decisions implemented here |
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
| `candor-intake-store` | `candor-istore` | intake-gw | rw: `/var/lib/candor/intake/blobs`; PG via Unix socket | TCP 7443 listen on relay interface only | no | disabled |
| PostgreSQL (intake) | `postgres` | intake-gw | `/var/lib/postgresql` | Unix socket only (`listen_addresses=''`) | no | disabled |
| `candor-relay` | `candor-relay` | core | PG role `candor_relay`; blob store write | TCP to intake 7443 only (nft `skuid`) | no | disabled |
| `candor-case` | `candor-case` | core | PG role `candor_case`; blob store rw | Unix listeners (desk.sock, admin.sock) or TCP 8443/9443 | no | disabled |
| `candor-auth` | `candor-auth` | core | PG role `candor_auth`; TPM/HSM access group | Unix socket only | yes (session signing keys) | disabled |
| `candor-keydir` | `candor-keydir` | core | PG role `candor_kd` (append-only) | Unix socket; outbound witness HTTPS (optional, via egress proxy) | no | disabled |
| `candor-notify` | `candor-notify` | core | PG role `candor_notify` | egress to allow-listed SMTP/HTTPS only | no | disabled |
| `candor-audit` | `candor-audit` | core | DB `candor_audit` role `candor_audit_w` (INSERT only); checkpoint key via TPM/HSM | Unix socket only | yes | disabled |
| `candor-ekv` | `candor-ekv` | core | rw `/var/lib/candor/ekv` (0700); TPM/HSM access for the Vault Master Key | Unix socket only (`/run/candor/ekv/ekv.sock`, peers `candor-case`, `candor-worker`) | yes | disabled |
| `candor-worker` | `candor-worker` | core | PG role `candor_worker` | calls local services via Unix sockets | no | disabled |
| `candor-health` agent | `candor-health` | all | read-only host facts; no application data dirs | TCP 8514 to monitor | no | disabled |
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

After every request:
- Tier W session material (derived source keys, seed, passphrase bytes) is zeroized on logout, idle timeout (20 min), absolute timeout (2 h) or sealer restart.
- The passphrase is zeroized immediately after derivation. It is never retained for the session.

### 4.5 Supervisor behavior

| Condition | Action |
|---|---|
| Crash of any intake process | systemd `Restart=on-failure`, `RestartSec=2s`, `StartLimitBurst=5/60s`. After the burst the unit stays failed and the health agent raises `SYSTEM:service_failed`. Restarting the sealer drops all in-RAM drafts and sessions, and sources see a generic "please retry" page. |
| Config bundle signature invalid | Service refuses to start (§7.4) |
| Schema version mismatch | Service refuses to start |

## 5. Modules

### 5.1 Intake web (`candor-web`, C-06)

| Submodule | Specification |
|---|---|
| HTTP stack | `hyper` 1.x server (HTTP/1.1 only on the onion socket; HTTP/2 disabled to reduce parsing surface; no pipelining: one in-flight request per connection, `Connection: close` after error). Request line ≤ 4 KiB; total headers ≤ 16 KiB; ≤ 50 headers. No compression, either inbound (`Content-Encoding` rejected) or outbound. |
| Router | Deny-by-default registry. Each route is declared with `route!{ method, path, audience, auth, csrf, pad_class, body_limit, handler }`. A CI test (`route-registry-lint`) fails if any handler is reachable without a declaration, or if any declaration lacks `audience` or `auth` (ADR-029). The audience is `source-web` or `source-app`, and paths are prefixed `/app/v1/` for the latter. |
| Multipart parser | In-house streaming parser (no framework auto-parse; INC-107). Allowed part names come from the route declaration. The first unexpected part aborts with 400 before any byte is forwarded. Per-part header ≤ 1 KiB. Filename ≤ 255 bytes, UTF-8, NFC-normalized, and then treated as **encrypted metadata only** (never a path). Max parts per request: 3 (message text, one file, CSRF token). |
| Templates | `askama` compile-time templates with auto-escaping. There is no raw-HTML filter in the template set (a CI grep bans `|safe` and `PreEscaped`). There are no inline scripts or styles. One CSS file is referenced by hash path `/static/<sha256>.css`. |
| Sessions | In-RAM map `SessionId(128-bit random) → SessionState`. Max 10,000 sessions. Idle 20 min, absolute 2 h. The cookie is `__Host-cs` (Secure; HttpOnly; SameSite=Strict; Path=/). No persistent state. A restart logs everyone out. |
| CSRF | Synchronizer token (256-bit) per session per form, verified in constant time. Also: `Origin` must be absent, `null`, or equal to this onion origin. |
| Rate limiting | Token bucket keyed by `EphemeralCircuitToken` (06 §11), in RAM only, plus global buckets. Values in §11. |
| Padding | The response body is padded (HTML comment filler) to the route's `pad_class`: 16, 32, 64 or 128 KiB. Headers are fixed-order, fixed-set. |
| Headers | Fixed set per 08-API.md §4.3. No `Server`, `Date`, `ETag` or `Last-Modified`. |
| Tier V validator | Validates canonical envelope CBOR (04-CRYPTOGRAPHY.md): exact field set and lengths, size bucket membership, and exactly 16 fixed-size anonymous recipient slots (ADR-030, ADR-033 §1). The server cannot and does not check recipients: slots carry no key IDs, and the signed recipient list is inside the AEAD payload. It never inspects ciphertext. |

### 5.2 Sealer IPC protocol (`candor-web` ↔ `candor-sealer`)

**Transport and framing:**
- `AF_UNIX`, `SOCK_SEQPACKET`; one datagram = one message; max datagram 80 KiB.
- The sealer checks `SO_PEERCRED.uid == uid(candor-web)` on accept and closes otherwise.
- Message = deterministic CBOR map `{ "v": 1, "op": u8, "rid": u32, "body": map }`.
- Responses echo `rid`.
- Unknown `op`, extra keys or oversize fields produce `ERR{code}` and close the connection.

**Operations:**

| op | Name | Request body | Response body | Limits / notes |
|---|---|---|---|---|
| 0x01 | `HELLO` | `{proto: 1}` | `{proto: 1, snapshot_version: u64}` | First message on every connection |
| 0x10 | `GEN_ACCOUNT` | `{sess: [u8;16]}` | `{words: [u16;10]}` (EFF large list indices) | Creates a pending session holding the seed. The seed is derived via Argon2id in sealer. Passphrase words are returned once for display, and the sealer keeps no copy after derivation. |
| 0x11 | `LOGIN_DERIVE` | `{sess, passphrase: bytes ≤ 256}` | `{locator_hash: [u8;32]}` | Argon2id (m = 256 MiB, t = 3, p = 1, per-deployment salt). Global concurrency 4. Queue ≤ 32. Queue wait ≤ 30 s, else `BUSY`. |
| 0x12 | `LOGIN_SIGN` | `{sess, challenge: [u8;32]}` | `{sig: [u8;64]}` | Ed25519 signature by the source auth key over `"candor-src-auth-v1" ‖ tenant_id ‖ challenge` |
| 0x13 | `LOAD_PREFS` | `{sess, prefs_ct: bytes ≤ 4 KiB}` | `{}` | After successful login. Decrypts the source's own preferences (COI selection, language) with the source X-Wing key, in RAM. |
| 0x20 | `SEAL_BEGIN` | `{sess, channel_id, coi: {excluded_labels: [u16] ≤ 16, categories: [u16] ≤ 8} \| null, part_kind: message\|file, followup: bool}` | `{part: [u8;16], recipients: u8}` | On the first part, computes the eligible set from the verified snapshot: channel roster minus source-selected role labels minus COI-map exclusions for the selected categories, restricted to members with a Member Epoch Key valid today (ADR-030). For follow-ups, `coi` is null and the selection is taken from the decrypted account preferences (`prefs_ct`, loaded at login). Refuses with `NO_ELIGIBLE_RECIPIENTS` if the eligible count is < the channel's `min_recipients` (§13). |
| 0x21 | `SEAL_CHUNK` | `{part, data: bytes ≤ 65536, last: bool}` | `{ct: bytes}` | STREAM chunk encryption. Plaintext slab zeroized after encryption. |
| 0x22 | `SEAL_FINISH` | `{sess, parts: [part], meta: {filenames: [text ≤ 255], lang: text ≤ 16}}` | `{header_ct (16 anonymous fixed-size HPKE slots, random order, no key IDs), manifest_ct (includes the recipient list of key IDs + directory tree head, signed with the source's Ed25519 key (ADR-005); exact construction in 04-CRYPTOGRAPHY.md), account: {locator_hash, auth_pk, xwing_pk, prefs_ct} \| null}` | Manifest (encrypted) contains per-part DEKs, display names and `thread_tag`. `account` is non-null only on first submission. |
| 0x23 | `SEAL_ABORT` | `{sess}` | `{}` | Drops the draft |
| 0x30 | `OPEN_REPLIES` | `{sess, cts: [bytes ≤ 70000] ≤ 64}` | `{pts: [bytes]}` | Decrypts with the source X-Wing key. Plaintext returned for immediate rendering. |
| 0x31 | `SEAL_SOURCE_MESSAGE_ACK` | — | — | Reserved; not implemented (no read receipts, ADR-010) |
| 0x40 | `ZEROIZE` | `{sess}` | `{}` | Idempotent |
| 0x7F | `STATUS` | `{}` | `{sessions: u16, argon_queue: u8, pool_free: u16}` | SYSTEM metrics only |

**Error codes:** `BAD_FRAME`, `UNKNOWN_SESSION`, `BUSY`, `NO_ELIGIBLE_RECIPIENTS`, `LIMIT`, `CRYPTO`, `INTERNAL`. Errors carry no other data.

**Session state machine (per `sess`):**

```
NONE -> PENDING_NEW (GEN_ACCOUNT) -> DRAFTING (SEAL_BEGIN) -> COMMITTED (SEAL_FINISH ok) -> AUTHENTICATED
NONE -> DERIVED (LOGIN_DERIVE) -> AUTHENTICATED (LOGIN_SIGN ok, confirmed by web) -> DRAFTING -> AUTHENTICATED
any  -> NONE (ZEROIZE | idle 20 min | absolute 2 h | restart)
```

### 5.3 Intake store (`candor-intake-store`, C-08)

- **IPC to web** (`/run/candor/istore/istore.sock`, SEQPACKET, peer = `candor-web`). Operations:
  - `PUT_PART(draft, ct_chunk)`, `DISCARD_DRAFT`, `COMMIT_ENVELOPE`;
  - `ACCOUNT_CREATE`, `AUTH_CHALLENGE(locator_hash)`, `AUTH_VERIFY(locator_hash, challenge, sig)`;
  - `MAILBOX_LIST(account)`, `MAILBOX_GET`, `MAILBOX_DELETE`, `ACCOUNT_DELETE`;
  - `UPLOAD_CREATE`, `UPLOAD_CHUNK`, `UPLOAD_STATUS`.
  - All take and return typed CBOR. The store never receives plaintext.
- **Uniform challenge:** `AUTH_CHALLENGE` returns a fresh 32-byte challenge whether or not the locator exists. For unknown locators, verification later fails with the same error and timing class (§11). This resists account enumeration.
- **Blob layout:**
  - `/var/lib/candor/intake/blobs/<2-char prefix>/<26-char base32 object id>`, created through `candor-safefs` with `O_CREAT|O_EXCL`, mode 0600.
  - Object IDs are random 128-bit. File names never derive from source input.
  - Blob files are written with `O_DIRECT` disabled but `fdatasync` on commit.
- **Relay export endpoint:** rustls TLS 1.3 server on the relay-link interface, TCP 7443. It requires a client certificate equal to the pinned relay certificate (SPKI SHA-256 pin from the signed config) and verifies Ed25519 request signatures (§5.4).
- **Routing key:** the Intake Routing Key private half is loaded from a systemd credential (`LoadCredentialEncrypted=`, TPM-sealed where available) and used only in `APPLY_REPLIES`.
- **Local jobs:** the intake store runs its own job loop on the intake DB (§6.3).

### 5.4 Relay pull protocol (`candor-relay`, C-09 ↔ intake export)

**Authentication (each direction):**
- TLS 1.3 with mutually pinned Ed25519 certificates.
- Each request carries `Candor-Relay-Sig: ed25519(relay_key, method ‖ path ‖ sha256(body) ‖ req_counter)`.
- `req_counter` is a strictly increasing u64 persisted on both sides. Replays are rejected.

**Cycle algorithm** (per intake instance; per tenant in EE):
```
every U(5, 25) min:
  1. GET  /relay/v1/health                     -> abort cycle if not "ok"
  2. POST /relay/v1/batches/claim {max_objects: 500, max_bytes: 2 GiB}
        -> {batch_no, objects:[{ref, kind, padded_size, sha256}]}
  3. for each object: GET /relay/v1/batches/{batch_no}/objects/{ref}
        verify sha256 and canonical structure; stream blob to C-13 via candor-safefs;
        insert import_envelope with NEW random id (intake ref not stored), received_date and batch_no only (no pull time, ADR-033 §4)
     commit per envelope (all parts or none)
  4. POST /relay/v1/batches/{batch_no}/ack {sha256[] of committed envelopes}
  5. POST /relay/v1/replies           (≤ 500 sealed replies from reply_outbox, state→pushed on 200)
  6. POST /relay/v1/directory-snapshot (if kd version advanced)
  7. POST /relay/v1/config            (if signed bundle version advanced)
  8. POST /relay/v1/deletions         (source-initiated deletions are local to intake; this carries retention-driven reply purges)
  9. GET  /relay/v1/counters          (daily, k-anonymized per §9.5)
 10. GET  /relay/v1/backup-snapshot   (daily, opaque blob encrypted to Backup Key)
```

**Intake-supplied data is untrusted.** The relay accepts only:
- `kind` ∈ {initial, followup};
- `channel_id` belonging to the intake's tenant;
- a header with exactly 16 fixed-size slots and no other cleartext recipient data;
- `received_date` ∈ [today−14, today];
- `header_ct` ≤ 8 KiB, `manifest_ct` ≤ 64 KiB;
- parts ≤ 32, each padded size ∈ the bucket set.

Anything else is rejected, counted (SYSTEM) and left unacknowledged. After 3 failed cycles it is quarantined.

**Idempotency:** a unique index on `import_envelope.header_digest` (SHA-256 of `header_ct`) prevents double import. The digest is retained 30 days and then nulled (09-DATABASE.md).

**Backpressure:** if C-13 free space < 10 % or `import_envelope` pending > 50,000, the relay stops claiming and raises `SYSTEM:relay_backpressure`. Intake keeps buffering (06 R-8).

### 5.5 Case service (`candor-case`, C-10)

| Aspect | Specification |
|---|---|
| Routers | `desk`, `admin`, `export` (EE connector), each its own listener, audience and route registry (08-API.md) |
| Request pipeline | TLS/onion → audience + token verification (via `candor-auth` Unix call, cached ≤ 30 s per token) → tenant context bind (`SET LOCAL candor.tenant_id`, `candor.user_id`) → schema validation (serde `deny_unknown_fields`, explicit per-route DTOs, no generic "set attribute" operations; INC-112) → **authorization** (§5.6) → handler → audit emit (fail-closed) → response |
| Concurrency | Optimistic: every mutable row has `version BIGINT`. Mutations carry `If-Match: <version>`. A mismatch returns 409. |
| Idempotency | Mutating Desk endpoints take an `Idempotency-Key` (128-bit client-generated). Stored 24 h per user. A replay returns the stored status code. |
| Key-wrap verification | On case create, member add and re-key, the service verifies that the set of `recipient_key_id`s in the wraps equals the eligible set returned by C-22 at that moment. Any extra wrap is rejected (THR-046). It verifies that each key is the current key-directory entry for the user. It cannot verify the ciphertext wraps themselves (no keys); Desk-side verification is in 12-FRONTEND-RECIPIENT.md. Before storing, each inner wrap is sealed under the case's Erasure Key by `candor-ekv` (§5.12; ADR-033 §3). On read, the caller's row is unsealed by `candor-ekv` and returned. |
| Blob I/O | Streaming to/from C-13 via `candor-safefs` (filesystem) or an S3 client (EE) with per-tenant prefix credentials. Max single object 4 GiB. |

### 5.6 Authorization engine integration (C-22)

- **Interface:** `fn authorize(p: &Principal, a: Action, r: &ResourceRef, ctx: &RequestCtx) -> Decision`.
  - `Decision = Permit { obligations: Vec<Obligation> } | Deny { reason: DenyCode }`.
  - `Obligation` examples: `RequireStepUp`, `RequireSecondApprover`, `AuditAs(CaseEventKind)`, `RedactField(FieldId)`.
- **Facts:** loaded per request inside the same DB transaction (role assignments, case ACL, COI exclusions, grants, legal holds). The engine is a pure function over `(facts, policy)`. The policy bundle is signed and versioned (15-AUTHENTICATION-AUTHORIZATION.md defines the language).
- **Route contract:** every route declares its `Action` and how the `ResourceRef` is derived (path parameter → loaded row → tenant, channel, case). The handler receives an `Authorized<T>` token type. Repository methods that return protected rows require `Authorized<T>`, so compile-time typing prevents unauthorized reads.
- **Deny mapping:** for resource-bound routes, `Deny` → **404 with uniform body** (08-API.md §3.4). For collection routes, the deny filters items. For actions on visible resources lacking a permission, 403 is returned only when the resource is already known to be visible to the caller. For example, a case member without export permission gets 403 on export.
- **Defense in depth:** Case DB RLS (tenant, plus case ACL for content-bearing tables) is enforced independently (09-DATABASE.md §6). Authorization does not depend on encryption state (INC-115).

### 5.7 SLA engine

- Timers are derived from the workflow definition (14-CASE-MANAGEMENT.md). Defaults for the EU channel template are acknowledgement ≤ 7 days and feedback ≤ 3 months (B-CO-02, Directive 2019/1937 Art. 9(1)(b),(f)).
- Timer fields: `kind`, `anchor_day` (EpochDay), `due_day` (EpochDay), `business_calendar_id`, `state ∈ {running, paused, met, breached, cancelled}`.
- The anchor for source-driven timers is `received_date` (day granularity; ADR-010).
- Evaluation job `sla_evaluate` runs daily at a jittered time 02:00–04:00 local, and on every workflow transition. A breach produces a content-free notification to case leads plus a CASE audit event.

### 5.8 Notification service (C-23)

- Only template `T1` exists: "Candor: secure case-management action requires attention" + instance label (≤ 32 chars, admin-set, SAFE). No case ID, count, channel or time (ADR-017).
- Delivery modes:
  - `digest` (default): at most one per recipient per hour, dispatched at uniformly random minute offsets.
  - `daily`: one per day.
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
  - `CHANNEL_ROSTER` (role labels ↔ member identity key IDs; signed by the channel identity key);
  - `MEMBER_EPOCH_KEY` (per member per channel per epoch, listed under the member's role label, signed by the member's identity key; ADR-030);
  - `COI_MAP` (category → excluded role labels; signed by the channel identity key);
  - `ROUTING_KEY` (intake routing public key);
  - `CONNECTOR_KEY` (**EE**, export connector encryption key);
  - `RECOVERY_QUORUM_STATE`;
  - `PROTECTION_STATEMENT`;
  - `CLIENT_RELEASE` (hash of Desk and Source App releases, copied from C-32);
  - `CONFIG_SIGNER` (admin signing keys).
- **Append:** only via `candor-case` after the approvals required by the entry type (e.g., `USER_KEY` needs admin approval plus a second admin for privileged roles; 15-AUTHENTICATION-AUTHORIZATION.md).
  - Entries are immutable. The PG role `candor_kd` has INSERT/SELECT only, and a trigger rejects UPDATE/DELETE.
- **Checkpoint:** signed by the directory key after each append batch (≤ 60 s). Pushed to intake via relay snapshot.
  - Optional witnesses cosign; Desk and Source App require ≥ 1 witness cosignature when witnesses are configured (THR-046).
- **Snapshot for intake:** checkpoint + all current (non-revoked) entries needed by sources + consistency proof from the previous snapshot. Signed. Intake verifies before exposing it at `/app/v1/directory/*` and to the sealer.

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
  - Member Epoch Key runway (days of valid keys ahead per member, alert < 14; channel alert when members with valid keys would drop below `min_recipients`);
  - relay lag;
  - clock offset;
  - TUF metadata expiry;
  - backup age.
- Output: `HealthEvent{host_role, check_id, status ∈ {ok, warn, fail}, value_bucket}`. There are no free-text fields. Pushed to the collector (TCP 8514, mTLS).

### 5.12 Erasure Key Vault (`candor-ekv`, ADR-033 §3)

- IPC ops: `CREATE(tenant, case)`, `SEAL(tenant, case, inner) → outer`, `UNSEAL(tenant, case, outer) → inner`, `DESTROY(tenant, case)`, `EXPORT_BACKUP`. The Erasure Key never leaves the process.
- AEAD: XChaCha20-Poly1305 (STD) or AES-256-GCM (FIPS), AAD = tenant ‖ case ‖ key_epoch ‖ recipient_key_id.
- Storage: 09-DATABASE.md §5.6. Excluded from routine backups; own backup stream with ≤ 14-day retention.
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
- Jobs triggered by imports (for example `notify_intake_available`) get `run_after` = the next hourly digest slot + U(0, 10 min), not an offset from the import time. They are deleted immediately on completion, so no job row preserves the import time (ADR-033 §4).

### 6.2 Z-CORE job types

| Kind | Runner service context | Trigger | Payload | Notes |
|---|---|---|---|---|
| (relay cycle) | relay | in-process timer U(5, 25) min; **no job row** | — | §5.4; avoids persisting pull times (ADR-033 §4) |
| `notify_intake_available` | notify | after an import batch commit | `{channel_id}` | Content-free digest to the channel roster. Servers cannot know recipients (anonymous slots). |
| `notify_digest_flush` | notify | hourly jittered | `{}` | |
| `sla_evaluate` | case | daily jittered + on transition | `{case_id?}` | |
| `retention_evaluate` | case | daily | `{}` | Enqueues `crypto_erase_case` for due cases without legal hold |
| `crypto_erase_case` | case | retention / manual dual-approved | `{case_id}` | `candor-ekv` DESTROY of the case Erasure Key first, then deletes all `case_key_wrap` rows, then blobs, then rows (35-DATA-RETENTION-DELETION.md; ADR-033 §3) |
| `import_escalate` | case | daily | `{}` | Pending `import_envelope` rows older than 7 days: set `escalated_date` and send a content-free escalation to the channel's independent escalation role. There is **no** automatic expiry (ADR-033 §2). |
| `ekv_backup` | ekv | daily | `{}` | Encrypted vault backup to its own stream; the store enforces ≤ 14-day retention |
| `epoch_runway_check` | keydir | daily | `{}` | Alerts per member when < 14 days of future Member Epoch Keys exist; per channel when fewer than `min_recipients` members would have valid keys |
| `epoch_key_destroy` | keydir | daily | `{}` | Marks a Member Epoch Key `destroy_due` only when its decrypt window has passed **and** no envelope of its channel and epoch is `pending` (ADR-033 §2). Each Desk deletes its private key on sync and acknowledges (DA-15). No private epoch key material exists server-side (ADR-030). |
| `blob_gc` | case | daily | `{}` | Removes unreferenced blobs > 24 h old |
| `audit_checkpoint` | audit | 10 min | `{class}` | |
| `audit_anchor` | audit | hourly (if configured) | `{}` | |
| `audit_reconcile` | audit | 5 min | `{}` | §5.9 |
| `kd_checkpoint_publish` | keydir | on append ≤ 60 s | `{}` | |
| `kd_witness_cosign` | keydir | on checkpoint | `{}` | Outbound to witnesses |
| `backup_run` | backup | daily (configurable) | `{}` | |
| `backup_verify` | backup | weekly | `{}` | Restore test into a scratch instance (19-BACKUPS-DR.md) |
| `session_gc` | auth | 15 min | `{}` | |
| `breakglass_expire` | case | 15 min | `{}` | |
| `breakglass_review_due` | case | daily | `{}` | Escalates overdue reviews |
| `export_delivery` (EE) | connector | on approval | `{export_id}` | |
| `export_expire` | case | daily | `{}` | Removes approved-but-undelivered package blobs after 7 days |
| `legal_hold_review` | case | monthly | `{}` | Reminder only |
| `counters_rollup` | case | daily | `{}` | Aggregates with k ≥ 5 suppression |
| `update_check` | health | 6 h | `{}` | TUF metadata freshness only |
| `idempotency_gc` | case | hourly | `{}` | |

### 6.3 Z-INTAKE local jobs (intake DB, same mechanism)

| Kind | Schedule | Action |
|---|---|---|
| `draft_gc` | 60 min | Increment the in-RAM `draft_generation` counter. Delete uncommitted draft parts whose `draft_generation` ≤ current − 3 (i.e., older than 2–3 h). On `candor-intake-store` restart, delete all uncommitted drafts. No wall-clock time is stored per draft. |
| `upload_gc` | daily | Delete Tier V uploads not committed within 3 epoch days |
| `reply_expiry` | daily | Delete replies older than channel reply retention (default 90 days) |
| `snapshot_backup` | daily, jittered | Encrypted snapshot for relay pull |
| `counters_rollup` | daily | Produce day counters (§9.5) |

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
| `intake.max_file_bytes` | 1 MiB – 2 GiB | 512 MiB | SAFE |
| `intake.max_files_per_envelope` | 1–32 | 20 | SAFE |
| `intake.reply_retention_days` | 30–365 | 90 | SAFE |
| `intake.pow.app_level.enabled` | bool | false | SAFE |
| `tor.vanguards.full` | bool | profile | ADVANCED |
| `channel.<id>.mode` | ANONYMOUS/CONFIDENTIAL/IDENTIFIED | ANONYMOUS | DANGEROUS when moving away from ANONYMOUS |
| `clearnet_intake.enabled` (C-38) | bool | false | DANGEROUS |
| `recovery_quorum.enabled` | bool | false | DANGEROUS (ADR-013) |
| `logging.level` (trust path) | `codes` only; there is no debug level in release builds | codes | n/a (not configurable) |
| `audit.external_witness.url` | https URL | none | ADVANCED |
| `notify.mode` | digest/daily | digest | SAFE |
| `notify.allowlist_hosts` | list | [] | ADVANCED |
| `epoch.length_days` | 1–14 | 7 | ADVANCED |
| `channel.<id>.min_recipients` | 1–16 | 1 (2 recommended) | ADVANCED (lowering is DANGEROUS) |
| `envelope.recipient_slots` | 16, 32, 64 | 16 | ADVANCED (increase only; ADR-030) |
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
- Counters (`submissions_received`, `tier_w_vs_v`, `followups`, `logins`) are accumulated per day in the intake DB.
- They are exported by relay pull only as daily totals, with small-cell suppression: values 1–4 are reported as `<5`, and totals per channel are published only if ≥ 5 (THR-039).
- Counters are never broken down below day or channel granularity.

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
| Global login (Argon2id) concurrency | 4 active, 32 queued, 30 s wait | sealer | "busy" page |
| New accounts (global) | 600 / hour default (ADVANCED) | web | "busy" page; SYSTEM alert |
| Sealer sessions | 64 | sealer | `BUSY` |
| Web sessions | 10,000 | web | oldest idle evicted |
| Request body (message route) | 80 KiB (64 KiB text + form overhead) | web parser | 413 page |
| Message text | 64 KiB after UTF-8 validation | web | 413 page |
| File per request (Tier W) | `intake.max_file_bytes` (default 512 MiB) | web streaming counter | 413; draft part discarded |
| Files per envelope | 20 (max 32) | web/sealer | 400 |
| Envelope total (Tier W / Tier V) | 2 GiB / 4 GiB padded | istore | 413 |
| Tier V upload chunk | 4 MiB (64 STREAM chunks), last chunk ≤ 4 MiB | web | 400 |
| Pending uploads (global) | 2,000; per upload ≤ 1,024 chunks | istore | 503 |
| Intake disk reserve | refuse new envelopes when free < 15 % | istore | 503 "busy" |
| Relay batch | 500 objects / 2 GiB | relay | next cycle |
| Desk API request body (non-blob) | 1 MiB | case | 413 |
| Desk blob upload chunk | 8 MiB; object ≤ 4 GiB | case | 413 |
| Desk API rate per user | 600 req/min, burst 100 | case | 429 |
| Admin API rate per user | 120 req/min | case | 429 |
| DB pool | web 0 (no DB), istore 16, case 32, relay 4, worker 8 | services | queue ≤ 5 s then 503 |
| Timeouts | header read 10 s; body idle 60 s (Tor-friendly); total Tier W upload request 4 h; Desk request 120 s (non-blob) | services | connection closed |

**Timing uniformity for unauthenticated source endpoints:**
- The login response is sent only after `max(elapsed, 2.0 s)` + U(0, 250 ms). The same floor applies whether the account exists or not.
- `AUTH_VERIFY` compares in constant time.

## 12. Time handling (ADR-010)

| Type | Resolution | Used for | Source |
|---|---|---|---|
| `EpochDay` (u32, days since 1970-01-01 UTC) | 1 day | All source events (received, reply available), SLA anchors, retention | `SourceClock::today()` |
| `BatchNo` (u64 monotonic) | n/a | Ordering of intake batches | intake DB sequence |
| `StaffTimestamp` (UTC, 1 s) | 1 s | SECURITY/CASE audit, sessions, approvals, break-glass | `StaffClock::now()` |
| `Monotonic` | ns | Timeouts, rate limits (RAM only) | `Instant` |

Rules:
- Trust-path crates on intake-gw have **no** API returning wall-clock time finer than a day except `Monotonic`. `SourceClock` is the only wall-clock accessor there, enforced by lint banning `SystemTime::now`/`chrono::Utc::now` outside `candor-types::time`.
- The Case DB has `timestamptz` columns only in tables on the 09-DATABASE.md §8 allow-list.
- Staff-authored times shown in the Desk (e.g., note times) are carried **inside** encrypted payloads, not in cleartext columns.
- Member Epoch Key selection uses `today` in UTC.
  - The sealer and Tier V clients use keys valid for `today`. Intake cannot check key validity because slots are anonymous (ADR-033). The Desk checks the signed recipient list and flags envelopes encrypted to keys outside their validity (± 1 day tolerance).
- **Clock sanity (THR-043):**
  - At start and hourly, services compare the wall clock with (a) chrony offset and (b) on intake-gw, the Tor consensus `valid-after`/`valid-until` window.
  - If out of window, intake refuses new submissions (busy) and raises `SYSTEM:clock_insane`.
  - Core refuses token issuance at > 120 s offset.

## 13. Graceful degradation and fail-closed behavior

| Failure | Behavior (never weaker protection) | User-visible | Alert |
|---|---|---|---|
| Sealer down or killed | Tier W submit and login unavailable. **No** fallback to writing plaintext or to a web-side encryptor. Tier V continues. | Tier W: static "temporarily unavailable, try later" page; no alternative channel suggested | SYSTEM fail |
| Eligible members with valid Member Epoch Keys < `min_recipients` (default 1) after the COI filter | Refuse the submission for that selection (ADR-030). Never encrypt to other or fewer parties or to an expired, unsigned or unverified key. | "channel temporarily unavailable" | SYSTEM fail (should be prevented by the runway alert at 14 days) |
| Directory snapshot signature invalid | Keep the last valid snapshot while its keys remain valid, then refuse | as above | SECURITY |
| Intake store disk < 15 % | Refuse new envelopes. Replies still served. | busy page | SYSTEM warn at 25 %, fail at 15 % |
| Relay unreachable | Intake buffers. Replies delayed. | none | SYSTEM at lag > 2 h |
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
| BE-005 | Source passphrases SHALL be zeroized immediately after key derivation. Derived source keys SHALL be zeroized at logout, 20-min idle, 2-h absolute timeout, or restart. | ADR-005 | THR-014; THR-034 | C-07 | TST: memory scan test in the sealer harness after each state transition |
| BE-006 | The sealer SHALL accept IPC only from the `candor-web` UID (SO_PEERCRED) and only the operations in §5.2, with strict CBOR decoding (unknown keys and oversize fields rejected). | INC-103 | THR-014; THR-021 | C-07 | TST: IPC fuzzing (cargo-fuzz corpus) and wrong-UID connection test |
| BE-007 | The web multipart parser SHALL enforce allowed parts, per-part header limits and size limits before forwarding any byte, and SHALL never write request data to disk. | INC-107; B-OS-02 | THR-032; THR-014 | C-06 | TST: crafted multipart suite + fanotify zero-write assertion |
| BE-008 | Source-supplied filenames SHALL be carried only inside encrypted manifests and SHALL never influence any server filesystem path. | ADR-027; INC-101; INC-102 | THR-023 | C-06; C-07; C-08 | TST: path-injection corpus in filenames; `safefs-lint` |
| BE-009 | All server filesystem access to input-derived objects SHALL use `candor-safefs` (openat2 RESOLVE_BENEATH\|NO_SYMLINKS\|NO_MAGICLINKS\|NO_XDEV, O_EXCL, mode 0600, random 128-bit names). The CI lint SHALL fail on banned APIs in trust-path crates. | ADR-027; INC-108; INC-109 | THR-023; THR-014 | C-08; C-09; C-10; C-13 | TST: `safefs-lint`; cargo-fuzz on `candor-safefs` |
| BE-010 | `AUTH_CHALLENGE` SHALL return a challenge for unknown locators indistinguishable from known ones. Login responses SHALL be delayed to a 2.0 s floor + U(0, 250 ms) regardless of outcome. | INC-112; B-GL-37 | THR-034; THR-021 | C-06; C-08 | TST: timing distribution test (KS test, p > 0.01, n = 10,000) known vs unknown |
| BE-011 | There SHALL be no per-account lockout for source logins. Brute-force resistance SHALL rely on passphrase entropy (≈129 bits) plus per-circuit and global Argon2id throttles. | ADR-005; ADR-026 | THR-034; THR-032 | C-06; C-07 | INSP: design review; TST: throttle tests |
| BE-012 | The relay SHALL authenticate the intake by pinned certificate and signed, counter-protected requests. It SHALL validate every intake-supplied field against §5.4 bounds and SHALL quarantine non-conforming objects. | ADR-009; INC-103 | THR-014; THR-037 | C-09 | TST: malicious-intake harness (oversize, wrong tenant, future day, replay counter) |
| BE-013 | The relay SHALL assign new random IDs on import and SHALL NOT persist intake object references. Header digests used for idempotency SHALL be nulled after 30 days. | ADR-010 | THR-015; THR-038 | C-09; C-12 | TST: post-import DB scan for intake refs; retention job test |
| BE-014 | The intake SHALL delete envelope rows and blobs within one relay cycle after a digest-verified ack. Unacked data SHALL be retained. | ADR-009; ADR-025 | THR-015; THR-017 | C-08 | TST: ack/nack scenarios; blob presence checks |
| BE-015 | The case service request pipeline SHALL perform audience verification, tenant binding, strict DTO validation (`deny_unknown_fields`, no generic attribute setters), authorization and audit in that order for every route. | ADR-029; INC-112; INC-114 | THR-021; THR-018 | C-10 | TST: route-registry lint; property-based mass-assignment fuzz per role |
| BE-016 | Repository methods returning protected rows SHALL require an `Authorized<T>` capability produced only by C-22. | INC-114; B-GL-37 | THR-021 | C-10; C-22 | TST: compile-fail tests; INSP |
| BE-017 | Authorization decisions SHALL NOT depend on whether the caller could decrypt data. The authz test suite SHALL pass with key material available to all test users. | INC-115 | THR-021 | C-22 | TST: "simulated key leak" authz suite |
| BE-018 | The case service SHALL reject case creation, member addition or re-key if the set of wrapped-to keys differs from the C-22 eligible set, or if any key is not the current key-directory entry. | ADR-015; INC-14 | THR-046; THR-020 | C-10; C-14 | TST: extra-wrap and stale-key injection tests |
| BE-019 | Mutable resources SHALL use optimistic concurrency (`version`, `If-Match`). Mutating Desk endpoints SHALL honor `Idempotency-Key` for 24 h. | Design | — | C-10 | TST: concurrent update tests |
| BE-020 | Job payloads SHALL contain only opaque IDs, enums and day numbers, validated by per-kind schema, and SHALL never contain ciphertext or SOURCE-SENSITIVE data. | ADR-016 | THR-016; THR-015 | C-10; C-12 | TST: job schema tests; DB lint on the `job.payload` CHECK |
| BE-021 | Jobs triggered by imports SHALL be scheduled on the next hourly digest slot + U(0, 10 min), never at an offset from the import time, and SHALL be deleted on completion. | ADR-010; ADR-033 | THR-011 | C-10; C-23 | TST: scheduler test (run_after independent of import time) |
| BE-022 | The job runner SHALL use `FOR UPDATE SKIP LOCKED` leases of 5 min with renewal, bounded retries with jittered exponential backoff, and a `dead` state that raises a SYSTEM alert. | ADR-019 | THR-042 | C-10 | TST: lease expiry and crash-recovery tests |
| BE-023 | Behavior configuration SHALL be loaded only from signed bundles meeting the signer threshold of the highest changed class, with monotonic versions and rejection of unknown keys. | INC-114; INC-106 | THR-035; THR-018 | all server components | TST: unsigned, under-signed, rollback and unknown-key bundles rejected |
| BE-024 | DANGEROUS configuration changes SHALL require two distinct admins with step-up, a 72-h cancellable cool-off, content-free notice to all staff, and a source-visible protection statement update when source-affecting. | ADR-013; INC-114 | THR-035; THR-018 | C-10; C-14; C-19 | TST: e2e: single approval stays pending; cancel works; statement entry appended |
| BE-025 | Release builds SHALL contain no configuration or code path that enables access logs, IP or user-agent capture, exact source timestamps, or request-body debug logging on trust-path services. | ADR-016; INC-60; INC-03 | THR-016; THR-035 | C-05; C-06; C-07; C-08 | TST: binary string scan + config schema test; INSP |
| BE-026 | Errors SHALL carry only closed codes. No error, panic or log path SHALL include source-derived data. The `error-scrub` canary test SHALL pass on every release. | ADR-016; INC-60; INC-56 | THR-016 | all | TST: `error-scrub` |
| BE-027 | The panic hook SHALL emit only `{crate_id, code_site_id}`, and `RUST_BACKTRACE` SHALL be disabled in production units. | INC-58 | THR-016 | all | TST: induced panic produces only a coded event |
| BE-028 | Trust-path logging SHALL use only `candor-log` typed events with the §9.1 field types. `println!`/`log`/`tracing` macros SHALL be banned by CI, and dependency logs SHALL go to a null subscriber except allow-listed mapped codes. | ADR-016 | THR-016; THR-038 | all | TST: clippy `disallowed-macros` in CI; runtime test that dependency log output is suppressed |
| BE-029 | Intake-gw journald SHALL be volatile. Tor logging SHALL be disabled or SafeLogging-only with no persistent file. The self-test SHALL verify both. | ADR-016; B-SD-21 | THR-016; THR-001 | C-05; C-25 | TST: health checks `journald_volatile`, `tor_log_off` |
| BE-030 | SOURCE-SENSITIVE counters SHALL be exported only as daily totals with suppression of values 1–4 and of groups with total < 5. | ADR-016 | THR-039 | C-08; C-09 | TST: counter export tests with small cells |
| BE-031 | Wall-clock access on intake-gw trust-path code SHALL be limited to `SourceClock::today()` (day resolution). A lint SHALL ban other wall-clock APIs there. | ADR-010 | THR-011 | C-06; C-07; C-08 | TST: `time-lint` |
| BE-032 | Services SHALL detect clock insanity (§12) and fail closed as specified. Epoch-key selection SHALL tolerate exactly one day of skew. | ADR-010 | THR-043 | C-07; C-08; C-21 | TST: clock-skew injection |
| BE-033 | Every failure listed in §13 SHALL produce the specified fail-closed behavior. No component SHALL fall back to plaintext storage, clearnet, unverified keys or an alternative notification channel. | ADR-002; ADR-004 | THR-040; THR-035 | all | TST: fault-injection suite (one test per §13 row) |
| BE-034 | The audit append SHALL precede business commit (two-phase with reconciliation). Failure to append SHALL abort the mutation. | ADR-016 | THR-037; THR-018 | C-24; C-10 | TST: audit outage makes mutations fail; reconciliation test |
| BE-035 | Audit chains SHALL be hash-chained per class per tenant and checkpoint-signed every ≤ 1,000 events or ≤ 10 min, with the signing key in TPM or HSM. | ADR-016 | THR-037 | C-24 | TST: chain verification tool; tamper detection test |
| BE-036 | The key directory store SHALL be append-only (DB privileges + trigger). Checkpoints SHALL be signed within 60 s of append and delivered to intake in signed snapshots with consistency proofs. | ADR-022; INC-14 | THR-046 | C-14 | TST: UPDATE/DELETE rejected; snapshot verification tests; split-view test with witnesses |
| BE-037 | The notification service SHALL send only template T1 with the instance label, in hourly (or daily) digests at random offsets, to allow-listed hosts, and SHALL never message sources. | ADR-017; INC-57 | THR-028 | C-23 | TST: output golden test; egress allow-list test |
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
| BE-051 | The sealer SHALL apply the ADR-030 COI filter in RAM using only the verified directory snapshot (roster, COI map, Member Epoch Keys). It SHALL wrap the content key only to eligible members in 16 anonymous slots (dummies for the rest, random order), put the signed recipient list inside the payload, and return `NO_ELIGIBLE_RECIPIENTS` when fewer than `min_recipients` remain. | ADR-030; ADR-033; ADR-015; INC-22 | THR-020; THR-046 | C-07 | TST: COI matrix tests on the sealer (all selections × rosters); TST: slot indistinguishability (size, order) |
| BE-052 | A source's COI selection SHALL persist only inside `prefs_ct`, encrypted to the source's own X-Wing key, and SHALL be re-applied to follow-ups. The intake store SHALL never hold it in cleartext. | ADR-030; ADR-010 | THR-020; THR-015 | C-07; C-08 | TST: intake DB inspection after a COI submission; TST: follow-up recipient set equals the original filter |
| BE-053 | `candor-ekv` SHALL run as its own OS user with the §4.2 baseline, `PrivateNetwork=yes` and memory locking. It SHALL expose only the §5.12 operations to the `candor-case` and `candor-worker` UIDs. | ADR-033; ADR-028 | THR-017; THR-013 | C-12 | TST: IPC peer tests; unit hardening check |
| BE-054 | The relay SHALL NOT persist pull timestamps (no job rows for cycles; import rows carry date and batch number only). Import-triggered jobs SHALL be scheduled on hourly digest slots and deleted on completion. | ADR-033 §4 | THR-011 | C-09; C-10 | TST: DB and audit inspection after relay cycles |

## 15. Residual risks and limitations

- **Live-compromise exposure:** root on intake-gw can read the sealer's memory despite `mlock`/`dumpable=0`. This is unavoidable (06 R-1). The controls reduce *accidental* persistence (swap, dumps, logs), not active compromise.
- **Login throttles:** global Argon2id throttles enable a DoS against logins (THR-032). PoW and queueing reduce but do not remove this. Tier V clients do their own KDF and are unaffected.
- **Timing floor:** the 2 s login floor hides existence only against request-level timing. It does not hide it against a network observer seeing follow-on page sizes. Pages are therefore padded to the same class for "wrong passphrase" and "inbox" responses (08-API.md).
- **Audit ordering:** the two-phase audit leaves a window in which a pending audit row exists for an aborted mutation. The reconciliation job marks it `aborted`, which is visible and not deleted.
- **systemd sandbox:** sandboxing depends on kernel correctness. A kernel exploit bypasses it.

## 16. Open issues

| # | Issue | Proposal |
|---|---|---|
| O-1 | ADR-019 names axum/hyper. Using raw hyper plus an in-house router for the source socket reduces surface but diverges from "axum". | Use axum for Desk/Admin routers and a minimal hyper service for `candor-web`. Record as a clarification in ADR-019. |
| O-2 | Argon2id m = 256 MiB for Tier W logins creates DoS pressure. | Evaluate a Tier W-specific cost profile in 04-CRYPTOGRAPHY.md. It cannot change without changing the passphrase KDF for all tiers (same seed derivation). |
| O-3 | The 72-h DANGEROUS cool-off may conflict with urgent incident response (e.g., disabling a compromised feature). | Allow *tightening* changes (disable features) as ADVANCED with no delay; only *loosening* changes are DANGEROUS. Confirm in 32-OPERATIONS.md. |
| O-4 | The Intake Routing Key and Backup Key are not in ADR-008. | See 06 O-3. |

### Open Issues for ADR revision
- **ADR-019:** router library clarification (O-1).
- **ADR-008:** add Intake Routing Key and Backup Key.
