<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-sealer

`candor-sealer` is the Intake Sealer (component C-07). It is the isolated process that handles Tier W plaintext (ADR-004, ADR-034):
- **Drafts** (text, identity block, COI ticks) live only in its locked, non-dumpable RAM. Each draft is keyed by an opaque session handle.
- **Attachment parts** are padded to their ADR-011 bucket. They are STREAM-encrypted under `K_stage = HKDF(K36, part_id)` and staged on tmpfs through `candor-safefs`.
- **Recipients** are fixed only at Submit. The sealer applies the COI filter to the Triage Set and seals the SUBMISSION, ATTACHMENT_BUNDLE and IDENTITY objects with `candor-core`. It signs the Recipient List with the source key and with K35, then commits through the store.
- **Passphrases** (10 EFF words) are generated in the sealer, confirmed by 3 random words and zeroized after derivation. Argon2id derivations wait behind a semaphore of 4.
- **Logged-in sources** can read verified replies, send follow-ups (only to the original eligible set) and rotate their passphrase.
- **Chaff** follows a Poisson schedule per channel (mean 2 h). It uses the same format and write path as real envelopes, with every slot a dummy and a chaff-kind `disposition_ct`.

Licence: AGPL-3.0-or-later. No `unsafe`. Nothing is logged, printed or written to disk in plaintext. Read `SPEC-NOTES.md` first: it covers the spec findings, the implementation decisions, the security self-review and the integration notes.

## Layout

| Module | Feature | Content |
|---|---|---|
| `proto` | always (needs only `zeroize`) | IPC types (`Request`, `Response`, `ErrorCode`, `Op`), strict deterministic CBOR (`proto::cbor`), framing (`frame`, `read_frame`, `write_frame`, `call`) |
| `server` | `server` (default) | `Sealer` (sessions, operations, Argon2id gate, chaff), `directory` (verified snapshot view and high-water mark), `clock::Clock`, `sink::EnvelopeSink`, `hardening` |

`candor-web` depends on the crate with `default-features = false` and uses `proto` only.

## IPC

The wire format is `u32be(len) ‖ CBOR {"v": 1, "op", "rid", "body"}`, with 1 ≤ len ≤ 128 KiB. Bodies use integer keys, and key 1 is always `sess`. `HELLO {1: 2}` must be the first message on every connection. A malformed frame gets `ERR{BAD_FRAME}` and the connection is closed. The listener checks `SO_PEERCRED.uid` against `allowed_peer_uid` before it reads a byte.

| op | name | purpose |
|---|---|---|
| 0x01 | HELLO | protocol 2 and snapshot version |
| 0x02 | SESSION_OPEN | open a RAM drafting session and generate K36 |
| 0x03 / 0x04 | DRAFT_SET / DRAFT_GET | replace or read the RAM draft (`DRAFT_GET` shows parts as buckets) |
| 0x20 / 0x21 / 0x24 | PART_BEGIN / PART_CHUNK / PART_DROP | stage an attachment (`declared_len` upper bound, ≤ 64 KiB chunks) |
| 0x10 | GEN_ACCOUNT | passphrase word indices and 3 confirmation positions |
| 0x14 | CONFIRM_PASSPHRASE | constant-time check; 5 failures zeroize the draft and passphrase |
| 0x22 / 0x23 | SEAL_FINISH / SEAL_ABORT | seal and commit (`fsync`ed) or drop the draft |
| 0x11 / 0x12 / 0x13 | LOGIN_DERIVE / LOGIN_SIGN / LOAD_PREFS | Argon2id → `lookup_tag`; auth signature; unlock the inbox |
| 0x30 | OPEN_REPLY | one dead-drop entry → verified reply or `null` |
| 0x15 / 0x16 | ROTATE_PASSPHRASE / ROTATE_FINISH | new passphrase; re-wrap replies; KEY_ROTATION follow-up |
| 0x25 | NOTE_REAL | Tier V real `disposition_ct`; cancels the next chaff event |
| 0x40 / 0x41 / 0x7F | ZEROIZE / TOUCH / STATUS | drop a session; reset the idle timer; coarse bands |

## Use

```rust
use candor_sealer::server::{Sealer, SealerConfig, hardening::{harden_process, LandlockLevel}};

// main thread, before the tokio runtime:
harden_process(&staging_path, LandlockLevel::Required)?;   // no dumps, mlockall, Landlock
let staging: &'static SafeRoot = Box::leak(Box::new(SafeRoot::open(&staging_path, RootPolicy::Staging)?));
let k35 = SigningKey::from_seed(&credential_bytes);       // from $CREDENTIALS_DIRECTORY, never env
let sealer = Sealer::new(config, k35, staging, clock, store_sink)?;  // self-test, empties staging
sealer.set_high_water_mark(persisted_hwm);
sealer.install_snapshot(verified_snapshot)?;               // rollback-checked
sealer.spawn_background();                                 // reaper + chaff
sealer.serve(listener).await?;                             // socket-activated UnixListener
```

The integrator supplies four things:
- `Clock` (16 §14.3): the independent day clock, built from the Tor consensus and Roughtime.
- `EnvelopeSink`: the store client. It covers `COMMIT_ENVELOPE` and `ACCOUNT_ROTATE`.
- The verified `DirectorySnapshot`, refreshed hourly by the relay control cycle.
- K35, loaded from a systemd credential.

## systemd unit (07 §4.2/4.3, BE-003; R7 §B)

```ini
[Service]
User=candor-sealer
LoadCredentialEncrypted=sealer-k35:/etc/candor/credentials/sealer-k35.cred
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
LimitMEMLOCK=2G
LimitCORE=0
MemoryMax=2560M
MemorySwapMax=0
ProtectSystem=strict
ReadOnlyPaths=/
ReadWritePaths=/run/candor/staging
InaccessiblePaths=/var/lib/candor /var/lib/postgresql /var/lib/tor
NoNewPrivileges=yes
CapabilityBoundingSet=
PrivateTmp=yes
PrivatePIDs=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
# 07 §4.3 list plus what tmpfs staging needs (SPEC-NOTES item 7):
SystemCallFilter=read write recvmsg sendmsg accept4 close epoll_wait epoll_pwait epoll_ctl epoll_create1 futex mmap munmap mremap madvise brk rt_sigreturn rt_sigprocmask rt_sigaction clock_gettime getrandom exit exit_group sched_yield nanosleep clock_nanosleep restart_syscall fstat newfstatat statx getsockopt mlock munlock mlockall prctl setrlimit prlimit64 openat unlinkat renameat2 linkat fsync fdatasync fchmod utimensat getdents64 lseek pread64 sigaltstack landlock_create_ruleset landlock_add_rule landlock_restrict_self clone3 set_robust_list rseq
SystemCallErrorNumber=EPERM
Restart=on-failure
RestartSec=2s
```

## Checks

```
cargo fmt --all
cargo clippy -p candor-sealer --all-targets -- -D warnings
cargo clippy -p candor-sealer --no-default-features --lib -- -D warnings   # proto only
cargo test -p candor-sealer
```

The full flow test runs four Argon2id derivations at m = 64 MiB, so it takes about 20–30 s in debug builds.
