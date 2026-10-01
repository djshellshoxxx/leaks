<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-sealer

`candor-sealer` is the Intake Sealer (component C-07). It is the isolated process that handles Tier W plaintext (ADR-004, ADR-034):
- **Drafts** (text, identity block, COI ticks) live only in its locked, non-dumpable RAM. Each draft is keyed by an opaque session handle.
- **Attachment parts** are padded to their ADR-011 bucket. They are STREAM-encrypted under `K_stage = HKDF(K36, part_id)` and staged on tmpfs through `candor-safefs`.
- **Recipients** are fixed only at Submit. The sealer applies the COI filter to the Triage Set and seals the SUBMISSION, ATTACHMENT_BUNDLE and IDENTITY objects with `candor-core`. It signs the Recipient List with the source key and with K35, then commits through the store.
- **Passphrases** (10 EFF words) are generated in the sealer, confirmed by 3 random words and zeroized after derivation. Argon2id derivations wait behind a semaphore of 4.
- **Logged-in sources** can read verified replies, send follow-ups (only to the original eligible set) and rotate their passphrase.
- **Chaff** follows a Poisson schedule per channel (mean 2 h). It uses the same format and write path as real envelopes, with every slot a dummy and a chaff-kind `disposition_ct`.
- **Uniform shape (ADR-052(1)/(2)).** Every envelope group, real or chaff, is SUBMISSION/SOURCE_MESSAGE + ATTACHMENT_BUNDLE + IDENTITY, with the text objects at their maximum bucket and dummies where nothing was supplied. Accounts are a separate store operation; chaff writes dummy accounts and draws delivery delays like real traffic.

Licence: AGPL-3.0-or-later. No `unsafe`. Nothing is logged, printed or written to disk in plaintext. Read `SPEC-NOTES.md` first: it covers the spec findings, the implementation decisions, the security self-review and the integration notes.

## Layout

| Module | Feature | Content |
|---|---|---|
| `proto` | always (needs only `zeroize`) | IPC types (`Request`, `Response`, `ErrorCode`, `Op`), strict deterministic CBOR (`proto::cbor`), framing (`frame`, `read_frame`, `write_frame`, `call`) |
| `server` | `server` (default) | `Sealer` (sessions, operations, Argon2id gate, chaff, account batches), `directory` (verified snapshot and high-water mark), `kd` (Key Directory entry verifier), `merkle` (RFC 9162), `clock::Clock`, `sink::EnvelopeSink`, `handover` (sealed-bundle descriptor hand-over), `hardening` |

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
use candor_sealer::server::{Sealer, SealerConfig, hardening::{confined_runtime, harden_process, LandlockLevel}};

// main thread, no other thread and no runtime yet (AUD-RM2-SEA-20):
let staging: &'static SafeRoot = Box::leak(Box::new(SafeRoot::open(&staging_path, RootPolicy::Staging)?));
harden_process(&staging_path, LandlockLevel::Required)?;   // no dumps, mlockall, Landlock
let rt = confined_runtime(workers)?;                       // the only runtime the sealer serves on
let k35 = SigningKey::from_seed(&credential_bytes);       // from $CREDENTIALS_DIRECTORY, never env
let sealer = Sealer::new(config, k35, staging, clock, store_sink)?;  // self-test, empties staging
sealer.set_high_water_mark(persisted_hwm);
sealer.install_snapshot(bundle, |hwm| persist(hwm))?;     // derives the view from the signed log
rt.block_on(async {
    sealer.spawn_background();                             // reaper, account batches, chaff
    let term = sealer.spawn_sigterm_flush()?;              // SIGTERM: one last shuffled batch
    tokio::select! {
        r = sealer.serve(listener) => r,                   // refuses unless hardened, per thread
        _ = term => Ok(()),                                // then exit
    }
})?;
// The unit sets CANDOR_SEALER_MEMORY_BUDGET_MIB (below MemoryMax) and
// CANDOR_SEALER_SESSION_UPLOAD_MIB; Sealer::new refuses to start without them (SEA-29).
```

The integrator supplies four things:
- `Clock` (16 §14.3): the independent day clock, built from the Tor consensus and Roughtime.
- `EnvelopeSink`: the store client. `commit_envelope_group` (no account reference) hands the sealed bundle (`Blob::Staged`, a sealed memfd) to the store with `handover::StoreConnection::hand_over` (or `hand_over_group_bundle(&EnvelopeGroup)`) over `istore.sock` (`SCM_RIGHTS`, deploy D-33; the connection is closed on any error or timeout) and returns only after the store's commit acknowledgement (hand-over protocol 2, below); `upsert_account` is called from the shuffled account batches (`flush_accounts`, every `account_flush_interval`; ADR-052(2), SEA-21).
- `SnapshotBundle`s (the signed checkpoint, the consistency proof from the high-water mark and **every** SignedKDEntry of the log), refreshed hourly; the pinned `DirectoryTrust` (K01, epoch origin, cosignature floors) in the config. The sealer verifies every entry itself (`kd`, AUD-RM2-SEA-19).
- K35, loaded from a systemd credential.

### Hand-over protocol 2 (AUD-RM2-STO-29, C-5)

The sealer sends one 41-byte message `u8 version = 2 ‖ u64be len ‖ sha256(bundle)` with the bundle memfd attached (`SCM_RIGHTS`). Every answer from the store is 33 bytes, `u8 code ‖ 32 bytes`:

| Code | Meaning | Hash field |
|---|---|---|
| `0x02` | copied: the bundle is durable in the store's blob root | `sha256(bundle)` |
| `0x01` | committed: the envelope that names the blob is committed | `sha256(bundle)` |
| `0x00` | refused: nothing committed | all zero |

`hand_over` returns `Ok` only after `0x02 ‖ h` and then `0x01 ‖ h`, both with the hash of the bundle it sent:
- `0x02` must arrive within `copy_deadline(len) = 10 s + ⌈len / 50 MB/s⌉` (`COPY_DEADLINE_BASE`, `MIN_COPY_RATE`).
- `0x01` must then arrive within `ACK_TIMEOUT` (60 s).

A refusal, a wrong hash, a short or long answer (including the protocol-1 one-byte ack), any other code, a returned descriptor, EOF or a missed deadline is an error and closes the `StoreConnection`, so a late answer can never be credited to the next bundle. Bundles above `MAX_BUNDLE_LEN` (4 GiB, the same value as the store's `STAGED_MAX_BUNDLE_LEN`) are refused before anything is sent. Deploy requirement: the blob volume sustains at least `MIN_COPY_RATE` (50 MB/s); nothing checks this yet (deploy-owner open item).

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
# 07 §4.3 list plus what tmpfs staging needs (SPEC-NOTES item 7). The shipped unit
# (deploy/intake/systemd/candor-sealer.service) expresses the same allow-list as the
# @system-service baseline minus every other call (config-check.sh requires that form):
SystemCallFilter=read write readv writev pread64 pwrite64 preadv pwritev lseek _llseek recvmsg sendmsg recvfrom sendto recv send accept accept4 socket connect getsockopt setsockopt getsockname getpeername shutdown close close_range fcntl fcntl64 ioctl memfd_create dup dup3 epoll_create epoll_create1 epoll_ctl epoll_wait epoll_pwait epoll_pwait2 eventfd2 poll ppoll ppoll_time64 futex futex_time64 futex_waitv mmap mmap2 munmap mremap madvise mprotect brk mlock mlock2 mlockall munlock membarrier rt_sigreturn sigreturn rt_sigprocmask rt_sigaction sigaltstack tgkill tkill getpid gettid clock_gettime clock_gettime64 clock_getres clock_getres_time64 clock_nanosleep clock_nanosleep_time64 nanosleep gettimeofday time getrandom exit exit_group restart_syscall sched_yield sched_getaffinity clone clone3 set_robust_list get_robust_list rseq set_tid_address arch_prctl set_thread_area set_tls execve prctl prlimit64 getrlimit ugetrlimit fstat fstat64 newfstatat fstatat64 statx fstatfs fstatfs64 openat unlinkat renameat2 linkat mkdirat fsync fdatasync fchmod fchmodat utimensat utimensat_time64 getdents64 readlinkat getuid geteuid getgid getegid getuid32 geteuid32 getgid32 getegid32 uname sysinfo access faccessat faccessat2 landlock_create_ruleset landlock_add_rule landlock_restrict_self
SystemCallErrorNumber=EPERM
Restart=on-failure
RestartSec=2s
```

## Checks

```
cargo fmt --all
cargo clippy -p candor-sealer --all-targets --all-features -- -D warnings
cargo clippy -p candor-sealer --no-default-features --lib -- -D warnings   # proto only
cargo test -p candor-sealer
```

Fuzzing (ST-043): `cd crates/candor-sealer && cargo +nightly fuzz run fuzz_sealer_ipc fuzz/corpus/fuzz_sealer_ipc fuzz/seeds/fuzz_sealer_ipc -- -max_total_time=600 -rss_limit_mb=2048` (seed corpus: `cd fuzz && cargo +nightly run --release --bin gen_seeds`).

The full flow test runs four Argon2id derivations at m = 64 MiB, so it takes about 20–30 s in debug builds.
