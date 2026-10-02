<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# deploy/ — Candor deployment artefacts

This directory holds host configuration for Candor Community Edition. The first slice covers the
**intake host** (Z-INTAKE: C-05 tor, C-06 source web, C-07 sealer, C-08 intake store with its
PostgreSQL) for the **CE-SINGLE** profile (intake VM) and the **CE-HARDENED** profile (dedicated
H-INTAKE). Normative sources: `specs/16-TOR-I2P.md`, `specs/17-INFRASTRUCTURE.md`,
`specs/18-DEPLOYMENT.md`, `specs/07-BACKEND.md` §4, `specs/09-DATABASE.md` §10 and
`specs/20-LOGGING-AUDITING.md`. The decisions are ADR-001, 009, 028, 032, 046(1,3) and 049.
`research/R7-secure-implementation.md` §B/§D also applies. Every deviation from the specs and
every ambiguity is recorded in [`SPEC-NOTES.md`](SPEC-NOTES.md).

## Layout

| Path (in repo) | Installed as | Purpose |
|---|---|---|
| `intake/torrc` | `/etc/tor/instances/candor-intake/torrc` (root 0644) | Intake onion service, 16 §7.1. PoW and intro-point DoS defences are on, vanguards-lite only (ADR-049). Logging is `warn` to stderr with SafeLogging (the unit discards stderr, SPEC-NOTES D-28). Sandbox is on. No SocksPort, no TCP listener and no control interface (D-27). |
| `intake/nftables.conf` | `/etc/nftables.conf` | Default-deny ruleset. Only the two tor UIDs may leave via ext0, and only to public addresses over TCP. Other flows: E3 health push and E4 NTS to H-MON, inbound I1 relay 7443 and optional I2 ssh. There are no LOG targets. The installer fills only the three address sets. |
| `intake/systemd/tor@candor-intake.service` | `/etc/systemd/system/` | tor runs as `_tor-candor-intake:_tor-candor-intake` (never root) with `--defaults-torrc /dev/null` under the `candor-tor-intake` AppArmor profile. It is fully sandboxed. AF_INET is allowed for tor only, and non-public IP ranges are denied in-kernel. |
| `intake/systemd/candor-intake-web.{socket,service}` | `/etc/systemd/system/` | C-06. PID 1 creates `/run/candor/source-web/http.sock` (0660 `candor-web:_tor-candor-intake`). The service has `PrivateNetwork=yes` and AF_UNIX only. |
| `intake/systemd/candor-sealer.{socket,service}` | `/etc/systemd/system/` | C-07. Socket `seal.sock` is `SOCK_STREAM` with u32be length-prefixed frames (0660 `candor-sealer:candor-web`; sealer SPEC-NOTES item 9). The sealer has no network. Its only writable path is the staging tmpfs, which it writes itself through candor-safefs (sealer SPEC-NOTES item 7; AUD-RM2-SEA-16). It locks memory through `LimitMEMLOCK=2G` and has no capabilities. Its secrets arrive as TPM-sealed credentials. The syscall allow-set is pinned exactly by config-check (AUD-RM2-DEP-16). |
| `intake/systemd/candor-intake-store{,-relay}.socket`, `candor-intake-store.service` | `/etc/systemd/system/` | C-08. It receives the IPC socket and the relay TCP socket (relay0:7443) from PID 1. The process itself is AF_UNIX-only in an empty network namespace, so it can accept the core's pull but can never initiate a connection (ADR-009). |
| `intake/systemd/run-candor-staging.mount` | `/etc/systemd/system/` | Tier W staging tmpfs `/run/candor/staging`, mode 0700 `candor-sealer`, `noswap`. It is RAM-only (ADR-034). The store has no access; staged bundles reach it as passed file descriptors (D-33). |
| `intake/systemd/candor-intake-pg.service` | `/etc/systemd/system/` | Dedicated PostgreSQL 16 cluster for the intake store. Unix socket only, `PrivateNetwork=yes`. Cumulative statistics live in RAM (`pg_stat` → `/run/candor/intake-pg-stat`, D-34). |
| `intake/systemd/candor-intake-{vacuum,maint}.{service,timer}` | `/etc/systemd/system/` | Fixed-time maintenance (D-34; AUD-RM2-STO-11/23/24): plain VACUUM 15 min after each import slot, and a daily window (deletion-list prune, statistics reset, `VACUUM FULL`, `CHECKPOINT`). Both run `candor-intake-maint` as `candor-imaint` (DB role `candor_intake_maint`), sandboxed like the services, under the `candor-intake-maint` profile. Enable the two timers only. |
| `intake/systemd/nftables.service.d/candor-intake.conf` | `/etc/systemd/system/nftables.service.d/` | Loads the ruleset only after the service users exist. |
| `intake/postgresql/{candor-intake.conf,pg_hba.conf,pg_ident.conf}` | `/etc/candor/intake/postgresql/` (root:postgres 0640) | `wal_level=minimal`, no archiving or replication, `track_commit_timestamp=off`, `track_counts=off`, `track_activities=off`, `autovacuum=off`, `temp_file_limit=256MB`. PostgreSQL emits no log at all: `log_min_messages = panic` and the unit discards stderr (AUD-RM2-STO-02). Access is peer-only, through three ident maps: `candor-istore`, `candor-imaint` and `candor-migrate` (ADR-052(9)). config-check compares pg_hba/pg_ident line by line and the conf as an allow-list (AUD-RM2-DEP-19). |
| `intake/apparmor/{candor-tor-intake,candor-web,candor-sealer,candor-intake-store,candor-intake-pg,candor-intake-maint}` | `/etc/apparmor.d/` | Enforce-mode profiles for all intake processes. Units attach them with `AppArmorProfile=` and no `-` prefix, so a unit fails to start if its profile is missing. config-check compares each profile statement by statement with the release (AUD-RM2-DEP-15). |
| `intake/journald/journald@candor-intake.conf` | `/etc/systemd/` | Journal namespace of the five units. They send nothing to it (stdout/stderr discarded, D-28); it only contains a stray `syslog()` write. Volatile, hourly files, at most 24 h, nothing below `crit` stored, no forwarding. |
| `intake/journald/candor-intake-host.conf` | `/etc/systemd/journald.conf.d/50-candor-intake.conf` | Host journal: volatile, hourly files, at most 24 h, `Audit=no`, no forwarding (17 §5.5, 20 §11.3). |
| `intake/sysctl.d/90-candor-intake.conf` | `/etc/sysctl.d/` | Kernel baseline (20 §11.4, 17): ptrace scope 3, no core dumps, restricted dmesg/kptr/bpf/userns, no TCP timestamps, no redirects or forwarding, no `exception-trace` printk lines (D-30, AUD-RM2-DEP-20). |
| `intake/coredump.conf.d/50-candor-intake.conf` | `/etc/systemd/coredump.conf.d/` | systemd-coredump stores nothing (D-30). |
| `intake/sysusers.d/candor-intake.conf` | `/usr/lib/sysusers.d/` | One UID per service, plus every UID that nftables names. |
| `intake/tmpfiles.d/candor-intake.conf` | `/usr/lib/tmpfiles.d/` | Socket and state directories. Each is 0750 with group set to the single permitted client (07 §4.1). |
| `intake/resolv.conf` | `/etc/resolv.conf` | No DNS (`nameserver 127.0.0.1` with nothing listening). |
| `intake/profiles/{ce-single,ce-hardened}/` | `/etc/systemd/system/<unit>.d/` | Profile drop-ins. Staging is 4 GiB on CE-SINGLE and 8 GiB on CE-HARDENED. The sealer's `MemoryMax` is 2560M plus the staging size, because tmpfs pages are charged to the writer's cgroup. |
| `intake/secret-placement.toml` | `/usr/share/candor/manifests/intake.toml` | ADR-028 Secret Placement Manifest for role `intake`. |
| `tools/check-placement.sh` | `/usr/lib/candor/tools/` | Verifies the manifest on a host: owner, group, mode, parent mode, symlinks and hard links per entry. It also scans for unlisted secret material and checks names in the ciphertext-only directories. |
| `tools/config-check.sh`, `tools/config-check.baseline`, `tools/config-check.manifest`, `tools/candor-safe-read` (built by `tools/build-safe-read.sh` from `crates/candor-safe-read`) | `/usr/lib/candor/tools/` | The subset of `candorctl check` (18 §14) that covers these files. It checks **effective** configuration against allow-lists: tor's own canonical dump, the nft ruleset as loaded into a throw-away network namespace, units as systemd merges them (all drop-in locations), the sealer's expanded syscall set, `postgres -C`, `systemd-analyze cat-config`, live `/proc/sys`, AppArmor profiles statement by statement (SPEC-NOTES D-31, D-35). It never follows a symlinked input and never prints file content. Every input is read by the compiled `candor-safe-read` (`openat2` `RESOLVE_NO_SYMLINKS|BENEATH`, `O_NOFOLLOW`, `O_NONBLOCK`, fstat checks, size cap; AUD-RM2-DEP-24). Self-contained AppArmor profiles are compared as compiled policy against an isolated compile (AUD-RM2-DEP-23). The baseline and the reader are verified against the manifest, whose digest is pinned in the script. Needs root, `jq`, `tor`, `nft`, `unshare`, `setpriv`, `systemd-analyze`, `sha256sum`, `timeout`, `apparmor_parser` (`--host`). |
| `tests/validate.sh` | — (CI) | Runs all the checks listed under "Validation" below. |

## Users, sockets and flows

```
 Tor network ──ext0──► tor (_tor-candor-intake, AF_INET; nft: TCP to public IPs only)
                          │ unix:/run/candor/source-web/http.sock   (0660 candor-web:_tor-candor-intake; no control socket)
                          ▼
                    candor-web (C-06, no netns, AF_UNIX)
                       │ seal.sock (STREAM, length-prefixed; 0660 candor-sealer:candor-web)
                       ▼                         istore.sock (SEQPACKET, 0660 candor-istore:candor-istore-clients)
                    candor-sealer (C-07) ───────────────►  candor-intake-store (C-08, no netns)
                       │ (writes /run/candor/staging)        │ /run/candor/intake-pg/.s.PGSQL.5432 (peer)
                                                             ▼
                    candor-intake-maint (timers) ──────► PostgreSQL (postgres, no netns)
 C-09 (core) ──relay0:7443──► socket bound by PID 1 ──► candor-intake-store (accept only)
```

## Install order on a host (reference; the installer automates this)

1. Install the packages from the release's Platform Manifest (17 §4.5). tor must be ≥ 0.4.8, and
   `tor --list-modules` must show `pow: yes`. The kernel must be Linux ≥ 6.3 (Platform Manifest
   floor: `vm.memfd_noexec`, `MFD_NOEXEC_SEAL`, `F_SEAL_EXEC`; Debian 13 ships 6.12).
   `config-check.sh --host` checks `uname -r`.
2. Install `sysusers.d` and `tmpfiles.d`, then run `systemd-sysusers` and `systemd-tmpfiles --create`.
3. Install `nftables.conf` with the site's address sets filled in, then enable `nftables.service`.
4. Run `initdb` for the intake cluster as `postgres`:
   `initdb -D /var/lib/postgresql/16/candor-intake --data-checksums -A reject -U postgres`
   (`data_checksums` per 09 §10). Replace its statistics directory with the RAM-only one:
   `mv /var/lib/postgresql/16/candor-intake/pg_stat /root/pg_stat.initdb && ln -s /run/candor/intake-pg-stat /var/lib/postgresql/16/candor-intake/pg_stat`
   (D-34). Install the PostgreSQL files. This must be the only PostgreSQL cluster on the host:
   see SPEC-NOTES D-16.
5. Seal the credentials with `systemd-creds encrypt --with-key=tpm2 --name=<name> <plain> /etc/credstore.encrypted/candor-intake.<name>.cred`,
   then shred the plaintext. Names and paths are in `secret-placement.toml`.
6. Install the units, profile drop-ins, AppArmor profiles (`apparmor_parser -r`), journald,
   sysctl.d and coredump.conf.d files; `sysctl --system`. Write the relay socket drop-in with the
   core address (`IPAddressAllow=<core>/32`, equal to the `@core_relay` element; see the comment
   in the unit).
7. Mask what must not run: `systemctl mask tor.service tor@default.service
   systemd-coredump.socket` (and `swap.target` unless random-key dm-crypt swap is used), turn swap off (`swapoff -a`, remove swap from
   `/etc/fstab`; only random-key dm-crypt swap is tolerated), keep `systemd-journal` and `adm`
   without members.
8. Run `config-check.sh --host` (must exit 0) and `check-placement.sh --mode full` (must exit 0).
   Its race-free input reader is the compiled `candor-safe-read` next to it (no interpreter on
   H-INTAKE, ADR-055(3)); the release manifest pins its digest. Before installing `pg_hba.conf`,
   replace `candor_intake_TENANT` with the site's one intake database name (ADR-054). Once that
   database is provisioned and the cluster runs, the ST-120 gate is
   `config-check.sh --host --pg-db candor_intake_<tenant>`. It checks that the cluster has exactly
   that one intake database, which `candor_intake_maint` owns. The role must own no object, be no
   member of the schema owner, and have no connection limit and no `ALTER DATABASE … SET` (a
   running server checked without `--pg-db` fails).
   Then enable the sockets, services, `tor@candor-intake` and the two maintenance timers.

## Requirements on the Candor binaries (C-06/C-07/C-08 implementers)

- **Socket activation:** take listeners from `sd_listen_fds` by `FileDescriptorName`:
  `http` (web), `seal` (sealer), `istore` and `relay` (store). Never `bind()` an IP socket;
  `SocketBindDeny=any` and `RestrictAddressFamilies=AF_UNIX` enforce this.
- **Secrets:** read only from `$CREDENTIALS_DIRECTORY/<name>`: `sealer_signing_key` (K35; the
  crate README's `sealer-k35` example name is superseded, D-33), `argon2_salt`, `routing_key`,
  `batch_signing_key` and `relay_tls_key`. Never read them from the environment.
- **Sealer transport and staging (D-33):** `seal.sock` is `SOCK_STREAM`; the sealer owns
  `/run/candor/staging` (0700) and hands a staged bundle to the store as a file descriptor
  (`SCM_RIGHTS` on `istore.sock`), never as a path.
- **Maintenance binary (D-34):** `/usr/lib/candor/intake-store/candor-intake-maint vacuum|daily`,
  connecting as `candor_intake_maint` over the PostgreSQL socket only.
- **Logging:** stdout and stderr are discarded by the units (no journald line may carry the
  exact time of a source action, SPEC-NOTES D-28). Hour-truncated SYSTEM events (LOG-004) need
  an application-side sink; do not rely on journald.
- **Peers:** check `SO_PEERCRED` on every accepted IPC connection (07 §5.2/§5.3).
- **Self-sandboxing:** the systemd filter permits `seccomp` and `landlock_*` so that each binary
  can apply its own seccomp filter (07 §4.3) and Landlock ruleset (R7 SI-B-02/03).

## Validation

Run `deploy/tests/validate.sh`. Set `CANDOR_TEST_PG=1` to include the PostgreSQL run. The script
runs as root in CI with `shellcheck`, `tor`, `nft`, `apparmor_parser` and PostgreSQL 16 present,
and with the users from `sysusers.d` created.

| Check | Result (2026-10-01, this container: systemd 255, tor 0.4.9.11, nft 1.0.9, jq 1.7, AppArmor 4 parser, PG 16.13) |
|---|---|
| shellcheck (tools, tests) | clean |
| `config-check.sh` on the shipped tree (base, `--profile ce-single`, `--profile ce-hardened`) | 875 checks OK, exit 0 |
| `config-check.sh --host --root` on a synthetic installed host (CE-SINGLE layout) | exit 0 (live-only checks reported as SKIP) |
| `config-check.sh` on 251 deliberately broken copies (every AUD-RM2-deploy round-1, round-2 and round-3 bypass, SEA-16, the STO-08/11/23/24 settings and timers; 54 of them host-root cases; symlinked inputs point at a marker file that must never appear in a report) | every copy rejected with exit 30, no marker printed |
| `config-check.sh` invocation and integrity | `--only typo`, `--only tor,typo`, a selection running no check: exit 2; edited baseline, baseline + re-written manifest: exit 30; work base root 0700 and empty afterwards |
| `config-check.sh --host --only pg` against a live cluster (`postgres -C`) | clean cluster passes (stats link in place); `pg_stat` as a real directory, a data directory behind a symlink and an `ALTER SYSTEM`-style `postgresql.auto.conf` override are rejected (exit 30) |
| `systemd-analyze verify --man=no` (14 units) | clean apart from the expected messages below |
| `systemd-analyze security --offline --threshold` | web 0.4, sealer 0.4, store 0.4, vacuum 0.4, maint 0.4, PostgreSQL 0.5 (budget 0.5); tor 1.4 (budget 1.5, 17 §5.3) |
| `nft -c -f nftables.conf` | OK |
| `apparmor_parser -Q -K` (6 profiles, exit status checked) | OK |
| `tor --verify-config` (as `_tor-candor-intake`) | valid |
| `check-placement.sh` | 3 positive cases pass; 22 negative cases fail as expected (exit 30 or 2) |
| PostgreSQL 16 with `candor-intake.conf` | effective settings match (incl. `max_wal_size=256MB`, `wal_recycle=off`, `autovacuum=off`, `track_counts=off`, `track_activities=off`, `temp_file_limit=256MB`). Peer map, database restriction and socket permissions refuse other users and roles, including `postgres`. The server writes zero bytes of log output, even after errors. |

**Expected `systemd-analyze verify` messages**, filtered by `validate.sh`:
`Command /usr/lib/candor/{source-web/candor-web,sealer/candor-sealer,intake-store/candor-intake-store,intake-store/candor-intake-maint} is not executable: No such file or directory`.
These binaries are not built yet; the units name their future install paths. On systemd < 257,
any later `PrivatePIDs=` addition would appear as `Unknown key name`; that message is filtered
too.

**Not verifiable here**, because no systemd runs as PID 1 in the container: the actual start of
the units under their sandbox and AppArmor profiles, `LogNamespace=`, `LogLevelMax=` filtering of
PID 1's unit messages, `LoadCredentialEncrypted=` with a TPM, the interaction of
`PrivateNetwork=` with socket activation, and the live parts of `config-check.sh --host`
(`systemctl show`, loaded ruleset, `/proc/sys`, AppArmor load state). These need an integration run on Debian 13
(see SPEC-NOTES "Open items").
