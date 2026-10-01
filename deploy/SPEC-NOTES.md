<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# deploy/ — SPEC-NOTES (intake host, CE-SINGLE / CE-HARDENED)

This file records implementation decisions, spec conflicts and residual risks for
`deploy/intake` and `deploy/tools`. When specs conflict, the stricter reading is taken. No
protection named in the specs is weakened. Section references: 07 = `07-BACKEND.md`,
09 = `09-DATABASE.md`, 16 = `16-TOR-I2P.md`, 17 = `17-INFRASTRUCTURE.md`,
18 = `18-DEPLOYMENT.md`, 20 = `20-LOGGING-AUDITING.md`, 32 = `32-OPERATIONS.md`,
R7 = `research/R7-secure-implementation.md`.

## Implementation decisions and spec conflicts

**D-01 Names.**
- **Unit name.** The unit is `candor-intake-web.service`, as the RM-2 brief names it. 07 calls the service `candor-web` and 17 §5.2 calls the profile `candor-source-web`.
- **Users.** Users follow 07 §4.1: `candor-web`, `candor-sealer`, `candor-istore` and `postgres`.
- **tor user.** 07 §4.1 lists `debian-tor` for tor. 16 §7.3 and 17 §4.3 require one user per instance, so tor runs as `_tor-candor-intake`, which is stricter.
- **Binaries.** Binary paths are `/usr/lib/candor/{source-web/candor-web,sealer/candor-sealer,intake-store/candor-intake-store}`. These are new and follow 17 §5.2's `/usr/lib/candor/source-web/**`.
- **Socket paths.** Socket paths follow 16 §7.1 (`/run/candor/source-web/http.sock`) and 07 (`/run/candor/sealer/seal.sock`, `/run/candor/istore/istore.sock`). 17 §5.2's `/run/candor/source-web.sock` is superseded by 16 §7.1, the torrc template, which is normative per NET-004.

**D-02 tor logging.**
- **Destination.** 16 §7.1 says `Log warn syslog`. LOG-005 says "stderr only". `Log warn stderr` is used. stderr goes only to the volatile `candor-intake` journal namespace, so no syslog daemon can ever receive tor output.
- **Level.** Level `warn` satisfies NET-008 and 32 `tor.log_level`.
- **Added from LOG-005.** `LogTimeGranularity 1 hour` and `HiddenServiceStatistics 0` are added; neither is in 16 §7.1.
- **Version banner.** tor prints its banner at notice level to stdout before the torrc is applied. The unit sets `StandardOutput=null`, so no version string reaches any log (R7 D3).
- **Superseded in part by D-28.** stderr is now discarded too (`StandardError=null`), so tor output reaches no journal at all. `LogTimeGranularity` only coarsens tor's own text prefix; it never could coarsen journald's timestamps (AUD-RM2-DEP-05).

**D-03 `CompiledProofOfWorkHash 0`.**
- **Reason.** 16 §7.3 and NET-010 require `MemoryDenyWriteExecute=yes`. The HashX JIT that tor uses for Equi-X needs W+X memory, so the interpreted verifier is forced.
- **Cost.** PoW verification costs more CPU under a flood. The PoW queue parameters must be load-tested in that mode (34).
- **Not used instead.** Dropping MDWE would weaken a stated control, so it was not done.

**D-04 `HiddenServiceExportCircuitID haproxy`.**
- **Conflict.** 17 §5.5 says "No `HiddenServiceExportCircuitID`". 16 §7.1, which is normative for the torrc (NET-004), and 16 §13 L4 / NET-029 need the circuit ID for per-circuit rate limiting.
- **Decision.** The option is kept. The identifier is an internal tor circuit counter, not an address. It must stay in RAM only (NET-013) and must never be logged (C-06 obligation).
- **Unverified.** PROXY-header support on Unix-socket targets is Knowledge (unverified) per 16 §7.1 and must be confirmed in integration.
- **Request.** 17 §5.5 should be aligned with this.

**D-05 Socket activation for C-06, C-07 and C-08.**
- **Mechanism.** PID 1 creates every listener with fixed owner, group and mode: `http`, `seal`, `istore` and the relay TCP socket.
- **Effect.** No Candor service needs write access to `/run`, and none can change socket permissions. The intake store needs no `AF_INET` and runs with `PrivateNetwork=yes`. It accepts the core's pull on the inherited socket but cannot initiate any connection. That enforces ADR-009 in the kernel instead of only through nftables.
- **Relation to 07 §4.2.** This replaces the 07 §4.2 delta for `candor-intake-store` (`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `IPAddressAllow=<core>`). The IP allow-list now sits on `candor-intake-store-relay.socket`, set through the installer drop-in.
- **Binaries.** The binaries must support `sd_listen_fds`; see README.

**D-06 tor sandbox details.**
- **Address families.** `RestrictAddressFamilies=AF_UNIX AF_INET`. 16 §7.3 lists `AF_INET6 AF_NETLINK` as well. AF_NETLINK is not needed by a non-relay onion service. AF_INET6 is added only by a site drop-in when the host has an IPv6 uplink (16 §7.1 note, 17 §4.3).
- **Address ranges.** `IPAddressDeny=` lists every non-public range, because Tor relays are public. nftables does the same for both tor UIDs.
- **No `ProcSubset=pid`.** tor reads `/proc/meminfo` for `MaxMemInQueues`.
- **Syscalls.** `setrlimit` is re-allowed because tor raises `RLIMIT_NOFILE` at start. `seccomp` is re-allowed for `Sandbox 1`.
- **Exposure.** The tor unit scores 1.4 (budget 1.5).

**D-07 tor control-socket group (superseded by D-27).** The intake tor instance has no control socket and no `_candor-torctl` group any more. The unit runs with `Group=_tor-candor-intake`, which also gives tor access to `/run/candor/source-web` (AUD-RM2-DEP-11).

**D-08 nftables. The 17 §4.3 ruleset and the §4.3.1 matrix are the base; the following are stricter.**
- **No `log` statement.** 16 §14.2's sample has one; LOG-007 forbids LOG targets. Drops go to named counters only.
- **`ct state invalid drop`.** Added in both directions.
- **Non-public destinations dropped for tor UIDs.**
- **ICMPv6 router advertisements and redirects dropped** (NET-041).
- **Empty address sets.** `mon_hosts`, `admin_jump` and `core_relay` ship empty, so the default is fail-closed. The installer fills them; config-check pins every accept rule to the template.

**D-09 E5 (Tang).** 17 §4.3's ruleset contains a `skuid 0 … dport 7500 accept`. Both matrices (16 §14.2 E5, 17 §4.3.1 E5) say the rule must exist only in the initramfs and be absent after switch-root. The main ruleset therefore omits it. The initramfs ruleset belongs to the FDE/clevis work and is not part of this slice.

**D-10 Tier W staging.**
- **Brief vs spec.** The brief mentions "sealer with tmpfs staging dir". 07 §5.3, ADR-034 and 17 §5.4 make `/run/candor/staging` the intake store's tmpfs. The sealer has no writable path at all (07 §4.2), so the only tmpfs it has is its `PrivateTmp`.
- **Mount.** Staging is `run-candor-staging.mount`: tmpfs, `noswap`, `nosuid,nodev,noexec`, 0700 `candor-istore` via libmount `X-mount.owner/group/mode`. This was verified with util-linux 2.39.
- **Sizes.** 4 GiB on CE-SINGLE (18 §4.1) and 8 GiB on CE-HARDENED (18 §4.2, 32 default).
- **Restart.** The mount is not remounted when the store restarts. Emptying it on start stays an application duty (07 §4.5). Staged parts are undecryptable once the sealer's K36 is gone.

**D-11 PostgreSQL.**
- **Unit.** A dedicated `candor-intake-pg.service` starts `postgres` directly, so the full sandbox applies. `pg_ctlcluster` and `postgresql@16-main` are not used.
- **Log prefix.** `log_line_prefix='%e '` is stricter than 09's `'%m %e '`. LOG-004 asks for coarse intake timestamps. Since D-26, PostgreSQL output is discarded anyway.
- **Defaults turned off.** `log_checkpoints` and `log_autovacuum_min_duration` are disabled because PG ≥ 15 enables them by default and both timestamp write activity. `update_process_title=off` is also set.
- **pg_hba.** pg_hba is exactly 09 §10. Even the `postgres` superuser is rejected on the socket, so bootstrap (role and database creation) and migrations must run in single-user mode with the service stopped.
- **Open item.** This interacts with R7 SI-E-06 `candorctl migrate`, which needs a decision: either a time-boxed hba entry or single-user mode only.
- **Socket.** The socket group is set via `unix_socket_group='candor-istore'` (0770). `SupplementaryGroups=candor-istore` exists in the unit only, so `postgres` is not added to `/etc/group`. `@chown` stays allowed for that. The directory is 0750 `postgres:candor-istore`.

**D-12 Manifest format and paths.**
- **Format.** 18 §15.1 shows YAML at `/usr/share/candor/manifests/<role>.yaml`. The brief asks for `secret-placement.toml`, so a strict TOML subset is used, parseable with awk because H-INTAKE has no interpreter (17 §5.1).
- **Onion key path.** It is `/var/lib/tor-instances/candor-intake/hs-source/…`, following the 16 §7.1 torrc, not 18's `/var/lib/tor/candor-source/…`.
- **Key group.** The key's group is `_tor-candor-intake` (tor's primary group; D-27). Mode 0600 gives it no access.

**D-13 Secrets as TPM-sealed systemd credentials.** This follows R7 SI-B-01 and the "never Environment=" bar.
- **Storage.** Every service secret is a `.cred` file in `/etc/credstore.encrypted`, root 0700, files root 0400.
- **Delivery.** PID 1 unseals each one into the unit's private `$CREDENTIALS_DIRECTORY`.
- **Owner.** 18 §15.1 lists per-service owners. Root ownership is stricter: no service user can read another service's secret, or the sealed file itself.
- **Added entries.** The manifest adds K31 (intake batch signing) and K35 (sealer signing). Both are on the intake host per 04 §19, but 18 §15.1 omits them.
- **Optional entries.** The health-agent and backup-signer keys are `required = false` until those packages exist.
- **Relay key path.** The relay mTLS server key moves from 18's `/var/lib/candor/relay/tls.key` (owner `candor-relay`, a core user) to a credential owned by the intake store.

**D-14 check-placement scope.**
- **Content-scanned files.** Regular files up to `max_file_kib` (1 MiB) are content-scanned. Symlinks are not followed.
- **Ciphertext directories.** The blob and staging directories are checked by name layout only (candor-safefs: `<2>/<26 base32>`, `.tmp-<26>`). Reading them would touch source-data atimes and cost I/O.
- **Excluded.** `/run/credentials` is excluded because it holds PID 1's unsealed per-unit copies.
- **Binary formats.** Binary OpenPGP and PKCS#12 are recognised only by armour or by file name.
- **Exit codes.** Manifest parse errors and invalid paths exit 2 (fail closed).

**D-15 Journald namespace (owner OPSEC instruction; amended by D-28).** tor, web, sealer, store and PostgreSQL run in `LogNamespace=candor-intake`, but since D-28 none of them sends stdout/stderr to it. The namespace remains as containment for any `syslog()`/journal-socket write (`MaxLevelStore=crit`). The bullets below describe the namespace configuration.
- **Storage.** Volatile, `RuntimeMaxUse=16M`, `MaxRetentionSec=24h`, `MaxFileSec=1h`.
- **Filtering.** `MaxLevelStore=warning`. No forwarding to syslog, kmsg, console or wall.
- **Per unit (D-28).** All five units set `StandardOutput=null`, `StandardError=null` and `LogLevelMax=emerg`.
- **Not chosen.** `Storage=none` for the namespace: it would also drop the containment value of a separate store. With D-28 nothing is stored in practice.

**D-16 One PostgreSQL cluster per intake host.**
- **Why.** `RemoveIPC=yes` with `User=postgres` would remove IPC objects of any other cluster run by `postgres`.
- **Installer.** The installer must set `create_main_cluster = false` (postgresql-common) and must not enable `postgresql@16-main`.

**D-17 Sealer memory locking.** 17 §5.3 grants `CAP_IPC_LOCK` with `LimitMEMLOCK=infinity`; 07 §4.2 uses `LimitMEMLOCK=2G`. The 07 approach is followed and the capability set is empty, which is stricter. 17 §5.2 lets the sealer "write ciphertext to blobs", which contradicts 07 §4.2 (`InaccessiblePaths=/var/lib/candor`). 07 is followed: the sealer hands envelopes to the store over IPC.

**D-18 (spec gap, 07 §4.3 vs §5.3).** The sealer's in-process seccomp allow-list has no `socket`/`connect`. Yet 07 §5.3 has the sealer call `COMMIT_ENVELOPE` on `istore.sock` for chaff. Either the connection is opened before the filter and never re-established, so a reconnect means a restart, or `socket(AF_UNIX)`/`connect` must join the allow-list. Feedback for the 07 owner. The deployment allows both: AppArmor permits `connect` to `istore.sock` only.

**D-19 Key Directory snapshot hand-off.**
- **Location.** `/run/candor/directory` is 0750 `candor-istore:candor-sealer`. The store writes the snapshot that C-09 pushes; the sealer reads it.
- **Open question.** 07 §4.3 says the sealer re-reads only on restart, and a restart drops every Tier W session. How snapshot updates trigger that restart (for example, only at import slots) needs a design decision. No `.path` unit is shipped.

**D-20 Requirements on future binaries** (listed in the README):
- socket activation by fd name;
- secrets only from `$CREDENTIALS_DIRECTORY`;
- `SO_PEERCRED` checks;
- stderr-only typed logging;
- self-applied seccomp and Landlock. `seccomp` and `landlock_*` are re-allowed in the systemd filter for that purpose.

**D-21 Hardening not enabled (and why).**
- **`PrivateUsers=`.** It would break `SO_PEERCRED` UID checks and group-based socket access.
- **`PrivatePIDs=`.** It needs systemd 257. Its interaction with `LISTEN_PID` and `SO_PEERCRED` PIDs is untested.
- **`RestrictFileSystems=`.** It needs the BPF LSM, which Debian does not enable by default.
- **`ProcSubset=pid` for tor.** See D-06.

All four are follow-ups for the Debian 13 integration run.

**D-22 AppArmor coverage.** Enforce-mode profiles ship for all five intake processes: `candor-web`, `candor-sealer`, `candor-intake-store`, `candor-tor-intake` (derived from Debian's `system_tor`, limited to this instance: no capabilities, no exec, TCP only, no UDP, no control socket, no log file) and `candor-intake-pg` (no exec, no IP, only its data, socket and configuration paths). Every unit attaches its profile without a `-` prefix (AUD-RM2-DEP-08). Enforce-mode behaviour (no `DENIED` lines under load) is an integration item.

**D-23 sysusers.** `_tor-candor-update`, `candor-health` and `_chrony` are created here, even though their packages are outside this slice. Two failures depend on it:
- nft refuses a ruleset that names an unknown user, which would leave the host unfiltered.
- Every intake unit has `Requires=nftables.service`, and `nftables.service` is ordered after `systemd-sysusers`.

**D-24 DNS.** `resolv.conf` points at `127.0.0.1` with nothing listening (17 §4.5). The config check fails on any non-loopback nameserver.

**D-26 PostgreSQL emits no log at all (AUD-RM2-STO-02).**
- **Finding.** Expected-path errors would become server `ERROR` lines with millisecond timestamps, for example a unique violation when a source retries. Each such line records the exact time of a source action.
- **Settings.** The intake cluster sets `log_min_messages = panic` and `log_min_error_statement = panic`. It also keeps `logging_collector = off`, `log_destination = stderr`, `log_connections`/`log_disconnections = off`, `log_statement = none`, `log_checkpoints = off` and `track_commit_timestamp = off`.
- **Unit.** `candor-intake-pg.service` sets `StandardError=null` and `LogLevelMax=emerg`, so not even PANIC lines reach a journal.
- **Checks.** config-check asserts each of these, and two mutations test it. The PostgreSQL run in `validate.sh` shows zero bytes of server output after rejected connections and a deliberate unique violation.
- **Residual.** PANIC-level crash messages and start-up configuration errors are discarded too. A crashed or misconfigured intake database is visible only through the unit state (`systemctl`, health agent `SYSTEM:service_failed`). Diagnosis needs `config-check.sh`, `postgres -C` or a dual-approved, time-boxed debugging window (NET-037 pattern) with `StandardError=journal`. The `09 §10` value `log_min_messages = warning` is superseded by this audit finding.

**D-25 `systemd-analyze security` budgets** (R7 SI-B-01, internal scale ×10):
- Candor services and PostgreSQL: ≤ 0.5. Achieved: 0.4, 0.4, 0.4 and 0.5.
- tor: ≤ 1.5 (17 §5.3). Achieved: 1.4.
- config-check now enforces both the threshold and the exact list of scoring items per unit (`sec|` lines in `config-check.baseline`), offline in static mode and against the loaded unit with `--host`.

The remaining exposure items are `PrivateUsers`, `RootDirectory`, AF_UNIX allowed, `SupplementaryGroups`, and the implicit `char-rtc` device ACL that comes with `ProtectClock`. tor additionally has network access by design.

**D-27 No tor control interface; health without control access (AUD-RM2-DEP-04; lead decision; spec amendment requested).**
- **Decision.** The intake torrc has `ControlPort 0` and no `ControlSocket`; the `_candor-torctl` group is gone. tor has no per-command ACL, so any control access gives circuit/stream events (exact visit times, forbidden by LOG-005) and `SETCONF` of path-selection options.
- **Health.** The health agent derives liveness from the unit/process state (`systemctl is-active`, `NRestarts`) and from a periodic self-fetch of the onion's `/.well-known/candor/health` through a tor SOCKS listener on a Unix socket readable only by the health agent's group.
- **Where that SOCKS listener lives.** NET-045 forbids a SocksPort on the source onion instance, so the listener belongs to the client-only `candor-update` instance (`_tor-candor-update`, flow E2), e.g. `SocksPort unix:/run/tor-instances/candor-update/health.sock GroupWritable` with group `_candor-health`, IsolateSOCKSAuth. That instance is outside this slice (AUD-RM2-DEP-14), so nothing for it ships yet; this is recorded as a requirement for the next deploy slice.
- **Residual.** The descriptor-integrity values of 16 §15 (intro points, revision counter, PoW-active flag) and the daily load band are no longer available from the intake host. C-25 on the monitor host can still compare descriptors it fetches itself. A self-fetch cannot tell "onion unreachable from the Internet" from "local tor broken" on its own; the external C-25 probe (16 §15) stays the reachability signal.
- **Spec amendment (for the lead).** NET-009 ("control access via a Unix socket ... readable only by the vanguards and health-exporter users") and 16 §15 "Intake health exporter ... reads the control socket" should be amended to "no control interface on the intake tor instance".
- **Enforced.** config-check fails on any effective `ControlSocket`/`ControlPort`/`HashedControlPassword`; `--host` fails if `_candor-torctl` exists or if the group `_tor-candor-intake` has members or is any other user's primary group.

**D-28 No service output in any journal (AUD-RM2-DEP-05/06; lead decision; spec amendment requested).**
- **Why.** journald stores `__REALTIME_TIMESTAMP` with µs precision on every line and has no option to coarsen it. LOG-004's hour truncation therefore cannot be met by any journald setting, and any source-triggerable warning would record the exact time of a source action.
- **Decision.** All five source-path units (tor, web, sealer, store, intake PostgreSQL) set `StandardOutput=null`, `StandardError=null` and `LogLevelMax=emerg`. `LogLevelMax=` also filters the messages PID 1 logs about the unit (start, stop, "Main process exited, code=killed"), which would otherwise land in the host journal with µs timestamps.
- **Host journal.** `Storage=volatile`, `MaxRetentionSec=24h`, `MaxFileSec=1h` (journald deletes only whole files, so hourly files are what makes 24 h real on a quiet host), `Audit=no` (20 §11.3; no kernel audit/AppArmor records), no forwarding. No `MaxLevelStore` cap: admin SSH/sudo accountability needs INFO (20 §11.4). config-check checks the effective configuration (`systemd-analyze cat-config`, all drop-ins) and `--host` requires the `systemd-journal` and `adm` groups to be empty (journal files are readable by those groups).
- **Crash diagnostics.** None are kept by default. Diagnosis uses unit state, `config-check.sh`, `postgres -C`, or a dual-approved, time-boxed (≤ 1 h) debugging window with `StandardError=journal` into the volatile namespace (NET-037 / 16 §15 pattern).
- **Spec amendment (for the lead).** NET-008 ("tor ... SHALL log at warn ... to volatile journald storage"), 32 `tor.daemon`/`logging.config` and 20 §11.3 should say that intake source-path services emit nothing to journald, and that service health comes from unit state and the health agent's coarse codes, not from log lines. Hour-granular SYSTEM events (LOG-004) need a candor-log sink that truncates before storage; that is application work (C-06/C-07/C-08), not deployment.
- **Residual.** Kernel messages (OOM kills, segfault lines from `print-fatal-signals`, which is off by default) still go to the host journal with µs timestamps. `kernel.printk = 3 3 3 3` and `dmesg_restrict` limit them; they are retained ≤ 24 h in RAM.

**D-29 WAL size (AUD-RM2-DEP-07).** `max_wal_size = 256MB` (09 §10), `min_wal_size = 32MB`, `wal_recycle = off` (old segments are removed, not renamed with their content), `checkpoint_timeout = 5min`. Every WAL commit record carries the commit time (ms) whatever `track_commit_timestamp` says; the conf comment no longer claims otherwise. Residual: commit times inside the live WAL (≤ 256 MB); handled by AT-007/AT-020 and the 09 §13 small-WAL mitigation, not by configuration.

**D-30 Kernel baseline (AUD-RM2-DEP-09).**
- **sysctl.** `sysctl.d/90-candor-intake.conf` carries the 20 §11.4 / 17 values (`kernel.printk=3 3 3 3`, `dmesg_restrict=1`, `core_pattern=|/bin/false`, `fs.suid_dumpable=0`, `yama.ptrace_scope=3`, `kptr_restrict=2`, `unprivileged_bpf_disabled=1`, `tcp_timestamps=0`, `vm.swappiness=0`) plus stricter items: `perf_event_paranoid=3`, `kexec_load_disabled=1`, `sysrq=0`, `bpf_jit_harden=2`, `unprivileged_userfaultfd=0`, the `fs.protected_*` set, redirect/source-route/forwarding off, `log_martians=0` (martian logging would record addresses, LOG-007), `rp_filter=1`.
- **`user.max_user_namespaces = 0`.** No unit uses `PrivateUsers=`. config-check's nftables check uses `unshare -n` as root, which needs CAP_SYS_ADMIN but no user namespace, so it keeps working.
- **ptrace_scope 3.** Chosen over 2: nothing on H-INTAKE needs ptrace, and mode 3 cannot be lowered without a reboot.
- **Core dumps.** `coredump.conf.d/50-candor-intake.conf` (`Storage=none`, all sizes 0); the installer masks `systemd-coredump.socket`; `LimitCORE=0` in all units.
- **Swap.** Disabled; `--host` accepts only no swap or dm-crypt swap with a fresh `/dev/urandom` key (`crypttab` option `swap`). zram and plain swap fail.
- **Checks.** Static mode checks the file against the baseline (no extra or missing keys). `--host` reads the live `/proc/sys` values (so any later sysctl.d file or runtime change is caught) and the effective coredump configuration.

**D-31 config-check architecture (AUD-RM2-DEP-01/02/03).**
- **Effective configuration, allow-lists.** See the script header. Expected values live in `deploy/tools/config-check.baseline` next to the script (root-owned like the script; the mutation tests copy only `deploy/intake`, so they cannot edit it).
- **tor.** The torrc text must use only full template option names (no abbreviations, no `+`/`/` prefixes, no `%include`, no repeats). Then tor itself canonicalises it in a private mount namespace (tmpfs over `/var/lib` and `/run`, so real state and keys are never touched), running as the instance user. The `--dump-config short` output (every non-default option) must equal the allow-list exactly, with integer ranges only for the six DoS tunables; the `--dump-config full` output must show the required defaults and empty `HSLayer2Nodes`/`HSLayer3Nodes`/`EntryNodes`/`ExcludeNodes`/...
- **nftables.** `include`/`define`/`$` are rejected before nft sees the file (an include could also make the root-run checker read an arbitrary file; nft's error output is never echoed). The file is loaded with `unshare -n` and read back with `nft -j list ruleset`; every rule of every chain must equal the template rule at the same position, so extra accepts, reordering and include-injected rules all fail. Sets `non_public4/6` are pinned; `mon_hosts`/`admin_jump`/`core_relay` may only contain plain IPv4 addresses (`core_relay` at most one). `--host` checks the loaded ruleset as well and that its `@core_relay` matches the file.
- **systemd.** `systemd-analyze verify --root=<tree>` at debug level lists the fragment and every drop-in systemd applies (unit, prefix `candor-.service.d`, template `tor@.service.d`, type `service.d`, `/etc`, `system.control`, `/run`, `/usr/local/lib`, `/usr/lib`). Their section-aware merge must equal the baseline for every key in every section; resets, overrides, extra directives and directives in the wrong section all fail. `systemd-analyze verify` must be clean, and `systemd-analyze security` must meet the budget with only the documented items scoring. `--host` also rejects transient and generator drop-ins, compares `systemctl show -p DropInPaths` with the files, requires `NeedDaemonReload=no`, and checks key properties of the loaded units. The relay socket's `IPAddressAllow=` must be exactly `<@core_relay>/32`.
- **Sealer syscall filter.** Its lines belong to the sealer hardening work (AUD-RM2-SEA-06), so the baseline marks the key `*`: it must start in allow-list mode, never be reset, and systemd's assessment must show every deny group closed. Pin it exactly once SEA-06 is merged.
- **PostgreSQL.** Static: the conf file (no includes, no duplicates, exact values incl. WAL). `--host`: `postgresql.auto.conf` must be empty, and `postgres -C <guc>` (run as the data directory owner) must return the expected effective value for 51 settings. `-c` options on `ExecStart` are impossible because `ExecStart` is pinned exactly.
- **Requirements.** root, `jq`, `tor`, `nft`, `unshare`, `setpriv`, `systemd-analyze`, and the PostgreSQL binary for `--host`; anything missing is a FAIL. **Spec feedback (17 §5.1 "no interpreter"):** `jq` is a JSON filter, not a general interpreter; it must be added to the H-INTAKE Platform Manifest for this check (or the check runs off-host on an exported ruleset).
- **Not verifiable here.** The live `--host` parts (`systemctl show` property formats, the loaded ruleset, `/proc/sys`, AppArmor load state) need a real PID 1; they were exercised only offline (`--root`) in this container.

**D-32 check-placement (AUD-RM2-DEP-10).** A manifest entry whose `id` is in `[forbidden]` is a violation. Every path component of an entry is checked for symlinks, not only the leaf. On a host (no `--root`), the onion key's filesystem must be backed by a dm-crypt device (`findmnt -T` + `lsblk -s`); with `--root` that check is reported as SKIP. The `ED25519-V3:` export format is recognised as a tor onion key.

## Open items for integration (Debian 13, systemd 257, real PID 1)

1. Start every unit under its sandbox with real binaries and the AppArmor profiles in enforce mode. Fail on any `apparmor="DENIED"` line (R7 B4).
2. Confirm that `LoadCredentialEncrypted=` from `/etc/credstore.encrypted` works with TPM2 sealing. The web, tor and PostgreSQL units list that directory in `InaccessiblePaths=`; the sealer and store do not, because they load from it.
3. Confirm `LogNamespace=` together with `PrivateNetwork=` and socket activation, and `TemporaryFileSystem=/var:ro` together with `BindPaths=`.
4. Confirm that tor `Type=notify` works with the Platform-Manifest tor build, and confirm the PROXY header on the Unix target (D-04).
5. Test PoW under load with `CompiledProofOfWorkHash 0` (D-03).
6. Confirm that tor needs neither AF_NETLINK nor AF_INET6 on an IPv4-only uplink (D-06).
7. Run `config-check.sh --host` on the installed host (live: `systemctl show` property formats, loaded nft ruleset, `/proc/sys`, AppArmor enforce state). Confirm that `LogLevelMax=emerg` suppresses PID 1's messages about the units in the host journal (D-28), that `InaccessiblePaths=-/var/tmp` wins over `PrivateTmp=`'s `/var/tmp` (AUD-RM2-DEP-12; on systemd ≥ 256 switch to `PrivateTmp=disconnected`), and that tor reaches `http.sock` through its primary group (AUD-RM2-DEP-11) with a real rendezvous.
8. Enforce-mode runs of the new `candor-tor-intake` and `candor-intake-pg` profiles under load, including tor's `Sandbox 1` start-up and PostgreSQL checkpoints and autovacuum (D-22).

## Security self-review (OWASP ASVS 5.0 L3 mindset; owner OPSEC bar)

What I checked, reading the diff as an attacker:

- **Clearnet exposure.**
  - **tor.** tor has every `*Port` set to 0 and no TCP listener. Its only service target is a Unix socket.
  - **Web and PostgreSQL.** The web service and PostgreSQL have no network namespace access at all.
  - **Relay port.** The only inbound IP port is relay0:7443. It is restricted three times: by `BindToDevice`, by the socket unit's `IPAddressDeny=any` plus the single allowed address, and by nftables `@core_relay`.
  - **Config check.** config-check evaluates effective configuration (D-31) and rejects 162 mutations (the original 80, all bypasses of AUD-RM2-deploy, and new-artefact cases; 21 of them on a synthetic installed host with `--host --root`), including a SocksPort, ControlPort or MetricsPort, a TCP onion target (also abbreviated), an extra HiddenServicePort, inbound HTTP, an nft include and a PostgreSQL TCP listener.
- **Egress and no clearnet fallback.**
  - **ext0.** Only the two tor UIDs may leave ext0, TCP only, and only to public addresses.
  - **Candor services.** They have `PrivateNetwork=yes` and AF_UNIX only, plus nftables.
  - **DNS and NTP.** There is no DNS. Public NTP is impossible; only chrony may reach H-MON.
  - **Firewall failure.** A failed nft load keeps every intake unit stopped (`Requires=nftables.service`).
- **Logging and metadata.**
  - **tor.** `SafeLogging 1`, `warn` only, 1 h granularity, no hidden-service statistics, never a file.
  - **PostgreSQL.** It emits nothing: `log_min_messages = panic` and `StandardError=null` (D-26, AUD-RM2-STO-02). `update_process_title=off`.
  - **journald.** No service output at all (D-28); the namespace and host journal are volatile, hourly files, ≤ 24 h, `Audit=no`.
  - **nftables.** No LOG targets.
  - **Verification.** The PG run confirmed zero bytes of server output, even after errors.
  - **Process titles and banners.** Process titles carry no role or database. Version banners go to `/dev/null` for tor (D-02).
- **Secrets.**
  - **At rest.** Secrets are TPM-sealed credentials, root-only at rest and per-unit at runtime. No `Environment=` or plain `LoadCredential=` is allowed; config-check enforces this.
  - **Placement.** The manifest catches unlisted keys, copies, symlinks, hard links, wrong modes, a missing key, and a second onion key copy (NET-043).
- **Privilege.**
  - **Users.** Every unit runs as its own non-root user.
  - **Capabilities and privilege escalation.** Capabilities are empty, `NoNewPrivileges=yes` is set, and no `+`/`!` exec prefixes are used.
  - **Filesystem.** `ProtectSystem=strict`, `NoExecPaths=/` with `ExecPaths=/usr`, and `/var` hidden apart from each unit's own state.
  - **Syscalls and memory.** Syscalls are filtered from `@system-service` minus 13–14 groups. MDWE is on everywhere. `LimitCORE=0` is set everywhere.
  - **AppArmor.** Enforce profiles deny exec, IP networking (except the store's inherited TCP), `ptrace` and capabilities, and fail closed if missing.
  - **Drop-ins.** config-check uses systemd's own drop-in resolution (all locations, prefix/template/type drop-ins) and compares the merged, section-aware result with an exact per-unit allow-list; `--host` adds transient/generator directories and the loaded unit's `DropInPaths`. Tested for each location.
  - **Kernel.** sysctl baseline (ptrace scope 3, no core dumps, no unprivileged BPF/userns, no TCP timestamps), coredump storage off, swap off (D-30); live values checked by `--host`.
- **Fail-closed behaviour.**
  - Empty nft address sets.
  - Relay socket `IPAddressDeny=any` until the site drop-in exists.
  - A missing AppArmor profile, missing credential or missing `noswap` support stops the unit.
  - The checkers exit non-zero on any unreadable input or manifest parse error.
- **The tools themselves.** They run as root on attacker-influenced input.
  - **Process.** No `eval`. All variables are quoted. `--` is passed before paths. `umask 077`, `mktemp` and a cleanup trap are used.
  - **Patterns and paths.** Regexes are built in rather than taken from the manifest. Manifest paths are validated (absolute, no `..`, restricted charset). Unknown or duplicate manifest keys are errors.
  - **File names.** A newline in a file name is itself a violation.
  - **Output.** Report output is reduced to printable ASCII to block terminal-escape injection.
  - **Content.** File contents are never printed.

Residual risks (accepted or out of scope for this slice):

1. **CE-SINGLE.** The hypervisor and the host admin can read all intake RAM: Tier W plaintext, keys and the volatile journal (18 §4.1). This deployment does not change that.
2. **Live root compromise of H-INTAKE.** It defeats every control here; tor's key is online (16 §10, OI-3).
3. **Untested sandbox details.** The runtime sandbox interactions in the open items list are untested in this container, which has no systemd as PID 1. They fail closed (the unit does not start), not open.
4. **Staging tmpfs on restart.** The staging tmpfs survives a store restart until the application clears it (D-10).
5. **Scan limits.** check-placement does not content-scan files over 1 MiB, ciphertext-only directories, `/run/credentials` or binary key formats. A deliberate insider can hide a key from it, so the check targets accidental misplacement (B-SD-22).
6. **Crash diagnostics.** PostgreSQL's and every other intake service's output is discarded (D-26, D-28). tor's PoW verifier is interpreted (D-03).
7. **Spec gaps.** D-04, D-11 (migrations), D-18 and D-19 need owner decisions. Until then the strict choice applies.
8. **Checker trust.** config-check and its baseline are root-owned files on the host they check; a root attacker can change them (ST-120 detects drift and mistakes, not a live root compromise; see residual 2). The checker runs tor (unprivileged, private mount namespace) and nft (private network namespace) on the configuration under test, and never echoes their error output.
9. **Health signal (D-27).** Without control access, descriptor-level health values are gone from the intake host; reachability relies on the external C-25 probe and the update-instance self-fetch.

## Fixes for AUD-RM2-DEP (process/audits/AUD-RM2-deploy.md)

| ID | Sev. | Fix | Where | Test |
|---|---|---|---|---|
| DEP-01 | High | Name denylist replaced by an allow-list on **effective** tor configuration: raw text must use full template option names only (no abbreviations, `+`/`/` prefixes, `%include`, repeats); tor itself canonicalises the file in a private mount namespace (`--verify-config`, `--dump-config short/full`) and the short dump must equal the allow-list (DoS tunables in ranges), the full dump must show the required defaults and empty node-restriction options (D-31). | `tools/config-check.sh` (`check_torrc`), `tools/config-check.baseline` (`tor*` lines) | all 7 audit variants plus `HSLayer3Nodes`, `DirAuthority`, `ExcludeNodes`, `Sandbox 0`, control socket re-added (with and without cookie auth), log file |
| DEP-02 | High | `include`/`define`/`$` rejected before load; the ruleset is loaded with `unshare -n` and the kernel's rules (`nft -j list ruleset`) must equal the template rule by rule, in order; safety drops must precede every UID accept; fixed sets pinned, site sets plain addresses only; `--host` also checks the loaded ruleset (D-31). | `config-check.sh` (`check_nft`, `nft.jq`), baseline `nft-*` lines | include accept-all, `define`, E1 above the safety drops, extra rule, `core_relay` as 0.0.0.0/0 interval, `non_public4` element removed |
| DEP-03 | High | Units are evaluated as systemd resolves them: fragment + every drop-in (`systemd-analyze verify --root` unit dump: prefix, template, type, `system.control`, `/run`, `/usr/local/lib`, `/usr/lib`), merged section-aware; every key of every section must equal the per-unit baseline (exact `ExecStart`, `Group`, `SupplementaryGroups`, `AppArmorProfile`, `SocketUser/Group`, ...; unknown or extra directives fail); `systemd-analyze verify` clean; `systemd-analyze security` threshold and item list; relay `IPAddressAllow` = `<@core_relay>/32`. `--host`: transient/generator drop-ins rejected, `systemctl show` drop-ins and properties, `NeedDaemonReload=no`, `postgresql.auto.conf` empty and `postgres -C` effective values. | `config-check.sh` (`check_units`, `check_units_live`, `check_pg`), baseline `unit|`, `sec|`, `pgc|`, `show|` | PG `ExecStart -c` override, `Environment=PGOPTIONS`, keys moved to `[Install]`, `ReadWritePaths=/`, `BindReadOnlyPaths`, `SupplementaryGroups`, `DeviceAllow`, `SocketBindAllow`, `Group=` removed, `TemporaryFileSystem` removed, `InaccessiblePaths` removed, wrong `AppArmorProfile`, `SocketUser/SocketGroup=users`, relay `IPAddressAllow=any` and a non-`@core_relay` address, prefix/template/type drop-ins, `ExecStartPre`, sealer filter reset to deny-list, line continuation, unknown key; host-root cases for `system.control`, `/run`, `/usr/lib` prefix, `/usr/local/lib` template, transient and generator drop-ins; `postgresql.auto.conf` (`ALTER SYSTEM`) with `CANDOR_TEST_PG` |
| DEP-04 | Med | No tor control interface at all; `_candor-torctl` removed; health = unit liveness + onion self-fetch through a SOCKS Unix socket of the client-only `candor-update` instance (NET-045 forbids it on the intake instance); spec amendment requested (D-27). | `intake/torrc`, `sysusers.d`, tor unit, `config-check.sh` | control socket re-added; host: `_candor-torctl` recreated, member in tor's group |
| DEP-05 | Med | All five source-path units: `StandardOutput=null`, `StandardError=null`, `LogLevelMax=emerg`; namespace `MaxLevelStore=crit`; spec amendment requested (D-28). | 5 units, `journald@candor-intake.conf` | tor/web stderr to journal, namespace storing `warning` |
| DEP-06 | Med | Host journal `MaxFileSec=1h`, `Audit=no`; `LogLevelMax=emerg` also filters PID 1's messages about the units; effective journald config checked via `cat-config`; `--host`: `systemd-journal`/`adm` groups empty (D-28). | `candor-intake-host.conf`, `config-check.sh` | host journal without `MaxFileSec`, `Audit=yes`; host-root drop-ins setting `Storage=persistent` and namespace forwarding; admin in `systemd-journal` |
| DEP-07 | Med | `max_wal_size=256MB`, `min_wal_size=32MB`, `wal_recycle=off`, `checkpoint_timeout=5min`; comment corrected (D-29). | `postgresql/candor-intake.conf`, baseline `pg|`/`pgc|` | `max_wal_size 1GB`, `wal_recycle on`; live cluster settings |
| DEP-08 | Med | Enforce-mode AppArmor profiles `candor-tor-intake` and `candor-intake-pg`, attached without `-` (D-22); `--host` requires all five profiles loaded in enforce mode. | `apparmor/`, tor and PG units | tor profile removed, PG soft-fail `-`, host: profile file missing |
| DEP-09 | Med | sysctl baseline, coredump `Storage=none`, coredump socket masked, swap none or random-key dm-crypt; static file allow-list, live `/proc/sys` with `--host` (D-30). | `sysctl.d/`, `coredump.conf.d/`, `config-check.sh` (`check_kernel`) | ptrace_scope 1, core_pattern pipe, tcp_timestamps 1, key dropped, extra key, coredump stored; host-root: later sysctl.d and `/etc/sysctl.conf` overrides, `coredump.conf.d` override, socket unmasked, plain swap in fstab |
| DEP-10 | Low | `[forbidden]` ids enforced, every path component checked for symlinks, onion key must be on dm-crypt (`--host` only), `ED25519-V3:` export pattern (D-32). | `tools/check-placement.sh` | forbidden id, symlinked tor state dir, exported key |
| DEP-11 | Low | tor runs with `Group=_tor-candor-intake` (its primary group owns the web socket directory); no control group needed any more. Real rendezvous stays an integration item. | tor unit | `Group=_candor-torctl` mutation |
| DEP-12 | Low | AppArmor validation checks the parser's exit status; PostgreSQL test stops its own postmaster by PID; `InaccessiblePaths=-/var/tmp` on all five units (`PrivateTmp=disconnected` needs systemd ≥ 256; integration item 7). | `tests/validate.sh`, 5 units | `/var/tmp` line removed from tor |
| DEP-13 | Info | Unchanged: PoW load test with the interpreted verifier remains open item 5. | — | — |
| DEP-14 | Info | `--host` requires `tor.service` and `tor@default.service` masked; the update instance, chrony and apt `tor+https` remain next-slice work (D-27 adds the health SOCKS socket to that list). | `config-check.sh` (`check_host`), README step 7 | host: `tor@default` unmasked |

**Not done, with reason.** None of the findings was left unfixed. The `--host` live paths cannot be exercised without a real PID 1 and are integration item 7. The sealer's `SystemCallFilter=` is checked semantically, not pinned, until AUD-RM2-SEA-06 lands (D-31).
