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

**D-07 tor control-socket group.**
- **Mechanism.** The tor unit uses `Group=_candor-torctl`, so `control.sock` and `control.authcookie` get that group (NET-009). `HiddenServiceDir`, the key and `DataDirectory` stay 0700/0600.
- **Verified.** This was verified with tor 0.4.9.11 and `DisableNetwork 1`.
- **Membership.** Only `candor-health` may be a member. The vanguards add-on is not deployed (ADR-049(1)).

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
- **Key group.** The key's group is `_candor-torctl` (D-07). Mode 0600 gives it no access.

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

**D-15 Journald namespace (owner OPSEC instruction).** tor, web, sealer and store log to `LogNamespace=candor-intake`. PostgreSQL emits nothing (D-26).
- **Storage.** Volatile, `RuntimeMaxUse=16M`, `MaxRetentionSec=24h`, `MaxFileSec=1h`.
- **Filtering.** `MaxLevelStore=warning`. No forwarding to syslog, kmsg, console or wall.
- **Per unit.** The four logging units set `StandardOutput=null`, `SyslogLevel=warning` (un-prefixed stderr is stored) and `LogLevelMax=warning` (anything explicitly lower is dropped at the source).
- **Not chosen.** `Storage=none` was considered and rejected. NET-008 and 32 `tor.daemon`/`logging.config` need tor and service warnings visible to the health agent for ≤ 24 h.

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

**D-22 AppArmor coverage.** Profiles ship for `candor-web`, `candor-sealer` and `candor-intake-store`; the brief asked for two, and the store was added. 17 §5.2 and R7 SI-B-04 also want enforce-mode profiles for tor and the intake PostgreSQL. Debian's `system_tor` profile exists. A tightened PostgreSQL profile is a follow-up.

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

The remaining exposure items are `PrivateUsers`, `RootDirectory`, AF_UNIX allowed, `SupplementaryGroups`, and the implicit `char-rtc` device ACL that comes with `ProtectClock`. tor additionally has network access by design.

## Open items for integration (Debian 13, systemd 257, real PID 1)

1. Start every unit under its sandbox with real binaries and the AppArmor profiles in enforce mode. Fail on any `apparmor="DENIED"` line (R7 B4).
2. Confirm that `LoadCredentialEncrypted=` from `/etc/credstore.encrypted` works with TPM2 sealing. The web, tor and PostgreSQL units list that directory in `InaccessiblePaths=`; the sealer and store do not, because they load from it.
3. Confirm `LogNamespace=` together with `PrivateNetwork=` and socket activation, and `TemporaryFileSystem=/var:ro` together with `BindPaths=`.
4. Confirm that tor `Type=notify` works with the Platform-Manifest tor build, and confirm the PROXY header on the Unix target (D-04).
5. Test PoW under load with `CompiledProofOfWorkHash 0` (D-03).
6. Confirm that tor needs neither AF_NETLINK nor AF_INET6 on an IPv4-only uplink (D-06).

## Security self-review (OWASP ASVS 5.0 L3 mindset; owner OPSEC bar)

What I checked, reading the diff as an attacker:

- **Clearnet exposure.**
  - **tor.** tor has every `*Port` set to 0 and no TCP listener. Its only service target is a Unix socket.
  - **Web and PostgreSQL.** The web service and PostgreSQL have no network namespace access at all.
  - **Relay port.** The only inbound IP port is relay0:7443. It is restricted three times: by `BindToDevice`, by the socket unit's `IPAddressDeny=any` plus the single allowed address, and by nftables `@core_relay`.
  - **Config check.** config-check rejects 78 mutations, including a SocksPort, ControlPort or MetricsPort, a TCP onion target, an extra HiddenServicePort, inbound HTTP and a PostgreSQL TCP listener.
- **Egress and no clearnet fallback.**
  - **ext0.** Only the two tor UIDs may leave ext0, TCP only, and only to public addresses.
  - **Candor services.** They have `PrivateNetwork=yes` and AF_UNIX only, plus nftables.
  - **DNS and NTP.** There is no DNS. Public NTP is impossible; only chrony may reach H-MON.
  - **Firewall failure.** A failed nft load keeps every intake unit stopped (`Requires=nftables.service`).
- **Logging and metadata.**
  - **tor.** `SafeLogging 1`, `warn` only, 1 h granularity, no hidden-service statistics, never a file.
  - **PostgreSQL.** It emits nothing: `log_min_messages = panic` and `StandardError=null` (D-26, AUD-RM2-STO-02). `update_process_title=off`.
  - **journald.** Volatile and capped at 24 h and 16 MiB.
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
  - **Drop-ins.** config-check evaluates the unit plus all drop-ins, so a later drop-in cannot reset a filter or re-enable networking. Both cases are tested.
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
6. **PostgreSQL crash diagnostics.** They are discarded (D-26). tor's PoW verifier is interpreted (D-03).
7. **Spec gaps.** D-04, D-11 (migrations), D-18 and D-19 need owner decisions. Until then the strict choice applies.
