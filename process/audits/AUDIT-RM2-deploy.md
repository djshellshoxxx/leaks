<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# AUDIT-RM2-deploy — Intake host deployment artefacts (C-05 tor, C-06/C-07/C-08 confinement, PostgreSQL, journald, nftables, checkers)

| Field | Value |
|---|---|
| Step | RM-2 (deploy slice: IMPL-RM2-INTAKE §2.1 / §2.2) |
| Audited revision | `9f368a303d085910eb9344585f3415d85f28b3b2` plus the uncommitted working tree under `deploy/` (read on 2026-10-01) |
| Scope | `deploy/README.md`, `deploy/SPEC-NOTES.md`, `deploy/intake/**` (torrc, nftables.conf, 10 systemd units/sockets/mount, nftables drop-in, 2 profile drop-in sets, 3 AppArmor profiles, PostgreSQL conf/hba/ident, journald x2, sysusers, tmpfiles, resolv.conf, secret-placement.toml), `deploy/tools/{config-check.sh,check-placement.sh}`, `deploy/tests/validate.sh` |
| Tier | All T1 (trust path / source-facing host confinement); checkers T2 but run as root on attacker-influenced input |
| Auditor | Independent auditor (did not write this code) |
| Date | 2026-10-01 |
| Inputs read | R9 §6.3–§6.6; AUDIT-CHECKLIST §A–§G (B1, B9.5, B10 focus); BUILD-BRIEF "Security and OPSEC bar" + RM-2 addendum; IMPL-RM2-INTAKE §2.1, §2.2, §4 (A1–A15), §6; specs 09 §10/§13, 17 §4.3/§5, 20 §11.3/§11.4 (LOG-004/005/007); ADR-032 |
| Time per phase | A1 10 % · A2 10 % · A3 45 % · A4 (tools + adversarial edits) 30 % · A5 5 % |

## Tools (versions, results)

| Tool | Version | Command | Result |
|---|---|---|---|
| shellcheck | 0.9.0 | `shellcheck -S style -x deploy/tools/*.sh deploy/tests/*.sh` | clean |
| systemd-analyze | 255 (255.4) | `systemd-analyze security --offline=true <unit>` | tor 1.4, web 0.4, sealer 0.4, store 0.4, PostgreSQL 0.5. All within budget (≤1.5 tor, ≤0.5 others). Remaining tor items: AF_INET, no PrivateNetwork, `@resources`, no ProcSubset, no PrivateUsers. All are documented (D-06, D-21). |
| nft | 1.0.9 | `nft -c -f deploy/intake/nftables.conf` | OK |
| apparmor_parser | 4.0.1 | `apparmor_parser -Q -K -T <profile>` x3 | OK (parse only; enforce-mode behaviour is not verifiable here) |
| tor | 0.4.9.11 | `tor --defaults-torrc /dev/null -f torrc --verify-config` as `_tor-candor-intake` | valid. Adversarial variants: see DEP-01 |
| PostgreSQL | 16.13 | `CANDOR_TEST_PG=1 deploy/tests/validate.sh`; `postgres -C max_wal_size` | Effective settings, peer-only access and zero log bytes confirmed. `max_wal_size` = 1024 MB (DEP-07) |
| validate.sh | in-repo | `deploy/tests/validate.sh` (with and without `CANDOR_TEST_PG`) | 127 PASS, 0 FAIL, 1 SKIP (PG, without the env var) |
| config-check.sh (adversarial) | in-repo | 22 hand-made mutations outside the builder's mutation set | **17 accepted (exit 0)**. Details in DEP-01/02/03 |
| lynis | 3.0.9 | — | **Not run.** B10.8 applies to a built deployment image; this container is not one |

## Attacker goals (A2)

| # | Goal | Result |
|---|---|---|
| G1 | Get source IP / UA / circuit data into any log (tor, journald, PG, kernel, nft) | Refuted for the shipped config. Sources have no IP at intake; tor has `SafeLogging 1` and logs at warn; nft has no LOG target; PG emits nothing. **But** the configuration checker can be bypassed into SafeLogging 0, info-level logs and PG statement logging (DEP-01, DEP-03), and the control socket allows circuit/stream event subscription (DEP-04) |
| G2 | Record the exact time of a source action | **Finding.** journald stamps every stored line with µs precision, so tor's `LogTimeGranularity` and LOG-004 hour truncation have no effect there (DEP-05). PID 1 crash records go to the host journal, which can keep them for more than 24 h (DEP-06). WAL commit records are kept in up to 1 GB, against the 256 MB the spec requires (DEP-07) |
| G3 | Clearnet egress / DNS / NTP from any process | Refuted for the shipped ruleset (output policy drop, tor UIDs only, TCP only, public destinations only; resolv.conf points at loopback; NTP only to H-MON). **But** an nft `include` passes the checker and can re-open egress (DEP-02) |
| G4 | Expose the onion key (permissions, placement, backup, HA) | Refuted for the shipped files (0700/0600, tor-owned, a single copy is enforced). Residual gaps: no check that the key sits on an encrypted volume, parent-directory symlinks are not detected, `[forbidden]` is never enforced (DEP-10). Two-host HA (ADR-032) is out of scope for CE |
| G5 | Deanonymise the service by steering tor's path selection (guard pinning, fake directory authority) | **Finding.** Via torrc options the checker does not cover (DEP-01), or via the control socket (DEP-04) |
| G6 | Escape or weaken the sandbox of web/sealer/store (AF_INET, writable paths, capabilities, syscalls) | Refuted for the shipped units (exposure ≤0.5, AF_UNIX, PrivateNetwork, no capabilities, MDWE, LimitCORE=0). The checker can be bypassed (DEP-03). tor has no AppArmor profile (DEP-08) |
| G7 | Make PostgreSQL log statements, bind values or connection times | Refuted for the shipped conf and unit. A unit `ExecStart=` override with `-c logging_collector=on …` passes the checker (DEP-03) |
| G8 | Abuse the root-run checkers or validate.sh (injection, terminal escape, unsafe temp files) | Refuted: no eval, all variables quoted, `mktemp`, output reduced to printable characters, manifest charset validated. Minor issues in DEP-12 |
| G9 | Disable the PoW / intro-point DoS defences | Refuted (exact-value checks, tor verifies). The trade-off of `CompiledProofOfWorkHash 0` is noted (DEP-13) |

## Summary

| Severity | Count | IDs |
|---|---|---|
| Critical | 0 | — |
| High | 3 | DEP-01, DEP-02, DEP-03 |
| Medium | 6 | DEP-04, DEP-05, DEP-06, DEP-07, DEP-08, DEP-09 |
| Low | 3 | DEP-10, DEP-11, DEP-12 |
| Info | 2 | DEP-13, DEP-14 |

Gate: **FAIL** (3 open High). The shipped configuration files themselves are strong. Every High is in the configuration checker, which these artefacts rely on to detect drift and tampering (ST-120, 18 §14).

---

### AUD-RM2-DEP-01 — config-check accepts torrc edits that disable Sandbox, cookie auth and SafeLogging, add a TCP onion target, pin HS guards or add a directory authority
- Severity: High
- Location: `deploy/tools/config-check.sh:108-221` (`tor_vals`, `check_torrc`)
- Category: B10.5, B10.7 (CWE-184 incomplete denylist, CWE-1173)
- Description: the torrc check matches option names exactly against a denylist. tor's parser accepts more forms than that:
  - **`/Option` lines.** These reset an option to its default (confline.c `CONFIG_LINE_CLEAR`).
  - **`+Option` lines.** These append a value.
  - **Deprecated prefix abbreviations.** tor accepts these with only a warning.

  The checker counts only lines whose key is exactly `Sandbox`, `Log` and so on, so none of these forms is caught. Option families that do the most damage to anonymity are also on no list. All of the following were verified with tor 0.4.9.11 (`--verify-config` says valid, `--dump-config short` shows the effective change), and `config-check.sh --dir` exits 0 for each:
  - `/Sandbox`: Sandbox is effectively 0.
  - `/CookieAuthentication`: the control socket has no authentication.
  - `SafeLog 0`: SafeLogging is effectively 0.
  - `+Log info stderr`: info-level log output. Because of `SyslogLevel=warning`, journald stores every unprefixed tor line at warning, so `LogLevelMax=warning` does not filter it.
  - `HiddenServicePor 81 127.0.0.1:8080`: a second HiddenServicePort with a TCP target.
  - `HSLayer2Nodes <fp>` / `StrictNodes 1`: pins the onion service's layer-2 guards to chosen relays.
  - `AlternateDirAuthority …`: tor trusts an attacker-run directory authority.

  Single `EntryNodes`, `SocksPor 9050` and `ControlPor 9051` are rejected by tor itself.
- Exploit scenario: ADV insider or compromised config management, or an admin following a bad tuning guide. Requires write access to `/etc/tor/instances/candor-intake/torrc`, which is root-owned. The ST-120 check passes, so the host looks compliant. Effects:
  - SafeLogging off plus info logging puts per-circuit events into the journal.
  - Layer-2 pinning or a rogue directory authority enables guard discovery and deanonymisation of the service location (INC-35).
  - With Sandbox off, a tor RCE has more reach.

  This is a silent degradation of a protection (Critical class), lowered one level for the root precondition.
- Fix recommendation:
  - Replace the denylist with an **allowlist**. Every non-comment line must have a key from the template's set (exact, case-insensitive). Reject any key starting with `+`, `/` or `_`, and any key that is not a full option name.
  - Compare the whole file against the release template, allowing only the 16 §7.1 numeric tunables to differ. This implements NET-004's hash pin (`tor.config_hash`).
  - In `--host` mode, also run `tor --verify-config` followed by `tor --dump-config short` as the tor user, and diff the effective option set against an expected list.
  - Add each variant above to `validate.sh` as a mutation (SG-21).
- Spec / requirement reference: 16 §7.1/§7.4, NET-004/005/008/010, LOG-005, ADR-049; IMPL-RM2 §4 A1/A2, ST-120; BUILD-BRIEF "Fail closed".
- Status: Open

### AUD-RM2-DEP-02 — config-check accepts an nftables `include` (which can insert an accept-all rule) and accepts template accept rules moved above the safety drops
- Severity: High
- Location: `deploy/tools/config-check.sh:224-315` (`nft_clean`, `check_nft`)
- Category: B10.4 (CWE-184)
- Description: the nft check reads only the top-level file. nft follows `include` directives, but the checker does not check for them. Verified:
  - Appending `include "/path/extra.nft"`, where that file holds `insert rule inet candor_intake output accept`, gives `nft -c` OK and config-check exit 0. The result is unrestricted egress for every UID, including clearnet DNS and NTP by any daemon.
  - Accept rules are compared by text only, not by position. Moving the template E1 line `oifname "ext0" meta skuid "_tor-candor-intake" … accept` above the `169.254.0.0/16` and `@non_public4` drops also passes (exit 0). tor can then reach cloud metadata, the LAN and relay0 subnets through ext0. The tor unit's `IPAddressDeny=` still blocks this, which is why the overall severity rests on the `include` case.
- Exploit scenario: same actor class as DEP-01. One include line silently removes the "no clearnet" guarantee (ADR-002) at host level. Candor units keep `PrivateNetwork=yes`, but tor-update, chrony, apt/root and any future package do not.
- Fix recommendation:
  - Reject any `include`, `define` or `$variable`, and any `add`/`insert`/`replace` command outside the table block.
  - Better: compare the normalised ruleset with the template, allowing only the three set-element lists to vary.
  - In host mode, also check the **loaded** ruleset: `nft -j list ruleset`, compared with the template after replacing the set elements.
  - Check rule order: the metadata and non-public drops must come before E1/E2.
  - Add mutations for both cases to `validate.sh`.
- Spec / requirement reference: 17 §4.3/§4.3.1, 16 §14.2, NET-031/041, LOG-007, ADR-002/009; IMPL-RM2 §4 A2.
- Status: Open

### AUD-RM2-DEP-03 — config-check unit checks are bypassable: PostgreSQL `ExecStart=` `-c` overrides, keys moved to another section, unchecked weakening directives, unread drop-in directories in host mode
- Severity: High
- Location: `deploy/tools/config-check.sh:413-490` (`unit_vals`, `unit_expect_many`, `check_service`), `:562-590` (`build_effective_units`), `:668-680`
- Category: B10.1, B10.2, B9.5 (CWE-184, CWE-693)
- Description: these were each verified by editing a copy of the tree. config-check exits 0 in every case:
  1. **PG logging re-enabled.**
     - Edit: a drop-in `ExecStart=` / `ExecStart=…postgres -c config_file=… -c logging_collector=on -c log_statement=all -c log_min_messages=info -c log_line_prefix=%m`.
     - Effect: command-line GUCs override `candor-intake-conf`, so the collector writes every statement with ms timestamps to `<datadir>/log` on disk. The unit has the data directory read-write, and `StandardError=null` does not apply to collector files. This undoes AUD-RM2-STO-02.
     - Also not read: `<datadir>/postgresql.auto.conf` (ALTER SYSTEM), which PG loads (confirmed by `postgres -C`).
  2. **Section misplacement.**
     - Edit: move `PrivateNetwork=yes` and `RestrictAddressFamilies=AF_UNIX` from `[Service]` to `[Install]` in `candor-sealer.service`.
     - Effect: systemd ignores them there, and `systemd-analyze security` rises to 1.5 (network allowed). The checker greps keys regardless of section.
  3. **Weakening directives that are never examined.**
     - `ReadWritePaths=/`, `BindReadOnlyPaths=/var/lib/tor-instances`, `SupplementaryGroups=_tor-candor-intake postgres`, `DeviceAllow=/dev/mem rw`, `SocketBindAllow=`.
     - `Group=`; `TemporaryFileSystem=` and every `InaccessiblePaths=` line can be removed.
     - `AppArmorProfile=candor-intake-store` on the sealer (any `candor-*` name is accepted).
     - `SocketUser`/`SocketGroup` on the IPC sockets (changed to `users`).
     - `IPAddressAllow=any` on the relay socket: the README asks for a `<core>/32` drop-in, but its value is never checked.
  4. **Host mode reads only `/etc`, `/run` and `/usr/lib` `<unit>.d/`.**
     - Missed: prefix drop-ins (`candor-.service.d/`), template drop-ins (`tor@.service.d/`), top-level `service.d/`, `/etc/systemd/system.control/` (written by `systemctl set-property`), `/run/systemd/transient`, generator directories and `/usr/local/lib/systemd/system`.
     - Verified: `--host --root` exits 0 with `candor-.service.d/zz.conf` setting `PrivateNetwork=no`, `RestrictAddressFamilies=`, `SystemCallFilter=` and `AppArmorProfile=`, plus a `tor@.service.d` reset and a `system.control` `IPAddressDeny=` reset.

  The self-review claim "a later drop-in cannot reset a filter or re-enable networking" holds only for `<unit>.d/` in the three directories read.
- Exploit scenario: same actor class as DEP-01. Item 1 brings back the exact source-timing leak that AUD-RM2-STO-02 fixed, persisted to disk. Items 2–4 silently strip the sandbox from the sealer, web or tor while ST-120 reports PASS.
- Fix recommendation:
  - On hosts, evaluate the **effective** unit as systemd sees it: `systemctl show -p <Prop>… <unit>` (or `systemd-analyze security --json=short` plus `systemctl cat`), not by grepping files.
  - Statically, parse sections and accept only keys under `[Service]`/`[Socket]`/`[Mount]`. Use an allowlist of permitted keys per unit with exact values (`ExecStart=` included), so that unknown or extra directives fail.
  - Pin `AppArmorProfile` per unit, and pin `SocketUser`, `SocketGroup` and `DirectoryMode`.
  - Require the relay socket's `IPAddressAllow=` to be a single `/32` that equals the `@core_relay` element.
  - Check that `postgresql.auto.conf` is absent or empty, and compare PG's effective settings (`postgres -C <guc>` as postgres) with the expected values.
  - Run `systemd-analyze security --threshold` in host mode as well.
  - Add each case as a validate.sh mutation.
- Spec / requirement reference: 07 §4.2, 17 §5.3, 18 §14, 09 §10, R7 SI-B-01, AUD-RM2-STO-02, IMPL-RM2 §4 A1/A11/A14.
- Status: Open

### AUD-RM2-DEP-04 — Control socket gives the `_candor-torctl` group unrestricted tor control: circuit/stream events, SETCONF of path options; group members can egress
- Severity: Medium
- Location: `deploy/intake/torrc:41-46`; `deploy/intake/systemd/tor@candor-intake.service:24`; `deploy/intake/sysusers.d/candor-intake.conf` (`g _candor-torctl`)
- Category: B10.5, B1.1 (CWE-250, CWE-732)
- Description:
  - **Access.** `ControlSocketsGroupWritable 1` + `CookieAuthFileGroupReadable 1` give every member of `_candor-torctl` the full control protocol. tor has no per-command ACL.
  - **What a member can do.** It can `SETEVENTS CIRC STREAM HS_DESC CIRC_MINOR`, which gives the exact time of every rendezvous circuit, that is, every source visit. It can `GETINFO circuit-status`. It can `SETCONF` options that Sandbox does not freeze, for example `HSLayer2Nodes`, `StrictNodes` and `SafeLogging`.
  - **Who the member is.** The intended member is `candor-health`, which is also the only non-tor UID with an nft egress rule (E3 to H-MON).
  - **Spec.** LOG-005 forbids "controller subscription to circuit or stream events". Nothing in the deployment enforces it; it relies on future health-agent code.
- Exploit scenario: a compromise of the health agent (a parser of local data, with network egress to H-MON) gives per-source-visit timing it can exfiltrate. It can also steer tor's path selection to enable guard discovery of the service. Precondition: a compromised health agent. The agent is not shipped yet; membership is added by its package.
- Fix recommendation:
  - Do not give the health agent the raw control socket. Put a small allowlisting control filter in between (onion-grater style: `GETINFO status/bootstrap-phase`, `status/circuit-established`, `network-liveness`; no `SETEVENTS` for CIRC/STREAM/HS_*; no `SETCONF`/`SAVECONF`/`SIGNAL`), running as its own UID.
  - Alternatively, derive health from journald or unit state only.
  - Add a config-check rule that `_candor-torctl` has no members other than the filter's UID.
- Spec / requirement reference: LOG-005, NET-009, ADR-049(1), 16 §7.2; IMPL-RM2 §4 A1.
- Status: Open (must be resolved before the health-agent package joins the group)

### AUD-RM2-DEP-05 — journald records µs timestamps on every stored line from tor/web/sealer/store, so LOG-004 hour truncation and `LogTimeGranularity` are ineffective
- Severity: Medium
- Location: `deploy/intake/journald/journald@candor-intake.conf`; `StandardError=journal` in the four logging units; `deploy/intake/torrc:57`
- Category: B1.2, B10.6 (CWE-532)
- Description:
  - LOG-004 requires Z-INTAKE SYSTEM events to have timestamps truncated to the hour.
  - The deployment routes every warning-level line to journald, which stores `__REALTIME_TIMESTAMP`/`__MONOTONIC_TIMESTAMP` at µs precision, plus `_PID` and `_SOURCE_REALTIME_TIMESTAMP`. journald has no option to coarsen these.
  - tor's `LogTimeGranularity 1 hour` affects only tor's own text prefix. SPEC-NOTES D-02/D-15 present it as achieving coarse timing.
  - Any warning that a source can cause carries the exact time: staging full, sealer busy, a decode error, a PoW-effort change, tor warnings about a client circuit. Even without per-request logging, a source-caused event pins the time of a source action, and it is kept up to 24 h on a running host.
- Exploit scenario: a seizure of a running host (or the health agent / anyone with `systemd-journal` group) reads the namespace journal. A source whose upload hit the staging cap at 14:03:17.123 is tied to that moment.
- Fix recommendation: pick one of these and document it in SPEC-NOTES:
  - (a) `StandardError=null` for web/sealer/store, with `candor-log` writing hour-truncated SYSTEM events to its own volatile tmpfs sink that the health agent reads.
  - (b) Keep journald, but require in C-06/C-07/C-08 that only non-source-triggerable events reach stderr. Add an AT-006-style test that a source-driven fault produces zero journald lines.
  - (c) Accept explicitly as residual, signed off by the spec owner.

  For tor, consider `Log err stderr`.
- Spec / requirement reference: LOG-004, LOG-005, ADR-010/016, 20 §11.3; IMPL-RM2 §4 A1, §6 "Exact arrival time".
- Status: Open

### AUD-RM2-DEP-06 — Host journal lacks `Audit=no`, `MaxFileSec` and a level cap: exact-time PID-1 crash and kernel audit records, possibly kept for more than 24 h
- Severity: Medium
- Location: `deploy/intake/journald/candor-intake-host.conf`; `deploy/tools/config-check.sh:668-680`
- Category: B10.6, B1.2, B1.12 (CWE-532)
- Description:
  - **Missing `Audit=no`.** 20 §11.3 requires `Audit=no` for the Z-INTAKE host journal. Without it, the host journal collects kernel audit records, such as AppArmor `DENIED` lines for the Candor profiles.
  - **Unit-state records.** Messages that PID 1 writes about the Candor units are stored in the **host** journal, not in the namespace, with µs timestamps. An example: `candor-intake-web.service: Main process exited, code=killed, status=6/ABRT`. With `panic = "abort"`, a source-triggered panic is recorded there to the microsecond.
  - **Retention.** `MaxFileSec` is not set (default one month). journald deletes only whole files under `MaxRetentionSec`, and the active file rotates only by size (`RuntimeMaxUse/8` = 8 MiB). On a quiet host, entries can therefore outlive 24 h by a large margin. The namespace file sets `MaxFileSec=1h`; the host file does not.
  - **Checker.** config-check does not verify `Audit`, `MaxFileSec` or `MaxLevelStore`.
- Exploit scenario: a source finds an input that crashes C-06. Each attempt leaves a µs-precise host-journal record of the crash and restart, which may still be present days later on a seized running host.
- Fix recommendation:
  - Add `Audit=no`, `MaxFileSec=1h` and `MaxLevelStore=notice` (or `warning`) to the host drop-in.
  - Optionally set `LogLevelMax=` on PID 1's own messages via `systemd-system.conf`, or accept with a note.
  - Extend `check_journald_file` to require `MaxFileSec ≤ 1h` and `Audit=no`, with mutations.
- Spec / requirement reference: 20 §11.3, LOG-007, 17 §5.5; IMPL-RM2 §4 A1, AT-006.
- Status: Open

### AUD-RM2-DEP-07 — Intake PostgreSQL keeps up to 1 GB of WAL (spec: `max_wal_size = 256MB`); WAL commit records carry exact commit times regardless of `track_commit_timestamp`
- Severity: Medium
- Location: `deploy/intake/postgresql/candor-intake.conf` (no `max_wal_size` / `min_wal_size`); config-check does not check it
- Category: B9.4, B1.2 (CWE-212)
- Description:
  - Every `xl_xact_commit` WAL record stores `xact_time` (ms), whether or not `track_commit_timestamp` is on. The conf comment "no commit times (ADR-010)" overstates what that setting does.
  - 09 §10 bounds this residue by requiring `max_wal_size = 256MB` for the intake DB. The file omits it, and `postgres -C max_wal_size` returns 1024 MB.
  - On a quiet intake host, a larger WAL holds commit times for more submissions for longer (09 §13 "small WAL" mitigation). Recycled segments are renamed, not zeroed, so old records persist until overwritten.
- Exploit scenario: a seizure of a running or recently running intake host (LUKS unlocked). `pg_waldump` lists exact commit times of recent envelope commits, about four times as much history as the spec intends.
- Fix recommendation:
  - Set `max_wal_size = 256MB` and `min_wal_size = 32MB`. Consider a short `checkpoint_timeout`, and `wal_recycle = off` so old segments are removed rather than renamed with their content.
  - Add them to config-check's exact-value list.
  - Correct the comment.
  - Record in SPEC-NOTES that WAL commit times are a residual handled by AT-007/020, not by `track_commit_timestamp`.
- Spec / requirement reference: 09 §10 (line "Intake DB … `max_wal_size = 256MB`"), 09 §13, DB-009, ADR-010, ADR-046(1); IMPL-RM2 §4 A11.
- Status: Open

### AUD-RM2-DEP-08 — tor (the network-facing parser) runs without an AppArmor profile; the PostgreSQL profile is also missing
- Severity: Medium
- Location: `deploy/intake/systemd/tor@candor-intake.service` (no `AppArmorProfile=`), `candor-intake-pg.service`; SPEC-NOTES D-22
- Category: B10.3 (CWE-693)
- Description:
  - IMPL-RM2 §2.1 ("AppArmor enforce profile for tor"), 17 §5.2 and R7 SI-B-04 require enforce-mode profiles for tor and the intake PostgreSQL.
  - D-22 notes that Debian's `system_tor` profile exists. That profile is attached by name (Debian's `tor@.service` uses `AppArmorProfile=system_tor`). This concrete unit does not set it, so tor runs unconfined by AppArmor.
  - config-check enforces AppArmor only for `candor` units.
- Exploit scenario: a tor memory-safety RCE (ADV remote, via Tor cells). The systemd sandbox and tor `Sandbox 1` still apply. There is no MAC layer to stop reads of world-readable host files or connects to Unix sockets reachable by mode, for example `/run/candor/istore`, which is also protected by group.
- Fix recommendation:
  - Ship `candor-tor-intake`, derived from `system_tor`, limited to `/var/lib/tor-instances/candor-intake/**`, `/run/tor-instances/candor-intake/**` and `/run/candor/source-web/http.sock`, with no exec and `network inet stream`. Set `AppArmorProfile=candor-tor-intake` without a `-` prefix.
  - Do the same for PostgreSQL.
  - Extend config-check to require both.
- Spec / requirement reference: IMPL-RM2 §2.1, 17 §5.2, R7 SI-B-04, NET-010; IMPL-RM2 §4 A14.
- Status: Open

### AUD-RM2-DEP-09 — No host kernel baseline shipped or checked: sysctls (dmesg_restrict, printk, ptrace_scope, tcp_timestamps, core_pattern), coredump masking, swap
- Severity: Medium
- Location: `deploy/` (no `sysctl.d`, no `systemd-coredump` mask); `config-check.sh check_host` checks only tor, resolved and swap
- Category: B1.12, B10.6, B10.8 (CWE-1188)
- Description:
  - 20 §11.4 and 17 (sysctl row) make these mandatory on Z-INTAKE: `kernel.printk=3 3 3 3`, `kernel.dmesg_restrict=1`, `kernel.core_pattern=|/bin/false`, `fs.suid_dumpable=0`, systemd-coredump masked, `kernel.yama.ptrace_scope=3`, `kernel.kptr_restrict=2`, `kernel.unprivileged_bpf_disabled=1`, `net.ipv4.tcp_timestamps=0` (reduces clock-skew fingerprinting of the onion host) and `vm.swappiness=0`. IMPL-RM2 §2.2 lists "Host sysctls per SI-B-06" and "Swap disabled" as deliverables of this step.
  - None of these is shipped.
  - `LimitCORE=0` covers the units. It does not cover kernel-initiated dumps through a `core_pattern` pipe helper. With `|`, RLIMIT_CORE=0 is ignored for pipe handlers on older kernels; since 5.x a limit of 0 still skips them, but systemd-coredump captures per its own policy.
- Exploit scenario: a host-level crash or a ptrace by a compromised same-host process (outside systemd's sandbox) captures sealer or tor memory. TCP timestamps from tor's guard connections enable clock-skew fingerprinting of the host (B-AN note, Knowledge-unverified in 17).
- Fix recommendation:
  - Ship `deploy/intake/sysctl.d/90-candor-intake.conf` with the 20 §11.4 / 17 values, a `systemd-coredump.socket` mask (or `coredump.conf` with `Storage=none`, `ProcessSizeMax=0`), and `systemd.zram`/swap masking.
  - Add `--host` checks that read `/proc/sys/...`.
- Spec / requirement reference: 20 §11.4, 17 §5 sysctl row, LOG-007, REQ-H-58, IMPL-RM2 §2.2, ST-110, AT-011.
- Status: Open

### AUD-RM2-DEP-10 — check-placement: `[forbidden]` is parsed but never enforced, parent-path symlinks are not detected, no check that the onion key is on the encrypted volume
- Severity: Low
- Location: `deploy/tools/check-placement.sh:76` (parsed only), `:152-173`
- Category: B6.2, B10 (CWE-59)
- Description:
  - **`[forbidden]` ignored.** `[forbidden] ids` (including `onion.standby_key` and `rcp_onion.client_auth_private`) is never compared with the manifest's entry ids, so a manifest edited to add a forbidden entry still passes.
  - **Symlinks.** `[ -L "$f" ]` tests only the final component. If `/var/lib/tor-instances/candor-intake` is a symlink to a directory on an unencrypted disk, the key entry passes.
  - **Encrypted volume.** A15 requires the onion key "on the encrypted volume", and nothing checks the backing filesystem.
  - **Known limits.** Compressed or base64 (`ED25519-V3:` control-port format) copies are not recognised. This is documented in D-14.
- Exploit scenario: an operator moves tor state to another disk; the check stays green while the onion key sits on unencrypted storage.
- Fix recommendation:
  - Fail if any manifest `id` is in `[forbidden]`.
  - Resolve each path component (`find -P` / `stat` on each prefix) and fail on any symlink.
  - In host mode, verify with `findmnt -T` plus `lsblk -no TYPE` that the key's filesystem is backed by `crypt`.
  - Add an `ED25519-V3:[A-Za-z0-9+/]{86}==` pattern.
- Spec / requirement reference: ADR-028, ADR-032, NET-043, 18 §15; IMPL-RM2 §4 A15.
- Status: Open

### AUD-RM2-DEP-11 — tor probably cannot open the onion target socket: the socket group is tor's passwd primary group, which systemd does not grant when `Group=` differs
- Severity: Low (functional; fails closed)
- Location: `deploy/intake/systemd/tor@candor-intake.service:24` (`Group=_candor-torctl`); `candor-intake-web.socket:17`; `tmpfiles.d` (`/run/candor/source-web 0750 candor-web:_tor-candor-intake`)
- Category: B10.1
- Description:
  - systemd calls `initgroups(User, <Group= gid>)`. The supplementary set is therefore `_candor-torctl` plus groups that list `_tor-candor-intake` as a member, and none do.
  - The user's passwd primary group `_tor-candor-intake` is not included. tor then cannot traverse `/run/candor/source-web` (0750) or connect to `http.sock` (0660), and every rendezvous stream fails.
  - The README's verification used `setpriv --clear-groups`, which also omits that group, and `DisableNetwork 1`, so this path was never exercised. A shell `setpriv --init-groups` does include it, because setpriv passes the passwd gid, which is why it can look fine in ad-hoc tests.
- Exploit scenario: none directly. The risk is an operator "fixing" it by widening the socket or directory mode.
- Fix recommendation: add `SupplementaryGroups=_tor-candor-intake` to the tor unit, or use a dedicated `_candor-onion-web` group for the socket and directory. Confirm in the Debian 13 integration run with a real rendezvous.
- Spec / requirement reference: 16 §7.1, 07 §4.1, NET-002.
- Status: Open (confirm in integration)

### AUD-RM2-DEP-12 — Minor checker/test issues: AppArmor validation passes on a silent parser failure; broad pkill; per-unit `PrivateTmp` gives a disk-backed `/var/tmp`
- Severity: Low
- Location: `deploy/tests/validate.sh:196-198`, `:302`; all units `PrivateTmp=yes`
- Category: B10.7, B1.11
- Description:
  1. **AppArmor check.** `if apparmor_parser … || ! grep -vq 'Cache…' aa.err` takes the success branch when the parser fails with empty stderr (or with only the cache message), and then reports PASS.
  2. **pkill.** `pkill -INT -u pgtest -f "$PGBIN/postgres"` stops every pgtest-owned postmaster on the CI host, not only the test one. Use the PID or `pg_ctl -D`.
  3. **`/var/tmp`.** `PrivateTmp=yes` gives a private `/var/tmp` backed by the host's `/var/tmp`, which is on disk unless the host image applies 17's tmpfs rule. It is re-exposed under `TemporaryFileSystem=/var:ro` because the deeper mount wins. AppArmor (`abstractions/base`) blocks writes for web, sealer and store, but not for tor or PostgreSQL. On systemd ≥256 prefer `PrivateTmp=disconnected`, or add `InaccessiblePaths=/var/tmp`.
- Exploit scenario: test false-negative; residue of a temp write on disk if code ever writes to `/var/tmp`.
- Fix recommendation: as above. Check `$?` of `apparmor_parser` directly.
- Spec / requirement reference: 17 §5 filesystems row; BUILD-BRIEF "no swap/disk for plaintext".
- Status: Open

### AUD-RM2-DEP-13 — `CompiledProofOfWorkHash 0` trade-off (interpreted HashX) not yet load-tested
- Severity: Info
- Location: `deploy/intake/torrc:21`; SPEC-NOTES D-03
- Description:
  - The choice is correct: MDWE forbids the JIT, and `auto` would only fail over at run time.
  - tor documents the compiled implementation as about 20× faster per HashX evaluation. Service-side verification is bounded by the intro-point DoS limits (25/s, burst 200, per intro point × 5), so the expected CPU cost is small. That has not been measured.
- Fix recommendation: include the ST-100 PoW flood with the interpreted verifier in the integration run; record CPU per INTRODUCE2.
- Status: Open (tracking)

### AUD-RM2-DEP-14 — Out-of-slice items relied on by this config but not shipped: tor update instance torrc, Roughtime/chrony config, apt `tor+https`, disabling Debian's `tor@default`
- Severity: Info
- Location: `deploy/` (absent); nftables E2/E4 rules reference them
- Description:
  - E2 (`_tor-candor-update`) and E4 (`_chrony`) are allowed in nft, but their configs are not part of this slice.
  - Debian's `tor` package enables `tor@default` (debian-tor, SocksPort 9050). nft drops its egress, but it is a second, unchecked tor on the host and should be masked.
  - None of this is a leak today, but SI-D-03 ("only tor ORPort traffic during an apt upgrade") cannot be demonstrated until these exist.
- Fix recommendation: track for the next deploy slice. Add a `--host` check that `tor@default` and `tor.service` are masked.
- Status: Open (tracking)

---

## Checklist coverage notes (B10, B9.5, B1)

- **B9.5 PostgreSQL logging.** All R9 settings are present and enforced, and zero output was verified. Remaining issues: the bypass in DEP-03 (1) and the WAL size in DEP-07.
- **pg_hba.** Peer-only, superuser rejected, regex database restriction. Verified live.
- **B10.2.**
  - `RestrictAddressFamilies=AF_UNIX`, `PrivateNetwork=yes`, `IPAddressDeny=any`, `LimitCORE=0`, `UMask=0077` on web, sealer, store and PostgreSQL.
  - Secrets only via `LoadCredentialEncrypted=`. No `Environment=`.
  - The relay TCP listener is created by PID 1 in the socket unit's cgroup (BPF `IPAddressDeny=any` until the site drop-in), so the store never needs `AF_INET`. The design is sound.
- **B10.4 nftables.** Policy drop on all three hooks, no LOG/NFLOG, tor UIDs to public addresses over TCP only, no udp/53, metadata blocked. Sound as shipped; see DEP-02.
- **B10.5 torrc.** Sound as shipped (SafeLogging 1, warn to stderr, Unix socket target, no TCP ControlPort, DisableDebuggerAttachment, Sandbox, PoW and intro-point DoS defences on, single-hop and non-anonymous modes off). See DEP-01, DEP-04 and DEP-13.
- **AppArmor profiles.**
  - No `/** rw`, no `ux`/`Ux`/`px` transitions (no `x` permission at all), `deny ptrace`/`capability`/`mount`.
  - The sealer has `deny network inet`; the store has inet stream only, for the inherited relay socket.
  - Unix rules have no `peer=` restriction. This is acceptable because each service has its own network namespace, which isolates abstract sockets.
- **B10.7.** shellcheck is clean. There is no `eval`, no unquoted expansion and no input-derived regex, and output is sanitised. The checkers are robust as programs; their weakness is coverage (DEP-01/02/03).
- **Two-host HA (ADR-032).** Not applicable to CE-SINGLE/CE-HARDENED. The manifest and check enforce a single source onion key (NET-043).

Gate: FAIL 2026-10-01 9f368a303d (open High: DEP-01, DEP-02, DEP-03)
