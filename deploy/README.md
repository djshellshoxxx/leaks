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
| `intake/torrc` | `/etc/tor/instances/candor-intake/torrc` (root 0644) | Intake onion service, 16 §7.1. PoW and intro-point DoS defences are on, vanguards-lite only (ADR-049). Logging is `warn` to stderr with SafeLogging. Sandbox is on. No SocksPort and no TCP listener. |
| `intake/nftables.conf` | `/etc/nftables.conf` | Default-deny ruleset. Only the two tor UIDs may leave via ext0, and only to public addresses over TCP. Other flows: E3 health push and E4 NTS to H-MON, inbound I1 relay 7443 and optional I2 ssh. There are no LOG targets. The installer fills only the three address sets. |
| `intake/systemd/tor@candor-intake.service` | `/etc/systemd/system/` | tor runs as `_tor-candor-intake` (never root) with `--defaults-torrc /dev/null`. It is fully sandboxed. AF_INET is allowed for tor only, and non-public IP ranges are denied in-kernel. |
| `intake/systemd/candor-intake-web.{socket,service}` | `/etc/systemd/system/` | C-06. PID 1 creates `/run/candor/source-web/http.sock` (0660 `candor-web:_tor-candor-intake`). The service has `PrivateNetwork=yes` and AF_UNIX only. |
| `intake/systemd/candor-sealer.{socket,service}` | `/etc/systemd/system/` | C-07. Socket `seal.sock` is SEQPACKET (0660 `candor-sealer:candor-web`). The sealer has no network and no writable path. It locks memory through `LimitMEMLOCK=2G` and has no capabilities. Its secrets arrive as TPM-sealed credentials. |
| `intake/systemd/candor-intake-store{,-relay}.socket`, `candor-intake-store.service` | `/etc/systemd/system/` | C-08. It receives the IPC socket and the relay TCP socket (relay0:7443) from PID 1. The process itself is AF_UNIX-only in an empty network namespace, so it can accept the core's pull but can never initiate a connection (ADR-009). |
| `intake/systemd/run-candor-staging.mount` | `/etc/systemd/system/` | Tier W staging tmpfs `/run/candor/staging`, mode 0700 `candor-istore`, `noswap`. It is RAM-only (ADR-034). |
| `intake/systemd/candor-intake-pg.service` | `/etc/systemd/system/` | Dedicated PostgreSQL 16 cluster for the intake store. Unix socket only, `PrivateNetwork=yes`. |
| `intake/systemd/nftables.service.d/candor-intake.conf` | `/etc/systemd/system/nftables.service.d/` | Loads the ruleset only after the service users exist. |
| `intake/postgresql/{candor-intake.conf,pg_hba.conf,pg_ident.conf}` | `/etc/candor/intake/postgresql/` (root:postgres 0640) | `wal_level=minimal`, no archiving or replication, `track_commit_timestamp=off`. Logging is minimised: no connections, no statements, no checkpoints or autovacuum events, `log_line_prefix='%e '`. Access is peer-only for `candor-istore`. |
| `intake/apparmor/{candor-web,candor-sealer,candor-intake-store}` | `/etc/apparmor.d/` | Enforce-mode profiles. Units attach them with `AppArmorProfile=` and no `-` prefix, so a unit fails to start if its profile is missing. |
| `intake/journald/journald@candor-intake.conf` | `/etc/systemd/` | Journal namespace for all five intake units. Volatile storage, at most 24 h retention, 16 MiB, nothing below `warning` stored, no forwarding. |
| `intake/journald/candor-intake-host.conf` | `/etc/systemd/journald.conf.d/50-candor-intake.conf` | Host journal: volatile, at most 24 h, no forwarding (17 §5.5). |
| `intake/sysusers.d/candor-intake.conf` | `/usr/lib/sysusers.d/` | One UID per service, plus every UID that nftables names. |
| `intake/tmpfiles.d/candor-intake.conf` | `/usr/lib/tmpfiles.d/` | Socket and state directories. Each is 0750 with group set to the single permitted client (07 §4.1). |
| `intake/resolv.conf` | `/etc/resolv.conf` | No DNS (`nameserver 127.0.0.1` with nothing listening). |
| `intake/profiles/{ce-single,ce-hardened}/` | `/etc/systemd/system/<unit>.d/` | Profile drop-ins. Staging is 4 GiB on CE-SINGLE and 8 GiB on CE-HARDENED. The store's `MemoryMax` is staging plus 1 GiB, because tmpfs pages are charged to its cgroup. |
| `intake/secret-placement.toml` | `/usr/share/candor/manifests/intake.toml` | ADR-028 Secret Placement Manifest for role `intake`. |
| `tools/check-placement.sh` | `/usr/lib/candor/tools/` | Verifies the manifest on a host: owner, group, mode, parent mode, symlinks and hard links per entry. It also scans for unlisted secret material and checks names in the ciphertext-only directories. |
| `tools/config-check.sh` | `/usr/lib/candor/tools/` | The subset of `candorctl check` (18 §14) that covers these files. It checks the unit files together with their drop-ins. |
| `tests/validate.sh` | — (CI) | Runs all the checks listed under "Validation" below. |

## Users, sockets and flows

```
 Tor network ──ext0──► tor (_tor-candor-intake, AF_INET; nft: TCP to public IPs only)
                          │ unix:/run/candor/source-web/http.sock   (0660 candor-web:_tor-candor-intake)
                          ▼
                    candor-web (C-06, no netns, AF_UNIX)
                       │ seal.sock (SEQPACKET, 0660 candor-sealer:candor-web)
                       ▼                         istore.sock (SEQPACKET, 0660 candor-istore:candor-istore-clients)
                    candor-sealer (C-07) ───────────────►  candor-intake-store (C-08, no netns)
                       (chaff only)                          │ /run/candor/intake-pg/.s.PGSQL.5432 (peer)
                                                             ▼
                                                     PostgreSQL (postgres, no netns)
 C-09 (core) ──relay0:7443──► socket bound by PID 1 ──► candor-intake-store (accept only)
```

## Install order on a host (reference; the installer automates this)

1. Install the packages from the release's Platform Manifest (17 §4.5). tor must be ≥ 0.4.8, and
   `tor --list-modules` must show `pow: yes`.
2. Install `sysusers.d` and `tmpfiles.d`, then run `systemd-sysusers` and `systemd-tmpfiles --create`.
3. Install `nftables.conf` with the site's address sets filled in, then enable `nftables.service`.
4. Run `initdb` for the intake cluster as `postgres`:
   `initdb -D /var/lib/postgresql/16/candor-intake --data-checksums -A reject -U postgres`
   (`data_checksums` per 09 §10). Install the PostgreSQL files. This must be the only PostgreSQL
   cluster on the host: see SPEC-NOTES D-16.
5. Seal the credentials with `systemd-creds encrypt --with-key=tpm2 --name=<name> <plain> /etc/credstore.encrypted/candor-intake.<name>.cred`,
   then shred the plaintext. Names and paths are in `secret-placement.toml`.
6. Install the units, profile drop-ins, AppArmor profiles (`apparmor_parser -r`) and journald
   files. Write the relay socket drop-in with the core address
   (`IPAddressAllow=<core>/32`; see the comment in the unit).
7. Run `config-check.sh --host` (must exit 0) and `check-placement.sh --mode full` (must exit 0).
   Then enable the sockets, services and `tor@candor-intake`.

## Requirements on the Candor binaries (C-06/C-07/C-08 implementers)

- **Socket activation:** take listeners from `sd_listen_fds` by `FileDescriptorName`:
  `http` (web), `seal` (sealer), `istore` and `relay` (store). Never `bind()` an IP socket;
  `SocketBindDeny=any` and `RestrictAddressFamilies=AF_UNIX` enforce this.
- **Secrets:** read only from `$CREDENTIALS_DIRECTORY/<name>`: `sealer_signing_key`,
  `argon2_salt`, `routing_key`, `batch_signing_key` and `relay_tls_key`. Never read them from
  the environment.
- **Logging:** write to stderr only, as typed `candor-log` codes. Anything on stdout is
  discarded. Lines without a `<N>` priority prefix are stored at level `warning`.
- **Peers:** check `SO_PEERCRED` on every accepted IPC connection (07 §5.2/§5.3).
- **Self-sandboxing:** the systemd filter permits `seccomp` and `landlock_*` so that each binary
  can apply its own seccomp filter (07 §4.3) and Landlock ruleset (R7 SI-B-02/03).

## Validation

Run `deploy/tests/validate.sh`. Set `CANDOR_TEST_PG=1` to include the PostgreSQL run. The script
runs as root in CI with `shellcheck`, `tor`, `nft`, `apparmor_parser` and PostgreSQL 16 present,
and with the users from `sysusers.d` created.

| Check | Result (2026-10-01, this container: systemd 255, tor 0.4.9.11, nft, AppArmor 4 parser, PG 16.13) |
|---|---|
| shellcheck (tools, tests) | clean |
| `config-check.sh` on the shipped tree (base, `--profile ce-single`, `--profile ce-hardened`) | 365 checks OK, exit 0 |
| `config-check.sh` on 79 deliberately broken copies | every copy rejected with exit 30 |
| `systemd-analyze verify --man=no` (10 units) | clean apart from the expected messages below |
| `systemd-analyze security --offline --threshold` | web 0.4, sealer 0.4, store 0.4, PostgreSQL 0.5 (budget 0.5); tor 1.4 (budget 1.5, 17 §5.3) |
| `nft -c -f nftables.conf` | OK |
| `apparmor_parser -Q -K` (3 profiles) | OK |
| `tor --verify-config` (as `_tor-candor-intake`) | valid. A `DisableNetwork 1` start also confirmed the socket and cookie group `_candor-torctl` and the key modes. |
| `check-placement.sh` | 2 clean cases pass; 19 negative cases fail as expected (exit 30 or 2) |
| PostgreSQL 16 with `candor-intake.conf` | effective settings match. Peer map, database restriction and socket permissions refuse other users and roles. The log has no connection records and no SQL. |

**Expected `systemd-analyze verify` messages**, filtered by `validate.sh`:
`Command /usr/lib/candor/{source-web/candor-web,sealer/candor-sealer,intake-store/candor-intake-store} is not executable: No such file or directory`.
These binaries are not built yet; the units name their future install paths. On systemd < 257,
any later `PrivatePIDs=` addition would appear as `Unknown key name`; that message is filtered
too.

**Not verifiable here**, because no systemd runs as PID 1 in the container: the actual start of
the units under their sandbox, `LogNamespace=`, `LoadCredentialEncrypted=` with a TPM, and the
interaction of `PrivateNetwork=` with socket activation. These need an integration run on Debian 13
(see SPEC-NOTES "Open items").
