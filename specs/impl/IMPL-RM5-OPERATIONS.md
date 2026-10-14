# IMPL-RM5 — Operations: installers, config checker, self-test, backup/restore, signed auto-update

Status: Draft v1.0 (2026-10-01) · Edition applicability: both (CE first; EE profiles reuse) · Owner: T6 Platform/Infra, with T7 (update client) · Roadmap milestone: RM-5 (`38-IMPLEMENTATION-ROADMAP.md` §4)

Global rules (Rust coding, unsafe policy, secrets, logging, dependency policy, PR Definition of Done, audit-gate mechanics) are in `IMPL-00-SECURE-IMPLEMENTATION-STANDARD.md` and are **not repeated here**. This document adds only what is specific to RM-5. Rule IDs: `SI-x-nn` = `research/R7-secure-implementation.md`; `SL-R-nnn` = `research/R8-secure-dev-lifecycle.md`; `INC-nn` = R3/00-RESEARCH incidents; `INC-SL-nn` = R8 §3.

## 1. Purpose and scope

| Item | Content |
|---|---|
| Goal | An operator can install, check, monitor, back up, restore and update a Candor instance with protections on by default and with failures that stop service instead of weakening it |
| Components | C-19 (`candorctl`, `candor-setup`), C-25 (self-test agent + H-MON collector), C-27 (backup agent + store), C-32/C-33 client side (`candor-update`/`candor-updater`), C-05..C-14 and C-21..C-24 as packaged units, C-39 host baseline |
| Proposed crates/packages | `candor-update` (TUF client, T0), `candor-platform` (Platform Manifest + floor verifier, T0), `candor-check` (rule engine, T1), `candor-health` (agent, T1), `candor-backup` (T0: handles wraps and vault sets), `candorctl`, `candor-setup` (TUI), `candor-bootstrap` (.deb holding `root.json`) |
| Spec sections implemented | 18 §5–§15 (packaging, installers, go-live gates, upgrade, rollback, backup commands, config checker, Secret Placement Manifest); 19 §3–§11 (sets, keys, format, padding, immutability, restore tests, retention, ransomware, RPO/RTO, DR); 32 §5 (self-test), §7 (CFG classes), §8 (support bundle); 33 §4.1, §8, §14 (security floor, rollback/freeze, update client); 17 host baselines; 20 LOG-018; 31 playbook hooks |
| Out of scope | Production signing keys and public TUF repository (RM-7, `IMPL-RM7-GA-RELEASE.md`); EE-HA rolling upgrade and DR automation (RM-10); Fleet Manager (RM-9) |

## 2. Preconditions

| # | Precondition | Evidence |
|---|---|---|
| P1 | RM-3 and RM-4 exit reports signed (RM-005) with 0 open Critical/High | Milestone reports in transparency log |
| P2 | IMPL-00 global rules enforced in CI (lints, cargo-vet/deny, SL-R-009 cooldown, Scorecard subset) | CI required checks |
| P3 | RM-0 TUF **test-key** repository and Builder A/B reproducible pipeline exist | RM-0 report; SG-13 on skeleton |
| P4 | `candor-core` startup KATs callable (`crypto.selftest`), `candor-safefs` and `candor-log` stable APIs | crate READMEs |
| P5 | Pinned Debian snapshot mirror and Tor Project repo pin available for Platform Manifest generation (28 §5.4) | mirror config in `supply-chain/` |
| P6 | CFG table (32 §7) frozen for 1.0 with every option classed SAFE/ADVANCED/DANGEROUS/FIXED (ADR-046(6)) | 32 §7; ST-167 lint |

## 3. Build sequence

Each step ends with the independent audit gate (§7). Step IDs are used for audit files `process/audits/AUDIT-RM5-Sn.md`.

### RM5-S1 Host baseline packaging (role .debs, units, AppArmor, sysctl, nftables, torrc)

| Aspect | Specification |
|---|---|
| Build | One .deb per host role (intake, core, monitor, backup) carrying: systemd units with the SI-B-01 drop-in; enforce-mode AppArmor profiles for every daemon, tor and PostgreSQL (SI-B-04); sysctl file (SI-B-06: `ptrace_scope=3`, `suid_dumpable=0`, `core_pattern=\|/bin/false`, `kptr_restrict=2`, `dmesg_restrict=1`, `unprivileged_bpf_disabled=1`, `kexec_load_disabled=1`); coredump disabled; nftables with egress only for the tor UID on intake (SI-D-03); managed torrc from 16 §7.1 (SI-D-01); PostgreSQL `pg_hba` peer-only (SI-E-01) and logging settings (SI-E-04) |
| Interfaces | Files under `/usr/lib/candor`, `/etc/candor` (root-owned, 0644 config / 0600 secrets), unit names `candor-<role>.service` |
| Rules | Maintainer scripts SHALL NOT fetch from the network or copy directories into secret-bearing paths (18 §5–§6); `RUST_BACKTRACE` unset; secrets only via `LoadCredentialEncrypted=` (SI-B-01); swap off or random-key encrypted swap (SI-A-05.3); no NTP to public pools from intake (SI-D-03); vanguards add-on SHALL NOT be packaged (ADR-049(1)) |
| Pitfalls | INC-106 (installer copied whole dir of onion client-auth keys to Monitor); INC-34 (mod_status/version leaks on onion hosts); INC-33 (real-IP leak via clearnet path) |
| Verify | `systemd-analyze security --offline=yes --threshold=<per-role> ` (intake ≤ 1.5, others ≤ 2.0 displayed scale, SI-B-01); `systemd-analyze verify`; `lintian`; `aa-logprof` clean run under functional suite; `tor --verify-config -f`; CI lint `installer-no-dir-copy` |

### RM5-S2 Secret Placement Manifest and `candorctl secrets verify` (ADR-028)

| Aspect | Specification |
|---|---|
| Build | Per-role YAML manifest (18 §15.1) shipped in the signed role package; scanner that walks every host for secret patterns (PEM, OpenSSH, tor `hs_ed25519_secret_key`, age/HPKE keys, LUKS headers, credstore files) and compares the set with the manifest for the active feature flags |
| Interfaces | `candorctl secrets verify [--host H] [--json]`; self-test check `secret.placement` (32 §5.2); exit codes per 18 §14 |
| Rules | Manifest parsed strictly (unknown keys rejected, size cap); secrets `provenance: generated_on_host` except BS-SECRETS restores (18 §6); file writes only via `candor-safefs` (SL-R-001: validate before write, no untrusted names); any forbidden item on intake → intake stop (DEP-024) |
| Pitfalls | INC-106 (GHSA-rqwh); INC-59 (cloud storage exposure of keys) |
| Verify | ST-121 on every profile × feature-flag combination (SG-16); negative test plants an onion key copy on monitor and expects FAIL + intake stop |

### RM5-S3 TUF update client (`candor-update`, Z-INTAKE and Z-CORE variants)

| Aspect | Specification |
|---|---|
| Build | TUF client behind an internal trait (33 §14; OI-1 hybrid key type `candor-ed25519-mldsa65`, a key counts only if both signatures verify); log-proof verifier (Sigsum inclusion proof + cosigned tree head, `w = 2` of ≥ 3 witnesses, 33 §7); local verified APT repo at `/var/lib/candor/repo` signed by a host-local key; client-side random rollout delay 0–72 h; `security_hold` and `revoked` handling (33 §13.2) |
| Interfaces | `candor-update {refresh,plan,fetch,apply}`; Z-INTAKE path only via the dedicated client-only tor instance (UID `_tor-candor-update`) to the project onion mirror; Z-CORE path via egress-restricted HTTPS to one configured mirror (ADR-046(3)); offline bundle import (33 §8 air-gap row) |
| Rules | Requests carry no instance ID, tenant, onion address, licence ID, cookie or auth header; fixed `User-Agent: candor-updater/<major>`; fetch all targets metadata for all products (33 §14); randomized check interval 2–6 h; no push channel; artifacts verified before unpacking; HTTP client: redirects off, response length caps from TUF lengths, total timeouts (SI-C-05 pattern; INC-104); every metadata parser bounded and fuzzed (SI-A-02, SI-A-03); trust decisions carry `Verified<Targets>` typestate, never a re-lookup by path or ID (SL-R-003); freeze: alert when metadata cannot refresh for > 36 h, fail closed on expired timestamp > 7 d with operator alert (R8 §4.5) |
| Pitfalls | INC-49 (NotPetya: update server compromise), INC-48 (CCleaner: signed backdoor), INC-52 (Linux Mint: hash on same server), INC-14 (Anom: targeted delivery), INC-104 (redirect follows), INC-SL-07 (unverified fallback path: run KATs of the signature verifier on every shipped arch, SL-R-004) |
| Verify | ST-130 rejection suite (unsigned, under-threshold, expired, rollback, freeze, mix-and-match, unlogged, endless-data); ST-047 `fuzz_tuf_metadata`; TUF conformance vectors where available; root rotation chain N→N+1→N+2; packet capture shows only tor ORPort traffic from intake during refresh (SI-D-03 verify) |

### RM5-S4 Platform Manifest verification and security floors (ADR-040)

| Aspect | Specification |
|---|---|
| Build | `candor-platform`: compares dpkg database (name, version, SHA-256 of .deb) with the TUF `platform` target; floor evaluator reading `{min_secure_version, effective_day}`; `ExecStartPre=/usr/lib/candor/bin/candor-floor-check <product>` in every trust-path unit |
| Interfaces | `candorctl platform verify [--all-hosts]`, `candorctl verify-installed`; self-test `integrity.platform_manifest`, `update.security_floor`, `integrity.running_manifest` |
| Rules | Unlisted package, missing package, hash mismatch or any upstream APT source configured → FAIL with code {EXTRA, MISSING, HASH, SOURCE}; below floor after `effective_day` → unit refuses start; intake below floor stops accepting and shows the outage page (33 §4.1); no local or Fleet override (ADR-045); time for `effective_day` from the independent time floor (ADR-036(6)), not wall clock alone (THR-043) |
| Pitfalls | INC-37 (xz: release artefact differed from reviewed source; verify hashes, not names); INC-53/INC-46 class (unexpected third-party component appears) |
| Verify | ST-153 (SG-27); ST-106 clock-skew cases for `effective_day`; fault injection: install an extra package → FAIL and intake stop (F13) |

### RM5-S5 Installers (`candor-bootstrap`, `candor-setup`, `candorctl site plan/apply/go-live`, appliance first boot)

| Aspect | Specification |
|---|---|
| Build | Bootstrap .deb embeds `root.json`; `candor-setup` TUI implements 18 §8 steps 1–11; `candorctl site` implements declarative `candor-site.toml` (18 §9.1); go-live gate evaluator (18 §8.1 items 1–11); appliance first-boot regenerator (machine-id, SSH host keys, LUKS re-encrypt, onion keys, TLS keys) |
| Interfaces | `candorctl site {record-checklist,plan,apply,go-live}`; IRK share printer (paper QR + words, legibility re-entry) |
| Rules | Secrets generated on the owning host, never on the admin workstation except BS-SECRETS encrypted to the IRK (18 §6); refuse: no UEFI, no IOMMU, cloud IMDS detected, non-empty disks, other listeners; refuse single backup disk; DANGEROUS settings not reachable from the wizard; go-live refuses until checker/secrets/selftest/platform all OK and ≥ 2 distinct natural persons (AAGUID distinctness, 15); installer output sheets contain onion address and publication checklist only, no secrets; installer logs exclude secrets and source data (IMPL-00 logging rules) |
| Pitfalls | INC-106 (directory copy); SecureDrop Focal→Noble migration problems (B-SD-02/03: no in-place major upgrades, 18 §11.4); VM image with baked host keys (18 §5) |
| Verify | ST-124 idempotence/drift; fresh-install CI job on CE-SINGLE and CE-HARDENED VMs → `candorctl check` exit 0 without manual hardening (RM-5 exit); DEMO: non-specialist install ≤ 60 min (feeds AT-073); test image contains no secrets (ST-121 on image) |

### RM5-S6 Configuration checker (`candorctl check`, `candor-check`)

| Aspect | Specification |
|---|---|
| Build | Rule engine reading **effective** state (running torrc, nft ruleset, sysctl values, unit properties via D-Bus, AppArmor status, FDE bindings, package list, Candor config) per 18 §14; rule records `{id, cfg_class, expected, check, remediation}`; attested rules (CFG-008) checking signed attestations |
| Interfaces | `candorctl check [--all-hosts] [--json]`; exit codes 0/10/20/30; acknowledgement records signed with admin FIDO2, logged as SECURITY events |
| Rules | Rule set ships in the signed package; no local overrides, only acknowledgements; dry run before every config apply; exit ≥ 20 blocks upgrades and intake start (fail closed); config loader rejects partial loads (ST-050); every new CFG option needs a rule (SG-17); "Tor version below floor" and `pow: yes` missing fail the checker (R8 §1.3; SI-D-01); headers/CSP checked on the served response, not on a template (SL-R-007) |
| Pitfalls | INC-118 / INC-SL-14 (headers absent in production, tests ran against dev), INC-114 (network config changed without role check), INC-SL-15 |
| Verify | ST-120, ST-050 fuzz, ST-078 (DANGEROUS needs 2 persons), ST-159 (backup-exclusion attestation); golden-file tests per profile |

### RM5-S7 Self-test agent and H-MON collector (C-25)

| Aspect | Specification |
|---|---|
| Build | `candor-health` agent per host (user `candor-health`), every 5 min ± 60 s, checks of 32 §5.2; collector on H-MON accepting only the fixed schema; external onion probe of `/.well-known/candor/health` via H-MON's own tor client |
| Interfaces | mTLS push (flow F4); result record `{check_id, host_role, status, code, bucket, sched_ts, agent_version}` (32 §5.3) |
| Rules | 32 §5.1 privacy rules 1–6 (no counts, no per-request data, bands only, no onion/host/IP, minute-rounded schedule time, 30-day retention); collector rejects unknown fields and free text; agent runs read-only checks except declared fail-closed actions (stop C-06); add host-introspection checks from R7: `/proc/<pid>/status` `NoNewPrivs: 1`, `Seccomp: 2`, `CapEff: 0` (SI-B-01), Landlock ABI ≥ profile minimum (SI-B-03), sysctls (SI-B-06), `aa-status` (SI-B-04), `tor --list-modules` `pow: yes` (SI-D-01), `rolbypassrls`/`rolsuper` false for app roles (SI-E-02) |
| Pitfalls | INC-60 (secrets in internal logs), INC-58 (key exposed via crash dump), INC-74 (aggregate activity data revealing patterns: no counts) |
| Verify | AT-001 canary run over agent/collector sinks; schema fuzz of the collector; fault injection per check (egress opened, swap on, extra listener, torrc drift) → expected fail action |

### RM5-S8 Backup agent, backup wizard, restore and drills (C-27)

| Aspect | Specification |
|---|---|
| Build | `candor-backup` producing `candor-backup/1` sets (19 §5.1) per zone (BS-CORE, BS-CORE-WAL, BS-INTAKE, BS-ERASURE, BS-ERASELOG, BS-SECRETS, BS-CONFIG, BS-ANCHOR); padding to size classes (19 §5.2); signed manifest hash chain anchored daily; Object Lock (compliance mode) client; restore engine; `candorctl dr drill` sandbox |
| Interfaces | 18 §13 commands (`backup status/create/verify/offline-rotate`, `restore secrets/data`, `ekv verify/rewrap`); restore test schedule RT-0..RT-7 (19 §7) |
| Rules | No compression of secret-bearing data before encryption unless padded to a fixed size class (SL-R-005); backup ciphertext size independent of key bytes (INC-SL-05 test); key separation per set (19 §4; SL-R-011 labels); agent credentials put-only ≤ 24 h, cannot delete or shorten retention (19 §9); Erasure Key Vault excluded from BS-CORE, BS-ERASURE ≤ 14 days (ADR-033(3)); restore applies newest verifiable erasure log and intake deletion list **before** any service serves (ADR-044(4), ADR-047(9)); restore refuses sets with bad signature/chain/anchor; BS-INTAKE holds no envelopes; restored onion key tested only in a netns without Internet (RT-3) |
| Pitfalls | INC-55 (LastPass: backups stolen with keys reachable), INC-113 (cross-tenant escrow wipe: every UPDATE scoped), INC-63/INC-SL-05 (compression side channel), INC-42 class ransomware dwell (19 §9) |
| Verify | ST-108 (SG-20), ST-158, ST-159, ST-174, ST-175; RT-1 drill on CE-SINGLE and CE-HARDENED measuring RPO/RTO against 19 §10 (RM-5 exit); size-invariance test (vary key, fixed payload → equal sizes) |

### RM5-S9 Upgrade and rollback orchestration

| Aspect | Specification |
|---|---|
| Build | `candorctl upgrade plan/apply`, `rollback plan/apply` (18 §11–§12); migration runner as `schema_owner` with expand/backfill/contract (SI-E-06); post-upgrade health gate with automatic rollback within 15 min |
| Rules | Pre-upgrade backup mandatory and verified; rollback only to N-1 and never to a `revoked` target or below floor; DB snapshot restored only if migration not expand-compatible; EE/GOV rollback needs `--co-sign`; migrations never at app start; `urgent=true` window counted from end of cooling period; intake applies emergency releases ≥ 6 h after log publication unless dual override (33 §10 E6) |
| Pitfalls | B-SD-02/03 major-version migration failures; INC-49 (update as attack vector: never bypass TUF for "quick fixes") |
| Verify | ST-107 from each supported prior version (N-2 minors) incl. power loss mid-migration (ST-103), SG-19; ST-130 rollback cases |

### RM5-S10 Support bundle and incident playbook tooling

| Aspect | Specification |
|---|---|
| Build | `candorctl support-bundle create --preview` and Desk Diagnostics per 32 §8; playbook runner exposing the evidence-collection and containment steps of 31 (PB-xx) as scripted, dry-runnable commands (subcommand names owned by 31/18) |
| Rules | Allow-list content only; per-bundle random HMAC key kept locally (deleted after 30 d); timestamps truncated to the hour; canary/regex scan aborts creation on any hit; FIDO2-confirmed preview; encrypted (age/HPKE) to the confirmed support key; never auto-uploaded; INDEPENDENT-channel Desk bundles only to vendor or OVERSIGHT key; playbook capture steps never collect source-linked data (no tor state, no DB dumps, no memory images) and require approval per ADR-035(4) |
| Pitfalls | INC-56 (Okta HAR files with session tokens), INC-60 |
| Verify | AT canary run over generated bundles (planted canaries must abort); fuzz of the scrubber; ST-068 (admin bundle contains no case content) |

## 4. Auditor threat checklist (component-specific)

| # | Check | Threats |
|---|---|---|
| 1 | Can any update path (intake, core, Desk proxy, offline bundle) accept an artifact without threshold TUF signatures **and** a witness-cosigned log proof? | THR-025, THR-024 |
| 2 | Do update requests or timings differ by instance, tenant or installed product set? | THR-025, THR-026 |
| 3 | Is every TUF/manifest/backup/config parser bounded (length caps before allocation, no recursion, no panics)? | THR-012, THR-032 |
| 4 | Can a local admin, Fleet policy or clock manipulation run a trust-path unit below the security floor? | THR-025, THR-043 |
| 5 | Does any installer or maintainer script copy directories, fetch from network, or log secrets? | THR-013, THR-016 |
| 6 | Does the checker read effective state (running services) rather than intended config files? | THR-035 |
| 7 | Can a DANGEROUS option be enabled by one person or acknowledged without FIDO2 signature? | THR-018, THR-035 |
| 8 | Do self-test results, collector storage or alerts contain counts, onion addresses, IPs or event times? | THR-016, THR-039 |
| 9 | Does any restore path serve data before applying the erasure log and intake deletion list? | THR-017 |
| 10 | Are backup sizes or timing dependent on secret values or submission activity (compression, unpadded sets)? | THR-011, THR-015 |
| 11 | Can backup credentials delete, overwrite or shorten retention? | THR-042 |
| 12 | Does a support bundle or playbook capture contain tokens, tor state, case data or staff names? | THR-027, THR-016 |
| 13 | Are secrets passed via environment variables, command lines or world-readable files anywhere in installers/units? | THR-013 |
| 14 | Do failure paths fail closed (intake stops) on checker exit ≥ 20, manifest FAIL, floor FAIL and crypto self-test FAIL? | THR-035, THR-014 |

## 5. Test plan

| Test | Command / tool | Gate |
|---|---|---|
| Unit/property | `cargo test -p candor-update -p candor-platform -p candor-check -p candor-health -p candor-backup --locked` | PR |
| Lints | `cargo clippy --workspace --all-targets --locked -- -D warnings` | PR |
| Fuzz | `cargo fuzz run fuzz_tuf_metadata -- -max_total_time=3600`; `cargo fuzz run fuzz_config -- -max_total_time=3600`; backup manifest and support-bundle scrubber targets (≥ 60 s per PR, ≥ 1 h nightly, SI-A-07) | PR/nightly; SG-07 |
| Mutation | `cargo mutants -p candor-update -p candor-platform -p candor-backup` — 0 surviving mutants in `verify_*`/`check_*` (SL-R-006) | PR (changed fns) |
| Unit hardening | `systemd-analyze security --offline=yes --threshold=<n> /usr/lib/systemd/system/candor-*.service`; `systemd-analyze verify` | PR on packaging |
| Update rejection | ST-130 harness against a test TUF repo (rollback, freeze, mix-and-match, unlogged, under-threshold) | SG-19 |
| Platform/floor | ST-153; `candorctl platform verify --all-hosts --json` on fault-injected hosts | SG-27 |
| Secret placement | ST-121 matrix job (profiles × flags) | SG-16 |
| Config | ST-120; `candorctl check --all-hosts --json \| jq -e '.exit==0'` on fresh CE-SINGLE/CE-HARDENED | SG-17; RM-5 exit |
| Egress | `tcpdump -i <uplink> -w cap.pcap` during full suite + `candor-update refresh`; assert only tor ORPort flows | SI-D-03 |
| Backup/restore | ST-108, ST-158, ST-174, ST-175; `candorctl dr drill --profile ce-hardened` recording RPO/RTO | SG-20; RM-5 exit |
| Upgrade/rollback | ST-107 (N-2 minors), ST-103 power loss | SG-19 |
| Anonymity | AT-001..AT-019 canary over agent, collector, backup manifests, support bundles, updater logs | SG-10 |

## 6. OPSEC checklist (exposure this step could create)

| Exposure | Control |
|---|---|
| Update fetch timing/requests fingerprint an instance to mirror/CDN/vendor | Identical metadata fetch, no identifiers, randomized interval and rollout delay; intake via onion mirror only |
| Mirror access logs | Mirrors keep date/path/status only, no IP > 24 h (33 §14.1) |
| Backup store sees sizes and times correlating with submissions | Size-class padding; fixed nightly schedule with jitter; BS-INTAKE holds no envelopes |
| H-MON onion probe pattern reveals operator monitoring | Synthetic probe only, fixed-size endpoint; no real source traffic observed |
| Installer outputs (printed sheets, IRK shares) | No secrets on the publication sheet; IRK shares handled per 19 §4; printing on local printer only (no network printing), stated in guide |
| Admin workstation holds secrets | Secrets generated on owning host; BS-SECRETS only encrypted to IRK |
| Support bundles reach vendor | Allow-list, hashing, hour truncation, operator preview, ≤ 30-day vendor retention |
| APT/OS updates from intake | Only Platform Manifest packages via local verified repo; tor+https sources only through update tor instance |
| Self-test and checker JSON exported to SIEM later (RM-9) | Fixed schema already privacy-safe; no free text |
| Maintenance windows revealing org working hours | Default windows at night with jitter (18 §8); guidance against business-hour patterns (SI-D-03 uptime rule) |

## 7. Exit criteria

| Type | Criterion |
|---|---|
| Roadmap (38 RM-5) | Fresh install → `candorctl check` all-green without manual hardening; restore drill meets 19 RPO/RTO for CE-SINGLE and CE-HARDENED; update rollback/freeze tests pass |
| Security gates | SG-16, SG-17, SG-19, SG-20, SG-27 pass; SG-05/07/10/13/14 pass for all new crates; R8 §5.4 RM-5 items: TUF freeze UX and SG-13 extended to delta targets and installer bundles |
| Audit gate | For every step RM5-S1..S10: `process/audits/AUDIT-RM5-Sn.md` by an independent auditor (not the builder) using `process/AUDIT-CHECKLIST.md` + §4 above; 0 open Critical/High; Medium fixed or accepted in writing by the lead; auditor re-test recorded |
| Milestone record | Signed RM-5 milestone report with SG results and open findings logged (RM-005) |

## 8. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| IMP-RM5-001 | Every packaged Candor daemon unit SHALL apply the SI-B-01 sandbox baseline and SHALL score ≤ 2.0 (intake units ≤ 1.5) in `systemd-analyze security`, enforced in CI. | B-SI-18; B-SI-19 | THR-014, THR-016 | C-05 | TST: CI job `unit-exposure`; INSP |
| IMP-RM5-002 | Installer logic and maintainer scripts SHALL NOT copy directories into secret-bearing paths and SHALL NOT access the network. | INC-106; ADR-028 | THR-013, THR-044 | C-19 | TST: lint `installer-no-dir-copy`; ST-121 |
| IMP-RM5-003 | Each host SHALL be verified after every deploy and every 5 minutes against its signed Secret Placement Manifest; a forbidden secret on an intake host SHALL stop intake. | ADR-028; INC-106 | THR-013, THR-044 | C-25 | ST-121; TST: fault-injection `secret.placement` |
| IMP-RM5-004 | The update client SHALL install an artifact only if threshold TUF signatures (hybrid Ed25519 + ML-DSA-65 per key) and a log inclusion proof cosigned by ≥ 2 pinned witnesses verify. | ADR-022; INC-48; INC-52 | THR-025, THR-024 | C-32 | ST-130; ST-047 |
| IMP-RM5-005 | Update requests SHALL carry no instance, tenant, onion or licence identifier, SHALL fetch metadata for all products, and SHALL use a randomized 2–6 h interval; intake hosts SHALL fetch only through the update tor instance. | ADR-022; ADR-046(3); INC-14 | THR-025, THR-026, THR-001 | C-32 | TST: request-capture equality test across two instances; TST: intake pcap shows only tor flows |
| IMP-RM5-006 | The update HTTP client SHALL NOT follow redirects and SHALL enforce TUF lengths and total timeouts. | INC-104; B-SI-17 | THR-025, THR-032 | C-32 | TST: redirect and endless-data cases in ST-130 |
| IMP-RM5-007 | Trust-path units SHALL refuse to start below the signed security floor after `effective_day`, evaluated against the independent time floor; no local or Fleet setting SHALL override this. | ADR-040; ADR-045 | THR-025, THR-043 | C-25 | ST-153; ST-106 |
| IMP-RM5-008 | The installed package set on Z-INTAKE and Z-CORE SHALL equal the TUF-signed Platform Manifest; any EXTRA, MISSING, HASH or SOURCE deviation SHALL fail the self-test and stop intake. | ADR-040; INC-37 | THR-024, THR-035 | C-25 | ST-153; TST: extra-package injection |
| IMP-RM5-009 | `candorctl check` SHALL evaluate effective runtime state, ship its rules in the signed package, accept no local rule overrides, and block intake start and upgrades at exit ≥ 20. | INC-118; INC-SL-14; ADR-046(6) | THR-035 | C-19 | ST-120; ST-050; TST: drift fixtures |
| IMP-RM5-010 | Go-live SHALL be refused until checker, secrets verify, self-test and platform verify report OK and the 18 §8.1 gates are recorded. | INC-101; ADR-045 | THR-035, THR-018 | C-19 | TST: go-live gate matrix; DEMO: AT-073 |
| IMP-RM5-011 | Self-test results SHALL conform to the fixed schema of 32 §5.3 and SHALL contain no counts, onion addresses, IPs or event timestamps; the collector SHALL reject non-conforming records. | INC-60; ADR-016 | THR-016, THR-039 | C-25 | AT-001; TST: collector schema fuzz |
| IMP-RM5-012 | Backup sets SHALL NOT compress secret-bearing data before encryption unless padded to a fixed size class, and set size SHALL be independent of key bytes. | INC-63; INC-SL-05; SL-R-005 | THR-015, THR-011 | C-27 | TST: size-invariance test; INSP |
| IMP-RM5-013 | Every restore SHALL apply the newest verifiable erasure log and intake deletion list before any service serves data, and SHALL refuse sets whose signature, chain or anchor fails. | ADR-044(4); ADR-047(9) | THR-017, THR-042 | C-27 | ST-158; ST-174; ST-108 |
| IMP-RM5-014 | Backup agent credentials SHALL be put-only with ≤ 24 h validity and SHALL NOT delete, overwrite or shorten retention. | INC-55; 19 §9 | THR-042, THR-017 | C-27 | TST: credential-scope negative tests; AUD: A8 |
| IMP-RM5-015 | A restore drill on CE-SINGLE and CE-HARDENED SHALL meet the RPO/RTO of 19 §10 before RM-5 exit, with results recorded as SYSTEM events without row data. | 19 §10; ADR-044 | THR-042 | C-27 | DEMO: `candorctl dr drill` report; ST-108 |
| IMP-RM5-016 | Upgrades SHALL take a verified pre-upgrade backup, use expand/contract migrations run by `schema_owner`, and roll back automatically if self-test is not OK within 15 minutes; rollback to revoked or below-floor versions SHALL be refused. | B-SD-02; SI-E-06 | THR-025, THR-042 | C-19 | ST-107; ST-103 |
| IMP-RM5-017 | Support bundles SHALL be allow-list generated, previewed and FIDO2-confirmed, hour-truncated, encrypted to a confirmed key, and aborted on any canary or secret-pattern hit. | INC-56; INC-60 | THR-027, THR-016 | C-19 | AT-001 on bundles; ST-068 |
| IMP-RM5-018 | Appliance images SHALL contain no secrets and SHALL regenerate machine-id, host keys, LUKS keys, onion keys and TLS keys on first boot. | 18 §5; INC-106 | THR-013, THR-044 | C-39 | ST-121 on image; TST: first-boot uniqueness test |

## 9. Residual risks and open issues

| # | Item | Handling |
|---|---|---|
| R1 | Self-test runs on the host it checks; a root attacker can forge results | Detects drift and accidents, not a capable root attacker; external onion probe and watchers (ADR-035) partially compensate; stated in 32 |
| R2 | TUF hybrid key type (OI-1) not supported upstream in `tough`/`rust-tuf` | Implement behind internal trait with a Candor verifier; A6/A9 review; keep in RM-5 audit scope |
| R3 | Attested rules (hypervisor/SAN) depend on third-party honesty | Signed attestations + RT-7 probe; deletion statement conditional (INFRA-037) |
| R4 | Not-yet-imported envelopes are lost on intake host destruction (19 §10) | Documented; source notice via 31 |
| R5 | `systemd-analyze` score semantics (0–100 internal vs /10 display) UNVERIFIED (R7 B1) | Pin systemd version in CI image and calibrate thresholds once |
| OI-1 | Exact playbook-runner subcommands not yet specified in 31/18 | Cross-document request to 31 owner |
