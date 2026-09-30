# 30 — Anonymity and Metadata-Leak Testing
Status: Draft v1.0 · Edition applicability: both (EE-only sinks such as SIEM export and Fleet Manager tested in EE matrix) · Owner: Security Engineering — Anonymity Verification (with UX Research for §10)

## 1. Purpose and scope

Conventional security tests check that attackers cannot get in. This document checks what Candor itself **writes down, emits or reveals** about sources, and what an adversary who compromises or seizes a component would **learn**. It specifies:

1. **Instrumented canary tests** (AT-001..AT-019). Unique marker values (network identity, User-Agent, filename, file content, message text, passphrase, exact action times, sizes, circuit/stream IDs) are injected through full source journeys. Then **every** sink is scanned: application logs, reverse-proxy/web-server logs (which must not exist on the path), tor logs, journald, kernel logs, all database tables including WAL, metrics, tracing, SIEM, APM, crash dumps, backup contents and metadata, support bundles, the notification outbox and audit logs. **Any hit is a security regression and a release blocker.**
2. **Compromise drills** (AT-020..AT-032). "Compromise the DB, the log server, the application servers, the SIEM; seize backups; steal an admin credential; steal a recipient device; ship a malicious update": each has a procedure and an expected, minimized answer to "what is learned?".
3. **Timing and size leak tests** (AT-040..AT-048): timestamp granularity, ordering, response timing, padding.
4. **Fingerprinting and third-party request tests** for the source UI (AT-050..AT-058): no JavaScript, storage or cookies beyond the session, and no external requests (network capture during the full source flow).
5. **Mode-confusion, notification content, telemetry-off and aggregate k-threshold tests** (AT-060..AT-068).
6. A **usability-security study programme** (AT-070..AT-075) with nontechnical whistleblowers, investigators, HR, compliance staff, journalists, administrators and users of assistive technology.

Requirements on the programme itself use **ANT-** IDs (§12).

Honest language: these tests show that the tested markers did not reach the scanned sinks under the tested journeys and configurations. They cannot prove that no metadata leaks exist. Unscanned sinks, untested journeys and side channels remain. The compromise drills describe what Candor's design is *intended* to limit an adversary to. They are validated against a lab system, not every real deployment.

## 2. Context and dependencies

| Document | Relationship |
|---|---|
| `DECISIONS.md` | ADR-001/002/003 (onion only, modes, no fingerprinting), ADR-004 (Tier W/V), ADR-005 (passphrase), ADR-007/008 (key custody, epochs), ADR-009 (intake/core), ADR-010 (timing), ADR-011 (padding), ADR-014 (sealed identity), ADR-016 (audit classes, typed logging), ADR-017 (content-free notifications), ADR-022/023 (updates, telemetry), ADR-025 (deletion), ADR-028 (secret placement) |
| `03-PRIVACY-ANONYMITY.md` | Owns the **compelled/compromise disclosure inventory** (the expected answers are checked against it), the k-threshold parameter for aggregates, and the prohibited-field list |
| `20-LOGGING-AUDITING.md` | Typed event schema; sink inventory must match it |
| `11-FRONTEND-SOURCE.md` | Source UI cookie/session/padding behaviour under test (SUI-) |
| `16-TOR-I2P.md` | tor configuration under test (NET-) |
| `19-BACKUPS-DR.md` | Backup contents and metadata |
| `24-LICENSING-BUSINESS-MODEL.md` | Telemetry schema (TEL-) |
| `26-ACCESSIBILITY.md` | Accessibility targets used in §10 |
| `27-SECURE-DEVELOPMENT.md` | Gates SG-10, SG-11, SG-12, SG-24 |
| `29-SECURITY-TESTING.md` | Shared lab (E2 candor-lab with chutney Tor, E4 live-Tor staging, E5 profile matrix) |
| `40-SECURITY-ASSUMPTIONS.md` | ASM-* assumptions (e.g., Tor anonymity, endpoint integrity) that bound what these tests can claim |

Research basis: R3 INC-60 (Facebook plaintext logs), INC-56 (Okta HAR), INC-58 (crash dump key), INC-53 (Meta Pixel), INC-34 (onion misconfiguration), INC-33 (Silk Road IP leak), INC-16 (Reality Winner timing/audit), INC-55 (LastPass backups), INC-57 (push metadata), INC-74 (Strava aggregates) and REQ-H-06/10/25/27/33/34/55/56/60/70/74 [B-INC-29..B-INC-32, B-INC-60, B-INC-61, B-INC-83..B-INC-93, B-INC-111]; R4 application-layer attacks, fingerprinting, timing correlation [B-AN-01..B-AN-05, B-AN-14..B-AN-22]; R1 logging practice and SEC-01-016 logging tension, GHSA-rqwh secret placement [B-SD-13, B-SD-21, B-SD-22]; R2 GlobaLeaks logs staff IPs by default; Hush Line PRIVACY.md "no IP in database" [B-GL-04, B-GL-34]; R6 accessibility and COGA [B-CO-28, B-CO-36].

## 3. Principles

1. **Any hit is a blocker.** A canary marker found in any sink outside its documented allowed location is a SEV-1 anonymity regression. Gate SG-10 is non-waivable (27 §13.2).
2. **Test the release artefacts** (signed candidate packages), installed by the real installer in each deployment profile, not developer builds.
3. **Test the worst permitted configuration.** Every canary run is repeated at the most verbose logging and diagnostics settings the configuration schema permits without a DANGEROUS flag, and separately with each DANGEROUS diagnostic flag. For DANGEROUS flags, the expected result may differ, but the difference must match the flag's documented warning text.
4. **Scan everything, including what "should not exist".** The sink inventory (§4.3) is enumerated by crawling the hosts, not only from the design. Any new file, table or stream discovered on a host that is not in the inventory fails the run until classified (ANT-004).
5. **Expected answers are documentation.** Compromise-drill answers must be a subset of the published disclosure inventory in 03. If a drill finds more, either the product is fixed or 03 and the source-facing guidance are updated (ANT-011) before release.

## 4. Canary methodology

### 4.1 Markers

Each run generates fresh random markers (128-bit hex `H`). The harness records all markers in a run manifest held **outside** the system under test.

| Marker | Value / construction | Injection point | Allowed location(s) on platform |
|---|---|---|---|
| M-IP4 / M-IP6 | Unique per run: `198.51.100.x` / `2001:db8:<H[0:4]>::<H[4:8]>` (documentation ranges) assigned to the source client's network namespace; traffic enters the platform only via chutney Tor (E2) or real Tor (E4) | Client network identity | **None** (the platform must never see it) |
| M-IP-HDR | The same IP strings injected in `X-Forwarded-For`, `Forwarded`, `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP`, `Via`, `Client-IP` request headers (header-smuggling attempt) | HTTP headers | **None** |
| M-UA | `Mozilla/5.0 (Windows NT 10.0; rv:140.0) Gecko/20100101 Firefox/140.0 CndrCnry-H` (test profile override) | User-Agent header | **None** |
| M-LANG | `Accept-Language: x-cndr-H` | Header | **None** |
| M-FNAME | `cnry-H-Quarterly report ü.pdf` | Upload filename (multipart `filename`), Source App file picker | Only inside encrypted envelope (never plaintext on any server; in C-15 only in encrypted local store and in C-17 disposable VM) |
| M-FCONTENT | File containing `CNRYFILE-H` repeated, a JPEG with EXIF `Artist=cnry-H`, GPS `12.3456789,-65.4321098`, a DOCX with `dc:creator=cnry-H` | Attachments | Same as M-FNAME |
| M-MSG | Message text `cnry-msg-H` plus questionnaire answers `cnry-form-H` | Text fields | Encrypted only |
| M-PASS | The generated source passphrase (captured by harness from the page/app), its Argon2id seed, derived auth key and public keys (computed by harness) | Tier W generation, login | Passphrase and seed: **none**. Source public keys and auth verifier: only the designated C-08 columns and sealed relay batches |
| M-SESSION | Session cookie value | Source web session | Nowhere persistent (memory only) |
| M-CIRC | tor circuit IDs and stream IDs observed for the harness's connections (read from the lab tor control port at C-05) | Tor transport | Nowhere persistent (in-memory rate limiter only, ADR-026) |
| M-TIME | Exact UTC time T of each source action (submit, upload, login, read reply, send reply, delete), performed inside a **quiet window** of ±10 min with no other scripted activity | Source actions | Only `received_epoch_day` (date) and batch number; no timestamp within [T−600 s, T+600 s] at finer than day granularity in any source-linked record |
| M-SIZE | Unique content sizes (for example text 3,217 bytes; file 1,337,421 bytes) | Sizes | No exact plaintext size anywhere; only padded bucket sizes (ADR-011) |
| M-TZ | Browser/app time zone and locale set to rare values (`Pacific/Chatham`, `kl-GL`) | Client environment | **None** |

### 4.2 Encodings and transformations searched
For every marker, the scanner searches:

- plain text (case-sensitive and case-insensitive);
- URL/percent encoding, HTML entities, JSON-escaped and quoted-printable forms;
- base64 (standard and URL-safe, all 3 alignments) and hex (lower/upper);
- UTF-16LE/BE;
- IPs as integers and reverse-DNS form, plus /24 and /48 prefixes ("198.51.100.");
- unkeyed digests (SHA-256, SHA-1, MD5, BLAKE3) of each marker and of lowercase forms;
- Unix epoch seconds/milliseconds/microseconds/nanoseconds, ISO-8601 and PostgreSQL text forms for M-TIME;
- decimal and hex forms for M-SIZE.

Compressed containers are decompressed before scanning: gzip, zstd, lz4, xz, zip, tar and journald compressed fields. PostgreSQL TOAST is covered by the logical dump. Keyed hashes (HMACs) cannot be detected by scanning. Code paths that compute keyed hashes of source attributes are prohibited by 20/03 and checked by INSP of the typed-log schema.

### 4.3 Sink inventory (scanned in every canary run)

| # | Sink | Host / zone | Collection method | Expected |
|---|---|---|---|---|
| S01 | Application logs (C-06, C-07, C-09, C-10, C-21, C-23, C-24 local buffers) | Z-INTAKE, Z-CORE | journald export + any files under `/var/log`, `/var/lib/candor/*/log` | 0 hits |
| S02 | Reverse-proxy / web-server access and error logs | Z-INTAKE | Assert **no** access-log configuration and no such files exist on the source path (tor → C-06 directly over Unix socket); scan error logs if any | Files absent; 0 hits |
| S03 | tor daemon logs | C-05 | tor log files + journald; config asserts `SafeLogging 1`, `Log notice` | 0 hits |
| S04 | journald (all units) | all hosts | `journalctl -o export` full, including compressed fields | 0 hits |
| S05 | Kernel logs / audit | all hosts | `dmesg`, `/var/log/kern.log`, auditd logs, conntrack table dump | 0 hits |
| S06 | Intake DB (C-08) | Z-INTAKE | `pg_dump` (all schemas incl. catalog stats) **and** raw scan of PGDATA incl. `pg_wal/`, `pg_xact/`, temp files, `pg_stat_statements` view, `pg_stat_activity` snapshots, PostgreSQL server logs | Hits only in allowed columns (M-PASS public values) |
| S07 | Case DB (C-12) | Z-CORE | Same as S06 | 0 hits (source public keys may appear only in designated reply-routing columns if 09 defines them) |
| S08 | Blob stores (C-08 blob dir, C-13) | both | Raw scan of files; verify files are ciphertext (entropy ≥ 7.9 bits/byte, format header); filesystem metadata listing (names, mtimes) | 0 plaintext hits; names random; mtimes normalized per AT-040 |
| S09 | Metrics (Prometheus/OpenMetrics endpoints, TSDB on C-25) | Z-SOC | Scrape all endpoints; scan TSDB blocks; label cardinality report | 0 hits; no per-source labels |
| S10 | Tracing / APM (if any exporter configured) | all | OTLP collector in lab captures all spans/attributes | 0 hits; no spans on the source path carrying request attributes |
| S11 | SIEM export (C-26, EE) | Z-SOC → lab SIEM | Capture every exported event at the lab SIEM | 0 hits |
| S12 | Crash dumps / panic output | all | Force panics/crashes (AT-011); check `systemd-coredump`, `/var/crash`, `/var/lib/apport`, stderr captured in journald | No dumps exist; 0 hits |
| S13 | Backup contents and metadata (C-27) | Z-BAK | Scan backup archives (decrypting with backup keys available to the lab operator) **and** unencrypted backup metadata (manifests, file names, catalog DB, object-store keys, timestamps) | 0 hits; metadata contains no source-linked times finer than day |
| S14 | Support bundles | Z-ADM (generated by `candorctl support-bundle`) and Desk diagnostics | Generate bundles at max verbosity; scan | 0 hits (REQ-H-56) |
| S15 | Notification outbox (C-23) and delivered notifications | Z-CORE; lab mailpit / Matrix / webhook sinks | Scan outbox table, queue, SMTP transcripts, delivered bodies and headers | 0 hits; content = fixed template (AT-062) |
| S16 | Audit log (C-24) all classes + checkpoints + external witness anchors | Z-CORE | Export and scan all streams | 0 hits; no SOURCE-SENSITIVE events |
| S17 | Filesystem sweep | all hosts incl. `/tmp`, `/var/tmp`, `/dev/shm`, home dirs, package caches | Full-disk file scan + raw block-device scan of intake hosts | 0 hits |
| S18 | Swap / hibernation | all | Assert no swap and no hibernation image configured | Absent |
| S19 | Recipient side (C-15 local logs, OS logs, thumbnail caches, recent-files lists, clipboard history, C-17 VM after destruction) | Z-RCP, Z-VIEW | Scan Desk data dir (only encrypted store may contain markers, and it must be ciphertext), OS logs/caches, verify C-17 VM image destroyed | 0 plaintext hits outside encrypted store |
| S20 | Update requests and telemetry (if enabled) | all → lab mirror | Capture update client requests | 0 hits; no instance identifier (ADR-022) |
| S21 | Host-level tooling (C-25 monitor agent, hardening agents, IDS such as OSSEC/Wazuh if used) | all | Scan agent state/queues/alerts | 0 hits |
| S22 | HTTP responses (reflection) | Z-INTAKE | Capture all responses to the harness | Markers appear only where the source themselves submitted them in their own session view (for example their own message when viewing it) and never in error pages |

### 4.4 Procedure

```mermaid
sequenceDiagram
  participant H as Canary harness
  participant L as Lab (release artefacts, profile P, log level max)
  participant S as Sink collector
  participant X as Scanner
  H->>L: Provision from signed RC packages (installer), profile P
  H->>H: Generate markers (fresh H), record manifest outside SUT
  H->>L: Source journeys J1..J9 (Tier W, Tier V web, Source App) in quiet windows
  H->>L: Failure journeys F1..F6 (errors, crashes, disk full, DB down)
  H->>L: Staff journeys (import, read, reply, export, delete), backup, support bundle, SIEM export
  H->>L: Wait for relay pulls + notification digest + log rotation (≥2 cycles)
  L->>S: Collect S01..S22 (+ any newly discovered stores)
  S->>X: Artefacts
  X->>X: Search all markers × all encodings
  X-->>H: Report: hits (sink, offset, marker, encoding), unknown sinks
  H-->>H: PASS only if 0 hits outside allowed locations and 0 unclassified sinks
```

Source journeys:
- **J1** first submission (text only);
- **J2** submission with 3 attachments (M-FCONTENT);
- **J3** return login + read reply;
- **J4** send follow-up message;
- **J5** failed login (wrong passphrase);
- **J6** unknown account login;
- **J7** abandoned submission (form partly filled, session expires);
- **J8** source-initiated deletion (if offered);
- **J9** oversized upload rejected.

Failure journeys:
- **F1** C-07 crash during seal;
- **F2** DB unavailable;
- **F3** disk full on intake;
- **F4** malformed multipart;
- **F5** relay pull failure;
- **F6** notification delivery failure.

Profiles: CE-SINGLE, CE-HARDENED and EE-ONPREM nightly; all 8 profiles (ADR-024) at RC.

### 4.5 Hit handling
- The run fails; SEV-1 ticket; `main` is marked not releasable.
- Root-cause analysis within 5 business days (27 SDL-051). The fix includes a regression test and a structural control where possible (27 SDL-052), for example a new typed-log lint.
- An allow-list entry is possible **only** for the allowed locations in §4.1. The entry must identify table/column or file path and prove that the content there is ciphertext or a permitted public value. It needs two approvals (Anonymity Reviewer + Security Lead).

## 5. Canary test catalogue (AT-001..AT-019)

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| AT-001 | Canary full-flow Tier W | No marker from J1–J9 reaches any sink S01–S22 outside allowed locations (Tier W no-JS web) | §4.4 with headless Tor Browser at Safest over chutney | Nightly (3 profiles), RC (8 profiles) | Yes (release blocker) |
| AT-002 | Canary full-flow Tier V (web bundle + Source App) | Same for Tier V clients; additionally server never receives plaintext markers (only ciphertext) | §4.4 with WEBCAT-verified bundle (when available) and C-03 | Nightly, RC | Yes |
| AT-003 | App-log sink | S01 = 0 hits at max permitted log level | Subset scan | Nightly, RC | Yes |
| AT-004 | No access logs on source path | S02 files absent; web/access logging disabled in shipped config; C-06 peer address is always Unix socket/loopback | Config + filesystem assertions; C-06 debug endpoint absent | PR (config), nightly, RC | Yes |
| AT-005 | tor logs | `SafeLogging 1`, level ≤ notice; no marker or circuit/stream IDs in logs | Config + scan | Nightly, RC | Yes |
| AT-006 | journald/kernel/conntrack | S04/S05 = 0 hits; conntrack on intake shows no marker IP (only tor ↔ relays) | Scan + `conntrack -L` snapshots during journeys | Nightly, RC | Yes |
| AT-007 | Databases incl. WAL | S06/S07 = 0 hits outside allowed columns; `pg_stat_statements` disabled or parameters normalized; `log_statement=none`, `log_min_error_statement=panic`, `log_connections=off` on intake DB | Logical + raw scans | Nightly, RC | Yes |
| AT-008 | Metrics | S09 = 0 hits; no metric label derived from request attributes; source-related counters only as defined in 20 | Scrape + TSDB scan | Nightly, RC | Yes |
| AT-009 | Tracing/APM | S10 = 0 hits; source-path spans (if any) carry no attributes | OTLP capture | Nightly, RC | Yes |
| AT-010 | SIEM export | S11 = 0 hits; only allow-listed event types exported (ADR-016/018) | Lab SIEM capture | Nightly (EE), RC | Yes |
| AT-011 | Crash dumps | Induced crashes of C-06/C-07/C-09/C-10/C-15 produce no dumps and panic messages carry no markers | Signal/panic injection + S12 | Nightly, RC | Yes |
| AT-012 | Backups & backup metadata | S13 = 0 hits; backup manifests, filenames and catalogs contain no source-linked exact times, sizes or names | Backup run after journeys; scan | Nightly, RC | Yes |
| AT-013 | Support bundles | S14 = 0 hits at max verbosity for server and Desk bundles (REQ-H-56) | Generate + scan | Nightly, RC | Yes |
| AT-014 | Notification outbox & deliveries | S15 = 0 hits; queue rows contain no case/source references | Outbox + mailpit/Matrix capture | Nightly, RC | Yes |
| AT-015 | Audit log | S16 = 0 hits; no SOURCE-SENSITIVE class events emitted; CASE events use pseudonymous case IDs | Export + scan | Nightly, RC | Yes |
| AT-016 | Filesystem & raw-disk sweep | S17/S18 = 0 hits; no swap/hibernation; raw block scan of intake shows no plaintext markers | Full scans | Nightly (file), RC (raw block) | Yes |
| AT-017 | Response reflection | Error pages and all responses never reflect markers except the source's own content in their own authenticated view | S22 capture | Nightly, RC | Yes |
| AT-018 | Failure-path canaries | F1–F6 journeys produce 0 hits in all sinks (errors never echo input; no debug dumps on failure) | §4.4 failure journeys | Nightly, RC | Yes |
| AT-019 | Recipient-side sinks | S19: Desk, OS logs, thumbnails, recent files, clipboard history, C-17 residue contain no plaintext markers outside the encrypted store; C-17 VM destroyed | Desk automation on Linux/Windows/macOS + scan | Nightly (Linux), RC (all OS) | Yes |

## 6. Compromise drills (AT-020..AT-032)

### 6.1 Drill method
1. **Seed history.** Deploy the RC on candor-lab and run `candor-synth` history: 200 synthetic sources over 90 simulated days (70% Tier W, 30% Tier V), 400 messages, 300 attachments, 150 replies, 20 deletions, 3 channels, 12 staff users, a COI exclusion, 1 CONFIDENTIAL report with sealed identity (ADR-014). All canary markers from §4.1 are embedded per source.
2. **Grant capability.** Give the "adversary" exactly the stated capability (for example a root shell on host X, or a copy of backup set Y) and the **adversary toolkit**: scripts that dump DBs, grep for markers, attempt key use, replay credentials, and query all reachable APIs.
3. **Record the Learned Inventory.** Record everything learnable as a structured `learned.json` (data category, example, scope such as "all sources"/"sources active during window", precision).
4. **Compare.** Compare with the Expected Answer below **and** with the 03 disclosure inventory. PASS if learned ⊆ expected. Anything extra fails SG-11.
5. **Report.** A report for each release is published in summary form (ANT-012).

### 6.2 Drill catalogue

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| AT-020 | Compromise Intake DB (C-08 snapshot incl. WAL + blob dir) | Seizure/theft of intake storage yields only the minimized set below | §6.1 with DB + blob copy | RC; nightly automated subset | Yes (SG-11) |
| AT-021 | Compromise Case DB + blob store (C-12, C-13) | Theft of core storage yields no content or source identity | §6.1 | RC; nightly subset | Yes |
| AT-022 | Compromise log server (C-24 store + host log aggregation) | Logs cannot identify sources | §6.1 with full log store | RC | Yes |
| AT-023 | Compromise SIEM (EE C-26 destination) | SIEM cannot identify whistleblowers | §6.1 with lab SIEM contents after 90 simulated days | RC (EE) | Yes |
| AT-024 | Compromise intake application server (root on Z-INTAKE: C-05..C-08) | Which historical reports are readable; what live compromise exposes | §6.1 + live attacker window of 24 h during which scripted sources act | RC | Yes |
| AT-025 | Compromise core application server (root on Z-CORE app host: C-09, C-10, C-14, C-21..C-24) | No content decryption; tampering detected | §6.1 + key-substitution and withholding attempts | RC | Yes |
| AT-026 | Seize backups (C-27 full set incl. offsite copy) | Backups yield no content, no keys, no source-linked metadata beyond the inventory; deleted cases unreadable | §6.1 with backup set, without recipient devices/quorum | RC | Yes |
| AT-027 | Steal admin credential (admin FIDO2 key + PIN, or admin workstation session) | Admin compromise yields no case content and cannot silently degrade anonymity | §6.1 via Admin Console/`candorctl` | RC | Yes |
| AT-028 | Steal recipient device (a) powered off/locked, no token; (b) with hardware token but no PIN; (c) unlocked with token + PIN | Exposure is bounded by device state and that member's ACL | §6.1 against Desk data dir and running session | RC | Yes |
| AT-029 | Malicious update ((a) one targets key compromised; (b) distribution server compromised; (c) targets threshold compromised; (d) targeted per-instance update) | Only (c) installs, and it is publicly logged and identical for all; (a)(b)(d) rejected | Rogue TUF repo (29 E3) + transparency monitor | RC | Yes |
| AT-030 | Compromise monitor host (C-25) | Monitor holds no secrets outside its manifest and cannot reach content | §6.1 + ST-121 manifest check | RC | Yes |
| AT-031 | Hosting provider / hypervisor snapshot (disk + RAM snapshot of intake VM; PRIVATE-CLOUD/MANAGED) | Exposure is equal to AT-024 for the snapshot instant | Take VM memory snapshot during a Tier W submission; analyse | RC | Yes |
| AT-032 | Compelled or compromised vendor (EE Fleet Manager C-34, support C-36, licensing C-35) | Vendor-side systems hold no onion addresses in cleartext, no content, no keys, no source metadata | §6.1 on vendor-side lab stores | RC (EE) | Yes |

### 6.3 Expected (minimized) answers

**AT-020: Compromise Intake DB.** *What is learned?*
- Sealed envelopes (ciphertext), padded to ADR-011 buckets (bucket size only, no exact size), and the target channel/epoch key ID for each envelope.
- `received_epoch_day` (UTC date) and monotonic batch number per envelope (ADR-010). Within-day **insertion order** may be inferable from physical row order/WAL LSNs (residual, §13).
- Source public keys and auth verifiers for accounts on this intake. These cannot be inverted to passphrases (≈129-bit entropy, ADR-005). Messages sealed under the **same** source key are linkable to each other (one passphrase per report by default).
- Sealed replies awaiting pickup (ciphertext, padded).
- Counts of envelopes per day per channel (day granularity).
- Envelopes already pulled by C-09 and acknowledged are absent, because intake retention deletes them after acknowledgement (see 07/09). A seizure therefore sees only the not-yet-pulled window plus replies awaiting pickup.
- *Not learned:* content, filenames, sizes beyond bucket, IPs, User-Agents, exact times, circuit IDs, identity, and links between different passphrases.

**AT-021: Compromise Case DB + blob store.**
- Pseudonymous case IDs, workflow states, channel, assignment (staff user IDs), SLA fields, staff-action timestamps (exact; staff audit per ADR-010), and received dates (day).
- Wrapped case keys, which are useless without member devices or quorum shares (ADR-007/008/013), and ciphertext evidence objects with padded sizes.
- Structural metadata defined as plaintext in 09, listed exactly in the 03 inventory, for example case category if 09 keeps it in plaintext.
- *Not learned:* content, sealed identity (encrypted to custodians, ADR-014), IPs, UA, exact submission times.
- Honest note: the staff-action timestamps of the first import give an **upper bound** on submission time (submission ≤ import time; lag ≥ the relay pull delay 15±10 min).

**AT-022: Compromise log server.**
- SECURITY events (staff logins, admin actions, config changes), SYSTEM health events, and CASE events with pseudonymous case IDs and exact staff-action times.
- *Not learned:* any source-linked field (IP, UA, filename, passphrase, exact submission time). Tor/web access logs do not exist.
- Upper bound on arrival time: as in AT-021, via staff import events.

**AT-023: Compromise SIEM.** *Can whistleblowers be identified?*
- Expected answer: **not from SIEM data alone.** The SIEM receives only allow-listed, scrubbed SECURITY/SYSTEM events (ADR-016/018): staff authentication outcomes, admin config changes, health, and relay "pull OK/failed" without envelope counts. Submission counters are exported only as daily thresholded aggregates (AT-065).
- The SIEM can learn staff working patterns and the dates on which staff imported new reports. Combined with employer-side knowledge (for example who accessed a document), that may narrow suspects by **date**. This is the residual that ADR-010 bounds to day granularity, and the drill documents it.
- *Fail criteria:* any event with sub-day timing linked to a specific submission, any per-submission event, any source attribute.

**AT-024: Compromise intake application server (root, live).** *Which historical reports are readable?*
- **Historical submissions sealed before the compromise: none readable.** Epoch private keys are never on Z-INTAKE (ADR-008). Envelopes on disk are ciphertext.
- **Tier W submissions made during the compromise window: readable** (live plaintext in C-07 RAM; ADR-004 honest statement).
- **Tier W sources who log in during the window:** the attacker can capture the passphrase and therefore derive source keys. That exposes those sources' **historical reply threads** (replies are encrypted to source keys) and allows impersonating those sources afterwards. This is a significant residual and is stated in source guidance (05/11).
- **Tier V sources:** no plaintext. The attacker can attempt to serve altered client code. The WEBCAT-enforced bundle and the Source App verification must reject it (ST-093/094; THR-007).
- **Live metadata:** the attacker can observe live session timing, User-Agent (Tor Browser uniform) and circuit IDs, but **not source IP** (onion service).
- **Onion service key:** stolen (THR-044), which allows impersonation of the service. Recovery follows 31 (rotate onion address, key-directory announcement).
- *Fail criteria:* any envelope sealed before the window decryptable; any IP learnable; any stored UA/time data from before the window.

**AT-025: Compromise core application server (root, live).**
- Everything in AT-021, plus live staff session metadata. No content decryption: recipient private keys live only on endpoints (ADR-007).
- The attacker can withhold or delay envelopes (DoS), alter workflow data (detectable via audit hash chain and checkpoints, 20), and attempt key substitution or hidden recipients in the key directory. Clients must reject or flag these (ST-093/094). The transparency log makes a split view detectable.
- *Fail criteria:* any content decryptable; any successful silent key substitution in the drill.

**AT-026: Seize backups.**
- The union of AT-020/AT-021 metadata as of each backup time (ciphertext, padded sizes, day-granularity dates), plus backup-catalog metadata (backup time and size of the backup set, not per-source).
- No case keys (wrapped only to members/quorum, ADR-025), no epoch private keys, no recipient private keys.
- The onion service private key is **not** present in plaintext. If 19 includes it, it is encrypted to the offline recovery key.
- Cases crypto-erased before the backup was taken, or whose keys were destroyed afterwards, remain unreadable even with all member devices (ADR-025).
- *Fail criteria:* any key material usable without member devices; any source-linked exact time/size/name in catalog metadata (REQ-H-55).

**AT-027: Steal admin credential.**
- System configuration, staff directory, SECURITY/SYSTEM audit events, and health data.
- **No case content:** admins hold no case keys (ADR-015).
- DANGEROUS/anonymity-affecting changes (enable C-38 clearnet intake, raise logging, enable recovery quorum, add SIEM fields) stay **pending** until a second admin approves (ST-078), and generate notifications to all channel members. Changes visible to sources (for example escrow ENABLED) are published in the key directory.
- An admin can create staff accounts but cannot grant access to existing cases without a channel/case member's client wrapping keys (ADR-015). A newly added recipient appears in the key directory and in member clients (ST-093).
- *Fail criteria:* any content access; any DANGEROUS change applied by one credential; any silent recipient addition.

**AT-028: Steal recipient device.**
- (a) Powered off / locked, no token: encrypted Desk store only; no case keys usable (hardware-bound wrapping, ADR-007). CE software-passphrase fallback: offline guessing of that passphrase is possible (warned configuration; drill reports guessing cost per 04 parameters).
- (b) Token but no PIN: the token's PIN retry limit applies; nothing else learned.
- (c) Unlocked with token + PIN: that member's currently authorized cases (ACL-bounded), not other cases, not sealed identities unless the member is an Identity Custodian.
- Revocation per 15/04 removes the device's future access. Content already decrypted on the device is exposed (residual).
- *Fail criteria:* access beyond the member's ACL; keys usable in state (a) with hardware binding.

**AT-029: Malicious update.**
- (a) One targets key: rejected (threshold 2-of-3).
- (b) Distribution server: rejected. The effect is only DoS or freeze, bounded by timestamp expiry (1 day).
- (c) Threshold compromised together with both builders or reviewed source: accepted, but **logged in the public transparency log, identical for all instances**, and visible to monitors within the monitor interval. A 72-h cooling window applies to normal releases (28 SCM-045).
- (d) Per-instance targeted update: impossible without a second target hash for the same version, which monitors flag (SCM-050). Clients refuse artefacts without inclusion proofs.
- *Fail criteria:* (a), (b) or (d) installs; (c) installs without a log entry.

**AT-030: Compromise monitor host.** Secrets on C-25 match its manifest (no onion client-auth keys, no DB credentials beyond read-only health, per ADR-028). There is no path to content, and logs contain no source data (AT-003..AT-016).

**AT-031: Hosting-provider snapshot.** Same as AT-024 at the snapshot instant: in-flight Tier W plaintext and passphrases of sources active at that instant may be in RAM. Historical envelopes cannot be decrypted. It is documented that PRIVATE-CLOUD/MANAGED profiles carry this provider-observer risk (ADR-024).

**AT-032: Compelled/compromised vendor.** Fleet Manager stores opaque instance IDs and health aggregates only. It holds no onion addresses in cleartext, no content, no keys and no source metadata. Support systems receive only scrubbed bundles (AT-013). The licensing service is offline-file based, with no phone-home (C-35).

## 7. Timing and size leak tests (AT-040..AT-048)

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| AT-040 | Timestamp granularity | All source-linked columns in C-08/C-12 are `date`/epoch-day typed; `track_commit_timestamp = off`; blob files' mtime/atime normalized to 00:00 UTC of epoch day (and `noatime`); no application-level exact time for source actions; M-TIME scan across all sinks finds no sub-day timestamp in [T−600 s, T+600 s] attributable to source actions | Schema introspection; PG settings check; `stat` on blobs; M-TIME scan | PR (schema), nightly, RC | Yes |
| AT-041 | Identifier and ordering leaks | Object IDs are random (UUIDv4, no time component); no sequence-based IDs on source-linked tables exposed to staff or APIs; batch numbers are the only ordering exposed; document the residual of physical row order/ctime | ID entropy test; schema lint; API response inspection | PR (schema), RC | Yes |
| AT-042 | Response-equivalence timing | Wrong passphrase vs unknown account vs locked: identical status, body size class and timing distribution (KS-test p > 0.01 over 10,000 samples; median difference < 5 ms); submission acceptance latency independent of content beyond bucket | Lab timing harness at C-06 (loopback) and over chutney | Weekly, RC | Yes |
| AT-043 | Notification timing decorrelation | Notification sends occur only at digest slots (default hourly) ± configured jitter, never per submission; the send time distribution is independent of submission times within the slot (χ² p > 0.01) (ADR-017) | 1,000 randomized submissions in accelerated clock; SMTP capture | Weekly, RC | Yes |
| AT-044 | Message padding | All message ciphertexts at rest and in transit are 4 KiB-bucketed (max 64 KiB); replies from staff padded identically | Size census of stored envelopes vs plaintext sizes | Nightly, RC | Yes |
| AT-045 | Attachment padding | Stored attachment sizes fall only on the geometric bucket series (ratio 1.25, min 256 KiB); chunk counts do not reveal exact size | Census over synthetic sizes 1 B..2 GiB | Nightly, RC | Yes |
| AT-046 | Source web response size classes | Source web responses fall in the documented size classes (11) per page type; the onion-side transfer size (cells) for "has reply" vs "no reply" is indistinguishable per 11's design | HTTP-layer size census; tor cell counting at client in chutney | Weekly, RC | Yes |
| AT-047 | No last-seen / read receipts / presence | Source login and reply reading change **no** persistent state (DB diff before/after = empty, or only the documented allowed change such as reply deletion at a batch-aligned time) | DB diff harness | Nightly, RC | Yes |
| AT-048 | Relay pull randomization | C-09 pull intervals follow 15 ± 10 min uniform randomization independent of queue length (no "pull sooner when busy") | 7-day accelerated trace; distribution tests | Weekly, RC | Yes |

## 8. Fingerprinting and third-party request tests (AT-050..AT-058)

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| AT-050 | Safest-mode completeness | Every source journey J1–J9 completes in Tor Browser at "Safest" (JS disabled) (ADR-003/004; REQ-H-27) | tbselenium automation at Safest | PR (source UI), nightly, RC | Yes |
| AT-051 | Cookies and storage | At most one cookie (the session cookie defined in 11) with `HttpOnly; Secure; SameSite=Strict; Path=/`, no `Expires`/`Max-Age`; none before first state-changing form; no localStorage/sessionStorage/IndexedDB/Cache API/Service Worker registration/`window.name` use; no HSTS/ETag/Last-Modified-based identifiers | Browser storage inspection after each journey; header inspection | PR (source UI), nightly, RC | Yes |
| AT-052 | No external requests (network capture) | During all source journeys, every Tor stream opened by the client targets **only** the Candor onion address; zero DNS lookups; zero requests to any other origin (fonts, images, CSS, scripts, OCSP, favicons); same for C-03 (INC-46, INC-53) | tor control-port `STREAM` event log at the client + browser request log + packet capture on client netns | PR (source UI), nightly, RC | Yes |
| AT-053 | No fingerprinting surfaces | Tier W pages contain zero `<script>`; CSP `script-src 'none'` (Tier W) / hash-pinned bundle (Tier V); no web fonts; no canvas/WebGL/Audio usage in Tier V bundle; static resource URLs identical across sessions (no per-user unique URLs); no server-side UA branching (ADR-003) | HTML/CSP inspection; two-session URL-set diff; bundle static analysis | PR (source UI), RC | Yes |
| AT-054 | Caching and headers | `Cache-Control: no-store` on all dynamic pages; `Referrer-Policy: no-referrer`; no `Server`/version headers; no `Onion-Location` loops; identical header set for all users | Header golden test (shared with ST-074) | Nightly, RC | Yes |
| AT-055 | Source device residue | Journeys create no downloads and no files in the TB profile beyond TB defaults; the passphrase page offers no download/print; the Source App leaves only documented state (none by default) after exit (REQ-H-23; THR-048) | Profile-dir diff; app data-dir diff | Nightly, RC | Yes |
| AT-056 | Clearnet information site (C-37) | No analytics/trackers/third-party origins; no cookies; the Tor-exit check is in-memory with no logging; no submission form for anonymous mode (ADR-002/003; REQ-H-53/54) | Crawler + capture; config inspection | Nightly, RC | Yes |
| AT-057 | Source App network and platform leaks | C-03 contacts only Tor (embedded Arti) and the TUF update endpoint via Tor; no push SDK/entitlements, no analytics, no crash reporter, no clipboard reads, screenshots disabled on sensitive screens, no OS backup of app data (REQ-H-57) | Emulator/device capture; static checks (ST-014) | Nightly, RC | Yes |
| AT-058 | Onion service configuration audit | No `HiddenServiceNonAnonymousMode`, no mod_status-like endpoints, no hostnames/IPs in errors or headers; `HiddenServicePoWDefensesEnabled 1`; vanguards per profile; backend bound to Unix socket (INC-33, INC-34; REQ-H-33/34) | Config audit + probing over Tor | Nightly, RC | Yes |

## 9. Mode confusion, notifications, telemetry and aggregates (AT-060..AT-068)

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| AT-060 | Mode-confusion usability test | Participants correctly identify their mode (ANONYMOUS / CONFIDENTIAL / IDENTIFIED) and what it means: ≥95% correct mode identification; ≤5% (target 0) of CONFIDENTIAL-condition participants believe they are anonymous (THR-040) | Moderated study per §10 (short protocol, n ≥ 20 per round) | Each change to mode UI; each major | Yes (SG-24) |
| AT-061 | Mode labelling automation | Every C-38 page shows "NOT ANONYMOUS" in the fixed banner position; anonymous-mode pages request no identity fields; voluntary identity disclosure shows the conversion warning before submit (ADR-002/014) | Crawler with DOM assertions in all locales | PR (source UI), nightly | Yes |
| AT-062 | Notification content | Every notification (email, Matrix, webhook) body and subject equal the fixed template byte-for-byte except the instance label; headers carry no case ID, count, channel or time of submission; Message-ID/boundary values random (ADR-017; REQ-H-25) | mailpit/Matrix/webhook capture; template diff | Nightly, RC | Yes |
| AT-063 | Telemetry-off verification | On a default install of every profile, 72 h of full egress capture from all hosts shows only: tor network traffic, configured NTP, and (if auto-update enabled) update fetches via the configured path; zero other destinations; zero DNS lookups except configured NTP/update names (ADR-023) | Egress capture at lab gateway; DNS log | RC (72 h), nightly (6 h) | Yes |
| AT-064 | Telemetry-on schema conformance | When telemetry is enabled, every payload validates strictly against the TEL schema (24), is viewable locally before sending, and contains no identifiers, onion addresses or source-linked counts below threshold | Capture + schema validation | Nightly (EE), RC | Yes |
| AT-065 | Aggregate k-threshold | All dashboards, statistics, exports and transparency reports suppress cells with count < k (k per 03; test at configured and minimum-allowed k); published statistics have ≤ monthly time granularity (REQ-H-70/74; INC-74) | Generated datasets with small cells; inspection of every aggregate endpoint | Nightly, RC | Yes |
| AT-066 | Differencing attacks on aggregates | Overlapping/complementary queries (different filters, time windows, before/after one submission) cannot reveal a suppressed cell or a single submission's attributes | Automated differencing attack script over all aggregate endpoints | Weekly, RC | Yes |
| AT-067 | Audit records not source-identifying | CASE/SECURITY audit events contain no field enabling identification of a source (no source key fingerprint, no exact submission time, no file names) (THR-038) | Schema review + canary scan of S16 | Nightly, RC | Yes |
| AT-068 | Sealed identity isolation | Identity voluntarily disclosed in CONFIDENTIAL mode never appears in case views, exports, search indexes, notifications or logs; unsealing requires dual approval and records legal basis (ADR-014) | Canary identity + full sink scan; unseal scenario | Nightly, RC | Yes |

## 10. Usability-security study programme (AT-070..AT-075)

### 10.1 Rationale
Most deanonymizations in R3 were human and process failures (INC-16, INC-21, INC-31, INC-32). A secure design that users misunderstand fails in practice. The studies measure whether real user groups can use Candor safely.

### 10.2 Ethics and data protection
- Approval by an independent ethics board (IRB or equivalent) before each round.
- Informed consent, and the right to withdraw at any time.
- Only **synthetic misconduct scenarios**. Participants are told never to use real information.
- Lab devices only. Participants never install Candor on their own devices for the study.
- Pseudonymous participant IDs. No video of faces. Screen recordings of lab devices are allowed. Audio recordings are deleted after coding (≤ 30 days).
- Study data retained ≤ 12 months, then deleted. Study data never enters any Candor instance.
- Participants who disclose a real whistleblowing need are given the neutral resources list prepared in advance (05); they are not recruited further.

### 10.3 Participant groups and sample sizes (per round)

| Group | Profile | n (min) | Scenario |
|---|---|---|---|
| G1 Nontechnical whistleblower proxies | Employees without IT roles; mixed age (18–70), ≥30% aged 50+, ≥2 languages (from 26 I18N priorities) | 24 | Report a synthetic fraud anonymously from a "home" laptop; return after 7 and 30 days to read a reply |
| G2 Investigators / compliance officers | Corporate compliance, internal audit, IG investigators | 12 | Triage, investigate, reply, request identity unsealing (ADR-014), export for legal |
| G3 HR case handlers | HR business partners | 8 | Handle a harassment case with COI exclusion |
| G4 Journalists | Newsroom staff receiving tips | 8 | Receive, verify, open evidence in viewer, prepare publication copy |
| G5 Administrators | IT admins | 8 | Install CE-HARDENED, respond to config-checker warnings, run backup/restore, handle a DANGEROUS change request |
| G6 Users of assistive technology | Screen reader users (NVDA, JAWS, VoiceOver, Orca; ≥4), keyboard-only/motor (≥3), low vision/400% zoom (≥3), cognitive/learning disabilities (≥2) | 12 | G1 source scenario (and G2 tasks for ≥4 staff participants) |

### 10.4 Metrics, definitions and pass thresholds

| Metric | Definition | Groups | Pass threshold (per round) |
|---|---|---|---|
| Submission completion | % completing a submission unassisted within 30 min, given Tor Browser pre-installed; reported separately including Tor Browser installation from scratch | G1, G6 | ≥ 90% (pre-installed); ≥ 75% (from scratch); G6 within 10 pp of G1 |
| Security-critical errors (SCE) | % participants committing ≥1 SCE. Source SCEs: entering real name/identifying details in anonymous mode without intent; using the simulated work network/device despite warning; storing passphrase in cloud notes/email/work device; uploading a file after ignoring a metadata warning for a file seeded with identifying metadata; copying the onion address from an untrusted source. Staff SCEs: opening an original outside the viewer; exporting originals without dual approval path; forwarding content to an external channel; sharing credentials; approving a DANGEROUS change without reading the warning | all | Sources ≤ 10%; staff ≤ 5%; **0** SCEs caused by a UI defect (each SCE root-caused as UI vs user) |
| Credential recovery success | % returning participants who log in successfully at T+7 d and T+30 d using the storage method they chose | G1, G6 | ≥ 85% at 7 d; ≥ 75% at 30 d; unsafe storage methods ≤ 10% |
| Misunderstanding of anonymity | 10-item knowledge questionnaire, for example: "the organization can see my IP address" (false, anonymous mode); "my employer's network can see that I used Tor" (true); "document metadata can identify me" (true); "confidential mode is anonymous" (false); "recipients will see the exact time I submitted" (false; date only); "if I lose my passphrase, support can reset it" (false) | G1, G6; staff variant for G2–G4 | ≥ 80% of participants score ≥ 8/10; no single item < 70% correct |
| Mode identification | Same as AT-060 | G1, G6 | ≥ 95% correct; ≤ 5% false-anonymous |
| Unsafe file handling | Source: % uploading files with seeded identifying metadata without using the offered stripping or acknowledging; staff: % of evidence-handling tasks with an unsafe action | G1, G2, G4 | Sources ≤ 15%; staff ≤ 5% of tasks |
| Perceived usability | SUS (Knowledge (unverified) instrument) | all | Mean ≥ 70 |
| Accessibility blockers | WCAG 2.2 AA failures that block task completion (B-CO-28) | G6 | 0 blockers |
| Admin misconfiguration | % G5 participants leaving a DANGEROUS option enabled unintentionally or failing restore | G5 | ≤ 10% and 0 silent failures |

### 10.5 Tests

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| AT-070 | Whistleblower (nontechnical) study | G1 thresholds met for completion, SCE, misunderstanding, unsafe files | Moderated in-person/lab-remote sessions, think-aloud, questionnaire | Before 1.0 GA; each major; any change to source flow (short round n≥12) | Yes (SG-24 when triggered) |
| AT-071 | Investigator / HR / compliance study | G2/G3 SCE and misunderstanding thresholds met; COI and unsealing flows understood | Task-based sessions | Before 1.0; each major; changes to case/export flows | Yes (conditional) |
| AT-072 | Journalist study | G4 evidence-handling SCE thresholds met | Task-based sessions with viewer | Before 1.0; each major | Yes (conditional) |
| AT-073 | Administrator study | G5 misconfiguration thresholds met; config-checker warnings understood | Install/operate tasks | Before 1.0; each major; installer changes | Yes (conditional) |
| AT-074 | Assistive-technology study | G6 parity and zero blockers | Sessions with participants' own AT configurations on lab machines | Before 1.0; each major; UI framework changes | Yes (conditional) |
| AT-075 | Credential recovery longitudinal | Recovery success at 7 d and 30 d | Follow-up sessions | Each G1/G6 round | Yes (conditional) |

Outputs: a published summary report (anonymized, aggregate only, respecting k ≥ 5 per reported cell), a UI-defect list feeding 11/12/13, and updated guidance text (05).

## 11. Frequency and gating summary

| Group | PR | Nightly | Weekly | RC / Release | Per major / trigger |
|---|---|---|---|---|---|
| Canary AT-001..AT-019 | config/log-schema changes run AT-004/AT-007 subset | B (3 profiles) | — | B (8 profiles, max verbosity + DANGEROUS diagnostics) | — |
| Drills AT-020..AT-032 | — | automated subsets of AT-020/021 | — | B (SG-11) | full manual review each major |
| Timing/size AT-040..AT-048 | schema tests | B | B (statistical) | B | — |
| Fingerprinting AT-050..AT-058 | B (source UI changes) | B | — | B | — |
| Mode/notification/telemetry/aggregates AT-060..AT-068 | AT-061 | B | AT-066 | B (AT-063 72 h) | AT-060 per trigger |
| Studies AT-070..AT-075 | — | — | — | SG-24 when triggered | before 1.0 and each major |

B = runs and blocks.

## 12. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| ANT-001 | Every release candidate SHALL pass the canary suite AT-001..AT-019 with zero marker hits outside allowed locations; any hit SHALL block release and SHALL NOT be waivable. | INC-60 (REQ-H-60); ADR-016 | THR-016; THR-001; THR-011; THR-038 | C-06; C-07; C-08; C-09; C-10; C-12; C-23; C-24; C-25; C-26; C-27 | AT-001..AT-019; SG-10 |
| ANT-002 | Canary markers SHALL include network identity (addresses and forwarding headers), User-Agent, Accept-Language, filename, file content incl. EXIF/Office metadata, message and form text, passphrase and derived secrets, session and circuit identifiers, exact action times, exact sizes and client time zone/locale. | INC-03; INC-60; INC-20; ADR-010 | THR-001; THR-006; THR-009; THR-011 | C-06; C-07 | INSP: harness marker manifest; AT-001 |
| ANT-003 | The scanner SHALL search each marker in the encodings and transformations of §4.2, including decompressed containers and unkeyed digests. | INC-60; INC-56 | THR-016 | C-25 | TST: scanner self-test with seeded encodings (must detect 100%) |
| ANT-004 | Each canary run SHALL crawl all hosts for data stores and log streams, and SHALL fail on any store or stream not classified in the sink inventory. | INC-58; B-SD-22 | THR-016; THR-035 | C-05; C-06; C-07; C-08; C-10; C-12; C-24; C-25; C-27 | AT-016; TST: planted unknown log file detected |
| ANT-005 | Canary runs SHALL use signed release-candidate artefacts installed by the real installer and SHALL run at the most verbose non-DANGEROUS settings and separately with each DANGEROUS diagnostic flag. | B-GL-39; B-GL-04 | THR-035; THR-016 | C-19; C-25 | INSP: run manifest; AT-001 |
| ANT-006 | The source path SHALL have no access logs; C-06 SHALL receive connections only over a Unix socket or loopback from tor, verified in each run. | INC-33; INC-34; REQ-H-33 | THR-001 | C-05; C-06 | AT-004; AT-058 |
| ANT-007 | Failure paths (crash, DB outage, disk full, malformed input, relay and notification failures) SHALL be included in canary runs. | INC-58; INC-60 | THR-016 | C-06; C-07; C-09; C-23 | AT-018; AT-011 |
| ANT-008 | Recipient-side sinks (Desk data, OS logs, thumbnails, recent-files, clipboard history, viewer residue) SHALL be scanned on Linux each night and on all supported OSs per release. | INC-16; REQ-H-16 | THR-041; THR-016 | C-15; C-16; C-17 | AT-019 |
| ANT-009 | Compromise drills AT-020..AT-032 SHALL be executed for every release candidate against a seeded 90-day synthetic history, producing a machine-readable learned inventory. | REQ-H-06; INC-55 | THR-014; THR-015; THR-016; THR-017; THR-018; THR-025; THR-027; THR-030; THR-031; THR-034 | C-08; C-12; C-13; C-24; C-26; C-27; C-15; C-19; C-32; C-34 | AT-020..AT-032; SG-11 |
| ANT-010 | A release SHALL NOT ship if any drill's learned inventory exceeds the expected answers in §6.3 or the disclosure inventory in 03. | REQ-H-06; REQ-H-12 | THR-015; THR-026 | C-08; C-12 | AT-020..AT-032; INSP: inventory diff |
| ANT-011 | Any approved expansion of learned data SHALL be reflected in 03's disclosure inventory and in source-facing guidance before release. | REQ-H-12; INC-03 | THR-040; THR-026 | C-06; C-37 | INSP: guidance diff review |
| ANT-012 | A summary of drill results (per drill: PASS/FAIL and learned categories) SHALL be published with each major and minor release. | REQ-H-06; B-CO-54 | THR-026 | C-37 | INSP: release page |
| ANT-013 | The intake-server compromise drill SHALL explicitly verify that envelopes sealed before the compromise window are not decryptable with anything present on Z-INTAKE. | ADR-008; INC-02 | THR-014 | C-05; C-06; C-07; C-08 | AT-024 |
| ANT-014 | The backup-seizure drill SHALL verify absence of usable key material and of source-linked exact times, sizes or names in backup catalogs, and SHALL verify crypto-erased cases remain unreadable. | INC-55 (REQ-H-55); ADR-025 | THR-017; THR-031 | C-27 | AT-026; AT-012 |
| ANT-015 | The malicious-update drill SHALL verify rejection of single-key, distribution-server and targeted updates, and logging of threshold-signed updates. | INC-49; INC-14; ADR-022 | THR-025; THR-046 | C-32; C-33 | AT-029; ST-130 |
| ANT-016 | Source-linked timestamps SHALL be verified to be day-granular in all stores, with `track_commit_timestamp` off and blob mtimes normalized. | ADR-010; INC-16 | THR-011 | C-08; C-12; C-13 | AT-040 |
| ANT-017 | Authentication failure modes on the source path SHALL be verified indistinguishable in status, size class and timing. | ADR-005 | THR-034; THR-011 | C-06; C-07 | AT-042 |
| ANT-018 | Notification send times SHALL be verified statistically independent of submission times within digest slots, and notification content SHALL match the fixed template. | ADR-017; INC-57; REQ-H-25 | THR-028; THR-011 | C-23 | AT-043; AT-062 |
| ANT-019 | Message and attachment padding and source web response size classes SHALL be verified by census tests each release. | ADR-011; B-AN-14 | THR-004; THR-011 | C-06; C-07; C-11 | AT-044; AT-045; AT-046 |
| ANT-020 | Source reading of replies and logins SHALL be verified to change no persistent state beyond documented allowed changes. | ADR-010 | THR-011 | C-06; C-08 | AT-047 |
| ANT-021 | Every source journey SHALL be verified to complete in Tor Browser at Safest (no JavaScript). | REQ-H-27; ADR-003 | THR-008; THR-006 | C-06 | AT-050 |
| ANT-022 | Source UI SHALL be verified to set at most the single session cookie with the attributes in AT-051 and to use no web storage, service workers or cache-based identifiers. | REQ-H-27; B-AN-14 | THR-006 | C-06 | AT-051; AT-053 |
| ANT-023 | Network capture during full source flows SHALL show connections only to the Candor onion service and zero DNS lookups, for web and Source App clients. | INC-46; INC-53 (REQ-H-46, REQ-H-53) | THR-036; THR-001 | C-02; C-03; C-06 | AT-052; AT-057 |
| ANT-024 | Default installs SHALL be verified to emit no telemetry over a 72-hour capture per release, and enabled telemetry SHALL be verified against the TEL schema. | ADR-023; INC-53 | THR-036 | C-25; C-35 | AT-063; AT-064 |
| ANT-025 | All aggregate outputs SHALL be verified against k-threshold suppression and differencing attacks each release. | REQ-H-70; REQ-H-74; INC-74 | THR-039 | C-10; C-19; C-26 | AT-065; AT-066 |
| ANT-026 | Mode labelling SHALL be verified automatically on every page and locale, and mode comprehension SHALL be verified by user study with ≥95% correct identification. | ADR-002; INC-03 | THR-040 | C-06; C-38 | AT-061; AT-060 |
| ANT-027 | The usability-security study programme in §10 SHALL run before 1.0 GA and for each major release, with the listed groups, ethics safeguards and pass thresholds; failed thresholds SHALL block release when the corresponding flows changed. | INC-16; INC-21; INC-31; INC-32 | THR-040; THR-041; THR-034; THR-048 | C-06; C-15; C-19 | AT-070..AT-075; SG-24 |
| ANT-028 | Study rounds SHALL include users of assistive technology and SHALL achieve zero WCAG 2.2 AA completion blockers and completion within 10 percentage points of non-AT participants. | B-CO-28; B-CO-36 | THR-040; THR-034 | C-06; C-15 | AT-074 |
| ANT-029 | Study data SHALL use synthetic scenarios only, pseudonymous IDs, no face video, deletion of audio within 30 days and of all study data within 12 months. | B-CO-09 | THR-015 | C-30 | INSP: ethics approval and data-deletion records |
| ANT-030 | Sealed identity data SHALL be verified absent from all case views, exports, indexes, notifications and logs in every release. | ADR-014 | THR-018; THR-019; THR-020 | C-10; C-12; C-15 | AT-068 |
| ANT-031 | The Source App SHALL be verified to use no push services, analytics or crash reporters and to leave no undocumented on-device state. | INC-57 (REQ-H-57); REQ-H-23 | THR-028; THR-036; THR-048 | C-03 | AT-057; AT-055 |
| ANT-032 | New data flows introduced by features SHALL add markers and sinks to the canary harness in the same PR (via the feature threat model, 27 §10.2). | INC-60 | THR-016 | C-30 | INSP: PR review; TST: sink-list lint compares 20 schema to harness inventory |

## 13. Residual risks and limitations

- **Keyed or derived leaks** (HMACs, embeddings, aggregates of source attributes) cannot be found by marker scanning. They are prevented by schema review (20) and by typed-log lints (27), not by this suite.
- **Physical ordering and filesystem metadata.** Row order in heap files, WAL LSNs, inode numbers and filesystem ctime on C-08 may reveal the order and approximate time of writes to an adversary with raw disk access. Normalizing mtime does not normalize ctime. Deleting pulled envelopes from intake shrinks the exposure window but does not remove it. A future batching/"write-at-slot" design (write only at fixed slots) could reduce this; see open issues.
- **Import time bounds submission time.** Staff import events give an upper bound on submission time (AT-021/AT-022/AT-023). The day-granularity guarantee holds for **what recipients are shown and what source-linked records store**, not for inference from staff activity.
- **Tier W live compromise** exposes the passphrases of sources who log in during the window, and therefore those sources' historical reply threads (AT-024). This follows from ADR-004/005 and is disclosed. Tier V avoids it.
- **Network-level adversaries** (THR-002/003/004) are out of scope for server-side sinks. AT-046 checks only application-layer size classes. Traffic correlation between the source's link and the onion service is not tested and cannot be prevented by Candor (R4).
- **Lab vs real Tor.** chutney does not reproduce guard selection, the real anonymity set, or the timing of the real network.
- **Studies** use proxies for real whistleblowers, who are under stress and at higher risk. Thresholds are design targets, not guarantees, and sample sizes are small by design.
- **Operator-added infrastructure** (their own reverse proxies, EDR agents, backup software, hypervisor logging) is outside what Candor ships. The config checker and 32 guidance warn about it, but the canary suite cannot scan unknown third-party systems at customer sites.

## 14. Open issues

1. Decide whether C-08 should write envelopes only at fixed time slots (for example every 30 min) to remove ctime/order inference. This needs an ADR amendment to ADR-010 if adopted.
2. Obtain the final k parameter and aggregate schema from 03/20 to finalize AT-065/066 fixtures.
3. Obtain from 11 the exact source web response size classes and session-cookie specification, and align AT-046/AT-051 fixtures.
4. Define a customer-runnable "canary self-check" mode (limited to Candor-shipped sinks) so that operators can re-run AT-001 against their own deployment, including their own added agents. The mode must itself generate no persistent records.
5. Recruitment channels for G1/G6 in multiple jurisdictions, and budget (coordinate with 26 and 38).

### Open Issues for ADR revision
- **ADR-010** says intake records only `received_epoch_day` and a batch number. Physical storage ordering (heap/WAL/ctime) can still reveal intra-day order and approximate time to a raw-disk adversary. I propose an ADR-010 amendment that either (a) adopts slot-based batched writes at the intake, or (b) explicitly documents this residual as accepted. This document conforms to ADR-010 as written and lists the residual in §13.
- **ADR-005/ADR-004:** the consequence that a returning Tier W source's historical replies become readable during a live intake compromise is implied but not stated. I recommend adding it to ADR-004's SECURITY EFFECT for honesty.
