# IMPL-RM2 — Intake zone (Tier W): gateway, source web, sealer, intake store

Status: Draft v1.0 · Edition applicability: both · Owner: T2 Intake (sealer key paths with T1) · Standard: `IMPL-00-SECURE-IMPLEMENTATION-STANDARD.md`

## 1. Purpose and scope

| Item | Content |
|---|---|
| Milestone | RM-2 (`38` §4): Intake Gateway torrc, Source Web Service (no-JS), Intake Sealer isolation, Intake Store, PoW and rate limits, source passphrase flow, drafts in RAM, reply fetch |
| Components | C-05 Intake Gateway (tor, host network) · C-06 Source Web Service (`candor-web`) · C-07 Intake Sealer (`candor-sealer`) · C-08 Intake Store (`candor-intake-store`, intake PostgreSQL, blob dir, tmpfs staging, relay export endpoint) |
| Specs implemented | 06 (zones, flows) · 07 §4 (process model, systemd, seccomp, no-dump), §5.1–§5.3 (web, sealer IPC, chaff, store), §8–§13 · 08 §3 (conventions, CSRF, padding, headers), §4 (Source Web), §6 (relay endpoint, intake side) · 09 §5.1 (intake schema), §8 (time rules), §10 (hardening) · 11 §5–§7 (page contract, sessions, flows S01–S13) · 16 §7 (torrc), §13 (DoS), §14 (no-clearnet enforcement, independent time) · 20 §6.2, §11.1–§11.4 (zone and host logging) · ADR-001..005, -009..-011, -026, -029, -034, -035, -036(6), -038, -039, -046(7), -047(3)(4)(6)(9) |
| Not in scope | Tier V / Source App API (RM-8; the store keeps the `UPLOAD_*` ops behind a disabled feature), relay **client** (RM-3), installers (RM-5) |

## 2. Preconditions

| # | Precondition |
|---|---|
| P1 | RM-1 exit: `candor-core` formats frozen, `kd` verifier, `candor-safefs`, `candor-log`, `candor-limits`, `candor-time`, `candor-memlock` audited (IMP-RM1-016) |
| P2 | `anon-marker-scan` (AT-001) required in CI (RM-002) |
| P3 | Interfaces published by their owners (BUILD-BRIEF RM-2 addendum): `candor-sealer::proto` (types and codec, usable without the `server` feature) and the `candor-intake-store` `IntakeStore` trait. Consumers depend on the trait only |
| P4 | Feature threat models approved: `RM2-tierw-session`, `RM2-sealer`, `RM2-store`, `RM2-gateway` (27 §10; inferential analysis 5a for every time-, count- and membership-bearing value) |
| P5 | Test PostgreSQL 16 available via `CANDOR_TEST_PG` (non-root `pgtest` user). Tests skip cleanly without it |
| P6 | Current partial code: `candor-sealer` (`proto/cbor.rs`, `server/`) and `candor-intake-store` (in-memory store, dead-drop, deletion list, validation) have **no README/SPEC-NOTES and no tests yet** → they must be brought to IMPL-00 §14 before further code lands |

**Spec-over-research resolutions for this step:** cookie `__Host-cs` with the server holding only `SHA-256(HKDF(cs))` in sealer RAM (11 §5.6; SI-C-01 would store `HMAC(token)`). `Origin` absent/`null`/exact-onion accepted (08 §3.7; SI-C-02 would reject `null`). The Candor tightening adds: reject `Sec-Fetch-Site` ∈ {`cross-site`, `same-site`} on POST. Idle timeout 20 min (11 §5.6). Size classes P1/P2 only (08 §3.8).

## 3. Build sequence

### 2.1 Intake host network baseline and tor (C-05)
- **Build:** managed `deploy/intake/torrc` per 16 §7.1: v3 onion, `HiddenServicePort 80 unix:/run/candor/web.sock`, PoW on (`pow: yes`, GPL build), intro DoS defence, `HiddenServiceMaxStreams` + `CloseCircuit 1`, `HiddenServiceExportCircuitID haproxy` on a second listener, `SocksPort 0` except the update and Roughtime client, control port as a unix socket with cookie auth only, minimal `Log` (no client or circuit data), `Sandbox 1`. nftables: egress only for the `debian-tor` uid, relay link 7443 only from the core IP. No DNS resolver (or tor `DNSPort` only), no NTP to public pools, apt over `tor+https`, no clearnet SSH. AppArmor enforce profile for tor. Full vanguards on HIGH profiles (16 §7.2).
- **Rules:** SI-D-01, SI-D-02, SI-D-03, SI-D-04, SI-B-04. ADR-001, ADR-002, ADR-026, ADR-032. 16 §14.2. 07 §12 independent time.
- **Pitfalls:** INC-33 (Silk Road real-IP leak through a misconfigured service) and INC-34 (OnionScan: `mod_status`, co-hosted clearnet) → no clearnet route and no co-hosting. INC-35 (guard discovery) → vanguards. INC-29/INC-30 (malicious relays) → vanguards, no relay mode. An Arti service with experimental PoW (R7) → C tor only.
- **Verify:** `tor --verify-config` and the 16 §7.4 lint in CI. `tor --list-modules | grep 'pow: yes'`. ST-122 host network baseline. A namespace `tcpdump` during the full suite and an apt upgrade shows only tor ORPort traffic (SI-D-03). AT-005 (tor logs), AT-058 (onion config audit).

### 2.2 Process skeleton, units and confinement (all intake daemons)
- **Build:** sysusers (`candor-web`, `candor-sealer`, `candor-istore`), tmpfiles (`/run/candor/<svc>` 0750, group = the single permitted peer; `/run/candor/staging` tmpfs `mode=0700,nosuid,nodev,noexec,size=…`), systemd units from the 07 §4.2 baseline (`candor-web`: `RestrictAddressFamilies=AF_UNIX`; `candor-sealer`: `PrivateNetwork=yes`, `MemoryDenyWriteExecute`, `LimitMEMLOCK`; `candor-istore`: AF_UNIX + relay TCP only). Per-role seccomp JSON (07 §4.3) installed after init. Landlock ABI ≥ 6 HardRequirement in production. `PR_SET_DUMPABLE=0`. Panic hook per IMPL-00 §4.4. Swap disabled. journald volatile (20 §11.3). Host sysctls per SI-B-06.
- **Rules:** SI-B-01..SI-B-06. IMP-STD-007, IMP-STD-013, IMP-STD-024. 07 §4.1–§4.5.
- **Pitfalls:** INC-106 (onion client-auth keys copied to the wrong host) → Secret Placement Manifest (ADR-028). Services sharing a UID. `DynamicUser` for a stateful service.
- **Verify:** `systemd-analyze security --offline=true` ≤ 1.5 for each intake unit. Negative seccomp tests (SIGSYS on `execve`, `socket(AF_INET)` in sealer/web, `ptrace`). Landlock EACCES tests. ST-110 core-dump prohibition. ST-121 secret placement. AT-006 (journald/kernel/conntrack), AT-011 (crash dumps).

### 2.3 Sealer IPC protocol (`candor-sealer::proto`, T1; T0 for key-bearing fields)
- **Build:** frame `{v, op, rid, body}` as deterministic CBOR with a strict decoder (unknown op, extra or duplicate key, indefinite length, trailing bytes → `BAD_FRAME` + close). Typed request/response structs per op from the 07 §5.2 table, with per-field limits from `candor-limits` (datagram ≤ 128 KiB, `DRAFT_SET` ≤ 96 KiB, passphrase ≤ 256 B, `OPEN_REPLIES` ≤ 64 × 70,000 B). Error enum = the 07 §5.2 codes only. Matching `istore` protocol types (07 §5.3) in the store crate.
- **Rules:** IMPL-00 §8 (all items). SI-B-05. IMP-STD-009.
- **Pitfalls:** serde self-describing formats accepting unknown or duplicate fields. Length-prefix truncation (RUSTSEC-2024-0363 class). Echoing input in errors.
- **Verify:** round-trip proptest (parse ∘ encode = id; canonical uniqueness). A negative corpus (each malformation → `BAD_FRAME`). A new fuzz target `fuzz_sealer_ipc` (registered as an ST-043 sub-target). Kani on length arithmetic.

### 2.4 Intake Sealer server (C-07, T0)
- **Build:** a `SO_PEERCRED` uid check on accept (ST-097). A session table keyed by `SHA-256(HKDF(cs,"candor/src/handle"))`, an explicit state-machine enum (07 §5.2), and deadlines on the **monotonic** clock (20 min idle / 2 h absolute). Drafts, identity block, COI ticks and `K_sp`/`K_att` only in mlocked RAM (ADR-034). `GEN_ACCOUNT` at S09 only. `CONFIRM_PASSPHRASE` constant-time with 3 random positions, zeroizing after 5 failures. `LOGIN_DERIVE`: Argon2id via a semaphore (4 active / 32 queued / 30 s) on `spawn_blocking`. `SEAL_FINISH` is the **only** step that wraps to recipients: it computes the eligible set from the **verified** snapshot now (Triage Set − source ticks − COI map; `effective_day` ≤ today; MEK valid today) and refuses with `NO_ELIGIBLE_TRIAGE`. Snapshot freshness ≤ 7 days by independent time (ADR-047(4)). `OPEN_REPLIES` returns plaintext only for immediate rendering. The chaff generator (07 §5.2a) uses a Poisson schedule in RAM, the same C-11 code path as real envelopes, and cancellation on real commits. Worker recycling after N sessions. `mlockall`. No network.
- **Rules:** SI-A-05, SI-A-06, SI-B-05, SL-R-003. ADR-034, ADR-036(2)(4)(6), ADR-037, ADR-046(7), ADR-047(3)(4)(6). IMP-STD-006, IMP-STD-007, IMP-STD-011.
- **Pitfalls:** RVW-A-07 (sealing before the recipient set is fixed) → `SEAL_BEGIN` withdrawn and ST-144. INC-SL-04 (snapshot entries used by ID after verification). Passphrase string kept after S10 (must be zeroized right after rendering). The KDF run only on the "known account" path → a timing oracle (R9 §6.6). Chaff that differs from real envelopes in code path, size distribution or commit peer.
- **Verify:** ST-143 (RAM-only drafts, tmpfs cleanup), ST-144 (seal only after the set is fixed), ST-145 (passphrase never persisted; confirm before finalize), ST-146/147 (triage-first, blinded COI at seal), ST-148 (follow-up sealing rule), ST-168 (chaff format identity), ST-172 (snapshot freshness), ST-177 (per-locale wordlists), ST-053 `fuzz_passphrase_input`, ST-027 (memory scan after `ZEROIZE`), AT-076 (draft and passphrase residue), AT-087 (chaff indistinguishability), AT-093 (stale-directory fail-closed indistinguishability), AT-094 (confirmation loss).

### 2.5 Intake Store (C-08, T1)
- **Build:** `IntakeStore` trait implementations (in-memory for tests, PostgreSQL for production). Intake schema per 09 §5.1 (date-only columns, no IP/UA, random 128-bit IDs, `received_date`/`release_day` as `EpochDay`). PG over a unix socket only, `peer` auth, app role not owner, no `BYPASSRLS` (SI-E-01/02; single tenant DB, so no RLS needed per 09 §5.1). `log_statement='none'`, no bind values logged, `log_line_prefix` without `%h`/`%r`, `pg_stat_statements` off (SI-E-04). `sqlx::query!` only (SI-E-05). Forward-only migrations via `candorctl migrate` (SI-E-06). Staging writes via safefs `RootPolicy::Staging`. `COMMIT_ENVELOPE` ordering: blobs fsynced → rows → dir entries → `ok` (ADR-046(1)). Blob mtime = 00:00 UTC of `received_date`. Uniform `ACCOUNT_AUTH_CHALLENGE` for unknown locators, with constant-time verify. Mailbox ops each append a K31-signed deletion-list entry in the same transaction (ADR-047(9)). Fetch-all reply set: 64 entries × 70,000 B per page, page count padded to a power of two, rebuilt only at slot times (ADR-039). Relay export endpoint: rustls TLS 1.3 on the relay interface, client-cert SPKI pin, Ed25519 request signatures with a strictly increasing persisted counter (07 §5.4). Routing key via `LoadCredentialEncrypted=`. Chaff and real commits are written identically, with nothing recording the peer.
- **Rules:** SI-E-01..SI-E-06, SL-R-001, IMP-STD-010, IMP-STD-023. ADR-009, ADR-010, ADR-038, ADR-039, ADR-047(9).
- **Pitfalls:** RUSTSEC-2024-0363 (sqlx < 0.8.1). PostgreSQL WAL and page residue revealing order or time (AT-007, AT-020). Sequential IDs and `now()` defaults in the schema. INC-11 (exposed database) → unix socket only. Showing "received" before the fsync. A unique-constraint existence oracle on `locator_hash`.
- **Verify:** ST-083 (no plaintext at rest in intake), ST-102/103 (DB corruption, power loss mid-commit), ST-174 (deletion list across DR), schema lint (09 §8: no `timestamptz` on intake), AT-007 (DB incl. WAL), AT-016 (filesystem and raw-disk sweep), AT-020 (intake DB compromise drill), AT-041 (ID ordering), AT-042 (uniform challenge timing), AT-077, AT-078 (fetch-all indistinguishability). PG integration tests gated by `CANDOR_TEST_PG`.

### 2.6 Source Web Service (C-06, T1)
- **Build:** hyper `http1` only on `unix:/run/candor/web.sock` (no reverse proxy, no HTTP/2, no compression). Header read 10 s, body idle 60 s, `max_buf_size` ≤ 64 KiB, `Content-Length`+`Transfer-Encoding` rejected. A route registry with `audience = source-web`, deny-by-default, an authz declaration per route and GET side-effect-free (ADR-029). The single cookie `__Host-cs` (no Max-Age/Expires). CSRF: a 256-bit synchronizer token in the `csrf` field (ADR-051(4)), compared with `subtle`, plus the `Origin` rule (08 §3.7) and the `Sec-Fetch-Site` tightening. Language from the URL path only. Form validation per IMPL-00 §7 (bytes + graphemes, NFC, control characters rejected, 112 KiB body, 64 KiB message). Multipart streamed chunk by chunk to `SEAL_CHUNK` (no filename on disk, no sniffing, nested multipart rejected, per-file and total caps). Responses rendered by `candor-source-ui`, padded to P1/P2, with byte-identical busy and error pages. Login response delayed to `max(elapsed, 3 s) + U(0, 250 ms)` on every outcome (07 §11). Per-circuit rate limits keyed by the PROXY-v2 circuit ID held only in RAM. No access log. A panic maps to a fixed padded 500 page.
- **Rules:** SI-C-01..SI-C-06, SL-R-007. ADR-011, ADR-029, ADR-034, ADR-051(2)(4). IMP-STD-005, IMP-STD-008.
- **Pitfalls:** INC-116 (HTTP pipelining bug in the framework) and hyper smuggling advisories (RUSTSEC-2020-0008, -2021-0020/0078/0079). INC-105 (token reusable across audiences). INC-114 (missing role check on one route). INC-119 / INC-SL-14 (no step-up, missing headers in production). INC-03 (IP logging capability) → none exists. INC-SL-15 (unauthenticated free text forwarded to staff channels). Circuit IDs leaking into logs or persistent maps.
- **Verify:** ST-044 `fuzz_http_request`, ST-054 `fuzz_form_urlencoded`, ST-043 `fuzz_multipart_intake`, ST-065 (audience replay), ST-066 (session lifecycle and timers), ST-071 (CSRF matrix incl. `Sec-Fetch-Site: cross-site`, missing or wrong token), ST-072, ST-073, ST-074 (header golden per route), ST-075 (smuggling corpus), ST-079 (rate limits), ST-082 (upload attacks), ST-101 (slowloris and slow-POST via `slowhttptest` through `socat`), AT-017 (no reflection), AT-018 (failure-path canaries), AT-042 (login timing equivalence), AT-046 (size classes per route × outcome), AT-050 (Tor Browser Safest via tbselenium), AT-051, AT-052, AT-053, AT-054, AT-055.

### 2.7 DoS, PoW and global limits (C-05/C-06/C-07)
- **Build:** the 07 §11 limit table enforced at the stated layer with byte-identical busy pages. Global limits sized to ≥ 10× design peak, so single probes do not reveal other sources' activity (ADR-038(5)). Source-influenced counters leave the host only as a global daily band (BE-073).
- **Rules:** ADR-026, ADR-038(5). SI-C-05, SI-D-01.
- **Pitfalls:** INC-110 (receive-mode DoS). A limit hit visible as a different page size or timing (a side channel on other sources).
- **Verify:** ST-100 intake DoS (PoW solvers vs non-solver flood), ST-109 memory pressure, AT-008 (metrics: bands only).

### 2.8 Source flows end to end (S01–S13, reply fetch, rotation)
- **Build:** the full Tier W flow per 11 §6–§7, including the inbox with exactly `N_fixed = 32` entries (dummies included), S11r rotation (`ROTATE_PASSPHRASE`), S13 delete/abandon (signals sealed before deletion), and the C4 signals with release offsets.
- **Verify:** ST-003 (E2E source → intake), AT-001 (full-flow canary through every sink), AT-044/045 (padding), AT-047 (no presence or read receipts), AT-060/061 hooks (mode banner present on every page), AT-092 (IDENTIFIED-over-onion banner).

### 2.9 Intake self-test and config checker rules
- **Build:** C-25 intake checks (07 §5.11): access logs absent, `core_pattern`, swap off, journald volatile, nft hash, Landlock ABI, `Seccomp: 2`, PoW module, clock sanity versus consensus and Roughtime. Config-checker rules for every new option. DANGEROUS options off by default.
- **Verify:** ST-120 config checker, AT-058, ST-106 clock issues (submissions refused when the clock is insane).

### 2.10 Compromise drills and independent audit
- **Build:** run drills AT-020 (intake DB), AT-024 (root on intake app server) and AT-031 (hypervisor snapshot) and compare the answers to the generated oracle (SG-11). Then the independent audit gate.
- **Verify:** answers ⊆ oracle. `process/audits/AUDIT-RM2-*.md` with 0 open Critical/High.

## 4. Component-specific threat checklist (auditor)

| # | Check | Threat |
|---|---|---|
| A1 | No sink (log, journald, error, panic, metric, DB, WAL, tmpfs, response, HTML comment) contains source IP, UA, Accept-Language, exact time, filename, size, passphrase, codename, circuit ID or body | THR-001, THR-016, THR-011 |
| A2 | No outbound connection other than tor and the relay listener. No DNS, NTP or clearnet fallback on any error path | THR-001, THR-035 |
| A3 | Plaintext exists only in sealer RAM (mlocked), never on disk, tmpfs or in web memory beyond the request buffer. Staged parts are ciphertext under RAM-only keys | THR-014, THR-015 |
| A4 | The recipient set is computed only at `SEAL_FINISH` from a `Verified` snapshot. No wrap is created earlier. Freshness and `effective_day` are enforced | THR-046, THR-020 |
| A5 | Existence oracles: unknown vs known locator, wrong passphrase vs success, mailbox empty vs full, busy vs normal → same size class, same timing floor, same text | THR-034, THR-011 |
| A6 | Every input (HTTP, form, multipart, IPC, relay request) is bounded before allocation. No panic is reachable (fuzz evidence) | THR-032 |
| A7 | Session: one cookie with `__Host-`, `Secure`, `HttpOnly`, `SameSite=Strict`, no expiry. `cs` never stored. New `cs` on login, logout and re-auth. Monotonic deadlines | THR-006, THR-034 |
| A8 | CSRF on every POST. GET side-effect-free. Audience-bound routes. Route registry is complete | THR-021 |
| A9 | Headers and CSP exact. No script. No third-party URL. No compression. No `Server`/version | THR-008, THR-036, THR-004 |
| A10 | IPC: peer uid checked. Strict decoder. Code-only errors. No key-returning op | THR-014, THR-018 |
| A11 | Store: unix-socket PG, no `host` lines in pg_hba, no bind values logged, `query!` only, date-only columns, random IDs, fixed blob mtimes | THR-015, THR-011 |
| A12 | Chaff indistinguishable in format, size, commit path and DB residue. Never counted | THR-011, THR-003 |
| A13 | Fail-closed: snapshot stale, clock insane, staging full, sealer down → busy page, never unsealed storage or a degraded mode | THR-035, THR-014 |
| A14 | systemd exposure ≤ 1.5. Seccomp and Landlock active. Core dumps impossible. ptrace denied | THR-014, THR-030 |
| A15 | Onion key only on the intake host, 0700 tor-owned, on the encrypted volume. Secret placement manifest passes | THR-044 |

## 5. Test plan

| ID | Test | Command / tool |
|---|---|---|
| ST-043/044/053/054 + `fuzz_sealer_ipc` | Fuzz | `cargo +nightly-2026-09-28 fuzz run <t> -- -max_total_time=3600 -rss_limit_mb=2048 -timeout=10` |
| ST-065/066/071..075/079/082 | HTTP security suite | `cargo test -p candor-web --test http_security` |
| ST-075 | Smuggling corpus | `python3 smuggler.py -u http://localhost` via `socat TCP-LISTEN:8080,fork UNIX-CONNECT:/run/candor/web.sock` (pinned) |
| ST-101 | Slow request abuse | `slowhttptest -c 1000 -B -u http://localhost:8080/en/report` (via socat) |
| ST-083/143/145 | Residue: no plaintext or passphrase on disk | `cargo test -p candor-lab --test intake_residue -- --ignored` (raw tmpfs/disk scan) |
| ST-097 | Wrong-uid IPC | `cargo test -p candor-sealer --test peer_uid` (runs as a second user) |
| ST-100 | Intake DoS | `tools/load/pow_flood.sh` (PoW solvers + non-solvers) |
| ST-102/103 | DB corruption, power loss | `CANDOR_TEST_PG=1 cargo test -p candor-intake-store --test crash_consistency` |
| ST-110 | Core dump | `gcore $(pidof candor-sealer)` must fail; `/proc/<pid>/status` checks |
| ST-120/122 | Config checker, host network | `candorctl check --profile ce-single`; namespace `tcpdump -i <uplink>` |
| ST-144/146/147/148/168/172/174/177 | Revision controls | `cargo test -p candor-sealer -p candor-intake-store` |
| AT-001 | Full-flow canary | `make anon-marker-scan PROFILE=ce-single` |
| AT-005/006/007/011/016 | Sink sweeps | candor-lab sink collectors |
| AT-020/024/031 | Drills | `candor-lab drill <id>`, compared to the generated oracle |
| AT-040..042, 044..047 | Timing and size | `cargo test -p candor-lab --test timing_size --release` (t-test on login outcomes; size per route × outcome) |
| AT-050..055 | Browser surface | `pytest tests/tbselenium/` with Tor Browser at Safest |
| AT-076/077/078/087/093/094 | Revision leakage | candor-lab suites |
| Unit hardening | systemd | `systemd-analyze security --offline=true --threshold=15 deploy/intake/systemd/*.service` |

## 6. OPSEC checklist

| Metadata at risk | How prevented |
|---|---|
| Source IP | Never available (unix socket behind tor). No `X-Forwarded-For` parsing. The circuit ID exists only in RAM rate-limit maps with TTL, is never logged and is never a key in persistent state |
| User-Agent, Accept-Language, other headers | Not read except for the CSRF headers. Never logged |
| Exact arrival time | `EpochDay` only. Blob mtime at day start. No `timestamptz` on intake. WAL residue tested by AT-007/020. Delayed delivery and chaff (ADR-038, ADR-047(3)) |
| Size | Message and attachment padding before encryption. P1/P2 page classes. Fixed inbox of 32 entries. Fixed-size reply pages |
| Filename | Encrypted in the manifest only. Never on disk or in logs |
| Passphrase, codename | Sealer RAM only. Zeroized after S10 render or login. Locator is a hash only. No word-by-word comparison |
| Session continuity across visits | Session-only cookie. No persistent identifier. Language in the URL only |
| Activity of other sources | Global limits at ≥ 10× peak, byte-identical busy pages, daily bands only |
| Onion uptime pattern | Continuous service. Randomised maintenance windows (SI-D-03) |
| Server fingerprint | No `Server`/`Date` build info. No version strings. Static assets stripped |
| Staff reaction timing | Out of scope here. Relay import slots (RM-3) decouple intake from core |

## 7. Exit criteria (RM-2 definition of done)

- [ ] AT-001 marker scan: **zero hits in all sinks** (38 RM-2 exit).
- [ ] The no-JS flow passes at Tor Browser "Safest" (AT-050).
- [ ] Malicious-input fuzzing of form, multipart, HTTP, passphrase and sealer-IPC parsers: ≥ 72 h each, 0 crashes (38 RM-2 exit; SG-07).
- [ ] The ST authz suite for the source audience passes (ST-065, ST-066, ST-071; route registry 0 undeclared routes; SG-08 subset).
- [ ] Revision controls ST-143..148, ST-168, ST-172, ST-174, ST-177 pass. Drills AT-020/024/031 ⊆ oracle. Timing and size AT-040..047 pass.
- [ ] Every intake unit has `systemd-analyze security` ≤ 1.5. Seccomp, Landlock and AppArmor enforced in the functional suite.
- [ ] README and SPEC-NOTES complete for `candor-web`, `candor-sealer`, `candor-intake-store`. Independent audits closed (0 open Critical/High).

## 8. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| IMP-RM2-001 | The intake host SHALL have no egress except tor's (nftables uid match), no DNS resolver and no clearnet NTP, and the onion service SHALL forward to a unix socket. | B-SI-29; B-SI-32; INC-33; INC-34 | THR-001; THR-035 | C-05 | TST: ST-122; uplink capture; AT-058 |
| IMP-RM2-002 | tor SHALL be C tor ≥ 0.4.8 with `pow: yes`, intro DoS defence, stream limits and a minimal log configuration, checked by the 16 §7.4 lint. | B-SI-29; B-SI-30; B-SI-31; INC-35 | THR-005; THR-032 | C-05 | TST: torrc lint; `tor --list-modules`; AT-005 |
| IMP-RM2-003 | Each intake daemon SHALL run as its own user with a unit scoring ≤ 1.5, a post-init seccomp allow-list, Landlock ABI ≥ 6 (production) and AppArmor enforce. | B-SI-18; B-SI-19; B-SI-20; B-SI-21; INC-106 | THR-014; THR-030 | C-06; C-07; C-08 | TST: `systemd-analyze security`; SIGSYS/EACCES tests |
| IMP-RM2-004 | The sealer SHALL have no network namespace access, SHALL `mlockall`, set `PR_SET_DUMPABLE=0` and recycle workers, and SHALL never return key material over IPC. | B-SI-04; B-SI-23; ADR-034 | THR-014; THR-013 | C-07 | TST: ST-110; ST-027; IPC op audit |
| IMP-RM2-005 | Sealer and store IPC SHALL use SEQPACKET with `SO_PEERCRED` checks and a strict canonical CBOR decoder that rejects unknown or duplicate keys and oversize fields. | B-SI-24; INC-103; B-AU-04 | THR-014; THR-018 | C-06; C-07; C-08 | TST: ST-097; `fuzz_sealer_ipc` |
| IMP-RM2-006 | Drafts, identity blocks, COI ticks, passphrases and session keys SHALL exist only in sealer RAM with monotonic deadlines (20 min idle / 2 h absolute) and SHALL be zeroized on every exit. | ADR-034; INC-60 | THR-014; THR-034; THR-048 | C-07 | TST: ST-143; ST-145; AT-076 |
| IMP-RM2-007 | Recipient wrapping SHALL occur only in `SEAL_FINISH`, using the eligible set computed from a `Verified` snapshot that is ≤ 7 days old by independent time. | ADR-036; ADR-037; ADR-047; INC-14 | THR-046; THR-020 | C-07 | TST: ST-144; ST-146; ST-147; ST-172; AT-093 |
| IMP-RM2-008 | Chaff envelopes SHALL be produced through the same C-11 code path and store commit path as real envelopes, and SHALL NOT be counted. | ADR-047; ADR-038 | THR-011; THR-003 | C-07; C-08 | TST: ST-168; AT-087 |
| IMP-RM2-009 | The intake store SHALL use PostgreSQL over a unix socket with peer auth, compile-time-checked queries only, no logged bind values and no sub-day time columns. | B-SI-35; B-SI-37; INC-11 | THR-015; THR-011 | C-08 | TST: pg_hba lint; schema lint; AT-007; AT-020 |
| IMP-RM2-010 | `COMMIT_ENVELOPE` SHALL fsync blobs, rows and directory entries before the source is shown "received", and SHALL write chaff and real envelopes identically. | ADR-046; ADR-047 | THR-037; THR-011 | C-08 | TST: ST-103 power-loss test |
| IMP-RM2-011 | Account challenges and verification SHALL be uniform for known and unknown locators, and login responses SHALL wait for the login latency floor plus jitter on every outcome. | B-SI-06; B-AU-12 | THR-034; THR-011 | C-06; C-08 | TST: AT-042 t-test; ST-067 |
| IMP-RM2-012 | The web service SHALL speak HTTP/1.1 only over the unix socket with header, body and time limits, reject ambiguous framing, and expose no compression. | B-SI-17; INC-116 | THR-032; THR-004 | C-06 | TST: ST-044; ST-075; ST-101 |
| IMP-RM2-013 | Every route SHALL be declared in the registry with audience `source-web` and an authz rule. Every POST SHALL require the `csrf` token, and `Sec-Fetch-Site` cross-site or same-site SHALL be rejected. | B-SI-26; INC-105; INC-114; ADR-029 | THR-021; THR-006 | C-06 | TST: ST-065; ST-071; route-registry lint |
| IMP-RM2-014 | The only cookie SHALL be `__Host-cs` (Secure, HttpOnly, SameSite=Strict, no expiry), and the server SHALL store only the derived handle hash in sealer RAM. | B-SI-25; B-SI-28 | THR-006; THR-034 | C-06; C-07 | TST: ST-066; AT-051; `sui-cookie-onion` |
| IMP-RM2-015 | Uploads SHALL stream into the sealer without touching disk in plaintext, without sniffing, and with the filename used only as encrypted metadata. | ADR-012; B-SI-25; INC-107 | THR-009; THR-015 | C-06; C-07 | TST: ST-082; ST-083; AT-016 |
| IMP-RM2-016 | All source-facing responses, busy and error pages included, SHALL fall in their P1/P2 class, with byte-identical busy pages, and carry the 11 §5.3 header set. | ADR-011; ADR-051; INC-118 | THR-004; THR-011; THR-008 | C-06 | TST: AT-046; ST-074 |
| IMP-RM2-017 | Global limits SHALL be sized to trigger only at ≥ 10× design peak, and source-influenced counters SHALL leave the host only as a global daily band. | ADR-038; ADR-026 | THR-011; THR-032; THR-039 | C-06; C-07; C-08 | TST: ST-079; ST-100; AT-008 |
| IMP-RM2-018 | The reply set SHALL be served fetch-all, in fixed 64-entry pages of 70,000-byte entries with power-of-two page counts, rebuilt only at slot times. | ADR-039 | THR-011; THR-003 | C-08 | TST: AT-078 |
| IMP-RM2-019 | Mailbox and account deletions SHALL append a K31-signed deletion-list entry in the same transaction, and a restored intake SHALL refuse source requests until the newest verified list is applied. | ADR-047; INC-55 | THR-017 | C-08 | TST: ST-174; AT-091 |
| IMP-RM2-020 | The intake SHALL refuse new submissions (busy page) when its clock is outside the consensus window or disagrees with the Roughtime median by > 2 h. | ADR-036; ADR-047 | THR-043 | C-05; C-06; C-07 | TST: ST-106 |
| IMP-RM2-021 | Compromise drills AT-020, AT-024 and AT-031 SHALL produce answers that are a subset of the generated oracle before RM-2 exit. | ADR-016; INC-03 | THR-014; THR-015; THR-030 | C-05..C-08 | TST: SG-11 drill report |
| IMP-RM2-022 | No unauthenticated source text SHALL be forwarded to any staff-facing channel outside the sealed envelope. | INC-SL-15; ADR-017 | THR-028; THR-016 | C-06; C-08 | TST: canary-URL absence in outbound bodies |

## 9. Residual risks and open issues

- **Tier W trusts the server** (ADR-004). A compelled or compromised operator can prospectively modify C-06/C-07 to capture plaintext and passphrases (02 residual Medium–High). The mitigations are integrity evidence (ADR-035) and Tier V (RM-8), not this step.
- Sealer RAM plaintext is exposed to a root or hypervisor adversary (THR-030). mlock and no-dump do not stop live memory reads.
- `__Host-` cookie behaviour on HTTP onions in Tor Browser is "Knowledge (unverified)". The `sui-cookie-onion` per-release test is the only guard. Fallback 08 O-3.
- Timing floors are tested in the lab. Network jitter across Tor can hide or reveal more in production (AT-042 is a lab bound).
- Full-vanguards addon maintenance is UNVERIFIED (R7 D2). Re-check before enabling on HIGH profiles.
- Open: the `Sec-Fetch-Site` tightening must be verified not to break Tor Browser Safest flows (AT-050) before it becomes normative in 08.
