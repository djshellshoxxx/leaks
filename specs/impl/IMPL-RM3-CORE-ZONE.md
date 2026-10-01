# IMPL-RM3 — Core zone: relay, case service, DB/RLS, authz/COI, audit, key directory, notifications, EKV, retention

Status: Draft v1.0 · Edition applicability: both (EE-HA variants deferred to RM-10) · Owner: T3 Case Core (C-14 crypto parts and EKV with T1) · Standard: `IMPL-00-SECURE-IMPLEMENTATION-STANDARD.md`

## 1. Purpose and scope

| Item | Content |
|---|---|
| Milestone | RM-3 (`38` §4): relay pull, Case Service, DB schema + RLS, authz engine with COI, audit-log hash chain, content-free notifications, Erasure Key Vault, retention jobs |
| Components | C-09 Intake Relay (`candor-relay`) · C-10 Case Service (`candor-case`) · C-12 Case DB · C-13 Case Blob Store · C-14 Key Directory service (`candor-keydir`) · C-21 Authentication Service (`candor-auth`, server side) · C-22 Authorization Engine (`candor-authz`) · C-23 Notification Service (`candor-notify`) · C-24 Audit Log Service (`candor-audit`) · `candor-ekv` (ADR-033(3)) · `candor-worker` jobs |
| Specs implemented | 07 §4, §5.4–§5.12, §6 (jobs), §13 · 08 §3, §6 (relay, core side), §7, §8–§9 (desk/admin APIs, server side), §11 · 09 §5.2–§5.6, §6–§11 · 14 (case workflow, routing) · 15 §4–§5 (staff authn, RBAC/ABAC, COI, break-glass, dual control, IDOR) · 20 §3–§12 · 35 §4–§7, §10–§12 · ADR-008, -009, -013..-017, -021, -025, -029, -030, -033, -036, -037, -038, -044, -045, -047(7)(8)(9)(10) |
| Not in scope | Desk client (RM-4), SIEM exporter (EE, RM-9), HA/DR automation (RM-10), installers and backup wizard (RM-5; the core-side backup **hooks** are in scope) |

## 2. Preconditions

| # | Precondition |
|---|---|
| P1 | RM-1 exit (formats frozen, `kd` verifier, candor-log chain). RM-2 exit (intake export endpoint, deletion list, chaff disposition) |
| P2 | `authz/matrix.yaml` (15 §5.2) and the signed policy bundle format agreed. The route registry crate exists (ADR-029) |
| P3 | Feature threat models approved: `RM3-relay`, `RM3-authz-coi`, `RM3-audit`, `RM3-keydir-governance`, `RM3-ekv-retention`, `RM3-notify` (each with item 5a inferential analysis: import times, staff reaction times, COI exclusion inference) |
| P4 | 03 §10 compelled-disclosure inventory and 09 column classifications final, so SG-11 oracles can be **generated** (SDL-061) |
| P5 | TPM 2.0 (or an HSM in EE) available in the test lab for the audit checkpoint key and the EKV Vault Master Key |

**Spec-over-research note:** the tenant GUC is `candor.tenant_id` (09 §6.1). The `app.tenant_id` spelling in 27 §12.5 is superseded and should be filed as spec feedback.

## 3. Build sequence

### 3.1 Case DB schema, roles, RLS and migrations (C-12)
- **Build:** schemas `core`, `auth`, `kd` and `candor_audit` per 09 §5.2–§5.5. Roles per 09 §7 (`candor_migrator` NOLOGIN owner; app roles `NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION`). `ENABLE` + `FORCE ROW LEVEL SECURITY` on every tenant table, with the tenant policy and the restrictive case-ACL policies (09 §6.2–§6.5). `candor.tenant()`/`uid()` fail closed on a missing context. Uniqueness keys include `tenant_id` (SI-E-03). `security_invoker` views. The SECURITY DEFINER allow-list each pins `search_path`. Column-level grants exclude `*_ct` from the worker. Hardening per 09 §10 (no `pg_stat_statements`, `log_min_error_statement = panic`, no bind values logged, `track_commit_timestamp = off`). Forward-only migrations via `candorctl migrate` with `lock_timeout`/`statement_timeout` (SI-E-06). A schema lint enforcing the 09 §8 time allow-list and the §8.1 cleartext field allow-list.
- **Rules:** SI-E-01..SI-E-06. ADR-010, ADR-015, ADR-021, ADR-025. IMP-STD-023.
- **Pitfalls:** INC-113 (cross-tenant wipe through a missing tenant check) → fail-closed context. A unique/FK constraint used as a cross-tenant existence oracle (RLS bypass). A session-level `SET` leaking tenant context across pooled connections. INC-115 (authorization tied to encryption state). `now()` defaults on source-linked tables.
- **Verify:** ST-062 cross-tenant snapshot, ST-063 RLS fail-closed (no context → error), `db-grant-audit` (09 §6.4), an RLS suite as `candor_case` with tenant A (0 rows from B, inserts into B error, FK and unique probes), migration test (empty DB and previous snapshot → RLS regression suite), AT-021 drill, AT-079 (joint uniqueness of cleartext fields).

### 3.2 Repository layer and `TenantTx` (C-10)
- **Build:** a `TenantTx` wrapper that runs the three `SET LOCAL` statements from the authenticated principal **inside each transaction**. Raw `PgPool::begin()` is banned by lint. Repository methods returning protected rows require `Authorized<T>` (07 §5.6). `sqlx::query!` with offline `.sqlx` metadata committed. Bound values are size-capped at the application layer.
- **Rules:** SI-E-03, SI-E-05. IMPL-00 §4.6 (`Authorized<T>`). 27 §12.5 SQL.
- **Verify:** trybuild (unauthorized repository call does not compile). Semgrep (no `query(` with `format!`). ST-073 injection suite.

### 3.3 Relay pull (C-09)
- **Build:** a core-initiated pull only. TLS 1.3 with mutually pinned Ed25519 certificates, request signatures over `method ‖ path ‖ sha256(body) ‖ req_counter`, and a strictly increasing persisted counter (replays rejected). Two in-process timers: fixed **import slots** (`relay_import_schedule`) and an hourly **control cycle** that never claims. The 07 §5.4 slot algorithm with **one commit per slot at `slot_start + slot_commit_offset`**, a new random import ID (the intake ref is not stored), `import_date = date(slot_start)`, blob mtime = `slot_start`, and S3 versioning off. Strict validation of intake-supplied data (tenant channel, exactly 16 slots, epoch window, size caps, bucket set), quarantine after 3 failed slots, idempotency via `header_digest` nulled after ≤ 24 h, backpressure. Deletion-list chain verification and restore push-back (ADR-047(9)). A `chaff_discard` job after commit (04 §12.7). nftables `skuid` restricts the relay to intake:7443.
- **Rules:** ADR-009, ADR-038(1), ADR-047(3)(9). SL-R-003. IMPL-00 §7. IMP-STD-004.
- **Pitfalls:** an event-driven import revealing arrival times (RVW-A-09). A compromised intake sending hostile batches (ST-096). INC-104 / INC-SL-03 (HTTP client following redirects) → `candor-http` with redirects off and a pinned endpoint. Trusting intake-reported identity or time.
- **Verify:** ST-052 `fuzz_relay_batch`, ST-096 hostile intake batch, ST-092 redirects and origin pinning, ST-123 zone direction (no inbound Z-INTAKE → Z-CORE; firewall test), ST-169 chaff discard residue, AT-048 import schedule conformance, AT-077 fixed-schedule residue, AT-088 chaff discard leaves no core-side signal, AT-080 timing-correlation audit (WAL, blob mtimes, audit `ts`).

### 3.4 Authentication service, server side (C-21)
- **Build:** WebAuthn/FIDO2 (first factor + PRF for key unlock happen client-side; the server verifies assertions), staff sessions (15 §4.6), audience-bound tokens (`desk-api`, `admin-api`, `relay`) with tenant binding, step-up within 5 min for sensitive settings (15 §4.7; SL-R-007), session signing keys mlocked, no OIDC in CE. Login, step-up and enrolment events are SECURITY-class audit events.
- **Rules:** ADR-029, ADR-015. SI-A-06. IMP-STD-006, IMP-STD-007.
- **Pitfalls:** INC-105 (token reusable on another audience). INC-119 (OTP reuse, no throttle, no step-up). INC-22 (an executive pressuring for unmasking) → step-up and dual control are not substitutes for governance, but they are enforced.
- **Verify:** ST-065 audience replay matrix, ST-066 session lifecycle, ST-067 authentication attacks, AT-027 (stolen admin credential drill).

### 3.5 Authorization engine and COI (C-22)
- **Build:** a pure `authorize(p, a, r, ctx) -> Decision` over facts loaded in the same transaction. Deny by default. Obligations (`RequireStepUp`, `RequireSecondApprover`, `AuditAs`, `RedactField`). A signed, versioned policy bundle. The route contract (`Action` + `ResourceRef` derivation per route). Deny → 404 with a uniform body on resource routes. COI via the blinded tag check `candor.coi_tag_present` only, so C-22 never learns whose tag it is (ADR-037(3)). Triage-first visibility (ADR-037(2)). Admin ≠ case access (ADR-015, enforced by grants and crypto). Break-glass and the dual-control list (15 §5.6, §5.8). Organisation-as-adversary controls (ADR-045). Key-wrap verification on case create, member add and re-key: wraps ⊆ candidate set, ≥ `min_recipients`, no excluded tag present (07 §5.5).
- **Rules:** SL-R-006 (mutation testing), INC-SL-08 (heterogeneous N ≥ 2 properties), IMP-STD-017. ADR-015, ADR-030, ADR-037, ADR-044(2), ADR-045.
- **Pitfalls:** INC-114 (missing role check). INC-112 (mass assignment) → per-route DTOs with `deny_unknown_fields`. INC-SL-08 (a check applied to the wrong element). COI reason codes leaking into audit or errors (THR-020). A 403-vs-404 existence oracle.
- **Verify:** ST-060 authz matrix (generated from `matrix.yaml`), ST-061 IDOR enumeration, ST-064 mass assignment, ST-068 admin ≠ case access, ST-069 COI exclusion, ST-070 break-glass and dual authorization, ST-077 authz independent of encryption, ST-078 dangerous config needs two people, ST-146/147 triage-first and blinded COI, ST-164 org-as-adversary, AT-069 (unticked accused member never decrypts), AT-082/084 (exclusion inference), `cargo mutants -p candor-authz` with 0 survivors, proptest "deny unless an explicit grant exists; COI always wins".

### 3.6 Case Service and APIs (C-10)
- **Build:** separate `desk` and `admin` listeners, each with its own audience and route registry. Pipeline: token → tenant bind → schema validation (`deny_unknown_fields`, per-route DTOs) → authorize → handler → audit (fail-closed) → response. Optimistic concurrency (`If-Match`). `Idempotency-Key`. Desk/admin rate limits (07 §11). The blob I/O path streams to C-13 through `candor-safefs` with a 4 GiB maximum object. Uniform 404 bodies. No server-side parsing of evidence (ADR-012).
- **Rules:** ADR-029, ADR-012. IMPL-00 §4.4, §4.9. IMP-STD-005.
- **Verify:** ST-045 `fuzz_api_json`, ST-055 stateful API fuzzing, ST-073, ST-074, ST-079, ST-165 (undecryptable-envelope handling with a 14-day pending period and dual approval).

### 3.7 Audit Log Service (C-24)
- **Build:** an append API over a unix socket for classes SECURITY, CASE and SYSTEM (SOURCE-SENSITIVE is never an event). Per-class, per-tenant chain `hash_n = SHA-256("candor-audit-v1" ‖ class ‖ seq ‖ hash_{n−1} ‖ canonical_cbor(event))`. Checkpoints every 1,000 events or 10 min, signed with the TPM/HSM Ed25519 key. Optional witness anchoring. Two-phase fail-closed writes (pending → commit → committed) with a reconciliation job. INSERT-only DB role. Date-only automatic import events. Retention per 20 §12 and ADR-051(3). A verification tool (`candorctl audit verify`). The MANAGED audit export key (ADR-047(10)) behind its profile flag.
- **Rules:** ADR-016, ADR-051(3), ADR-047(10). IMP-STD-008.
- **Pitfalls:** INC-60 (secrets in logs). INC-68/INC-69/INC-70 (insiders abusing access) → investigator-activity auditing without source metadata (20 §10). Audit `ts` precision correlating with arrivals (THR-038).
- **Verify:** ST-051 `fuzz_audit_log_verify`, ST-111 audit dependency failure (mutation rolled back), ST-176 MANAGED export key, AT-015 audit sink canary, AT-022 log-server drill, AT-067 audit records not source-identifying, the chain-tamper suite (deletion, reorder, modification, truncation, splice).

### 3.8 Key Directory service (C-14)
- **Build:** a Merkle log (RFC 6962) with signed-note checkpoints at a **fixed hourly cadence**. Immutable entries (`candor_kd` INSERT/SELECT only, trigger rejects UPDATE/DELETE). Entry-type approvals (07 §5.10). Governance: additions time-locked `directory_time_lock` (HIGH/GOV `directory_time_lock_high_gov`), dual approval with an independent role, content-free notice to members and OVERSIGHT. Removals and revocations immediate. The weekly `directory_publication_slot` for MEK and time-locked entries. Witness cosignature collection (CE recommended; EE/GOV/MANAGED ≥ 2 incl. 1 external). The signed intake snapshot with a consistency proof from the high-water mark, pushed in the control cycle.
- **Rules:** ADR-036, ADR-046, ADR-047(4). SL-R-003. Uses the RM-1 `kd` verifier for self-checks.
- **Pitfalls:** INC-14 Anom / THR-046 (hidden recipient insertion by the operator). An admin adding themselves to a roster (THR-131). Split view. A publication time that reveals staff reactions (AT-086).
- **Verify:** ST-033, ST-150 governance time-lock, ST-151 witness cosignature, ST-152 role-label certification and new-key warning, ST-093 key substitution, ST-094 split view and rollback, AT-086 directory publication cadence.

### 3.9 Notification Service (C-23)
- **Build:** only template T1 (fixed text + admin-set label ≤ 32 chars). Modes `daily_constant` (one message per subscribed staff member per day, **sent whether or not anything is pending**, addressee set = all subscribed staff) and `off`. No event-driven mode. Allow-listed egress, TLS verified, `recipient_ref` only in logs, retries then drop. Never sends anything to sources.
- **Rules:** ADR-017, ADR-038(2). IMP-STD-022 (no other egress).
- **Pitfalls:** INC-57 (push-notification metadata demands). INC-SL-15 (unauthenticated text reaching staff email). Send time or addressee set depending on imports.
- **Verify:** AT-014 outbox and deliveries, AT-043 constant-schedule notifications, AT-062 notification content, AT-080 addressee/send-time independence.

### 3.10 Erasure Key Vault (`candor-ekv`) and retention (C-10/C-13 jobs)
- **Build:** the EKV IPC ops (07 §5.12) over a unix socket (peers `candor-case`, `candor-worker`), XChaCha20-Poly1305 with AAD = tenant ‖ case ‖ key_epoch ‖ recipient_key_id, VMK in TPM (physical TPM or HSM for HIGH/GOV), a host-local volume excluded from routine and infrastructure backups (by recorded attestation), its own backup stream (`erasure_vault_backup_retention`), a signed erasure log, and restore that applies the newest verified erasure log before serving (BE-066). Per-case metadata erasure (`META_SEAL`/`META_OPEN`, ADR-047(8)). `REKEY_MISSING` for dual-approved re-wrap (ADR-047(7)). Retention engine and legal holds (35 §5, §10). `crypto_erase_case`, `blob_gc` and `export_expire` jobs (worker-scoped DELETE). Tombstones and deletion receipts (35 §6.4). Wrap-deletion cooling-off (`keywrap_deletion_cooling_off`). Unavailable EKV → 503 fail-closed.
- **Rules:** ADR-025, ADR-033(3), ADR-044(4), ADR-047(7)(8). IMP-STD-006, IMP-STD-007.
- **Pitfalls:** INC-55 (backup theft) → the EKV is excluded from backups, which contain only ciphertext. A restore resurrecting erased cases (THR-017). A "temporary" unsealed wrap fallback.
- **Verify:** ST-108 backup and restore (deleted cases stay unreadable), ST-158 EKV restore applies the erasure log, ST-159 infrastructure-backup exclusion checker, ST-170 per-case metadata erasure, ST-175 re-wrap after vault loss, AT-012 backups, AT-026 seized-backup drill, AT-089 metadata erasure in seized backups.

### 3.11 Jobs, SLA and core self-test
- **Build:** a PostgreSQL `SKIP LOCKED` job queue (07 §6) with per-kind principals. SLA evaluation daily at a fixed time plus on staff transitions, never triggering an immediate message (07 §5.7). C-25 core checks (07 §5.11: schema hash, grants, `rolbypassrls`/`rolsuper` false, EKV backup age, clock vs NTS, Platform Manifest).
- **Verify:** ST-102 DB corruption, ST-104 partition (relay buffering), ST-106 clock (core refuses tokens at > 120 s offset), ST-120, ST-153 Platform Manifest and floor, AT-025 core-app-server drill, AT-030 monitor-host drill.

### 3.12 Drills, inferential suite and independent audit
- **Build:** generate the SG-11 oracles from 03 §10. Run AT-020..AT-025 and AT-084, the SG-26 inferential suite (AT-080..083, AT-085) and the independent audit gate per component.
- **Verify:** answers ⊆ oracle. No predictor beats the day-granular baseline by the 30-defined margin. 0 open Critical/High.

## 4. Component-specific threat checklist (auditor)

| # | Check | Threat |
|---|---|---|
| A1 | Every tenant table has `FORCE RLS`. No app role has `BYPASSRLS` or ownership. A missing context raises an error. Uniqueness and FKs are scoped by tenant | THR-021, THR-045 |
| A2 | `TenantTx` sets `SET LOCAL` per transaction from the principal only, never from request input. Raw pool use is impossible | THR-021 |
| A3 | Every route is declared with action, resource derivation and audience. Deny → uniform 404. No 403/404 existence oracle | THR-021, THR-020 |
| A4 | Authz loops (recipient wraps, members, approvals) check **every** element (mutation and property evidence) | THR-046, THR-021 |
| A5 | COI: C-22 never learns tag ownership. No COI reason code in audit, errors or notifications. Excluded members never receive wraps | THR-020, THR-019 |
| A6 | Admin has no SELECT on content tables. Admin aggregate views apply k-thresholds | THR-018, THR-039 |
| A7 | Relay: core initiates only. Intake data fully validated. Commit only at slot times. No arrival-time residue (WAL, mtimes, audit ts, S3 Last-Modified) | THR-011, THR-014 |
| A8 | Relay HTTP client: redirects off, proxy-from-env off, pinned SPKI, counter replay protection | THR-007, THR-014 |
| A9 | Audit append failure rolls back the business mutation. The chain covers class and seq. Checkpoint key in TPM/HSM. No source-identifying fields | THR-038, THR-018 |
| A10 | Key directory: entries immutable. Time-locks and dual approval enforced server-side. Checkpoint cadence fixed. Witness quorum enforced where required | THR-046 |
| A11 | Notifications: fixed text, constant schedule, addressees independent of activity. No other egress | THR-028, THR-011 |
| A12 | EKV: no plaintext key outside the vault. Fail-closed. Restore applies the erasure log first. Excluded from infrastructure backups | THR-017, THR-013 |
| A13 | SQL: only `query!`. No string-built SQL. No bind values in PG logs. No `pg_stat_statements` | THR-015, THR-016 |
| A14 | Step-up and dual control on the 15 §5.8 list cannot be bypassed through the admin API or `candorctl` | THR-018, THR-022 |
| A15 | Panics and resource limits on the desk, admin and relay inputs. Fuzz evidence | THR-032 |

## 5. Test plan

| ID | Test | Command / tool |
|---|---|---|
| ST-060..070, ST-077, ST-078 | AuthZ, IDOR, tenancy, RLS, COI, break-glass | `CANDOR_TEST_PG=1 cargo test -p candor-case --test authz_matrix -p candor-authz` |
| ST-045/051/052/055 | Fuzz | `cargo +nightly-2026-09-28 fuzz run <t> -- -max_total_time=3600 -rss_limit_mb=2048 -timeout=10` |
| ST-015 | Mutation | `cargo mutants -p candor-authz -p candor-relay --in-diff` |
| `db-grant-audit` | Grant matrix | `CANDOR_TEST_PG=1 cargo test -p candor-case --test grants` |
| RLS regression | Migrations | `candorctl migrate --dry-run` against snapshot N-1 + RLS suite |
| ST-092/096/123 | Relay hostile intake, zone direction | `cargo test -p candor-relay --test hostile_intake`; nft test in candor-lab |
| ST-093/094/150..152 | Directory | `cargo test -p candor-keydir` |
| ST-108/158/159/170/175 | EKV and backup | `cargo test -p candor-ekv`; candor-lab restore drill |
| ST-111 | Audit failure | Kill `candor-audit` mid-mutation → rolled back |
| ST-165/169/174/176 | Revision controls | candor-lab suites |
| AT-012/014/015/021/022/025/026/030/084 | Sinks and drills | `candor-lab drill <id>` vs generated oracle |
| AT-043/048/062/069/077/079/080..083/085..089 | Schedules, inferential | `candor-lab inferential --profile ce-single` |
| ST-102/104/106 | Resilience | candor-lab chaos suite |

## 6. OPSEC checklist

| Metadata at risk | Prevention |
|---|---|
| Submission arrival time in core (WAL, `xmin`, blob mtime, S3 Last-Modified, audit `ts`, job rows) | One commit per fixed slot. `import_date` only. mtime = `slot_start`. `track_commit_timestamp = off`. Date-only automatic audit events |
| Intake reference linking intake and core records | New random import ID. The intake ref is not stored. `header_digest` nulled ≤ 24 h |
| Chaff vs real distinction | Identical import path. Discard at a derived hold slot. AT-088 |
| Staff reaction timing (logins, views, notifications) | Constant-schedule notifications. SLA digest only. Staff timestamps only in the 09 §8 allow-list. SG-26 staff-reaction correlation test |
| COI exclusion identities | Blinded tags padded to `coi_tag_padding`. No SELECT. Definer function only |
| Small-cell aggregates | k = 10, calendar month, complementary suppression (24 §TEL). `v_case_counts` withdrawn |
| Audit records naming sources | No source-sensitive events. Counters only. AT-067 |
| Notification content and addressees | T1 fixed text. All subscribed staff. Daily constant |
| Deleted data surviving in backups or EKV | EKV excluded. Erasure log applied before serving. Per-case metadata erasure |

## 7. Exit criteria (RM-3 definition of done)

- [ ] IDOR and cross-tenant suites pass: ST-060..070, 077, 078; `db-grant-audit`; route registry 0 undeclared (38 RM-3 exit; SG-08).
- [ ] The audit chain verification tool detects every tamper class (`candorctl audit verify`).
- [ ] Relay one-way enforcement passes the firewall test (ST-123).
- [ ] Compromise drills AT-020..AT-024 (and AT-025, AT-084) produce the expected minimal answers ⊆ the generated oracle (SG-11).
- [ ] The inferential suite (SG-26 tests in scope) passes. AT-043 and AT-048 schedule conformance pass.
- [ ] Mutation testing shows 0 surviving mutants in `candor-authz` `check_*`/`verify_*` and in the relay validation functions.
- [ ] EKV restore and erasure tests pass (ST-158, ST-159, ST-170, ST-175).
- [ ] Each core crate has complete SPEC-NOTES and a closed independent audit (0 open Critical/High).

## 8. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| IMP-RM3-001 | Every tenant-scoped table SHALL use `ENABLE` + `FORCE ROW LEVEL SECURITY` with a fail-closed tenant context, and no application role SHALL own tables or have `BYPASSRLS`. | B-SI-35; INC-113 | THR-021; THR-045 | C-12 | TST: ST-062; ST-063; self-test role check |
| IMP-RM3-002 | Uniqueness and foreign-key constraints on tenant tables SHALL include `tenant_id` so that existence cannot be probed across tenants. | B-SI-35 | THR-045; THR-021 | C-12 | TST: FK/unique probe tests |
| IMP-RM3-003 | Tenant and user context SHALL be set per transaction by `TenantTx` from the authenticated principal only. Raw pool transactions SHALL be banned by lint. | B-SI-35; INC-113 | THR-021 | C-10 | TST: Semgrep/clippy ban; pooled-connection leak test |
| IMP-RM3-004 | Repository methods returning protected rows SHALL require an `Authorized<T>` token produced by C-22. | ADR-029; INC-114 | THR-021 | C-10; C-22 | TST: trybuild |
| IMP-RM3-005 | The authorization engine SHALL be deny-by-default and pure. Resource-route denials SHALL return a uniform 404. Mutation testing SHALL leave 0 surviving mutants in decision functions. | B-SL-16; INC-114; INC-112 | THR-021; THR-020 | C-22 | TST: ST-060; ST-061; ST-015 |
| IMP-RM3-006 | COI checks SHALL use only the blinded tag-presence function. No COI reason SHALL appear in audit, errors or notifications. | ADR-037; ADR-030 | THR-020; THR-019 | C-22; C-24 | TST: ST-069; ST-147; AT-082; AT-084 |
| IMP-RM3-007 | Key-wrap verification SHALL check every wrap against the candidate set, `min_recipients` and excluded tags on create, add and re-key, and SHALL reject any extra wrap. | ADR-044; INC-14 | THR-046 | C-10 | TST: ST-093; heterogeneous N ≥ 2 property |
| IMP-RM3-008 | The admin role SHALL have no grants on content tables, and admin aggregates SHALL apply the k-threshold regime. | ADR-015; INC-68 | THR-018; THR-039 | C-12 | TST: `db-grant-audit`; ST-068; AT-065 |
| IMP-RM3-009 | The relay SHALL be core-initiated with pinned mutual TLS, signed counter-protected requests and redirects disabled. No inbound connection SHALL reach Z-CORE from Z-INTAKE. | ADR-009; INC-104; B-SL-28 | THR-014; THR-007 | C-09 | TST: ST-092; ST-123 |
| IMP-RM3-010 | Imports SHALL commit only at fixed slot times in one transaction per slot, with a new random ID, date-only fields and slot-time blob mtimes. | ADR-038; ADR-010 | THR-011 | C-09; C-12; C-13 | TST: AT-048; AT-077; AT-080 |
| IMP-RM3-011 | Intake-supplied batches SHALL be strictly validated (tenant, 16 slots, epoch window, sizes, buckets), quarantined after 3 failed slots, and fuzzed. | ADR-047; B-AU-04 | THR-014; THR-032 | C-09 | TST: ST-052; ST-096 |
| IMP-RM3-012 | Chaff SHALL be discarded after commit by the derived hold slot without leaving any core-side signal. | ADR-047 | THR-011 | C-09; C-10 | TST: ST-169; AT-088 |
| IMP-RM3-013 | Tokens SHALL be bound to one audience and tenant. Sensitive settings SHALL require step-up within 5 min. | ADR-029; INC-105; INC-119 | THR-022; THR-021 | C-21 | TST: ST-065; ST-066; ST-067 |
| IMP-RM3-014 | An audit append failure SHALL roll back the originating mutation. The chain SHALL bind class, sequence and previous hash, with checkpoints signed by a TPM/HSM key. | ADR-016; INC-60 | THR-038; THR-018 | C-24 | TST: ST-111; ST-051; tamper suite |
| IMP-RM3-015 | Key-directory entries SHALL be immutable. Roster additions SHALL be time-locked and dual-approved. Checkpoints SHALL be signed at a fixed hourly cadence. | ADR-036; INC-14 | THR-046 | C-14 | TST: ST-150; ST-151; AT-086 |
| IMP-RM3-016 | Notifications SHALL use only template T1 on a constant daily schedule to all subscribed staff, or be off. No event-driven mode SHALL exist. | ADR-017; ADR-038; INC-57 | THR-028; THR-011 | C-23 | TST: AT-043; AT-062 |
| IMP-RM3-017 | The EKV SHALL fail closed when unavailable, SHALL be excluded from routine and infrastructure backups, and restore SHALL apply the newest verified erasure log before serving. | ADR-033; ADR-044; INC-55 | THR-017; THR-013 | C-10; C-13 | TST: ST-158; ST-159; AT-026 |
| IMP-RM3-018 | Per-case metadata SHALL be erasable through `META_SEAL` keys so that seized backups yield no metadata of erased cases. | ADR-047 | THR-017; THR-015 | C-10; C-12 | TST: ST-170; AT-089 |
| IMP-RM3-019 | Case DB logging SHALL never record SQL text or bind values, and `track_commit_timestamp` SHALL be off. | B-SI-35; INC-60 | THR-016; THR-011 | C-12 | TST: config lint; AT-007 |
| IMP-RM3-020 | Drill answers for AT-020..AT-025 and AT-084 SHALL be checked against oracles generated from 03 §10, never hand-written. | ADR-016 | THR-015; THR-018 | C-10; C-12; C-24 | TST: SG-11 oracle-generation check |
| IMP-RM3-021 | Core services SHALL refuse token issuance at > 120 s clock offset and raise `SYSTEM:clock_insane` alerts on independent-time disagreement. | ADR-036 | THR-043 | C-10; C-21 | TST: ST-106 |

## 9. Residual risks and open issues

- **Root on the core app host** sees Desk-API traffic, metadata and ciphertext, but no plaintext (keys live on recipient endpoints, ADR-007). Staff action metadata remains (AT-025 residual).
- RLS is defense in depth. A logic bug in C-22 that issues `Authorized<T>` wrongly is caught only by tests and audit (ST-060 coverage limits).
- PostgreSQL may retain deleted row versions until page reuse (09 §12). Crypto-erasure is the primary control.
- Fixed slots bound timing leakage to slot granularity. They do not remove it for low-volume channels (30 SG-26 thresholds).
- Witness cosignatures are optional in CE. Without an external witness, CE relies on clients' consistency checks only.
- Open: 27 §12.5 `app.tenant_id` → `candor.tenant_id` spec correction. Policy-language implementation choice (15 §5.9) must stay a pure function to remain mutation-testable.
