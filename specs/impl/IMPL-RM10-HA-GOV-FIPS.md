# IMPL-RM10 — EE-HA and GOV: HA profiles, DR automation, FIPS profile, GOV hardening, compliance packs, OSCAL evidence

Status: Draft v1.0 (2026-10-01) · Edition applicability: EE (EE-HA, GOV-ONPREM, AIRGAP-RCP); FIPS build of trust-path code is AGPL and reproducible · Owner: T8 Enterprise; T6 Platform/Infra; T1 (FIPS crypto build) · Roadmap milestone: RM-10

Global rules are in `IMPL-00-SECURE-IMPLEMENTATION-STANDARD.md` and are not repeated. Rule ID sources as in `IMPL-RM5-OPERATIONS.md`.

## 1. Purpose and scope

| Item | Content |
|---|---|
| Goal | Higher availability and government deployment without adding hidden observers, intake replication or a second, weaker cryptographic path |
| Components | C-05/C-06/C-07/C-08 (active/passive intake, fencing), C-10/C-12/C-13 (Patroni/etcd, replicas, blob store), C-27 (DR automation, vault replica), C-29 (in-zone HSM), C-11 (CANDOR-FIPS-1 build), C-19 (compliance packs, OSCAL export), C-33 (in-zone TUF mirror), C-39 |
| Spec sections | ADR-024, ADR-032, ADR-044(3)(4), ADR-046(1)(2)(7), ADR-048(1)(2); 21 §5 (HA topology, key availability, observer inventory O1–O14), HA-001.., HA-007, HA-015, HA-018; 19 §6.1, §10, §11 (vault replication, RPO/RTO, DR); 22 §4–§10 (GOV profile, FIPS scope, sovereignty, controlled networks), GOV-011/014/015/017/028/032/035; 04 §4.1 (CANDOR-FIPS-1); 25 COMP-012, COMP-026; 29 ST-031, ST-104, ST-158; 37 A6 (FIPS), A8 (38 calls it "A7 audit (infrastructure/HA)"), A17 (GOV settings) |

## 2. Preconditions

| # | Precondition |
|---|---|
| P1 | RM-9 exit (EE foundations; Fleet, HSM integration audited) |
| P2 | RM-5 backup/restore drills green on single-host profiles |
| P3 | AWS-LC FIPS module version with a current validation certificate selected and recorded in the Platform Manifest (module validation is the vendor's, 37 §12) |
| P4 | Decision recorded on FIPS anonymous slots: KEM key-privacy ASM in 40 **or** pure ML-KEM-1024 slots (22 §8, RVW-C-15) |
| P5 | GOV reference site (lab) with physical TPMs and in-zone HSM |

## 3. Build sequence

### RM10-S1 HA topology (EE-HA)

| Aspect | Specification |
|---|---|
| Build | Z-CORE: PostgreSQL with Patroni/etcd, in-site replicas, cross-site async; blob store nodes; L4 balancer for Desk API (TLS passthrough). Z-INTAKE: active/passive on shared-nothing hosts, no DB replication (`wal_level=minimal`, no archiving, `track_commit_timestamp=off`, ADR-046(1)); onion key on ≤ 2 intake hosts, both in the Secret Placement Manifest (ADR-032); planned switchover at an import slot (18 §11.3) |
| Rules | Exactly one Tor instance publishes an onion at a time; promotion only after successful fencing (HA-001); fencing credentials scoped and SECURITY-audited; balancer and mesh access logs off (O4, O11); etcd holds no application data; K8s only for Z-CORE with dedicated cluster, NetworkPolicy default-deny, Pod Security `restricted`, audit policy `Metadata`, KMS-encrypted Secrets (18 §5); source sees "received" only after local fsync; every new observer appears in the 21 §5.4 inventory before merge |
| Pitfalls | INC-33 (real-IP leak through misconfigured component), INC-54 (Cloudbleed: shared infrastructure memory leak), INC-113 (operation hitting all tenants) |
| Verify | Observer-inventory test: enumerate processes, sockets, log files and persistent stores on every HA node and diff against O1–O14 (38 RM-10 exit); split-brain test (both intake nodes believe active → second refuses to publish); ST-104 partitions; AT canary across all HA nodes |

### RM10-S2 DR automation and vault replication

| Aspect | Specification |
|---|---|
| Build | DR runner executing DR-P playbooks (19 §11); Erasure Key Vault replica to DR site within ≤ 15 min (19 §6.1); erasure log applied before serving at DR site |
| Rules | Runner cannot unseal backups without the IRK quorum (HA-015); vault replica excluded from DR-site image backups (HA-018); HIGH/GOV vault on physical TPM, not vTPM (ADR-044(4)); DR staff hold no Desk roles by default; runner credentials short-lived and logged SECURITY class |
| Pitfalls | INC-55 (backup copies with reachable keys), INC-59 (exposed storage) |
| Verify | Failover drills RT-4 twice yearly incl. quorum assembly time (19 §7); ST-158; measured RTO vs 19 §10 EE-HA row |

### RM10-S3 FIPS profile (CANDOR-FIPS-1)

| Aspect | Specification |
|---|---|
| Build | Separate build feature/target of candor-core and dependants using `aws-lc-rs` in FIPS mode for all primitives; FIPS KATs; PBKDF2-HMAC-SHA-512 210,000 iterations for passphrase KDF (ADR-046(7)); ML-KEM-1024 / P-384 / AES-256 / SHA-384 parameters (22 §8) |
| Rules | Suite selected at build time, never negotiated at runtime (27 §11.3 item 9; R8 §1.8); any STD-only algorithm call in the FIPS build fails (ST-031); FIPS module power-on self-tests must pass before service start (fail closed); AEAD counter nonces with per-key message cap (R8 §2.3); KATs and Wycheproof run on every shipped arch and backend incl. forced-portable (SL-R-004); FIPS build reproducible on both builders — the C/assembly portion of AWS-LC built with pinned toolchain and recorded flags; differential test FIPS vs STD where algorithms overlap |
| Pitfalls | INC-51 (Debian OpenSSL: downstream patch removed entropy), INC-50 (Dual_EC: approved-but-weakened component), INC-SL-07 (unverified arch fallback produced wrong outputs) |
| Verify | ST-031; FIPS KATs (38 RM-10 exit); ST-021; multi-arch matrix; ST-131 on FIPS artifacts; 37 A6 review of the FIPS build |

### RM10-S4 GOV profile hardening

| Aspect | Specification |
|---|---|
| Build | GOV-ONPREM defaults per 22 §4: Tier W preselected OFF in CJIS/FIPS-mandated deployments, enabling is ADVANCED with recorded agency determination (ADR-048(1), GOV-028); Recovery Quorum enabled by default with independent custodians, disclosed to sources (ADR-044(3), ADR-048(2)); 7-day time-locks for directory changes (ADR-036(2)); in-zone TUF mirror; offline update bundles (33 §8); attested rules for guest-invisible knobs (GOV-035) |
| Rules | EDR on H-INTAKE prohibited; monitoring mandates met by the alternative implementations of 25 §5.7; inner TLS 1.3 with the validated module for Desk API (GOV-032); all zones and DR in one sovereignty zone (GOV-014); SOC non-correlation policy checked by deployment checklist (GOV-017) |
| Pitfalls | INC-22/INC-121 (organisation as adversary using security tooling to unmask), INC-25/INC-26 (records seized/pretexted) |
| Verify | `candorctl check` GOV rule set; ST-164; 37 A17 for GOV time-lock/approval settings; A8 for GOV-ONPREM and AIRGAP-RCP |

### RM10-S5 Compliance packs and OSCAL evidence export

| Aspect | Specification |
|---|---|
| Build | Jurisdiction/compliance packs (25); OSCAL component-definition and assessment-results export for SP 800-53r5.2.0 (COMP-012) and per-release §5.7 control-tailoring annex (COMP-026); generated from the gate-evidence bundle |
| Rules | Evidence exports contain configuration classes, test IDs and results only — no case data, no counts below the 24 §TEL regime (k = 10, monthly), no staff names, no onion addresses; OSCAL generated deterministically and signed |
| Pitfalls | INC-74 (aggregate data revealing sensitive patterns), THR-039 small cells |
| Verify | OSCAL schema validation (COMP-012/026 TST); AT-001 over export bundles; small-cell checker |

### RM10-S6 Audits

| Aspect | Specification |
|---|---|
| Build | 37 A8 (EE-HA, GOV-ONPREM, AIRGAP-RCP, PRIVATE-CLOUD), A6 (FIPS build), A17 (GOV settings), A1 scoped pentest for HA attack surface |
| Verify | Published reports; 0 open Critical/High |

## 4. Auditor threat checklist (component-specific)

| # | Check | Threats |
|---|---|---|
| 1 | Is there any intake replication path (DB, WAL, file sync, snapshot) in any HA mode? | THR-015, THR-017 |
| 2 | Can two intake nodes publish the same onion concurrently or promote without fencing? | THR-044, THR-005 |
| 3 | Does any new HA element (balancer, mesh, etcd, K8s, monitoring, DR runner, hypervisor) log request bodies, staff IPs beyond declared, or source-derived data? | THR-016, THR-030 |
| 4 | Can the DR runner or DR staff decrypt backups or vault content without the quorum? | THR-013, THR-018 |
| 5 | Is the vault replica excluded from DR-site image backups, and is the erasure log applied before DR serves? | THR-017 |
| 6 | Can the FIPS build call a non-approved primitive, negotiate suites at runtime, or skip module self-tests? | THR-012 |
| 7 | Are FIPS outputs identical across architectures and backends (no unverified fallbacks)? | THR-012 |
| 8 | Does the GOV profile ship Tier W off where mandated, Recovery Quorum disclosed, and EDR absent from intake? | THR-040, THR-018 |
| 9 | Do OSCAL/compliance exports contain small cells, names or identifiers? | THR-039, THR-016 |

## 5. Test plan

| Test | Command / tool | Gate |
|---|---|---|
| Observer inventory | `candorctl ha inventory --json` vs 21 §5.4 golden; `ss -ltnpx`, `find /var/log -newer` diff on each node | 38 RM-10 exit |
| Failover | fault-injected node kill, network partition, split-brain fencing; ST-104 | SG-18 |
| DR | RT-4 drill; ST-158; ST-174 | SG-20 |
| FIPS | `cargo test -p candor-core --features fips --locked`; ST-031; ST-021; FIPS KAT suite on x86_64 + aarch64 | SG-06 |
| Reproducibility | ST-131 on FIPS and HA images (OCI by digest) | SG-13 |
| GOV config | `candorctl check --profile gov-onprem --json` | SG-17 |
| OSCAL | `oscal-cli validate` (or equivalent) on exported files (tool UNVERIFIED) | COMP-012 |
| Anonymity | AT-001..AT-019 on EE-HA and GOV; AT-080..AT-085 inferential tests incl. HA observers | SG-10, SG-26 |

## 6. OPSEC checklist

| Exposure | Control |
|---|---|
| Second intake host doubles onion-key exposure | ≤ 2 hosts, same hardening, manifest-verified (ADR-032) |
| Hypervisor/SAN snapshots of core incl. vault | Signed exclusion attestations; RT-7 probe; deletion statement conditional |
| DR site staff and physical location | Same physical controls; no Desk roles |
| L4 balancer sees staff IPs and timing | Logs off except counters |
| K8s audit logs capture request metadata | Audit policy `Metadata`, no bodies |
| Agency SOC correlates Tor alerts with hotline | Written non-correlation policy (customer responsibility) |
| Compliance evidence exported to auditors/regulators | Fixed fields, TEL regime, no names |

## 7. Exit criteria

| Type | Criterion |
|---|---|
| Roadmap (38 RM-10) | HA observer inventory verified by test; FIPS-mode KATs pass; failover drills pass; infrastructure/HA audit complete (37 A8) |
| Spec gates | SG-06 (FIPS), SG-13, SG-17, SG-18, SG-20, SG-26 on EE-HA and GOV profiles |
| Audit gate | Each step RM10-S1..S6 audited independently (`process/audits/AUDIT-RM10-Sn.md`); 0 open Critical/High; Medium fixed or lead-accepted in writing |
| Milestone record | Signed RM-10 report logged (RM-005) |

## 8. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| IMP-RM10-001 | No HA mode SHALL replicate intake data; intake PostgreSQL SHALL run with `wal_level=minimal`, no archiving and `track_commit_timestamp=off`. | ADR-046(1) | THR-015, THR-017 | C-08 | TST: config assertion; ST-121; AUD: A8 |
| IMP-RM10-002 | A standby intake SHALL publish the onion only after successful fencing of the prior active, and at most one Tor instance SHALL publish an onion at any time. | HA-001; ADR-032 | THR-044, THR-005 | C-05 | TST: split-brain fencing test |
| IMP-RM10-003 | Every HA element SHALL be listed in the 21 §5.4 observer inventory with its permitted data, and a test SHALL fail on any undeclared store, log or listener. | 21 §5.4; INC-33 | THR-016, THR-030 | C-39 | TST: observer-inventory diff; AT-001 |
| IMP-RM10-004 | DR automation SHALL be unable to unseal backups or vault content without the IRK quorum, and DR restores SHALL apply the erasure log before serving. | HA-015; ADR-044(4); INC-55 | THR-013, THR-017 | C-27 | ST-158; DEMO: RT-4 drill |
| IMP-RM10-005 | HIGH/GOV deployments SHALL keep the Erasure Key Vault on a physical TPM and exclude its replica from DR-site image backups. | ADR-044(4); HA-018 | THR-017, THR-031 | C-27 | INSP: attestation; ST-159 |
| IMP-RM10-006 | The FIPS profile SHALL be a separate build using only the validated AWS-LC module for all primitives, SHALL never negotiate suites at runtime, and SHALL fail closed if module self-tests fail. | INC-51; INC-50; ST-031 | THR-012 | C-11 | ST-031; TST: self-test fault injection |
| IMP-RM10-007 | FIPS KATs and Wycheproof vectors SHALL pass on every shipped architecture and backend, and FIPS artifacts SHALL be reproduced by both builders. | SL-R-004; INC-SL-07 | THR-012, THR-024 | C-31 | TST: multi-arch FIPS KAT matrix; ST-131 |
| IMP-RM10-008 | The GOV profile SHALL preselect Tier W off for CJIS/FIPS-mandated deployments, enable the disclosed Recovery Quorum by default, and prohibit EDR on intake hosts. | ADR-048(1)(2); ADR-044(3) | THR-040, THR-018, THR-016 | C-19 | TST: GOV profile config test; AUD: A17 |
| IMP-RM10-009 | OSCAL and compliance exports SHALL validate against schema and SHALL contain no case data, staff names, onion addresses or cells below the 24 §TEL threshold. | COMP-012; COMP-026; INC-74 | THR-039, THR-016 | C-19 | TST: OSCAL schema validation; AT-001 on exports |
| IMP-RM10-010 | K8s, where used, SHALL host only Z-CORE on a dedicated cluster with default-deny NetworkPolicy, `restricted` Pod Security, Metadata-level audit and HSM-KMS-encrypted Secrets. | ADR-024; 18 §5 | THR-045, THR-016 | C-10 | INSP: manifest lint; AUD: A8 |
| IMP-RM10-011 | HA failover drills SHALL meet the EE-HA RPO/RTO of 19 §10 including quorum assembly time. | 19 §10; HA-007 | THR-042 | C-27 | DEMO: RT-4; ST-104 |

## 9. Residual risks and open issues

| # | Item | Handling |
|---|---|---|
| R1 | Envelopes on a failed intake node are unavailable until its disk is recovered | Documented (19 §10, ADR-046(1)) |
| R2 | Tor transport is not FIPS; Tier W plaintext crosses Tor before FIPS encryption | 22 §8 scope statement; Tier V FIPS Source App for in-transit needs |
| R3 | FIPS module validation status can lapse | Recorded in Platform Manifest; monitored each release |
| R4 | Hypervisor and SAN owners can still copy images | Attestations + probes; not a technical guarantee |
| OI-1 | FIPS anonymous-slot key-privacy decision (22 §8, RVW-C-15) | Precondition P4 |
| OI-2 | OSCAL component granularity (25 open issue 1) | Decide before S5 |
| OI-3 | 38 "A7 audit (infrastructure/HA)" corresponds to 37 A8 | Cross-document request |
