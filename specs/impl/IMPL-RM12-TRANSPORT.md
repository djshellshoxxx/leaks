# IMPL-RM12 — Transport evolution: Arti onion-service migration and cover-traffic transport admission

Status: Draft v1.0 (2026-10-01) · Edition applicability: both · Owner: T2 Intake (adapter), T6 (deployment), T9 Research (anonymity analysis); external anonymity reviewers · Roadmap milestone: RM-12 (not on the CE critical path; depends on RM-7)

Global rules are in `IMPL-00-SECURE-IMPLEMENTATION-STANDARD.md` and are not repeated. Rule ID sources as in `IMPL-RM5-OPERATIONS.md`.

## 1. Purpose and scope

| Item | Content |
|---|---|
| Goal | Move the intake onion service from C-tor to Arti only when Arti meets every migration gate, and admit any new transport as ANONYMOUS only when it meets every admission criterion; otherwise keep C-tor and label new transports CONFIDENTIAL |
| Components | C-04, C-05 (intake gateway daemon), C-06 (Transport Adapter consumer), C-03 (client parity), C-14 (AdmissionRecord policy entries), C-25 (transport health), C-32 (Platform Manifest tracking) |
| Spec sections | ADR-001, ADR-002, ADR-026, ADR-046(8)(9), ADR-049(1)(2); 16 §6 (Transport Adapter interface §6.1, client §6.2, admission criteria AC-1..AC-10 §6.3), §7 (torrc), §9 (migration criteria AM-1..AM-8, phases P0–P4, PQ tracking §9.4), §13 (DoS), §15 (monitoring); 30 (AT suites); 37 A7 |
| Current state (2026-10-01) | Arti 2.6.0: onion-service example config warns privacy features incomplete; service-side `hs-pow-full` experimental in tor-hsservice 0.46.0; restricted discovery experimental (R7 D1, B-SI-30/31). Python vanguards add-on dormant and not deployed (ADR-049(1)). Intake stays on C-tor ≥ 0.4.8 GPL build with `pow: yes` |

## 2. Preconditions

| # | Precondition |
|---|---|
| P1 | RM-7 GA; C-tor intake baseline (16 §7.1, SI-D-01) running in production with AT suites green |
| P2 | Transport Adapter trait (16 §6.1) implemented for `tor-onion-v3-ctor` with an AdmissionRecord |
| P3 | Staging environment able to run a separate test onion and ≥ 3 canary deployments willing to participate (AM-8) |

## 3. Build sequence

### RM12-S1 Gate tracking (automated)

| Aspect | Specification |
|---|---|
| Build | CI job run on every Arti release: records Arti version, Cargo feature status of `hs-pow-full`, `restricted-discovery`, vanguards for services, release-note statements, open security advisories (TROVE/RustSec); dashboard of AM-1..AM-8 and ADR-049(2) status; same job tracks Tor PQ handshake availability (16 §9.4) |
| Rules | Migration work beyond staging SHALL NOT start until ADR-049(2) holds (service PoW non-experimental and default-enabled) **and** AM-1..AM-7 hold; tracking output signed and logged with each Platform Manifest release |
| Verify | Job output reviewed per release; INSP by Security Lead |

### RM12-S2 `tor-onion-v3-arti` Transport Adapter

| Aspect | Specification |
|---|---|
| Build | Adapter implementing `TransportAdapter` (16 §6.1) on Arti's onion-service API, exact-pinned Arti crates with minimal features |
| Rules | Expose only a byte stream, `CircuitToken` (random, in-memory, cleared on circuit close) and `AnonymityClass`; no peer address, relay fingerprint, timing data or Arti circuit IDs leave the adapter; `start` fails closed with no partial start; health aggregate and bucketed (16 §15); logging equivalent to `SafeLogging` (AM-5); onion key storage permissions and custody per SI-D-04; adapter runs under the C-05 sandbox baseline (SI-B-01..03) with network limited to Tor; per-circuit token for in-memory rate limiting (AM-6, ADR-026); AdmissionRecord signed by K01 + 2 Key-Admins and logged in C-14 |
| Pitfalls | INC-35 (guard discovery against a service), INC-29 (relay-early traffic confirmation), INC-30 (malicious relay operator), INC-33/INC-34 (service misconfiguration leaks) |
| Verify | Unit/property tests that `CircuitToken` is unlinkable to Arti IDs; fuzz of any parsed control/config input; AT-001 canary over adapter logs |

### RM12-S3 Parity test suite (C-tor vs Arti)

| Aspect | Specification |
|---|---|
| Build | Side-by-side suite: PoW under flood (non-solving flood vs solving clients, queue prioritisation, tunables equivalent to 16 §7.1); intro-point DoS limits; stream limits and circuit close; full vanguards behaviour; restricted discovery for the staff onion; key import preserving the onion address (AM-4) with derived-address equality check; reachability and latency distributions; log content |
| Rules | Parity means "no worse on any measured property"; any regression blocks; the vanguards comparison is against C-tor vanguards-lite (ADR-049(1)) |
| Verify | 38 RM-12 exit "Arti parity tests (PoW, vanguards equivalent)"; AT-040..AT-058 on Arti staging; reachability ≥ C-tor baseline |

### RM12-S4 Phased rollout (16 §9.3)

| Aspect | Specification |
|---|---|
| Build | P1 staging dual-run on a separate test onion; P2 canary on ≥ 3 production deployments for 30 days after 90 days staging (AM-8); P3 default for new installs via the new AdmissionRecord; P4 migration of existing installs with key import, C-tor kept installed and disabled for 6 months as rollback |
| Rules | Rollback on any AT failure or unresolved security advisory; existing onion address preserved (no new address unless compromise procedure 16 §10 applies); Platform Manifest records which daemon each profile uses; floors apply to Arti versions |
| Verify | Canary AT reports; rollback drill from Arti to C-tor preserving address |

### RM12-S5 Independent review of the Arti migration

| Aspect | Specification |
|---|---|
| Build | Published independent audit covering Arti onion-service code (AM-7, may be upstream's); 37 A7 anonymity review of the Candor deployment on Arti |
| Verify | Reports published; 0 open Critical/High affecting intake |

### RM12-S6 Cover-traffic / new transport admission (AC-1..AC-10)

| Aspect | Specification |
|---|---|
| Build | Admission dossier per candidate transport (e.g. a CoverDrop-style cover-traffic design, B-GL-20): literature review in 00-RESEARCH format (AC-1), anonymity-set metrics or design proof independent of real-sender count (AC-2), client availability without JS or embeddable in C-03 (AC-3), audit ≤ 36 months (AC-4), maintenance record (AC-5), service DoS defence (AC-6), service-location protection (AC-7), censorship circumvention (AC-8), fail-closed deployment test (AC-9), ADR amending ADR-001 (AC-10) |
| Rules | All ten criteria required for ANONYMOUS; otherwise admit only as CONFIDENTIAL with "NOT ANONYMOUS" branding via C-38 (16 §6.1, ADR-002); adding a transport never lowers requirements on existing ones; cover traffic schedules generated from a CSPRNG and independent of user activity; any client-side cover traffic must not create device residue beyond documented state; independent anonymity review (37 A7) before any source exposure |
| Pitfalls | Small anonymity sets in alternative networks (16 §4), INC-31/INC-35 (correlation of few users) |
| Verify | External expert review report; AC-9 via 30 anonymity suite; ADR merged |

## 4. Auditor threat checklist (component-specific)

| # | Check | Threats |
|---|---|---|
| 1 | Is migration beyond staging gated on ADR-049(2) and AM-1..AM-8, enforced by process and recorded evidence? | THR-005, THR-032 |
| 2 | Does the Arti adapter expose any circuit identifier, peer data or timing beyond `CircuitToken`? | THR-001, THR-016 |
| 3 | Is PoW and intro DoS protection at least equivalent under flood? | THR-032, THR-033 |
| 4 | Are vanguards (full) active for the service, and is restricted discovery used for the staff onion? | THR-005 |
| 5 | Does key import preserve the address without exposing the key outside the intake host? | THR-044 |
| 6 | Is rollback to C-tor tested and address-preserving? | THR-032 |
| 7 | Can any transport be labelled ANONYMOUS without a signed AdmissionRecord meeting AC-1..AC-10? | THR-040, THR-003 |
| 8 | Does cover traffic depend on user activity or leave residue? | THR-003, THR-048 |

## 5. Test plan

| Test | Command / tool | Gate |
|---|---|---|
| Gate tracker | `cargo run -p candor-transport-gates -- --arti <version> --json` (feature and advisory status) | RM12-S1 |
| Adapter | `cargo test -p candor-transport-arti --locked`; fuzz of config/control inputs | PR |
| PoW parity | flood harness: non-solving clients at N× capacity plus C-tor 0.4.8+ solving clients; compare admitted-solver ratio C-tor vs Arti | RM12-S3 |
| Config lint | `tor --verify-config` (C-tor) and Arti config schema check in CI; self-test `tor.pow_vanguards` equivalent for Arti | SG-17 |
| Anonymity | AT-001..AT-019, AT-040..AT-058 on Arti staging and canaries | SG-10, SG-12 |
| Egress | uplink `tcpdump` shows only Tor traffic from intake during suite | SI-D-03 |
| Rollback | address-preserving switch Arti → C-tor drill | RM12-S4 |
| Review | 37 A7 on Arti deployment; AC dossier external review | RM-12 exit |

## 6. OPSEC checklist

| Exposure | Control |
|---|---|
| Dual-running two daemons increases attack surface and guard exposure | Test onion only on staging; C-tor disabled (not running) during P4 rollback window |
| Canary deployments become identifiable as early adopters | Canary participation not published; same Candor release for all |
| New transport traffic visible on source networks | Disclosed in 05 guidance; CONFIDENTIAL label when criteria unmet |
| Onion key handling during import | On-host import only; backup to IRK quorum; no transfer via admin workstation |
| Gate-tracking telemetry | Uses public release data only; no deployment data |

## 7. Exit criteria

| Type | Criterion |
|---|---|
| Roadmap (38 RM-12) | Arti parity tests (PoW, vanguards equivalent) pass; independent anonymity review of any new transport complete |
| Spec gates | ADR-049(2) and AM-1..AM-8 met before P3; AC-1..AC-10 met before any new ANONYMOUS label; SG-10, SG-12, SG-17 green on Arti profile |
| Audit gate | Each step RM12-S1..S6 audited independently (`process/audits/AUDIT-RM12-Sn.md`); 0 open Critical/High; Medium fixed or lead-accepted in writing |
| Milestone record | Signed RM-12 report logged (RM-005) |

## 8. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| IMP-RM12-001 | The intake onion service SHALL remain on C-tor ≥ 0.4.8 with PoW until Arti service-side PoW is non-experimental and default-enabled and AM-1..AM-8 are met. | ADR-049(2); B-SI-30; B-SI-31 | THR-032, THR-005 | C-05 | INSP: gate-tracker record; TST: Platform Manifest daemon check |
| IMP-RM12-002 | The vanguards add-on SHALL NOT be deployed; C-tor vanguards-lite is the baseline until Arti full vanguards are in use. | ADR-049(1) | THR-005 | C-05 | TST: Platform Manifest/package check; ST-153 |
| IMP-RM12-003 | The Arti adapter SHALL expose only a byte stream, a random in-memory `CircuitToken` and the anonymity class, and SHALL fail closed on start errors. | 16 §6.1; INC-35 | THR-001, THR-016 | C-06 | TST: adapter interface tests; AT-001 |
| IMP-RM12-004 | Arti intake SHALL show no regression against C-tor on PoW flood handling, DoS limits, vanguards, restricted discovery, logging and reachability before becoming a default. | 16 §9.2; INC-29 | THR-032, THR-005 | C-05 | TST: parity suite; AT-040..AT-058 |
| IMP-RM12-005 | Onion key migration SHALL preserve the address, occur on the intake host only, and be reversible to C-tor for 6 months. | 16 §9.3; SI-D-04 | THR-044 | C-05 | TST: address-equality and rollback drill; ST-121 |
| IMP-RM12-006 | A transport SHALL be labelled ANONYMOUS only with a signed AdmissionRecord evidencing AC-1..AC-10 and an approved ADR; otherwise it SHALL be served only as CONFIDENTIAL via C-38. | 16 §6.3; ADR-001; ADR-002 | THR-040, THR-003 | C-14 | INSP: AdmissionRecord; TST: C-06 class enforcement; AUD: A7 |
| IMP-RM12-007 | Cover-traffic schedules SHALL be generated independently of user activity and SHALL leave no undocumented device residue. | 16 §6.3 AC-2; B-GL-20 | THR-003, THR-048 | C-03 | TST: schedule independence test; AT-090 |
| IMP-RM12-008 | Tor post-quantum handshake availability SHALL be tracked each Platform Manifest release and adopted in the first minor release after a stable Tor release meets 16 §6.3. | ADR-046(8); 16 §9.4 | THR-012, THR-003 | C-32 | INSP: release tracking record |

## 9. Residual risks and open issues

| # | Item | Handling |
|---|---|---|
| R1 | Tor-network-level correlation and guard discovery remain (16 §16) | Documented; vanguards; Tier V for HIGH risk |
| R2 | Arti onion-service maturity timeline unknown | RM-12 off CE critical path (38 §5) |
| R3 | Cover-traffic transports may never reach AC-2 anonymity sets at Candor scale | CONFIDENTIAL-only admission |
| R4 | Harvest-now-decrypt-later on classical Tor handshakes | ADR-046(8) residual; Tier V hybrid PQ end-to-end |
| OI-1 | AM-4 key-import tooling name UNVERIFIED (16 §9.2) | Confirm against Arti docs at P1 |
