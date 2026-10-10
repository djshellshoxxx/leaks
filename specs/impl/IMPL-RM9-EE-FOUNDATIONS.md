# IMPL-RM9 — EE foundations: Fleet Manager, SSO bridge, PIV/CAC, HSM/PKCS#11, SIEM exporter, records connector

Status: Draft v1.0 (2026-10-01) · Edition applicability: EE (commercial modules, source-available; never in the Trust Path) · Owner: T8 Enterprise; T1 for HSM signing integration; Security Lead for boundary review · Roadmap milestone: RM-9

Global rules are in `IMPL-00-SECURE-IMPLEMENTATION-STANDARD.md` and are not repeated. Rule ID sources as in `IMPL-RM5-OPERATIONS.md`.

## 1. Purpose and scope

| Item | Content |
|---|---|
| Goal | Add enterprise management and integration features without giving the vendor, the IdP, the SIEM or downstream systems access to report content, keys or source-identifying metadata |
| Components | C-34 (Fleet Manager + instance agent), C-21 (SSO/OIDC/SAML bridge as first factor; PIV/CAC), C-29 (HSM/PKCS#11 via `candor-ffi`), C-26 (SIEM export gateway), C-40 (records/ticketing connectors via Export Packages), C-35 (offline licence files), C-36 (support tooling touchpoints) |
| Spec sections | ADR-018, ADR-020, ADR-022, ADR-029, ADR-044(1), ADR-045, ADR-046(2)(12); 21 §3 (Charter test), §4, §8 (integration patterns, §8.1 anonymity-destroying integrations), §9 (Fleet Manager), ENT-001..ENT-019, ENT-044; 15 (auth); 20 (event classes); 24 §TEL; 29 ST-076, ST-097; 30 AT marker scan |
| Boundary | EE code lives in a separate repository; it SHALL NOT import intake crates or modify Trust Path code except through public AGPL contributions (RM-004); TUF `ee-modules` delegation is terminating and cannot sign trust-path paths (33 §6.1) |

## 2. Preconditions

| # | Precondition |
|---|---|
| P1 | CE 1.0 GA (RM-7 exit); ADR-048(4) satisfied — no EE work before this |
| P2 | Charter test classification for every module (ENT-001) published |
| P3 | Repository boundary check in CI (EE repo cannot depend on `candor-intake-*`, `candor-sealer`, `candor-source-*`) |
| P4 | Documented, versioned Z-CORE/Z-ADM APIs that EE modules consume; deny-by-default route registry covers them (ADR-029) |
| P5 | Customer-held K15-class token procedure for Fleet signing keys (21 §9.3) |

## 3. Build sequence

### RM9-S0 Boundary, licensing and audience binding

| Aspect | Specification |
|---|---|
| Build | `ee/` repository with CI boundary check (`cargo tree` deny-list of trust-path crates; forbidden-path lint); per-module audience-bound API tokens (ADR-029: `fleet-agent`, `siem-export`, `connector`) |
| Rules | EE modules hold no private keys and receive plaintext only via human-created Export Packages (ADR-020); offline licence verification with no phone-home (C-35); no feature that weakens a CE protection (Edition Charter) |
| Verify | RM-004 boundary job; ST-060..ST-070 authz suite with EE audiences; INSP of Charter classification |

### RM9-S1 Fleet Manager (C-34) and instance agent

| Aspect | Specification |
|---|---|
| Build | Fleet service with the complete data model of 21 §9.2; instance agent in Z-ADM/Z-CORE pulling every 60 ± 30 min over Tor (vendor fleet onion) or to a customer-hosted C-34; signed command sets and policy bundles; public fleet-policy transparency log of ring assignments (ENT-044) |
| Rules | `instance_id` 128-bit random at enrolment, not derived from any address or key; no onion addresses/keys, intake hostnames/IPs, user lists or CASE audit events stored; `display_label` lint warns on `[a-z2-7]{56}` / `.onion`; command allow-list only (`schedule_update` for public TUF targets, `run_selftest`, `apply_policy_bundle` restricted to the fleet-settable keys, `request_support_bundle` with local approval and preview, `set_update_window`); agent verifies signature, allow-list and CFG class and refuses anything else, queuing for local approval incl. the customer's independent role; cannot defer past a security floor, lower a floor, disable intake or change routing (ADR-040, ADR-045); command-signing key customer-held on hardware even when vendor-hosted; agent never on Z-INTAKE and Z-INTAKE has no route to C-34; direct clearnet mTLS is ADVANCED and not allowed in GOV-ONPREM; message parsers bounded and fuzzed (SI-A-02); agent identity from transport mTLS, never from payload (ST-097, INC-103) |
| Pitfalls | INC-49 (central management/update server as attack path), INC-113 (operation on one tenant affecting all: every query tenant-scoped), INC-103 (identity from payload) |
| Verify | ST-097; agent refusal tests for every non-allow-listed key and availability-affecting command; schema tests that forbidden fields cannot be stored; Fleet-compromise drill (21 §9.3 impact list) |

### RM9-S2 SSO bridge (OIDC/SAML) — first factor only

| Aspect | Specification |
|---|---|
| Build | OIDC and SAML relying-party bridge in C-21 using vetted, maintained libraries; SCIM endpoint |
| Rules | IdP assertion is a first factor only; FIDO2 (or PIV) second factor always required (15); no IdP assertion, SCIM operation or group mapping grants case or channel key access (ENT-015); SCIM limited to create-inactive, update display attributes and suspend (ENT-016, ADR-044(1)); strict SAML validation (signature over the whole assertion, single assertion, audience/recipient/NotOnOrAfter checks, reject XML comments/entity expansion/DTD); OIDC: exact redirect URIs, PKCE, `nonce`/`state` constant-time compared (SI-A-06), issuer pinned; discovery and JWKS URLs pass SSRF guard (ST-076); tokens audience-bound (ADR-029); step-up FIDO2 within 5 min for auth-factor, recovery, routing or export-policy changes (SL-R-007) |
| Pitfalls | INC-105 (token reusable across audiences), INC-119 (no step-up, no throttle), INC-22/INC-121 (management using IdP/admin power to unmask: SSO must not grant case access) |
| Verify | SAML/OIDC negative corpus (signature wrapping, audience mismatch, replay, alg confusion); ST-076; ST-164; authz suite proving IdP group changes never add key wraps |

### RM9-S3 PIV/CAC authentication

| Aspect | Specification |
|---|---|
| Build | Certificate path validation with locally cached CRLs or stapled OCSP (ENT-017) |
| Rules | No per-login OCSP queries to external responders unless configured with a warning (each query tells the CA who logs in and when); validated chain policy pinned to configured roots; certificate fields never logged beyond role mapping; card PIN never touches Candor process memory beyond the PKCS#11/PC/SC call |
| Pitfalls | INC-57 (third parties receive login metadata) |
| Verify | Network capture during login shows no external OCSP; expired/revoked/wrong-policy certificate tests |

### RM9-S4 HSM / PKCS#11 integration (`candor-ffi`)

| Aspect | Specification |
|---|---|
| Build | `candor-ffi` crate: the only crate besides `candor-sys` allowed `unsafe` (SI-A-04), exposing a safe signing/unwrap API for server signing keys (audit checkpoints, directory) |
| Rules | `clippy::undocumented_unsafe_blocks`, `multiple_unsafe_ops_per_block`, `unsafe_op_in_unsafe_fn` denied; two reviewers per change; foreign pointers checked, no panics across FFI; Kani harnesses for wrapper preconditions; no fallback software keys when the HSM fails (ADR-046(2), FAIL-013); HSM PIN via `LoadCredentialEncrypted=`; HSM audit logs go to SECURITY class; HSM vendor cloud telemetry disabled; key generation inside HSM with weak-key checks (ST-028) |
| Pitfalls | INC-61 (ROCA: flawed on-device key generation), INC-58 (key material in crash dumps) |
| Verify | `cargo geiger` delta reviewed; Kani proofs; SoftHSM-based CI suite plus vendor HSM lab; fault test: HSM unavailable → signing fails closed, no fallback key present (`keys.availability`) |

### RM9-S5 SIEM exporter (C-26)

| Aspect | Specification |
|---|---|
| Build | Export gateway emitting allow-listed SECURITY and SYSTEM events in a fixed schema to configured targets (syslog-TLS / HTTPS) with certificate pinning |
| Rules | Allow-list per event type and field; SOURCE-SENSITIVE never exported; CASE class only as DANGEROUS, day-granular and pseudonymised with per-export salt (ENT-014); no free-text fields; canary test at enablement and monthly — synthetic canaries, codenames and onion circuit IDs injected upstream must appear 0 times (ENT-018); SSRF guard on endpoints (ST-076); no IPs of sources exist to export (ADR-010/016) |
| Pitfalls | INC-60 (secrets in internal logs), INC-56 (support/monitoring data containing tokens), INC-115 (implicit trust in other controls) |
| Verify | AT-001 sink set extended with the SIEM target; ENT-018 canary job; schema fuzz |

### RM9-S6 Records/ticketing connectors (C-40) via Export Packages

| Aspect | Specification |
|---|---|
| Build | Connector framework consuming only human-created, dual-approved Export Packages (ADR-018): PDF/A + JSON metadata + SHA-256 manifest + applied redactions, encrypted to the Connector Key (ADR-046(12)); destination system recorded (ENT-019) |
| Rules | No automatic push of case data, no webhooks with case fields, no email with case content (ENT-006); packages never include originals unless explicitly approved with beacon warnings (12 export wizard); connector runs in Z-CORE with egress allow-list; destination credentials in credstore; connectors never receive keys |
| Pitfalls | THR-029 class (integrations exfiltrate content), INC-104 (redirect follows to other origins: disable redirects), INC-SL-15 (unauthenticated text forwarded to privileged channels) |
| Verify | Export E2E with dual approval; canary in source text must not appear in any connector payload beyond the approved package; redirect tests |

### RM9-S7 Extend anonymity testing to EE modules and vendor flows

| Aspect | Specification |
|---|---|
| Build | AT marker scan sink inventory extended to Fleet DB, agent messages, SIEM targets, connector payloads, licence files, support bundles and vendor ticketing (38 RM-9 exit); compromise drills with vendor and IdP as adversary |
| Verify | AT-001..AT-019 on EE profiles; AT-031/AT-032 vendor union drill subsets |

### RM9-S8 EE module boundary audit

| Aspect | Specification |
|---|---|
| Build | 37 A12 (38 calls it "A6 audit (EE modules)") plus A1 scoped multi-tenancy pentest and A8 for EE-ONPREM per 37 "EE 1.0 GA" row |
| Verify | Published reports; 0 open Critical/High |

## 4. Auditor threat checklist (component-specific)

| # | Check | Threats |
|---|---|---|
| 1 | Can any EE module link into or call trust-path internals, hold private keys, or receive plaintext outside Export Packages? | THR-027, THR-029 |
| 2 | Can Fleet Manager learn onion addresses, intake hosts, user lists or case activity finer than 24 §TEL? | THR-027, THR-039 |
| 3 | Can a Fleet command change routing, intake, logging, retention, escrow or floors, or be authored by the vendor? | THR-026, THR-027 |
| 4 | Can an IdP or SCIM change grant case access, delete key wraps, or bypass FIDO2? | THR-022, THR-020 |
| 5 | Is SAML/OIDC validation strict against wrapping, replay, alg confusion and audience confusion? | THR-022 |
| 6 | Does PIV validation leak login timing to external responders? | THR-036 |
| 7 | Is all `unsafe` confined to `candor-ffi` with documented invariants, and does HSM failure fail closed? | THR-013 |
| 8 | Can any SIEM export carry source-sensitive data, free text or canaries? | THR-016, THR-038 |
| 9 | Can connectors push data without dual-approved Export Packages, or follow redirects? | THR-029 |
| 10 | Are all EE queries tenant-scoped (no cross-tenant update/delete)? | THR-021, THR-045 |

## 5. Test plan

| Test | Command / tool | Gate |
|---|---|---|
| Boundary | `cargo tree -p <ee-crate> \| rg -q 'candor-(intake\|sealer\|source)' && exit 1` | RM-004 |
| Unit/fuzz | `cargo test --workspace --locked` (ee repo); fuzz agent/command/SAML parsers ≥ 1 h nightly | SG-07 |
| unsafe | `cargo geiger -p candor-ffi`; `cargo kani -p candor-ffi`; `cargo miri test` where FFI is mocked | SI-A-04 |
| Authz | ST-060..ST-070 incl. EE audiences; ST-164 | SG-08 |
| SSRF | ST-076 on OIDC discovery, SIEM and connector URLs | SG-08 |
| SSO negative corpus | SAML signature-wrapping and OIDC replay suites | RM9-S2 |
| SIEM canary | ENT-018 job at enablement + monthly | SG-10 |
| Anonymity | AT-001..AT-019 on EE profiles; AT-031/AT-032 | SG-10/SG-11 |
| Audit | 37 A12, A1 scoped, A8 | RM-9 exit |

## 6. OPSEC checklist

| Exposure | Control |
|---|---|
| Vendor learns customer deployments | Opaque instance IDs, no onion DB, day-granular check-in, Tor transport |
| Vendor learns staff identities | No user lists in Fleet; support bundles strip staff names |
| IdP learns case activity | IdP sees only first-factor logins; no case attributes in assertions or SCIM |
| CA/OCSP responders learn login times | Cached CRLs/stapling |
| SIEM retains sensitive events long term | Allow-list, no SOURCE-SENSITIVE, CASE only DANGEROUS and day-granular |
| HSM vendor telemetry | Disabled; HSM logs local SECURITY class |
| Records systems receive more than intended | Dual-approved, redacted packages; destination recorded |

## 7. Exit criteria

| Type | Criterion |
|---|---|
| Roadmap (38 RM-9) | ENT privacy-risk mitigations verified; AT marker scan extended to EE modules and fleet/support flows; EE module audit (37 A12) |
| Spec gates | SG-05, SG-07, SG-08, SG-10, SG-11 on EE profiles; ENT-001..ENT-019 verified |
| Audit gate | Each step RM9-S0..S8 audited independently (`process/audits/AUDIT-RM9-Sn.md`); 0 open Critical/High; Medium fixed or lead-accepted in writing |
| Milestone record | Signed RM-9 report logged (RM-005) |

## 8. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| IMP-RM9-001 | EE modules SHALL NOT depend on intake, sealer or source crates, SHALL hold no private keys, and SHALL receive plaintext only through Export Packages. | ADR-020; RM-004 | THR-027, THR-029 | C-34 | TST: CI boundary job; AUD: A12 |
| IMP-RM9-002 | Fleet Manager SHALL store only the 21 §9.2 fields with a random 128-bit instance ID and SHALL NOT store onion addresses, intake hostnames or IPs, user lists or CASE audit events. | 21 §9.2; ADR-022 | THR-027 | C-34 | TST: schema test; AT-001 on Fleet DB |
| IMP-RM9-003 | The instance agent SHALL execute only allow-listed commands signed by the customer-held key and SHALL refuse changes to routing, intake, logging, retention, escrow or security floors. | ADR-045; ADR-040; ENT-008 | THR-026, THR-027 | C-34 | TST: agent refusal suite; AUD: A12 |
| IMP-RM9-004 | The agent SHALL run only in Z-ADM or Z-CORE, reach C-34 over Tor or a customer-hosted endpoint, and authenticate peers from the transport. | 21 §9.3; INC-103 | THR-027, THR-001 | C-34 | ST-097; ST-122 |
| IMP-RM9-005 | IdP assertions SHALL serve only as a first factor; no assertion, SCIM operation or group mapping SHALL grant case or channel key access or delete key wraps. | ENT-015; ENT-016; ADR-044(1) | THR-022, THR-020 | C-21 | ST-060..ST-070; TST: SCIM negative suite |
| IMP-RM9-006 | SAML and OIDC processing SHALL reject signature wrapping, replay, algorithm confusion, audience mismatch and unpinned issuers. | INC-105; ADR-029 | THR-022 | C-21 | TST: SSO negative corpus; ST-076 |
| IMP-RM9-007 | PIV/CAC validation SHALL use cached CRLs or stapled OCSP and SHALL NOT query external responders per login unless configured with a warning. | ENT-017; INC-57 | THR-036 | C-21 | TST: login network capture |
| IMP-RM9-008 | All PKCS#11 `unsafe` code SHALL be confined to `candor-ffi` with documented invariants and Kani-checked preconditions, and HSM failure SHALL fail closed with no fallback key. | SI-A-04; ADR-046(2) | THR-013 | C-29 | TST: Kani; TST: HSM-down fault test; INSP |
| IMP-RM9-009 | The SIEM exporter SHALL emit only allow-listed SECURITY/SYSTEM fields, SHALL never export SOURCE-SENSITIVE data, and SHALL pass a canary test at enablement and monthly. | ENT-014; ENT-018; INC-60 | THR-016, THR-038 | C-26 | AT-001 (SIEM sink); TST: ENT-018 canary job |
| IMP-RM9-010 | Connectors SHALL transmit only dual-approved, redacted Export Packages encrypted to the Connector Key, SHALL record destinations, and SHALL NOT follow redirects. | ADR-018; ENT-019; INC-104 | THR-029 | C-40 | TST: export E2E; TST: redirect test |
| IMP-RM9-011 | The anonymity marker scan SHALL include Fleet, SIEM, connector, licence and vendor-support sinks before RM-9 exit. | RM-002; INC-56 | THR-016, THR-027 | C-31 | AT-001..AT-019 (EE profiles) |
| IMP-RM9-012 | Licence validation SHALL work offline with no phone-home. | ADR-023; 24 | THR-036, THR-027 | C-35 | TST: offline licence test with egress blocked |

## 9. Residual risks and open issues

| # | Item | Handling |
|---|---|---|
| R1 | A customer IdP or MDM controlled by management can still observe staff logins and endpoints | ADR-043 independent-custody devices for INDEPENDENT channels; disclosed |
| R2 | SIEM operators may correlate Tor alerts with hotline use | Customer policy (22 GOV-017 pattern); not a technical control |
| R3 | SAML library ecosystem in Rust is thin | Library selection record + A12 focus; consider OIDC-only first |
| R4 | Vendor-hosted Fleet still learns check-in days and instance count | Disclosed; customer-hosted option |
| OI-1 | 38 "A6 audit (EE modules)" corresponds to 37 A12 | Cross-document request |
