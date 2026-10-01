# IMPL-RM7 — CE 1.0 GA: threshold signing, TUF repository, transparency log and witnesses, two-builder verification, bug bounty, advisories/CVE, LTS

Status: Draft v1.0 (2026-10-01) · Edition applicability: both (release infrastructure is shared; CE first) · Owner: T7 Supply Chain & Release; Security Lead (VDP, advisories, bounty); governance (36) for keyholder and builder selection · Roadmap milestone: RM-7

Global rules are in `IMPL-00-SECURE-IMPLEMENTATION-STANDARD.md` and are not repeated. Rule ID sources as in `IMPL-RM5-OPERATIONS.md`.

## 1. Purpose and scope

| Item | Content |
|---|---|
| Goal | Ship CE 1.0 so that no single person, organisation, jurisdiction, build machine or mirror can deliver a modified trust-path artifact that clients accept unnoticed, and so that vulnerabilities are received, fixed and disclosed on a published schedule |
| Components | C-31 (Builders A/B, independent rebuilder), C-32 (offline threshold keys, TUF repository/publisher, transparency log integration, monitors), C-33 (mirrors incl. project onion mirror), C-30 (forge, tag signing), C-37 (security.txt), VDP onion reporting instance (a Candor deployment run by the project) |
| Spec sections | 33 §4–§13, §17–§18 (artifacts, builders, gating, TUF roles, log, rollback/freeze, channels incl. `lts`, emergency procedure, rotation, compromise and malicious-release response, SBOM, operator verification); 28 (SCM gates, keyholders SCM-042/046, mirrors SCM-069); 36 §3.4 (keyholder spread); 37 §6–§11 (VDP, advisories/CVE, CRA, severity/AIR, bounty, CE/EE disclosure, publication); 27 SG-13/14/23 |
| Out of scope | Update client (RM-5); Source App and WEBCAT bundle targets (RM-8) except their TUF roles being created here |

## 2. Preconditions

| # | Precondition |
|---|---|
| P1 | RM-6 exit: RM6-A1..A4 published, 0 open Critical/High |
| P2 | Keyholders selected per 33 §6.1 and 36 §3.4: root 5 holders in ≥ 3 organisations and ≥ 3 jurisdictions, ≤ 2 keys per organisation or jurisdiction, ≥ 1 civil-society holder, nobody holds > 1 root key; targets 3 holders in 3 organisations and 3 jurisdictions |
| P3 | Builder B operated by a different organisation in a different jurisdiction on different infrastructure, admins and CI software (33 §5.1; ADR-040) |
| P4 | ≥ 2 independent monitors and ≥ 3 witnesses committed (33 §7) |
| P5 | Counsel review of safe-harbor text and CRA role determination (37 §7.1, §9.3) |
| P6 | Hardware: FIDO2/PIV-class tokens for every signer, air-gapped root ceremony workstation image (reproducible, from RM-0), online HSMs for snapshot/timestamp |

## 3. Build sequence

### RM7-S1 Production key ceremonies (root, targets, delegated roles, auxiliary keys)

| Aspect | Specification |
|---|---|
| Build | Ceremony scripts (`release/ceremony/`) for root 3-of-5, targets 2-of-3, delegated product roles (`server`, `desk`, `source-app`, `web-bundle`, `oci`, `appliance`, `platform`) 2-of-3, `ee-modules` terminating delegation; hybrid key pairs Ed25519 + ML-DSA-65 (ADR-006); APT archive key, cosign key, WEBCAT Sigsum signer keys, log submitter key (33 §6.2) |
| Rules | Keys generated on the token or on the air-gapped ceremony workstation and never exported in plaintext; ceremony workstation booted from a verified, reproducible image with no network hardware enabled; script refuses when signer identity = release author identity = Builder B operator (SL-R-010); transcript, video-free attendance list and public key fingerprints logged in the transparency log; first root ceremony observed by the 37 A9 auditor; `root.json` v1 embedded in client builds and published out of band in ≥ 3 independent places (33 §18.1); RNG health checks and weak-key checks at generation (ST-028) |
| Pitfalls | INC-58 (Storm-0558: signing key exposed via crash dump → no crash dumps on ceremony machines, `LimitCORE=0`); INC-50 (Juniper: unauthorised key/parameter change → fingerprints logged and witnessed); INC-48 (CCleaner: signed backdoor → signatures alone insufficient, need reproducibility + log); INC-61 (ROCA: flawed hardware keygen → token model vetted, keys checked) |
| Verify | Ceremony dry run with TEST keys reproduces fingerprints from transcript; independent verification of `root.json` thresholds; A9 ceremony attestation |

### RM7-S2 TUF repository, publisher and mirrors

| Aspect | Specification |
|---|---|
| Build | Repository publisher holding snapshot (7-day expiry) and timestamp (1-day, re-signed every 6 h) keys in online HSMs; targets metadata with custom fields (`channels`, `security`, security floor, log proofs, reproducibility attestation hashes); Platform Manifest as `platform` target; mirrors as content-addressed caches incl. project onion mirror |
| Rules | Publisher and mirrors are separate systems; mirrors cannot sign and SHALL NOT store onion addresses, tenant names or per-request identifiers, logs limited to date/path/status, no IP > 24 h (33 §14.1); same metadata for every requester, no server-side selection (ADR-022); `security_hold` support in timestamp metadata (33 §13.2); metadata generation code is T0 and passes the IMPL-00 gate |
| Pitfalls | INC-49 (NotPetya: update server compromise), INC-52 (Linux Mint: download and hash on one server), INC-44 (tj-actions: CI secret exfiltration → publisher keys never in CI) |
| Verify | ST-130 against the production-shaped repository; ST-132 artefact+hash swap; endless-data/slow-retrieval tests; mirror log inspection |

### RM7-S3 Transparency log, witnesses and monitors

| Aspect | Specification |
|---|---|
| Build | Sigsum submission of every release bundle (artifact hashes, metadata versions, SBOM/provenance/rebuild attestation hashes, WEBCAT manifests, security holds); Rekor v2 secondary; inclusion proof + cosigned tree head embedded in TUF custom metadata; witness policy file (`w = 2` of ≥ 3) embedded in clients; open-source monitor tooling |
| Rules | Clients reject tree heads without the required cosignatures; monitors compare tree heads daily, check each entry against a signed tag and release note, rebuild within the cooling period, and publish results (33 §7); monitors and witnesses are independent of each other and of the project; Candor milestone reports (RM-005) and ceremony transcripts are logged too |
| Pitfalls | INC-14 (Anom: targeted builds) and split-view attacks; INC-37 (xz: release tarball differed from git → log source tarball hash, rebuild from tag) |
| Verify | ST-094 split-view/rollback detection; drill: publish a test entry with no matching tag → monitor alarm; witness-quorum failure test |

### RM7-S4 Reproducible verification by two builders and an independent rebuilder

| Aspect | Specification |
|---|---|
| Build | Builder A (project CI, ephemeral hardened workers, egress only to pinned mirror) and Builder B each build every artifact twice at different paths/times and diffoscope (33 §5.2); 37 A11 third-party rebuilder for 1.0; `REPRODUCIBILITY.md` listing every artifact's status |
| Rules | Both builders verify the signed tag against a pinned maintainers keyring inside the hermetic build and record it in provenance (R8 §1.7); `SOURCE_DATE_EPOCH` from tag, `--remap-path-prefix` for source, target and Cargo home (ADR-051(5)), `CARGO_INCREMENTAL=0`, `--locked --frozen`, no network; `cargo auditable` embeds dependency lists (R8 §4.4); SG-13 covers delta/patch targets and installer bundles, not only full packages (R8 §1.6); platform signatures applied only after hash agreement on unsigned payload (33 §5.2); builders hold no signing keys; an artifact that is not reproducible is not released on any channel |
| Pitfalls | INC-38 (SolarWinds: build-time injection), INC-41 (3CX: upstream compromise cascading), INC-37 |
| Verify | ST-131; `slsa-verifier verify-artifact --source-uri <repo> --source-tag <tag> <artifact>` with tampered-provenance negative test; diffoscope empty for every SBOM entry |

### RM7-S5 Release pipeline dry runs, GA release and post-release checks

| Aspect | Specification |
|---|---|
| Build | End-to-end release per 33 §5.3: tag → A/B builds → hash equality → log → targets signers verify locally and sign → cooling ≥ 72 h → veto window → snapshot/timestamp publish; emergency-path drill (≥ 2 h cooling, 2-of-3 signers from ≥ 2 organisations, published diff, intake applies ≥ 6 h after log publication) |
| Rules | Each targets signer independently verifies tag signature, both rebuild attestations, hash equality, SBOM diff and log inclusion on their own workstation before signing; nothing in 33 §10 "never relaxed" list is relaxed; GA artifacts identical for all customers; signed RM-7 milestone report logged (RM-005) |
| Verify | Two complete dry runs (normal and emergency) on staging with TEST keys; GA: post-release AT canary scan of the reference deployment clean (38 RM-7 exit); SSDF attestation generated from gate evidence (R8 §4.1) |

### RM7-S6 Vulnerability disclosure, advisories and CVE process

| Aspect | Specification |
|---|---|
| Build | `SECURITY.md` in every repo; `/.well-known/security.txt` on project site and C-37 templates; OpenPGP security key with fingerprint in ≥ 2 independent places (SCM-046); forge private reporting; **onion reporting channel** = a Candor instance operated by the project (production-grade, RM-5 operations applied); advisory template with AIR and anonymity impact statement (37 §7); signed security-announcement list; OSV publication via forge; CNA application within 12 months of 1.0; CRA Art. 14 runbook (37 §7.1) |
| Rules | Service levels of 37 §6.2 (ack ≤ 2 business days, ≤ 24 h for exploited/deanonymization); pre-notification ≤ 7 days before disclosure to a free list that requires no onion address or instance identity, with no exploit detail; EE receives no earlier or more detailed notice (ADR-020, 37 §10); every fixed vulnerability gets a CVE incl. internal findings; source-facing notice text in all supported languages when AIR ≥ A2; regulatory reports never include source data or customer onion addresses |
| Pitfalls | INC-07 (Riseup: lapsed canary and compelled silence → no warrant-canary promises the project cannot keep); INC-118 (production differed from tested config) |
| Verify | Tabletop: synthetic report through each channel to published advisory within SLA; SG-23 on first security release; advisory template lint (all mandatory sections present) |

### RM7-S7 Bug bounty

| Aspect | Specification |
|---|---|
| Build | Bounty lab instances (onion service + clearnet C-37 demo) labelled "TEST — do not submit real information"; scope/out-of-scope table and rewards (37 §9); safe-harbor text; pseudonymous payout options |
| Rules | Lab instances share no keys, hosts, onion addresses, credentials or mirrors with production or with the VDP instance; synthetic canary data only; testing of operator production instances is out of scope; supply-chain bypass in lab rewarded at Critical tier; lab rebuilt from release artifacts each release |
| Verify | ST-121 and AT-001 on lab; scope page review by counsel; payout process test |

### RM7-S8 LTS branch and backport process

| Aspect | Specification |
|---|---|
| Build | `lts-<year>` branch and TUF channel metadata (33 §9.1), 24-month support; backport workflow with the same review, builders, signers and cooling rules; embedded end-of-life date per version line (33 §15.1) |
| Rules | Branch protection identical to `main` (signed commits, two-party review, required SG gates); security floors per line in the Platform Manifest; CE and EE LTS lines identical and fixed simultaneously (37 §10); dependency pins on LTS still follow advisory floors (SI-A-09) |
| Verify | Backport drill of a synthetic fix to `lts` and `stable` with both builders; ST-107 from previous LTS patch |

### RM7-S9 Public assurance artefacts

| Aspect | Specification |
|---|---|
| Build | SSDF attestation from gate-evidence bundle; OpenSSF Best Practices Gold; Scorecard aggregate ≥ 9 (R8 §4.3); 37 A16 watcher and operator-statement programme review |
| Verify | Published badge/score; A16 report |

## 4. Auditor threat checklist (component-specific)

| # | Check | Threats |
|---|---|---|
| 1 | Can any one organisation or jurisdiction reach a root or targets threshold? | THR-024, THR-026 |
| 2 | Can the release author or a builder operator also sign targets/snapshot for the same release? | THR-024 |
| 3 | Can the publisher, a mirror or CI produce metadata clients accept as targets? | THR-025 |
| 4 | Could a client accept an artifact absent from the log or with a tree head cosigned by fewer than `w` witnesses? | THR-025 |
| 5 | Do builders verify tag signatures inside the hermetic build, and do both reproduce delta/installer artifacts? | THR-024 |
| 6 | Can the server side serve different metadata to different requesters? | THR-025, THR-026 |
| 7 | Do mirrors or the announcement list collect onion addresses, instance identity or IPs beyond 24 h? | THR-027, THR-001 |
| 8 | Can an emergency release skip two-builder agreement, two-party review, threshold, log or the ≥ 2 h cooling? | THR-025 |
| 9 | Do bounty labs or the VDP instance share secrets or infrastructure with production? | THR-044, THR-013 |
| 10 | Do advisories or CRA reports risk including source data or customer identifiers? | THR-016, THR-027 |
| 11 | Are ceremony machines free of networking, crash dumps and persistent storage of secrets? | THR-013 |

## 5. Test plan

| Test | Command / tool | Gate |
|---|---|---|
| Ceremony dry run | `release/ceremony/run --test-keys --role root` then independent `tuf verify` of resulting `root.json` | RM7-S1 |
| Update rejection | ST-130 against production-shaped repo | SG-19 |
| Hash swap | ST-132 | SG-14 |
| Reproducibility | ST-131; `diffoscope a/<artifact> b/<artifact>` empty for every SBOM entry | SG-13 |
| Provenance | `slsa-verifier verify-artifact` positive and tampered-negative | SG-14 |
| Split view | ST-094 with a forked log | — |
| Monitor | inject untagged log entry → alarm within one cycle | RM7-S3 |
| Emergency drill | E1–E8 timeline on staging with TEST keys | RM7-S5 |
| Canary | AT-001..AT-019 on reference deployment after GA | 38 RM-7 exit |
| VDP | tabletop per channel; advisory template lint | SG-23 |
| Scorecard | `scorecard --repo=<repo> --format json` ≥ 9 aggregate; required checks 10/10 | RM7-S9 |

## 6. OPSEC checklist

| Exposure | Control |
|---|---|
| Keyholder identities and locations | Published only at organisation level unless holders consent; travel to ceremonies not announced in advance |
| Ceremony recordings capturing PINs or screens | No video of token PIN entry; transcript only |
| Mirror and CDN logs of instance downloads | Minimal logs; project onion mirror recommended for Z-CORE too (RVW-C-13) |
| Announcement-list subscribers identify deployments | No instance identity required; subscribe via onion or alias address |
| VDP onion instance receives real reports | Operated under full RM-5 operations and IR procedures; staff roles separated from release signers |
| Bounty researchers testing real deployments | Out of scope; stop-and-report rule in safe harbor |
| Advisories reveal which customers were affected | Only versions/profiles; never customer names or onion addresses |

## 7. Exit criteria

| Type | Criterion |
|---|---|
| Roadmap (38 RM-7) | Release signed by threshold across ≥ 2 organisations (33 requires 3 for targets); transparency log entries witnessed; post-release canary scan of reference deployment clean; bounty live; advisories process live; LTS branch cut |
| Spec gates | SG-13, SG-14, SG-23 and all SG gates on the GA tag; R8 RM-7 items: two-party ceremony with production keys, SSDF attestation, Best Practices Gold; 37 "1.0 GA" row complete (reports published, full bounty, CNA application submitted, A9-observed root ceremony, A16 review) |
| Audit gate | Each step RM7-S1..S9 audited independently (`process/audits/AUDIT-RM7-Sn.md`), incl. ceremony scripts, publisher and monitor code; 0 open Critical/High; Medium fixed or lead-accepted in writing |
| Milestone record | Signed RM-7 report logged (RM-005) |

## 8. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| IMP-RM7-001 | Root (3-of-5) and targets/delegated (2-of-3) keys SHALL be held so that no organisation or jurisdiction can reach a threshold alone, with ≥ 1 root key held by an unaffiliated civil-society organisation. | ADR-022; ADR-040; INC-48 | THR-024, THR-026 | C-32 | INSP: keyholder register; AUD: A9 |
| IMP-RM7-002 | Each signing key SHALL be an Ed25519 + ML-DSA-65 pair and SHALL count toward a threshold only if both signatures verify. | ADR-006; 33 §6.1 | THR-025, THR-012 | C-32 | ST-130 hybrid cases; ST-021 |
| IMP-RM7-003 | The ceremony tooling SHALL refuse a signature when signer identity equals the release author or the Builder B operator. | SL-R-010; B-SL-01 | THR-024 | C-32 | TST: ceremony identity-check test; AUD: A9 attestation |
| IMP-RM7-004 | Ceremony and signing workstations SHALL have no network, no crash dumps and no persistent plaintext key storage. | INC-58; INC-50 | THR-013, THR-024 | C-32 | INSP: ceremony image config; AUD: A9 |
| IMP-RM7-005 | Snapshot and timestamp keys SHALL reside in online HSMs on a publisher separate from all mirrors and from CI. | INC-49; INC-44 | THR-025 | C-32 | INSP: infrastructure inventory; ST-130 |
| IMP-RM7-006 | Every release bundle SHALL be logged in Sigsum with inclusion proofs embedded in TUF custom metadata, and clients SHALL reject tree heads with fewer than `w = 2` pinned witness cosignatures. | INC-14; INC-52 | THR-025, THR-046 | C-32 | ST-094; ST-130 |
| IMP-RM7-007 | ≥ 2 independent monitors SHALL rebuild every release within the cooling period and SHALL be able to veto it. | 33 §7; §9.3 | THR-024, THR-025 | C-31 | DEMO: monitor veto drill; INSP |
| IMP-RM7-008 | Builders A and B (different organisations and jurisdictions) SHALL each verify the signed tag inside the hermetic build and produce bit-identical artifacts, including delta targets and installer bundles, before any signing. | INC-38; INC-37; ADR-040 | THR-024 | C-31 | ST-131; SG-13 |
| IMP-RM7-009 | Mirrors and the publisher SHALL serve identical metadata to every requester and SHALL NOT retain requester IPs beyond 24 h or store onion addresses or instance identifiers. | ADR-022; 33 §14.1 | THR-025, THR-027 | C-33 | TST: request-equality probe; INSP: log config |
| IMP-RM7-010 | Emergency releases SHALL keep two-builder agreement, two-party review, a 2-of-3 threshold from ≥ 2 organisations, log publication with the source diff, and a cooling period of ≥ 2 h. | ADR-040; 33 §10 | THR-025 | C-32 | DEMO: emergency drill; INSP |
| IMP-RM7-011 | The VDP SHALL offer an onion reporting channel, encrypted email and forge private reporting, and SHALL meet the 37 §6.2 acknowledgement and triage targets. | 37 §6; B-SD-41 | THR-026, THR-024 | C-30 | DEMO: VDP tabletop; INSP |
| IMP-RM7-012 | Every fixed vulnerability SHALL receive a CVE and an advisory with CVSS 4.0, AIR and an anonymity impact statement, published simultaneously for CE and EE. | 37 §7; ADR-020 | THR-024 | C-30 | SG-23; TST: advisory template lint |
| IMP-RM7-013 | Pre-notification SHALL require no onion address or instance identity and SHALL contain no exploit details. | 37 §6.3; ADR-022 | THR-027, THR-001 | C-30 | INSP: list sign-up form |
| IMP-RM7-014 | Bounty lab instances SHALL be labelled TEST, hold only synthetic data, and share no keys, hosts or credentials with production or the VDP instance. | 37 §9; INC-106 | THR-044, THR-013 | C-05 | ST-121; AT-001 on lab |
| IMP-RM7-015 | LTS lines SHALL have 24-month support, identical branch protection and release rules, embedded end-of-life dates, and simultaneous CE/EE fixes. | 33 §9.1; 37 §10 | THR-025 | C-32 | TST: backport drill; ST-107 |
| IMP-RM7-016 | A post-release canary scan of the reference deployment SHALL be clean before GA is announced. | RM-002; INC-60 | THR-016 | C-31 | AT-001..AT-019 |

## 9. Residual risks and open issues

| # | Item | Handling |
|---|---|---|
| R1 | Collusion of a root threshold across organisations | Spread rules, logging and monitors; re-bootstrap procedure (33 §12) |
| R2 | Monitors and witnesses may lapse for lack of funding | Budget in 24/36; client fails closed when witness quorum unavailable, which affects availability |
| R3 | Platform signatures (Authenticode, Apple notarization) cannot be reproduced | Hash agreement on unsigned payload; iOS residual (33 §20) |
| R4 | TUF hybrid key type is a Candor extension (33 OI-1) | Interop documented; A9 review |
| R5 | CRA role determination pending legal review | 37 §7.1 runbook; counsel sign-off is a precondition |
| OI-1 | 38 RM-7 states "≥ 2 organisations"; 33/ADR-040 require 3 organisations for targets and ≥ 3 for root | Implement the stricter 33 rule; cross-document request to align 38 |
