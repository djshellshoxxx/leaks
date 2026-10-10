# Completeness Checklist

Status: v1.0 final (2026-09-30). Verified after revision rounds 2–3 (ADR-034..047), with `tools/traceability.py` reporting 2,200 requirements, 0 errors, 0 warnings, every catalogued threat covered by ≥1 requirement, and `tools/constants_lint.py` reporting 0 conflicts.

Each item names where it is specified (primary → supporting) and how it is verified. "Residual" points to the honest limits.

| ✔ | Item | Primary specification | Verification | Residual / limits |
|---|---|---|---|---|
| [x] | Source anonymity | 03 §2–§8, DECISIONS ADR-001..005, 030, 033, 037–039, 047 | 30 AT-001.., drills AT-020.., inferential AT-080.. | 03 residuals; REVIEW-REPORT §6 |
| [x] | Anonymity limitations | 03 (protected-from-whom), 02 residual ratings, 40 ASM-*, 05 | 37 anonymity review (A3) | stated per protection |
| [x] | Tor | 16 (torrc, PoW, vanguards, onion keys, Arti plan) | 29/30 network tests; A3 | THR-003/004 residual |
| [x] | I2P | 16 §comparison, 00 §Tor vs I2P, ADR-001 (rejected for v1; transport abstraction) | admission criteria in 16 | re-evaluation RM-12 |
| [x] | Traffic correlation | 00 attack literature (practical/lab/theoretical), 16, 05, ADR-038 | AT timing tests | not preventable at network layer |
| [x] | Source OPSEC | 05 (normal/high-risk tracks, GC cards) | 30 usability study | behaviour-dependent |
| [x] | Recipient OPSEC | 12 (RO-01..), 32 recipient/investigator guides, ADR-043 | DEMO: operational exercises (31) | managed-endpoint residual |
| [x] | Document metadata | 05, 10 (per-format handling, MAT2/qpdf in sandbox), 11 metadata warning | 29 hostile/metadata corpus | watermarks, canary traps, stylometry |
| [x] | Malware | 10 containment levels, ADR-012, ADR-042 | 29 hostile-file corpus, malicious-server harness | platform-tier limits |
| [x] | Cryptography | 04, ADR-006..008, 030, 033, 047 | KAT/Wycheproof/fuzz/formal model (29, 37 A1) | 40 crypto assumptions |
| [x] | Key management | 04 key table (who holds / what decrypts / if stolen), 19, 21 HSM | 29 key tests; 31 key-theft playbooks | recovery-quorum trade-off |
| [x] | Legal-compulsion architecture | 03 §10 compulsion tables, ADR-035, 24 | AT compromise/compulsion drills | Tier W live-compulsion residual |
| [x] | Malicious administrators | 15 (admin ≠ case access), ADR-015, 045, 32 HUM-* | AT-0xx "steal admin credential" drill | infra-control residual |
| [x] | Insider threats | 02 ADV-*, 20 audit, 32 HUM-*, ADR-036/044/045 | 29 dual-control tests | coercion (THR-116) |
| [x] | File handling | 10, 08 upload protocol (canonical), ADR-027 safe-fs | 29 upload/path/archive attacks | — |
| [x] | Chain of custody | 10 EVID-*, 14, 20 CASE events | 29 evidence integrity tests | — |
| [x] | Case management | 14 (ISO 37002 mapping, SLA engine, lifecycle) | 29/30 workflow tests | — |
| [x] | Conflict-of-interest routing | 14 §8, ADR-030, 037 (triage-first, blinded COI) | AT exclusion-inference tests | checklist answers hint at subject |
| [x] | Authentication | 15 (WebAuthn/FIDO2, PIV/CAC, SSO first-factor only, source passphrase) | 29 authn suites | — |
| [x] | Authorization | 15 (RBAC+ABAC+ACL+COI, break-glass, dual control), ADR-029 | 29 IDOR/cross-tenant/authz suites | — |
| [x] | Frontend | 11 source, 12 recipient, 13 admin/SOC/enterprise | 26 a11y tests; 30 fingerprint tests | — |
| [x] | Backend | 07 | 29 | — |
| [x] | API | 08 (every endpoint: method, path, authz, I/O, rate limit, errors, sensitive data, logging, security) | 29 API suites | — |
| [x] | Database | 09 (schema, classification, RLS, linkability analysis) | 30 DB drills; schema lint | WAL/residue per 03 |
| [x] | Deployment | 18 (8 profiles × 9 attributes; installers; IaC; offline; rollback) | 29 upgrade/rollback tests | — |
| [x] | Monitoring | 32 self-test (27 checks), 17 alert relay, 13 SOC UI | 30 health-leak tests | — |
| [x] | Privacy-preserving logging | 20, ADR-016 | AT marker scan across 22 sinks | — |
| [x] | Backups | 19, ADR-025/033/044/047 | restore drills | ≤14-day erasure window |
| [x] | Deletion | 35, ADR-025, 033(3), 047(8–9) | 29/30 deletion verification | "delete ≠ physical erasure" table |
| [x] | HA | 21 HA-*, 34 (observer inventory), ADR-032, 046(1) | failover drills | extra observers listed |
| [x] | Disaster recovery | 19 DR-*, ADR-047(7) | DR drills | vault-loss procedure |
| [x] | Physical compromise | 17 PHYS-*, seizure analysis | 31 seizure playbook | — |
| [x] | Forensic seizure | 17 seizure table (source/recipient/admin device, app server, DB, backup, HSM) | AT seizure drills | source device residue (05) |
| [x] | Supply chain | 28 (incident→requirement table), ADR-022, 040 | 29 SCM gates; 37 A4 | — |
| [x] | CI/CD | 28 (Actions hardening, isolated builders), 27 gates | SG gates | — |
| [x] | Reproducible builds | 28, 33, ADR-022 (≥2 builders, ≥2 orgs) | rebuild verification (37) | builder independence (40) |
| [x] | Updates | 33 (TUF, thresholds, floors, emergency cooling), ADR-040 | 29 update/rollback/freeze tests | — |
| [x] | Incident response | 31 (14+ playbooks: DETECT/CONTAIN/PRESERVE/NOTIFY/ROTATE/RECOVER/LESSONS) | tabletop exercises | — |
| [x] | Security testing | 29 (ST-001..178, CI gating matrix) | — | — |
| [x] | Anonymity testing | 30 (AT-001..094; marker scans, compromise drills, inferential tests, usability study) | — | — |
| [x] | Independent auditing | 37 (A1–A17, schedule, disclosure, CVE, bug bounty) | published reports | — |
| [x] | Accessibility | 26 (WCAG 2.2 AA, EN 301 549 v4.1.1, Section 508, ADA Title II) | 26 test plan incl. AT users | Tor Browser defaults |
| [x] | Localization | 26 I18N-*, 11 RTL, ADR-047(6) per-locale wordlists | pseudo-localization tests | — |
| [x] | Small-business deployment | 23 SMB-*, 18 simple installer, ADR-045 small-org mode | DEMO: install → checker green | reduced SoD disclosed |
| [x] | Enterprise deployment | 21, 18 EE profiles | 29/30 EE extensions | — |
| [x] | Municipal government | 22 per-level table | — | — |
| [x] | State/provincial government | 22 | — | — |
| [x] | Federal government | 22 (FIPS, FedRAMP 20x, CJIS, PIV/CAC, records law), ADR-044(3) | 37 A-audits | — |
| [x] | Compliance | 25 control mappings (never "makes you compliant") | evidence artefacts per control | customer responsibilities |
| [x] | Community Edition | 23 (full feature set; parity table) | same tests as EE | — |
| [x] | Enterprise/Government Edition | 21, 22 | — | — |
| [x] | Sustainable open-source business model | 24 (AGPL + charter; revenue without data incentives; telemetry schema), 36 | — | funding risk (38) |
| [x] | Documentation | 32 operational guides; README; each spec | — | — |
| [x] | Lifecycle maintenance | 32 maintenance calendar, 33 LTS/channels, 36 governance/succession, 38 roadmap | — | — |

## Known open items (tracked, not blocking the specification)

- Research items marked UNVERIFIED in `00-RESEARCH.md` §1 (blocked primary sources) must be re-checked before the affected decisions are frozen in implementation (RM-1 exit).
- Each document's "Open issues" section lists remaining implementation-level questions; none contradicts a binding ADR.
- 87 reviewer findings: see `REVIEW-REPORT.md`. Status is computed strictly (weakest disposition across affected documents). "Partially fixed" means the design change landed and a documented residual remains.
