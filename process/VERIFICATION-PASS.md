# Verification Pass — 2026-10-01

Scope: UNVERIFIED / [K] items in `specs/00-RESEARCH.md` (104 UNVERIFIED occurrences before this pass, 87 after) and research notes R1–R6, prioritising items that drive design decisions.

Method and access limits:
- Most primary hosts were blocked to direct fetch: datatracker/ietf.org, rfc-editor, csrc.nist.gov, iana.org, eur-lex, legislation.gov.uk, blog/gitlab.torproject.org, globaleaks.org, securedrop.org, osv/nvd, and github.com advisory pages (403).
- Primary sources actually read:
  - Shallow git clones: `dconnolly/draft-connolly-cfrg-xwing-kem` @2026-09-23 (tag -11), `hpkewg/hpke-pq` @2026-07-06 (tag -05), `freedomofpress/securedrop`, `freedomofpress/securedrop-client`, `freedomofpress/webcat` @2026-09-29, `globaleaks/globaleaks-whistleblowing-software` @2026-09-05, `OWASP/ASVS`, `mikeperry-tor/vanguards`.
  - CVE List V5 records via raw.githubusercontent.com (`CVEProject/cvelistV5`).
  - Arti crate sources (`arti` 2.6.0, `arti-client`, `tor-hsservice` 0.46.0) from static.crates.io.
- Other items used WebSearch extracts of the primary page; the Source column says "(search extract)" for these. Nothing was fetched from a URL that is not listed here.
- Result meanings:
  - **CONFIRMED**: the claim matches the primary source.
  - **CORRECTED**: the claim was wrong, or an open question was resolved to a value different from what the notes assumed.
  - **STILL UNVERIFIED**: could not be settled from primary material.

## Results table

| Item (doc:line) | Original claim | Result | Correct value | Source (URL, date) |
|---|---|---|---|---|
| 00:441 F-011; R5:13,38-40 | X-Wing = HPKE KEM 0x647a; draft -11 Sep 2026, Informational | CONFIRMED | Draft -11 (tag 2026-09-23), `category: info`. The draft *requests* 0x647a for HPKE KEM and the TLS group ("25519 + 203 … (please)"). The TLS codepoint is not assigned. The IANA HPKE registry lists 0x647A (search extract). | https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem (tag draft-connolly-cfrg-xwing-kem-11, 2026-09-23); https://www.iana.org/assignments/hpke/hpke.xhtml (search extract, 2026-10-01) |
| 00:873 B-CR-06; R5:38-40 | draft-ietf-hpke-pq-05, 2026-07-06, Standards Track; 0x0040-42, 0x0050/51, 0x647a | CONFIRMED | -05 tagged 2026-07-06, `category: std`. IANA is asked to *replace* existing 0x0040-42 and 0x647a entries and add 0x0050/0x0051. Datatracker: IESG state "I-D Exists", no AD or shepherd. | https://github.com/hpkewg/hpke-pq (tag draft-ietf-hpke-pq-05); https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/ (search extract) |
| 00:875 B-CR-08; 00:40; R5:42,317 | RFC 10024 number/date UNVERIFIED | CONFIRMED | RFC 10024, *PQ/T Hybrid Key Agreement Mechanisms for TLS 1.3*, August 2026, Standards Track (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024) | https://www.rfc-editor.org/rfc/rfc10024.html (search extract, 2026-10-01) |
| 00:877 B-CR-11; R5:84 | AWS-LC 3 CMVP #5314, ML-KEM in boundary, sunset 2031 | CONFIRMED | #5314 "AWS-LC 3 Cryptographic Module (static)", FIPS 140-3 L1, Active, sunset 2031-06-04, ML-KEM listed | https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5314 ; https://sec-certs.org/fips/1e0b605fa2f516ae/ (search extracts) |
| R5:85 B-CR-12 | OpenSSL 3.5.4 FIPS certificate issuance by 2026-09 UNVERIFIED | CONFIRMED (not issued) | 3.5.4 is still in CMVP review with no certificate. Active OpenSSL FIPS certificates: #4985 (3.1.2, 140-3, to 2030-03-10); #4282/#4811 (140-2, end 2026-09-21). | https://openssl-library.org/news/fips-cve/index.html (search extract, 2026-10-01) |
| R6:263 | FIPS 140-2 sunset "Sept 2026" [K — exact date UNVERIFIED] | CONFIRMED | 2026-09-21 (140-2 certificate end date) | https://openssl-library.org/news/fips-cve/index.html (search extract) |
| R5:36 B-CR-03 | NIST IR 8547 still ipd (Nov 2024) as of mid-2026 | STILL UNVERIFIED | Secondary sources agree that IR 8547 is still ipd, with no final as of Oct 2026. csrc.nist.gov could not be fetched. | https://csrc.nist.gov/pubs/ir/8547/ipd (blocked); https://detectors.xygeni.io/xydocs/compliance/nist_pqc_transition.html (secondary) |
| R5:43 | FN-DSA (FIPS 206) status; HQC draft | STILL UNVERIFIED | Secondary sources say FIPS 206 is still a draft. No HQC draft standard was found. | encryptionconsulting.com (secondary, search extract) |
| R5:216 | SP 800-218r1 (SSDF 1.2) final status | STILL UNVERIFIED | The ipd (2025-12-17) is confirmed. Publication of a final version was not confirmed. | https://csrc.nist.gov/pubs/sp/800/218/r1/ipd (search extract) |
| R5:223 | CycloneDX 1.7 existence/date UNVERIFIED | CONFIRMED | Released 2025-10-21 | https://cyclonedx.org/news/cyclonedx-v1.7-released (search extract) |
| 00:545 F-115; R5:218 | ASVS 5.0.0 (2025-05-30), 17 chapters, ~350 reqs, ID `v5.0.0-x.y.z` | CONFIRMED | Version 5.0.0, May 2025 (tag `v5.0.0_release`). 17 chapters V1–V17, including V9 Self-contained Tokens, V10 OAuth/OIDC and V17 WebRTC. 345 requirements. ID format `v<version>-<chapter>.<section>.<req>`. The exact day (30 May) is not stated in the repo. | https://github.com/OWASP/ASVS (5.0/en, 0x01-Frontispiece.md; 0x03 line 157) |
| R5:224-227 B-CR-50 | CRA: reporting from 11 Sep 2026; full application 11 Dec 2027 | CONFIRMED | Art 71: notified-body provisions from 2026-06-11; Art 14 reporting from 2026-09-11; everything else from 2027-12-11 | https://www.springlex.eu/en/packages/cra/cra-regulation/article-71/ (OJ L 2024/2847 text mirror, search extract); https://www.jonesday.com/de/insights/2026/07/eu-cyber-resilience-act-24hour-reporting-duties-start-september-11-2026 |
| R5:163; 00:156 | WEBCAT alpha, v3.0.0 tag 2026-09-29, EF 1TS grant Aug 2026 | CONFIRMED | Readme: "experimental … alpha … might not yet provide the intended security guarantees"; tag v3.0.0; 1TS grant 2026-08-05 | https://github.com/freedomofpress/webcat (2026-09-29); https://blog.ethereum.org/2026/08/05/1ts-grant (search extract) |
| 00:156; R5:162 | WEBCAT Tor Browser integration "in progress" | STILL UNVERIFIED | The repo test harness supports Tor Browser and the Readme thanks a Tor Project developer. No primary statement on integration status was found. | https://github.com/freedomofpress/webcat |
| 00:39,486 F-056; R4:47 | Arti service-side PoW parity UNVERIFIED; client PoW behind non-default `hs-pow` | CORRECTED | Client and service PoW exist only behind the **experimental** `hs-pow-full` feature (arti 2.6.0, arti-client, tor-hsservice 0.46.0). No `hs-pow` feature exists. Service PoW is not in a stable feature set. | https://static.crates.io/crates/arti/arti-2.6.0.crate ; tor-hsservice-0.46.0.crate (Cargo.toml `[features]`), 2026-10-01 |
| 00:39,486,1006 F-056; R4:76-78 | Arti onion services not production-recommended (2026) | STILL UNVERIFIED | `onion-service-service` is a stable, non-default feature in 2.6.0. The only "not recommended for production" statement found is from 2024 (Arti 1.1.12). No 2026 primary statement either way. | crates.io arti 2.6.0; https://forum.torproject.org/t/arti-1-1-12-is-released-now-you-can-test-onion-services/11045 (search extract) |
| 00:489 F-059; R4:37,71 | Arti vanguards (full mode for services) | CONFIRMED | `vanguards` is a default feature of arti 2.6.0 | crates.io arti 2.6.0 Cargo.toml |
| 00:39,489,1024 F-059; R4:71 | Python `vanguards` add-on maintenance status UNVERIFIED | CORRECTED (resolved: dormant) | No upstream commit since **2023-10-31**; latest tag **v0.3.1**. Treat as unmaintained. | https://github.com/mikeperry-tor/vanguards (HEAD 2023-10-31) |
| 00:846 B-AN-45; R4:76,224 | Arti 2.5.1 date UNVERIFIED | CONFIRMED | 2.5.1 released 2026-08-04. Arti 2.6.0 released 2026-09-01 (new). | https://forum.torproject.org/t/arti-2-5-1-released/21947 ; https://blog.torproject.org/arti_2_6_0_released/ (search extracts); index.crates.io/ar/ti/arti |
| 00:847 B-AN-46; R4:76,225 | Arti 2.0.0 date UNVERIFIED (early 2026) | CONFIRMED | 2026-02-02 | https://blog.torproject.org/arti_2_0_0_released/ (search extract) |
| R4:47; R1:252 | Tor 0.4.8 PoW (`HiddenServicePoWDefensesEnabled`), blog 2023-08-23 | CONFIRMED | Released with 0.4.8 on 2023-08-23 | https://blog.torproject.org/introducing-proof-of-work-defense-for-onion-services (search extract) |
| 00:416; R4:106,130 | No public third-party audit of Java I2P / i2pd (negative) | STILL UNVERIFIED | Two searches found no audit report. A negative cannot be proven from primary material. | (searches 2026-10-01) |
| 00:409; R4:49,117 | Tor Metrics: millions of daily users; ~7–8k relays | STILL UNVERIFIED | Only secondary dashboards were reachable, and they report about 10.7k relays, which conflicts with ~7–8k. Recheck metrics.torproject.org. | metrics.torproject.org (blocked) |
| 00:413; R4:85 | Onion Browser status | STILL UNVERIFIED | Not resolved | — |
| 00:850 B-AN-49 | TB 13.5 month UNVERIFIED | CONFIRMED | 2024-06-20 | https://blog.torproject.org/new-release-tor-browser-135/ (search extract) |
| 00:809 B-AN-08; R4:187 | Tor blog *Tor is still safe*, URL UNVERIFIED | CORRECTED (title) | URL confirmed. The title is *Is Tor still safe to use?* (2024-09-18). | https://blog.torproject.org/tor-is-still-safe/ (search extract) |
| 00:824 B-AN-23; R4:202 | Relay-early advisory 2014-07-30 (day UNVERIFIED) | CONFIRMED | 2014-07-30 | https://blog.torproject.org/node/893 (search extract) |
| 00:750 B-INC-66; R3:743 | xz disclosure URL UNVERIFIED | CONFIRMED | https://www.openwall.com/lists/oss-security/2024/03/29/4 | search index of openwall.com; mirror https://seclists.org/oss-sec/2024/q1/274 |
| R1:140 B-SD-35; 00:134 | CVE-2026-35465 fixed version conflict (0.17.3 vs 0.17.5) | CORRECTED | Affected ≤0.17.4, fixed **0.17.5**; 0.17.3 was skipped. CVE published 2026-04-18, CVSS 7.5. | https://github.com/CVEProject/cvelistV5 (cves/2026/35xxx/CVE-2026-35465.json); securedrop-client `changelog.md` §0.17.5 |
| 00:133; R1:143,205,326 B-SD-22 | CVE-2026-71863 (GHSA-rqwh-4873-322p) | STILL UNVERIFIED | No CVE List record exists. The GHSA page returned 403. SecureDrop 2.16.1 changelog confirms the fix ("only copy specified GPG pubkeys and not the entire directory"). Cite the GHSA ID only. | https://github.com/CVEProject/cvelistV5 (404 for CVE-2026-71863); securedrop `changelog.md` §2.16.1 |
| R2:598 | CVE-2026-70655 (GHSA-9vhh-65v7-3xj6) | STILL UNVERIFIED | No CVE List record. The fix is consistent with GL 5.0.97 "Correct reports listing on platforms still without encryption". | cvelistV5 (404); GL CHANGELOG 5.0.97 |
| 00:37,133,136 (CVE list) | CVE-2026-50000, -45020, -46647, -46648 | STILL UNVERIFIED | No CVE List records for any of the four (404) | https://github.com/CVEProject/cvelistV5 (checked 2026-10-01) |
| 00:134,136; R1:138-146 | CVE-2025-24888/24889, CVE-2026-49996, -54706, -54707, -33284, CVE-2024-41671 | CONFIRMED | Records exist. 49996: securedrop-client <1.3.1, CVSS 3.7, published 2026-08-20. 33284: GL <5.0.89, GHSA-84wr-q36q-wqhv. 41671: Twisted ≤24.3.0, fixed 24.7.0rc1. | https://github.com/CVEProject/cvelistV5 |
| 00:191 A-28; R1:147 | OnionShare CVE-2021-41867/41868 (from memory) | CONFIRMED | 41867: chat participant list of a non-public node disclosed. 41868: unauthenticated upload to a non-public node in receive mode. Both affect 2.3 before 2.4; published 2021-10-04; the CNA gives no CVSS. | cvelistV5 cves/2021/41xxx |
| 00:136,200 A-37; R2:219,591,711 B-GL-19 | ISGroup 2026 "29 confirmed vulnerabilities" UNVERIFIED | CONFIRMED | 29 confirmed, 2 High, no Critical, 12 DoS observations; audit 2026-06-01..30; fixes start in 5.0.96 | https://globaleaks.org/2026/07/30/globaleaks-strengthens-security-against-ai-enabled-threats/ (search extract) |
| 00:136 "8 external audits"; R2 audit table | GL audit list 2013–2026 | CONFIRMED | 8 audits: iSEC 2013, Cure53 2013, LeastAuthority 2014, Subgraph 2018, ROS 2019, ROS 2022, ISGroup 2024, ISGroup 2026 | GL repo `documentation/technical/security/security-audits.rst` |
| 00:196,197 A-33/A-34; R2:586,587 | LeastAuthority fixes in 2.60; 3.3.0 SSRF/stacktrace | CONFIRMED | 2.60 (2014-04-22) "solve the issues spotted by LeastAuthority code audit"; 3.3.0 (2018-08-06) "Fix SSRF issue on HTTPS Proxy", "Disable Error Stacktrace" | GL `CHANGELOG` |
| 00:195 A-32; R2:582-585 | Cure53 GL01-002/-003/-004/-011 details and severity | STILL UNVERIFIED | Report PDF not reachable | — |
| 00:198 A-35; R2:588,590 | ROS 2019 and ISGroup 2024 contents | STILL UNVERIFIED | — | — |
| 00:134,186,916 A-23 B-CR-55; R5:272 | X41 2026 SDW review contents UNVERIFIED | CONFIRMED | 4 vulnerabilities, 2 fully mitigated during the audit, none easily exploitable. Informational: commit-signing enforcement gaps, weak hash algorithms, no mitigation for compromised submission keys. | https://www.x41-dsec.de/security/research/job/news/2026/04/21/securedrop-review-2026/ (search extract) |
| 00:36,133,165,611 A-02 B-SD-43; R1:115-120,347 | Pre-2020 SD audit list UNVERIFIED | CONFIRMED (list); contents mostly STILL UNVERIFIED | UW + Schneier spring 2013; Cure53 late 2013 (no critical, 11 low–medium); iSEC 2014 (no critical, 2 High); iSEC 2015; Leviathan late 2018; Include Security SDW Nov 2018 | https://docs.securedrop.org/en/stable/what_is_securedrop.html ; https://freedom.press/news/securedrop-undergoes-second-security-audit/ ; https://freedom.press/tech/news/announcing-the-new-version-of-securedrop-with-the-results-from-our-third-security-audit/ (search extracts) |
| 00:164 A-01, 178 A-15, 181 A-18 | UW assessment contents; Orrù audit contents; 7ASecurity per-ID severity | STILL UNVERIFIED | — | — |
| R6:91,94 | Directive Art 9(1)(b) 7 days; 9(1)(f) 3 months | CONFIRMED | Matches; 9(1)(f) wording confirmed verbatim | https://www.legislation.gov.uk/eudr/2019/1937/chapter/II (search extract; fetch blocked) |
| R6:101 | Directive Art 16(2)–(3) | CONFIRMED | "necessary and proportionate obligation imposed by Union or national law…"; inform beforehand unless it would jeopardise investigations; explanation in writing | https://www.legislation.gov.uk/eudr/2019/1937/chapter/V/data.html (search extract) |
| R6:100,96 | Directive Art 16(1); Art 9(2) | STILL UNVERIFIED ([K]) | No verbatim text obtained | — |
| R6:140-142 | GDPR Art 15(4); Art 23 | CONFIRMED | Art 15(4) verbatim; Art 23(1) opening text matches | https://gdpr-info.eu/art-15-gdpr/ ; https://gdpr-text.com/en/read/article-23/ (OJ text mirrors) |
| R6 other [K] / UNVERIFIED (ISO 37002/37001, US/CA/UK/AU statutes, CNIL list, EDPS retention, Art 27(3) report, Poland C-147/23, etc.) | various | STILL UNVERIFIED | Not attempted in this pass | — |
| 00:63,75,88,101,127,140 B-GL-44; R2 §5 | All commercial-vendor claims | STILL UNVERIFIED | Not attempted (vendor sites blocked) | — |
| 00:69,94,97,100,102,107,108,121,123,126,128,138,212 | SDW Electron posture, SSD erase, GL antivirus claim, HL backups, P3 IP claim, Noble grsecurity, SDW RPM repo, VPATs, Texas §414.008, CoverDrop audit | STILL UNVERIFIED | Not attempted | — |
| 00:382,392,393,399,414,419 | WF/canary citations, Overdorf/Jansen, Evans/Sniper/Point Break, Tor design paper URL, I2P PT ecosystem, I2P platform precedent | STILL UNVERIFIED | Not attempted | — |
| 00:575 B-SD-07, 605, 643 (2024 PDF), 678, 687, 699, 742, 772, 783-795, 810, 811, 815, 819, 830 (dates), 833, 844, 849, 883, 894, 904, 913, 992 | Bibliography URLs/dates (Hushmail, Whisper, Krebs, Wyden, Efail, MEGA, ROCA, Nextcloud, INC-103..111, Øverlier, Biryukov, Panchenko, Cherubin, Conjure, Winner, Deprecation wiki, Albertini, PKCS#11, rbm, zipbomb, state statutes) | STILL UNVERIFIED | Not attempted (budget). No URL invented. | — |

## Counts

- Table rows: **CONFIRMED 27** (one row is "list confirmed, contents still unverified"; another is OpenSSL 3.5.4 "confirmed not issued"), **CORRECTED 4** (Arti PoW feature and status; `vanguards` add-on dormant; CVE-2026-35465 fixed version; B-AN-08 title), **STILL UNVERIFIED 20** (including the bulk rows that were not attempted).
- `specs/00-RESEARCH.md` UNVERIFIED occurrences went from 104 to 87. This pass added 25 verified tags there and 34 verified or corrected tags across R1–R6.

## Spec impacts (not edited; owners must act)

1. **`vanguards` add-on dormant since 2023-10-31 (v0.3.1).** These sections make the add-on a requirement or plan around it:
   - DECISIONS.md:192 (ADR-001) and :435 (ADR-046(9)).
   - 16-TOR-I2P.md:57, 69, 88, 217, 222, 230, 527 (HIGH profile requires the add-on "while it is maintained" and has a maintenance gate).
   - 06-SYSTEM-ARCHITECTURE.md:629.
   - 28-SUPPLY-CHAIN.md:136.
   - 02-THREAT-MODEL.md:1124 (OI-07).
   - 40-SECURITY-ASSUMPTIONS.md:716.

   The maintenance gate is now evidently failing, so the documented fallback (vanguards-lite, or Arti `vanguards`) should be made the HIGH-profile default.
2. **Arti PoW feature name and status.** The feature is the experimental `hs-pow-full`; there is no `hs-pow`, and service PoW is experimental. Affected:
   - 16-TOR-I2P.md:253 ("client PoW enabled via the `hs-pow` feature"), :488 NET-017 (client PoW enabled in the Source App), :260 AM-2 (service-side PoW parity), :543 OI-4.
   - 38-IMPLEMENTATION-ROADMAP.md:47 RM-12.

   Shipping NET-017 means building against an `__is_experimental` feature.
3. **CVE IDs with no CVE List record.** They are not corrected, but specs cite them as evidence:
   - CVE-2026-46648: DECISIONS.md:262, 294; 04:827; 18:708 DEP-027; 21:261, 479, 480; 27:343; 29:164; 39:1225, 1394, 1565, 1566.
   - CVE-2026-46647: DECISIONS.md:327; 02:694; 15:406; 21:488; 25:308; 39:1230, 1517, 1574, 1703.
   - CVE-2026-45020: DECISIONS.md:327; 02:694; 15:330, 409; 27:344; 39:1233.
   - CVE-2026-50000: DECISIONS.md:327; 15:142; 29:36; 39:1214.

   Cite GHSA IDs instead until CVE records exist.
4. CVE-2026-35465 fixed version: no spec depends on the version. No impact.
