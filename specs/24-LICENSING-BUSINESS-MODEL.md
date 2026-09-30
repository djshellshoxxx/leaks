# 24 — Licensing, Business Model, Edition Charter and Telemetry
Status: Draft v1.1 (round-2 revision: ADR-031, 035, 045, 046) · Edition applicability: both · Owner: Governance & Product Leadership (with Legal)

## 1. Purpose and scope

This document covers:
- evaluation of licensing and business-model options;
- the license decision for each component (open AGPL, source-available, proprietary, or separate service);
- the trust implications of any closed component;
- revenue design that creates no incentive to collect data;
- the **Edition Charter** text;
- the complete **telemetry schema** and fingerprinting analysis;
- **§TEL, the canonical metrics regime** for every aggregate in the product (ADR-046 §5).

This is not legal advice. License interpretation must be confirmed by counsel (R6 note).

## 2. Context and dependencies

| Topic | Source |
|---|---|
| Edition decisions | `DECISIONS.md` §2, ADR-020, ADR-022, ADR-023, ADR-031, ADR-035(2), ADR-045, ADR-046(5) |
| Feature boundary | `21-ENTERPRISE.md` §3–4 |
| CE product | `23-COMMUNITY-EDITION.md` |
| Governance, DCO, trademark, CRA | `36-OPEN-SOURCE-GOVERNANCE.md` |
| Research | R6 Topic D (B-CO-50..66) |
| Incidents | R3 (INC-14, INC-53, INC-72) |

## 3. License option evaluation

| Option | Advantages | Disadvantages | Fit for Candor Trust Path |
|---|---|---|---|
| **AGPL-3.0-or-later** | Network clause (§13) forces hosted modified versions to publish source, closing the SaaS loophole. Aligned with GlobaLeaks (B-CO-50) and SecureDrop (B-CO-54). Strong trust signal. OSI/FSF approved, so it fits government open-source policies and FOSS grants. | Some enterprises ban AGPL internally. Dual licensing impossible without a CLA. EE modules must be separate works. | **Chosen** (ADR-020) |
| GPL-3.0 | Familiar | Hosted forks need not share changes | Rejected: the web service is network-used |
| MPL-2.0 | Easy open-core | New closed files allowed, so third parties can close up the product | Rejected for Trust Path |
| Apache-2.0 / MIT | Maximum adoption and reuse | Closed, modified forks under a different name, with no guarantee that the code sources rely on is the code running | Rejected for Trust Path services and clients; **chosen** (dual `Apache-2.0 OR MIT`) for the reusable libraries `candor-core` and `candor-safefs` only (ADR-031) |
| BSL / FSL / SSPL / ELv2 (source-available) | Protects against cloud free-riding | Not OSI. Trust damage and forks (HashiCorp→OpenTofu, Elastic, Redis; B-CO-60..63). Ineligible for many government OSS policies. | **Prohibited** for any Trust Path code |
| Open-core | Proven commercial model when the paid tier is organizational (R6 D1) | Controversy if protections move to paid | Chosen, bounded by the Charter |
| Dual licensing | Revenue from OEM/embedding | Requires a CLA; relicensing risk erodes trust (B-CO-60..62) | Rejected (DCO chosen; see `36-OPEN-SOURCE-GOVERNANCE.md`) |
| Support subscriptions | No code restriction; aligned incentives | Revenue scales with labor | Chosen |
| Managed hosting | Recurring revenue; serves SMEs and municipalities | Vendor becomes an observer (see `21-ENTERPRISE.md` E05) | Chosen, with dedicated intake and a disclosure inventory |
| Professional services | Deployment quality | Vendor staff as insiders | Chosen, with key-ceremony exclusion (ENT-024) |
| Enterprise modules (source-available commercial) | Monetizes scale and integrations | Not auditable by the public | Chosen **only outside the Trust Path** |

## 4. Per-component license decision

| Component | Class | License | Distribution | Reasoning |
|---|---|---|---|---|
| C-03 Source App | Open | AGPL-3.0-or-later | Public, reproducible, threshold-signed | Trust Path (source-facing, keys) |
| C-06 Source Web Service, C-07 Sealer, C-08 Intake Store schema | Open | AGPL | Public | Trust Path (source-facing, plaintext) |
| C-05 intake configuration and Tor integration | Open | AGPL | Public | Trust Path |
| C-09 Relay | Open | AGPL | Public | Handles sealed content and anonymity timing |
| C-10 Case Service, C-22 Authz engine | Open | AGPL | Public | Enforces COI and access, so it is a source-protection function (Charter T2) |
| C-11 candor-core and `candor-safefs` (ADR-027) | Open | Apache-2.0 OR MIT (ADR-031) | Public, reproducibly built, in audit scope | Keys; permissive licensing maximizes independent reuse and review; the services embedding them stay AGPL |
| C-12/C-13 schemas and migrations | Open | AGPL | Public | Stores protected data |
| C-14 Key Directory | Open | AGPL | Public | Hidden-recipient defense (INC-14) |
| C-15 Candor Desk, C-17 Viewer | Open | AGPL | Public, reproducible | Plaintext and keys |
| C-19 Admin Console / `candorctl` | Open | AGPL | Public | Controls dangerous configuration |
| C-21 Auth Service core (WebAuthn, PIV, local) | Open | AGPL | Public | Staff authentication feeding key operations |
| C-21 SSO/SCIM bridge | EE module | Candor Enterprise License (source-available to customers and auditors) | EE | Organizational scale. Cannot grant keys (ENT-015). |
| C-23 Notification Service | Open | AGPL | Public | Enforces content-free notifications |
| C-24 Audit Service **including the scrubbing allow-list** | Open | AGPL | Public | DECISIONS §2(e) |
| C-25 Self-test / health agent | Open | AGPL | Public | Verifies secret placement |
| C-26 SIEM exporter (transport and format) | EE module | Enterprise License | EE | Consumes only the scrubbed stream |
| C-27 Backup agent | Open | AGPL | Public | Keys and ciphertext |
| C-28 Recovery Quorum tooling | Open | AGPL | Public | Keys |
| C-29 PKCS#11/TPM integration | Open | AGPL | Public | Keys |
| C-31/C-32/C-33 build, sign, TUF tooling and recipes | Open | AGPL (scripts); public metadata | Public | Trust Path (d) |
| C-34 Fleet Manager | EE module | Enterprise License | EE | Scale. Cannot deliver code (ENT-038). Authorization limited to the `fleet` principal allow-list (15 §5.12, ADR-045): cannot disable intake, lower or hold below security floors, or change routing; tighten-only for logging/retention; availability-affecting actions need the customer's independent role. |
| C-35 Licensing service | Vendor proprietary | Proprietary | Vendor-internal | Issues offline license files only. Never contacted by instances. |
| C-36 Vendor support infrastructure | Separate service | Proprietary / third-party | Vendor-operated | Scrubbed bundles only |
| C-37 Information-site generator | Open | AGPL; templates CC0 | Public | Source-facing guidance |
| C-40 Integration connectors | EE module | Enterprise License | EE | Export Package consumers |
| HA orchestration / cluster operator | EE module | Enterprise License | EE | Availability only |
| Advanced workflow designer and rule engine UI | EE module | Enterprise License | EE | COI invariant is enforced in AGPL C-22 (ENT-003) |
| DR automation | EE module | Enterprise License | EE | Cannot unseal backups (HA-015) |
| Compliance pack schema and loader | Open | AGPL | Public | Parses data affecting Case Service |
| Starter compliance packs | Open content | CC BY 4.0 | Public | Protection-neutral content |
| Certified compliance packs | Commercial content | Commercial content license | EE | Legal-review labor |
| Documentation, threat model, specifications | Open content | CC BY-SA 4.0 | Public | Verifiability |
| Telemetry collector | Open | AGPL | Public, self-hostable | Users must be able to inspect what is collected |

**Enterprise License terms (normative minimum):**
- source is available to customers and to auditors they appoint;
- modification is allowed for internal use;
- redistribution is not allowed;
- no telemetry or phone-home;
- license validation uses offline signed files;
- on expiry, EE modules freeze **configuration changes** only; they **never** disable intake, decryption, case access, staff login via the SSO bridge, or safety-relevant automation (HA fencing and failover, DR automation, SIEM export of already-configured streams) (RVW-C-24).

## 5. Trust implications of closed components

| Principle | Application |
|---|---|
| Any component seeing plaintext, keys or source network metadata must be open and reproducible (R6 D2; INC-14) | Enforced by §4 classification and by the CI boundary (ENT-002) |
| Publication lag is itself a trust event (Signal, B-CO-64) | Same-day source publication for every Trust Path release, including LTS (BIZ-004) |
| Open source plus reproducible builds plus published audits is the trust package (Threema, B-CO-65) | CE audits are public (`37-SECURITY-AUDIT-PLAN.md`) |
| Closed EE code can still harm sources indirectly (by routing, exporting or configuring) | EE modules are limited to APIs that cannot grant keys, cannot enable dangerous configuration remotely, and cannot egress content except via Export Packages. Customers and auditors can read EE source. |
| An adversary can tell a customer "trust our closed module" | The Charter forbids closed code in the Trust Path. Violating it is a trademark-license breach (see `36-OPEN-SOURCE-GOVERNANCE.md`). |

## 6. Revenue model without data incentives

| Revenue stream | Pricing basis | Prohibited bases |
|---|---|---|
| EE subscription | Per instance tier and per staff-seat band (self-declared, contract-audited) | Per report, per case, per source, per submission volume, per message |
| Managed hosting | Per dedicated instance plus storage band (ciphertext bytes, monthly) | Per report or submission |
| Support tiers | Fixed annual | — |
| Professional services | Time and materials / fixed scope | — |
| Certified compliance packs | Per jurisdiction pack per year | — |
| Assurance packages (ACR, OSCAL, FIPS evidence) | Fixed | — |
| Grants (public-good components: accessibility, crypto, Tor tooling) | Grant terms | Grants requiring user analytics |

Absolute prohibitions:
- no advertising;
- no data sales or sharing;
- no source profiling;
- no source analytics (including aggregate behavioral analytics on source UIs);
- no A/B testing on source UIs using real traffic;
- no third-party SDKs on any surface;
- no training of ML models on customer content or metadata;
- no pricing that requires the vendor to measure source activity.

Reasoning: a pricing metric creates a measurement need, and a measurement need creates telemetry (INC-53, INC-72).

## 7. Edition Charter (normative text, published verbatim)

> **Candor Edition Charter v1.0**
>
> 1. **Same protection for every source.** Every protection of source anonymity, report confidentiality, evidence integrity and protection from retaliation that exists in any Candor edition exists in the Community Edition, under an OSI-approved license (AGPL-3.0-or-later).
> 2. **No closed code in the trust path.** Code that serves sources, handles report plaintext, generates, stores, wraps or uses keys, builds, signs or updates any of these, or enforces anonymity-related logging suppression is AGPL (the reusable libraries `candor-core` and `candor-safefs`: Apache-2.0 OR MIT), reproducibly built and publicly auditable in all editions.
> 3. **Nothing moves backwards.** No feature or protection shipped in the Community Edition will be removed from it and offered only in a commercial edition.
> 4. **Simultaneous security fixes.** Security fixes to shared code are published for the Community Edition no later than for any commercial edition. Early vulnerability notice is never sold.
> 5. **Same-day source.** Source code for every trust-path release is public on the day the release is published, including long-term-support releases.
> 6. **No data business.** We do not sell, share, profile, advertise with, or train on data from any Candor deployment. Sources are never measured. Instance telemetry is off unless an administrator turns it on, and only fields in the published schema are sent.
> 7. **No license rug-pull.** Trust-path code will not be relicensed to a non-OSI license. Contributions are accepted under the DCO, and no contributor assigns copyright.
> 8. **Enforcement.** This Charter is incorporated in the Foundation bylaws and in the Candor trademark license. A breach entitles any person to use the Candor name for a Charter-compliant fork, as specified in the trademark policy. Amendments require the process in `36-OPEN-SOURCE-GOVERNANCE.md` and may only strengthen these commitments.

## 8. Telemetry

### 8.1 Rules (ADR-023)

- **Source-facing telemetry: none.** C-02, C-03, C-06 and C-37 emit nothing to any collector. This includes crash reports and update pings from C-03 carrying identifiers. The C-03 update check fetches public TUF metadata over Tor only.
- **Instance telemetry: OFF by default in CE and EE.** Levels:
  - `off` (default);
  - `health-min`;
  - `health-full`.
- `health-full` is not available in the GOV-ONPREM profile (RVW-B-20).
- **Enabling telemetry** requires an admin action in Desk admin mode. It is SECURITY-audited, and it is displayed on the source landing page as "Operational telemetry: ENABLED (schema vX)".
- **Transparency.**
  - Every payload is written to `/var/lib/candor/telemetry/outbox/` 72 h before upload.
  - `candorctl telemetry show` renders it for inspection.
  - The admin may cancel any upload.
- **Transport and destination.**
  - Upload to a self-hosted collector (AGPL), or to the vendor collector over its **onion address**, so the instance's IP is not revealed.
  - Upload cadence: weekly, at a random time within the week.
  - Uploads are unauthenticated: no instance key and no license ID.
- **No persistent identifiers.** Each upload has a fresh random `upload_id`. No instance ID, license ID, onion address or hostname is sent.
- **Payload.** JSON, maximum 4 KiB. It is validated against the schema locally before writing to the outbox. Unknown fields cause the upload to be dropped.

### 8.2 Telemetry schema v1 (complete)

Level column: M = `health-min`, F = `health-full` only.

| # | Field | Type | Example | Level | Purpose | Why not identifying |
|---|---|---|---|---|---|---|
| 1 | `schema_version` | int | `1` | M | Parsing | Constant |
| 2 | `upload_id` | UUIDv4, fresh per upload | `"9f1c…"` | M | Deduplication at collector | Random. Never reused. Not derived from instance data. |
| 3 | `period` | string ISO week `YYYY-Www` | `"2026-W40"` | M | Aggregation window | Week granularity. Upload time is randomized within the week. |
| 4 | `edition` | enum {CE, EE} | `"CE"` | M | Product planning | Two values |
| 5 | `release_version` | string (public release tag) | `"1.4.2"` | M | Update adoption, vulnerable-version exposure | Shared by all instances on that release |
| 6 | `release_channel` | enum {stable, lts, beta} | `"stable"` | M | Support planning | Three values |
| 7 | `update_lag_bucket` | enum {0-7d, 8-30d, 31-90d, >90d} | `"0-7d"` | M | Patch-latency health | Bucketed |
| 8 | `deployment_profile` | enum (ADR-024 eight values) | `"CE-HARDENED"` | M | Test-matrix prioritization | ≤ 8 values |
| 9 | `os_family` | enum {debian13, debian12, appliance, other} | `"debian13"` | M | Support matrix | Coarse |
| 10 | `arch` | enum {x86_64, aarch64} | `"x86_64"` | M | Build matrix | Two values |
| 11 | `tor_impl` | enum {ctor-0.4.8, ctor-0.4.9, arti, other} | `"ctor-0.4.8"` | M | Transport migration planning | Coarse |
| 12 | `pg_major` | enum {16, 17, 18, other} | `16` | M | Support matrix | Coarse |
| 13 | `selftest` | map check_id → {pass, warn, fail} over a fixed list of ≤ 40 check IDs | `{"secret_placement":"pass",…}` | M | Detect common misconfigurations and product defects | Check IDs are fixed public constants. No values, paths or messages. |
| 14 | `crash_counts` | map component_id → int bucket {0, 1-2, 3-10, >10}; **Z-INTAKE components (C-05..C-08) excluded** | `{"C-10":"0"}` | M | Stability | Counts only. No stack traces, messages or times. Intake crash bursts could correlate with hostile or malformed submissions (RVW-B-20). |
| 15 | `crypto_profile` | enum {STD-1, FIPS-1} | `"STD-1"` | F | Profile adoption | Two values |
| 16 | `tier_v_enabled` | bool | `true` | F | Feature adoption | Boolean. Tier V download is public anyway. |
| 17 | `clearnet_intake_enabled` | bool | `false` | F | Monitor dangerous-option prevalence | Already shown publicly to sources (ADR-002) |
| 18 | `recovery_quorum_enabled` | bool | `false` | F | Monitor escrow prevalence | Already published in the key directory (ADR-013) |
| 19 | `channel_count_bucket` | enum {1, 2-5, 6-20, >20} | `"2-5"` | F | Scale planning | Bucketed |
| 20 | `staff_account_bucket` | enum {1-2, 3-10, 11-50, 51-250, >250} | `"3-10"` | F | Scale planning | Bucketed. Staff, not sources. |
| 21 | *removed* (was `new_cases_bucket`) | — | — | — | — | Withdrawn (RVW-B-09): a bucket flip on one report reveals that report's month to the vendor. The index is not reused. |
| 22 | `storage_bucket` | enum {<10GB, 10-100GB, 100GB-1TB, >1TB} | `"10-100GB"` | F | Capacity planning | Bucketed ciphertext volume |
| 23 | `pow_active_bucket` | enum {none, <1h, 1-24h, >24h} per week | `"none"` | F | DoS defense tuning | Coarse. Refers to attack pressure, not source activity. |
| 24 | `locale_count_bucket` | enum {1, 2-3, 4-10, >10} | `"2-3"` | F | Localization investment | Count only. No language codes (these would narrow jurisdiction). |

**Prohibited in any telemetry, forever:**
- onion addresses or keys;
- hostnames, IPs, domain names;
- organization, tenant, channel or user names;
- license IDs;
- any timestamp finer than `period`;
- case, envelope, batch or evidence identifiers;
- exact counts;
- per-channel breakdowns;
- configuration string values;
- error messages, stack traces or file paths;
- language codes;
- source-side metrics of any kind;
- staff activity metrics;
- any free text.

### 8.3 Fingerprinting analysis

Even without an identifier, the combination of fields is a quasi-identifier. It can link weekly uploads from the same instance. For example, the tuple (`deployment_profile`, `os_family`, `pg_major`, `channel_count_bucket`, `staff_account_bucket`, `locale_count_bucket`) may be unique among uploads.

Consequences and mitigations:
- **Linking weekly uploads** reveals an instance's trajectory, but not its identity. Identity requires external knowledge, such as the vendor knowing which EE customer runs FIPS-1 + GOV-ONPREM.
- **EE customers are known to the vendor.** With `health-full`, the vendor could plausibly associate uploads with a customer. Treat `health-full` telemetry from EE as **attributable** and disclose this in the enablement dialog (TEL-008).
- **No field counts cases or submissions** since #21 was removed; `storage_bucket` (#22) changes slowly with ciphertext volume and may still reveal large evidence uploads over months.
- `health-min` omits every organization-shape field, which reduces uniqueness.

## 9. §TEL — Canonical metrics regime (ADR-046 §5)

This section is the **single source of truth** for every aggregate derived from case, intake or source-derived data, for every audience (ADR-046(5); resolves RVW-B-07, RVW-B-08, RVW-B-09). Other documents (`03-PRIVACY-ANONYMITY.md` §12, `09-DATABASE.md`, `13-FRONTEND-ADMIN.md`, `14-CASE-MANAGEMENT.md` §14, `20-LOGGING-AUDITING.md` §5.4/§13, `21-ENTERPRISE.md`, `23-COMMUNITY-EDITION.md`, `30-ANONYMITY-TESTING.md`, `32-OPERATIONS.md`) SHALL reference "24 §TEL" and SHALL NOT restate or vary its parameters. The parameters are also published as the machine-readable file `spec/constants/tel.yaml` for the spec-constant lint in `39-REQUIREMENTS-TRACEABILITY.md`.

### 9.1 Scope

- in-instance dashboards and reports (`23-COMMUNITY-EDITION.md` health dashboard; `21-ENTERPRISE.md` E20 reports; the `14-CASE-MANAGEMENT.md` §14 report catalog);
- published and statutory statistics (EU Art 27, PSDPA annual reports);
- SOURCE-SENSITIVE counters (`20-LOGGING-AUDITING.md` §5.4) and anything derived from them;
- SOC/SIEM views, C-26 exports, support bundles and Fleet Manager health data;
- telemetry (§8).

### 9.2 Audience classes

| Class | Audience | What they may see |
|---|---|---|
| M0 | users viewing only cases they can open (case team, Triage Set for its own intake) | case-level data of those cases; aggregates over **only** those cases; no suppression beyond access control |
| M1 | *retired* (RVW-B-04): round-1 "channel operations" counts over cases the viewer cannot open enabled subtraction attacks by excluded members. Channel members see M0 only; non-triage roles see no intake counts (ADR-037(2)) | — |
| M2 | program owners, management, board, internal audit, METRICS_VIEWER (no case access) | §9.3 regime, catalog reports only |
| M3 | public, regulators | §9.3 regime, catalog reports only, plus rounding and channel-type dimension only |
| H | SOC, SYS_ADMIN, SIEM, support bundles, Fleet Manager | only **global daily health bands** per service {NORMAL, ELEVATED, UNDER_ATTACK}; no source-derived counts, no per-channel or per-tenant data, nothing hourly |
| T | telemetry (§8) | only the §8.2 schema, which contains no case or submission counts |

### 9.3 Parameters (M2/M3)

| Parameter | Value |
|---|---|
| Minimum cell size k | **10** for every cell of every M2/M3 table. Configurable **upward only**; no configuration lowers it. Suppressed cells display "<10"; in M2/M3 zero and "<10" are merged ("0–9"). |
| Complementary suppression | If a row or column contains exactly one primary-suppressed cell, the next-smallest non-zero cell is also suppressed, repeated until no suppressed value is derivable from published cells and marginals; marginals that would allow recovery are rounded (to nearest 5) or withheld. |
| Period | **Calendar month minimum**, tumbling (non-overlapping) windows only. Coarser periods (quarter, year) allowed. A period's figures are computed and released once, after the period closes; no intra-period or cumulative-to-date figures; dashboards refresh once per period, not daily (RVW-B-09). |
| Small-program coarsening | Tenants with < 100 non-spam reports in the prior calendar year publish M2/M3 only yearly (GOV-013). The switch is evaluated once per calendar year and switches back only after 2 consecutive years above the threshold (hysteresis, RVW-B-09). |
| Magnitude statistics | Medians, means, percentiles and durations are published only for cells with n ≥ k, durations rounded to whole weeks; ratios and rates only if the denominator ≥ k and the numerator ∉ {0, denominator}; otherwise "—". No medians/ratios/percentiles for cells < k (ADR-046(5), RVW-B-08). |
| Per-channel dimension | A channel appears as its own row/column only for a period in which it has ≥ 3 cases (ADR-046(5)) **and** a declared population estimate ≥ 50 (RVW-B-10); otherwise it is merged into a declared channel group of ≥ 2 channels. M3 uses channel *type* only. |
| Dimensions | At most 2 per table. Allowed: channel group (M2), channel type (M3), lifecycle outcome, SLA met/not met, coarse category (only where server-visible, i.e., not for ANONYMOUS reports), mode (ANONYMOUS vs other, as totals only). Never: reporter department/location/business unit, accused role/level, submission weekday/hour, language/locale, Tier W/V, attachment presence/size, follow-up counts, staff member. |
| Rounding | M3 published counts ≥ k rounded to nearest 5 (deterministic on frozen values). |
| Query model | Fixed signed report catalog (14 §14). No ad-hoc queries, filters, custom date ranges or drill-down from aggregates to cases. |
| Revision policy | Published periods are frozen. Late-arriving data goes into the next period. |
| Statutory exact counts | Not produced by the metrics system. Where law requires exact counts below k, an authorized M0 user produces a signed Export Package with the legal reference recorded, under dual approval (ADR-018). |

### 9.4 SOURCE-SENSITIVE counters and health bands

| Rule | Value |
|---|---|
| Counters | defined in `20-LOGGING-AUDITING.md` §5.4; per-day values never leave C-08; monthly totals in C-24 released only under §9.3 |
| Health bands (class H) | computed once per UTC day per service from internal detectors; the band thresholds are set so that ELEVATED/UNDER_ATTACK occur only under load ≥ 10× design peak (RVW-A-27); no band is derived from per-channel data |
| Abuse alerting | raw values are evaluated only inside C-24/C-25 and emit "threshold exceeded" SYSTEM events with date-only `ts` |
| Retired | round-1 M4 "7-day rolling buckets", per-hour request-rate bands, `v_case_counts`-style per-channel weekly admin counts (RVW-B-07) |

### 9.5 Inference risks

| Attack | Example | Mitigation |
|---|---|---|
| Small cells | "1 report in the Finance department in March" | k = 10; no reporter-department dimension |
| Excluded-member subtraction | An excluded channel member subtracts the cases they can see from a channel count | M1 retired; channel members see M0 only; non-triage roles see no intake counts |
| Differencing (windows) | Jan 1–31 minus Jan 1–30 | tumbling monthly windows only; no custom ranges |
| Differencing (filters) | totals with and without one channel | no filters; channel groups ≥ 2 channels; complementary suppression |
| Rolling/cumulative displays | daily-refreshed month-to-date figure reveals a daily delta | release once after period close |
| Regime switches | publication before/after a coarsening switch | yearly evaluation with hysteresis |
| Magnitude statistics | median time-to-close over 3 cases; substantiation 1/1 | n ≥ k for medians; ratio rules |
| Revision differencing | revised figure reveals a late report | frozen periods |
| Timing correlation | SOC sees an hourly band move at 22:00 | class H only daily global bands |
| Cross-source linkage | statistics + HR events | month/year granularity; documented residual |
| Long-run averaging | repeated rounded values | deterministic rounding of frozen values |
| Telemetry + external knowledge | vendor links an EE customer to activity | telemetry carries no case/submission counts (field #21 removed) |

### 9.6 Differencing test suite

The CI test `stats-inference` runs against the report catalog with synthetic data:
- enumerates all pairs of catalog reports and periods and attempts linear reconstruction of every suppressed cell;
- attempts reconstruction of any single-case contribution, including through magnitude statistics (medians, ratios);
- runs "before/after one submission" across consecutive periods and across a regime switch;
- simulates an excluded channel member with all views available to their role and checks that no count of cases they cannot open is derivable.

It fails if any cell below k, or any single-case attribute, becomes derivable.

## 10. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| BIZ-001 | (amended ADR-031) Every component SHALL carry the license class and license in §4. The build SHALL fail if a Trust Path crate other than `candor-core` and `candor-safefs` carries a non-AGPL license, if those two carry anything other than `Apache-2.0 OR MIT`, or if any Trust Path crate depends on an Enterprise-License crate. | ADR-020; B-CO-55 | THR-024 | C-30, C-31 | TST: `license-boundary` job (cargo-deny) |
| BIZ-002 | No Trust Path code SHALL ever be licensed under BSL, FSL, SSPL, ELv2 or any non-OSI license. | B-CO-60; B-CO-61; B-CO-62; B-CO-63 | THR-024 | C-30 | INSP; AUD: charter audit |
| BIZ-003 | The Edition Charter (§7) SHALL be published verbatim in the repository root and on the project site. Amendments SHALL only strengthen it. | ADR-020 | THR-024 | C-30 | INSP |
| BIZ-004 | Source for every Trust Path release, including LTS, SHALL be public no later than the release's publication time. | B-CO-64 | THR-024 | C-30, C-32 | TST: release pipeline checks tag visibility before signing; AUD |
| BIZ-005 | Pricing SHALL NOT be based on any metric of source activity (reports, cases, submissions, messages, sources). | INC-53; INC-72 | THR-036 | C-35 | INSP: price-list review by the governance board |
| BIZ-006 | The vendor SHALL NOT sell, share, advertise with, profile or train models on deployment data or metadata. This SHALL be a contractual term in all EE and MANAGED agreements. | INC-53; INC-72 | THR-027, THR-036 | C-36 | AUD: contract template review |
| BIZ-007 | (amended RVW-C-24) EE license validation SHALL be offline (signed license files). Expiry SHALL freeze only configuration changes of EE modules and SHALL NOT disable intake, decryption, case access, SSO-bridge login, HA fencing/failover, DR automation or configured SIEM export. | ADR-023; C-35; RVW-C-24 | THR-032, THR-036 | C-35, C-19 | TST: expired license + node failure: failover completes; SSO-first-factor login works; config change rejected |
| BIZ-008 | EE modules SHALL be source-available to customers and customer-appointed auditors under the Enterprise License. | R6 D6; B-CO-65 | THR-024 | C-26, C-34, C-40 | INSP |
| BIZ-009 | The Enterprise License SHALL prohibit telemetry or phone-home in EE modules. | ADR-023 | THR-036 | C-26, C-34, C-40 | TST: EE network egress test |
| BIZ-010 | Starter compliance packs and documentation SHALL be licensed CC BY 4.0 and CC BY-SA 4.0 respectively. | R6 D6 | — | C-30 | INSP |
| BIZ-011 | AGPL §13 source offer on the source web interface SHALL be satisfied by a static link to the release tag and reproducible-build hash, served from the onion site itself. It SHALL NOT load clearnet resources. | B-CO-55; ADR-001 | THR-036, THR-006 | C-06 | TST: page contains offer; no external requests |
| BIZ-012 | Grants SHALL NOT be accepted if their terms require user analytics or source data. | INC-53 | THR-036 | C-30 | INSP: governance board record |
| BIZ-013 | In MANAGED service the vendor, as operator, SHALL publish the ADR-035(2) quorum-signed operator statement for each customer instance every 30 days (with ≥ 1 customer-side independent signer) and an annual per-jurisdiction transparency report of legal demands received; failure to renew SHALL surface as the source-facing warning banner. | ADR-035(2); RVW-A-01; RVW-B-19 | THR-026; THR-027 | C-14; C-36 | INSP: statement cadence audit; TST: expired statement shows banner |
| BIZ-014 | EE Fleet Manager SHALL act only through the `fleet` principal allow-list (15 §5.12); the Enterprise License and product SHALL NOT offer fleet actions that disable intake, lower or hold below security floors, or change routing, rosters or COI. | ADR-045; ADR-040; RVW-C-13 | THR-025; THR-027; THR-032 | C-34; C-22 | TST: see 15 AUTHZ-026; INSP: Fleet API surface |
| TEL-001 | Source-facing components (C-02 served content, C-03, C-06, C-37) SHALL emit no telemetry, crash reports or analytics to any destination. | ADR-023; REQ-H-13; INC-53 | THR-036, THR-006 | C-03, C-06, C-37 | TST: network capture and static SDK scan; AT (see `30-ANONYMITY-TESTING.md`) |
| TEL-002 | Instance telemetry SHALL default to `off` in CE and EE. Enabling it SHALL require an admin action in Desk admin mode, SHALL be SECURITY-audited, and SHALL be displayed on the source landing page. | ADR-023; B-CO-66 | THR-036, THR-035 | C-19, C-06 | TST |
| TEL-003 | Telemetry payloads SHALL contain only the fields of §8.2 for the enabled level. Validation SHALL occur locally, and unknown or extra fields SHALL cause the upload to be dropped. | ADR-023 | THR-036 | C-25 | TST: schema fuzz |
| TEL-004 | Payloads SHALL be placed in a local outbox ≥ 72 h before upload, viewable via `candorctl telemetry show`, and cancellable. | B-CO-66 | THR-036 | C-19 | TST; DEMO |
| TEL-005 | Uploads SHALL use a fresh random `upload_id`, SHALL carry no instance, license or network identifier, and SHALL go to a self-hosted collector or the vendor's onion collector. | ADR-022; ADR-023 | THR-036, THR-001 | C-25 | TST: capture shows Tor-only egress; no stable fields |
| TEL-006 | Upload time SHALL be uniformly random within the week. | ADR-010 | THR-011 | C-25 | TST: distribution test |
| TEL-007 | WITHDRAWN (ADR-046(5); RVW-B-09): `new_cases_bucket` SHALL use a floor of `<20`, calendar-month granularity, and SHALL be sent only in the first upload after month close. Replaced by TEL-019 (no case or submission counts in telemetry). | INC-74; INC-70 | THR-039 | C-25 | TST |
| TEL-008 | The telemetry enablement dialog SHALL state that `health-full` telemetry from EE customers may be attributable by the vendor. | Design; ADR-023 | THR-027 | C-19 | INSP |
| TEL-009 | The telemetry collector SHALL be AGPL and self-hostable. The vendor collector SHALL retain raw uploads ≤ 90 days and publish only aggregates meeting §9.3 (k = 10). | B-CO-66 | THR-036, THR-039 | C-25 | INSP; AUD |
| TEL-010 | (amended ADR-046(5)) Aggregates in dashboards, reports and published statistics SHALL apply §9.3: k = 10, complementary suppression, calendar-month minimum tumbling periods released after close, fixed catalogue, frozen periods, M3 rounding to 5. | INC-74; INC-70; ADR-016; ADR-046(5); RVW-B-08 | THR-039 | C-10 | TST: `stats-inference` suite (§9.6) |
| TEL-011 | (amended ADR-046(5)) k SHALL be configurable upward only; no configuration, role or profile SHALL lower k below 10; exact statutory counts below k SHALL be produced only as dual-approved Export Packages outside the metrics system. | INC-74; ADR-046(5); RVW-B-08 | THR-039, THR-035 | C-10 | TST: configuration schema rejects k < 10; report generator has no k override |
| TEL-012 | Reports SHALL NOT offer custom date ranges, filters, reporter-attribute dimensions, or drill-down from aggregates to cases. | INC-70 | THR-039 | C-10 | TST: API surface test |
| TEL-015 | Medians, means, percentiles and durations SHALL be published only for cells with n ≥ k (durations rounded to whole weeks), and ratios only when the denominator ≥ k and the numerator is neither 0 nor the denominator; otherwise "—". | ADR-046(5); RVW-B-08 | THR-039 | C-10 | TST: `stats-inference` magnitude cases; fixtures with n < k render "—" |
| TEL-016 | A channel SHALL appear as its own dimension only for periods with ≥ 3 cases and a declared population estimate ≥ 50; otherwise it SHALL be merged into a declared channel group of ≥ 2 channels; M3 SHALL use channel type only. | ADR-046(5); RVW-B-10 | THR-039; THR-015 | C-10 | TST: small-channel fixture merged; M3 output contains no channel names |
| TEL-017 | Aggregates over cases a viewer cannot open SHALL be shown only to audiences without case access (M2/M3); channel members SHALL see only M0 aggregates, and non-triage roles no intake counts. | RVW-B-04; ADR-037(2) | THR-020; THR-039 | C-10; C-22 | TST: excluded-member subtraction simulation in `stats-inference`; role-view tests |
| TEL-018 | SOC, SYS_ADMIN, SIEM, support-bundle and Fleet Manager views SHALL receive only global daily per-service health bands; no source-derived count, per-channel, per-tenant or sub-daily value SHALL be exposed to them. | ADR-046(5); ADR-038(5); RVW-B-07; RVW-A-27 | THR-011; THR-039; THR-016 | C-25; C-26; C-19; C-34 | TST: SOC/API surface and C-26 output inspection; bundle inspection |
| TEL-019 | Telemetry SHALL contain no case, submission, message or source-derived count at any level, `crash_counts` SHALL exclude Z-INTAKE components, and `health-full` SHALL be unavailable in GOV-ONPREM. | RVW-B-09; RVW-B-20; ADR-023 | THR-036; THR-039 | C-25 | TST: schema test; GOV-ONPREM profile rejects `health-full` |
| TEL-020 | Regime switches (e.g., small-program yearly coarsening) SHALL be evaluated once per calendar year with hysteresis of 2 consecutive years, and no intra-period or cumulative-to-date figure SHALL be displayed for M2/M3. | RVW-B-09 | THR-039 | C-10 | TST: before/after-one-submission across switch in `stats-inference`; UI shows no month-to-date values |
| TEL-021 | The §TEL parameters SHALL be published once in `spec/constants/tel.yaml`, and CI SHALL fail when any specification or code literal for k, period, band or rounding diverges from it. | ADR-046(5); RVW-B-07; RVW-B-29 | THR-039; THR-035 | C-30; C-31 | TST: spec-constant lint (39) |
| TEL-013 | The C-03 update check SHALL fetch only public TUF metadata over Tor, SHALL send no identifiers, and SHALL use the same request for all clients. | ADR-022; INC-57 | THR-036, THR-001 | C-03 | TST: request golden test |
| TEL-014 | Any schema change SHALL increment `schema_version`, SHALL be published with a privacy analysis 30 days before shipping, and SHALL NOT be applied to instances until the admin re-consents. | B-CO-66 | THR-036 | C-25 | INSP; TST: consent version check |

## 11. Residual risks and limitations

- AGPL does not stop a hostile operator from running modified code privately. Sources can verify only Tier V clients and published keys, not the server (ADR-004).
- Enterprise-License modules are not publicly auditable. Indirect harms (routing, export) are bounded by AGPL-enforced invariants, but not eliminated.
- Telemetry quasi-identifiers can link uploads (§8.3).
- k = 10 with monthly periods reduces but does not eliminate inference: small programs still reveal "at least N reports this period", and attackers with external knowledge (HR events, a known interview date) may link a count change to a person (THR-039). Formal privacy accounting (noise) for M3 is not adopted (open issue 2).
- The §TEL regime governs Candor outputs only; organisations can still compile their own statistics from case content outside the system.
- The Fleet Manager allow-list constrains the product; a compelled vendor can still withhold updates within the allowed scheduling window (ENT-040 lag alert mitigates).
- Revenue concentration in EE could pressure governance. Charter enforcement relies on the Foundation (see `36-OPEN-SOURCE-GOVERNANCE.md`).

## 12. Open issues

1. Whether the §4 exception list needs a per-module review on each new EE module (proposed: yes, by the governance board).
2. Formal privacy accounting (bounded discrete-Gaussian noise with a published annual budget) for M3 public statistics (RVW-B-09 fix 3): research item; conflicts with statutory exact-count reporting in some jurisdictions.

## 13. Open Issues for ADR revision

- **Licensing of `candor-core` and `candor-safefs`.** Resolved by ADR-031 (`Apache-2.0 OR MIT`); §4 and BIZ-001 updated.
- **Metrics regime ownership.** Resolved by ADR-046(5): this document's §TEL is canonical.
