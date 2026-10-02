# REVIEW-B — Privacy / Anonymity Adversarial Review of the Candor Specification Set

Reviewer: B (privacy and anonymity research: LINDDUN, traffic analysis, statistical disclosure control, inference attacks, usable security)
Baseline reviewed: `specs/DECISIONS.md` (ADR-001..033, read in full); `03-PRIVACY-ANONYMITY`, `05-SOURCE-OPSEC`, `11-FRONTEND-SOURCE`, `14-CASE-MANAGEMENT`, `20-LOGGING-AUDITING`, `24-LICENSING-BUSINESS-MODEL`, `30-ANONYMITY-TESTING`, `35-DATA-RETENTION-DELETION` (the relevant sections in depth); targeted reads of `01`, `06`, `07`, `08`, `09`, `12`, `13`, `15`, `19`, `21`, `23`, `32`, `33`.
Date: 2026-09-30
ID prefix: `RVW-B-nn` (DECISIONS §3 assigns `RVW-` to review reports).

## 0. How to read this review

- **Severity** reflects impact on source anonymity or safety × likelihood under the adversaries in `02-THREAT-MODEL.md`.
  - **Critical:** a documented protection is defeated by stored data or a design contradiction, for a realistic insider adversary, with no special capability needed.
  - **High:** the anonymity set shrinks sharply, or a documented guarantee is false, for a realistic adversary.
  - **Medium:** a meaningful inference aid, an honesty or usability defect, or a gap in regression detection.
  - **Low:** a hygiene issue or a defence-in-depth gap.
- **"Proposed fix"** names the document and requirement to amend. New requirement numbers are suggested as the next free ID in the owning prefix, marked "(new)". The owning author assigns the final ID.
- **Main finding.** The core cryptography (ADR-006/007/008/030/033) is strong. Nearly every weakness below is **metadata** that the cryptography does not cover. Much of it comes from contradictions between documents: 03 states a minimized design, while 09, 11, 13, 14, 19, 20 and 35 each quietly re-introduce data that 03 says does not exist. The published legal-compulsion inventory (03 §10) and the source-facing copy (05 GC-01, GC-34) are therefore currently **inaccurate**, and the test oracles in 30 inherit the same contradictions.

### Severity summary

| Severity | Count | IDs |
|---|---|---|
| Critical | 2 | RVW-B-01, RVW-B-02 |
| High | 14 | RVW-B-03, -04, -05, -06, -07, -08, -10, -11, -14, -19, -21, -23, -29, -31 |
| Medium | 15 | RVW-B-09, -12, -13, -15, -16, -17, -18, -20, -22, -24, -25, -26, -27, -28, -30 |
| Low | 2 | RVW-B-32, -33 |
| **Total** | **33** | |

---

## 1. Weaknesses

### RVW-B-01 — The COI exclusion set ("who the report is about") is persisted in cleartext and logged, defeating ADR-033(1)
- **SEVERITY:** Critical
- **SCENARIO:**
  1. A source ticks "Chief Financial Officer" on S04b. On import, the case's permanent exclusion set is written to C-12 table `coi_exclusion(case_id, user_id, source=source_selection, declared_by)` (09, `coi_exclusion`; 14 §3 "COI exclusion rows (user/group IDs)").
  2. If the CFO was a case member, `case.member_removed` is emitted with `target UserRef` and `reason_code=COI` (20 §5.2).
  3. When the CFO's Desk touches the case, `authz.denied` with `reason_code=COI_EXCLUDED` and `actor` is written to SECURITY and **exported to the SIEM** (20 §13 allow-list exports `actor` and `reason_code` for `authz.denied`).
  4. Result: a DBA, a backup thief, the MANAGED vendor, the SOC/SIEM operator (IT, often reporting to the CFO/CIO), or AUDITOR/OVERSIGHT readers (AUD-006, all tenant CASE events) learn that "case CS-… received 2026-09-30 in channel *Audit Committee* concerns the CFO, and the source said so (`source_selection`)".
  5. That is exactly the leak ADR-033(1) was written to prevent ("server and DB thieves cannot tell which members were excluded (would otherwise hint at the accused)"). `case.coi_exclusion_applied` carefully logs only `excluded_count` and explains why, but three sibling artefacts log the identities.
- **AFFECTED:** ADR-015, ADR-030, ADR-033(1); 09 `coi_exclusion`, `coi_registry`, grant matrix §7 (worker R, admin RW registry); 14 §3, §8.4 step 1, ROUTE-006/-012; 20 §5.1 `authz.denied`, §5.2 `case.member_removed`, §13, AUD-006; 03 §10.1 (the inventory omits this row); 30 AT-021/-022/-023 expected answers (omit it); THR-020, THR-038, THR-018.
- **WHY NOT PREVENTED:**
  - Server-side enforcement of "excluded members may never be added" (ROUTE-012, CASE-022) was implemented as a cleartext policy table.
  - ADR-033(1) only considered the envelope header.
  - The log schema catalogues were reviewed per event, not for joint disclosure.
  - Nothing in 03 §8 lists `coi_exclusion`, so `inventory-check` (META-001) is only as good as §8.
- **PROPOSED FIX:**
  1. **09:** replace `coi_exclusion.user_id` with `excl_tag = HMAC(K_case_excl, user_id)`, where `K_case_excl = HKDF(case key, "candor/coi-excl")`.
     - The adding member's Desk computes the tag for a candidate and C-22 checks set membership (a blind check).
     - Every member Desk verifies on sync that no wrap exists for an excluded user and raises a SECURITY alert otherwise.
     - Pad each case's tag set to a fixed size (e.g., 8) with random tags.
     - Drop the `source` enum from cleartext: move it into the encrypted case record.
  2. **20 §5.2:** `case.member_removed.reason_code` SHALL NOT distinguish COI from other removals (use `REMOVED`). **20 §5.1:** add `COI_EXCLUDED` to the reason codes that are never emitted; map it to `NO_RELATION`. Add LOG-020 (new): "No event, table or export SHALL associate a user identity with a COI exclusion for a specific case."
  3. **14 §3:** delete "COI exclusion rows (user/group IDs)" from the server-visible list.
  4. **03 §10.1:** add an explicit row "COI exclusion identities: No (blinded)".
  5. **30:** add a drill assertion to AT-021/-022/-023/-026: "exclusion identity of the synthetic COI case not learnable".
- **RESIDUAL RISK:**
  - Case members legitimately know who is concerned.
  - A live Z-CORE attacker who also compromises a member Desk can compute tags.
  - An excluded member can still infer their exclusion (RVW-B-04).

### RVW-B-02 — Triage-time COI exclusion comes after the accused already holds a key
- **SEVERITY:** Critical
- **SCENARIO:**
  1. The report concerns the source's direct manager, M, who is an "HR Investigations Lead" and a member of the HR channel.
  2. The source ticks the subject role "my direct manager". Intake cannot resolve that to a person: 14 §8.2 row 1 says the exclusion is "applied at triage (§8.4) because intake cannot know the source's manager".
  3. The envelope content key is therefore wrapped to M's Member Epoch Key (ROUTE-001). M opens the Inbox (12 R02 "Open preview") before or during triage and reads the report.
  4. Triage later removes M (§8.4 step 4, ROUTE-006/-007), but the content was already disclosed. 14 §16.2 admits "may retain case keys or DEKs cached before removal".
  5. The same happens whenever the source does not know that the accused is a channel member, or the COI map lacks the category rule.
- **AFFECTED:** ADR-015, ADR-030; 14 §8.2 (row "Source's direct manager"), §8.4, §8.5, §16.2–3, ROUTE-001/-006/-007; 12 R02; 11 S04b; 03 §5 note 10 (acknowledged only as "not flagged"); THR-020, THR-019.
- **WHY NOT PREVENTED:**
  - The cryptographic exclusion works only for exclusions known at sealing time.
  - The design has no stage in which a small, independent set sees the report first and decides the wider recipient set.
- **PROPOSED FIX:**
  1. **ADR (new, amends ADR-030):** "Triage-first routing". Each channel designates a **Triage Set**: ≥ 2 members with independent-body role labels (14 §8.1 list) or, failing that, the channel owner plus OVERSIGHT.
     - The envelope is wrapped **only** to the Triage Set's Member Epoch Keys.
     - After COI detection (§8.4), the Triage Set's Desk wraps the Case Key to the remaining eligible members.
     - Default ON for every channel whose COI map contains a subject role that cannot be resolved at intake ("direct manager", "manager chain", "named person").
  2. **14 ROUTE-001:** amend to "eligible Triage Set".
  3. **11 S04b:** state who reads first ("Your report is first read by: {triage_role_labels}").
  4. **30:** add AT-069 (new): a synthetic report concerning a channel member not ticked by the source must not be decryptable by that member at any point.
- **RESIDUAL RISK:**
  - A captured Triage Set (14 §16.4).
  - Slower first response. SLA ACK is still satisfied by auto-acknowledgement (§6.4).

### RVW-B-03 — The "Source's direct manager" option and manager-chain exclusions reveal the source's team
- **SEVERITY:** High
- **SCENARIO:**
  1. The source ticks "Source's direct manager" (14 §8.2), or names their manager in `persons_concerned`.
  2. The triager maps this to user M via the EE SCIM `manager` attribute (15 attribute use; ROUTE-006 manager chain depth 2).
  3. The case team, and via RVW-B-01 the DB, now know that the source is a direct report of M. That is typically 3–12 people, and one join with HR data (who had access, who was on shift) finishes the identification.
  4. S04b copy (11) says only that ticked people "will not get a key". It never says that **the case team will see what you ticked** (12 R03 "the source's 'people kept out' roles") or that ticking your own manager identifies your team.
- **AFFECTED:** 11 S04b; 14 §8.2, §8.3 (the "honest disclosure" omits it), §8.4, ROUTE-003/-006; 12 R03; 15 SCIM attributes; THR-010, THR-019, THR-040.
- **WHY NOT PREVENTED:**
  - The COI map template treats "subject role" as routing data, not as a quasi-identifier of the reporter.
  - The relationship-to-reporter semantics ("*my* manager") are inherently self-describing.
- **PROPOSED FIX:**
  1. **14 §8.2:** remove the relational subject "Source's direct manager" from the default template. Replace it with non-relational options: "a manager in my reporting line" (resolved by the Triage Set of RVW-B-02, not by directory lookup) or named roles only.
  2. **11 S04b:** add the mandatory `sec:critical` sentence: "The people handling your report will see which boxes you ticked. Ticking your own manager tells them which team you work in."
  3. **05:** add a guidance card (GC-new) on "who-you-report-about reveals who you are".
  4. **15:** SCIM `manager` attribute use SHALL be optional per channel and OFF for ANONYMOUS-only channels.
- **RESIDUAL RISK:** Report content often reveals the reporting line anyway (PR-05).

### RVW-B-04 — Excluded channel members can learn that they are the subject of a report
- **SEVERITY:** High
- **SCENARIO:** An accused member X of the Audit Committee channel is excluded cryptographically, but learns of the report through four independent signals:
  - **(a) Trial decryption.** X's Desk lists channel envelopes, finds one it cannot open, and a modified Desk shows it (06 R-3; 09 §13 "reveals *that* it was excluded… on a given day").
  - **(b) Notifications.** `notify_intake_available` notifies the **whole channel roster** (07 job table), so X is told "action requires attention" and then finds nothing.
  - **(c) M1 dashboards.** M1 "Channel operations" shows monthly counts of channel cases with k ≥ 5 for cells X cannot open (03 §12.1). X subtracts the cases they can see (M0) and gets exactly the number of cases they are excluded from. Suppression ignores the viewer's own knowledge.
  - **(d) Workload.** Colleagues' SLA reminders and task lists spike.

  X now knows a report concerns them and its received day. That is the precondition for retaliation and evidence destruction (INC-22 Barclays/Staley).
- **AFFECTED:** ADR-030, ADR-033(1); 06 R-3, O-2; 09 §13; 07 §job `notify_intake_available`; 03 §12.1 M1, §12.2; 14 §6.5; 12 R02; THR-020.
- **WHY NOT PREVENTED:**
  - ADR-033 hid exclusions from servers but not from the excluded member.
  - k-suppression assumes the viewer knows nothing about the underlying records (no "subtraction attack" model).
- **PROPOSED FIX:**
  1. **ADR (new):** "Chaff envelopes". C-07 emits a Poisson stream of chaff envelopes per channel (rate λ = max(1/day, 2× the median real rate)), with all 16 slots dummy. "An envelope I cannot open" then becomes the normal case for every member. Chaff is dropped at import by Triage Set Desks: they cannot open it either, and a signed "chaff" marker inside a slot keyed to a separate chaff key known only to the Triage Set identifies it.
  2. **03 §12.1 M1:** counts SHALL include only cases the viewer can open (M0), or be restricted to the channel owner. The owner SHALL be hidden from counts of cases from which the owner is excluded.
  3. **07/23 (new NOTIF rule):** notifications to channel rosters SHALL be constant-rate (one digest per member per business day at a fixed time, sent whether or not there is activity), or pull-only (Desk task list). This also fixes RVW-B-05.
  4. **30:** add AT (new) "exclusion inference". An excluded member with a modified Desk and all M1 views SHALL NOT distinguish, better than chance plus 5 %, days with a report excluding them from days without.
- **RESIDUAL RISK:**
  - Chaff costs storage.
  - A colluding non-excluded member can still tip X off (THR-019).

### RVW-B-05 — Notification delivery metadata reveals channel, day and hour to the employer's mail/IT staff
- **SEVERITY:** High
- **SCENARIO:**
  1. Notifications are content-free (ADR-017, META-017), but the **addressee set** is the channel roster, e.g., only the three Audit Committee members' addresses.
  2. The send slot is the next hourly digest after import (07 §6.3 "run_after = next hourly digest slot + U(0,10 min)").
  3. The corporate Exchange/M365 admin or DLP, often in IT under the CIO/CFO, sees "Candor notification to {Audit Committee members} at 14:07 on 2026-09-30". That reveals channel choice and import hour, i.e., submission within about 1.5 h. 03 §9 rates this "Negligible".
  4. Mail relays retain these logs for months, outside Candor's retention control.
- **AFFECTED:** ADR-017, ADR-010; 03 §9 (row "Notifications + mail provider"), META-017; 07 job `notify_intake_available`; 14 §6.5, CASE-009; 30 AT-043 (tests only jitter within a slot, not addressee-set leakage); THR-028, THR-011.
- **WHY NOT PREVENTED:**
  - Content minimization was done.
  - Traffic analysis of *who receives* and *when* was not modelled. Hourly jitter does not hide day or hour.
- **PROPOSED FIX:**
  1. **ADR-017 amendment:**
     - (i) Default delivery is a **fixed daily time** per tenant, sent to **all** staff holding any Candor role (constant set), every business day, regardless of activity ("Candor daily reminder: check your task list").
     - (ii) An alternative is pull-only (Desk tray badge), with no external notification. This SHOULD be the default for HIGH-profile channels.
     - (iii) Per-event notifications to channel rosters SHALL be a WEAKENING configuration with warning text.
  2. **03 META-017:** amend accordingly.
  3. **30 AT-043:** extend. The notification addressee set and send times SHALL be statistically independent of which channel received a submission (χ² over 1,000 randomized submissions across channels).
- **RESIDUAL RISK:** Staff reacting to the reminder (logging into Desk) is still visible to IT (RVW-B-31).

### RVW-B-06 — Exact timestamps of source-driven events give submission time to ±25 min despite "date only" promises
- **SEVERITY:** High
- **SCENARIO:** On a quiet instance (say 3 reports per month), an adversary with any one of the following recovers submission time to within one relay interval (15±10 min):
  - `case.imported` carries `received_day`, but the common envelope `ts` is **millisecond** for all CASE events (20 §4). ADR-033(4) says the import event "records the date only".
  - The Core-DB WAL commit timestamps of relay inserts are archived in backups (09 O-2).
  - `sys.relay_pull` SYSTEM events have second-precision `ts` and `batch_count_bucket` (0 vs 1–9). A pull with a non-zero bucket brackets the arrival between the previous and current pull (20 §5.3). They are readable by SYS_ADMIN and included for 7 days at minute precision in support bundles (32 §8).
  - Import-triggered job rows exist until completion (07 §6.3).
  - Source-initiated C4 escalation events are evaluated hourly (14 §9.4, CASE-017/018).

  Combined with employer proxy logs of Tor usage, this identifies the source (INC Reality Winner class). The source is told otherwise:
  - GC-01: "We only record the date a report arrives, not the time."
  - GC-34: "This site stores only the date a report arrives, not the time."
- **AFFECTED:** ADR-010, ADR-033(4); 20 §4 (`ts`), §5.2, §5.3 `sys.relay_pull`, §16.2, Open Issue "ADR-010 exact staff timestamps vs import"; 09 O-2, §13; 32 §8 (support bundle time precision); 14 §16.5; 05 GC-01, GC-34; 30 AT-021/022 (accept "upper bound" as honest), AT-040; THR-011.
- **WHY NOT PREVENTED:**
  - ADR-010 permits exact timestamps for "staff actions", and import is treated as a staff/system action even though its timing is a function of the source's timing.
  - SYSTEM events were never classified as source-derived.
  - Four documents each flag a piece as an "open issue" or "residual", but no one owns the aggregate budget.
- **PROPOSED FIX:**
  1. **ADR-010 amendment (new ADR):** "Any event, row or log whose time is causally triggered by a source action (import, relay pull with arrivals, source-initiated escalation, mailbox-closed detection) is SOURCE-DERIVED and SHALL be recorded at UTC-day granularity or at a fixed daily time."
  2. **09/07:** adopt O-2 alternative B, a **single daily import transaction** at a fixed tenant time. Make it the default for all profiles (import delay ≤ 24 h is compatible with 7-day ACK and with auto-ACK, §6.4). Keep 15-min pulls only as a WEAKENING option.
  3. **20 §5.3:** remove `batch_count_bucket` from `sys.relay_pull`, or emit only a daily `sys.relay_daily {pulls_ok, pulls_failed}`.
  4. **20 §4:** CASE events with `actor=system:*` SHALL carry `ts` truncated to the day.
  5. **32 §8:** truncate all bundle times to the hour, and exclude relay events.
  6. **05 GC-01/GC-34:** keep the text only once 1–5 hold; otherwise state the residual honestly.
  7. **30:** see RVW-B-29 (correlation test).
- **RESIDUAL RISK:**
  - Staff who act immediately on a daily import leak only the import time, which is fixed and hence uninformative.
  - A live Z-INTAKE compromise still sees exact times (PR-02).

### RVW-B-07 — Four incompatible regimes for SOURCE-SENSITIVE counters; the weakest leaks hourly activity
- **SEVERITY:** High
- **SCENARIO:** The same counters are specified differently in each document:

  | Source | Granularity | Scope | Threshold / retention |
  |---|---|---|---|
  | 03 §12.4 (M4) | 7-day rolling buckets {0, 1–4, …} | instance-wide, never per channel | 30 days daily, 90 days bucketed |
  | 20 §5.4 | per channel per `received_day` in C-08, monthly in C-24 | per channel | monthly k ≥ 10/20, kept 13 months |
  | 09 `counter_daily` | per channel per day | per channel | "exported only with k ≥ 5" (BE-030); `v_case_counts` gives admins counts per channel, state and **week** with k ≥ 5 (09 §6.4), contradicting AUI-001 and M4 |
  | 13 §5.3 (SOC UI) | "all-request rate bands **per hour**", "submission counts **daily**" | — | — |
  | 30 AT-023 | "daily thresholded aggregates" to the SIEM | — | contradicts 20 §13, where no counters are exported |

  A SOC analyst on a small instance sees the hourly request-rate band move from 0 to 1 at 22:00–23:00 on Tuesday. Employer VPN/Tor logs show that employee E used Tor at 22:10 that day. Rolling 7-day buckets recomputed daily leak the day by differencing consecutive windows.
- **AFFECTED:** ADR-016; 03 §12.1 M4, §12.4, META-018, PRIV-007; 20 §3, §5.4, §12, LOG-011; 09 `counter_daily`, §6.4 `v_case_counts`; 13 §5.3, SOCUI-001; 23 SMB-008; 30 AT-023, AT-065/066; THR-039, THR-016.
- **WHY NOT PREVENTED:**
  - Each document re-specified counters locally.
  - The 39 traceability matrix checks that requirement IDs exist, not whether parameters are consistent.
  - AT-065/066 test "aggregate endpoints", not SOC event views.
- **PROPOSED FIX:**
  1. **03 §12.4** becomes the single normative source. 20 §5.4, 09 `counter_daily`, 13 §5.3 and 30 AT-023 SHALL reference it, not restate it.
  2. Normative content of that single source:
     - no per-hour source-derived bands anywhere;
     - **tumbling** (non-overlapping) 7-day windows, published once after the window closes;
     - no per-channel counters below M2;
     - `v_case_counts` for admins removed (admins need capacity data, which `sys.capacity` gives).
  3. Add a CI "spec-constant lint" to 39: machine-readable constants (k, windows, retention) declared once and referenced elsewhere.
- **RESIDUAL RISK:** On very low-volume instances, even weekly buckets reveal "≥ 1 report this week".

### RVW-B-08 — Inconsistent k-thresholds and granularity, and non-count statistics (medians, ratios) that bypass suppression
- **SEVERITY:** High
- **SCENARIO:**
  1. The documents disagree on thresholds:

     | Document | Management audience | Public/statutory audience |
     |---|---|---|
     | 03 §12.1 | M2 k ≥ 10, **quarterly**, "configurable upward only" | M3 k ≥ 20, **yearly** |
     | 14 §14, CASE-026 | GOVERNANCE k default 10, **minimum 5**, **monthly** | PUBLIC k 20, minimum 10, monthly |
     | 24 §9.2 | k = 20, lowerable to 5 (dangerous), month minimum | — |
     | 32 §7 CFG `metrics.k_threshold` | "lower k" is an allowed WEAKENING setting | — |

     An implementer following 14, the document that owns the report catalog, ships monthly board dashboards at k = 5.
  2. The KPI list (14 §14) includes "median days to acknowledge/feedback/close", "substantiation rate", "retaliation/detriment reports" and "canary escalations count". k-suppression is defined for **counts** only. A median over a channel-month with 3 cases, or a substantiation rate of 1/1, discloses individual case attributes.
  3. "Mode (ANONYMOUS vs other, as totals only)" can still be differenced across periods.
- **AFFECTED:** 03 §12.1–12.3, PRIV-004/005; 14 §14, CASE-026; 24 §9.2, TEL-010/011; 23 CE-009, SMB-008; 20 LOG-011 (points to 14); 32 §7; THR-039.
- **WHY NOT PREVENTED:**
  - No single owner for SDC parameters.
  - The SDC design covers frequency tables but not magnitude tables (medians, ratios) or dominance rules.
- **PROPOSED FIX:**
  1. **03 §12** is normative; 14 §14 and 24 §9.2 are reduced to references.
  2. Fix the values: M2 k ≥ 10, quarterly (monthly only above 240 reports per year); M3 k ≥ 20, yearly; lowering k is DANGEROUS and never below 10 for M2.
  3. Add a **magnitude rule** to 03 §12.2 (PRIV-017, new): medians and percentiles are published only if n ≥ k, and rounded to whole weeks. Ratios are published only if the denominator ≥ k and the numerator is not in {0, n}. Otherwise show "—".
  4. Extend `stats-inference` (24 §9.4) and AT-066 to magnitude statistics.
- **RESIDUAL RISK:** Rich side knowledge (PR-06).

### RVW-B-09 — Sliding windows, bucket boundaries and rule switches enable differencing over time
- **SEVERITY:** Medium
- **SCENARIO:** Four switching points each leak a single report:
  - **(a)** M4 "rolling 7 days" re-evaluated daily. A transition 0 → "1–4" on day D pinpoints a submission on D.
  - **(b)** Telemetry `new_cases_bucket` (24 §8.2 #21). An instance hovering at 19 cases per month flips from "<20" to "20–49" when one report arrives, and the vendor sees that.
  - **(c)** 03 §12.1 switches M2 from quarterly to monthly when the prior 12 months reach ≥ 240 reports, and the small-tenant rule (§12.2 rule 5, < 50 reports) switches between "single total" and breakdowns. Published tables before and after a switch can be differenced.
  - **(d)** 24 §9.3: "Dashboards update daily at a fixed time". Daily-refreshed cumulative monthly figures are daily deltas.
- **AFFECTED:** 03 §12.1–12.4; 24 §8.2 #21, §9.2–9.3, TEL-007; 30 AT-066; THR-039.
- **WHY NOT PREVENTED:** Temporal differencing (03 §12.2 rule 6) was considered only for regenerated reports of the same period, not for rolling or cumulative displays or regime switches.
- **PROPOSED FIX:**
  1. **03 §12.2** (new rule 8): all displays are tumbling-window and published only after the window closes. No intra-period cumulative figures for M1+.
  2. Regime switches are evaluated **once a year** with hysteresis (switch back only after 2 consecutive years below the threshold).
  3. For M3 public statistics, adopt a formal privacy-accounting mechanism (e.g., bounded discrete-Gaussian noise with a published annual budget) in addition to k. Record this as an open research item in 03 §15.
  4. **24:** drop `new_cases_bucket` from telemetry, or report it only yearly.
  5. **30 AT-066:** add "before/after one submission" across rolling displays and regime switches.
- **RESIDUAL RISK:** Noise lowers statistical utility for regulators; statutory exact-count reporting may be legally required (24 §9.2 note).

### RVW-B-10 — Channel choice, `routing_visible` fields and `category_class` act as server-visible quasi-identifiers
- **SEVERITY:** High
- **SCENARIO:**
  1. Channels are department-scoped (15 AUTHZ-008; 21 §… "Division/Department … used for routing"). A channel such as "Plant 7 Safety" serves 14 staff.
  2. M2 allows the `channel` dimension (03 §12.1) and only M3 forbids "channel names that identify small bodies". `counter_daily` and `v_case_counts` are per channel (RVW-B-07). The public Key Directory publishes each channel's roster (ROUTE-002), which reveals how small the unit is.
  3. EE `routing_visible` fields (21 ENT-007) let a tenant make **any** questionnaire field (e.g., "site", "shift") server-visible. The only safeguard is a "visible to the routing system" label to the source.
  4. `category_class` becomes server-visible when any SLA or route rule needs it (14 §3, CASE-012).
  5. All of these are visible to admins, the DB, backups and the MANAGED vendor for the case lifetime.
- **AFFECTED:** 03 §12.1 M2/M3, §8.2 F21; 14 §3, CASE-012, OI-14-1; 21 ENT-007; 15 AUTHZ-008; 09 `case.channel_id`, `category_class`; THR-015, THR-039, THR-011.
- **WHY NOT PREVENTED:**
  - Channel is treated as routing data, not as a population attribute.
  - No minimum population size exists for a channel.
- **PROPOSED FIX:**
  1. **14/03** (ROUTE-015, new): every channel declares `population_estimate`.
     - Channels with population < 50 SHALL NOT appear as a separate dimension in M1–M3 or admin views.
     - They are merged into declared channel groups of ≥ 2 channels and ≥ 250 population (aligning with 24 §9.3 "channel groups").
  2. **21 ENT-007:** `routing_visible` fields SHALL be prohibited in ANONYMOUS-mode channels unless the field is an enumeration in which every value has a declared population ≥ 50. Values SHALL be stored only inside the encrypted case record, and routing SHALL be evaluated by the Triage Set Desk (RVW-B-02) rather than server-side.
  3. **14 OI-14-1:** resolve in favour of client-side category routing; `category_class` is never server-visible for ANONYMOUS reports.
- **RESIDUAL RISK:** Channel choice remains visible to case members and to the DB for the case (inherent to routing).

### RVW-B-11 — Per-source activity timelines are stored, contradicting META-007 (intersection attack by visit days)
- **SEVERITY:** High
- **SCENARIO:** The following records each accumulate a timeline of source activity:
  - C-12 `import_envelope` rows hold `kind ∈ {initial, followup}` and `received_date`, and are linked to the case via `submission` (09). They are retained **for the case lifetime** and visible to the DB, backups and the MANAGED vendor.
  - The Case Desk shows each message's day (12 R04).
  - C-08 `source_account.activity_day` stores the last day an envelope was committed (09).
  - 03 META-021 specifies per-account padded bytes **per UTC day for 30 days**, i.e., a 30-day upload calendar per account. 09 `quota_bucket` keeps only the current day; the two documents disagree.
  - 35 D-03 retains replies "until **read** + 30 days", which needs read tracking.
  - 35 §9 deletes mailboxes after "**no login** for 365 days", which needs login tracking.
  - 30 AT-047 permits "reply deletion at a batch-aligned time" after reading.

  **Attack:** the employer holds Tor-usage logs (proxy, EDR, Wi-Fi) for all employees. Each follow-up day D_i gives a candidate set S_i = {employees who used Tor on D_i}. The intersection ∩S_i collapses to about one person after 3–4 follow-ups, even with thousands of daily Tor users (a classic statistical-disclosure / intersection attack). The case team is itself the organization, and is shown these days in the Desk.
- **AFFECTED:** ADR-010; 03 META-007, META-021, §8.2 R-03 note 1; 09 `import_envelope`, `submission`, `source_account.activity_day`, `quota_bucket`; 35 D-02, D-03, §9; 12 R04; 30 AT-047; 05 GC-33 (guidance only); THR-011, THR-002.
- **WHY NOT PREVENTED:**
  - Each record individually is "day granularity, permitted by ADR-010".
  - Nobody analysed the **sequence** of days, which is the actual identifier.
  - Retention and abandonment rules were written against a login-tracking mental model.
- **PROPOSED FIX:**
  1. **09:** drop `import_envelope.kind` and null `received_date` for follow-ups after import. Store follow-up dates only inside the encrypted case record (Desk needs them; the server does not). The case-level `received_date` (first envelope) remains for SLA.
  2. **03 META-021:** replace with "quota is enforced per session in C-07 RAM plus a per-account counter for the current epoch-week only, overwritten weekly".
  3. **09:** `activity_day` coarsened to month.
  4. **35 D-03/§9:** retention SHALL be based on `available_day` + N days (as 09 already does) and account-level `activity_day` (month). Remove the words "read" and "login".
  5. **30 AT-047:** remove the "reply deletion" exception.
  6. **12:** for channels flagged HIGH (or when the source answered "1–5 people know"), Desk displays follow-up dates at ISO-week granularity.
  7. **11/05 (Tier V):** add "Send later" (the client queues a follow-up and releases it at a random time 12–72 h later, while the app is next open). **05 GC-33:** add the explicit advice "batch your messages; each visit day can be compared with who used Tor that day".
- **RESIDUAL RISK:**
  - Network observers of the source still see Tor use (THR-002).
  - Cover traffic (05 OI-05-4) is the only full fix.

### RVW-B-12 — Draft storage: four contradictory designs; the PRD promise is broken and timestamps leak
- **SEVERITY:** Medium
- **SCENARIO:** The documents specify four different draft designs:

  | Source | Design | Timers |
  |---|---|---|
  | 01 PRD §7.8 / PRD-053 | The UI SHALL tell the source "typed text is not saved server-side" | — |
  | 03 R-02 | "draft parts held only in C-07 RAM, ≤ 2 h" | META-014: idle 20 min, absolute 2 h |
  | 06/07/09 | `draft_part` blobs in C-08 with `draft_generation` (hourly counter), ≤ 3 h | — |
  | 11 §5.6 | all answers, identity block, file names, chosen mode and the generated passphrase stored in C-08 as AEAD under the cookie-derived `k_draft` | kept **24 h** (T_DRAFT 20–48 h); expiry stored at 1-hour granularity; T_IDLE_AUTH 30 min; T_ABS_AUTH 4 h (range 1–8) |

  Consequences:
  - **(a)** The source is told something false: the PRD copy versus 11's "Your draft is kept only while this Tor Browser window stays open".
  - **(b)** Hour-granular expiry = last-save hour + 24 h, which is an on-disk source activity time finer than a day (ADR-010). The 07 `draft_generation` "hourly counter, not wall time" is equivalent to wall time, because `sys.service_started` gives boot time.
  - **(c)** C-08 PostgreSQL pages, WAL and (per META-016) BS-INTAKE backups can retain draft ciphertext of reports the source **chose not to send**, plus identity blocks for CONFIDENTIAL drafts later reverted to ANONYMOUS (S05b "Remove my name…").
  - **(d)** Draft attachments are sealed immediately to channel epoch keys (11 §5.6), so an abandoned draft attachment is decryptable by recipients if the ciphertext is ever relayed or leaked with an epoch key.
- **AFFECTED:** ADR-005, ADR-010; 01 PRD-053, §7.8; 03 R-02, META-014; 06 §… `candor-sealer` "RAM-only drafts"; 07 `draft_gc`; 09 `draft_part`; 11 §5.6, §5.7, OI-11-6; 19 BS-INTAKE; THR-048, THR-011, THR-017.
- **WHY NOT PREVENTED:** 11 raised OI-11-6 but the conflict was never resolved in DECISIONS, and 03 §8 was not updated (META-001 violation).
- **PROPOSED FIX (which should win):** 11's *need* is legitimate (no-JS multi-step state, WCAG 2.2.1), but 03's **bounds** should win. New ADR:
  - Drafts are stored as ciphertext under `k_draft` in a **tmpfs-backed, UNLOGGED** store on the intake host. It is excluded from WAL, backups and replicas.
  - Absolute lifetime is 2 h (idle 20 min, per META-014), which satisfies WCAG 2.2.1 via warning plus extension.
  - No wall-clock or generation counter is persisted per draft: GC walks drafts by an in-RAM index, and a restart purges all.
  - Draft attachments are sealed to a per-draft ephemeral key derived from `cs` and re-wrapped (content-key re-wrap only) to Member Epoch Keys at commit.
  - Identity blocks are zeroized on revert.
  - Amend 01 PRD-053 copy to: "Your draft is saved encrypted only for this browser window, for at most 2 hours; we can't read it."
  - Amend 03 R-02 and §8 accordingly.
- **RESIDUAL RISK:** Live intake compromise sees drafts (Tier W, PR-01).

### RVW-B-13 — The passphrase is persisted server-side for re-display, contradicting ADR-005 and the published compulsion inventory
- **SEVERITY:** Medium
- **SCENARIO:**
  1. SUI-028 and T_SAVED_CRED (11 §5.6) store the passphrase as ciphertext in C-08 for up to 60 min after submit.
  2. 03 §10.1 publishes "Source Passphrase: Exists? **No**", and R-02 note 8 says "zeroized after key derivation".
  3. An adversary holding a C-08 snapshot or BS-INTAKE backup who later obtains the `cs` cookie (browser memory forensics after seizure, or a live C-06 compromise during the window) recovers the passphrase, and with it all future replies and impersonation.
  4. More importantly, the published inventory (PRIV-002) is inaccurate. That is an honesty defect for operators answering legal requests.
- **AFFECTED:** ADR-005; 03 §10.1, R-02 note 8, PRIV-002; 11 §5.6, S10, SUI-028, "Open Issues for ADR revision"; THR-034.
- **WHY NOT PREVENTED:** Robustness against dropped Tor responses was solved by persistence instead of by flow design.
- **PROPOSED FIX:**
  1. **11:** show the passphrase **before** final send.
     - S09 becomes "Save your passphrase", showing the words, then a confirmation step asking for words #3 and #8 (prevents "I'll save it later" and improves recall, RVW-B-26).
     - Only then POST `/send`. An interrupted response after commit is recoverable because the source already has the passphrase: the S10 "sent" page is simply a login.
  2. Delete T_SAVED_CRED and SUI-028's re-display clause. The passphrase is held only in C-07 RAM for the duration of S09 (≤ 20 min idle).
  3. **ADR-005:** keep "shown once".
- **RESIDUAL RISK:** Live C-07 compromise (AT-024).

### RVW-B-14 — Mode and honesty defects in source-facing copy
- **SEVERITY:** High
- **SCENARIO:** Six defects in the copy sources rely on:
  - **(a)** 03 §7 mandates the ANONYMOUS banner "Candor does not collect who you are. **Your writing and files can still identify you.**" 11 §5.2 (the implementing spec) drops the second sentence: "You have not told us who you are. This site cannot see your internet address." The most important caveat disappears from the only text every source sees.
  - **(b)** GC-01 says "No one outside the listed team can unlock reports". That ignores Identity Custodians (for C1), OVERSIGHT SILENT_MEMBER (14 §9.4, which is listed only if the source reads the descriptor), and **break-glass** (06 ARCH-025 grants content access via a key wrap to a non-member).
  - **(c)** GC-01 and GC-34 "only the date, not the time" are false (RVW-B-06).
  - **(d)** CONFIDENTIAL copy (11 S04 mock-up): "Only 2 named custodians can see your name, with approval." It omits three things: custodians are employees of the organization being reported on; unsealing can be legally compelled (03 PR-07); and the unseal notice can be deferred indefinitely (PRIV-008 re-reviews every 90 days, with no maximum).
  - **(e)** ADR-002 allows only CONFIDENTIAL via onion; 11 adds IDENTIFIED (see 11 "Open Issues for ADR revision"), which is unresolved.
  - **(f)** C-38 clearnet copy is good. But the CONFIDENTIAL (C1) banner on the onion does not say that the report content is readable by the case team (the misconception "confidential = content secret from my employer").
- **AFFECTED:** ADR-002, ADR-013, ADR-014; 03 §7, ANON-007/013, PRIV-008; 05 GC-01, GC-34, §9 "Accuracy" check; 11 §5.2, S04, S05b; 06 ARCH-025; 14 §9.4; 30 AT-060, AT-070 questionnaire; THR-040.
- **WHY NOT PREVENTED:**
  - 05 §9 "Accuracy: zero mismatches" is a manual review, with no machine link between normative strings in 03 and the Fluent catalog in 11.
  - Break-glass and oversight were designed in other documents after GC-01 was written.
- **PROPOSED FIX:**
  1. **11 §5.2:** restore the 03 §7 text verbatim. Add SUI-new: "`sui.mode.*` strings SHALL be generated from 03 §7 (single source); CI diff fails on mismatch."
  2. **05 GC-01:** "Who can unlock reports: {recipient roles}; {oversight_statement}; {break_glass_statement}; {escrow_statement}", each generated from live configuration.
  3. **11 S04/S05b:** add "The custodians work for {organization}. A court or regulator can require them to reveal your name. If they do, you will normally be told, but this can be delayed."
  4. **03 PRIV-008:** cap deferral at 12 months total unless a court order is recorded.
  5. **DECISIONS:** resolve IDENTIFIED-via-onion.
  6. **30 AT-070:** add knowledge items: "the organization's staff can read what I write in confidential mode" (true); "someone outside the listed team can ever open my report" (depends; shown).
- **RESIDUAL RISK:** Comprehension varies (05 §11.7).

### RVW-B-15 — Staff-recorded self-identification makes the CONFIDENTIAL guarantee false for that report
- **SEVERITY:** Medium
- **SCENARIO:**
  1. The source writes "I'm Jane from payroll" in a follow-up.
  2. Under ANON-010 staff record this, and the mode becomes CONFIDENTIAL. The "identifying excerpt" is sealed to custodians only "**on request**", so the message remains readable by every case member and in every Export Package that includes the conversation.
  3. The source then sees the CONFIDENTIAL banner, whose meaning (11 §5.2: "Only {custodian_label} can see your name") is now false.
- **AFFECTED:** 03 §6, ANON-010; 11 §5.2; 14 §11; ADR-014; THR-040, THR-111.
- **WHY NOT PREVENTED:** The mode label was attached to the report, not to where identity data physically lives.
- **PROPOSED FIX:**
  1. **03 ANON-010:** sealing of the excerpt SHALL be mandatory and immediate. Desk replaces the passage with "[identity sealed]" in the case copy and re-encrypts; export templates exclude unsealed identifying passages.
  2. Introduce a distinct mode label "CONFIDENTIAL (identity seen by case team)" when members have already read it.
  3. The mailbox notice tells the source exactly who has seen it.
- **RESIDUAL RISK:** Members remember what they read.

### RVW-B-16 — Tier V "stronger protection" upsell pushes mobile sources into app-store and MDM records
- **SEVERITY:** Medium
- **SCENARIO:**
  1. Every Tier W page says "For stronger protection use the verified app" (03 §7).
  2. On iOS the Source App is available only via the App Store (33 §… distribution table; "not user-verifiable", residual §20). The install is permanently tied to the Apple ID purchase history, which is subpoenable and visible on family-sharing devices.
  3. On a phone with any MDM enrolment, the installed-app inventory reports "Candor Source" to the employer.
  4. ADR-004 itself rejected native-only because "installation leaves device traces (THR-048)".
- **AFFECTED:** ADR-004; 03 §7; 11 §8; 33 §(artifact matrix), §20; 05 §B; THR-048, THR-002.
- **WHY NOT PREVENTED:** The tier recommendation is one-dimensional (crypto strength) and ignores install-trace cost per platform.
- **PROPOSED FIX:**
  1. **03 §7/11 §5.2:** the tier line is platform-neutral ("Web mode: encrypted on arrival. [What are my options?]").
  2. **05:** new card "Choosing web or app". The desktop app (AppImage/Tails) or Tor Browser is recommended. The iOS App Store app states "Apple keeps a record that your account downloaded this app". Never install on a phone managed by your employer.
  3. **33:** Android via F-Droid/direct APK only; iOS listed as "higher trace" in the UI.
- **RESIDUAL RISK:** Sources may choose Tier W and accept PR-01.

### RVW-B-17 — The Clearnet Information Site is the most dangerous first contact and the guidance comes too late
- **SEVERITY:** Medium
- **SCENARIO:**
  1. An employee clicks the intranet "Speak Up" link to C-37 (e.g., `speakup.example.com`) from a work laptop.
  2. The corporate proxy and EDR log the visit with a timestamp and username before any guidance is displayed. C-37's own no-logging (META-024) is irrelevant.
  3. The later onion submission, received the same or next day (the day is known to recipients), is then intersected with "who visited the Speak Up page this week".
- **AFFECTED:** ADR-003; 03 §11 obligations 2–4, META-024; 05 §7 placement map (C-37 row), SOPS-026; THR-002, THR-036.
- **WHY NOT PREVENTED:** The threat model treats C-37 as a benign publication point; the employer's own clearnet logging of *the first hop* is not modelled.
- **PROPOSED FIX:**
  1. **05** (SOPS-new): organizations SHALL be advised to publish the onion address offline (posters, printed cards, QR codes, payslip inserts) and, on intranets, as **non-hyperlinked text** with "Don't open this at work. Copy it into Tor Browser at home."
  2. C-37's first viewport shows GC-04/GC-05 ("If you are on a work device or network, stop here") above everything else.
  3. **03 §11:** recommend hosting C-37 on a neutral, multi-organization directory domain run by the project (a larger anonymity set than `speakup.<employer>`), as an option.
  4. **30:** usability item in AT-070: "visits C-37 from simulated work network" counted as a source SCE.
- **RESIDUAL RISK:** Organizations may ignore the advice.

### RVW-B-18 — Support bundles and vendor support reveal deployment structure and source-driven timing
- **SEVERITY:** Medium
- **SCENARIO:** The bundle allow-list (32 §8) includes:
  - SYSTEM logs of H-CORE for 7 days at **minute** precision, including `sys.relay_pull` with arrival buckets (RVW-B-06);
  - the "effective non-secret config", which includes channel names and role labels, COI maps, SLA/jurisdiction packs, holiday calendars and timezones (location), and `display_label`;
  - consistent per-bundle `user-<HMAC8>` pseudonyms (activity patterns per staff member);
  - an optional scrubbed intake-log section (`support.bundle.include_intake_logs`).

  Consequences:
  - The vendor learns the org chart of the whistleblowing function and arrival timing.
  - The operator keeps `bundle.key`, so it can re-identify on request, and the vendor can ask.
  - Retention also conflicts: 32 §8 says vendor retention ≤ 30 days; 03 §10.3 says support tickets and bundles are kept 2 years.
- **AFFECTED:** 20 §14, LOG-019; 32 §7, §8, OPS-008; 13 AUI-021; 21 ENT-020; 03 §10.3; 30 AT-013 (canary-literal only); THR-027, THR-016.
- **WHY NOT PREVENTED:**
  - The scrubber is pattern-based and removes identifiers.
  - Configuration semantics and SYSTEM time series are not treated as sensitive.
- **PROPOSED FIX:**
  1. **32 §8:** config is included only as `{key, class, value_hash}` except enumerated/boolean values. No channel, role-label, COI or calendar content.
  2. SYSTEM events are truncated to the hour, and `sys.relay_*` excluded.
  3. Staff pseudonyms are removed (use role labels).
  4. Unify vendor retention at ≤ 30 days in 03 §10.3.
  5. **30 AT-013:** add semantic checks (no relay events, no config strings from a seeded config).
- **RESIDUAL RISK:** Screenshots and ticket text typed by admins remain out of scope.

### RVW-B-19 — MANAGED service: the vendor sees all server-visible metadata of all customers; 03 §10.3 understates it
- **SEVERITY:** High
- **SCENARIO:** In MANAGED the vendor operates Z-INTAKE, Z-CORE, backups, the Fleet Manager and support. Compelled or malicious, it obtains, for every customer:
  - COI exclusion identities (RVW-B-01);
  - follow-up day timelines (RVW-B-11);
  - exact `case.imported` / WAL times (RVW-B-06);
  - SECURITY audit including staff IPs (90 days);
  - CASE audit (all investigator actions, with ms timestamps);
  - notification addressees (the whistleblowing staff list);
  - live Tier W plaintext via hypervisor snapshots (AT-031).

  03 §10.3 lists only "Case metadata, received days, padded sizes" and "Staff accounts, audit logs". One legal order to the vendor covers many organizations at once (cross-customer aggregation), and 03 PR-08 only mentions the customer↔onion mapping.
- **AFFECTED:** ADR-021, ADR-024; 03 §5 (Vendor column marks source identity "P"), §10.3, PR-08, PRIV-012; 18 MANAGED profile; 30 AT-031/032; THR-026, THR-027, THR-030.
- **WHY NOT PREVENTED:**
  - "Vendor cannot decrypt content" was treated as sufficient.
  - The vendor column in the §5 matrix is not reconciled with the §10.3 inventory.
- **PROPOSED FIX:**
  1. **03 §10.3:** enumerate every server-visible datum (generated from 09 classification SS/WF/SEC), and change the §5 "Vendor" cells for timing/linkage to PA.
  2. **New ADR:** in MANAGED, CASE audit events are encrypted to a customer-held audit key (the hash chain is computed over ciphertext; the witness remains customer-side). Tier V is **mandatory** for channels flagged HIGH. Backup KEKs are customer-held (IRK shares with customer custodians only). The RVW-B-01/-06/-11 minimizations are prerequisites for offering MANAGED.
  3. **PRIV-012:** transparency report per jurisdiction, plus a canary statement.
- **RESIDUAL RISK:** Hypervisor-level observation of Tier W remains (PR-01, AT-031).

### RVW-B-20 — Fleet Manager and telemetry: small inconsistencies and quasi-identifiers
- **SEVERITY:** Medium
- **SCENARIO:**
  - **(a)** 03 §10.1 says Fleet Manager stores a "salted onion hash". 21 §9.2 says neither address nor key is sent. If the vendor knows the salt, a salted hash is a confirmation oracle for "is instance X the onion Y".
  - **(b)** Fleet check-ins over mTLS every 60±30 min reveal the Z-ADM egress IP to a vendor-hosted C-34, which maps instance to customer network. Health maps and `last_checkin_day` give a timeline.
  - **(c)** Telemetry `health-min` includes `crash_counts` per component (24 #14). A C-07 crash burst in a week correlates with a hostile or malformed submission. 24 §8.3 admits the tuples are linkable and EE `health-full` is attributable.
- **AFFECTED:** 03 §10.1; 21 §9.2–9.3, ENT-037..040; 24 §8.2–8.3, TEL-005/008; THR-027, THR-036.
- **WHY NOT PREVENTED:** Documents were edited independently.
- **PROPOSED FIX:**
  1. **03 §10.1:** remove "salted onion hash" (align with 21).
  2. **21:** fleet transport SHALL be over Tor, or customer-hosted, for GOV/HIGH profiles.
  3. **24:** `crash_counts` excludes Z-INTAKE components, and `health-full` is unavailable in GOV-ONPREM.
- **RESIDUAL RISK:** Low.

### RVW-B-21 — Backups defeat metadata deletion; source-facing deletion statements are false; EKV construction is ambiguous
- **SEVERITY:** High
- **SCENARIO:**
  - **(a) Metadata outlives disposal.** The Erasure Key Vault protects only case-key wraps. All server-visible metadata of a disposed case survives in BS-CORE: `coi_exclusion` identities, follow-up days, CASE audit incl. `case.member_removed`, SLA dates, `persons_concerned`-derived exclusions, ACLs. AUD-012 tombstoning and 35 §6.4 minimal tombstones apply only to the live system. Retention also conflicts: 19 BAK-019 says BS-CORE ≤ 35 days by default; 35 D-15 says "35 days daily, 12 weeks weekly, **12 months monthly**". On the 35 reading, "who was accused, when the source wrote" persists 12 months after the organization "deleted" the case.
  - **(b) Intake backups contradict each other.** 03 META-016, 19 BS-INTAKE (14 days, source account records **and pending replies**) and 35 B6/§11 ("Z-INTAKE hosts are not backed up… Intake backups: none") disagree. The source is told the mailbox deletion is immediate (35 §9, 11 S13). 19 §… admits "pending-reply presence reveals which sources were answered".
  - **(c) ADR-033(3) wording.** "Each case key is additionally wrapped under a per-case Erasure Key". Read literally, this is a *direct* wrap. That would give the server (EKV holder) a master key to every case, contradicting ADR-008. 19 OI-5 and 35 §6.2 chose the layered construction, but the binding ADR text still says "additionally wrapped".
  - **(d) Object Lock blocks urgent purges.** Compliance-mode Object Lock (19 BAK-006) makes urgent purges impossible, e.g., an EU Art 17 "manifestly irrelevant" purge (CASE-028) or accidentally captured identity data. The data persists in all locked sets.
- **AFFECTED:** ADR-025, ADR-033(3); 19 §5, §8, BAK-006, BAK-019, BAK-028, OI-5; 35 D-15, §6.2, §6.4, §7 B6, §9, §11; 03 META-016, §8.4, §10.1; 20 AUD-012; 14 CASE-028; 30 AT-026 (expects "union of AT-020/AT-021 metadata as of each backup time", so it would not fail on this); THR-017.
- **WHY NOT PREVENTED:**
  - ADR-025/033 reasoned only about content keys.
  - "Delete" of metadata was scoped to the live DB.
  - Four documents own backup retention.
- **PROPOSED FIX:**
  1. **DECISIONS ADR-033(3):** reword to "member-key wraps are stored encrypted under the Erasure Key (layered); no direct wrap of the case key under the Erasure Key SHALL exist".
  2. **New ADR (metadata erasure layer):** encrypt all per-case server-visible SS/WF rows that need no server-side query after closure (exclusions, follow-up dates, custody/audit payloads of CASE events) under a per-case **Metadata Erasure Key** in the EKV, so disposal propagates to backups within the BS-ERASURE window. Pre-closure fields needed for workflow move under it at closure.
  3. **35 D-15:** align with 19 (≤ 35 days). Monthly/yearly archival sets are ADVANCED, with a warning that metadata persists.
  4. **Intake backups:** remove BS-INTAKE entirely (see RVW-B-22) and correct 03 META-016. Otherwise correct 35 and the source copy to "deleted from backups within 14 days".
  5. **19:** a CASE-028 purge SHALL be implemented by EKV key destruction (it already works through locks). Document that metadata in locked sets remains until expiry.
- **RESIDUAL RISK:**
  - Metadata in locked sets until expiry.
  - WAL pages hold deleted tuples (09 §13).

### RVW-B-22 — Z-INTAKE backups hold source account records "to preserve login ability", which is avoidable data (minimization)
- **SEVERITY:** Medium
- **SCENARIO:**
  1. A BS-INTAKE seizure within 14 days yields `lookup_tag`, `auth_pk`, `xwing_pk`, `activity_day`, `prefs_ct` and pending sealed replies for every active source.
  2. This allows offline guessing of passphrases (only as strong as RVW-B-26 allows), linkage of reply traffic to accounts, and "which sources were answered".
  3. The only purpose is availability of mailboxes after intake host loss (19 §… "exist only to preserve source login ability").
- **AFFECTED:** ADR-009, ADR-025; 03 META-016; 19 BS-INTAKE; 35 §7 B6; 09 `source_account`; THR-017, THR-015.
- **WHY NOT PREVENTED:** "Store securely" was chosen over "don't store".
- **PROPOSED FIX:**
  1. **ADR (new):** "Mailbox re-provisioning instead of intake backup". The Tier V client or C-07 includes in the sealed envelope `{locator_hash, auth_pk, xwing_pk}`; these are already known to recipients as the source public key per R-02 note 10.
  2. After intake loss, a Triage Set Desk re-pushes sealed account records to a fresh intake via C-09, as signed "re-provision" messages.
  3. Remove BS-INTAKE; onion keys stay in the offline backup.
- **RESIDUAL RISK:** Pending replies not yet re-pushed are lost; Desks re-send them.

### RVW-B-23 — The organization itself can identify the source (content + HR + originals), and the platform gives the case team every join key
- **SEVERITY:** High
- **SCENARIO:**
  1. In internal channels the case team **is** the employer.
  2. With Tier W (the default), originals with full EXIF, author, rsid and printer-dot content reach the case (05 §11.3). Originals are viewable in C-17 and exportable with dual approval (ADR-012), with both approvals inside the organization.
  3. EE SCIM supplies `department` and `manager` (15), and `persons_concerned` is mapped to directory users (14 §8.4). The case system now co-locates report content with the HR graph.
  4. Remediation owners and HR receive Export Packages (CASE-015).
  5. The only protection against a curious investigator running "who opened this file on 3 March" is the risk-panel **advice** (12 R03). In the canonical internal-reporting threat (THR-019, INC-22), a malicious triager can identify the source within hours from metadata the source could not see.
- **AFFECTED:** ADR-012, ADR-014, ADR-015; 05 §8.4, §11.2–11.4; 12 R03, RUI-013; 14 §8.4, §10.2, CASE-015/025; 15 SCIM attributes; THR-009, THR-010, THR-019, THR-041.
- **WHY NOT PREVENTED:**
  - The anonymity model protects against the platform operator and network, while the internal-reporting adversary is the recipient organization.
  - Recipient-side controls are advisory.
- **PROPOSED FIX:**
  1. **ADR-012 amendment ("originals custody"):** for ANONYMOUS reports the ORIGINAL evidence DEK is wrapped **only** to an Evidence Custodian set, i.e., the Identity Custodian set (ADR-014) or the independent Triage Set (RVW-B-02). Case members receive only the sanitized derivative, produced automatically in C-17 by the Triage Set Desk at import. Access to originals follows the ADR-014 procedure (legal basis, dual custodian approval, audited, source-notified).
  2. **14** (new "intermediary mode", default for HIGH channels): an independent-body member writes a paraphrased **Case Brief** for management investigators. The source's raw text and files stay with the independent body. This directly limits stylometry and canary-trap matching by management.
  3. **12** (RUI-new): Export Packages to HR/remediation owners and any investigation task tagged "IT log query" require a recorded **candidate-set estimate** ("how many people could this step point to?"). If fewer than 10, a second reviewer from an independent body must approve.
  4. **15:** SCIM `department`/`manager` attributes SHALL NOT be readable by Desk case views (C-22 only).
- **RESIDUAL RISK:**
  - Content knowledge (PR-05).
  - A captured independent body.

### RVW-B-24 — Text-level watermarks and canary traps pass straight through; cheap normalization is not offered
- **SEVERITY:** Medium
- **SCENARIO:**
  1. The source pastes a paragraph from an internal memo into "What happened".
  2. The memo was distributed with per-recipient zero-width characters, homoglyph substitutions or whitespace patterns (a known canary-trap technique; 05 GC-25/26 warn about it).
  3. Tier W sends the text as-is. Tier V's writing-style checklist (05 §8.6) does not detect invisible characters, and the §8.5 identity-hint check looks only for emails, phones and phrases.
  4. The recipient organization matches the marks to one employee.
- **AFFECTED:** 05 §8.5, §8.6, GC-25/26, SOPS-018; 11 S08; THR-010.
- **WHY NOT PREVENTED:**
  - Cleaning was framed as file-metadata removal (ADR-012 forbids server parsing of **files**).
  - Typed or pasted text in C-07 RAM is already processed for §8.5, so normalization there is no new parser surface.
- **PROPOSED FIX:** **05 §8.5** (SOPS-new; mirror in 11 S08):
  - Tier W C-07 and Tier V clients SHALL detect and offer to remove Unicode format characters (Cf: ZWSP/ZWJ/ZWNJ, BOM, bidi controls), variation selectors, tag characters and non-standard spaces.
  - They SHALL flag mixed-script homoglyphs within words.
  - Notice: "Your text contained 14 invisible characters that can act as a hidden signature. [Remove] [Keep]". Default: Remove.
  - Tier V's file cleaner additionally extracts plain text from documents ("send as text only").
- **RESIDUAL RISK:** Semantic canaries (different numbers or wording per copy) survive (05 §11.6).

### RVW-B-25 — OVERSIGHT register and AUDITOR reads are not COI-filtered
- **SEVERITY:** Medium
- **SCENARIO:**
  1. The Head of Internal Audit holds the AUDITOR role, and the board chair holds OVERSIGHT.
  2. A report concerns them.
  3. The OVERSIGHT register (CASE-021: pseudonym, channel, state, flags, SLA status, days since activity) and all tenant CASE events (AUD-006) remain readable by them. So are signed daily register snapshots pulled to their own Desk (CASE-019), which are diffable day to day.
  4. They see the new case in the "Audit Committee" channel on day D, `case.member_removed` (RVW-B-01), and `CANARY_ESCALATED` when investigators stall.
- **AFFECTED:** 14 §9 AS-7, §9.4, CASE-019/021; 20 §3, §9, AUD-006/014; ADR-015; THR-020.
- **WHY NOT PREVENTED:**
  - COI exclusion was applied only to content keys.
  - Oversight and audit roles are presumed independent (14 §16.4 acknowledges capture).
- **PROPOSED FIX:**
  1. **14/20** (new): C-22 applies each case's (blinded, RVW-B-01) exclusion set to register rows and CASE-event reads. An excluded OVERSIGHT/AUDITOR sees the case only as part of an aggregate count, which must itself obey RVW-B-04 (2).
  2. The COI map template SHALL include "AUDITOR/OVERSIGHT role holders" as excludable subjects.
  3. At least 2 OVERSIGHT holders are required, so that one exclusion never blinds oversight.
- **RESIDUAL RISK:** Full capture of oversight (14 §16.4).

### RVW-B-26 — Source-initiated state changes echo into staff-visible and audit-visible events
- **SEVERITY:** Medium
- **SCENARIO:**
  1. The organization interviews three suspects on Monday.
  2. On Tuesday one of them, alarmed, closes the mailbox (05 GC-35 recommends this after seizure risk). At the next reply push the case shows `mailbox_closed` (03 R-07 note 3) and the team is told "the source closed the mailbox" (05 §8.12).
  3. Mailbox closed on day D+1 after interviews narrows the set to the interviewees.
  4. Similar echoes: the "no response" escalation C4 (hourly-evaluated event), source-visible status reads, and "Ask the team to delete my report" messages.
- **AFFECTED:** 03 R-07; 05 GC-35, §8.12; 11 S13; 14 §9.4 C4, AS-10, CASE-017; 35 §9; THR-011, THR-019.
- **WHY NOT PREVENTED:** Each echo is a useful case-management signal; its timing as an inference channel was not considered.
- **PROPOSED FIX:**
  1. **03 R-07/35 §9:** the intake SHALL delay the "mailbox closed" signal to Z-CORE by a uniformly random 3–21 days, and report it at week granularity. C4 escalations are released at a random time within 72 h.
  2. **11 S13:** warn the source: "The team will learn, within a few weeks, that the mailbox was closed. If you close it right after something happens at work, that timing could point to you."
  3. **05 GC-35:** add the same point.
- **RESIDUAL RISK:** Delayed signals reduce the timeliness of oversight escalation.

### RVW-B-27 — Passphrase usability: 10 words is oversized for the threat and drives unsafe storage; there is no lost-passphrase path
- **SEVERITY:** Medium
- **SCENARIO:**
  1. AT-075's own pass threshold is 75 % recovery at 30 days (30 §10.4), so **1 in 4** sources is expected to lose the mailbox.
  2. Those sources either stop communicating, or re-contact identifiably (email, phone, a new report stating "I'm the person who reported X"), which is precisely the bypass THR-040/034 aims to prevent.
  3. Ten words (≈129 bits, ADR-005) pushes users to write the phrase down (THR-048) or sync it via password managers (cloud subpoena).
  4. Against offline attack on `lookup_tag` with Argon2id m=256 MiB, t=3 and a per-deployment salt, 7 EFF words (≈90 bits) already puts an attack at ≥ 2^89 Argon2 evaluations, orders of magnitude beyond any adversary (Knowledge (unverified); needs 04 sign-off).
- **AFFECTED:** ADR-005; 04 KDF parameters; 05 GC-32, OI-05-5; 11 S10, S11; 30 AT-075, §10.4; THR-034, THR-048.
- **WHY NOT PREVENTED:** Entropy was set by analogy to key strength rather than by the offline-attack cost model plus human recall.
- **PROPOSED FIX:**
  1. **ADR-005 amendment:** 7 words by default, 10 for HIGH-profile channels, with 04 providing a cost table.
  2. **11:** confirm-before-send (RVW-B-13), plus an optional "practice" login immediately after submission.
  3. **05** (new card "If you lose your passphrase"): "Send a new report. If you want the team to connect it with the earlier one, mention something only the first report contained. This links the two reports (ANON-006)."
  4. **30 AT-075:** raise the 30-day target to ≥ 85 % and report unsafe-storage separately by method.
- **RESIDUAL RISK:** Memorization failure under stress.

### RVW-B-28 — Usability studies and flows under-represent the dominant real-world bypasses (work device, phone-only, Tor friction)
- **SEVERITY:** Medium
- **SCENARIO:**
  1. The G1 study pre-installs Tor Browser and simulates a "home laptop" (30 §10.3).
  2. Realistic sources often own only a phone, or only a work laptop, and meet Tor bootstrap failures on restrictive networks.
  3. Such a source uses the work laptop in a browser without Tor. C-37 tells them "not using Tor", and they fall back to C-38 (if enabled) or email.
  4. Sample sizes cannot demonstrate the stated targets: n = 24 with 0 observed failures gives a 95 % upper bound of about 12 % ("rule of three"), not ≤ 5 % false-anonymous (AT-060/10.4). No study measures behaviour after a failed Tor bootstrap.
- **AFFECTED:** 30 §10.3–10.5, AT-060/070/074; 05 §4, §B, §C; 03 §11; 11 S01–S03; THR-002, THR-040, THR-048.
- **WHY NOT PREVENTED:** Studies measure the designed path, not the escape paths.
- **PROPOSED FIX:**
  1. **30:** add personas G1b "phone-only" (Android Tor Browser, iOS Onion Browser) and G1c "only a work device". Add a task "Tor fails to connect".
  2. Metric: % who choose an unsafe fallback.
  3. Sample sizes via power analysis. For "≤ 5 % false-anonymous" at 95 % confidence, n ≥ 59 with 0 failures, or use sequential testing.
  4. **05:** a phone-only track (GC-new) with honest iOS caveats.
  5. **11 S01:** when a channel offers C-38 or a staffed hotline, present it as a **clearly labelled CONFIDENTIAL alternative** for people who cannot use Tor, rather than letting them improvise.
- **RESIDUAL RISK:** Lab studies still differ from real stress.

### RVW-B-29 — Anonymity regression tests cannot catch inferential leaks, and the drill oracles inherit spec contradictions
- **SEVERITY:** High
- **SCENARIO:** Every weakness RVW-B-01, -04..-07, -09, -11 and -12 would **pass** the current 30 suite:
  - **(a)** Canary tests (AT-001..019) grep for literal marker values. Leaks such as bucket transitions, `ts` on `case.imported`, per-channel counts and exclusion rows keyed by user ID contain no marker.
  - **(b)** AT-040's M-TIME scan looks for timestamps within ±600 s "attributable to source actions". A relay import 5–25 min after submission falls partly outside the window, and "attributable" is undefined.
  - **(c)** Drill expected answers codify the contradictions:
    - AT-021 omits `coi_exclusion` and follow-up day lists and accepts "upper bound" timing;
    - AT-023 expects "daily thresholded aggregates" in the SIEM;
    - AT-026 expects backup metadata as "union … as of each backup time";
    - AT-047 permits read-triggered deletion.

    PASS is "learned ⊆ expected", so over-broad expectations pass everything.
  - **(d)** AT-065/066 test "aggregate endpoints", not SOC views, SYSTEM streams, telemetry, fleet or support bundles.
  - **(e)** No test covers excluded-member inference, notification addressee leakage, or intersection over multiple visit days.
  - **(f)** No cross-document constant-consistency check exists.
- **AFFECTED:** 30 §3–§9, AT-001..019, AT-021..026, AT-040, AT-047, AT-065/066, ANT-004/011; 39; 27 §… privacy-review triggers; THR-038, THR-039, THR-011.
- **WHY NOT PREVENTED:** Tests verify the absence of *known identifiers*, not *information flow*.
- **PROPOSED FIX (30, new tests):**
  - **AT-080 Timing-correlation audit.** Using `candor-synth` with Poisson submission times, collect **every** persisted or exported time-bearing value (DB columns, WAL LSN/commit ts, CASE/SECURITY/SYSTEM `ts`, notification send times, SIEM, support bundle, telemetry, fleet) and compute the mutual information / best-predictor error of submission time from each field and jointly. Fail if any predictor beats the day-granular baseline by more than a fixed margin (e.g., ≥ 10 % RMSE reduction).
  - **AT-081 Visit-day intersection.** Synthetic population of 5,000 employees with a Tor-usage model; simulate the org adversary with access to (i) Desk views, (ii) DB, (iii) SOC views; measure the anonymity-set size after k follow-ups. Fail if the median set < 50 after 5 follow-ups with default settings.
  - **AT-082 Exclusion inference.** As in RVW-B-04.
  - **AT-083 Spec-constant lint** in 39: k, windows, timers and retention declared once (YAML) and referenced; CI fails on a divergent literal in any spec.
  - Drill expected answers (§6.3) SHALL be generated from the 03 §10 inventory (single source), and the inventory from 09 column classifications. Any SS-class column absent from §10 fails.
- **RESIDUAL RISK:** Unknown unknowns; model-based tests depend on the adversary model.

### RVW-B-30 — Stale ADR-030 text (cleartext recipient key IDs) survives in implementing specs
- **SEVERITY:** Medium
- **SCENARIO:** ADR-033(1) removed recipient key IDs from the cleartext header. The old text survives in:
  - 14 §3 (server-visible "envelope recipient key IDs (ADR-030 header)"), §4.1 `PENDING_IMPORT`, §8.1 "Recipient slots", §16.1 residual;
  - 12 R02 ("Desk verifies that the envelope header's recipient key IDs match…");
  - 30 AT-020 ("target channel/epoch key ID for each envelope").

  A team implementing 12 or 14 will re-introduce header key IDs. That lets any DB reader compute exactly which role labels were excluded, i.e., who is accused.
- **AFFECTED:** ADR-030, ADR-033(1); 12 R02; 14 §3, §4.1, §8.1, §16.1; 30 AT-020; 09 (correct); THR-020, THR-046.
- **WHY NOT PREVENTED:** Amendment ADRs were not propagated; no "superseded-text" lint exists.
- **PROPOSED FIX:**
  1. Errata to 12/14/30 aligned with 09 `import_envelope.header_ct` ("16 anonymous slots; no recipient key IDs anywhere in cleartext").
  2. 39 gains a check listing superseded phrases per ADR amendment.
  3. **30 AT-021:** assert that no column or field contains recipient key IDs.
- **RESIDUAL RISK:** Relies on the KEM key-privacy assumption (ADR-033; 40).

### RVW-B-31 — Investigator activity is exported to IT/SIEM and reveals "a report arrived" plus the case team's work rhythm
- **SEVERITY:** High
- **SCENARIO:**
  1. Staff authentication events go to the SIEM with `ts`, `actor` and, optionally, enterprise usernames (20 §13; OI-20-3 open).
  2. The SOC, i.e., IT, possibly the accused's organization, sees the three Audit Committee members all log into Candor between 18:00 and 19:30 on day D, for the first time in weeks.
  3. Together with RVW-B-05 this reveals channel and day. Case-open exact timestamps (CASE stream) and anomaly alerts ("SOC sees count, day", 13 §5.4) add more.
  4. Investigator privacy suffers too: staff login patterns expose who handles whistleblowing (retaliation against investigators).
- **AFFECTED:** ADR-016; 20 §5.1, §13, OI-20-3, LOG-012; 13 §5.3–5.4; 03 DM-08; THR-038, THR-018, THR-020.
- **WHY NOT PREVENTED:** Staff events were deemed non-source-sensitive (ADR-010 "exact timestamps only for staff actions"), but staff reactions are a proxy for source activity.
- **PROPOSED FIX:**
  1. **20 §13:** export staff auth events to the SIEM only as daily per-role aggregates, or as pseudonymous `person_ref` with `ts` truncated to the hour and batched daily. Enterprise username mapping is DANGEROUS. Resolve OI-20-3 as "pseudonymous".
  2. **03 §9:** add a row "staff reaction timing ↔ submission".
  3. **13 §5.4:** SOC sees anomaly counts weekly, not daily.
- **RESIDUAL RISK:** Network-level observation of Desk connections by IT (the staff transport choice, 03 OI-07). Recommend the restricted-discovery onion for staff (16) in HIGH profiles.

### RVW-B-32 — The Key Directory permanently publishes the whistleblowing function's structure and roster changes
- **SEVERITY:** Low
- **SCENARIO:**
  1. C-14 publishes role labels (and optional personal names) of every channel member forever (35 D-22 "Not deleted"), plus each roster change.
  2. A roster change shortly after a report (e.g., a member removed or recused) is publicly visible, as is the structure of small investigation units, which makes investigators targetable.
- **AFFECTED:** ADR-030; 14 §8.1, ROUTE-002; 35 D-22; 03 §5 (THR-046 trade-off); THR-019.
- **WHY NOT PREVENTED:** The transparency requirement (THR-046) was prioritized; privacy of the roster was declared "acceptable" (ADR-030 PRIVACY EFFECT).
- **PROPOSED FIX:**
  1. **14 §8.1:** personal names SHALL NOT be published for ANONYMOUS channels.
  2. Roster changes are published only at epoch boundaries (weekly batching).
  3. **35 D-22:** role labels of retired members are replaced by a generic label after 12 months, keeping the key hash only (the log stays verifiable over hashes).
- **RESIDUAL RISK:** Low.

### RVW-B-33 — Minor minimization gaps
- **SEVERITY:** Low
- **SCENARIO and FIX (each item):**

  | # | Item | Where | Issue | Fix |
  |---|---|---|---|---|
  | (a) | Landing footer | 03 §7 | "last changed <UTC day>" reveals operator activity days to anyone, including a live observer | Week granularity |
  | (b) | `last_staff_activity_day` | 14 §3 | Server-visible in cleartext | Keep only in the OVERSIGHT register computation |
  | (c) | Identity retention | 21 ENT-009 (closure + 30 d) vs 35 D-09 (closure + 90 d) | Inconsistent | Align on the shorter |
  | (d) | Staff timeout parameters | 11 §5.6 vs 03 META-014 | Inconsistent (also RVW-B-12) | Align |
  | (e) | `header_digest` | 09 | Kept 30 days | Fine, but list it in 03 §8 |
  | (f) | "How many people know" answer | 05 §8.7, 12 R02 | Shown in the Inbox to every intake member before triage (RVW-B-02) | Restrict to Triage Set / case lead |

- **AFFECTED:** as listed.
- **RESIDUAL RISK:** Low.

---

## 2. Answers to the review questions (summary cross-reference)

| Question | Short answer | Items |
|---|---|---|
| Overlooked metadata | Follow-up day sequences; COI exclusion identities; import/relay exact times via audit `ts`, WAL and SYSTEM events; per-channel and hourly counters; draft timestamps; notification addressee sets; mailbox-closure timing; staff reaction timing | 01, 06, 07, 11, 12, 05, 26, 31 |
| What administrators see | Contrary to AUI-001: per-channel/week case counts (`v_case_counts`), hourly request-rate bands, relay-pull arrival buckets, COI exclusion rows via DB, follow-up days via DB | 01, 06, 07, 10, 11 |
| What the vendor sees | MANAGED: everything server-visible, across customers. Support bundles: org chart of the whistleblowing function plus arrival timing. Fleet: egress IP and health timeline. Telemetry: linkable tuples | 18, 19, 20 |
| Analytics / metrics / dashboards | Inconsistent k (5/10/20), month vs quarter vs year, rolling windows, medians and ratios unprotected, channel as small-population dimension, excluded-member subtraction | 04, 07, 08, 09, 10 |
| Backups vs deletion | Content: EKV works only if ADR-033(3) is read as layered. Metadata: persists 35 days to 12 months. Intake backups contradict source-facing deletion claims | 21, 22 |
| Support logs | Minute-level SYSTEM logs incl. relay pulls; config semantics; retention 30 d vs 2 y | 18 |
| Audit logs of investigator activity | `case.member_removed` (COI) and `authz.denied` (COI_EXCLUDED) identify the accused. Exact `case.imported`. Staff login bursts to SIEM | 01, 06, 31 |
| What the COI checklist leaks | To the case team: the subject, and with "my direct manager", the source's team. To DB/SIEM/auditors: the accused. To the excluded member: that they are accused | 01, 02, 03, 04, 25 |
| Org identifies source (content + HR) | Tier W originals with metadata inside the org; SCIM HR graph co-located; follow-up days vs Tor logs; text watermarks unfiltered | 11, 23, 24 |
| Mode confusion / dark patterns / honesty | Banner caveat dropped; "date only" false; "no one outside the team" false; confidential copy omits compulsion; staff-recorded self-ID. The ADP list is good | 14, 15, 06 |
| Drafts and passphrase re-display: which wins | 03's bounds win: ciphertext drafts allowed only in tmpfs/UNLOGGED storage, ≤ 2 h, no timestamps, no passphrase persistence; show the passphrase before send; fix PRD copy | 12, 13 |
| Data minimization ("don't store it") | Violated by `coi_exclusion`, follow-up dates, quota history, BS-INTAKE, `v_case_counts`, `routing_visible`, SCIM attributes | 01, 10, 11, 21, 22, 23 |
| Are anonymity tests sufficient | No: literal-marker tests cannot catch inferential leaks, and the oracles encode the contradictions | 29, 30 |
| Usability-driven bypass | 25 % passphrase loss is accepted; C-37 first contact at work; phone-only sources; iOS app traces; no lost-passphrase path | 16, 17, 27, 28 |

## 3. Things the design gets right

1. **Onion-only anonymous mode with no clearnet fallback** (ADR-001/002/003). The source IP is removed by construction, not by policy. There is no fingerprinting to "check Tor", and outage pages never offer a degraded anonymous path (SOPS-011).
2. **Honest two-tier client model** (ADR-004). It says plainly that a live-compromised Tier W intake can read submissions. The Tier W/V compulsion table (03 §10.2) is the most candid statement of its kind in any whistleblowing product.
3. **Per-member epoch keys with source-driven COI exclusion before wrapping, plus anonymous recipient slots** (ADR-030/033). This is a real cryptographic answer to the Barclays/Staley class of attack; the weaknesses above are in its metadata surroundings.
4. **No server-side master key; recipient keys only on hardware-bound endpoints** (ADR-007/008), with admin ≠ case access enforced cryptographically (ADR-015, ROUTE-010).
5. **Day-granular source timing as an explicit architectural invariant** (ADR-010), **size padding** (ADR-011) and **core-initiated randomized pull** (ADR-009). The design owns the right invariants. RVW-B-06/11 ask that they be enforced consistently.
6. **Typed, allow-listed logging** with no-`String` payloads, sensitive newtypes without Debug/Serialize, no access logs, `SafeLogging`, volatile journald and self-tests for logging configuration (20 §7, §11, LOG-001..018). This is excellent engineering against the most common real-world leak (INC-60).
7. **Metadata inventory per request × layer** (03 §8) and a **published legal-compulsion inventory** (03 §10, PRIV-002). This is the right artefact; it now needs to be generated from 09 rather than written by hand.
8. **Evidence never parsed on servers; a sanitized derivative by default; containment viewer** (ADR-012), plus the safe-path API (ADR-027).
9. **Content-free notifications, no push to sources, no read receipts, typing or presence** (ADR-017, META-007 intent).
10. **Statistical disclosure control taken seriously.** The M0–M4 classes, complementary suppression, a fixed report catalog, frozen periods and the `stats-inference` CI suite are well beyond industry practice, and need only consolidation (RVW-B-07/08/09).
11. **Source-side guidance** (05). It is risk-tracked, readable, evidence-backed (real cases), placed just in time, and honest about limits (canary traps, stylometry, printer dots, Tor visibility). The anti-dark-patterns list (11 §10) is normative and specific.
12. **Filename neutralization on by default; Tier V local metadata cleaning labelled "best-effort"; identity-hint check whose results are never stored** (05 §8.3–8.5).
13. **Anti-suppression machinery.** Auto-acknowledgement independent of staff, a canary (dead-man) evaluated on OVERSIGHT Desks off-infrastructure, epoch keys not destroyed while envelopes are un-imported (ADR-033(2)), and witness-cosigned audit.
14. **Supply-chain posture for the trust path.** Reproducible builds, TUF with threshold signing, transparency logs, no per-customer builds and no targeted updates (ADR-022). The Edition Charter forbids moving protections to EE.
15. **Telemetry off by default, a 72-h local outbox, onion-only upload and no identifiers** (ADR-023, 24 §8). The self-critical fingerprinting analysis in 24 §8.3 is a model for the rest of the set.
16. **Compromise drills with "learned ⊆ published inventory" as the pass criterion** (30 §6). This is the right methodology; RVW-B-29 asks that the oracle be generated rather than hand-written.
