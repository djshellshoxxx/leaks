# 32 — Operations, Human-Factor Controls and Configuration Classification

Status: Draft v1.0 · Edition applicability: both (EE-only items marked) · Owner: Operations & Security Team

## 1. Purpose and scope

This document specifies:
- operational guides per role: source (pointer), recipient, investigator, administrator, security team, organization management;
- **human-factor defenses** against insiders with legitimate access: curious admins, malicious investigators, executives seeking a source's identity, DBAs, support engineers, cloud admins and vendor personnel;
- the **self-test subsystem** (C-25), which checks platform health without leaking any source-traffic detail;
- the **configuration classification** of every configurable security control into SAFE DEFAULT, ADVANCED or DANGEROUS, with consequences;
- support-bundle scrubbing rules;
- the routine maintenance calendar.

Requirement prefixes:

| Prefix | Covers |
|---|---|
| OPS- | Operations and self-test |
| HUM- | Human-factor controls |
| CFG- | Configuration classification |

## 2. Context and dependencies

| Source | Use |
|---|---|
| ADR-010, 013, 015, 016, 017, 023, 028, 029, 030 | Timing minimization; recovery; admin ≠ case access; audit classes; content-free notifications; telemetry; secret manifest; audience-bound tokens; per-member epoch keys (cryptographic COI) |
| `05-SOURCE-OPSEC.md` | Source guidance (authoritative) |
| `14-CASE-MANAGEMENT.md` | Case workflow, COI maps, metric k-thresholds |
| `15-AUTHENTICATION-AUTHORIZATION.md` | Roles (SYS_ADMIN, USER_ADMIN, SECURITY_OFFICER, CHANNEL_OWNER, INVESTIGATOR, IDENTITY_CUSTODIAN, RECOVERY_TRUSTEE, METRICS_VIEWER, OVERSIGHT, …) and dual-control catalogue DC-01..DC-nn |
| `17-INFRASTRUCTURE.md` | Baselines verified by the self-test |
| `18-DEPLOYMENT.md` §14 | Configuration checker, which consumes the CFG table of §7 |
| `20-LOGGING-AUDITING.md` | Event names, prohibited fields (e.g., P-14: no onion addresses), SYSTEM class |
| `31-INCIDENT-RESPONSE.md` | Escalation from self-test alerts |

Research basis:

| Source | Point |
|---|---|
| Insider abuse (INC-68 to INC-72: LOVEINT, Twitter/Saudi, Uber God View, SnapLion, Tesla) | Insiders abuse access |
| Barclays CEO unmasking attempt (INC-22) | Executives seek source identity |
| Okta HAR support leak (INC-56); Facebook plaintext logs (INC-60) | Support tooling and diagnostics leak secrets |
| SecureDrop 7ASecurity open items: logging vs no-logging tension (SEC-01-016), SSH MFA [B-SD-13] | Monitoring vs source protection |
| GlobaLeaks logs staff IPs by default [B-GL-04] | Insider accountability |
| REQ-H-68..71 (no single operator can access source material; no admin tooling for source data) | Structural insider limits |

## 3. Operational guides by role

### 3.1 SOURCE

Source guidance is authoritative in `05-SOURCE-OPSEC.md`. Operators' duties towards sources:
1. Publish the onion address and guidance only on the Clearnet Information Site (C-37) and in channels the organization controls. Never publish it on pages with analytics or third-party scripts (INC-53).
2. Do not advertise the portal on the corporate intranet with tracking links, or with instructions that lead employees to use corporate devices (REQ-H-31).
3. Keep C-37 guidance in sync with `05-SOURCE-OPSEC.md` releases (checked quarterly, §9).

### 3.2 RECIPIENT (channel member)

| Do | Don't | Why |
|---|---|---|
| Use Candor Desk only on the enrolled workstation, with the hardware key removed when away | Do not use Candor on shared or personal devices, or via remote-desktop tools | ADR-007; `17-INFRASTRUCTURE.md` §8.3 |
| Open every attachment only in the Candor viewer (C-17) | Never "Save as" originals to Downloads or email them to yourself | ADR-012; THR-023, THR-041 |
| Work from sanitized derivatives; export only via Export Packages with the required approvals | Never forward, print or upload originals to cloud services | THR-041, INC-16 |
| Paraphrase source text when discussing a report outside Candor | Never quote distinctive phrases, typos or document formatting | REQ-H-73; THR-010 |
| Keep meetings about a case to members of its ACL | Do not circulate the report "for information" to managers | INC-22 |
| Treat unexpected requests "from the source" to confirm identity, meet, or switch channels as a possible source-account compromise | Never ask a source for identity, contact details or other channels | `17-INFRASTRUCTURE.md` §8.2; ADR-002 |
| Declare conflicts of interest as soon as you recognize them | Do not continue to read a case you are conflicted on | ADR-015, ADR-030 |
| Sync at least weekly (AIRGAP-RCP) and open Candor Desk at least weekly (member epoch key pre-publication, ADR-030) | Do not leave the Desk offline for more than 3 weeks without telling the Channel Owner | ADR-030: an offline member eventually has no valid member epoch keys |
| Report lost tokens or devices immediately (PB-05) | Do not re-use a found token | `31-INCIDENT-RESPONSE.md` |
| Travel with the hardware key separated from the laptop; inspect seals after unattended periods | Do not check the laptop into luggage | `17-INFRASTRUCTURE.md` §6.4 |

### 3.3 INVESTIGATOR

Investigators (INVESTIGATOR role, with case ACL) additionally:
1. **Never attempt to identify an anonymous source.** This is a policy commitment of the organization (§3.6) and a disciplinary matter. Candor provides no feature for it (REQ-H-70). Attempts may themselves be reportable retaliation (EU Directive 2019/1937 [B-CO-02]).
2. Interview subjects without revealing details that only the source could know. Use the case "disclosure check" to list facts that narrow the source set, as defined in `14-CASE-MANAGEMENT.md`.
3. Keep chain of custody inside Candor. Evidence leaves only as an Export Package (ADR-018) whose manifest records the transformations (ADR-012).
4. Request time-bounded grants for co-investigators rather than broad channel membership.
5. Close the case per the retention schedule. Do not keep private copies.

### 3.4 ADMINISTRATOR (SYS_ADMIN, USER_ADMIN)

| Duty | How | Frequency |
|---|---|---|
| Keep hosts patched | Review `candorctl upgrade plan`, apply within the window (`18-DEPLOYMENT.md` §11) | Security releases ≤ 72 h (REQ-H-29 for tor); others ≤ 14 days |
| Monitor self-test | Admin console "Health" tab / `candorctl selftest status` | Daily |
| Backups | `candorctl backup status`, weekly offline rotation, quarterly RT-1 (`19-BACKUPS-DR.md`) | Daily / weekly / quarterly |
| User lifecycle | Enrollment with in-person or verified-video identity check; deactivation on HR leave events (USER_ADMIN, dual control DC-07) | On event |
| Configuration | Only via `candorctl`/Admin API. DANGEROUS changes need dual approval (§7) | On change |
| Never | Request case access; hold case-content roles (AUTHZ-003/004); copy secrets off hosts; install monitoring agents, EDR, backup agents or log shippers not approved by the checker on Candor hosts; enable debug logging on Z-INTAKE | — |

Admins have no case-content capability (ADR-015; admins publish no member epoch keys, ADR-030). Their residual power is the **live** host: they could modify intake to capture future Tier W plaintext. §4 addresses this.

### 3.5 SECURITY TEAM (SECURITY_OFFICER)

1. Triage self-test alerts (§5) and SECURITY audit events. Escalate per `31-INCIDENT-RESPONSE.md` §5.
2. Review admin activity weekly: config changes, SSH sessions, approvals, secret-manifest results, attestation.
3. Hold the co-approver role for DANGEROUS changes (DC-09 in `15-AUTHENTICATION-AUTHORIZATION.md`) together with SYS_ADMIN.
4. Run the quarterly privacy-preserving access review (§4.4).
5. Own the IR Evidence Key share (with the DPO and Legal) and IR exercises.
6. Must **not** request SOURCE-SENSITIVE data (there is none as events), must not enable packet capture on intake uplinks (IR-008), and must not route Candor events beyond the C-26 allow-list.

### 3.6 ORGANIZATION MANAGEMENT

| Obligation | Detail |
|---|---|
| Published non-retaliation and non-identification policy | A board-approved statement: no attempt to identify anonymous reporters, and sanctions for attempts (INC-22) |
| Appoint independent roles | OVERSIGHT (audit committee / ombudsman), IRK custodians (`19-BACKUPS-DR.md`), Identity Custodians (ADR-014), Recovery Quorum trustees if enabled (ADR-013), and at least one reporting channel that bypasses executive management (ADR-015 routing) |
| Resourcing | Staffing for the SLA engine (acknowledgement deadlines per `25-COMPLIANCE.md`), administrators (§3.4 frequency), and a yearly budget for independent audit (`37-SECURITY-AUDIT-PLAN.md`) |
| Information management receives | Only k-thresholded, month-granular statistics (REQ-H-74; `14-CASE-MANAGEMENT.md`). Never case lists, never "who reported" |
| Accept exclusion | Executives named in the COI map for a category are cryptographically excluded (ADR-030) and SHALL NOT request exceptions |
| Hosting decisions | Choose the deployment profile with the threat model in `18-DEPLOYMENT.md` §4; record the uplink-independence decision (`17-INFRASTRUCTURE.md` §4.10) |

## 4. Human-factor defenses

### 4.1 Adversary × control matrix

| Insider | What they might try | Technical controls | Procedural controls | Detection | Residual |
|---|---|---|---|---|---|
| Curious admin (SYS_ADMIN) | Read reports; browse the DB; look up "who submitted around the time of X" | No case keys (ADR-015, ADR-030); DB holds ciphertext + day-granular dates (ADR-010); no admin tooling for source data (REQ-H-70); the Admin API has no content routes (ADR-029 deny-by-default) | SoD (§4.2); signed admin-conduct statement | SSH session events; DB access by the admin role outside maintenance windows (connection-level only) | Can see coarse metadata (`17-INFRASTRUCTURE.md` §8.6). With root on a live intake, could capture future Tier W (see next row) |
| Malicious admin | Modify the intake to capture Tier W plaintext; copy the onion key; weaken config | Attestation (`17-INFRASTRUCTURE.md` §5.6) from an independently administered H-MON; secret manifest; config checker blocks unapproved DANGEROUS changes; TUF-only code (no ad-hoc binaries: `debsums`, measured boot) | EE: two-person SSH certificate issuance for H-INTAKE (HUM-005); H-MON administered by the security team, not by SYS_ADMIN (HUM-006) | `host.attestation_mismatch`, `secret.placement_violation`, checker exit ≥ 20 | Memory-only implants (`17-INFRASTRUCTURE.md` §10); Tier V removes the exposure |
| Malicious investigator | Identify the source from content; leak to the accused; export originals; widen the ACL | ACL + COI cryptographic exclusion (ADR-030); dual approval for original exports (ADR-012); Export Package watermark and manifest; time-bounded grants; no global read (AUTHZ-006) | Non-identification policy (§3.6); training; paraphrase rule | CASE audit analytics: bulk export, access to cases after COI declaration attempts, exports shortly before confrontations (PB-01) | Content-based inference by an authorized reader cannot be technically prevented (THR-010) |
| Executive seeking identity | Pressure recipients or admins; demand logs; request "IT forensics" on the employee network | Nothing identifying exists in Candor (ADR-001, ADR-010); cryptographic COI exclusion (ADR-030); routing to independent channels (ADR-015); admins cannot read content | Escalation path to OVERSIGHT, bypassing the executive; staff instructed to record and report such requests; legal protections for recipients | An OVERSIGHT-visible record of any "identity request" logged by recipients (CASE event `case.identity_request_refused`, defined in `14-CASE-MANAGEMENT.md`) | Correlation with corporate network logs (Tor use by an employee at time T) happens outside Candor. Source guidance (never use employer networks) is the only mitigation |
| DBA (customer DB team, EE) | Dump the case DB; restore to a sandbox; run queries | Dedicated DB (not shared); RLS; case content encrypted; DB superuser not held by the enterprise DBA team (Candor-operated role); TDE optional | DBA access to the Candor DB only via an audited maintenance procedure with SECURITY_OFFICER co-approval | Connection-level audit; RT-0 detects unexpected snapshot/backup activity | Metadata exposure per `17-INFRASTRUCTURE.md` §8.6 |
| Support engineer (vendor or internal helpdesk) | Obtain logs/HAR/screenshots with tokens; request remote access | Support bundles scrubbed (§8); no HAR from sources (REQ-H-56); vendor remote access off by default; audience-bound tokens (ADR-029) | Two-person, time-bound vendor access with a customer-visible log (DEP-028) | Bundle creation events; access-log review | Helpdesk social engineering of recipients: training |
| Cloud admin (provider or customer cloud team) | Snapshot disks/RAM; read flow logs; use KMS | In-guest FDE with customer-held Tang/HSM; no provider KMS (INFRA-022); SCPs deny snapshots (DEP-015); confidential VMs | Separate cloud account for Candor with minimal principals; break-glass only | Cloud audit-log alerts on snapshot, console or disk-attach events | Hypervisor-level observation cannot be prevented (`17-INFRASTRUCTURE.md` §7) |
| Vendor personnel (Candor/EE vendor, MANAGED operator) | Access customer instance data; build a targeted update; learn deployment metadata | E2EE with endpoint keys (ADR-007); identical updates for all customers + transparency (ADR-022); opaque instance IDs (ADR-022, C-34); licensing offline (C-35) | MANAGED: two-person SSH issuance, customer-visible access log, per-customer keys (DEP-027/028); vendor staff background checks | Transparency monitors; customer access-log review | A MANAGED operator can observe intake metadata and live Tier W (`18-DEPLOYMENT.md` §4.8, disclosed) |

### 4.2 Separation of duties

The following role pairs SHALL NOT be held by the same person (`person_ref`) in CE-HARDENED and above. In CE-SINGLE they are ADVANCED exceptions with acknowledgement.

| Role A | Role B | Reason |
|---|---|---|
| SYS_ADMIN | Any case-content role (INVESTIGATOR, CHANNEL member) | ADR-015 (enforced by AUTHZ-004 in all profiles) |
| SYS_ADMIN | USER_ADMIN | Prevents a single person from creating and enrolling accounts and then configuring hosts |
| SYS_ADMIN | SECURITY_OFFICER | Removes the ability to approve one's own DANGEROUS change |
| SYS_ADMIN of H-INTAKE/H-CORE | Administrator of H-MON (attestation verifier) | Prevents an admin from hiding their own host tampering |
| IRK custodian (k shares) | WORM store root credential holder | Prevents one person from decrypting and deleting backups |
| IDENTITY_CUSTODIAN | CHANNEL_OWNER of the same channel | ADR-014 intent: identity separate from case handling |
| RECOVERY_TRUSTEE | SYS_ADMIN | ADR-013 independence |

### 4.3 Access expiry (defaults)

| Grant | Default duration | Renewal |
|---|---|---|
| Case co-investigator grant | 30 days | Requested by the case owner; CHANNEL_OWNER approves |
| Break-glass | 4 h | Dual approval; post-hoc OVERSIGHT review within 7 days |
| Admin role | 365 days | Re-certification (`15-AUTHENTICATION-AUTHORIZATION.md`) |
| EE SSH certificate for H-INTAKE | 8 h | Two-person issuance |
| Vendor support access (MANAGED/EE) | 24 h | Customer approval per session |
| DANGEROUS config approval | 90 days (auto-revert to SAFE DEFAULT unless renewed) where the control allows it | Re-approval via DC-09 |
| IR diagnostic mode | 24 h | IR Lead |

### 4.4 Privacy-preserving audits

1. Audit reviewers see pseudonymous case IDs, staff IDs and action types (ADR-016). Case content and source data are never part of an audit review.
2. Quarterly access review:
   - CHANNEL_OWNERs review membership and grants.
   - SECURITY_OFFICER reviews admin activity.
   - OVERSIGHT reviews break-glass and identity-unsealing events.
   - Every review is itself a CASE/SECURITY event: **who audits the auditors** is visible to OVERSIGHT.
3. Staff-activity analytics (for PB-01/PB-05 detection) run on CASE/SECURITY events only. Rules are published internally and limited to defined anomaly patterns: bulk export, off-ACL attempts, access after COI declaration, unusual volume. They are **not** general productivity monitoring. Results go to the SECURITY_OFFICER and, for SECURITY_OFFICER subjects, to OVERSIGHT.
4. Metrics exported to management follow k-thresholds (`14-CASE-MANAGEMENT.md`) and month granularity (REQ-H-74).

## 5. Self-test subsystem (C-25)

### 5.1 Design

- An agent runs on every host (`candor-health` user) every 5 min ± 60 s jitter (`06-SYSTEM-ARCHITECTURE.md` §8.5). Heavier checks run hourly or daily.
- Agents push results over mTLS to the H-MON collector (flow F4, `17-INFRASTRUCTURE.md`).
- H-MON additionally runs an **external onion probe** through its own tor client (flow F4b). It fetches the fixed-size `/.well-known/candor/health` from the source onion (`16-TOR-I2P.md`).
- Results use a fixed schema of `check_id`, `host_role`, `status ∈ {OK, WARN, FAIL}`, `code`, and `bucket`, where `bucket` is an optional value from a closed set. Anything else is rejected by the collector.
- Privacy rules, binding for every check:
  1. **No counts** of submissions, sessions, source accounts, circuits, connections, bytes or requests.
  2. No per-request or per-circuit data.
  3. Disk and queue values only as threshold states or 5%-bands.
  4. No onion addresses, hostnames or IPs in results (`20-LOGGING-AUDITING.md` P-14; use the boolean `onion_published`).
  5. Check timestamps are the agent's schedule time rounded to the minute, never event times.
  6. Results are retained 30 days (SYSTEM class).

### 5.2 Check catalogue

| Check ID | Host(s) | What | Method | Freq. | Output (allowed) | Fail behavior (see `34-PERFORMANCE-SCALABILITY.md` FAIL table) |
|---|---|---|---|---|---|---|
| `tor.daemon` | intake, core | tor running, bootstrapped 100% | control socket (unix) `GETINFO status/bootstrap-phase` | 5 min | OK/FAIL | FAIL → intake shows unreachable (fail closed) |
| `tor.onion_published` | intake | Our descriptor is uploaded | control socket `GETINFO` for HS descriptor upload status | 5 min | boolean | WARN after 30 min |
| `tor.onion_reachable` | monitor | End-to-end reachability via Tor | H-MON tor client fetches the health endpoint | 15 min ± 5 | OK/FAIL, latency bucket {<5 s, 5–15 s, 15–60 s, >60 s} | FAIL for 3 consecutive probes → alert |
| `tor.config_hash` | intake, core | torrc equals the signed template | hash compare | 15 min | OK/FAIL | FAIL → stop C-06 (`16-TOR-I2P.md` NET-034) |
| `tor.pow_vanguards` | intake | PoW enabled; vanguards mode as configured | parse effective config | hourly | OK/FAIL | FAIL → alert (DANGEROUS drift) |
| `net.egress` | all | Egress default-deny holds | non-tor UID connect attempt to a TEST-NET address must fail; ruleset hash | 15 min | OK/FAIL; `egress_violation` boolean | FAIL → stop C-06, alert |
| `net.listeners` | all | Only inventoried listeners | `ss -ltnpx` vs listener inventory (ARCH-033) | 5 min | OK/FAIL | FAIL → alert; intake stop if on H-INTAKE |
| `clock.offset` | all | NTP offset | chronyc tracking | 5 min | bucket {<1 s, 1–5 s, 5–30 s, >30 s} | >30 s WARN; Tor-consensus skew >30 min FAIL (INFRA-007) |
| `storage.disk_free` | all | Free space | statvfs | 5 min | band {≥50%, 30–50%, 20–30%, 10–20%, <10%} | <20% WARN; <10% FAIL (per FAIL table) |
| `storage.health` | all | SMART/NVMe health, RAID state | smartctl, mdadm | hourly | OK/WARN/FAIL | WARN → maintenance |
| `storage.fde` | all | Data volumes are LUKS2 and open only as expected; no swap or encrypted ephemeral swap | lsblk, cryptsetup status, swapon | hourly | OK/FAIL | FAIL → alert (baseline) |
| `relay.lag` | core | Time since the last successful pull | relay state | 5 min | bucket {<1 h, 1–2 h, 2–6 h, >6 h} | >2 h WARN (`06-SYSTEM-ARCHITECTURE.md` R-8) |
| `intake.queue_capacity` | intake | Queue fill relative to the 7-day capacity (DR-007) | used/capacity | 15 min | state {OK <50%, WARN 50–80%, FAIL >80%} | FAIL → per FAIL table (storage full) |
| `backup.status` | core, monitor | Last successful set per type within schedule; RT-0 result | backup state + RT-0 | hourly | OK/WARN/FAIL per set type | 2 missed nightly sets → FAIL alert |
| `crypto.selftest` | intake, core | candor-core KATs, CSPRNG health, AEAD round trip | built-in test vectors (`04-CRYPTOGRAPHY.md`) | at start + daily | OK/FAIL | FAIL → stop the affected service (fail closed) |
| `keys.epoch_runway` | core | For each channel: at least `min_recipients` eligible member epoch keys valid for the next N days (ADR-030) | key directory | hourly | per channel: {≥14 d, 7–14 d, 1–7 d, 0} | <7 d WARN to Channel Owner; 0 → intake for that channel fails closed (ARCH-037) |
| `keys.availability` | intake, core | Intake Routing Key unsealable; backup public keys present; audit signing key usable; HSM reachable | local ops (sign/verify test) | hourly | OK/FAIL | FAIL → per FAIL table |
| `certs.expiry` | all | mTLS certificates (relay, agent, RCP-LAN) | parse | daily | bucket {>30 d, 7–30 d, <7 d, expired} | <7 d WARN; expired FAIL |
| `perm.secrets` | all | Secret file owner/mode per manifest | stat | 15 min | OK/FAIL | FAIL → alert |
| `secret.placement` | all | ADR-028 manifest equality | scan (`18-DEPLOYMENT.md` §15) | 5 min light / daily full | OK/FAIL | FAIL → `secret.placement_violation`; forbidden item → intake stop (DEP-024) |
| `logging.config` | all | No access logs, tor SafeLogging, journald volatile on intake, no nft LOG targets, no capture tools | per `20-LOGGING-AUDITING.md` LOG-018 | hourly | OK/FAIL with `check_code` | FAIL → `selftest.logging_violation` |
| `update.status` | all | TUF metadata freshness; pending security updates; running version = installed version | candor-update, apt | hourly | {current, update-available, security-update-pending>72h, metadata-stale>7d} | security pending > 72 h WARN; stale > 7 d WARN |
| `integrity.packages` | all | debsums + Candor file manifest | debsums -c | daily | OK/FAIL | FAIL → IR PB-02 |
| `integrity.attestation` | intake, core | TPM PCR quote vs golden | H-MON verifies (INFRA-018) | 15 min | OK/FAIL | FAIL → `host.attestation_mismatch` |
| `hw.intrusion` | all | Chassis intrusion sensor | sysfs/IPMI SEL | 5 min | OK/ALARM | ALARM on intake → power-off (PHYS-007) |
| `config.checker` | all | `candorctl check` exit code | local | daily + on change | exit code class | ≥20 → intake blocked at next start |
| `canary.files` | core, intake | Ransomware canaries unchanged | hash | 5 min | OK/FAIL | FAIL → alert (BAK-025) |

### 5.3 Example result record

```json
{"check_id":"storage.disk_free","host_role":"intake","status":"WARN","code":"BAND_10_20","bucket":"10-20","sched_ts":"2026-10-01T02:15Z","agent_version":"1.0.0"}
```

## 6. Health and alert routing

| Severity | Route | Content |
|---|---|---|
| FAIL on privacy-critical checks (`net.egress`, `logging.config`, `secret.placement`, `integrity.*`, `tor.config_hash`) | SECURITY_OFFICER + SYS_ADMIN, immediately | `check_id`, `host_role`, `code` only (content-free, ADR-017) |
| Other FAIL | SYS_ADMIN | same |
| WARN | Daily digest | same |
| `keys.epoch_runway` WARN | CHANNEL_OWNER | "Channel requires member key refresh". No member names |

Alert transports: SMTP over tor, or a Matrix/Teams webhook over tor from H-MON (flow F10). Alerts never include onion addresses, IPs, counts or case data.

## 7. Configuration classification

Classes:
- **SAFE DEFAULT**: shipped value. No action is needed.
- **ADVANCED**: allowed, but reduces a margin or changes a tradeoff. It requires a signed acknowledgement by one admin (FIDO2) recorded in `candor-site.toml [acknowledgements]`. The config checker exits 10 until acknowledged.
- **DANGEROUS**: materially weakens source protection. It requires dual approval DC-09 (SYS_ADMIN + SECURITY_OFFICER, OVERSIGHT notified, `15-AUTHENTICATION-AUTHORIZATION.md`). Where it affects sources, it is disclosed on the source interface and in the key directory. Where marked ⏱, it auto-reverts after 90 days (or the stated period). The config checker exits 20 without valid approval.
- **FIXED**: not configurable. Listed so that operators know it cannot be changed.

`15-AUTHENTICATION-AUTHORIZATION.md` uses the label "WEAKENING" for some authentication options. For classification purposes WEAKENING = DANGEROUS (DC-09).

| Control (key) | SAFE DEFAULT | ADVANCED | DANGEROUS | FIXED / not allowed | Consequences text (shown in UI and checker) |
|---|---|---|---|---|---|
| Anonymous-mode transport | Tor v3 onion only | — | — | clearnet or I2P for anonymous mode (ADR-001/002) | — |
| `intake.clearnet_confidential` (C-38) | off | — | on (separately branded "NOT ANONYMOUS") | — | "Creates a clearnet path where the network, hosting provider and any proxy see reporter IP addresses. Reports via this path are CONFIDENTIAL, not anonymous. Risk of mode confusion (THR-040)." |
| `tor.pow` | on | — | off | — | "Removes onion DoS protection; floods can make the portal unreachable at critical moments (THR-032)." |
| `tor.vanguards` | lite (all); full (GOV, MANAGED high-risk, HIGH tenants per `16-TOR-I2P.md` NET-007) | full where not required | — | disabling vanguards-lite | "Full vanguards raise guard-discovery resistance at the cost of latency." |
| `tor.log_level` | notice | — | info/debug ⏱ 24 h | `SafeLogging 0` | "Verbose tor logs can record timing of source connections (THR-016)." |
| `intake.tier_w.enabled` | on | off (Tier V only) | — | — | "Tier V only removes server-side plaintext exposure but excludes sources without the Source App." |
| `intake.js_required` | false | — | — | true (ADR-004) | — |
| `intake.max_submission_size` | profile default (`34-PERFORMANCE-SCALABILITY.md` §4) | up to the profile hard max | — | above the hard max | "Larger uploads take longer over Tor and increase exposure time and storage use." |
| `intake.rate_limits` | defaults (ADR-026) | tuned values within ±50% | disabled | — | "Without limits, one party can exhaust intake capacity (THR-032/033)." |
| `intake.resumable_uploads` (Tier V) | on (design in 34 §5) | off | — | — | "Off: interrupted large uploads restart from zero." |
| `intake.upload_session_ttl` | 72 h | 24–168 h | > 168 h | — | "Longer TTL keeps partial-upload records (which link the reconnections of one upload to each other) for longer (THR-047)." |
| `intake.passphrase_multi_report` | off (one passphrase per report, ADR-005) | on | — | — | "Lets a source link several reports under one passphrase; increases linkability if the passphrase is compromised." |
| `intake.min_recipients` per channel | 1 | ≥ 2 | — | 0 | "With 1, a single member's absence blocks intake for the channel (fail closed)." |
| `intake.coi_checklist` | shown, none preselected (ADR-030) | hidden | — | — | "Hidden: sources cannot exclude accused roles themselves; only the pre-configured COI map applies." |
| `relay.pull_interval` | 15 ± 10 min uniform | 5–60 min mean, jitter ≥ 50% of mean | jitter < 50% of mean or fixed | — | "Regular pulls let observers of the relay link infer submission timing (THR-011)." |
| Timestamp granularity (source actions) | — | — | — | day only (ADR-010) | — |
| Read receipts / presence / push to sources | — | — | — | off (ADR-010, ADR-017) | — |
| `notify.mode` | hourly content-free digest | daily digest | per-event immediate | content in notifications (ADR-017) | "Per-event notifications reveal submission timing to the mail/chat provider (THR-028)." |
| `notify.transport` | none, or SMTP with pinned certificate | Matrix/Teams webhook over tor | plaintext SMTP / unpinned TLS | — | "Unpinned or plaintext transport exposes notification timing and staff addresses." |
| Web/tor access logs | off | — | — | on (ADR-016) | — |
| `ir.diagnostic_mode` | off | — | on ⏱ 24 h (allow-listed fields) | debug logging on Z-INTAKE | "Adds diagnostic SYSTEM fields during incidents; never request data." |
| `journald.intake_storage` | volatile, ≤ 7 d | — | persistent | — | "Persistent intake logs survive seizure (THR-016/031)." |
| `siem.export` (C-26, EE) | off | on (allow-listed events) | — | custom fields beyond the allow-list | "Scrubbed SECURITY/SYSTEM events leave Candor; reviewers outside Candor see staff activity." |
| `telemetry` | off (ADR-023) | on (TEL schema, previewable) | — | source-side telemetry | "Sends fixed-schema instance statistics to the configured collector." |
| `recovery_quorum` | off (ADR-013) | — | on (k-of-n, published in the key directory) | — | "k trustees acting together can decrypt all cases wrapped to the quorum. Visible to sources." |
| `case.min_key_holders` | 2 | 1 | — | 0 | "With a single key holder, loss of one device loses the case (no escrow)." |
| `retention.*` | per `35-DATA-RETENTION-DELETION.md` | longer within legal limits | indefinite | — | "Longer retention increases exposure under seizure or compulsion (THR-017/026)." |
| `backup.retention_days` | 35 | 36–365 | > 365 | — | "Deleted data persists in backups until expiry." |
| `backup.online_restore_test_key` | off | on (EE) | — | — | "A backup decryption key exists online on the restore host." |
| `backup.incremental_blob_sets` (EE) | off (padded full sets) | on (padded new-blob sets) | — | unpadded incrementals | "Incremental sets reveal slightly more about new-evidence volume per night (bucketed)." |
| Backup encryption | on | — | — | off | — |
| `fde.unlock_mode` | U3 or U4 per profile (U1, U6, U7 are equivalent alternatives) | U2 (TPM-only) | U5 (Tang-only) | none | "TPM-only: a stolen, powered-off server boots to a running OS without any secret." |
| `swap` | off | encrypted with a per-boot random key | plain swap | — | "Plain swap can write plaintext and keys to disk." |
| `hypervisor.intake_snapshots` | off | — | on | — | "Snapshots capture intake RAM and disk, including Tier W plaintext in flight." |
| `ce_single.separation` | VMs | containers | — | same process space | "Containers share a kernel; one kernel exploit crosses from intake to core." |
| `site.uplink_independent` | true | false (acknowledged risk) | — | — | "The uplink operator can observe intake traffic timing (THR-002/003)." |
| `rcp.path` | per profile (RCP-ONION or RCP-LAN) | the other option | — | browser-based recipient UI (ADR-007) | "RCP-LAN reveals staff IPs and times to the internal network team." |
| `ssh.auth` | FIDO2 sk-keys, N-MGMT or SSH onion | — | — | passwords, non-sk keys, root login | — |
| `auth.synced_passkeys` | off | — | on for limited roles (DC-09) | for content/admin roles (AUTH-008) | "Credential secrets are replicated to the passkey provider." |
| `auth.totp_fallback` (CE) | off | — | on ⏱ 90 d (AUTH-009) | for SYS_ADMIN/USER_ADMIN/custodians | "Phishable second factor." |
| `authz.break_glass` | enabled, dual approval + post-hoc review | disabled | — | single-approval break-glass | "Disabled: no emergency access; lost access is permanent without members." |
| Original-evidence export | dual approval (ADR-012) | — | — | single approval | — |
| `viewer.containment` | disposable microVM/DispVM (C-17) | air-gapped station (C-18) | allow "open with system application" ⏱ 90 d | — | "Opening outside containment exposes the workstation to hostile files (THR-023)." |
| `edr.sample_upload_candor_paths` | off | — | on | — | "EDR vendors receive submitted files or decrypted content (IR-027)." |
| `metrics.k_threshold` | per `14-CASE-MANAGEMENT.md` | higher k | lower k | k < 5 | "Small cells can identify sources (THR-039)." |
| `keydir.external_witness` | on (if available) | off | — | — | "Without an external witness, split-view attacks on the key directory are harder to detect." |
| `intake.physical.intrusion_action` | poweroff | alert-only | — | — | "Alert-only keeps a possibly tampered intake host running." |
| `updates.auto_security` | on (0–72 h random delay) | manual (≤ 14 days) | disabled > 30 days | — | "Unpatched intake exposes sources to known exploits." |
| `update.offline.max_age_days` | 30 | 31–90 | > 90 | — | "Stale offline metadata may miss revocations." |
| `vendor.remote_access` | off | on, two-person, time-bound, customer-logged | standing access | — | "The vendor can operate the hosts during sessions." |
| `tenancy` (EE) | dedicated | shared for low/moderate tenants in one customer group (ADR-021) | — | shared for high-risk tenants | "Shared instances increase co-residency exposure (THR-045)." |
| `cloud.intake_flow_logs` (PRIVATE-CLOUD) | off | — | on | — | "Flow logs record timing and volume of all intake Tor connections (THR-003/011)." |
| `cloud.provider_kms_for_candor_keys` | not used | — | — | used (INFRA-022) | — |
| `support.bundle.include_intake_logs` | off | on (scrubbed, §8) | — | raw logs | "Intake system logs are included after scrubbing." |

## 8. Support-bundle scrubbing

Command: `candorctl support-bundle create --preview --out bundle.tar.age`. For Candor Desk: Help → Diagnostics → Create bundle (preview first).

| Rule | Specification |
|---|---|
| Allow-list content | versions, SBOM hash, effective **non-secret** config (with secrets replaced by `<redacted:sha256-8>`), `candorctl check` output, self-test results (already privacy-safe), SYSTEM-class logs from H-CORE/H-MON (last 7 days), service states, resource bands |
| Never included | DB contents or dumps; blobs; C-08 data; SOURCE-SENSITIVE counters; case data; onion keys or any manifest secret; tor state; memory or core dumps (none exist); HAR files; screenshots; Desk local stores; exported files; tokens or cookies |
| Transformations | Onion addresses → `onion-<HMAC8>`. IPs → role labels (`intake.relay`, …) or `ip-<HMAC8>`. Staff usernames → `user-<HMAC8>`. Case IDs → removed. Hostnames → role labels. HMAC key: random per bundle, kept locally (`bundle.key`) so the operator can map values if support needs them, and never included |
| Time precision | Intake-host log timestamps truncated to the hour; others to the minute |
| Canary verification | Before finalizing, the tool scans the bundle for manifest secret patterns, JWT/cookie/token patterns, onion-address regexes, IPv4/IPv6, email addresses and known canary strings planted at install. Any hit aborts creation (REQ-H-56) |
| Operator preview | Full-text preview; the operator confirms by FIDO2 touch; bundle creation is a SECURITY event |
| Encryption | age/HPKE to the support recipient key (vendor or internal), fingerprint shown for confirmation |
| Transport & retention | Uploaded by the operator (never automatically). Vendor retention ≤ 30 days, deletion confirmed (EE contract) |
| Source side | Candor never requests diagnostics from sources (REQ-H-56) |

## 9. Routine maintenance calendar

| Frequency | Task | Owner | Reference |
|---|---|---|---|
| Daily | Review self-test dashboard; check `backup.status`, `relay.lag`, `keys.epoch_runway` | SYS_ADMIN | §5 |
| Daily | Triage SECURITY alerts | SECURITY_OFFICER | §6 |
| Weekly | Offline backup rotation (T2), one disk off-site | SYS_ADMIN (+ second person for transport) | `19-BACKUPS-DR.md` §6 |
| Weekly | Review admin activity (config changes, SSH, approvals) | SECURITY_OFFICER | §3.5 |
| Weekly | Open Candor Desk (member epoch key pre-publication); AIRGAP-RCP sync | Recipients | ADR-030; DEP-030 |
| Weekly | Apply non-urgent Candor/Debian updates within the window | SYS_ADMIN | `18-DEPLOYMENT.md` §11 |
| Monthly | Review ADVANCED acknowledgements and DANGEROUS approvals (expiry) | SECURITY_OFFICER | §7 |
| Monthly | Verify the key-directory transparency log against the external witness | SECURITY_OFFICER | `20-LOGGING-AUDITING.md` |
| Monthly (EE-HA/GOV) | RT-1 sandbox restore | SYS_ADMIN + IRK custodians | `19-BACKUPS-DR.md` §7 |
| Quarterly | RT-1 + RT-2 restore and canary decrypt (all profiles) | SYS_ADMIN + custodians + canary recipient | `19-BACKUPS-DR.md` §7 |
| Quarterly | Tamper-seal inspection with photos (two people) | SYS_ADMIN + SECURITY_OFFICER | `17-INFRASTRUCTURE.md` §6.4 |
| Quarterly | Access review (membership, grants, roles, break-glass) | CHANNEL_OWNERs, SECURITY_OFFICER, OVERSIGHT | §4.4 |
| Quarterly | IR tabletop | IR Lead | `31-INCIDENT-RESPONSE.md` §10 |
| Quarterly | Check C-37 guidance against `05-SOURCE-OPSEC.md`; verify C-37 has no third-party resources | Communications + SECURITY_OFFICER | §3.1 |
| Semi-annual | Failover drill (EE-HA/GOV) | Platform team | `18-DEPLOYMENT.md` §4.4 |
| Annual | RT-3 secrets restore test; RT-4 full DR exercise | Ops + security | `19-BACKUPS-DR.md` |
| Annual | Tang key rotation and FDE re-binding; BK-DATA key epoch rotation | SYS_ADMIN + custodians | `17-INFRASTRUCTURE.md` §6.3; `19-BACKUPS-DR.md` §8 |
| Annual | IRK custodian attestation (each confirms possession) | SECURITY_OFFICER | `19-BACKUPS-DR.md` |
| Annual | Onion-rotation drill in the lab; technical IR drill | IR Lead | `31-INCIDENT-RESPONSE.md` |
| Annual | Admin role re-certification; SoD verification | USER_ADMIN + OVERSIGHT | §4.2 |
| Annual | Independent security audit scope review | Management | `37-SECURITY-AUDIT-PLAN.md` |
| On event | HR leave → deactivation within 1 h | USER_ADMIN | REQ-H-47 |

## 10. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| OPS-001 | C-25 agents SHALL run the §5.2 checks at the stated frequencies and push results only in the fixed schema of §5.1. The collector SHALL reject records with fields or values outside the schema. | ADR-016; INC-60 | THR-016, THR-035 | C-25 | TST: schema-fuzz the collector; unknown-field records rejected |
| OPS-002 | Self-test results SHALL NOT contain counts of submissions, sessions, source accounts, circuits, connections, bytes or requests, nor onion addresses, hostnames or IPs. | ADR-016; REQ-H-74 | THR-016, THR-039, THR-011 | C-25 | TST: static check of the result schema; canary run with synthetic traffic shows identical results for idle vs busy intake (except threshold states) |
| OPS-003 | Disk and queue metrics SHALL be reported only as the bands or threshold states of §5.2. | ADR-011; ADR-010 | THR-011 | C-25 | TST: unit tests of the band functions |
| OPS-004 | Onion availability SHALL be tested from H-MON through Tor against a fixed-size health endpoint, never by intake-side traffic statistics. | B-AN-26; ADR-001 | THR-032, THR-016 | C-25, C-06 | TST: probe works with the intake tor log level at notice; health response is constant-size |
| OPS-005 | Privacy-critical check failures (`net.egress`, `logging.config`, `secret.placement`, `integrity.*`, `tor.config_hash`, `crypto.selftest`) SHALL trigger the fail-closed behaviors defined in `34-PERFORMANCE-SCALABILITY.md` and an immediate content-free alert. | ADR-002; B-SD-22 | THR-035, THR-014 | C-25, C-06 | TST: fault injection for each check → expected behavior and alert |
| OPS-006 | `keys.epoch_runway` SHALL warn Channel Owners when fewer than `min_recipients` eligible member epoch keys are valid for the next 7 days. | ADR-030 | THR-032 | C-25, C-14 | TST: simulated offline member → WARN at 7 days; intake closed at 0 |
| OPS-007 | Alerts SHALL be content-free (`check_id`, `host_role`, `code`) and sent only via tor-routed or certificate-pinned transports. | ADR-017; INC-57 | THR-028 | C-25 | TST: alert payload snapshot; transport config check |
| OPS-008 | Support bundles SHALL follow §8: allow-listed content, HMAC pseudonymization with a local-only key, time truncation, canary scan with abort on hit, operator preview with FIDO2 confirmation, and encryption to the support key. | INC-56; INC-58; REQ-H-56 | THR-027, THR-016 | C-19, C-15, C-36 | TST: bundle from an instance seeded with canaries → zero canaries; abort-on-hit test |
| OPS-009 | Candor SHALL NOT request or accept diagnostics (logs, HAR, screenshots) from sources. | INC-56 (REQ-H-56) | THR-016 | C-06, C-03 | INSP: source UI and support procedures review |
| OPS-010 | The maintenance calendar of §9 SHALL be generated as tasks in the admin console with completion records (signed SYSTEM events). Overdue tasks SHALL raise WARN. | B-SD-08 | THR-035, THR-042 | C-19, C-25 | DEMO: calendar in the admin console; TST: overdue-task warning |
| OPS-011 | The admin console SHALL show each deployment's current CFG class state (all ADVANCED and DANGEROUS items with approver and expiry). | ADR-013; THR-035 | THR-035 | C-19 | DEMO; TST: UI snapshot contains every non-default item |
| OPS-012 | C-37 and published guidance SHALL be reviewed quarterly against `05-SOURCE-OPSEC.md`, and C-37 SHALL load no third-party resources. | INC-53 (REQ-H-53) | THR-036 | C-37 | TST: tracker/third-party crawler on C-37; INSP: review record |
| HUM-001 | The role pairs of §4.2 SHALL NOT be held by the same person in CE-HARDENED and above. In CE-SINGLE, exceptions SHALL be ADVANCED acknowledgements (except SYS_ADMIN + case-content, which is never allowed). | ADR-015; INC-68; INC-70 | THR-018 | C-22 | TST: role-assignment conflict tests per profile |
| HUM-002 | Access grants SHALL expire by default per §4.3 and SHALL be renewable only through the stated approvals. | INC-71; INC-69 | THR-018, THR-019 | C-22 | TST: expiry tests; renewal requires the approver |
| HUM-003 | Audit reviews SHALL operate on pseudonymous case IDs and staff IDs without access to content, and every review action SHALL itself be audited and visible to OVERSIGHT. | ADR-016; INC-68 | THR-018, THR-038 | C-24 | TST: reviewer role has no content permission; review actions appear in the audit |
| HUM-004 | Staff-activity analytics SHALL be limited to published anomaly rules on CASE/SECURITY events. Their results SHALL go to SECURITY_OFFICER (or OVERSIGHT when the subject is a SECURITY_OFFICER). | INC-22; INC-72 | THR-019, THR-018 | C-24, C-25 | INSP: rule catalogue; TST: routing test |
| HUM-005 | In EE and GOV, SSH certificates for H-INTAKE principals SHALL require two-person issuance, with TTL ≤ 8 h. | INC-69; B-SD-13 | THR-018, THR-014 | C-29, C-19 | TST: single-approver issuance refused |
| HUM-006 | H-MON (attestation verifier and self-test collector) SHALL be administered by people other than the SYS_ADMINs of H-INTAKE/H-CORE in CE-HARDENED and above. | B-SD-04 (monitor role) | THR-018 | C-25 | INSP: role assignments; TST: SoD rule |
| HUM-007 | The Admin API and `candorctl` SHALL expose no function returning report content, source account data or source-related timing. | REQ-H-70; ADR-015 | THR-018 | C-19, C-10 | TST: route-registry scan (ADR-029) for forbidden data classes; AUD |
| HUM-008 | Recipients SHALL be able to record an "identity request refused" event on a case, visible to OVERSIGHT and not to the requester. | INC-22 | THR-020 | C-10, C-24 | TST: event visibility test |
| HUM-009 | Organizations SHALL adopt and publish a non-identification and non-retaliation policy before go-live. The installer's go-live checklist SHALL require confirming it. | INC-22; B-CO-02 | THR-019, THR-020 | C-19 | DEMO: go-live checklist |
| HUM-010 | DBA, cloud-admin and vendor access to Candor systems SHALL require SECURITY_OFFICER co-approval per session, be time-bound, and be logged in a customer-visible log. | INC-55; INC-56 | THR-027, THR-030, THR-018 | C-12, C-36 | TST: session without co-approval refused (where Candor-mediated); INSP: procedure |
| HUM-011 | Management reporting SHALL use only k-thresholded, month-granular statistics. | REQ-H-74; INC-74 | THR-039 | C-10 | TST: report generator suppression tests |
| HUM-012 | Role-specific training SHALL be completed before role activation and refreshed yearly (recipient §3.2, investigator §3.3, admin §3.4). | INC-16; INC-21 | THR-041 | C-19 | DEMO: training records gate role activation |
| CFG-001 | Every configurable security control SHALL be listed in the §7 table with a SAFE DEFAULT, and optional ADVANCED and DANGEROUS values with consequence text. Unlisted security-relevant settings SHALL NOT be exposed. | THR-035; B-GL-04 (unsafe defaults) | THR-035 | C-19 | TST: CI compares the config schema against the CFG table (every key present) |
| CFG-002 | ADVANCED values SHALL require a signed single-admin acknowledgement. DANGEROUS values SHALL require DC-09 dual approval with OVERSIGHT notification. | ADR-013; ADR-015 | THR-035, THR-018 | C-19, C-22 | TST: checker exit codes 10/20; approval enforcement tests |
| CFG-003 | DANGEROUS settings marked ⏱ SHALL auto-revert to SAFE DEFAULT at expiry unless re-approved. | B-SD-13 (long-open items) | THR-035 | C-19 | TST: time-travel test reverts the setting |
| CFG-004 | DANGEROUS settings that affect sources (e.g., `intake.clearnet_confidential`, `recovery_quorum`) SHALL be disclosed on the source interface and in the key directory. | ADR-013; ADR-002 | THR-040 | C-06, C-14 | TST: UI and directory show the disclosure when enabled |
| CFG-005 | FIXED controls SHALL NOT be changeable through configuration files, the Admin API or environment variables. Attempts SHALL be rejected and logged. | ADR-001; ADR-016 | THR-035 | C-19 | TST: attempts via each channel rejected |
| CFG-006 | The simple installer SHALL expose only SAFE DEFAULT values and, where §8 of `18-DEPLOYMENT.md` specifies, individual ADVANCED choices with typed confirmation. | B-SD-08 | THR-035 | C-19 | TST: wizard option inventory |
| CFG-007 | Configuration changes SHALL be recorded as SECURITY events with the old class, new class, approvers and expiry. | ADR-016 | THR-018, THR-035 | C-24 | TST: event emitted per change |

## 11. Residual risks and limitations

1. Authorized readers can infer a source's identity from content. Policy, training and paraphrasing reduce this, but it cannot be prevented technically (THR-010).
2. In small organizations (CE-SINGLE), separation of duties may be impossible. The acknowledged exceptions weaken insider controls.
3. The self-test runs on hosts an attacker may control. A compromised agent can report OK. The independently administered H-MON and attestation mitigate this partially.
4. Correlating corporate network logs with source Tor use happens outside Candor, and only source guidance addresses it.
5. Threshold states (disk bands, queue states) still leak very coarse activity during extreme bursts.
6. Support-bundle scrubbing is pattern-based. Novel secret formats may escape the canary scan.

## 12. Open issues

1. The `case.identity_request_refused` event name and schema must be added to `20-LOGGING-AUDITING.md` / `14-CASE-MANAGEMENT.md`.
2. Reconcile the "WEAKENING" label in `15-AUTHENTICATION-AUTHORIZATION.md` with the SAFE DEFAULT / ADVANCED / DANGEROUS classes (this document maps WEAKENING to DANGEROUS).
3. The "disclosure check" feature for investigators (§3.3) needs specification in `14-CASE-MANAGEMENT.md`.
4. Whether the external onion probe from H-MON should itself use vanguards-lite and fresh circuits per probe to avoid creating a recognizable periodic pattern (`16-TOR-I2P.md`).
