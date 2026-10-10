# REVIEW-C — Enterprise / Government Procurement Review (Operational, Integration, HA/DR, Compliance, Insider)

Reviewer: C (security architect approving Candor for (a) a large regulated enterprise and (b) a federal Inspector-General office).
Scope read in full: `DECISIONS.md` (ADR-001..033), 15, 17, 18, 19, 21, 22, 23, 25, 31, 32, 34. Targeted reads: 04 (§9, §14, §16, key table), 06 (§8.3, ARCH-037/039), 07 (notification jobs), 09 (§5.6, §8, §10), 12 (§4.1, §14), 14 (§6.4, §8.4–8.5, §9.4), 20 (§13), 24 (§8–9, BIZ-*), 26, 33 (§14–15), 35 (§10–11), 40 (ASM-019/043/044/045).
Date: 2026-09-30. Weakness IDs: `RVW-C-nn` (prefix RVW- per DECISIONS §3).

Premise of this review: in my two target deployments, the **organization that buys and runs Candor is itself a plausible adversary** (THR-018, THR-020; INC-22 Barclays; the IG case where "the audited agency, including its CIO and SOC" is the adversary, 22 §3). The spec defends well against *Candor server administrators*. It defends much less against the *enterprise that owns the endpoints, the network, the IdP, the hypervisors, the mail system, the legal function and the governance keys*. Most findings below come from that gap.

## Summary

| ID | Title | Severity |
|---|---|---|
| RVW-C-01 | Organization-managed recipient endpoints (MDM/EDR/IRM/VDI) defeat endpoint-only keys; MDM can ship a modified Candor Desk | **CRITICAL** |
| RVW-C-02 | Staff-side timing oracle: event-driven digests, IdP/SIEM login events and Desk update checks leak report arrival to the hour | HIGH |
| RVW-C-03 | Suppression by key loss: "remove-only" automation + no escrow + one device per user lets the organization permanently destroy case access | HIGH |
| RVW-C-04 | Incident response as a pretext: the organization's own IR/DPO/Legal can authorize intake memory and uplink capture | HIGH |
| RVW-C-05 | Governance-key capture: Org Root, Key-Admins, USER_ADMIN pairs and self-asserted `person_ref` let management re-roster channels for future reports | HIGH |
| RVW-C-06 | Hypervisor/SAN/enterprise backups of Z-CORE copy the Erasure Key Vault and vTPM, defeating the ≤ 14-day deletion bound invisibly | HIGH |
| RVW-C-07 | Erasure Key Vault is an undocumented availability single point of failure (ransomware dwell > 14 d, TPM-sealed VMK, DR-site gap) | HIGH |
| RVW-C-08 | Internal contradictions that make EE-HA unbuildable or force ad-hoc checker exceptions | MEDIUM |
| RVW-C-09 | Separation of duties collapses in small organizations; `person_ref` is administrator-asserted; installer bootstraps one admin | HIGH |
| RVW-C-10 | Break-glass and legal-hold approver sets can be satisfied entirely by the legal function; OVERSIGHT is only post-hoc | HIGH |
| RVW-C-11 | Microsoft 365 / desktop OS side channels on recipient workstations not covered by ENT-034 | MEDIUM |
| RVW-C-12 | Enterprise-mandated tooling vs. Candor host rules; guest-invisible logging/snapshot knobs cannot be detected | MEDIUM |
| RVW-C-13 | Paid-edition dependencies: Fleet Manager "tighten-only" is not harmless; clearnet vendor mirrors; fleet key custody undefined | MEDIUM |
| RVW-C-14 | Records law, FOIA/ATIP, DSAR, eDiscovery and breach scoping are not achievable with no cross-case search and no escrow | HIGH |
| RVW-C-15 | FIPS / FedRAMP / CJIS boundary gaps (Tor-transported plaintext and staff traffic, monitoring controls) | MEDIUM |
| RVW-C-16 | Section 508 / EN 301 549 blockers in the viewer and authentication; VDI unsupported | MEDIUM |
| RVW-C-17 | Operational burden unrealistic for municipalities; kernel-update vs. offline UKI-signing contradiction | MEDIUM |
| RVW-C-18 | Legal SLA and channel-availability risks from epoch runway, COI exhaustion and source-account RPO | MEDIUM |
| RVW-C-19 | DR key-custody logistics: quorums unreachable within RTO; key holders co-located with servers | MEDIUM |
| RVW-C-20 | Enterprise network team as a two-ended observer: uplink independence is only SHOULD; RCP-LAN default; C-37 on corporate web stack | MEDIUM |
| RVW-C-21 | MANAGED hosting: vendor root on intake, vendor-operated "customer-visible" log, Tier V not mandatory | MEDIUM |
| RVW-C-22 | IR playbook gaps for the organization-as-adversary, IdP/SCIM compromise, mass key loss, Desk tampering and persons-concerned notification | MEDIUM |
| RVW-C-23 | Tenant Risk Classification is self-assessed by the party it is meant to guard against | MEDIUM |
| RVW-C-24 | EE licence expiry semantics for HA orchestration and SSO bridge are undefined | LOW |

Count: CRITICAL 1 · HIGH 9 · MEDIUM 13 · LOW 1 (24 total).

---

## Weaknesses

### RVW-C-01 — Organization-managed recipient endpoints defeat endpoint-only keys; MDM can ship a modified Candor Desk
- **SEVERITY:** CRITICAL (for any deployment where the organization is a plausible adversary: IG, audit-committee channels, INC-22 class).
- **SCENARIO:** The CEO (or agency head) wants to know who reported. Corporate IT does not touch Candor servers. It uses the fleet tooling it already runs on every laptop, including the ombudsman's and investigators' laptops (C-16):
  1. **MDM repackaging.** Intune/SCCM/Jamf deploys "Candor Desk 1.4.2" wrapped in an `.intunewin` with a post-install script, or with a DLL placed in the WebView2 user-data path. A modified build, or a sideloaded library, logs decrypted DOM text and exfiltrates it. Enterprise users have no local admin rights, so the Desk "self-update" (33 §15.1) cannot run. IT must push every Desk update itself. IT therefore owns the binary by design.
  2. **EDR live response.** The EDR console (Defender, CrowdStrike) runs a script on the ombudsman's laptop while Desk is unlocked. It dumps the Desk and WebView2 renderer process memory, which holds case keys, K09 and plaintext DOM. A single EDR "collect investigation package" does this.
  3. **Insider-risk tooling.** Purview Insider Risk "forensic evidence" screen capture, Teramind or ObserveIT records the investigator's screen (Knowledge (unverified): whether capture-exclusion RUI-038 defeats each product).
  4. **VDI.** GOV and large enterprises often deliver desktops via Citrix/AVD. The hypervisor admin sees all memory. OI-15-2 leaves "forbid VDI?" open.
  The adversary gets the content of every case in the ACLs of the compromised members, including the source's own words and attachments. Content (THR-010) identifies the source in small populations, and it exposes the Sealed Identity Store if an Identity Custodian's laptop is managed the same way (ADR-014).
- **AFFECTED:** ADR-007 ("private keys live only on recipient endpoints"), ADR-015 ("admins have zero content capability, cryptographically"), ASM-019 (workstation integrity), ASM-043 (organization-as-adversary: its scope is only "administrators hold no case keys and cannot deploy modified trust-path code", read by 40 as *server* attestation, ASM-116), 12 §4.1 posture checks and RUI-057, 33 §15.1/UPD-013, 15 OI-15-2, 21 ENT-034, 32 §4.1 ("Executive seeking identity" row lists no endpoint vector), 17 §8.3.
- **WHY NOT PREVENTED:** Every cryptographic guarantee ends at C-16. Nothing in the spec requires C-16 to be administered by someone other than the reported-on organization. The Desk posture check ("running trust-path binaries match the transparency log") is performed **by the binary being checked**, so a modified build reports "OK". ASM-116's C-25 signed statement covers servers, not Desks. ENT-034 checks only EDR *sample upload* and DLP *indexing*, once, at enrollment. It does not check remote-response, memory-collection or screen-capture capabilities, and it can be overridden by the same admin with a "recorded risk acceptance". The "Admin ≠ case access" model (15 §5.7) considers Candor SYS_ADMIN and USER_ADMIN, never the enterprise's endpoint administrators.
- **PROPOSED FIX:**
  1. **New ADR-034 "Recipient endpoint custody".** For channels flagged `independent_route` or with OVERSIGHT_MODE, and for all GOV-IG/IA (22 §5.1/5.2) and D1/D2 tenants (21 §6.3), Candor Desk for roster members SHALL run on a device class **not administered by the reported-on organization**: (a) AIRGAP-RCP WS-VIEW; (b) a dedicated device enrolled in an MDM tenant controlled by OVERSIGHT or external counsel; or (c) a Candor-supplied hardened image (Qubes/Secureblue-class) with measured boot. Record the custody attestation per device in C-14 (`DEVICE_CUSTODY` entry, K15 + OVERSIGHT signature). Sources see "Recipient devices managed by: <org / independent>" in the channel descriptor (ROUTE-002).
  2. **Add ASM-019b** in 40: "C-16 is not administered by a party within the COI scope of the channel". Add the THR-018 sub-threat "enterprise endpoint administrator" to 02.
  3. **12/33:** remote device attestation for Desk. Desk reports TPM-quoted measured-boot PCRs plus the Desk binary hash, verified by the **server** (C-25) and by *peer* Desks, not by the Desk itself. Case-key wraps (AUTHZ-005) SHALL be refused to devices whose attestation fails or whose custody is `org-managed` on independent channels.
  4. **21 ENT-034** extended to a recurring (daily) `desk-preflight` that also detects EDR live-response/remote-shell, screen-recording and insider-risk agents, VDI/RDP sessions and non-vendor-signed modules loaded into the Desk or WebView2 process. On independent channels the override SHALL require OVERSIGHT approval (not an admin risk acceptance).
  5. **Resolve OI-15-2:** VDI SHALL be forbidden for roster members (AUTH-021).
  6. **33:** define an "enterprise distribution" mode. IT deploys only the vendor-signed MSI unchanged. Desk verifies its own Authenticode chain against a TUF-pinned publisher certificate, and C-25 compares the reported hash against CLIENT_RELEASE (04 §14.2) on every session, rejecting unknown hashes server-side.
- **RESIDUAL RISK:** A determined organization with physical access to independently managed devices can still implant hardware. Server-side attestation raises the cost but is defeated by a TPM/firmware-level implant. The organization can still refuse to fund independent devices, but that refusal then becomes visible to sources.

### RVW-C-02 — Staff-side timing oracle leaks report arrival to the hour
- **SEVERITY:** HIGH.
- **SCENARIO:** An employee submits via Tor Browser at 14:05 from home. The corporate proxy never sees it. But the employee also submitted a follow-up earlier from a corporate-VPN split-tunnel laptop, and the SOC sees "Tor from laptop X at 14:05". ADR-010 carefully stores only `received_epoch_day`. However:
  - C-09 pulls within 15 ± 10 min. `notify_intake_available` fires **only after an import batch commit** (07 §jobs, BE-021). The ombudsman receives the content-free email at the next hourly slot plus U(0,10) min. The corporate Exchange/Proofpoint journal (retained 7 years under SEC 17a-4 or records policy) stores the exact time of every Candor digest to every recipient. Teams webhooks appear in Microsoft 365 audit logs (ENT-035 acknowledges "digest timing" but not its meaning).
  - The investigator then logs in. Entra ID sign-in logs record time, IP and device (21 §8 row "Microsoft Entra ID"). C-26 exports `auth.login_succeeded` with `ts` and actor to the SOC (20 §13). `auth.stepup_failed` carries `operation_class`, which can reveal an identity-unseal attempt. `breakglass.*` carries `reason_code=IMMINENT_DANGER`.
  - Desk refreshes TUF metadata "on every start" via the vendor mirror over clearnet TCP 443 (33 §15.1; 06 flow matrix). The mirror/CDN and the corporate proxy see each Desk start.
  - RCP-LAN (the EE/GOV default) gives the network team per-flow timing (17 §4.6, which admits this).
  Each channel gives an *hour-granular* "a new report arrived" signal to parties the organization controls. Correlated with Tor-use observations (THR-002) across a source's several follow-ups, it narrows the candidate set sharply. This undoes ADR-010 for exactly the adversary ADR-010 exists for.
- **AFFECTED:** ADR-010, ADR-017, ADR-033(4), 07 BE-021/BE-037, 20 §13 allow-list (AUD-010), 21 §8 Entra/Teams rows, ENT-035, 17 §4.6/INFRA-009, 33 §15.1/UPD-013, 06 §8.3, THR-011, THR-028.
- **WHY NOT PREVENTED:** Timing minimization was applied to **source-side** records only. Staff reactions are treated as legitimate staff metadata ("exact timestamps exist only for staff actions", ADR-010). But staff reactions are a deterministic function of source actions. The "hourly digest" is event-driven, not constant-rate, so it batches without providing cover.
- **PROPOSED FIX:**
  1. **Amend ADR-017:** the default `notify.mode` becomes a **fixed daily digest at a fixed local time, sent every day whether or not there is activity** (cover traffic), or "no external notification, Desk badge only". Event-driven hourly digests become ADVANCED with consequence text: "reveals report arrival hour to the mail/chat operator."
  2. **20 §13:** for SIEM export, `auth.*` timestamps SHALL be day-granular by default (exact time ADVANCED). `operation_class` SHALL be removed from `auth.stepup_failed`. `breakglass.*` export SHALL be count-only per day. Z-INTAKE-derived `sys.capacity` SHALL NOT be exported. Add an AT test (30) "staff-reaction correlation": the latency distribution from submission to first staff event across all exported sinks must not be distinguishable from the no-submission baseline at hour resolution.
  3. **15 §4.4 / 21 §8:** document the IdP as a timing observer in the source-facing "what this protects" page (ANON-013). Add a SHOULD for a dedicated IdP (GOV-006 pattern) for independent channels.
  4. **33 §15.1:** Desk TUF refresh SHALL go through Z-CORE's mirror endpoint only (never the vendor clearnet mirror) and on a fixed daily schedule independent of Desk start.
  5. **12:** a "delayed reaction" option, where Desk defers import-driven actions to a scheduled daily work window, with guidance for recipients.
- **RESIDUAL RISK:** Humans will still react faster to urgent reports. Day-level correlation remains, which is inherent to any responsive process.

### RVW-C-03 — Suppression by key loss: remove-only automation, no escrow, one device per user
- **SEVERITY:** HIGH.
- **SCENARIO:** The accused CFO controls HR and IT. Without touching Candor, the organization can make every current case and every un-imported envelope permanently unreadable:
  - (a) HR edits `manager` chains in the HRIS. SCIM propagates. C-22 "computes additional exclusions from ... manager chain" and "Excluded current members are removed immediately", and the **server deletes their wrapped-key rows** (14 §8.4–8.5). AUTH-012 explicitly treats removal as the "safe" direction. Exclusions become the "permanent per-case deny list".
  - (b) SCIM deactivates both investigators ("deactivation takes effect immediately", 15 §4.4). SOAR `force re-enrollment` (ENT-032) has undefined key-continuity semantics.
  - (c) IT reimages both laptops ("malware suspected", "hardware refresh"). v1 allows **one active device per user** (04 §9.4). The device-link ceremony needs the old device. The member's K09 and MEKs are gone.
  - (d) An investigator on 5 weeks of leave has their device "revoked and treated as lost" after 30 days offline (35 §11). The dormant account auto-suspends at 60 days (AUTH-019).
  With no Recovery Quorum (ADR-013 default), DR-P6 says "content is unrecoverable (by design)". Backups do not help (19 §9). `intake.min_recipients` defaults to **1** (32 §7, ARCH-037), while `case.min_key_holders` defaults to 2. After COI filtering, an envelope may be wrapped to a single member, so one reimage loses it. The anti-suppression machinery (auto-ack, canary §9.4, ADR-033(2)) detects that work stopped. It cannot bring back the keys.
- **AFFECTED:** ADR-013, ADR-015, ADR-030, ADR-033(2), 04 §9.4 (single device), 14 §8.4–8.5, 15 AUTH-012/AUTH-019 and §4.4 SCIM table, 21 ENT-016/ENT-032/ENT-033, 35 §11 "Member device offline", 19 DR-P6/DR-008, 32 §7 `intake.min_recipients`, 34 F5.
- **WHY NOT PREVENTED:** The design treats *loss of access* as fail-safe. For whistleblowing, loss of access is the adversary's goal (suppression, THR-020, INC-22). "Remove-only" automation is exactly the capability the adversary wants. Wrap deletion is performed by the server on an attribute signal, with no human in the loop and no cooling-off period.
- **PROPOSED FIX:**
  1. **14 §8.5 / AUTH-012:** automatic exclusion from IdP/HR attribute changes SHALL *suspend* server delivery but SHALL NOT delete wrap rows. Deletion and re-keying require CASE_LEAD + OVERSIGHT approval (new DC-15). A removal that would leave a case or channel with fewer than 2 key holders SHALL be blocked until a replacement wrap exists.
  2. **15 §4.4:** SCIM deactivation SHALL enter a `DEACTIVATION_PENDING_HANDOVER` state (sessions revoked, keys intact) for up to 14 days. OVERSIGHT is notified, and the case-key handover to successors is completed by a member Desk.
  3. **04 §9.4:** allow ≥ 2 linked devices per roster member (a primary plus a sealed spare kept by OVERSIGHT, or AIRGAP spare). Define `force re-enrollment` in ENT-032 as "rotate authenticators, keep keystore".
  4. **32 §7:** `intake.min_recipients` SAFE DEFAULT = 2, with value 1 as ADVANCED. Envelopes SHALL be wrapped to ≥ 2 eligible members or fail closed with an explicit source message (see RVW-C-18).
  5. **35 §11:** replace "offline > 30 days → revoked" with a suspension (no data delivery) and an OVERSIGHT decision.
  6. **ADR-013:** for GOV and D1/D2 tenants, require a choice between an independent Recovery Quorum and documented acceptance of permanent-loss risk signed by OVERSIGHT. Add PB-15 (see RVW-C-22).
- **RESIDUAL RISK:** An organization that physically destroys all devices, including spares, still wins. Escrow adds its own risks (see RVW-C-14).

### RVW-C-04 — Incident response as a pretext to capture Tier W plaintext and uplink timing
- **SEVERITY:** HIGH.
- **SCENARIO:** Management wants the next submissions. The security team (SECURITY_OFFICER, who reports to the CIO) declares SEV-0 "attestation mismatch" (`candorctl ir declare`). This is trivially induced by any admin who reboots with a modified cmdline. IR Lead plus DPO approve `ir capture memory --host intake` (IR-007). IR Lead + DPO + Legal approve a 24 h header capture on N-INTAKE-EXT (IR-008). All three are employees of the organization. The IR Evidence Key is split 2-of-3 among **the same three roles** (31 §6.2). They now hold Tier W plaintext and passphrases in flight (E-MEM), plus exact Tor-flow timing. `ir diagnostic mode` and `ir isolate` are also available to them.
- **AFFECTED:** 31 §4 roles, §6.1 E-MEM/E-NET, §6.2 IEK, IR-007, IR-008, IR-009; 32 §3.5; ADR-004; ADR-015; THR-018, THR-020.
- **WHY NOT PREVENTED:** IR approvals mirror the corporate hierarchy. No approver is required to be independent (OVERSIGHT, external counsel). Nothing requires that an intake memory capture be disclosed to sources (SSN) or to OVERSIGHT before it runs. The COI exclusions in IR-003 depend on someone admitting that they are implicated.
- **PROPOSED FIX:**
  1. **IR-007/IR-008 amended:** H-INTAKE memory capture and N-INTAKE-EXT capture SHALL require **OVERSIGHT approval** (or, in GOV-IG, the IG's designated independent official) in addition to IR Lead + DPO, via a step-up Approval object (new DC-16). The capture tool SHALL encrypt to a **one-time key split between OVERSIGHT and the DPO**, not the standing IEK.
  2. **31 §7:** any E-MEM capture of H-INTAKE SHALL trigger an automatic SSN-GLOBAL `compromise-intake-window` for the capture day. This makes pretextual capture self-disclosing.
  3. **31 §6.2:** at least one of the three IEK holders SHALL be outside management's reporting line (OVERSIGHT or external counsel).
  4. Add a SEV-classification check: if the declared incident was not independently confirmed by H-MON (administered per HUM-006) within 1 h, captures remain blocked.
- **RESIDUAL RISK:** Collusion including OVERSIGHT, or the organization simply replacing the intake binary instead of "doing IR". That second path is caught by attestation only if H-MON is independent.

### RVW-C-05 — Governance-key capture lets management re-roster channels for future reports
- **SEVERITY:** HIGH.
- **SCENARIO:** After RVW-C-03 empties the channel, or simply by pressure, management uses **legitimate** governance paths:
  - (a) Two cooperative USER_ADMINs enroll a loyalist (DC-07). The out-of-band identity check is done by the second USER_ADMIN, and `person_ref` is typed in by a USER_ADMIN, so one person can appear as two (see RVW-C-09).
  - (b) An **orphan re-key** of the channel: K01 Org Root (3-of-5 shares) plus 2 K15 key-admins create a new Channel Identity Key and roster (04 §14, KEY-010).
  - (c) A cooperative CHANNEL_OWNER + OVERSIGHT approve a roster addition (DC-08).
  Future envelopes are wrapped to the new members' MEKs. Detection relies on Desk notifications to members (KEY-028), who may have been removed, and on sources noticing a changed role label or an "orphan" marker in the descriptor.
- **AFFECTED:** 04 §14.2 (CHANNEL_IDENTITY, CHANNEL_ROSTER, K01/K15 roles), KEY-010, KEY-028, 15 §4.2/DC-07/DC-08, ADR-030 ("role labels ... names optional"), ROUTE-002, THR-046, ASM-045.
- **WHY NOT PREVENTED:** The transparency log makes these changes *visible*, not *hard*. The holders of K01 and K15 are not required to include anyone independent of management. There is no cooling-off period, and Tier W sources are shown a descriptor they cannot meaningfully evaluate.
- **PROPOSED FIX:**
  1. **04 §14/§25:** K01 share distribution SHALL be such that no management-only coalition reaches k, e.g., ≥ (n−k+1) shares with OVERSIGHT/external parties. Record holder role labels in ORG_ROOT and show them to sources.
  2. Orphan re-keys and any roster addition to an `independent_route` channel SHALL have a **14-day publication delay**. During the delay the new keys are logged but not used for wrapping. The source landing page and Source App show a prominent "Recipients of this channel are changing on DATE" banner, and the old members' and OVERSIGHT Desks can file an objection that blocks activation (new ROUTE-010).
  3. Source App (Tier V) SHALL pin the roster and require explicit source acknowledgment of any roster change since the source's last visit (11).
  4. **15 AUTH-015:** identity verification for enrollment on independent channels SHALL be performed by OVERSIGHT, not by USER_ADMIN.
- **RESIDUAL RISK:** An organization that controls the independent body (a captured audit committee) is out of technical reach. The delay slows emergency staffing.

### RVW-C-06 — Enterprise hypervisor, SAN and backup copies of Z-CORE defeat the deletion bound invisibly
- **SEVERITY:** HIGH (deletion and "right to erasure" claims; evidence-destruction guarantees made to sources).
- **SCENARIO:** In EE-ONPREM, Z-CORE runs "on customer virtualization" (18 §4.3). The corporate backup team's Veeam/Commvault/Cohesity policy images all VMs nightly, with a 7-year retention for SOX. Each image contains `/var/lib/candor/ekv/` (the Erasure Key Vault, 09 §5.6), the DB with Erasure-Key-encrypted wraps, and the **vTPM state** that seals the VMK (CE-style TPM2 sealing, or the swtpm files in CE-SINGLE). SAN-level snapshots do the same. Every case "deleted" by crypto-erasure stays recoverable for 7 years by anyone who holds a former member's keys, or who later obtains them via RVW-C-01. The same images are subject to litigation holds and eDiscovery requests covering "all backups".
- **AFFECTED:** ADR-025, ADR-033(3), 09 §5.6 and DB-036, 19 §8 "Deletion propagation" and BAK-014/BAK-028, 18 DEP-031 ("config checker SHALL detect installed backup agents"), 17 INFRA-021 (libvirt-only), 32 CFG `hypervisor.intake_snapshots` (intake only), 35 §11 user-facing statement "unreadable ... in backups within 14 days".
- **WHY NOT PREVENTED:** DEP-031 detects only **in-guest** agents. Hypervisor-level backups, storage snapshots and vTPM state are invisible to the guest and to `candorctl check`. The CFG table covers only *intake* snapshots. The user-facing deletion promise is unconditional.
- **PROPOSED FIX:**
  1. **ADR-033(3) amended:** the VMK SHALL be held in an HSM (EE/GOV) or on the **physical** TPM of a dedicated host, never a vTPM, whenever Z-CORE runs on shared virtualization. The Erasure Key Vault SHALL live on H-CORE-EKV, a dedicated small physical host or HSM partition outside the virtualization estate.
  2. **18 §4.3:** EE-ONPREM Z-CORE on shared virtualization is ADVANCED, requiring a signed attestation by the virtualization/backup owners that Candor VMs are excluded from image-level backups and snapshots. Add a periodic *probe*: C-25 writes a canary file with a known key and verifies, via the DR/backup owner's restore-test interface, that it is **not** restorable (DEMO).
  3. **35 §11:** make the user-facing statement conditional on the deployment's attested backup exclusions, displayed in the configuration digest (03 §landing footer).
  4. **32 §7:** add `hypervisor.core_snapshots` and `backup.image_level_core` as DANGEROUS, with a customer attestation (not checker-detectable) disclosed to sources.
- **RESIDUAL RISK:** Attestations are only as honest as the virtualization team, which may report to the accused.

### RVW-C-07 — The Erasure Key Vault is an undocumented availability single point of failure
- **SEVERITY:** HIGH (DR workability).
- **SCENARIO:**
  1. **Ransomware dwell > 14 days.** Median dwell times are often measured in weeks. DR-P4 says "restore the latest set whose manifest chain verifies and whose creation predates T0". If T0 is 20 days ago, no BS-ERASURE set predates T0 (≤ 14-day hard retention, BAK-028/DB-036). F5d says "No re-wrapping of case keys without the Erasure Key layer", and Desk case opening pauses. Every case is unreadable unless members' Desks happen to cache case keys, and 19 OI-6 leaves that re-wrap path unspecified.
  2. **Hardware loss in CE.** The VMK is TPM2-sealed on H-CORE (09 §5.6). `EXPORT_BACKUP` is unspecified: if it exports `ek_sealed` records (sealed under the dead TPM's VMK), the vault is unrestorable on replacement hardware. BS-SECRETS (19 §3) does **not** list the VMK.
  3. **EE-HA site loss.** The vault is "replicated synchronously to the standby core host only (never to object storage)" (09 §5.6). The DR site receives async WAL/blob replicas but not the vault. HA-007 claims site RPO ≤ 15 min and RTO ≤ 4 h. For case access, the effective RPO is the last nightly BS-ERASURE (up to 24 h), and cases created since then need an unspecified member re-wrap.
- **AFFECTED:** ADR-033(3), 09 §5.6/DB-035/DB-036, 19 §3 BS-ERASURE, §8, §10 RPO table, §11 DR-P2/DR-P4, OI-5/OI-6, 21 HA-007, 34 F5d.
- **WHY NOT PREVENTED:** The vault was designed as a deletion control. Its role as a hard dependency for **all** case access was not propagated into the DR design, the RPO tables or the ransomware playbook.
- **PROPOSED FIX:**
  1. **04/09:** specify that Desks cache **case keys** (K06) in their keystore (K11-sealed) and specify a normative "re-wrap from Desk" procedure (closes 19 OI-6). Then vault loss degrades to "members must re-wrap" rather than total loss. State this explicitly in F5d and DR-P2/P4.
  2. **19 §3:** add the VMK (or VMK-escrow under BK-SECRETS) to BS-SECRETS. Define `EXPORT_BACKUP` as EKs re-encrypted to BK-DATA, not sealed under the TPM.
  3. **19 §11 DR-P4:** when T0 predates the oldest BS-ERASURE, restore the *latest* vault set (post-T0 vault contents are keys, not code, so integrity is checked by the AEAD against DB rows) with dual approval, instead of implicitly refusing.
  4. **21 §5.2:** replicate the vault to the DR site's HSM (EE) under the same 14-day rule, or restate the HA-007 RPO honestly.
  5. Add RT-5 to 19 §7: "vault loss drill: restore with vault ≥ 15 days old".
- **RESIDUAL RISK:** Caching case keys on Desks lengthens their exposure on endpoints (see RVW-C-01). That is a real tradeoff.

### RVW-C-08 — Internal contradictions make EE-HA unbuildable or force ad-hoc checker exceptions
- **SEVERITY:** MEDIUM.
- **SCENARIO:** An integrator builds EE-HA and finds that the binding documents conflict. Each conflict gets resolved locally by disabling a checker rule, which is exactly the "misconfiguration" class (THR-035) the checker exists to prevent.
  - **Intake replication.** 09 §8/§10 and DB-009: the intake DB SHALL run `wal_level=minimal`, `max_wal_senders=0`. 21 §5.2/HA-002 and 17 F16: intake uses **synchronous streaming replication** A→B, which requires `wal_level=replica` and WAL senders. The `pg_params` health check fails on every EE-HA intake.
  - **HSM fallback.** HA-013: with both HSMs down, per-node TPM keys SHALL sign audit checkpoints. FAIL-013: HSM unavailability SHALL NOT cause signing with fallback keys.
  - **Update path.** 17 §4.5/INFRA-008: H-CORE and H-INTAKE fetch Candor updates **only over tor**. 33 §14 and UPD-005: Z-CORE uses "HTTPS to vendor mirrors", and intake receives bundles "pushed by C-09 (default)". 06 flow matrix: Desk → update mirror TCP 443.
  - **Vault location.** ADR-033(3) and 19 BS-ERASURE: "C-12 separate schema / host-local file". 09 §5.6: a host-local file only. If implemented as a schema, it is included in Patroni replicas and WAL archives, contradicting BAK-028.
  - 12 RUI-055 still verifies "the envelope header's recipient key IDs", which ADR-033(1) removed from the cleartext header.
- **AFFECTED:** DB-009, DB-021, HA-002, HA-013, FAIL-013, INFRA-008, UPD-005, ADR-033(1)/(3), BAK-028, RUI-055.
- **WHY NOT PREVENTED:** There was no cross-document consistency pass after the ADR-032/033 amendments.
- **PROPOSED FIX:** An ADR-033 follow-up (ADR-035 "Consistency amendments"):
  - DB-009 applies to single-intake profiles only. For EE-HA, `wal_level=replica`, `max_wal_senders=1`, `archive_mode=off`, `wal_keep_size ≤ 256MB`, `track_commit_timestamp=off`.
  - Fix HA-013 to "TPM-resident keys published in C-14 are *not* software fallback", and reword FAIL-013 accordingly, or delete one of them.
  - Choose one update path per zone and fix 17/33/06.
  - Delete "separate schema" from ADR-033(3).
  - Fix RUI-055.
  - Add a CI "spec-lint" in 39 that cross-checks CFG keys, DB params and flow tables.
- **RESIDUAL RISK:** Low once reconciled.

### RVW-C-09 — Separation of duties collapses in small organizations
- **SEVERITY:** HIGH (for SMB, municipalities and small IG offices, which are the stated targets of 23 §4 and 22 §5.3).
- **SCENARIO:** The SMB target is "1–3 designated recipients and no in-house security team" (23 §4.1). The dual controls that must work need, at a minimum, distinct persons for:
  - SYS_ADMIN ≠ SECURITY_OFFICER (DC-09);
  - 2 USER_ADMINs (DC-07);
  - CHANNEL_OWNER + OVERSIGHT, and 2 OVERSIGHT for DC-12;
  - 2 IDENTITY_CUSTODIANs ≠ CHANNEL_OWNER (DC-04, 32 §4.2);
  - 2 distinct K15 key-admins for roster additions (04 §14.3 rule 3);
  - an H-MON admin ≠ SYS_ADMIN (HUM-006);
  - IRK and IEK custodians such that "no single person holds k shares".
  That is at least six natural persons. In reality an MSP technician holds SYS_ADMIN, USER_ADMIN and the "second" admin (CE-SINGLE permits "ADVANCED exceptions", HUM-001). `candor-setup` step 5 enrolls **one** admin with two FIDO2 keys (18 §8), so there is no second USER_ADMIN to perform the out-of-band identity check. `person_ref` is an attribute typed in by a USER_ADMIN (13 §user list; 15 §5.8 checks only distinctness), so one human with two `person_ref` values satisfies every "distinct person" check. In CE-SINGLE, H-MON is on the same hypervisor (18 §4.1), so attestation (the main defense against a malicious admin, 32 §4.1) is absent.
- **AFFECTED:** 15 §5.1, §5.8, AUTHZ-004, AUTHZ-011; 32 §4.2, HUM-001, HUM-006; 18 §8 step 5, DEP-011; 23 §4, SMB-001; ASM-045; 17 §5.6.
- **WHY NOT PREVENTED:** Dual control is specified in terms of role objects and `person_ref`, with no binding of `person_ref` to a verified natural person. The SMB profile claims it "SHALL NOT relax any ... default" (SMB-001), but SoD is *not* a default the checker can see.
- **PROPOSED FIX:**
  1. **15:** `person_ref` SHALL be bound at enrollment to the FIDO2 attestation plus a signed enrollment record witnessed by OVERSIGHT (or, in SMB, by an **external** party: the organization's statutory auditor, external counsel or a Candor-certified ombuds service). Two accounts with the same authenticator AAGUID+serial (where attestation exposes it) SHALL share a `person_ref`.
  2. **23 §4:** add an "SMB minimal-role profile" that states honestly which dual controls degrade to single control with notice, and which are replaced by an **external co-signer** (e.g., a MANAGED-style independent operator or an external ombudsperson holding OVERSIGHT, K15 #2 and IRK share #3). Make this mandatory when fewer than 4 distinct persons are enrolled, and disclose "Separation of duties: reduced" on the source landing page (configuration digest, 03).
  3. **18 §8:** the installer SHALL require a second, distinct admin (or the external co-signer) before go-live.
  4. **CE-SINGLE:** state in 18 §4.1 THREAT MODEL that a malicious SYS_ADMIN is **not detectable**, and require Tier V-only for high-risk use.
- **RESIDUAL RISK:** Small organizations will still concentrate trust. The goal is honest disclosure plus an external anchor.

### RVW-C-10 — Break-glass and legal-hold approvals can be satisfied entirely by the legal function
- **SEVERITY:** HIGH.
- **SCENARIO:** The General Counsel (COUNSEL, reporting to the CEO) files break-glass with reason `LEGAL_DEADLINE` ("regulator deadline tomorrow"). The rule is "two approvers from {CHANNEL_OWNER, COUNSEL, OVERSIGHT}, both ≠ requester, at least one from OVERSIGHT **or COUNSEL**" (15 §5.6/AUTHZ-010). The Deputy GC and a second in-house counsel approve, and OVERSIGHT only reviews within 7 days. The keys then come from "any available case member's Desk wrapping to the requester (preferred)". An investigator under employment pressure complies. Separately, a tenant-wide litigation hold "by COUNSEL with OVERSIGHT approval" (35 §10) freezes deletion of everything, including source-requested purges and Art 17 purges. eDiscovery Export Packages (ENT-019) go to the GC's matter-management system (21 §8), whose eDiscovery vendor, retention and custodians the GC controls. In retaliation litigation, the company's own counsel requests "all records relating to the complaint" and gets the Export Package, with "redaction" decided by in-house staff.
- **AFFECTED:** ADR-015 (break-glass), 15 §5.6, DC-05, DC-06, AUTHZ-010; 35 §10, RET-009; 21 E18/ENT-011/ENT-019, §8 Legal row; 31 IR-004; THR-019, THR-020.
- **WHY NOT PREVENTED:** Approver sets are defined by role, not by independence. COUNSEL is treated as independent although in-house counsel represents the organization, not the reporter. There is no requirement that a break-glass key donor be protected from pressure (anti-retaliation for the *recipient*).
- **PROPOSED FIX:**
  1. **AUTHZ-010:** at least one approver SHALL be OVERSIGHT, **before** execution. For `LEGAL_DEADLINE`, OVERSIGHT approval is mandatory and a 24 h minimum delay applies (IMMINENT_DANGER may be immediate, with post-hoc review). COUNSEL SHALL be tagged `internal` or `external`, and only external counsel counts toward independence.
  2. **15 §5.6:** a member who wraps to a break-glass requester SHALL be shown the approval set and SHALL be able to refuse with a recorded `case.identity_request_refused`-style event (HUM-008) visible to OVERSIGHT.
  3. **35 §10:** tenant-wide holds SHALL NOT block source-initiated mailbox deletion or Sealed Identity Store scheduled deletion unless the hold order names them (align with ENT-011). Holds SHALL be disclosed on the landing page as "A legal hold currently suspends deletion" (no detail).
  4. **21 ENT-019:** Export Packages for litigation SHALL require OVERSIGHT co-approval and a redaction review by a non-management reviewer, and SHALL record the destination system.
- **RESIDUAL RISK:** Lawful court orders will still compel production. That is outside technical control, but it should not be the default *internal* path.

### RVW-C-11 — Microsoft 365 and desktop OS side channels on recipient workstations
- **SEVERITY:** MEDIUM (accidental exposure, common in real deployments).
- **SCENARIO:**
  - The recipient saves an Export Package to "Documents". OneDrive Known Folder Move syncs it to SharePoint, where Purview, eDiscovery and Copilot index it (21 §8 addresses this only as "guidance ... customer responsibility").
  - Candor Desk's WebView2 renderer crashes. Windows Error Reporting and Edge WebView2 Crashpad upload a minidump containing decrypted DOM text and key material to Microsoft, subject to tenant diagnostic policy.
  - Purview Endpoint DLP "collect original file as evidence" copies an exported file to an Azure evidence store.
  - Windows cloud clipboard syncs the 60 s clipboard content (12 §14 item 3).
  - Windows Recall screenshots (Copilot+ PCs), if the capture-exclusion flag is not honored.
  (Product names and behaviors: Knowledge (unverified).)
- **AFFECTED:** 21 ENT-034, §8 (Purview, Defender, Copilot rows), 12 RUI-038/RUI-039, 20 LOG-009, 34 FAIL-007 (viewer crashes only), IR-027, THR-016, THR-029, THR-041.
- **WHY NOT PREVENTED:** Desk crash handling is specified only for the C-17 viewer (FAIL-007). The main Desk process and webview crash paths are not specified. ENT-034 is a one-time enrollment check with an admin override and covers EDR sample upload and DLP indexing only.
- **PROPOSED FIX:**
  1. **12:** add RUI-06x: Desk SHALL disable OS and webview crash reporting for its processes (WER `LocalDumps` off and `DontSendAdditionalData`; WebView2 `--disable-crash-reporter`, or its policy equivalent; macOS `ReportCrash` exclusion), SHALL set `PR_SET_DUMPABLE`/`SetProcessMitigationPolicy` equivalents, and SHALL default the Export Package destination to a Desk-managed encrypted folder excluded from sync clients. Detect KFM/Dropbox/Google Drive sync roots and block export there without OVERSIGHT approval.
  2. **21 ENT-034:** convert it to a recurring daily `desk-preflight` check with a maintained product catalogue (21 OI-3) covering KFM, endpoint DLP evidence collection, IRM screen capture, cloud clipboard, Recall and crash upload.
  3. Add AT/ST tests: crash Desk with canary content and assert that no dump leaves the host.
- **RESIDUAL RISK:** Vendor products change faster than the catalogue can track.

### RVW-C-12 — Enterprise-mandated tooling vs. Candor host rules; guest-invisible knobs
- **SEVERITY:** MEDIUM (procurement blocker, plus a detection gap).
- **SCENARIO:**
  - Corporate policy and CJIS/FedRAMP (SI-3, SI-4, RA-5, AU-6) require EDR, an authenticated vulnerability scanner and a log forwarder on **every** server. Candor forbids them on H-INTAKE (INFRA-017, INFRA-030; 32 §3.4 "Never install ... EDR, ... log shippers"). The checker fails and the intake closes (F13).
  - The organization either never deploys, or grants an "exception" in which the EDR runs on H-INTAKE with kernel-level memory scanning and cloud upload, which sees Tier W plaintext.
  - Knobs the guest cannot see: the network team enables SPAN or NetFlow on the H-INTAKE switch port; the storage team snapshots the intake LUN; BMC serial-over-LAN console logging captures boot output; hypervisor snapshots exist on non-libvirt hypervisors (INFRA-021 checks `virsh` only).
  The "accidental dangerous logging" questions: **Candor-managed knobs are well covered**. `tor.config_hash` stops C-06 on any torrc change (32 §5.2). DB-021 fixes `log_statement=none` and `log_min_error_statement=panic`. `journald.intake_storage=persistent` is DANGEROUS. `logging.config` → F13 stops intake. Exceptions: `tor.log_level` debug is available for 24 h with DC-09, and core `log_connections=on` is intended. **Non-Candor knobs are not covered.**
- **AFFECTED:** 17 INFRA-017, INFRA-021, INFRA-030, §4.10; 32 §3.4, §7; 18 DEP-031; 25 §5.2 SI-/RA-/AU- rows; 22 GOV-018; 34 F13.
- **WHY NOT PREVENTED:** The spec forbids rather than provides. There is no Candor-approved, allow-listed scanner/EDR mode, and no customer attestation workflow for infrastructure-layer settings.
- **PROPOSED FIX:**
  1. **17:** define an "Assured monitoring profile" for H-INTAKE. Candor ships its own AGPL, allow-listed integrity and malware scanner (on-host, offline signatures delivered via TUF, results in the C-25 schema only), an authenticated vulnerability *inventory* (package list and versions via `candorctl`) for RA-5, and a documented mapping showing that SI-3/SI-4/RA-5 are satisfied by these plus attestation. EDR on H-INTAKE stays FIXED-forbidden.
  2. **32 §7:** add customer-attested (non-checkable) CFG items: `infra.intake_port_mirroring`, `infra.intake_lun_snapshots`, `infra.bmc_console_logging`, `infra.hypervisor_snapshots_core`. Each requires signed attestation by the owning team, shown in the configuration digest and data-flow report (COMP-023).
  3. **25 §5.2:** add an explicit "Control tailoring" annex stating which 800-53 controls are satisfied by alternative implementation on Z-INTAKE, for the SSP.
- **RESIDUAL RISK:** Organizational exceptions will still be granted by people who report to the accused.

### RVW-C-13 — Paid-edition dependencies create new privacy and availability dependencies
- **SEVERITY:** MEDIUM.
- **SCENARIO:**
  - **Fleet Manager.** C-34 may send `apply_policy_bundle (tighten-only)`, `rotate_internal_certs` and `schedule_update` (21 §9.3). "Tighten-only" in a *security* sense can be destructive: raising `intake.min_recipients` to 16 closes every channel (ARCH-037); setting `authz.break_glass=disabled` (an allowed "tighter" value, 32 §7) removes emergency access; shortening `backup.retention_days` lowers recoverability; forcing `rotate_internal_certs` mid-pull breaks the relay. A compromised or compelled vendor can therefore mass-suppress intake across customers.
  - **Fleet key custody.** Who holds the fleet signing key is unspecified. The agent's egress path (tor or clearnet) is also unspecified, although it pulls every 60 ± 30 min.
  - **Vendor mirrors.** Desk (06 flow matrix: TCP 443) and Z-CORE (33 §14) contact vendor HTTPS mirrors, so the vendor or its CDN learns customer egress IPs, Desk start times (RVW-C-02) and, for CE users, *that an organization runs a whistleblowing system*.
  - **Support.** Support bundles are well designed (32 §8). The EE "internal support recipient" option lets corporate helpdesk (IT) receive Desk diagnostic bundles.
- **AFFECTED:** 21 E12, §9, ENT-008, ENT-036..040; 24 BIZ-007/009; 33 §14–15, UPD-011; 06 §flow matrix; 32 §8; THR-025, THR-027, THR-032, THR-036.
- **WHY NOT PREVENTED:** "Tighten-only" is defined against confidentiality only. Availability and evidence preservation are also source-protection properties (THR-020 suppression).
- **PROPOSED FIX:**
  1. **ENT-008:** replace "tighten-only" with an **explicit allow-list of fleet-settable keys** (update window, self-test schedule, telemetry off). All other keys are local-only. Specify that the fleet signing key is **customer-held** (K15-class token) even when the Fleet Manager runs at the vendor. Specify that agent egress goes over tor to a vendor onion collector, or to a customer-hosted Fleet Manager.
  2. **33 §15 / 06:** Desk and Z-CORE SHALL fetch updates via tor or an enterprise mirror (UPD-011 rules). The vendor clearnet mirror becomes ADVANCED.
  3. **32 §8:** Desk diagnostic bundles SHALL be encrypted only to the vendor key or an OVERSIGHT-designated key, never to corporate helpdesk on independent channels.
- **RESIDUAL RISK:** Vendor compulsion to *withhold* security updates remains. ENT-040's local update-lag alert mitigates it.

### RVW-C-14 — Records, FOIA/ATIP, DSAR, eDiscovery and breach scoping need cross-case search that does not exist
- **SEVERITY:** HIGH for GOV and regulated enterprise procurement.
- **SCENARIO:** A federal IG receives:
  - a FOIA request ("all hotline records mentioning contractor X");
  - a Privacy Act access request from an accused employee;
  - a litigation preservation demand;
  - a GDPR Art 15 DSAR (EU affiliate);
  - a breach event (PB-05) requiring Art 33/34 notification of **persons concerned** (the accused and witnesses are data subjects too).
  Each requires locating personal data **across all cases**. By design there is no global read (AUTHZ-006), RECORDS_OFFICER has no content (15 §5.1), servers hold ciphertext only, and the Desk search index is an open issue (12 OI-12-5). The agency must ask every case team to search its cases by hand, with no completeness evidence. Separately, the Federal Records Act prohibits unauthorized destruction (44 USC 3106 [K]): a lost last device (DR-P6, RVW-C-03), DC-12 "abandon un-imported envelope" or source-initiated deletion are each potentially reportable unauthorized destruction of federal records. The no-escrow default (ADR-013) therefore conflicts with federal records custody.
- **AFFECTED:** ADR-013, ADR-015, AUTHZ-006, 15 §5.1 RECORDS_OFFICER; 22 §7, GOV-008/009/020; 25 §4.3 (Art 15, 33/34), §6 records rows, COMP-010, COMP-016; 35 §10, RET-010; 31 §8 (Art 34 only for sources); 12 OI-12-5.
- **WHY NOT PREVENTED:** Records and FOIA are handled as *tagging and disposition* features. The *discovery/search* obligation and the *custody* obligation were not analyzed against endpoint-only keys.
- **PROPOSED FIX:**
  1. **New 35 §"Discoverability"**: specify a **federated search protocol**. A RECORDS/FOIA officer submits a signed query (terms and persons), and every case member Desk (or an OVERSIGHT-designated "records search Desk" holding SILENT_MEMBER wraps per 14 §9.4) executes it locally against its encrypted index and returns signed hit/no-hit attestations per case (content-free), with completeness tracked (cases × responses). Audited CASE events.
  2. **ADR-013 amendment for GOV:** records-scheduled deployments SHALL enable a **Records Custody Quorum**, a k-of-n key held by the records officer, the IG counsel and an external party, disclosed to sources as recovery escrow per ADR-013. Otherwise an explicit written determination by the agency's records officer and NARA liaison accepting the device-loss risk SHALL be recorded (GOV-028).
  3. **31 §8 / 25 §4.3:** add a procedure for scoping Art 33/34 notifications to persons concerned, performed by case members, with timelines compatible with 72 h.
  4. **22 §7:** DC-12 abandonment and source-initiated deletion SHALL be mapped to a disposition authority or blocked in records-scheduled channels.
- **RESIDUAL RISK:** Every escrow-like mechanism added for records law is a new compellable key. Sources must be told.

### RVW-C-15 — FIPS / FedRAMP / CJIS boundary gaps
- **SEVERITY:** MEDIUM (procurement blocker for federal and CJIS use).
- **SCENARIO:** The federal ISSO writes the SSP:
  - **Tier W.** Complaint plaintext (possibly CJI/CUI) crosses Tor, which uses non-validated crypto, into C-06 before FIPS encryption. 22 §8 admits this and pushes it to "Tier V FIPS Source App", but Tier W remains enabled by default in GOV (22 §4 "Tier W and Tier V").
  - **Staff path.** RCP-ONION (the default in CE and MANAGED, "allowed everywhere", 17 §4.6) carries Desk-API traffic over Tor. The HPKE layer protects content, but session tokens, metadata and the CJIS "data in transit" requirement apply to the channel.
  - **FedRAMP 20x (MANAGED only).** The Tor network is an external interconnection that the CSP cannot authorize. Continuous-monitoring expectations (AU-2/AU-12 event logging of all access, SI-4 system monitoring, IR-6 reporting with indicators) collide with the logging suppression of ADR-016.
  - **Authenticators.** The FIPS 140-3 authenticator catalogue is open (OI-15-1). WebAuthn PRF/hmac-secret use for key wrapping is outside most authenticators' validated security policy.
  - **Key privacy.** ADR-033(1) anonymous slots rely on "KEM key-privacy of X-Wing/ML-KEM", while the FIPS suite uses MLKEM1024-P384. The key-privacy assumption for that hybrid is not recorded in 40.
- **AFFECTED:** ADR-004, ADR-006, ADR-033(1); 22 §4, §8, GOV-011, GOV-018; 21 E08; 25 §5.2 (SC-8, SC-13, AU-*), §5.6; 15 OI-15-1; 17 §4.6.
- **WHY NOT PREVENTED:** The FIPS scope statement is written for *content confidentiality*. Accreditors assess *all* crypto protecting CUI/CJI in transit and the monitoring controls.
- **PROPOSED FIX:**
  1. **22 §4:** in CJIS or FIPS-mandated GOV deployments, `intake.tier_w.enabled=false` SHALL be the SAFE DEFAULT. Tier W becomes ADVANCED with an agency determination recorded (GOV-011).
  2. RCP-ONION SHALL NOT be used in FIPS-mandated deployments (RCP-LAN with FIPS TLS only), or it SHALL be wrapped in an inner FIPS mTLS session. Specify which.
  3. **25:** publish an SSP-ready "boundary and inherited-risk" annex: Tor as an anonymity overlay outside the boundary; mapping of AU/SI controls to C-24/C-25 alternatives; the IR-6 indicator policy (IPs never exist).
  4. **40:** add an ASM for the key privacy of MLKEM1024-P384 HPKE (or use pure ML-KEM-1024 slots in FIPS).
  5. Close OI-15-1 with a named, maintained list.
- **RESIDUAL RISK:** Some authorizing officials will not accept any Tor dependency. That is a market limit, not a fixable defect.

### RVW-C-16 — Section 508 / EN 301 549 blockers
- **SEVERITY:** MEDIUM (a procurement gate for federal, ADA Title II and EU public bodies).
- **SCENARIO:**
  - A blind investigator cannot read attachments: CL-3 viewing streams **pixels** from the C-17 microVM (12 OI-12-1, 06 TB8), which host screen readers cannot access. Only redacted, OCR'd Export Packages are text-accessible (A11Y-023, "partial conformance").
  - Staff with motor impairments must touch FIDO2 keys for every step-up (15 §4.7: exports, approvals, key ops), and have 60 s per assertion.
  - Linux Desk accessibility (WebKitGTK/Orca) is flagged as immature (12 §14 item 6).
  - VDI, the standard accommodation route in many agencies, is unresolved (OI-15-2).
  - Sources face a 10-word **English** passphrase (26 §residual 3) and Tor Browser with assistive technology (Knowledge (unverified): Tor Browser accessibility-service support varies by platform and version).
- **AFFECTED:** 12 §10, RUI-047; 26 A11Y-012, A11Y-023, §7 matrix; 15 §4.7, AUTH-018; 22 GOV-024; 25 COMP-020.
- **WHY NOT PREVENTED:** Accessibility was verified per screen, not per *task under containment*.
- **PROPOSED FIX:**
  1. **10/12:** C-17 SHALL produce an accessible text rendition inside the sandbox (OCR plus structure) delivered to the Desk as a sanitized derivative. That is the same trust as the existing derivative pipeline, and it is screen-reader navigable.
  2. **15 §4.7:** allow a per-user audited accommodation: PIV + PIN via reader, or platform authenticator with UV, with longer (180 s) windows.
  3. **26:** localized passphrase wordlists (per-locale EFF-style lists with the same entropy), listed as an open issue now.
  4. Publish the Tor Browser + AT test results per release.
- **RESIDUAL RISK:** Partial conformance for rasterized originals remains and must be declared in the ACR.

### RVW-C-17 — Operational burden is unrealistic for municipalities; kernel updates vs. offline UKI signing
- **SEVERITY:** MEDIUM.
- **SCENARIO:** A 3,000-inhabitant municipality (EU Art 8(9) threshold area, US ADA Title II) with one part-time IT contractor runs CE-HARDENED as recommended (22 §5.3). It must operate:
  - 2 FIDO2 keys per person;
  - K01 3-of-5 shares, K15 key-admin tokens, IRK 2-of-3 and IRK-S (separate custodians "SHOULD"), IEK 2-of-3 and the optional Recovery Quorum;
  - off-site Tang with yearly rotation and FDE rebinding;
  - quarterly two-person seal inspections with photo comparison;
  - weekly offline disk rotation with two-person transport;
  - quarterly RT-1 with IRK custodians;
  - yearly RT-3/RT-4;
  - a standby onion key and a yearly rotation drill;
  - quarterly tabletops;
  - weekly Desk opening by each recipient;
  - an air-gapped ceremony laptop "with radios physically removed" for GOV.
  18 §4.1 claims "2 h/week" and "no Linux expertise". There is also a direct contradiction: 17 §6.2 requires UKIs "signed with the site's MOK/db key ... kept on a hardware token in Z-ADM and **not** on the server", with LUKS unseal bound to a signed PCR 11 policy. 23 §4.2 promises "security releases apply within 24 h, unattended". Every Debian kernel or initrd security update therefore needs a human with the hardware token, or the reboot falls back to a recovery prompt. Either the municipality runs unpatched kernels, or the signing key ends up on the server.
- **AFFECTED:** 17 §6.2, §6.3, §6.4, PHYS-003/004/006/011; 18 §4.1, §4.2, §8, DEP-010/011; 19 §7, §8; 23 §4.2, SMB-004/010; 31 IR-029; 32 §9; 22 §3 "IT capacity: Low".
- **WHY NOT PREVENTED:** Each document added reasonable controls. Nobody summed them per profile against the staffing assumption.
- **PROPOSED FIX:**
  1. **18:** a normative **Operational Load Budget** table per profile: person-hours per month, distinct persons, tokens and ceremonies. Test it in the SMB-010 usability study, extended to a 6-month operational pilot.
  2. **17 §6.2:** specify the Candor-built UKI signing chain. The vendor signs generic UKIs (threshold, reproducible, via TUF) and the site enrolls the vendor PCR-11 policy key. A site-local MOK becomes ADVANCED for HIGH/GOV only. This resolves the unattended-update contradiction.
  3. **22 §5.3:** make "MANAGED by an independent operator" or a consortium-run instance the **recommended** municipal path, with CE-HARDENED self-operation requiring a named competent operator.
  4. Merge IRK/IEK/K15 custody into a single "custodian pack" per person to cut token count, while keeping k-of-n.
- **RESIDUAL RISK:** Outsourcing moves trust to the operator (see RVW-C-21).

### RVW-C-18 — Legal SLA and channel-availability risks
- **SEVERITY:** MEDIUM.
- **SCENARIO:**
  1. **COI exhaustion.** A two-member SMB channel; the source ticks both roles ("my report concerns the owner and the HR lead"). ARCH-037 fails closed with "temporarily unavailable ... try again later". The source retries for days, gives up, or goes to a less safe channel. The organization is in breach of EU Art 8/9 (channel availability) without knowing it.
  2. **Epoch runway.** Summer holidays: both recipients offline for more than 3 weeks. MEK runway reaches 0 and the channel closes (F5; `min_recipients` default 1).
  3. **Source-account RPO.** DR-P1 says "Accounts created after the last BS-INTAKE are lost (notice advises re-registration)". BS-INTAKE is nightly even in EE-ONPREM (intake RPO 24 h, 19 §10). Those sources lose their mailbox, so the 3-month feedback obligation (Art 9(1)(f)) cannot be met for them, and they cannot be told why.
  Positive note: the 7-day acknowledgement *is* achievable independent of staff, thanks to auto-ack at intake (14 §6.4, CASE-008).
- **AFFECTED:** ADR-030, ARCH-037/039, 34 F5, FAIL-005, 32 §7 `intake.min_recipients`, 19 §10/§11 DR-P1, 25 §4.2 Art 9(1)(f), 14 §6.4.
- **WHY NOT PREVENTED:** Fail-closed is correct for confidentiality, but the source-facing message and the organization-facing obligation were not designed.
- **PROPOSED FIX:**
  1. **11/06:** when the COI filter leaves fewer than `min_recipients`, show a *specific* message: "Your selection excludes everyone who receives reports on this channel. Please use channel <independent channel> (listed)." Channels SHALL have a mandatory `independent_route` fallback channel (ROUTE-*) that is itself never fully excludable. Record a content-free SECURITY counter `intake.coi_exhausted` (k-thresholded) so the organization learns of the structural gap.
  2. **32/23:** SMB requires ≥ 1 external recipient (ombuds/counsel) on every ANONYMOUS channel.
  3. **19:** EE BS-INTAKE every 1 h (padded, fixed cadence) or an intake-side replica in EE-ONPREM. Retain account records in a dedicated short-retention set.
  4. **ARCH-039:** raise channel runway alerts to OVERSIGHT at 14 days, not only to the Channel Owner.
- **RESIDUAL RISK:** Very small organizations may have no one to route to independently.

### RVW-C-19 — DR key-custody logistics: quorums within RTO, co-located key holders
- **SEVERITY:** MEDIUM.
- **SCENARIO:**
  - EE-HA DR requires: DR declaration by dual approval (HA-008), BS-SECRETS restore under the IRK-S quorum (3-of-5 EE), BS-CORE/BS-ERASURE restore under the IRK quorum, and HSM partition restoration (M-of-N) at the DR site. The DR RTO is 4 h (21 §5.2), and a Saturday-night fire needs 3 custodians with tokens and the offline media at the DR site within hours. Nothing requires custodian geographic dispersion, deputies, or quorum reachability tests.
  - Recipients' workstations (the only holders of MEKs and case-key access) sit in the same building as the primary servers. A site loss destroys servers **and** every key holder's device. The servers are restored with nothing able to decrypt them (DR-P6).
  - EE-HA intake failover is "≤ 10 min" in 21 and 18, but "≤ 15 min" in 19 §10.
- **AFFECTED:** 19 §4, §10, §11 DR-P3, RT-4; 21 §5.2, HA-007/HA-008/HA-015; 18 §4.4; 04 §9.4; ADR-013.
- **WHY NOT PREVENTED:** Server-centric DR design. Key-holder availability is not modeled as part of RTO.
- **PROPOSED FIX:**
  1. **19:** add a "Key-holder continuity" section: minimum geographic split of custodians and case-key holders (at least one holder of every case outside the primary site); named deputies; a quarterly quorum-reachability drill (time to assemble k custodians) recorded as a SYSTEM event. RT-4 SHALL measure it.
  2. **14/15:** a check `case.key_holder_site_diversity` (WARN if all holders of a case map to the same `site` attribute).
  3. Reconcile the intake RTO values.
- **RESIDUAL RISK:** Dispersing custodians increases coercion targets.

### RVW-C-20 — Enterprise network team as a two-ended observer
- **SEVERITY:** MEDIUM.
- **SCENARIO:**
  - EE-ONPREM places the physical H-INTAKE in the corporate data center. INFRA-025 makes uplink independence a SHOULD, waivable by a **single** admin's ADVANCED acknowledgement (32 §7 `site.uplink_independent`). The corporate NOC then sees every Tor OR connection of the intake with byte counts, and the same NOC sees employees' Tor use and corporate-VPN split-tunnel traffic. That is exactly the two-ended correlation position (THR-003) that 17 §7 calls "the strongest argument for self-hosted intake", except here the organization is both ends.
  - RCP-LAN (the default for EE, GOV and PRIVATE-CLOUD, DEP-032) gives the same NOC staff activity. INFRA-009's "SHALL be excluded from per-flow logging" is organizational and unverifiable.
  - C-37 (the Clearnet Information Site) is typically on the corporate CMS/WAF/intranet with SSO cookies. The corporate proxy logs who read the whistleblowing guidance. NET-025 forbids only *third-party* TLS termination.
- **AFFECTED:** 17 §4.6, §4.10, INFRA-009, INFRA-025; 18 §3, DEP-032; 32 §7; 16 NET-025; 03 §access table ("C-37: no logs unless a CDN is used").
- **WHY NOT PREVENTED:** These controls are SHOULDs or single-admin acknowledgements, and the observers are first-party.
- **PROPOSED FIX:**
  1. **INFRA-025:** for D1/D2 tenants and GOV-IG/IA, a non-independent uplink SHALL be DANGEROUS (DC-09 plus OVERSIGHT approval) and disclosed to sources.
  2. **DEP-032:** RCP-ONION SHALL be the default for independent channels in every profile (or RCP-LAN over a dedicated WireGuard terminated on H-CORE, so flows are encrypted end-to-end from the endpoint and the NOC sees one constant tunnel), with keepalive padding.
  3. **16 §11.3:** C-37 SHALL be hosted outside the organization's web stack for D1/D2 tenants (static host with no access logs, attested). A "not linked from the intranet with tracking" check becomes part of the quarterly C-37 review (OPS-012).
- **RESIDUAL RISK:** Sources using corporate networks remain exposed. Guidance only.

### RVW-C-21 — MANAGED hosting: vendor root on intake, vendor-operated audit, Tier V optional
- **SEVERITY:** MEDIUM.
- **SCENARIO:** A municipality follows 22 §5.3 and buys MANAGED. The vendor holds the onion keys and root on the dedicated intake (18 §4.8). A compelled vendor under a gag order (INC-07) modifies the intake to capture Tier W plaintext and passphrases. The "customer-visible access log" (ENT-026) and the vendor HSM partition are operated by the same vendor. The compelled-disclosure inventory (ENT-025) lists stored data, not live capture capability. Tier W is enabled by default.
- **AFFECTED:** ADR-004, ADR-021, ADR-024 (MANAGED); 18 §4.8, DEP-027..029; 21 E05, ENT-021, ENT-025, ENT-026; THR-026, THR-027.
- **WHY NOT PREVENTED:** Attestation (INFRA-018) is verified by H-MON, which in MANAGED is also vendor-run. The customer has no independent verifier.
- **PROPOSED FIX:**
  1. **18 §4.8:** MANAGED SHALL offer a **customer-held attestation verifier**. The customer's own Desk or a small appliance verifies TPM quotes of the vendor-hosted intake against public golden values (reproducible UKIs), and Desks block on mismatch (extend RUI-057 to intake attestation).
  2. The access log SHALL be anchored to a customer-controlled witness (20 external witness) within 15 min.
  3. For D1–D7 tenants on MANAGED, `intake.tier_w.enabled=false` SHALL be the default.
  4. ENT-025's inventory SHALL include "live capabilities" (Tier W capture, onion impersonation).
- **RESIDUAL RISK:** Hardware-level compelled capture at the vendor remains possible.

### RVW-C-22 — IR playbook gaps
- **SEVERITY:** MEDIUM.
- **SCENARIO:** The 14 playbooks (31 §9) lack:
  - (a) **Organization-as-adversary**: who runs IR when leadership is implicated? 31 §4 roles are all internal, and PB-06 assumes a "break-glass admin set" that is undefined in 15.
  - (b) **IdP/SCIM/SOAR compromise** (mass deactivation, attribute poisoning: RVW-C-03).
  - (c) **Mass key loss / suppression**: all holders' devices lost or reimaged.
  - (d) **Rogue roster or orphan re-key** detected by KEY-028 (RVW-C-05). PB-02 mentions directory monitors only in passing.
  - (e) **Desk distribution tampering** by local MDM (PB-09 covers vendor releases only).
  - (f) **Notification-transport or SIEM-sink compromise.**
  - (g) **Breach notification to persons concerned** (31 §8 covers sources only).
  Small organizations also cannot staff IR Lead + DPO + Legal + 2 Platform Admins + Channel Owner + Oversight.
- **AFFECTED:** 31 §4, §8, §9, IR-001, IR-003; 15 (no break-glass admin definition); 25 §4.3 Art 33/34.
- **WHY NOT PREVENTED:** The playbooks were derived from the threat catalogue (THR-*), not from the insider-integration scenarios in this review.
- **PROPOSED FIX:** Add PB-15 "Organizational suppression / mass key loss", PB-16 "IdP/SCIM/SOAR compromise", PB-17 "Unauthorized roster change / orphan re-key", PB-18 "Recipient endpoint tampering by the organization (MDM/EDR)" and PB-19 "Leadership-implicated incident" (IR run by OVERSIGHT with an external retained IR firm under a pre-signed engagement letter). Define the "break-glass admin set" in 15 §5.1 as a named role (`EMERGENCY_ADMIN`, held by OVERSIGHT-appointed persons, hardware tokens sealed in a two-person safe). Add an SMB IR minimal-roles annex.
- **RESIDUAL RISK:** Playbooks do not create independence where none exists.

### RVW-C-23 — Tenant Risk Classification is self-assessed by the party it guards against
- **SEVERITY:** MEDIUM.
- **SCENARIO:** A group's IT runs a shared EE instance for 40 subsidiaries. At onboarding the group itself completes the Tenant Risk Classification (21 §6.3) and answers D2 ("the operator or group is a plausible subject of reports") with "no" for every subsidiary. Subsidiary audit-committee channels, where group management is in scope, land on the group-operated shared instance. That shared instance hosts only per-tenant intake processes on a shared host (TEN-001, TEN-008), and its admins are group IT.
- **AFFECTED:** ADR-021; 21 §6.3, TEN-005, TEN-012; 22 GOV-002; THR-020, THR-045.
- **WHY NOT PREVENTED:** TEN-005 verifies that a classification *exists* ("INSP; onboarding workflow blocks on trigger"), not *who* made it.
- **PROPOSED FIX:** **TEN-005 amended:** the classification SHALL be signed by the tenant's own OVERSIGHT (audit-committee chair or ombudsperson), not by the group operator, and shown on the tenant landing page (TEN-012) together with "operated by <group>". D2 SHALL default to "yes" for any audit-committee, board or ethics channel.
- **RESIDUAL RISK:** The tenant's oversight body may itself be captured.

### RVW-C-24 — EE licence expiry semantics are undefined for HA orchestration and the SSO bridge
- **SEVERITY:** LOW.
- **SCENARIO:** An EE licence lapses during procurement renewal. BIZ-007 says expiry "SHALL NOT disable intake, decryption or case access", and 24 §3 says EE modules "degrade to read-only administration". It is unspecified whether the HA orchestration module (class S) still fences and promotes, and whether an SSO-first-factor tenant can still log in. A lapsed licence could turn a routine node failure into split-brain (HA-001) or into a staff lockout.
- **AFFECTED:** 24 BIZ-007, §3; 21 E09, E10, E26; HA-001.
- **WHY NOT PREVENTED:** "Read-only administration" does not map onto automated availability functions.
- **PROPOSED FIX:** **BIZ-007:** safety-relevant automation (fencing, failover, SSO bridge login, SIEM export) SHALL keep full function after expiry. Only configuration changes are frozen. Add a TST "expired licence + node failure".
- **RESIDUAL RISK:** Negligible.

---

## Things the design gets right

1. **No server-side content key, enforced cryptographically.** ADR-007, ADR-015 and AUTHZ-002/003 make "admin ≠ case access" a key-possession fact, not a policy. The DB-superuser test (15 §6) is the right acceptance test.
2. **Per-member epoch keys with anonymous slots** (ADR-030, ADR-033(1)) turn COI exclusion into cryptography and hide *who* was excluded from DB thieves. This is a genuine advance over GlobaLeaks, SecureDrop and commercial hotlines.
3. **The IdP can never unlock keys or grant access** (AUTH-011/012, ENT-015/016). A compromised Entra tenant yields at most DoS. This is exactly what an enterprise reviewer wants to see, though see RVW-C-03 for the DoS consequences.
4. **Integrations only via human-created Export Packages** (ADR-018), with a SIEM allow-list implemented in AGPL trust-path code *before* EE modules see events (21 E28) and canary testing (ENT-018).
5. **Honest Tier W statement** (ADR-004) and provider-observer disclosure (17 §7, INFRA-023). The hosting-provider metadata table is the best I have seen in a vendor spec.
6. **The configuration checker blocks intake on dangerous drift** (DEP-025, F13, `tor.config_hash`, DB-021 `log_statement=none`, volatile intake journald). A careless admin cannot silently turn on tor debug logs or SQL statement logging; it needs dual approval with auto-revert (32 §7).
7. **Secret Placement Manifests with continuous verification** (ADR-028) fix the SecureDrop GHSA-rqwh class generically.
8. **Backups add no decryption capability** (19 §4 invariants) and are padded, fixed-cadence and WORM. Legal hold is correctly *not* implemented by extending backup retention (BAK-020).
9. **Auto-acknowledgement at intake** (14 §6.4) makes the EU 7-day acknowledgement independent of staff, and the dead-man canary with OVERSIGHT-side independent evaluation (CASE-019) is a strong anti-suppression design.
10. **Fleet Manager without an onion-address database** (21 §9.2, ENT-036), offline licences with no phone-home (BIZ-007/009), identical updates for all customers (ADR-022), and a public LTS source (ENT-031).
11. **Edition Charter test** (21 §3) keeps source-protecting features (COI routing, legal hold, break-glass, Sealed Identity Store) in CE.
12. **HA observer inventory** (21 §5.4, 34 §7) and the list of prohibited HA mechanisms (no L7 on the source path, no cross-site sync intake replication) show the right instinct. Availability is openly traded against exposure.
13. **IR notification only through platform channels** (31 §7, IR-012), and "do not build a who-is-the-source hypothesis" (PB-01) are correct and rare.
14. **Records vs. minimization conflict is surfaced**, not hidden (22 §7, 25 §10), and "Candor never claims compliance" (COMP-001).

## Recommended priority for the next spec round

1. ADR-034 recipient-endpoint custody plus server-verified Desk attestation (RVW-C-01).
2. Constant-rate notifications and day-granular SIEM staff events (RVW-C-02).
3. Replace "remove-only is safe" with suspend-then-approve; multi-device; `min_recipients=2` (RVW-C-03).
4. Independent approvers for IR captures, break-glass, governance keys and TRC (RVW-C-04, 05, 10, 23).
5. Erasure Key Vault DR re-specification and hypervisor-backup exclusion (RVW-C-06, 07).
6. Consistency ADR (RVW-C-08) and the GOV records-custody decision (RVW-C-14).
