# REVIEW-A — Adversarial Design Review of the Candor Specification Set

Reviewer: A (defensive architecture review)
Date: 2026-09-30
Baseline reviewed: `specs/DECISIONS.md` (ADR-001..033) and specs 00–40 (selective, see §1)
Finding prefix: `RVW-A-nn` (REVIEW-REPORT owns the `RVW-` prefix per DECISIONS §3)

---

## 1. Scope, method and adversary

**Adversary.** The strongest adversary in the Candor threat model: a well-resourced state actor (ADV-17/18/19/20/26) that has (a) network visibility at the source's ISP/employer and at the intake host's hosting provider/uplink, including long-term traffic recording; (b) the power to compel, covertly and under gag, the operator (the organisation running Candor), the vendor (EE/MANAGED), hosting providers, app stores and individual key holders; (c) supply-chain reach (upstream packages, distribution infrastructure, one jurisdiction's worth of signers/builders). Where relevant, the review also considers the organisation's own corporate-security function (ADV-07) and an accused executive with administrative influence (ADV-06), because in whistleblowing the operator and the adversary are frequently the same organisation.

**Method.** Full read of DECISIONS.md; targeted read of 02 (§6, §9, §12), 03 (§8, §9, §10), 04 (§9–§15, §24–§28), 06 (§6, §8, §9, §16–17), 07, 08 (§3, §4), 09 (§5.1, §8–§10), 10, 11 (§4–§8, §13, §15–16), 12 (§5–§7), 16 (§7–§17), 17 (selected), 19 (selected), 28 (§5, §14), 33 (§3–§21), plus grep across all documents for cross-references. This is a document review: findings describe design weaknesses and specification changes, not procedures.

**Output format.** Each finding: TITLE, SEVERITY, SCENARIO, AFFECTED, WHY THE CURRENT SPEC DOES NOT PREVENT IT, PROPOSED FIX, RESIDUAL RISK.

**Severity scale.** *Critical*: the design gives false assurance on a core source-protection property against the in-scope adversary, at scale. *High*: realistic path to source identification, content exposure or undetected compromise for a targeted source, or a binding-document conflict on a trust-path rule. *Medium*: narrows the anonymity set, weakens detection, or requires additional preconditions. *Low*: minor leakage or hygiene.

### Summary table

| ID | Title | Severity |
|---|---|---|
| RVW-A-01 | Tier W compromise detection relies on controls that are not specified anywhere | **Critical** |
| RVW-A-02 | Three incompatible draft/session models; 11 §5.6 persists passphrase, identity block and hour-granular timers on disk | High |
| RVW-A-03 | Tier W login hands a compromised intake the source's entire mailbox history, linkage and identity-of-accused | High |
| RVW-A-04 | Directory freeze/rollback plus Z-CORE-supplied intake clock lets sealing target stale rosters and removed members | High |
| RVW-A-05 | Roster, COI_POLICY and role-label changes can be driven by a CIK-holding (possibly accused) member plus one key-admin, with immediate effect | High |
| RVW-A-06 | Follow-ups are sealed to the *current* roster, silently including members added after the source's original report | High |
| RVW-A-07 | Tier W draft parts are sealed before the final recipient set is known | High |
| RVW-A-08 | Tier V trust anchors are TOFU per session and witnesses are optional/same-organisation | High |
| RVW-A-09 | Case DB WAL archive, backups and blob-store object metadata persist import time ≈ submission time ± 25 min | High |
| RVW-A-10 | Operator can prospectively log return-visit times for a specific case's mailbox (Tier V and W) | High |
| RVW-A-11 | Harvest-now-decrypt-later of Tier W plaintext and permanent passphrases on classical onion circuits | High |
| RVW-A-12 | OS, tor and database packages on the intake host bypass TUF, transparency and reproducibility | High |
| RVW-A-13 | No externally verifiable per-instance uniformity; Fleet policy and operator control allow selective withholding or divergence | High |
| RVW-A-14 | Source App acquisition leaves compellable identity-linked records (app stores, clearnet downloads) | High |
| RVW-A-15 | Hostile-attachment containment undefined on Windows/macOS; host-side decoding and webview rendering of hostile strings | High |
| RVW-A-16 | Release path: emergency 0-hour cooling, signer/builder jurisdiction concentration, single-key bootstrap | Medium |
| RVW-A-17 | Tier W sources cannot verify the key directory, but the UI presents verification affordances | Medium |
| RVW-A-18 | Anonymous-slot COI confidentiality ends at import and is observable by excluded members | Medium |
| RVW-A-19 | Event-driven notifications give mail providers and corporate IT an hour-level submission-timing oracle | Medium |
| RVW-A-20 | Undecryptable envelopes pin Member Epoch Keys indefinitely (forward-secrecy erosion, escalation flooding) | Medium |
| RVW-A-21 | Response size classes, CSP and sub-resource rules differ between 03, 08 and 11 | Medium |
| RVW-A-22 | Unpadded Tier W uploads give the intake hosting provider exact volume/time per upload | Medium |
| RVW-A-23 | Intake egress/time/logging inconsistencies (monitor push vs nftables, chrony from core, tor log retention, C-37 CDN) | Medium |
| RVW-A-24 | Recipient endpoints managed by the investigated organisation (EDR/MDM/cloud AV) defeat Desk-side protections | Medium |
| RVW-A-25 | Original-evidence exports carry live beacons and canary marks to downstream systems | Medium |
| RVW-A-26 | Residual database linkability (tier column, quota history, own-message history, 30-day header digest, identity-object presence) | Medium |
| RVW-A-27 | Global rate-limit and queue states are an activity oracle | Low |
| RVW-A-28 | Source-initiated deletion is not durable across intake disaster recovery | Low |
| RVW-A-29 | Public key-directory publication cadence reveals staff activity and investigative roster changes | Low |
| RVW-A-30 | Pixel channel is integrity-unchecked; a compromised converter VM can falsify evidence renderings | Low |

Counts: Critical 1 · High 14 · Medium 11 · Low 4 (30 findings).

---

## 2. Findings

### RVW-A-01 — Tier W compromise detection relies on controls that are not specified anywhere
- **SEVERITY:** Critical
- **SCENARIO:** A compelled operator (or a vendor in MANAGED) is ordered to modify C-06/C-07 to capture Tier W submissions and passphrases, possibly only for sessions matching a selector (e.g., a specific `lookup_tag`, channel, or COI tick). Tier W is the default tier (ADR-004), the one 05 GC-38 recommends to sources whose device might be searched, and the one most high-risk sources will therefore use. The threat model rates the residual as reduced because of "sealer attestation to Desk", "published source-UI digests checked by C-25 and Desk", and "warrant canary / transparency report policy". None of these controls is specified in the documents that the threat model cites.
- **AFFECTED:** 02 §6 ADV-04/ADV-18/ADV-19 mitigations, §7.3, §9.1 THR-007/THR-014 residual ratings, §12.2 rows C-05/C-06/C-07, OI-03; 03 §10.4 row "Capture Tier W plaintext"; 06 (no attestation section); 11 (no digest publication); 24/36 (no canary); 17 §5.6, INFRA-018; 04 K35; ADR-004, ADR-009.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:**
  1. 02 OI-03 itself admits that "sealer remote attestation to Desk" is not fixed by DECISIONS and was deferred to 06. 06 contains no attestation mechanism. The only attestation specified (17 INFRA-018) is TPM PCR quotes verified by H-MON against golden values. H-MON, the golden values and the verification are all under the operator's control, so they are useless against a compelled operator. By 17's own residual, PCRs also miss memory-only implants.
  2. "Published source-UI digests" are cited in 02 THR-007 as defined in 11, but 11 defines none. Tier W pages are also not digestable: they contain per-request CSRF tokens, random padding bytes (08 §3.8) and session-dependent content. A selector-based modification is invisible to any probe (C-25, Desk) that is not the targeted source.
  3. K35 (sealer signing key) lives TPM-sealed on the intake host. Any root-level modification can use it, so `sealer_sig` proves only that "the intake host" signed.
  4. VR-9 at import detects extra or foreign recipient slots. A sealer that simply copies plaintext out adds no slot, so VR-9 cannot see it.
  5. The warrant-canary or transparency-report "policy" cited in 02 ADV-18/ADV-20 is absent from 24 and 36. Only 03 PRIV-012 (MANAGED vendor transparency report) exists.
- **PROPOSED FIX:**
  1. Add an ADR "Sealer integrity evidence". Its purpose is to bound the Tier W residual honestly and to stop 02 from crediting non-existent controls:
     - (a) Profile HIGH/GOV/MANAGED SHALL run C-07 (and SHOULD run C-06) inside a confidential VM/enclave (SEV-SNP/TDX). The measurement SHALL be reproducibly built and listed as a TUF target.
     - (b) K35 SHALL be generated inside the TEE and bound to its measurement. The attestation report SHALL be logged in C-14 as a new `SEALER_ATTESTATION` entry, refreshed at least every epoch.
     - (c) Desk VR-9 SHALL reject Tier W envelopes whose `sealer_sig` key is not bound to a currently logged, release-matching measurement.
     - (d) Attestation reports SHALL be pulled by at least one verifier outside the operator's administrative domain: the independent route's own host, an external monitor, or both. The verifier SHALL publish pass/fail.
  2. Remove "published source-UI digests" from 02/03, or specify them only for the static routes (SW-01, SW-17, SW-18) with a fixed, logged byte-exact response. State that dynamic pages are not covered.
  3. Add a normative operator transparency requirement in 32/25: a signed periodic statement (canary) on C-37 and in C-14 (`OPERATOR_STATEMENT` entry, K01-signed, ≤ 30-day cadence). Its absence SHALL be surfaced by Desks and the Source App.
  4. Re-rate THR-007/THR-014 Tier W residuals in 02 after 1–3, and mark any mitigation not specified elsewhere as "PROPOSED" in 02.
  5. Make TM-012 ("channel requires Tier V") the default for channels whose category list includes executive/board subjects, and for all MANAGED high-risk tenants.
- **RESIDUAL RISK:** TEEs have side-channel and vendor-trust limits (THR-123), and a compelled TEE vendor is out of scope. Without TEE profiles, Tier W against a compelled operator remains protected only by honesty statements. That residual must be stated as such, not as "detectable".

### RVW-A-02 — Three incompatible draft/session models; 11 §5.6 persists passphrase, identity block and hour-granular timers on disk
- **SEVERITY:** High
- **SCENARIO:** An adversary later seizes, or covertly images, a running or recently running intake host (ADV-18, ADV-10, THR-031). The adversary also gains transient live access during a window in which a source still has the same Tor Browser session open. Under 11's model, the adversary obtains more than the other documents claim:
  - hour-granular draft expiry timestamps (i.e., the source's last activity to the hour);
  - AEAD-encrypted answers;
  - the CONFIDENTIAL identity block;
  - the generated passphrase (re-displayable for 60 min), all on C-08 disk and therefore in WAL, heap pages and possibly the nightly BS-INTAKE snapshot.
- **AFFECTED:**
  - RAM-only model: 03 R-02 header and F24 ("draft parts held only in C-07 RAM, ≤ 2 h"); 06 §6 (`candor-sealer`: "RAM-only drafts"), ARCH-007; 08 SW-05 ("no disk").
  - Ciphertext-parts-on-disk model: 06 §9.1 (`PUT_PART(draft, ciphertext)`); 07 `draft_gc` (≤ 3 h, generation counter, "no wall-clock time stored"); 09 `draft_part`.
  - Cookie-keyed persisted-draft model: 11 §5.6, SUI-008/009/011/012, S92 ("kept for 24 hours"), OI-11-6, ADR-revision note on ADR-005.
  - Timers: 03 META-014 / 07 / 08 (idle 20 min, absolute 2 h, cookie `__Host-cs`) vs 11 (idle 30 min, absolute 4 h, cookie `__Host-s`) vs 11 OI-11-6 ("5 min idle, 10 min absolute").
  - Key residency: 04 §11.5 ("zeroizes seed and keys before the response is sent") vs 07 §5 / 03 R-03 (derived keys held for the session) vs 11 (wrapped seed held 30 min/4 h).
  - ADR-005, ADR-010, 09 L3/L11 (the intake DB timestamp allow-list is empty, yet 11 stores an expiry at 1-hour granularity).
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** Each document is internally consistent, so implementers of C-06/C-07/C-08 will pick different models. 11 explicitly stores the passphrase and identity block in C-08, and an hour-granular expiry, contradicting ADR-010 (day granularity), ARCH-007 in spirit, PRD §7.8 ("never stored server-side") and the 09 schema lint. SUI-012 makes every error path (busy, rate limit, expiry) write source text to disk. 09's schema-lint (L11) would reject 11's expiry column, and nothing reconciles them. Longer session timers (4 h) extend how long derived source keys stay in C-07 RAM, which is exposed to hypervisor snapshots (THR-030).
- **PROPOSED FIX:** Add an ADR "Tier W draft and session state" that resolves in favour of the most restrictive model and amends 11:
  1. Draft *text* (answers, identity block, passphrase) SHALL live only in C-07 mlocked RAM, keyed by the session handle. It SHALL never be persisted, including on error paths. SUI-012 becomes "preserve in RAM for the remaining session lifetime".
  2. Draft *attachment parts* MAY be written to C-08 only as sealed ciphertext under a per-draft key held only in C-07 RAM (not derived from a client cookie). They are destroyed on commit, discard, sealer restart or ≤ 2 h via the generation counter (07). No per-draft time value is stored.
  3. Single timer set: idle 20 min, absolute 2 h, one cookie name. Derived source keys zeroized per 04 §11.5 after each request. Replies are rendered in the same request as login, and subsequent inbox views re-derive or show cached rendered text only.
  4. WCAG 2.2.1 is satisfied through the "extend" control (already specified) and the "essential/security exception", recorded as an accessibility decision in 26. The 20-hour server-side draft is removed.
  5. The passphrase is re-displayable only within the same session and from RAM (≤ 10 min). Amend ADR-005 wording accordingly.
  6. Add an AT test that images C-08 disk (heap, WAL, blob dir, BS-INTAKE snapshot) after a draft/abandon/error flow and asserts no draft text ciphertext, identity ciphertext or sub-day timestamp.
- **RESIDUAL RISK:** Sources lose drafts when the sealer restarts or after 2 h. This is an accepted usability cost, and it must be stated on S04/S06.

### RVW-A-03 — Tier W login hands a compromised intake the source's entire mailbox history, linkage and identity-of-accused
- **SEVERITY:** High
- **SCENARIO:** During a covert compromise window, a Tier W source logs in to check for replies. The passphrase transits C-06/C-07. From it, the adversary derives `seed`, and with it:
  - all stored replies, up to 90 days at intake plus 14-day BS-INTAKE backups;
  - every `mailbox_id[i]`, which links all reports filed under the same passphrase;
  - `sign_sk`, which allows follow-ups that recipients will accept as authentic;
  - `prefs_ct`, i.e., which roles the source said the report concerns (a strong content and identity hint);
  - the ability to delete the mailbox or to monitor it indefinitely afterwards (the passphrase never rotates).
  The honesty statement tells sources only that "what you submit" could be read.
- **AFFECTED:** ADR-004 honest statement, ADR-005; 03 §10.2 (claims "past report plaintext: No"); 04 §11.3–11.6, §15.3 ("Replies to sources: no FS"), §27 #1/#15; 07 `LOAD_PREFS`; 09 `reply` retention; 19 BS-INTAKE; 02 §12.2 C-06 recovery ("recommend Tier W sources who logged in during window close mailbox").
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** Source keys are a deterministic function of a permanent passphrase. Tier W login necessarily reveals the passphrase to the server. The consequence is documented in fragments (04 §27) but not in the source-facing statement, and it is not bounded in time. The only recovery step (the notice "close mailbox and resubmit") depends on the operator, who may be gagged.
- **PROPOSED FIX:**
  1. Amend the ADR-004 Tier W statement (11 S03, 05 GC-01) to: "A live-compromised intake server could read what you submit **and, when you sign in, your replies and your passphrase**. Anyone with your passphrase can read future replies and write as you."
  2. Add **per-login key rotation for Tier W**: at each successful login, C-07 offers "rotate passphrase" (new seed, new `auth_pk`, re-encryption of pending replies to the new `src_pk` inside C-07). The source's new public key is delivered to the case in an authenticated SOURCE_MESSAGE, so that a passphrase captured earlier stops working. Default ON for HIGH profile. (C-07 sees both passphrases, so this bounds *past* captures, not a live one.)
  3. Reply minimisation: default `intake.reply_retention_days` = 30. A "delete after reading" default for Tier W (deletion on the next login after first display, source-controlled). Exclude replies from BS-INTAKE (the core is the source of truth, 19 DR-P1).
  4. Store the COI selection in `prefs_ct` only if the source opts in to re-use on follow-ups. Otherwise re-ask at follow-up time.
  5. Specify a gag-resistant source notice: the RVW-A-01 canary and a C-14 `INCIDENT_NOTICE` entry type, which Tier V clients and Desks surface.
- **RESIDUAL RISK:** A live compromise still captures everything that transits during the window. Tier V remains the only content-protecting path.

### RVW-A-04 — Directory freeze/rollback plus Z-CORE-supplied intake clock lets sealing target stale rosters and removed members
- **SEVERITY:** High
- **SCENARIO:** An adversary controls Z-CORE, for example a compelled administrator or a compromised core host. It wants new Tier W submissions to remain readable by a member who was just removed from a channel: an accused person's ally, a departed investigator, or a member whose device was compromised. It keeps pushing the last snapshot that still lists that member and keeps the intake clock from advancing past the freshness bound. The intake keeps sealing to the removed member's still-valid MEKs, and the removed member keeps those private keys (04 §27 #6). For Tier V, the server can keep serving the pre-removal snapshot for up to 72 h.
- **AFFECTED:** ADR-009 (C-09 pushes snapshots), 16 §14.2 ("host time from authenticated timestamps supplied by C-09 … chrony SOCK refclock"); 04 §12.1 step 2 (clock cross-checked only against the checkpoint, which also comes from core), §12.6, §14.5 VR-5 (72 h for sources/intake), VR-9(b)/(c) ("valid … at the stated checkpoint"); 09 `intake_meta.directory_version`; THR-043, THR-102 (02 says 14-day freshness, 04 says 72 h).
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** The only time source and the only directory source for Tier W sealing are the same party (Z-CORE). Freshness is judged against a clock that party supplies. Desk VR-9 validates the Recipient List against the checkpoint *stated in the envelope*, not against the directory state current on the envelope's `received_date`. A consistent stale view therefore passes. There is no emergency-revocation fast path to sources. The 72 h window is long relative to a member removal made because of COI or compromise.
- **PROPOSED FIX:**
  1. Intake time SHALL be cross-checked against an authenticated source independent of Z-CORE: the Tor consensus `valid-after` held by C-05. Skew > 2 h SHALL fail closed (NET requirement in 16). Remove the C-09-supplied chrony refclock, or keep it only as a secondary.
  2. Intake SHALL persist a monotonic `(directory_version, checkpoint tree_size)` high-water mark and reject older snapshots (DB requirement in 09).
  3. Desk VR-9 SHALL additionally require that the stated checkpoint is no older than 24 h before the envelope's `received_date` (with a day of tolerance). It SHALL also recompute eligibility against the roster current on that date, and alert on "sealed to superseded roster".
  4. Reduce VR-5 for sources and intake to 24 h. Add a `ROSTER_EMERGENCY` flag on CHANNEL_ROSTER removals that witnesses propagate. Tier V clients fetch the latest cosigned checkpoint from at least one witness endpoint reachable independently of the tenant onion (see RVW-A-08).
  5. Removal of a member SHALL trigger REVOCATION of their un-expired MEMBER_EPOCH entries in the same append (already in 04 §25.6). Sealers SHALL treat any MEK whose owner is absent from the latest roster *at the high-water mark* as ineligible.
- **RESIDUAL RISK:** Within the reduced freshness window, freeze remains possible for Tier V sources that cannot reach a witness. Tor consensus time can be skewed only by an adversary controlling directory authorities.

### RVW-A-05 — Roster, COI_POLICY and role-label changes can be driven by a CIK-holding (possibly accused) member plus one key-admin, with immediate effect
- **SEVERITY:** High
- **SCENARIO:** An executive, or someone acting for one, is a roster member of a channel. By default every member holds the Channel Identity Key (`channel_admin` default = all, 04 §9.5 / OI-7). With one colluding or compelled key-admin (K15, typically an IT/security role and therefore ADV-07), they can:
  - (a) add an ally as a new `read_intake` member with an innocuous pseudonymous label;
  - (b) relabel themselves (role labels are self-described, e.g., "Compliance officer B"), so sources do not tick them;
  - (c) edit COI_POLICY so that the category covering them no longer excludes them.
  All three take effect for sealing at the next snapshot. Existing members get a non-dismissable notification. Sources, who do not know the organisation's normal roster, cannot evaluate the change. Tier W sources see only "(as listed by this site)".
- **AFFECTED:** ADR-015, ADR-030, ADR-033(1); 04 §9.5, §14.2 (CHANNEL_ROSTER, COI_POLICY signatures: "current CIK + 1 K15"), §14.4 rules 2–3, §14.6 rows "Admin adds a hidden member" / "Member adds a hidden member", §25.5, §27 #8, OI-7; 11 S03/S04b; 14 COI map.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** The continuity rules require two signatures. One of them can come from the very member the COI machinery is meant to exclude, and neither needs to come from the channel's independent route. Role labels are not bound to any attested organisational role. There is no time lock, and no source-visible change history. The design treats "logged and visible" as sufficient, but the people who must react to the log (members, sources) are either possibly colluding or unable to judge.
- **PROPOSED FIX:** Amend 04 §14.2/§14.4 and add an ADR "Directory change governance":
  1. **Separation:** CIK default holders = the independent-route roster only (e.g., ombudsman, audit committee), not all members. `channel_admin` SHALL NOT be granted to any role label that appears in the tenant's COI map for any category of that channel.
  2. **COI-loosening and roster additions** (new `read_intake` member, label change, removal of an exclusion) SHALL require a co-signature by a member of the channel's `independent_route` roster, in addition to CIK + K15.
  3. **Time lock:** such entries take effect for sealing only after `T_ROSTER_DELAY` (default 7 days, SAFE range 3–14) from log inclusion. Witnesses and monitors can file a signed objection during that time, which blocks activation until the independent route resolves it. Removals take effect immediately (see RVW-A-04).
  4. **Label integrity:** role labels are assigned in a separate `ROLE_LABEL` entry signed by K01 or the independent route. Renames show "renamed from X on YYYY-MM-DD" to sources for 90 days.
  5. **Source-facing:** S03/S04b and the Source App show, per recipient, "member since YYYY-MM-DD" and a banner "This list changed in the last 30 days". Tier V VR-8 shows the diff since the checkpoint embedded in the pinned address statement.
- **RESIDUAL RISK:** Collusion of an independent-route member with a key-admin and the CIK holders remains possible, but it is now a three-party act with a public time-locked record.

### RVW-A-06 — Follow-ups are sealed to the *current* roster, silently including members added after the source's original report
- **SEVERITY:** High
- **SCENARIO:** A source files a report concerning a manager and ticks that manager's role. Weeks later the organisation adds a new member, for example that manager's deputy or a newly appointed "investigations lead" friendly to the accused. The source returns and sends follow-ups. BE-052 re-applies the stored COI ticks (role-label indices), but the new member's label was never ticked, so every follow-up, including new attachments, is wrapped to them.
- **AFFECTED:** 07 BE-052; 04 §12.1, §13.4 (roster hash in SUBMISSION), §25.5 ("no slots in earlier envelopes" only); 08 SW-12/SW-13, SA follow-up endpoints; 11 S12; ADR-030.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** COI selections are expressed as a blacklist over labels that existed at first submission. Recipient-set drift between the first report and follow-ups is neither shown to the source nor constrained.
- **PROPOSED FIX:**
  1. Store the original roster hash and eligible member key IDs (user_ids) in `prefs_ct` (Tier V: locally re-derived from the SUBMISSION the source signed; Tier W: in `prefs_ct`).
  2. For follow-ups, the default recipient set = (original eligible members ∩ current eligible members). Members added later are excluded unless the source explicitly opts in on a screen listing "New since your report: …".
  3. Desk VR-9(c) SHALL verify that follow-up recipient sets are subsets of the thread's original set plus explicitly source-approved additions.
- **RESIDUAL RISK:** If all original members leave, follow-ups fail closed until the source approves new recipients. That is correct behaviour, but it needs clear copy.

### RVW-A-07 — Tier W draft parts are sealed before the final recipient set is known
- **SEVERITY:** High
- **SCENARIO:** In Tier W, attachments are "sealed immediately on upload" (11 §5.6), and 06 §9.1 seals message parts at `SEAL_BEGIN(channel, COI selection)`. The category-based COI map is applied only at S08 (11 S04b "repeated at S08 after the tenant COI map for the chosen category is applied"). The source can navigate back to S04b/S05 and change ticks or category after uploading. A roster change or an epoch rollover can also occur mid-draft. Parts already sealed carry slots for members who are excluded from the final SUBMISSION. For attachments, which are the most identifying objects, cryptographic exclusion has then failed before anyone notices.
- **AFFECTED:** 11 §5.6 (also references the superseded "channel epoch key"), S04b, S08; 06 §9.1; 04 §12.1, §13.2 (per-object slot blocks), VR-9(d); ADR-030, ADR-033(1).
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** Sealing is incremental, but eligibility is only final at send. VR-9(d) at import would flag the mismatch, but only after the excluded member already holds a wrap and can decrypt with their MEK.
- **PROPOSED FIX:**
  1. Specify that Tier W parts are sealed under a *draft content key* whose wraps are created only at `SEAL_FINISH`. The CK stays in C-07 RAM, and slot blocks for every object are built at finish from the final eligible set, so no member wrap exists before send.
  2. If the recipient set, category or epoch changes after a part was uploaded, the part SHALL be re-wrapped (not re-encrypted) at finish, or discarded with a source notice.
  3. Fix 11 §5.6 wording ("Member Epoch Keys of the final eligible set at send").
  4. Add a TST: back-navigate after upload, change ticks, submit; assert no slot for the excluded member in any object.
- **RESIDUAL RISK:** None beyond RVW-A-02 (CK in C-07 RAM during the draft).

### RVW-A-08 — Tier V trust anchors are TOFU per session and witnesses are optional/same-organisation
- **SEVERITY:** High
- **SCENARIO:** A state actor compels the operator to present a targeted Tier V source with a forked directory that adds an adversary recipient key. The source obtains ORG_ROOT and the initial checkpoint from the signed onion-address statement. That statement is served by C-37 or printed material, both controlled by the operator. The Source App keeps no persistent state (11 V-7, 04 §25.2), so there is no prior checkpoint to be consistent with. Witnesses are optional (04 §14.3: "when any witness is configured"), and the suggested witness is "an organisation-internal host", which is compellable together with the operator. The "embedded checkpoint" of VR-3 cannot exist for a per-tenant log in an app that is identical for all tenants (ADR-022, 33 §15.2).
- **AFFECTED:** 04 §14.3, §14.5 VR-1/VR-2/VR-3, §14.6 "forked log" row, §27 #9, OI-13; 33 §15.2 ("embeds a KD checkpoint"); 16 §11; 02 THR-102/THR-118, TM-010 (gossip by Source App, which has no state or peers); 40 ASM-111.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** Split-view detection requires an honest party outside the operator's control that the client consults at use time. The design defers this to optional configuration and to import-time VR-9. VR-9 detects the fork only after the adversary has the ciphertext it can open, and a compromised core can suppress it (04 §27 #9).
- **PROPOSED FIX:**
  1. Make ≥ 2 witnesses mandatory for any tenant with ANONYMOUS channels, at least one operated outside the operator's legal entity and jurisdiction (vendor-independent civil-society witness network, per 36). ORG_ROOT SHALL fail validation if `w < 1` external.
  2. The Source App SHALL fetch the latest cosigned checkpoint for the tenant from ≥ 1 witness or monitor endpoint reachable over Tor, *not* via the tenant onion, and SHALL require consistency with the tenant-served checkpoint before sealing.
  3. Delete the claim that the Source App release embeds a tenant checkpoint. Replace it with "embeds the witness/monitor key set and endpoints".
  4. Give the Source App optional opt-in, passphrase-encrypted persistence of the last seen checkpoint per tenant (it already has an opt-in encrypted-state mode). Present the forensic trade-off.
  5. Signed onion-address statements SHALL carry a cosignature by at least one external witness, so a C-37-only substitution fails.
- **RESIDUAL RISK:** First contact still trusts the pinned K01 fingerprint obtained out of band. Multiple independent publication channels (16 §11.2) mitigate this.

### RVW-A-09 — Case DB WAL archive, backups and blob-store object metadata persist import time ≈ submission time ± 25 min
- **SEVERITY:** High
- **SCENARIO:** A state actor compels backup media or seizes the core site. The core WAL is archived every 900 s (`archive_timeout=900`, 18/19) and retained in encrypted 35-day backups. Its commit records carry exact commit times of `import_envelope` inserts. Relay pulls happen within U(5,25) min of submission, so import commit time bounds submission time to about ±25 min. The same bound appears in several other places:
  - S3-compatible C-13 objects carry server-set `Last-Modified`, which cannot be normalised like POSIX mtime;
  - filesystem ctime/btime on C-13;
  - `core.job` / `notification_queue` rows (timestamptz on the L3 allow-list) until vacuum and in WAL.
  Intake-side residue (heap order, WAL, inode ctime) is acknowledged in 09 §13 and 30 §13 but left open.
- **AFFECTED:** ADR-010, ADR-033(4) ("Relay pull times are not persisted beyond day granularity"); 09 §8 (explicitly "Core DB: WAL commit records carry relay batch times … accepted"), §5.1 blob mtime rule, §9 `blob_object` row; 19 §3 (`archive_mode=on`, `archive_timeout=900`); 07 BE-054; 30 AT-040/§13 open issue 1; 21 HA-006; 02 TM-013 (HIGH profile daily import, not default).
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** "Relay batch time" is treated as non-source metadata, but in the default profile it is a ≤ 25-min proxy for source action time. That directly contradicts ADR-033(4), and the backups make it retrospectively disclosable for 35 days. ctime and object-store metadata cannot be normalised by the application.
- **PROPOSED FIX:**
  1. Amend ADR-010/033: *default* import scheduling SHALL decouple import from arrival. Options: (a) TM-013 daily random import for all profiles, or (b) fixed import slots every 6 h with the intake holding envelopes until the slot. Latency is acceptable because recipients are notified in digests anyway.
  2. Intake SHALL write envelopes to a tmpfs staging area (encrypted with an ephemeral in-RAM key) and commit them to C-08 disk only at fixed slots (e.g., every 60 min, all pending at once). This closes the ctime/heap-order/WAL residue on intake, which is 30 §13 open issue 1.
  3. C-13 on S3: object keys written only by the slot-based import, versioning off (HA-006). Document that `Last-Modified` equals slot time.
  4. Core WAL: state in 09 that WAL commit times equal import slot times (not source-derived) only once item 1 is adopted. Until then, list this in 03 §10.1 as a disclosable datum ("approximate submission time ±25 min, in backups ≤ 35 days").
  5. Add AT-040 coverage for core WAL segments and object-store metadata.
- **RESIDUAL RISK:** Slot-level (hours) timing remains. Live observers of the intake still see arrival times (see RVW-A-22).

### RVW-A-10 — Operator can prospectively log return-visit times for a specific case's mailbox (Tier V and W)
- **SEVERITY:** High
- **SCENARIO:** The operating organisation (or a compelled operator) wants to identify the author of a specific case. It holds both the Case DB and the intake host, and therefore the Intake Routing Key. With these it resolves the case's `routing_ct` to the `mailbox_id`/`source_account_id` (03 §9 row 1, 09 §9). It then deploys a modified intake that records exact times of every authentication for that account: Tier V `SA-06 locator_hash`, Tier W login. Staff can also induce return visits by replying. The organisation is often also the employer network operator (ADV-07/08), so these precise return times can be intersected with corporate proxy/VPN/Tor-usage logs, badge data, or ISP data under compulsion. That is an intersection attack keyed to one known case.
- **AFFECTED:** ADR-005, ADR-009, ADR-010; 04 §11.5, §27 #12, OI-11 (private fetch deferred); 06 §8.2 (Intake Routing Key); 08 SA-06, SW-10; 03 §10.4 ("Start logging exact timestamps … Circuit IDs do not identify people"); 16 §16 predecessor/intersection row.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** Mailbox retrieval is per-account and authenticated, so the server always knows *which* account is active. 03 §10.4 treats exact-time logging as low-value because circuits do not identify people. It does not consider an operator that can select the account by case, and that also controls the source's likely network environment.
- **PROPOSED FIX:**
  1. Promote OI-11 to v1 for Tier V: **fetch-all dead-drop retrieval**. Replies are published in fixed-size, epoch-batched bundles that every Source App downloads in full, CoverDrop/SecureDrop-Protocol style. Clients trial-decrypt locally, so reading replies requires no authentication and reveals no account. Follow-ups are submitted unauthenticated (identity proved inside the ciphertext by `sign_sk`).
  2. Tier W cannot use this. State the residual in the Tier W statement ("each time you sign in, a compromised server could note the exact time") and in 05 guidance ("vary network and time; never from employer networks; replies may be used to prompt you to return").
  3. The Intake Routing Key SHALL be held in a TEE (RVW-A-01) or split so that case→mailbox resolution requires a relay-side proof. At minimum, record resolution use in the SECURITY audit with external witness anchoring.
  4. 12 SI-12/SI-11: add a Desk interlock warning when staff send many short replies in quick succession (a "prompting" pattern).
- **RESIDUAL RISK:** Tier W retains this exposure, and a source's own visiting pattern is observable at the network edge regardless.

### RVW-A-11 — Harvest-now-decrypt-later of Tier W plaintext and permanent passphrases on classical onion circuits
- **SEVERITY:** High
- **SCENARIO:** A state actor records all Tor traffic at the intake host's uplink, which is feasible via a compelled hosting provider (ADV-10), for years. Onion-service end-to-end encryption and link TLS use classical X25519. With a future cryptographically relevant quantum computer, the recorded Tier W sessions yield report plaintext, attachments and, critically, passphrases. The passphrases never expire, so any mailbox still existing then (and its replies) is exposed, and past reports can be linked by `mailbox_id` derivation.
- **AFFECTED:** 04 §5.1, §27 #2, OI-12 (onion TLS with PQ group undecided); ADR-006 (PQ for storage only); ADR-005; 16 §7.1 (port 80 HTTP inside onion by default).
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** PQ protection is applied to stored envelopes (X-Wing) but not to the transport that carries Tier W plaintext and credentials. Onion TLS is optional, default undecided, and depends on browser support. Passphrase permanence converts a transport break into a long-lived credential break.
- **PROPOSED FIX:**
  1. HIGH profile default: onion TLS with a hybrid PQ key-exchange group (X25519MLKEM768) as soon as Tor Browser supports it. Otherwise require Tier V for channels flagged high-risk (TM-012 default).
  2. Track Tor's PQ circuit handshake work and add it to the Transport Adapter admission criteria in 16 §6.3 ("PQ-hybrid end-to-end key agreement").
  3. Bound credential lifetime: optional passphrase rotation (RVW-A-03 item 2) and a maximum mailbox lifetime (e.g., 365 days, already `inactive_purge`) communicated to sources.
  4. Document the HNDL residual in 03 §10 and in the Tier W statement for high-risk sources.
- **RESIDUAL RISK:** Metadata (volumes, timing) is recorded regardless. The residual shrinks to the gap until PQ transport is available.

### RVW-A-12 — OS, tor and database packages on the intake host bypass TUF, transparency and reproducibility
- **SEVERITY:** High
- **SCENARIO:** A state actor with supply-chain reach compromises or compels a distributor of a third-party package that runs on H-INTAKE, for example the Tor Project APT repository signing key, a Debian security update, or a kernel/PostgreSQL/OpenSSL package. The intake host installs it via `unattended-upgrades` over `apt-transport-tor`. The package handles source-facing traffic (tor) or runs with root, yet it never passes through Candor's two-builder reproducibility, threshold TUF signing, Sigsum logging or monitor veto. A broadly shipped backdoor needs no targeting to hit every Candor intake.
- **AFFECTED:** DECISIONS §2 (Trust Path (a): "all code that handles source-facing requests"); ADR-022; 17 §4.5 (Debian updates via `apt-transport-tor`, signed Release files), §5 (`unattended-upgrades` security only), INFRA-008; 16 §7.3 (tor from the Tor Project repo or Debian, "patch SLA 72 h"); 28 §5.4 (`packages.lock` pinned snapshots — contradicts unattended upgrades), §14 ("Debian … trusted roots"); 33 §4 (`platform-pins` carries only version *floors*), §18.5.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** Two supply chains coexist. 28 pins OS packages by snapshot and hash for images, while 17 lets hosts pull live security updates. The version-floor mechanism in `platform-pins` checks minimum versions, not content. Nothing logs, rebuilds or delays third-party updates, and tor, the most source-facing binary, is outside the Trust Path controls.
- **PROPOSED FIX:**
  1. Amend ADR-022/28/17: H-INTAKE (and H-CORE for trust-path dependencies) SHALL install OS and third-party packages **only** from a Candor-published `platform` TUF target: a hash-locked package set (Debian snapshot + tor). Its hashes SHALL be logged in Sigsum and independently re-derived from upstream by both builders (and rebuilt from source for C-tor per 28 §5.5 "Level 4").
  2. Disable direct `apt` sources on H-INTAKE. `unattended-upgrades` SHALL consume only the local verified repository (UPD-020 extended to OS packages).
  3. Fast path for DSA/tor security releases: the platform role signs within the 72 h SLA with a shortened (≥ 12 h) cooling period; monitors compare against upstream.
  4. Extend `candorctl verify-installed` / UPD-021 to all installed packages, not only trust-path files.
- **RESIDUAL RISK:** An upstream-at-source backdoor (xz-class) is logged but not detected. Debian/Tor signing remains a trusted root, now with delay and visibility.

### RVW-A-13 — No externally verifiable per-instance uniformity; Fleet policy and operator control allow selective withholding or divergence
- **SEVERITY:** High
- **SCENARIO:** Identical artefacts (ADR-022) do not imply identical *running state*. The adversary can:
  - (a) with a compelled EE vendor-hosted Fleet Manager, assign one high-value instance to a ring that never approves a security release, then exploit the known vulnerability, since UPD-006 lets policy gate minor releases and maintenance windows;
  - (b) with a compelled operator, run modified binaries locally, which `verify-installed` run by that operator does not reveal to anyone else;
  - (c) in MANAGED, where the vendor operates the hosts, run anything at all.
  None of these is visible to sources, monitors or independent-route members.
- **AFFECTED:** ADR-022, ADR-020 (Fleet Manager), ADR-024 (MANAGED); 33 §14 (client-side staged rollout 0–72 h), §14.1 (Fleet distributes version policy), §18.5, UPD-006/012/021; 04 §14.2 (CLIENT_RELEASE only for clients); 02 THR-113, THR-025; 03 §10.3.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** All uniformity controls stop at the release boundary. Installed state is verified only by the instance's own operator. There is no directory entry for *server* releases, and no rule that security releases override Fleet or ring policy after a bound.
- **PROPOSED FIX:**
  1. Add a C-14 `SERVER_STATE` entry: installed trust-path package hashes + platform set + (where available) TPM/TEE attestation quote, appended by C-25 at least daily and signed by a host-bound key whose attestation is logged. Desks, external monitors and Tier V clients (S03 "Software" row) compare it against the transparency log. A stale entry older than 72 h is shown to sources as "server state not reported".
  2. UPD-006 amendment: any release carrying `security: true` or raising `min_secure_version` SHALL install within 7 days regardless of Fleet or ring policy. Fleet Manager SHALL NOT be able to defer it. If an instance runs below the floor, intake SHALL show a source-visible banner and Desks SHALL block case access (analogous to 33 §15.1).
  3. MANAGED: require TEE-attested intake (RVW-A-01) with attestation verifiable by the customer's own Desk, or require Tier V for ANONYMOUS channels on MANAGED.
  4. Fleet Manager version policy SHALL be logged (per-ring) in a vendor transparency log so that per-instance ring assignment anomalies are auditable by customers.
- **RESIDUAL RISK:** A root-level modification without TEE can forge state reports, and attestation reduces but does not eliminate that.

### RVW-A-14 — Source App acquisition leaves compellable identity-linked records (app stores, clearnet downloads)
- **SEVERITY:** High
- **SCENARIO:** The Source App is the design's strongest protection (04 §24.1 rank 1), but the ways of obtaining it are not treated as a metadata flow:
  - Google Play and the Apple App Store bind installs to a real account, with timestamps and device identifiers, and are routinely compelled (ADV-26);
  - F-Droid and "direct APK" downloads may occur over clearnet;
  - 11 §4 says the app is "enabled when the operator publishes the app download on C-37", the organisation's clearnet information site, so the employer's proxy or the ISP sees a download of a whistleblowing client from the employer's own integrity domain;
  - 11 V-11's "neutral name and icon configured per deployment" implies per-tenant builds, contradicting ADR-022, or tenant-specific store listings that reveal the organisation.
- **AFFECTED:** ADR-004, ADR-022; 11 §4, V-11; 33 §4 (Android F-Droid + direct, iOS App Store), §15.2; 05 GC-38 (discusses device search, not acquisition records); 16 §17; 03 §8 inventory (no acquisition layer); THR-002, THR-048.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** The metadata inventory (03 §8) starts at the first request to the onion. Acquisition of the client is outside every table, so no requirement governs it.
- **PROPOSED FIX:**
  1. Add request type R-00 "client acquisition" to 03 §8, covering app-store, F-Droid, C-37 and onion-mirror paths.
  2. Primary distribution: the vendor's onion mirror (identical for all tenants), downloadable in Tor Browser with TUF-verifiable hashes. C-37 SHALL link to generic vendor instructions, never host binaries. App-store listings SHALL be generic (vendor name, no tenant branding).
  3. 05 guidance: "Do not install from an app store tied to your account if your identity could be requested from that store; prefer Tails + the desktop AppImage downloaded over Tor."
  4. Resolve V-11: branding is runtime data from the pinned address statement, never a build variant.
  5. Evaluate an ephemeral Tier V for Tails: a verified AppImage run without persistence. This removes the device-search objection that pushes high-risk sources to Tier W.
- **RESIDUAL RISK:** iOS users have no store-independent option. The residual is disclosed.

### RVW-A-15 — Hostile-attachment containment undefined on Windows/macOS; host-side decoding and webview rendering of hostile strings
- **SEVERITY:** High
- **SCENARIO:** A hostile document crafted by the investigated organisation or a state actor (ADV-29) targets investigators to learn case content or plant implants. The design depends on L1 per-object microVMs, but:
  - (a) L1 is defined only as Firecracker (Linux/KVM) or gVisor. Candor Desk ships for Windows and macOS (33 §4), and 10 OI-10-2 leaves their substrate undefined, so the most common enterprise recipient platform has no specified containment;
  - (b) 12 R06 says the CL-2 safe viewer *decodes PNG pages on the host* in a "sandboxed renderer process", contradicting 10 §6 ("Desk … never links format parsers … renders only raw RGBA frames");
  - (c) several attacker-controlled strings are rendered in the Tauri webview, which has IPC access to decrypt/export commands: the Stage 0 CBOR results and metadata report (author fields, `EXTERNAL_REFS` host lists), filenames, OCR text and the source message text. Yet 12 RUI-002 only restricts network connections and OI-12-2 leaves CSP/IPC isolation open.
- **AFFECTED:** ADR-012, ADR-027, ADR-033(5); 10 §6 (L1 definition), FILE-009, OI-10-2, §18 #1; 12 R05 (metadata report), R06 (CL-2), RUI-002, OI-12-2; 19 ADR-019 (Tauri 2).
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** Containment is specified for one host OS family. Output validation across the VM boundary is specified for pixel frames but not for text and strings. The webview is not treated as a hostile-content boundary.
- **PROPOSED FIX:**
  1. Define L1 per platform in 10: Hyper-V isolated VM (Windows), Virtualization.framework VM (macOS), Firecracker (Linux). Each has no NIC, no shared folders and no clipboard, and is subject to the same tests. Where none is available, the Desk SHALL refuse CL-2/CL-3 for originals, fall back to L0 metadata-only, and offer AIRGAP/L3.
  2. CL-2 SHALL display only raw bounded RGBA frames (as 10 states). Remove host-side PNG decoding from 12, or specify a memory-safe, fuzzed, separately sandboxed decoder with no IPC.
  3. Add Desk requirements:
     - Tauri isolation pattern and a capability allow-list per window;
     - a CSP with `script-src 'self'` only and Trusted Types;
     - every string that originates in a source, a VM or the server rendered via text nodes only (no HTML sinks), plus bidi/control-character visualisation;
     - a fuzzing corpus of hostile metadata strings in the malicious-server harness (TM-004).
  4. Stage 0/metadata outputs SHALL be schema-validated and length-bounded per field by the host before display.
- **RESIDUAL RISK:** Hypervisor escape remains (10 §18). L3/L4 exist for suspect files.

### RVW-A-16 — Release path: emergency 0-hour cooling, signer/builder jurisdiction concentration, single-key bootstrap
- **SEVERITY:** Medium
- **SCENARIO:** A state actor compels, within one jurisdiction, two targets keyholders and the two contracted builder operators. It also induces or exploits an "emergency" to publish a reviewed-but-subtly-malicious fix (a bugdoor reviewed by two insiders under embargo). Emergency cooling is 0–24 h and emergency releases auto-install, so monitors have little time to rebuild or review the diff before instances update. Separately, first installs trust `root.json` and the witness policy from a bootstrap bundle signed by a single OpenPGP archive key (2-person procedure, not threshold). A targeted bootstrap served to one organisation's download of the vendor website would anchor that instance to attacker metadata unless the operator performs the multi-channel fingerprint comparison.
- **AFFECTED:** ADR-022; 33 §5.1 (Builder B "different organisation", no jurisdiction rule), §6.1 (targets: no jurisdiction rule), §9.3, §10 (E5 cooling 0–24 h, E6 auto-install), §18.1, REL-007 (root ≥ 2 jurisdictions) vs 28 SCM-042 (root ≥ 3 jurisdictions); 28 §14 residual.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** Multi-jurisdiction custody applies only to root keys. Emergency handling preserves cryptographic steps but removes the human-review time that the transparency design depends on. Bootstrap verification is a manual instruction, not an enforced check.
- **PROPOSED FIX:**
  1. Targets and delegated trust-path roles SHALL have holders in ≥ 2 jurisdictions and ≥ 2 organisations, so that 2-of-3 cannot be met within one jurisdiction. Builder A and Builder B SHALL be in different jurisdictions. Reconcile REL-007/SCM-042 (use ≥ 3).
  2. Emergency releases SHALL publish the source diff at log time and require a signed "reviewed" attestation by at least one external monitor before timestamping. Z-INTAKE hosts SHALL apply emergency releases after ≥ 6 h unless an operator with dual approval overrides.
  3. `candorctl tuf init` SHALL fetch the root hash from ≥ 2 independent monitor endpoints over Tor and refuse on mismatch. The bootstrap bundle hash SHALL be Sigsum-logged and witness-cosigned.
- **RESIDUAL RISK:** Cross-jurisdiction coercion (e.g., treaty-based) and reviewed-but-malicious code remain. Transparency makes them visible after the fact.

### RVW-A-17 — Tier W sources cannot verify the key directory, but the UI presents verification affordances
- **SEVERITY:** Medium
- **SCENARIO:** A Tier W source reads S03, `/keys` (SW-17: "channel key fingerprints, directory checkpoint, witness status, current client release hashes") and the roster "(as listed by this site)", and may compare fingerprints with C-37. This gives the impression of verification. However, the party rendering the page is the party that seals, so a compelled sealer can show the correct directory and seal to anything, or exfiltrate plaintext. Tier W sources therefore cannot meaningfully rely on key-directory verification. The only real protection is Desk-side VR-9, which catches slot insertion but not plaintext copying (RVW-A-01).
- **AFFECTED:** ADR-004, ADR-030; 08 SW-17; 11 S03 ("Software … as reported by this site"), §15 #9; 03 §10.2; 04 §14.6 first row.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** The labels "(as listed by this site)" are accurate but weak. SW-17 exposes witness status and fingerprints to Tier W without stating that checking them cannot protect a Tier W submission.
- **PROPOSED FIX:**
  1. SW-17 and S03 in Tier W SHALL carry a fixed sentence: "Checking these values does not protect a report sent from this website; only the Candor app checks them before encrypting."
  2. Move fingerprint and witness details to a Tier V-oriented page.
  3. Provide the one Tier W-meaningful check: an *after-the-fact* independent-route statement. Desks' VR-9 results are aggregated into a signed daily "intake integrity: OK/ALERT" C-14 entry that external monitors and C-37 mirror. A later Tier V session or the info site can reveal an alert window.
- **RESIDUAL RISK:** As RVW-A-01.

### RVW-A-18 — Anonymous-slot COI confidentiality ends at import and is observable by excluded members
- **SEVERITY:** Medium
- **SCENARIO:** ADR-033(1) says "server and DB thieves cannot tell which members were excluded". That holds only until import. After import:
  - the case ACL (plaintext to C-22) and the absence of an in-channel member reveal the exclusion;
  - the identity of the first importer is recorded;
  - per-member trial-decrypt and fetch behaviour (which Desks fetch full blobs of which envelope) is observable by C-10;
  - the MEK-retirement query (04 §12.5) reveals per-epoch import completion.
  Before import, an excluded member notices an envelope it cannot open (acknowledged in 04 §27 #5 and 06 R-3). An accused member in the channel therefore learns, with day precision, that a report concerning them (or someone else excluded) exists.
- **AFFECTED:** ADR-030, ADR-033(1); 04 §14.6 last rows, §25.4 (Desk fetch pattern), OI-6; 06 R-3, O-2; 12 §8; THR-020, THR-110.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** The anonymity property is claimed for the ciphertext at rest but not carried through the workflow. Mitigations are routing guidance, not design.
- **PROPOSED FIX:**
  1. Correct the ADR-033(1) effect statement to "until import".
  2. Adopt 06 O-2 as an ADR: **chaff envelopes**. The intake (or a Tier V "cover" client run by the independent route) emits Poisson-distributed envelopes with all-dummy slots at a rate comparable to real traffic. Each chaff envelope is provably chaff to the independent route after the decrypt window, via a commitment revealed later, so it is auto-rejected without dual approval (interacts with RVW-A-20).
  3. Desks SHALL fetch every pending envelope's slot block (not only the ones they can open) and SHALL delay imports to digest slots, so fetch/import behaviour does not single out recipients.
  4. Keep COI-driven case ACLs out of admin-visible views. Store case ACL membership for COI-sensitive categories encrypted, with C-22 enforcing via capability tokens issued by case members.
- **RESIDUAL RISK:** Workflow side-channels (investigation actions, THR-125) remain.

### RVW-A-19 — Event-driven notifications give mail providers and corporate IT an hour-level submission-timing oracle
- **SEVERITY:** Medium
- **SCENARIO:** Notifications are content-free, but `notify_intake_available` is triggered *by* an import batch and delivered in an hourly digest. Whoever runs the mail/Teams/Matrix transport learns the hour in which "something arrived": the organisation's own IT (ADV-07) or a cloud mail provider (compellable). Because a digest exists only when an event occurred, its presence is the signal. Combined with network logs of which employee used Tor in the preceding hour, this narrows candidates.
- **AFFECTED:** ADR-017; 07 `notify_intake_available`, BE-021/054; 09 §9 `notification_queue` row; 03 §9 ("Negligible").
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** Jitter and batching hide counts and case IDs, but not the *existence* of events per hour.
- **PROPOSED FIX:**
  1. Amend ADR-017: notifications about intake SHALL be either (a) constant-schedule (e.g., one digest per day at a fixed time, sent whether or not anything happened, identical text) or (b) pull-only (Desk shows the pending count when opened, no push).
  2. Default to (a) for ANONYMOUS channels.
  3. Combine with import slots (RVW-A-09).
- **RESIDUAL RISK:** Staff behaviour after a notification (logging in) is itself observable on the corporate network. Guidance for recipients should cover it.

### RVW-A-20 — Undecryptable envelopes pin Member Epoch Keys indefinitely (forward-secrecy erosion, escalation flooding)
- **SEVERITY:** Medium
- **SCENARIO:** MEK destruction waits until every envelope of the epoch is imported or dual-approved-rejected (ADR-033(2)), with no cap. Some envelopes can never be opened by anyone: envelopes whose slots are all dummies, which any Tier V client can upload; envelopes sealed to members whose Desks were lost; malformed envelopes. Such an envelope keeps every member's MEK private key for that epoch alive indefinitely, so a later device seizure exposes all envelopes of that epoch. It also triggers repeated escalations to the independent route after 7 days. An adversary can use this deliberately, to erode forward secrecy and to create alert fatigue.
- **AFFECTED:** ADR-033(2); 04 §9.5, §12.5, §15.2; 08 SA envelope upload; 02 THR-033.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** The anti-suppression rule is correct in intent, but it has no path to conclude that no eligible member can open an envelope, short of manual dual approval per envelope.
- **PROPOSED FIX:**
  1. Each Desk that trial-decrypts an envelope and finds no slot SHALL post a signed `NOT_MINE(envelope, epoch)` statement.
  2. When all members in the epoch's roster have posted it, the envelope becomes `UNOPENABLE` and is auto-rejected after a notice to the independent route, without dual approval. The independent route can hold it within 7 days.
  3. Rate-limit envelope-only (no account) Tier V uploads per circuit and globally, as for accounts.
  4. Add a hard MEK retention cap for epochs whose only blockers are `UNOPENABLE` envelopes.
- **RESIDUAL RISK:** A member withholding `NOT_MINE` delays retirement; that is visible in audit.

### RVW-A-21 — Response size classes, CSP and sub-resource rules differ between 03, 08 and 11
- **SEVERITY:** Medium
- **SCENARIO:** A local or guard-side network adversary performs website/state fingerprinting (THR-004, B-AN-14..19). Under 08's classes, an observer can distinguish landing (32 KiB), login (16 KiB), inbox/wrong passphrase (64 KiB) and larger pages. Under 11, S12/S08 switch to P2 (128 KiB) when content is large, which reveals that a source has an ongoing conversation. 08 SW-19 serves `/static/{sha256}.css|woff2|svg` sub-resources under `style-src 'self'; font-src 'self'`, while 11 mandates a single request per page with hash-pinned inline CSS and no sub-resources. Sub-resource fetches add distinguishable request bursts.
- **AFFECTED:** ADR-011; 08 §3.8, §3.10, SW-01/09/19; 11 §5.3–§5.4, OI-11-3; 03 ANON-004 (a third CSP); 11 §15 #3.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** Three documents define the source-web response contract independently.
- **PROPOSED FIX:**
  1. Make 11 §5.3/§5.4 normative (single request per view, inline CSS, no SW-19 static route) and delete conflicting text in 08/03.
  2. Adopt OI-11-3: a single size class (P2) for all Tier W responses, or at minimum ensure that inbox and conversation pages are always P2 regardless of content.
  3. Add login-latency flattening. BE's 2 s floor exists; also apply it to successful logins with replies, so decryption work is not a timing feature.
  4. One cookie name and one CSP string, tested by AT.
- **RESIDUAL RISK:** Request *sequences* and inter-request timing remain fingerprintable (11 §15 #3).

### RVW-A-22 — Unpadded Tier W uploads give the intake hosting provider exact volume/time per upload
- **SEVERITY:** Medium
- **SCENARIO:** The intake's hosting provider or uplink ISP (ADV-10, compellable) sees Tor cell volume into the intake host with exact timestamps. Tier W uploads are unpadded (11 §5.4 rule 6), so each file upload is a distinct volume spike at a precise time. A source-side observer under the same compulsion (ISP, employer) sees matching outbound Tor volume, which makes a strong end-to-end correlation feature. The day-granular storage (ADR-010) does nothing against live network observation.
- **AFFECTED:** ADR-011, ADR-010; 11 §4, §5.4, §15 #2; 03 R-02 F07 note ³; 16 §16 (end-to-end correlation); 17 INFRA-025.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** No-JS forms cannot pad request bodies. Service-side cover traffic is not considered.
- **PROPOSED FIX:**
  1. State in the Tier W honesty text and 05 guidance that large files sent via the website are recognisable by size to network observers at both ends. Recommend Tier V or splitting/archiving to standard sizes.
  2. Server-side: optional, for the HIGH profile, constant-rate cover traffic. A C-25 probe client on an *independent* network uploads decoy bodies of bucketed sizes to the onion at random times, so upload spikes are not unique.
  3. Evaluate a no-JS padding trick: a hidden fixed-size filler field is ineffective; instead, offer the source a server-provided "size-class" guidance and accept archives that the Source App or Tails tools pad.
- **RESIDUAL RISK:** THR-003 against an adversary at both ends is not defeated (NA-3).

### RVW-A-23 — Intake egress/time/logging inconsistencies (monitor push vs nftables, chrony from core, tor log retention, C-37 CDN)
- **SEVERITY:** Medium
- **SCENARIO:** Implementers reconciling contradictory rules tend to open egress broadly. The contradictions are:
  - 06 §8.5 has every host agent *push* to the monitor collector (TCP 8514), but 16 §14.2's normative nftables output chain drops everything except tor and established flows;
  - updates via "a dedicated tor client instance" need another egress UID that the ruleset does not list;
  - the host clock is fed from C-09 (see RVW-A-04);
  - 03 §10.1 says tor logs are kept 7 days on C-05, while 16 NET-008 says volatile ≤ 24 h;
  - 03 §10.1 allows C-37 "unless a CDN is used — documented", while 11 §9 and 16 §11.3 prohibit CDNs.
  Any generic "allow intake to reach the monitor host" rule creates a path from the intake host to a machine that has clearnet egress (H-MON runs mail), which undermines the no-clearnet invariant and risks onion-location disclosure (THR-104) through a chained misconfiguration or compromise.
- **AFFECTED:** ADR-001, ADR-002, ADR-009; 06 §8.5, R-9; 16 §7.3, §14.2, NET-008; 17 §4, F14; 03 §10.1; 11 §9.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** There is no single normative egress matrix for H-INTAKE across 06/16/17.
- **PROPOSED FIX:**
  1. One normative H-INTAKE egress matrix in 16 §14.2, listing each permitted flow (tor service UID → ext0; update-tor UID → ext0; agent → monitor collector over a dedicated interface to a collector with no clearnet egress).
  2. Alternatively invert monitoring to a pull through the relay path, so the intake initiates nothing but tor.
  3. H-MON's mail relay SHALL be on a separate host from the collector reachable by intake.
  4. Align tor log retention (≤ 24 h volatile) and delete the C-37 CDN allowance.
  5. Add a TST asserting that no packet from H-INTAKE can reach any host with a default route to the Internet except via tor.
- **RESIDUAL RISK:** Root compromise of intake can alter firewall rules (17 residual 9).

### RVW-A-24 — Recipient endpoints managed by the investigated organisation (EDR/MDM/cloud AV) defeat Desk-side protections
- **SEVERITY:** Medium
- **SCENARIO:** In EE deployments, recipient workstations are typically managed by the same corporate IT and security function that may be the subject of, or allied with, a report (ADV-06/07). Kernel-level EDR, MDM, DLP and cloud AV can capture the screen despite `WDA_EXCLUDEFROMCAPTURE`, read Desk process memory, upload samples or hashes (THR-108) and log activity timing. A state actor can compel the EDR vendor's cloud.
- **AFFECTED:** ADR-007, ADR-012; 12 SI-07/SI-08, RUI-038; 17 hardened workstation profile; 02 THR-108/THR-109/THR-041.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** Endpoint posture is guidance ("recommended hardened workstation profile"). Desk does not assess or disclose endpoint management.
- **PROPOSED FIX:**
  1. Add Desk posture checks at unlock (RUI requirement): detect enterprise EDR/MDM agents, cloud-AV sample submission settings, screen-recording/remote-assist tools and OS AI/recall features.
  2. Show a persistent "Managed endpoint" banner.
  3. Policy: independent-route members and COI-sensitive categories SHALL use unmanaged or separately managed endpoints (AIRGAP-RCP or dedicated hardened laptops). Record this in the key directory as a member attribute (`endpoint_class`), visible to Tier V sources in S03.
- **RESIDUAL RISK:** Detection of stealthy agents is best-effort.

### RVW-A-25 — Original-evidence exports carry live beacons and canary marks to downstream systems
- **SEVERITY:** Medium
- **SCENARIO:** A document contains a canary token or remote template (THR-107). Candor's viewers are network-less, but ORIGINAL export (E3/E7, e.g., an EU Art 12(4) forward "without modification", or delivery to outside counsel or a regulator) delivers the live document to systems that will open it with network access. The beacon fires and tells the originating organisation that this specific copy (often recipient- or employee-specific) has leaked, and when. That identifies the source by canary trap.
- **AFFECTED:** ADR-012, ADR-018; 10 §8 (EXTERNAL_REFS flag), §13, §15 E2–E8, PSR; 12 R08.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** The PSR checklist covers metadata, dots and watermarks, but it does not require beacon neutralisation or downstream no-network handling for originals.
- **PROPOSED FIX:**
  1. The Export Package manifest SHALL include the Stage 0/1 `EXTERNAL_REFS` list and a mandatory PSR item "beacons present: recipient informed / neutralised".
  2. ORIGINAL exports of files flagged `EXTERNAL_REFS` or `ACTIVE_CONTENT` SHALL be wrapped in an encrypted container with a cover note requiring opening only in a network-less environment. The exporter must acknowledge.
  3. For Art 12(4) forwards, include the rendition and hashes by default, with the original under a sealed layer.
- **RESIDUAL RISK:** Downstream recipients may ignore instructions.

### RVW-A-26 — Residual database linkability (tier column, quota history, own-message history, 30-day header digest, identity-object presence)
- **SEVERITY:** Medium
- **SCENARIO:** An adversary holding intake and core DB snapshots (seizure or compulsion) narrows sources using fields that are individually weak:
  - `envelope.tier` in cleartext: Tier V is a small, distinctive population;
  - per-account upload quota history (03 META-021: padded bytes per UTC day, 30-day rolling), which conflicts with 09's single `quota_bucket` and 16's "reset per epoch";
  - an unspecified store behind SW-11's "own messages as sent on YYYY-MM-DD", which implies a per-account history of follow-up days not present in the 09 schema;
  - `header_digest` retained 30 days, linking intake snapshots to core rows;
  - IDENTITY object presence: 04 §25.1 always includes a dummy IDENTITY object for Tier W, but 06 §9.1/§9.2 and the Tier V flow do not state that it is mandatory, so an envelope with an IDENTITY object would reveal a CONFIDENTIAL source.
- **AFFECTED:** ADR-010, ADR-014; 09 §5.1, §9; 03 META-021, R-03 note ¹; 08 SW-11; 16 §13 L7; 04 §13.1 (`object_type` cleartext), §25.1.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** Minimisation is analysed per field, not for joint uniqueness, and several stores are specified inconsistently.
- **PROPOSED FIX:**
  1. Remove `tier` from `envelope`, or move it into an aggregate-only counter increment at commit.
  2. Quota: one per-account bucket for the current day only, reset daily (align 03/09/16).
  3. SW-11 "sent on" dates SHALL come from `prefs_ct` or the source's own ciphertext (encrypted to the source key), never from a cleartext table.
  4. Null `header_digest` after acknowledgement plus 7 days.
  5. Make "exactly one IDENTITY object per initial envelope (dummy when anonymous), same padded size" normative for both tiers (ARCH + CRYPTO requirement, verified at import).
  6. Add a 30-ANONYMITY-TESTING test for joint-uniqueness (k-anonymity of the tuple of all cleartext fields per envelope).
- **RESIDUAL RISK:** `received_date` + channel + size buckets remain a weak link (09 §9).

### RVW-A-27 — Global rate-limit and queue states are an activity oracle
- **SEVERITY:** Low
- **SCENARIO:** An observer repeatedly probes public endpoints and learns in real time when other sources are active. The signals are the Argon2 concurrency queue (busy page when saturated), the global new-account cap, and the PoW "suggested effort" advertised in the onion descriptor. Correlated with a suspect's observed Tor sessions, this helps an employer-side adversary. It is limited on low-traffic instances, where one or two logins rarely saturate, but becomes relevant with small global limits (08 SW-10 "G: Argon2id 4 concurrent" vs 04 `ARGON2_MAX_CONCURRENT = 8`).
- **AFFECTED:** ADR-026; 04 §11.5; 08 SW-03/SW-10; 16 §13; 34.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** Global limits are designed for availability, not unobservability.
- **PROPOSED FIX:**
  1. Reconcile the limit values.
  2. Size global limits so that busy states occur only under attack-level load (≥ 10× design peak).
  3. Return the busy page with a randomised component, so single probes do not reveal saturation.
  4. Document in 03 §9.
- **RESIDUAL RISK:** Tor-level PoW effort is inherently public.

### RVW-A-28 — Source-initiated deletion is not durable across intake disaster recovery
- **SEVERITY:** Low
- **SCENARIO:** A source deletes their mailbox (SW-15) or replies (SW-14), for example after fearing device seizure. The intake is later restored from BS-INTAKE (14-day retention), and C-09 "re-pushes all undelivered replies" (19 DR-P1). The deleted account and replies reappear, so anyone later holding the passphrase can read them.
- **AFFECTED:** 19 DR-P1, BS-INTAKE; 08 SW-14/15; 35 DEL-; ADR-025.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** Deletions are local to intake and deliberately not reported to core, and restores do not replay deletions.
- **PROPOSED FIX:**
  1. Maintain an intake-local append-only tombstone list of deleted `lookup_tag`/`reply_ref` hashes, included in BS-INTAKE and applied after any restore.
  2. C-09 re-push SHALL skip replies whose mailbox tombstone exists.
  3. Tombstones expire with the backup window.
- **RESIDUAL RISK:** Tombstone hashes reveal that a deletion occurred (not whose).

### RVW-A-29 — Public key-directory publication cadence reveals staff activity and investigative roster changes
- **SEVERITY:** Low
- **SCENARIO:** The full directory is served to anyone who reaches the onion, including the investigated organisation. MEK publications happen at Desk sync times, checkpoint issuance follows appends (07: "after each append batch ≤ 60 s" vs 04: "every 15 min–6 h", hour-granular `issued`), and roster changes are dated. Together these reveal when named-role investigators are online, and when a member was removed from a channel, which may itself signal that a report concerns them.
- **AFFECTED:** ADR-030; 04 §12.4, §14.3; 07 §5 (checkpoint cadence); 03 R-10.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** The directory is treated as public, non-sensitive data.
- **PROPOSED FIX:**
  1. Desks SHALL publish MEK entries only at a fixed daily slot (server-side batching of appends to one daily checkpoint for MEK entries).
  2. Reconcile checkpoint cadence to fixed intervals.
  3. Roster removals SHOULD be batched with routine changes, and entries carry day-only dates.
- **RESIDUAL RISK:** Weekly epoch structure remains visible.

### RVW-A-30 — Pixel channel is integrity-unchecked; a compromised converter VM can falsify evidence renderings
- **SEVERITY:** Low
- **SCENARIO:** A hostile file exploits the Stage 1 converter. It cannot exfiltrate anything (no NIC), but it can emit pixel frames that differ from the document: hiding passages, altering figures, or inserting investigator-targeted social-engineering content such as a fake instruction to contact someone. Investigators then act on falsified evidence (THR-037/THR-122) or are lured off-platform.
- **AFFECTED:** ADR-012; 10 §5.3, H5; 12 R05/R06.
- **WHY THE CURRENT SPEC DOES NOT PREVENT IT:** Stage 2 validates the frame format, not the fidelity of the rendering.
- **PROPOSED FIX:**
  1. Offer, and default ON for the HIGH profile, a dual-render check: two independent renderers (poppler and MuPDF) in separate fresh VMs, with a perceptual-hash comparison per page.
  2. Label renderings as "machine-rendered; verify against original in CL-3 before relying on details".
- **RESIDUAL RISK:** A common-mode bug in both renderers remains possible.

---

## 3. Answers to the review questions (cross-reference)

| Question | Answer (findings) |
|---|---|
| Residual metadata overlooked | Core WAL, backup and object-store import times (A-09); intake ctime/WAL (A-09 item 2); hour-granular draft expiry (A-02); notification existence per hour (A-19); unpadded uploads at the service uplink (A-22); size-class inconsistency (A-21); directory publication cadence (A-29); busy/queue oracle (A-27); DB joint uniqueness (A-26); error paths persisting text (A-02); DR resurrection (A-28). |
| Cross-document inconsistencies | Draft/session models and timers (A-02); size classes/CSP/cookie (A-21); egress, time, tor log retention, CDN (A-23); VR-3 embedded checkpoint vs identical app (A-08); VR-5 72 h vs THR-102 14 days (A-04); REL-007 vs SCM-042 (A-16); 12 host PNG decoding vs 10 (A-15); 11 "channel epoch key" (A-07); phantom attestation/digest/canary controls (A-01). **Resolution of the draft conflict:** RAM-only text drafts in C-07 (≤ 2 h), attachment parts as sealed ciphertext under a C-07-RAM-only draft key, no cookie-derived persistence, no passphrase or identity at rest, no sub-day time values (A-02). |
| Targeted/undetected malicious update | Identical artefacts plus transparency are strong for *releases*, but: third-party/OS packages bypass them (A-12); installed state is not externally verifiable and Fleet/ring policy can withhold patches (A-13); emergency path and jurisdiction concentration (A-16); bootstrap anchor (A-16). Needed controls: platform TUF target, SERVER_STATE entries, forced security floors, mandatory external witnesses/monitors, multi-jurisdiction targets/builders, diff-review attestations. |
| Compromised/compelled intake vs Tier W | Plaintext during window, passphrase at login leading to all replies, multi-report linkage, impersonation and COI ticks (A-03); detection claims unsupported (A-01); bounding via TEE-attested sealer with external verifier, passphrase rotation, reply minimisation, canary/incident entries (A-01, A-03); return-visit targeting (A-10); HNDL (A-11). |
| Tier W reliance on key-directory verification | No; the verifier is the sealer. Only after-the-fact Desk VR-9 and published integrity statements help (A-17, A-01). |
| ADR-030/033 anonymous slots vs directory manipulation | Slots are sound cryptographically. The weaknesses are governance and freshness: CIK holders include potentially accused members, there is no time lock or label certification (A-05), freeze/rollback with a core-supplied clock (A-04), follow-up drift to new members (A-06), pre-final sealing of drafts (A-07), confidentiality lost at import (A-18), FS pinning (A-20). Source-facing safeguards: "member since", change banners, follow-up subset rule, witness-fetched checkpoints (A-05, A-06, A-08). |
| Hostile attachments | Undefined L1 on Windows/macOS, host PNG decoding, webview/IPC exposure to hostile strings (A-15); managed endpoints (A-24); export beacons (A-25); rendering integrity (A-30). |
| Anonymous traffic reaching clearnet | No direct path found in the source request flow. Adjacent paths: client acquisition via app stores or the org's clearnet site (A-14); intake→monitor egress ambiguity with a mail-capable monitor host (A-23); C-37 CDN allowance (A-23). |
| Database record linkability | A-26, A-09, A-10 (routing-key linkage used prospectively), A-28. |

---

## 4. Things the design gets right

1. **Onion-only anonymous mode with no clearnet fallback** (ADR-001/002/003), enforced by host networking (`PrivateNetwork=yes`, loopback-only C-06/C-07, nftables default-drop) and by honest outage behaviour. The platform never receives source IPs by construction, which removes the most commonly compelled datum.
2. **Honest two-tier model** (ADR-004). The spec admits that no-JS web intake cannot protect against a live-compromised server, refuses to serve un-WEBCAT'd JavaScript (04 §24), and offers a reproducible, threshold-signed, Arti-embedding client as the content-protecting path.
3. **Recipient private keys only on hardware-bound endpoints** (ADR-007), with no browser recipient UI and no server-side unwrapping. That eliminates the GlobaLeaks/Hushmail-class total-compromise mode for stored content.
4. **Per-member epoch keys with source-driven COI exclusion applied before wrapping** (ADR-030), and **anonymous fixed-count slots with verifiable dummies** (ADR-033(1), 04 §13.2). Making conflict-of-interest exclusion cryptographic is unusual and valuable. The recipient list is verifiable at import (VR-9), and the design candidly documents the excluded-member inference residual.
5. **Epoch-key retirement gated on import** (ADR-033(2)) closes suppression-by-waiting, an attack most intake designs ignore.
6. **Core-initiated one-way relay** (ADR-009), a separate intake routing key, and a new random ID at import limit what a Z-INTAKE compromise yields and prevent cleartext case↔mailbox links in the core DB.
7. **Timing minimisation as schema-enforced policy** (ADR-010; 09 schema-lint L1–L12, `track_commit_timestamp=off`, UUIDv4-only rule, blob mtime normalisation, no last-seen/read markers). The residual ctime/WAL issue is openly documented.
8. **Size padding and fixed mailbox shape** (ADR-011; 32-entry mailboxes; padded responses; no compression).
9. **Evidence never parsed on servers; per-object disposable network-less VMs; pixels-only boundary; immutable originals plus derived working copies with transformation records** (ADR-012, 10). This matches best current practice (Dangerzone, SecureDrop Workstation lessons), and the malicious-server harness (ADR-027) with a single safe-path API addresses a recurring CVE class.
10. **Release security:** ≥ 2 independent reproducible builders, hybrid PQ threshold TUF, Sigsum logging with witnesses, cooling-period veto, no instance identity in update requests, client-side staged rollout, and identical artefacts for all customers (ADR-022, 33). The design is structurally resistant to Anom/SolarWinds-class targeted updates for Candor's own code.
11. **Key Directory with continuity rules, dual control and non-dismissable member notifications** (04 §14). It makes hidden-recipient insertion an attributable, logged act rather than a silent one.
12. **Privacy-preserving audit** (ADR-016: typed allow-list logging, no free text, SOURCE-SENSITIVE counters only with k-thresholds), and **content-free notifications** (ADR-017).
13. **Crypto hygiene:** HPKE with X-Wing, key-committing STREAM framing, deterministic CBOR with strict decoding, KATs, formal modelling planned (Tamarin/ProVerif), and 129-bit generated passphrases (no user-chosen secrets, no email/SMS recovery).
14. **Cryptographic erasure with a bounded backup tail** via the Erasure Key Vault (ADR-033(3)). "Delete" has a documented upper bound in backups.
15. **Honest language discipline** (DECISIONS §0) and extensive per-document residual-risk sections. Most weaknesses in this review were found *because* the spec documents its own limits. Where it fails, it is mainly through cross-document drift and through controls cited but not specified (RVW-A-01, -02, -21, -23).

---

## 5. Recommended ADR additions (consolidated)

| Proposed ADR | Closes |
|---|---|
| ADR-034 Tier W draft and session state (RAM-only text, single timer set) | A-02, A-07 |
| ADR-035 Sealer integrity evidence (TEE profile, attested K35, external verifier, operator canary, SEALER_ATTESTATION / SERVER_STATE / OPERATOR_STATEMENT / INCIDENT_NOTICE directory entries) | A-01, A-03, A-13, A-17 |
| ADR-036 Directory change governance (CIK holders = independent route, time-locked additions, certified labels, follow-up subset rule, mandatory external witnesses, independent intake time source, snapshot high-water mark) | A-04, A-05, A-06, A-08 |
| ADR-037 Arrival/import decoupling (tmpfs staging, slot writes, default periodic import, constant-schedule notifications) | A-09, A-19, A-29 |
| ADR-038 Metadata-private reply retrieval for Tier V (dead-drop fetch-all) | A-10 |
| ADR-039 Platform package supply chain and forced security floors | A-12, A-13, A-16 |
| ADR-040 Client acquisition as a metadata flow | A-14 |
| ADR-041 Desk containment per platform and webview isolation | A-15, A-24, A-30 |
