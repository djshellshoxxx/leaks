# R3 — Historical Incidents That Exposed Sources, Users or Whistleblowers

**Purpose:** Derive testable requirements for a high-assurance whistleblowing platform from real failures.
**Prepared:** 2026-09-30. **Method:** Web search on primary and credible secondary sources (court records, government and regulator releases, vendor postmortems, peer-reviewed papers, established outlets). Each block cites bibliography IDs `[B-INC-xx]` (see end).

**Verification conventions**
- Facts supported by a source retrieved in this research session carry that source's ID.
- **UNVERIFIED** marks a fact or URL that comes from the author's prior knowledge and could not be re-checked in this session. The session hit its web-search quota, and the egress proxy blocked direct fetches of many primary domains (justice.gov, usenix.org, eprint.iacr.org, wikipedia.org, ftc.gov, openwall.com). Re-verify these items before relying on them. No URL was invented. Where a URL could not be confirmed, the bibliography gives only title, venue and date.
- Corrections to the brief: the Yik Yak precise-location flaw was **2022**, not 2024. The Sky ECC decryption method was never officially detailed.

**Requirement ID scheme:** `REQ-H-xx` (H = historical). Each requirement uses "shall" and comes with a test. Architectural themes that recur across incidents are collected in §9.

---

## 1. Compelled or coerced providers ("the operator is the adversary")

### INC-01 — Hushmail compelled disclosure (Nov 2007) [B-INC-01][B-INC-02][B-INC-03]
- **What failed:** An "encrypted" webmail provider handed 12 CDs of decrypted mail from three accounts to the US DEA under a Canadian court order (MLAT).
- **Root cause:** Hushmail offered a server-side-encryption mode in which the user's passphrase was temporarily held on Hushmail servers. Hushmail also acknowledged that it could be compelled to serve a targeted user a modified Java applet (reported by Wired; exact quote UNVERIFIED).
- **Data exposed:** Plaintext email content.
- **Attacker capability:** Lawful order in the provider's jurisdiction. No cryptanalysis needed.
- **Why design didn't prevent it:** The key-handling code was delivered by the server on every session. Nothing let the user verify that the code was unchanged, so "end-to-end" held only while the operator was honest.
- **Lesson:** Server-delivered crypto code is equivalent to server-side keys against a compelled operator.
- **REQ-H-01:** The source client **shall** run cryptographic code only from a signed, reproducibly built, versioned artifact that the server cannot alter per user. Any code change **shall** require an update verified against a transparency log.
- **Test:** Serve a modified JS/WASM bundle from a test server with a valid TLS certificate. The client must refuse to execute it, and the refusal must be logged locally. Rebuild from source and compare the hash to the release in the transparency log.

### INC-02 — Lavabit TLS key compulsion (Jun–Aug 2013; 4th Cir. 16 Apr 2014) [B-INC-04][B-INC-05]
- **What failed:** The US government sought one user's (reportedly Snowden's) metadata and compelled Lavabit's TLS private key. That key protected the traffic of all ~400,000 users. Levison handed over the key as a 4-point-font printout and then shut down the service. He was held in contempt, and the Fourth Circuit affirmed.
- **Root cause:** A single long-lived server key covered every user's transport. The server also saw user passwords and plaintext at login and delivery.
- **Data exposed:** Potentially all users' session traffic, metadata and credentials.
- **Attacker capability:** Court order plus traffic capture or an active interception position.
- **Why design didn't prevent it:** The provider could technically comply. Nothing was end-to-end.
- **Lesson:** Design so that compliance with a key-disclosure order yields nothing useful and cannot affect users beyond the named target.
- **REQ-H-02:** No server-held key **shall** be able to decrypt submission content or any past session. Transport **shall** use forward-secret key exchange only, and submission content **shall** be encrypted to recipient keys the server never holds.
- **Test:** Give an auditor the full server key material and recorded traffic from a test session. The auditor must be unable to recover submission plaintext or any earlier session. Also scan the TLS configuration and confirm there are no non-forward-secret cipher suites.

### INC-03 — ProtonMail IP logging of French climate activist (disclosed Sep 2021) [B-INC-06][B-INC-07]
- **What failed:** Swiss authorities, acting on a French request routed through Europol, issued a binding order that required Proton to start logging the IP address of a Youth for Climate organizer's account. The activist was later arrested.
- **Root cause:** The provider could see client IPs at login and could be ordered to record them from that point on. The "no logs" claim described default behavior, not a technical impossibility.
- **Data exposed:** IP address and device information, which led to identity.
- **Attacker capability:** Lawful order in the provider's jurisdiction, obtained through mutual legal assistance.
- **Why design didn't prevent it:** Clients connected directly to the service over the clearnet. A policy is not a technical control.
- **Lesson:** Anything the server can see, it can be ordered to record in future. Minimize what is observable, not only what is stored.
- **REQ-H-03:** The source-facing interface **shall** be reachable as a Tor onion service, and the default source guidance **shall** require it. The application tier **shall** never receive a routable source IP address (the onion service terminates on loopback).
- **Test:** Submit through the onion service and capture every log and every header at the application tier. Assert that no source IP address, and no client IP in X-Forwarded-For or similar headers, appears anywhere. Repeat with a patched server that logs everything (the "compelled logging" scenario) and confirm only 127.0.0.1 or the Tor circuit is recorded.

### INC-04 — Tutanota compelled monitoring (Cologne Regional Court, Nov 2020) [B-INC-08][B-INC-09]
- **What failed:** A court ordered Tutanota to build a monitoring function for one account used in an extortion case. The order covered future *unencrypted* inbound and outbound mail. End-to-end encrypted mail was not affected.
- **Root cause:** Interoperable mail arriving from outside was plaintext at the server before being encrypted on arrival.
- **Data exposed:** Future non-E2EE mail of the target.
- **Attacker capability:** A domestic court order under telecom-surveillance law.
- **Why design didn't prevent it:** Encryption-at-rest after receipt is not end-to-end. The server sees content at ingress.
- **Lesson:** Every plaintext ingress path, including legacy email, is an interception point that can be compelled.
- **REQ-H-04:** The platform **shall** have no plaintext ingress path for source content. Email-to-platform, SMS and similar bridges **shall** be absent from the high-assurance tier or clearly labelled as low assurance, with a blocking warning.
- **Test:** Enumerate all ingress endpoints in the architecture inventory and by port scan. For each one, show that the server process receives only ciphertext (use memory and log capture with a canary plaintext).

### INC-05 — Proton Mail recovery email disclosed; Catalan activist identified (reported May 2024) [B-INC-10]
- **What failed:** Under Swiss legal assistance to Spain's Guardia Civil in a terrorism-labelled investigation, Proton disclosed a pseudonymous user's *recovery email*. That was an iCloud address, and Apple then supplied identifying information.
- **Root cause:** The user optionally linked an identity-bearing recovery channel. The provider stored it in a form it could disclose.
- **Data exposed:** Recovery email, then real identity through a second provider.
- **Attacker capability:** Two sequential lawful requests across jurisdictions.
- **Why design didn't prevent it:** Account-recovery convenience created a durable link from pseudonym to identity.
- **Lesson:** Recovery and notification channels are identity side-channels. Chained disclosure across providers defeats single-provider privacy.
- **REQ-H-05:** Source accounts **shall** have no recovery email, phone number or other identifier. Recovery **shall** rely only on a client-held secret (for example a generated passphrase or codename). The UI **shall** refuse to accept an email or phone field for sources.
- **Test:** Inspect the database schema and API. There must be no column or endpoint that accepts or stores a source contact identifier. A fuzzing test that submits an email in every field must show that none is persisted.

### INC-06 — Signal subpoena responses (2016 onward; positive counterexample) [B-INC-11]
- **What worked:** Across several US grand-jury subpoenas published on signal.org/bigbrother, Signal was able to produce only an account's creation timestamp and last-connection date.
- **Root cause of success:** Deliberate data minimization. No contact lists, group memberships, message content or profile data is held in a form the server can read. Sealed-sender designs and SGX-based contact discovery reduce metadata further.
- **Data exposed:** Two timestamps.
- **Attacker capability:** Subpoena or court order, with the same power as in INC-01 to INC-05.
- **Why design succeeded:** "Can't" instead of "won't".
- **Lesson:** Publish legal-process responses, and engineer so that the honest answer is almost empty.
- **REQ-H-06:** The platform **shall** maintain a documented "compelled-disclosure inventory" listing every datum the operator could produce under order. That list **shall** contain no source content, IP address, contact identifier or device fingerprint. Legal responses **shall** be published where the law permits.
- **Test:** Run a quarterly tabletop exercise. A red team with root on production and an order "for everything about codename X" extracts all data. The output must match the published inventory exactly.

### INC-07 — Riseup sealed warrants and gag order, lapsed canary (Nov 2016 – Feb 2017) [B-INC-12][B-INC-13]
- **What failed:** Riseup received two sealed FBI warrants (for accounts tied to a DDoS extortion ring and a ransomware operation) with gag orders. It complied after exhausting legal options. Its warrant canary silently lapsed, which caused months of uncertainty. Riseup then moved to encrypt all mailboxes at rest.
- **Root cause:** Mail was stored in a form the provider could access. Gag orders prevented users from being told.
- **Data exposed:** Content of the targeted accounts, as far as is publicly known.
- **Attacker capability:** Sealed warrant plus a non-disclosure order.
- **Why design didn't prevent it:** Server-readable storage. A canary is a signalling mechanism, not a protection.
- **Lesson:** Assume a secret order is always possible. Protection must be cryptographic, and the canary process must be automated and unambiguous.
- **REQ-H-07:** All stored source material **shall** be encrypted to keys held only on journalist or recipient endpoints, so that a sealed order served on the operator yields ciphertext only. If a canary is used, it **shall** be signed on a fixed schedule by a quorum of keys held in at least two jurisdictions, and a missed deadline **shall** alert users automatically.
- **Test:** Simulate a sealed order in which operators hand over the full storage snapshot, and attempt decryption. It must fail. Delay the canary signature past its deadline and verify that clients show the warning.

---

## 2. "Anonymous" apps, location and platform deanonymization

### INC-08 — Whisper tracks "anonymous" users (Guardian, Oct 2014) [B-INC-14][B-INC-15]
- **What failed:** The Guardian reported that Whisper staff used an in-house tool to geolocate posts to within about 500 m, including coarse location for some users who had opted out. Staff monitored "newsworthy" users such as military personnel and Capitol Hill staff, retained data indefinitely, and shared some with the US Department of Defense. Whisper disputed parts of the report, and the Guardian later clarified some claims (see CJR).
- **Root cause:** The operator collected and retained location and identifiers. Insiders had query access to deanonymize.
- **Data exposed:** Location histories linked to posts.
- **Attacker capability:** Operator or insider access, needing no exploit.
- **Why design didn't prevent it:** "Anonymous" meant only that no name was shown to other users. The operator still saw everything.
- **Lesson:** Anonymity must hold against the operator, not just against other users. Coarse location plus a posting history is identifying.
- **REQ-H-08:** The platform **shall not** request or accept device location, and **shall** strip location from all uploaded content before persistence. No staff tool **shall** exist that correlates sources across submissions except through the source's own codename.
- **Test:** Static analysis for OS location APIs and permission manifests: expect none. Upload geotagged files and confirm that the stored copies contain no GPS tags. Review admin tooling for cross-source queries.

### INC-09 — Yik Yak precise GPS exposure (reported Apr–May 2022) [B-INC-16][B-INC-17]
- **What failed:** A researcher found that the API returned GPS coordinates for every post, accurate to about 10–15 feet, together with stable user IDs. That allowed tracking a user's posts over time and locating homes.
- **Root cause:** The server sent raw data to the client and relied on the UI to hide it. The API and the UI had different threat models.
- **Data exposed:** Precise location and a linkable identifier per post.
- **Attacker capability:** Any user with a proxy or modified client.
- **Why design didn't prevent it:** Privacy was enforced only in the presentation layer.
- **Lesson:** Never send data to a client that the client should not have. Stable IDs turn single leaks into histories.
- **REQ-H-09:** APIs **shall** return only fields authorized for the caller's role. No persistent source identifier **shall** be exposed to any party other than the source and the assigned recipients.
- **Test:** API contract tests that diff every response schema against a role allow-list. A proxy-based test as a low-privilege user must show that no source ID, timestamp finer than policy allows, or location field is returned.

### INC-10 — Secret app "friend" deanonymization (Aug 2014) [B-INC-18][B-INC-19]
- **What failed:** Rhino Security Labs showed that creating an account whose contacts were seven fake addresses plus one target made every "from a friend" post attributable to the target.
- **Root cause:** Showing a crowd-derived label ("friend") without guaranteeing a minimum crowd size, so the attacker controlled the anonymity set.
- **Data exposed:** Authorship of anonymous posts.
- **Attacker capability:** Ability to create Sybil accounts and control one's own contact list.
- **Why design didn't prevent it:** No k-anonymity floor, and no detection of attacker-constructed sets.
- **Lesson:** Any feature that reveals a membership signal must enforce a minimum anonymity set that the attacker cannot manufacture.
- **REQ-H-10:** The platform **shall not** show recipients or other users any attribute of a source derived from group membership, social graph, organisation or proximity unless the anonymity set is at least k (≥ 50, configurable) *and* not attacker-constructible.
- **Test:** Sybil simulation: create k−1 controlled identities plus a target and confirm that no attribute is shown. Unit tests on the k-threshold logic.

### INC-11 — Blind exposed database (Dec 2018) [B-INC-20]
- **What failed:** An Elasticsearch/Kibana instance of the workplace "whistleblowing" app Blind was left without a password. It exposed private messages, posts, work emails (many in plaintext) and MD5 password hashes for about 10% of users, including executives.
- **Root cause:** A misconfigured backend data store, plus retention of real work emails next to pseudonymous content.
- **Data exposed:** Linkage of work email to posts and private messages.
- **Attacker capability:** An internet scan for open Elasticsearch/Kibana.
- **Why design didn't prevent it:** Identity (the work-email verification) and content were stored together, in plaintext, on a reachable server.
- **Lesson:** Verification data must not persist next to pseudonymous content. Observability tools are attack surface.
- **REQ-H-11:** The platform **shall not** retain any identity used for eligibility checks. If affiliation proof is ever needed, it **shall** use an unlinkable credential (for example blind signatures or anonymous credentials) and the raw identifier **shall** be discarded. No data store **shall** be reachable from the internet.
- **Test:** External scan with Shodan/masscan-style tooling for open datastore ports: expect none. Check the schema for identity columns. Cryptographic review shows the credential issuer cannot link issuance to redemption.

### INC-12 — Glassdoor grand-jury subpoena (9th Cir., 8 Nov 2017) [B-INC-21][B-INC-22]
- **What failed:** A federal grand jury investigating a VA contractor subpoenaed the identities of about 100 anonymous reviewers. The Ninth Circuit rejected Glassdoor's First Amendment challenge and required disclosure absent government bad faith.
- **Root cause:** The platform retained identifying data (emails, IP addresses) linked to anonymous posts. The legal privilege turned out to be weaker than users assumed.
- **Data exposed:** Reviewer identities (the scope was narrowed in negotiation).
- **Attacker capability:** Grand-jury subpoena.
- **Why design didn't prevent it:** It relied on legal defence rather than on not holding the data.
- **Lesson:** Legal privilege for anonymous speech is fragile. Data minimization is the only reliable shield.
- **REQ-H-12:** Legal-defence procedures **shall** be treated as secondary. The primary control **shall** be REQ-H-06, meaning no identifying data to produce. The platform's terms and source guidance **shall** state plainly what could be produced.
- **Test:** Same as REQ-H-06, plus a review that source-facing copy matches the compelled-disclosure inventory.

### INC-13 — Grindr location trilateration (2014, 2016) and commercial app-signal data outing a priest (Jul 2021) [B-INC-23][B-INC-24][B-INC-25]
- **What failed:** (a) Researchers showed that distance values, and even distance-sorted ordering with "show distance" disabled, allowed trilateration to within a few feet. (b) In 2021 The Pillar bought commercially available app-signal and location data, correlated it to a senior US Catholic official's device, and published his Grindr use. He resigned.
- **Root cause:** (a) Precise relative-location oracles. (b) Ad-tech SDKs or bid-stream data leaving the app, with "anonymized" advertising IDs that can be re-identified from home and work locations.
- **Data exposed:** Location, sexual orientation and movement history.
- **Attacker capability:** (a) Fake accounts with spoofed GPS. (b) Money and a data broker.
- **Why design didn't prevent it:** Sorting leaked what the UI hid. Third-party SDKs exported data outside the app's control.
- **Lesson:** Any oracle over a secret can be queried repeatedly to recover it. Third-party SDKs are data exfiltration by design.
- **REQ-H-13:** Source-facing clients **shall** include zero third-party SDKs (ads, analytics, crash reporting, attribution). The build **shall** fail if any dependency is on the prohibited-SDK list or makes network calls to non-platform hosts.
- **Test:** Dependency allow-list enforced in CI. Dynamic test that runs the client under a network sandbox and asserts that no DNS or TLS connection goes to hosts outside the platform's onion service or pinned host list.

### INC-14 — Anom / Operation Trojan Shield (2018–2021; unsealed 7–8 Jun 2021) [B-INC-26]
- **What failed:** Criminals adopted an "encrypted" phone platform that the FBI and AFP had covertly run through an informant. A master key copied every message to law enforcement. More than 12,000 devices were involved and more than 800 people were arrested.
- **Root cause:** Users trusted a closed-source, vendor-controlled platform whose operator was the adversary.
- **Data exposed:** All message content and metadata.
- **Attacker capability:** Owning the supply of the platform itself.
- **Why design didn't prevent it:** No independent verification of the code, keys or build. Trust rested on reputation spread by word of mouth.
- **Lesson:** A security product with a single operator and no verifiable openness is indistinguishable from a honeypot. Legitimate whistleblower platforms carry the same trust burden and must prove it.
- **REQ-H-14:** All client and server code **shall** be open source with reproducible builds. Releases **shall** be signed by a threshold of independent maintainers and recorded in a public transparency log. The client **shall** display which recipient keys a message is encrypted to, and **shall** reject any additional hidden recipient.
- **Test:** Reproduce the binary from the tag on two independent build hosts and confirm matching hashes. A protocol test injects an extra recipient key server-side, and the client must detect it and abort.

### INC-15 — EncroChat (infiltrated 2020; announced 2 Jul 2020) and Sky ECC (announced 10 Mar 2021) [B-INC-27][B-INC-28]
- **What failed:** A French/Dutch joint investigation team intercepted millions of EncroChat messages "over the shoulder" in real time. Public reporting describes an implant delivered to the handsets through the vendor's update infrastructure; Eurojust only states that messages were intercepted (implant mechanism UNVERIFIED). Sky ECC encryption was "unlocked" and about 70,000 users were monitored. The method was not officially disclosed (UNVERIFIED specifics).
- **Root cause:** A centralized, vendor-controlled update channel and server infrastructure within reach of law enforcement.
- **Data exposed:** Message content, contacts and locations.
- **Attacker capability:** Seizure or co-option of servers, and the ability to push updates to devices.
- **Why design didn't prevent it:** Endpoint trust derived from the vendor. Updates were not independently verified.
- **Lesson:** The update channel is the most powerful attack path. Endpoint compromise defeats end-to-end encryption.
- **REQ-H-15:** Client updates **shall** be accepted only if signed by an m-of-n threshold of release keys held by independent parties *and* present in an append-only transparency log that monitors watch. Per-device targeted updates **shall** be technically impossible (every client receives the same artifact hash).
- **Test:** Push a correctly signed but unlogged update, then a logged update signed by fewer than m keys. Both must be rejected. Split-view test: two clients comparing their log checkpoints must detect a forked log.

---

## 3. Document, metadata and human-process failures

### INC-16 — Reality Winner identified (May–Jun 2017) [B-INC-29][B-INC-30][B-INC-31][B-INC-32]
- **What failed:** The Intercept shared a copy or photos of the leaked NSA document with the government to authenticate it. The copy showed the Augusta, GA postmark area and fold creases, which indicated a hand-carried printout. NSA audit logs showed six people had printed it, and only Winner had emailed The Intercept (from a personal account on a work machine). Yellow printer tracking dots on the published scan encoded the printer serial number and print time (Errata Security, via [B-INC-30]; the dots were not cited in the affidavit). She was sentenced to 63 months. The Intercept acknowledged its practices "fell short".
- **Root cause:** Several at once: newsroom verification handling, the physical-document watermark, access logs at the source's organization, and the source's own earlier contact from a monitored device.
- **Data exposed:** Source identity.
- **Attacker capability:** The organization's own audit logs, plus a publication-side mistake.
- **Why design didn't prevent it:** No guidance on handling submitted documents or sanitizing them before verification and publication. Sources had no guidance on contact hygiene.
- **Lesson:** The recipient side is attack surface. Originals must never leave the secure environment. Every artifact shown to a third party (including a verification query) must be treated as a disclosure.
- **REQ-H-16:** Journalist workflows **shall** by default produce derived, sanitized renderings (re-rasterized, metadata-stripped, with tracking-dot and colour-channel removal and cropping of postal and handling marks). The UI **shall** require an explicit, logged two-person approval before any original or its image leaves the secure viewing station.
- **Test:** Feed a colour scan containing synthetic tracking dots and a postmark. The exported rendering must pass a dot detector (for example DEDA-style analysis) with no pattern and contain no postmark region. Attempting export without a second approver must be blocked.
- **REQ-H-16b:** Source onboarding **shall** warn against printing, using work devices or networks, and any previous contact from identifiable accounts, and **shall** state that organizations log access to documents.
- **Test:** UX review checklist, plus usability test comprehension ≥ 80%.

### INC-17 — BTK killer floppy disk metadata (Feb 2005) [B-INC-33]
- **What failed:** Dennis Rader sent police a floppy disk after being told it could not be traced. Forensic tools recovered a deleted Word file whose metadata said "Christ Lutheran Church" and last-modified-by "Dennis", which led to his arrest.
- **Root cause:** Residual deleted data on the medium, plus author and organization fields in document metadata.
- **Data exposed:** Name and organization.
- **Attacker capability:** Commodity forensic software (EnCase).
- **Why design didn't prevent it:** The user trusted assurances and did not know about slack space or metadata.
- **Lesson:** Files and media carry more than their visible content. Sanitize at the platform, not only in guidance.
- **REQ-H-17:** On receipt, the platform **shall** offer sources, and apply to recipients' working copies, automatic metadata removal (e.g., in the manner of MAT2/Dangerzone: author, organization, revision, template path, printer and device IDs). It **shall** keep the unaltered original only in encrypted cold storage, visible to a designated reviewer.
- **Test:** A corpus of Office, PDF, ODF, JPEG, HEIC and MP4 files seeded with known metadata canaries. After sanitization, a grep for all canaries returns zero. Deleted-content canaries in DOCX and PDF incremental saves are also absent.

### INC-18 — UK "dodgy dossier" Word metadata (Feb–Jun 2003) [B-INC-34][B-INC-35]
- **What failed:** 10 Downing Street published an Iraq dossier as a .doc file. Richard M. Smith extracted its revision log, which showed the usernames of editors (e.g., "cic22", "JPratt") and file paths identifying the officials who handled it. The dossier was also found to be partly plagiarized from a US researcher's thesis.
- **Root cause:** Publishing native editable formats with revision history.
- **Data exposed:** Internal author identities and workflow.
- **Attacker capability:** A hex editor or metadata tool.
- **Why design didn't prevent it:** Document-publication workflows had no sanitization step.
- **Lesson:** Native formats leak authorship chains, and this applies equally to documents whistleblowers submit.
- **REQ-H-18:** Any document a recipient exports or publishes from the platform **shall** be flattened (re-rendered to images or a normalized PDF/A with no revision history, comments, tracked changes, embedded objects or XMP data). Native formats **shall** be blocked from export by default.
- **Test:** Export a DOCX containing tracked changes, comments, a custom author and a hidden-text canary. The output must contain none of them, verified with exiftool, pdfinfo, qpdf --qdf and a text-extraction grep.

### INC-19 — Redaction by overlay: US Army Calipari report (May 2005) and Manafort filing (Jan 2019) [B-INC-36][B-INC-37][B-INC-38]
- **What failed:** Both PDFs "redacted" text with black boxes drawn over it, and the text underneath stayed selectable. A Bologna student recovered the classified parts of the US military report on the death of Italian agent Nicola Calipari. Journalists copy-pasted Manafort's filing and revealed that he had shared polling data with Konstantin Kilimnik.
- **Root cause:** A visual overlay instead of removing the content. No check after redaction.
- **Data exposed:** Classified names and procedures; confidential case facts.
- **Attacker capability:** Copy and paste.
- **Why design didn't prevent it:** The tooling allowed cosmetic redaction, with no automated verification.
- **Lesson:** Redaction must destroy the underlying bytes, and each redaction must be verified by machine.
- **REQ-H-19:** The platform's redaction tool **shall** rasterize redacted pages, or remove the text objects and glyphs under each redaction box, and **shall** refuse export until an automated verifier confirms that no redacted string is extractable (text layer, OCR of the raster, hidden layers, incremental-update history).
- **Test:** Redact known canary strings in a test PDF. Run pdftotext, qpdf decompression, an incremental-save scan and OCR on the output: zero canary hits. A regression corpus includes known failure patterns (annotations, overlays, form fields).

### INC-20 — EXIF GPS: Vice photo of John McAfee (3 Dec 2012) [B-INC-39]
- **What failed:** Vice published an iPhone 4S photo with its EXIF GPS intact, pinpointing a location in Izabal, Guatemala. McAfee was detained within days.
- **Root cause:** A publication pipeline with no metadata stripping.
- **Data exposed:** Precise location and device model.
- **Attacker capability:** Any EXIF viewer.
- **Why design didn't prevent it:** Nobody reviewed metadata before publication.
- **Lesson:** The same applies to photos that sources upload.
- **REQ-H-20:** Covered by REQ-H-17 and REQ-H-08. In addition, the source client **shall** strip EXIF, XMP, IPTC and MakerNote data *before* encryption and upload, and show the source what was removed.
- **Test:** Upload a photo with GPS, serial number and owner name. The encrypted payload, once decrypted by the test recipient, contains none of them. The UI shows the "removed" list.

### INC-21 — Chelsea Manning and Adrian Lamo (May–Jun 2010) [B-INC-40]
- **What failed:** Manning confided in hacker Adrian Lamo over chat. Lamo reported Manning to authorities and gave the logs to Wired and to federal investigators.
- **Root cause:** The source disclosed to an untrusted intermediary over a channel with no legal or journalistic protection.
- **Data exposed:** Identity and admissions.
- **Attacker capability:** A trusted-seeming human.
- **Why design didn't prevent it:** No guidance, and no path to a vetted recipient.
- **Lesson:** Human trust failures dominate. The platform must route sources to vetted recipients and discourage side channels.
- **REQ-H-21:** The platform **shall** show sources the verified identity (key fingerprint plus organizational attestation) of each recipient. It **shall** warn against moving the conversation to other channels. Recipient onboarding **shall** require the recipient organization's attestation.
- **Test:** UI test that a recipient without attestation cannot be selected. Copy review of the side-channel warning.

### INC-22 — Jes Staley / Barclays attempts to unmask a whistleblower (2016; FCA/PRA fines 11 May 2018) [B-INC-41]
- **What failed:** The Barclays CEO directed the bank's security team to identify the author of anonymous letters. The FCA and PRA fined him £642,430 in total and placed Barclays under special annual reporting requirements on whistleblowing.
- **Root cause:** The organization held tools (group security, access to US law enforcement and to postal and other data) and the motive to unmask. Whistleblowing-programme controls did not stop a senior manager.
- **Data exposed:** An attempted identification (reportedly unsuccessful).
- **Attacker capability:** An employer with investigative resources.
- **Why design didn't prevent it:** The channel belonged to the organization under scrutiny.
- **Lesson:** Model the organization being reported on as a well-resourced adversary with log access, legal pressure and insiders.
- **REQ-H-22:** The platform **shall** be operated independently of any organization about which it receives reports. Tenant customers **shall** have no access to infrastructure logs, network telemetry or operator staff. The platform **shall** keep an audit log of every access to source material, retained under the source-protection policy, reviewable by an independent ombudsperson, and never disclosed to the reported-on organization.
- **Test:** Access-control matrix test: a tenant-admin role cannot read infrastructure logs or access metadata. Review contractual and hosting separation.

### INC-23 — Richard Boyle (ATO whistleblower; raid 4 Apr 2018) [B-INC-42][B-INC-43]
- **What failed:** After Boyle made an internal public-interest disclosure and then spoke to ABC and Fairfax, the AFP and ATO raided his home, seized his and his fiancée's phones, and he was charged with 66 offences. The statutory protections did not prevent prosecution. (Later outcomes, including his guilty plea and sentencing, are reported by [B-INC-42]'s successors; UNVERIFIED here.)
- **Root cause:** An identified source. Evidence sat on personal devices. The legal regime was weak.
- **Data exposed:** Device contents and communications.
- **Attacker capability:** A search warrant on the source's premises and devices.
- **Why design didn't prevent it:** Nothing technical. The source was already known through the internal channel.
- **Lesson:** Internal disclosure channels that record identity create a trail. Evidence on sources' devices is seizable.
- **REQ-H-23:** The source client **shall** leave no persistent local artifacts: no stored drafts, history, cache or downloaded files beyond an explicitly exported codename. It **shall** be usable from an amnesic OS such as Tails. Guidance **shall** explain seizure risk.
- **Test:** Forensic image of the device before and after a full submission in the supported browser (Tor Browser, safest mode). Disk diff finds no submission content or codename. Run the same test in Tails.

### INC-24 — John Kiriakou (charged Jan 2012; plea Oct 2012) [B-INC-44][B-INC-45]
- **What failed:** Investigators obtained the email exchanges between the ex-CIA officer and reporters. Material a journalist shared with a third party (defence investigators) led back to Kiriakou. He was sentenced to 30 months.
- **Root cause:** Unencrypted email with journalists on identity-bearing accounts. Journalist-side onward sharing.
- **Data exposed:** Communications metadata and content.
- **Attacker capability:** Legal process against email providers.
- **Why design didn't prevent it:** Third-party email providers hold the records.
- **Lesson:** Journalist-side handling and metadata held by third parties are as dangerous as the source's own mistakes.
- **REQ-H-24:** Source–recipient communication **shall** happen only inside the platform. Recipients **shall** be prevented from forwarding source material or messages to external channels without a logged sanitization step (REQ-H-16, REQ-H-18).
- **Test:** Attempt to forward, export or copy without a sanitization record. The action must be blocked or logged with an approval.

### INC-25 (added) — Journalist call-record seizures: DOJ seizure of AP phone records (disclosed May 2013) — UNVERIFIED [B-INC-110]
- **What failed:** The US DOJ secretly obtained about two months of toll records for 20-plus AP phone lines in a leak investigation (from the author's knowledge; not re-verified this session).
- **Root cause:** Carrier-held call metadata of news organizations.
- **Data exposed:** Who called whom and when, identifying sources.
- **Attacker capability:** Subpoena to the telecom carrier.
- **Lesson:** Metadata held by third parties identifies sources even when content is protected.
- **REQ-H-25:** The platform **shall not** use phone numbers, SMS, carrier push or email for any source interaction or notification. Recipient notifications **shall** carry no source-specific content or timing correlation (batched, content-free).
- **Test:** Architecture review shows no telephony dependencies. Notification timing analysis shows batching at a fixed cadence regardless of submission time.

### INC-26 (added) — HP board-leak "pretexting" investigation (2006) — UNVERIFIED [B-INC-109]
- **What failed:** HP's chair authorized investigators to find a board leaker. Contractors obtained phone records of directors and journalists by pretexting (impersonation). This led to resignations and California charges (from the author's knowledge; not re-verified this session).
- **Root cause:** A motivated organization plus social engineering of carriers.
- **Lesson / REQ-H-26:** Any account-support process **shall** be unable to reveal or reset source access through identity claims (sources have no identity-based recovery; see REQ-H-05). Support staff **shall** have no tool that returns source metadata.
- **Test:** Red-team social-engineering exercise against support ("I'm the source, I lost my codename") must yield nothing.

---

## 4. Tor and anonymity-network failures

### INC-27 — FBI Freedom Hosting NIT (Aug 2013) [B-INC-46]
- **What failed:** After seizing Freedom Hosting, the FBI served JavaScript exploiting a Firefox 17 ESR bug (MFSA 2013-53) to Tor Browser users. The Windows payload ("Magneto") sent the real IP address, MAC address and hostname to a server in Virginia.
- **Root cause:** A browser memory-safety bug reachable through JavaScript. A seized server served the exploit. The exploit bypassed Tor with a direct connection.
- **Data exposed:** Real IP, MAC address and hostname.
- **Attacker capability:** Control of the site, plus a browser exploit.
- **Why design didn't prevent it:** JavaScript was enabled by default. There was no network-level isolation forcing all traffic through Tor.
- **Lesson:** Assume the server gets seized and then turned against its visitors. Minimize attack surface in the source's browser and fail closed at the network layer.
- **REQ-H-27:** The source interface **shall** work fully with Tor Browser's "Safest" security level (no JavaScript). The platform **shall** detect and warn when JavaScript is enabled, and **shall** serve a strict CSP that prevents inline or third-party script execution.
- **Test:** An end-to-end submission test in Tor Browser Safest mode passes. A CSP scanner reports no `unsafe-inline`, `unsafe-eval` or external origins.

### INC-28 — FBI Playpen NIT (20 Feb – 4 Mar 2015) [B-INC-47]
- **What failed:** The FBI ran a seized onion site for about two weeks and deployed a NIT to users who logged in, identifying IP addresses across roughly 100,000 visitors under a single EDVA warrant.
- **Root cause:** Operator seizure, plus a client exploit, plus the continued operation of the service by the adversary.
- **Data exposed:** Real IPs and host identifiers.
- **Attacker capability:** Seizure of the server; client exploit.
- **Why design didn't prevent it:** Users could not detect that the service had changed operator.
- **Lesson:** Design for the "seized and operated by the adversary" scenario. Clients should detect a change in server identity or code.
- **REQ-H-28:** Server-delivered content that runs in the source browser **shall** be limited to static HTML and CSS. Its hash **shall** be published in a transparency log. Journalist clients **shall** verify server-side attestations (e.g., signed deployment manifests) and alert when an unexpected deployment happens.
- **Test:** Deploy an unsigned change to the staging onion service. The monitors (journalist client plus an external monitor) raise an alert within N minutes.

### INC-29 — CMU/SEI "RELAY_EARLY" traffic-confirmation attack (30 Jan – 4 Jul 2014; advisory 30 Jul 2014) [B-INC-48][B-INC-49][B-INC-50]
- **What failed:** About 115 relays, attributed to Carnegie Mellon's SEI, used relay versus relay_early cells to tag onion-service descriptor lookups and confirm them at guards, deanonymizing onion-service users and operators. A court later confirmed that the FBI obtained SEI data by subpoena (the Farrell case, Silk Road 2).
- **Root cause:** Protocol signalling channel, plus an adversary running many guards and HSDirs.
- **Data exposed:** Mapping from client IP to the onion service visited.
- **Attacker capability:** Operating a significant fraction of relays for months.
- **Why design didn't prevent it:** Tor does not claim to defeat an adversary that sees both ends of a circuit. Sybil detection was slow.
- **Lesson:** Tor is a necessary layer, not sufficient on its own. Minimize linkable repeat visits and long sessions.
- **REQ-H-29:** The platform **shall** follow current Tor Project onion-service guidance (v3, vanguards or equivalent full-vanguards protection where supported), **shall** track tor security advisories with a patch SLA of 72 hours or less, and **shall** minimize the number of source round trips needed to check replies.
- **Test:** Configuration audit (tor version, vanguards enabled). An advisory-response drill measures time-to-patch.

### INC-30 — KAX17 malicious relay operator (2017–2021; reported Dec 2021) [B-INC-51]
- **What failed:** An unknown actor ran hundreds of relays with no contact information, mainly guard and middle relays. At its peak there was about a 16% chance of choosing a KAX17 guard and about 35% of a KAX17 middle relay.
- **Root cause:** Open relay admission. Sybil detection depends on volunteer analysis.
- **Data exposed:** Potential circuit mapping (intent not proven).
- **Attacker capability:** Moderate budget and persistence.
- **Lesson:** The network-level adversary can control a large share of Tor. Layer defences and limit what a successful deanonymization reveals.
- **REQ-H-30:** Deanonymizing the network layer alone **shall not** reveal submission content or link separate submissions of one source (content is end-to-end encrypted, and codename-based conversations do not persist a network identifier). The threat model **shall** state explicitly that Tor deanonymization reveals "this IP address visited the platform".
- **Test:** Threat-model review. Protocol test showing that two submissions from the same source with different codenames have no shared server-side identifier.

### INC-31 — Eldo Kim, Harvard bomb threat (Dec 2013) [B-INC-52][B-INC-53]
- **What failed:** Kim used Tor and Guerrilla Mail from Harvard's wifi. Harvard's logs showed which users connected to Tor during the window. Kim was one of very few, and he confessed when questioned.
- **Root cause:** A tiny anonymity set on a monitored network. Tor use itself is visible to the local network.
- **Data exposed:** The fact of Tor use at a time, which was enough to identify him.
- **Attacker capability:** Local network logs plus timing correlation.
- **Why design didn't prevent it:** Tor hides destinations, not the fact that Tor is in use. The source used their own institution's network.
- **Lesson:** Instruct sources never to use the reported-on organization's network or devices. Bridges and pluggable transports hide Tor use.
- **REQ-H-31:** Source guidance **shall** state prominently that the employer's network and devices must never be used, and **shall** recommend bridges (e.g., obfs4/Snowflake) where Tor use is conspicuous. The platform **shall not** create time correlation by, for example, sending recipient alerts that the reported-on organization could observe.
- **Test:** Guidance review. A notification-timing test (see REQ-H-25).

### INC-32 — Ross Ulbricht / Silk Road opsec (2011 posts; arrest Oct 2013) [B-INC-54][B-INC-55]
- **What failed:** The early promotional posts by "altoid" on Shroomery and Bitcointalk included, in one later post, rossulbricht@gmail.com. An IRS agent's Google search linked the two.
- **Root cause:** Reusing a pseudonym across contexts and mixing identities.
- **Data exposed:** Real identity.
- **Attacker capability:** A search engine.
- **Lesson:** Pseudonym compartmentalization fails through human linkage. The platform must not encourage reusable identities.
- **REQ-H-32:** Codenames **shall** be generated randomly by the platform (never chosen by the user), unique per submission thread, and never shown publicly. Sources **shall** be warned against reusing any handle.
- **Test:** Unit test: codenames come from a CSPRNG with ≥ 80 bits of entropy, and the UI cannot accept user-chosen codenames.

### INC-33 — Silk Road server real-IP leak (2013; described in Tarbell declaration, Sep 2014) [B-INC-58][B-INC-59]
- **What failed:** The FBI claimed that a CAPTCHA or login component leaked the hidden service's real IP address. Experts (Krebs, Weaver, Errata) found that the explanation did not match the published nginx configuration, but the configuration did show services reachable on the clearnet IP.
- **Root cause:** An onion service whose web server also answered on the public interface, so it could be reached or fingerprinted outside Tor.
- **Data exposed:** Server location, leading to imaging of the server.
- **Attacker capability:** Internet scanning or probing.
- **Lesson:** Onion-service servers must be unreachable except through tor.
- **REQ-H-33:** Onion-service backends **shall** bind only to loopback or a Unix socket, **shall** have no public IPv4 or IPv6 interface in the application namespace, and **shall** make outbound connections only through tor (egress default-deny).
- **Test:** From the internet, scan the host's public IPs: no service banner. On the host, `ss -ltnp` shows listeners only on 127.0.0.1 or ::1 or Unix sockets. An egress firewall test confirms a direct outbound connection fails.

### INC-34 — Onion-service misconfiguration: Apache mod_status and other leaks (OnionScan 2016) [B-INC-60][B-INC-61]
- **What failed:** About 6% of onion sites exposed `/server-status`, because Tor traffic arrives from localhost. That revealed clearnet vhosts, client IPs and co-hosted sites. One case exposed a drug site hosted alongside the operator's legitimate business.
- **Root cause:** Defaults that trust localhost; co-hosting.
- **Data exposed:** Server IP, co-hosted domains, visitors.
- **Attacker capability:** An HTTP GET request.
- **Lesson:** Localhost is not a trust boundary on an onion host. Never co-host.
- **REQ-H-34:** The platform **shall** run on dedicated hosts with no co-hosted services. Status and debug endpoints **shall** be disabled. Error pages, headers and TLS certificates **shall** contain no hostnames or IPs.
- **Test:** OnionScan-class automated scan in CI and weekly in production: no status pages, no clearnet identifiers in headers, SSH banners, certificates or HTML.

### INC-35 — Ricochet user "Boystown" admin deanonymized via timing / guard discovery (German BKA; reported Sep 2024) [B-INC-56][B-INC-57]
- **What failed:** German police, according to reporting by NDR/Panorama and analysis reviewed by CCC experts, repeatedly used timing analysis over surveillance of Tor relays to identify the guard of a Ricochet (long-retired) user and then obtained the user's identity from the ISP. The Tor Project assessed this as a guard-discovery attack against old Ricochet, which lacked vanguards.
- **Root cause:** An outdated client without guard-discovery protections. A long-lived, always-on onion service that was repeatedly observable.
- **Data exposed:** Real identity of the onion-service operator (user).
- **Attacker capability:** Surveillance of many relays (state level) over months.
- **Lesson:** Long-lived client-side onion services and unmaintained clients are high risk.
- **REQ-H-35:** Sources **shall not** be required to run a persistent onion service or any always-on client. Any bundled client component **shall** have an end-of-life policy and refuse to run once past it.
- **Test:** Architecture review. A client with an expired support date blocks with an update prompt.

### INC-36 — Tor Browser leaks: TorMoil file:// (Oct–Nov 2017) and scheme-flooding fingerprint (2021) [B-INC-62][B-INC-63][B-INC-64]
- **What failed:** TorMoil: `file://` links on macOS and Linux made the OS connect directly, bypassing Tor (fixed in Tor Browser 7.0.8). Scheme flooding: probing custom URL handlers built a ~32-bit cross-browser identifier that worked even in Tor Browser (mitigated in 10.0.18).
- **Root cause:** Interactions between the browser and the OS outside the proxy boundary.
- **Data exposed:** Real IP; a stable device fingerprint.
- **Attacker capability:** A malicious web page.
- **Lesson:** Browser-level anonymity has edge cases. Page content should never be adversarial, and should not require features that expand attack surface.
- **REQ-H-36:** The source interface **shall** contain no external links, custom URL schemes, `file:` URIs or active content. The server **shall** reject submitted files for in-browser preview.
- **Test:** HTML lint for disallowed schemes and attributes. A security-header test (CSP `default-src 'self'`, no `object-src`, `form-action 'self'`).

---
