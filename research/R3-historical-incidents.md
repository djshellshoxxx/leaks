# R3 — Historical Incidents That Exposed Sources, Users or Whistleblowers

**Purpose:** Derive testable requirements for a high-assurance whistleblowing platform from real failures.
**Prepared:** 2026-09-30. **Method:** Web search on primary and credible secondary sources (court records, government and regulator releases, vendor postmortems, peer-reviewed papers, established outlets). Each block cites bibliography IDs `[B-INC-xx]` (see end).

**Verification conventions**
- Facts supported by a source retrieved in this research session carry that source's ID.
- **UNVERIFIED** marks a fact or URL that comes from the author's prior knowledge and could not be re-checked in this session. The session hit its web-search quota, and the egress proxy blocked direct fetches of many primary domains (justice.gov, usenix.org, eprint.iacr.org, wikipedia.org, ftc.gov, openwall.com). Re-verify these items before relying on them. No URL was invented. Where a URL could not be confirmed, the bibliography gives only title, venue and date.
- Corrections to the brief: the Yik Yak precise-location flaw was **2022**, not 2024. The Sky ECC decryption method was never officially detailed.

**Requirement ID scheme:** `REQ-H-xx` (H = historical). Each requirement uses "shall" and comes with a test. Architectural themes that recur across incidents are collected in §10.

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
## 5. Software supply-chain compromises

### INC-37 — xz-utils backdoor, CVE-2024-3094 (disclosed 29 Mar 2024) [B-INC-65][B-INC-66]
- **What failed:** Over about two years, a maintainer persona ("Jia Tan") gained commit rights to xz. The persona hid a backdoor in test fixtures and in the release tarball's build scripts (the backdoor was not in the git tree). On distros that link sshd through libsystemd, the compromised liblzma 5.6.0 and 5.6.1 hooked RSA verification, giving pre-auth remote code execution to the holder of the attacker's key. Andres Freund found it because of a ~500 ms sshd slowdown.
- **Root cause:** Social engineering of an overloaded single maintainer. Release tarballs differed from source control. Build-time obfuscation. A transitive dependency pulled into sshd.
- **Data exposed:** None known. It was caught before stable distros shipped it.
- **Attacker capability:** Patient, state-level social engineering.
- **Why design didn't prevent it:** Distros built from maintainer-supplied tarballs, with no reproducibility check against VCS.
- **Lesson:** Build from source control, verify tarball-to-git equivalence, and minimize the transitive dependencies of privileged daemons.
- **REQ-H-37:** Production images **shall** be built from pinned VCS commits (not upstream tarballs) in hermetic, reproducible builds. For every privileged daemon (sshd, tor, web server), a reviewed transitive-dependency manifest **shall** fail the build if it changes.
- **Test:** Two independent reproducible builds give the same image digest. Adding a new shared-library dependency to sshd or tor fails CI.

### INC-38 — SolarWinds Orion SUNBURST (discovered Dec 2020; CISA ED 21-01 of 13 Dec 2020) [B-INC-67]
- **What failed:** Attackers compromised the SolarWinds build system and inserted a backdoor into signed Orion updates (2019.4 to 2020.2.1 HF1). Victims included US federal agencies.
- **Root cause:** Build-environment compromise. The signature certified the build system, not the source.
- **Data exposed:** Network access to thousands of customers, then email and identity systems at selected targets.
- **Attacker capability:** State-level (attributed to Russia's SVR).
- **Why design didn't prevent it:** Code signing happened after the point of injection. There was no reproducible-build cross-check.
- **Lesson:** Signing a build from a compromised builder only authenticates the compromise.
- **REQ-H-38:** Releases **shall** be signed only if ≥ 2 independent builders on separate infrastructure produce bit-identical artifacts (SLSA Build L3 or higher). Monitoring and management agents with broad network privileges **shall not** run in the source-data enclave.
- **Test:** A CI gate compares the artifacts of two builders, and the release job fails on any mismatch. Inventory audit: no third-party management agent is in the enclave.

### INC-39 — Codecov Bash Uploader (31 Jan – 1 Apr 2021) [B-INC-68]
- **What failed:** A credential leaked from Codecov's Docker image-build process let attackers modify the curl-piped Bash Uploader. The modified script exfiltrated CI environment variables (tokens and keys) to attacker IPs.
- **Root cause:** A mutable, unverified script fetched at runtime (`curl | bash`), plus secrets exposed in CI environments.
- **Data exposed:** CI secrets of many customers.
- **Attacker capability:** Stealing one publishing credential.
- **Lesson:** Never execute unpinned remote code in CI. Keep secrets out of broad environments.
- **REQ-H-39:** CI **shall not** fetch and execute unpinned remote scripts. Every external tool **shall** be pinned by hash. Secrets **shall** use short-lived OIDC-issued credentials scoped per job, never long-lived environment variables.
- **Test:** A lint rule rejects `curl|sh` patterns and unpinned downloads in the pipeline. A secret-scanning check finds no long-lived tokens in the CI configuration.

### INC-40 — event-stream / flatmap-stream (Sep–Nov 2018) [B-INC-69]
- **What failed:** The original maintainer handed publishing rights to a volunteer, who added a malicious dependency. It targeted the Copay wallet build and stole keys from wallets with large balances.
- **Root cause:** Maintainer succession with no vetting. Encrypted payload triggered only in the target's build.
- **Data exposed:** Wallet private keys.
- **Attacker capability:** Social engineering; patience.
- **Lesson:** A targeted payload is invisible to general testing. Dependency updates are code changes from strangers.
- **REQ-H-40:** Every new dependency or version bump in client or server code **shall** require human review of the diff (for example with a vendoring or crev-style review record). Maintainer-change events **shall** trigger re-review.
- **Test:** CI blocks a lockfile change that has no linked review record. An automated alert fires on an upstream maintainer change for pinned packages.

### INC-41 — 3CX cascading supply-chain attack (discovered 29 Mar 2023) [B-INC-70]
- **What failed:** A 3CX employee installed a trojanized X_TRADER (itself a supply-chain victim) on a personal computer. The attackers moved laterally into 3CX's Windows and macOS build environments and shipped signed, trojanized 3CX desktop apps.
- **Root cause:** Personal-device compromise leading into corporate systems and then into build systems. The first software supply-chain attack known to have led to a second one.
- **Attacker capability:** State-level (attributed to a DPRK group, UNC4736).
- **Lesson:** Developer endpoints are part of the supply chain.
- **REQ-H-41:** Release-signing and build infrastructure **shall** be reachable only from dedicated, managed, hardware-key-authenticated admin workstations. Personal devices **shall** be technically barred from those networks.
- **Test:** Access review. An attempt from an unmanaged device is rejected by device attestation. A hardware-key-only authentication policy is enforced.

### INC-42 — ua-parser-js hijack (22 Oct 2021) [B-INC-71]
- **What failed:** The maintainer's npm account was hijacked. Versions 0.7.29, 0.8.0 and 1.0.0 dropped a cryptominer and a credential stealer during a window of about four hours.
- **Root cause:** A single-factor or compromised registry account. Install scripts ran automatically.
- **Lesson / REQ-H-42:** Package installation in builds **shall** run with lifecycle scripts disabled (`--ignore-scripts` or equivalent) except for an allow-list. Dependencies **shall** be resolved only from a lockfile with integrity hashes.
- **Test:** CI verifies that the install flags and lockfile integrity are enforced. A malicious postinstall test package fails to execute.

### INC-43 — PyPI and npm typosquatting (ongoing; e.g., PyPI suspended registrations, Mar 2024) [B-INC-72]
- **What failed:** Waves of look-alike packages stole credentials, wallets and browser data. PyPI temporarily halted new registrations and projects.
- **Root cause:** Open registries, name confusion and human typos.
- **Lesson / REQ-H-43:** Builds **shall** resolve dependencies only from an internal mirror with an allow-list of approved package names and hashes. New names **shall** require approval.
- **Test:** Adding `reqeusts` (a typo) to the manifest fails CI with "not on allow-list".

### INC-44 — tj-actions/changed-files, CVE-2025-30066 (Mar 2025) [B-INC-73]
- **What failed:** Attackers repointed the Action's version tags to a malicious commit that printed CI secrets into the workflow logs. The logs were public for public repositories. About 23,000 repositories used the Action.
- **Root cause:** Mutable git tags used as dependency pins. Secrets available to third-party Actions.
- **Lesson / REQ-H-44:** CI **shall** reference third-party Actions or plugins only by full commit SHA, **shall** grant minimum token permissions, and **shall** keep build logs private with secret-masking verified.
- **Test:** A lint rule (e.g., a policy check) rejects `uses: x@vN` tags. A log-scan job for high-entropy strings finds none.

### INC-45 — "Shai-Hulud" self-replicating npm worm (Sep 2025) [B-INC-74]
- **What failed:** Malware in compromised packages harvested GitHub PATs and cloud keys, then used the stolen npm tokens to inject itself into more packages and republish them. More than 500 packages were affected.
- **Root cause:** Long-lived publishing tokens on developer machines. Automated republish without additional authentication.
- **Lesson / REQ-H-45:** Publishing of platform packages **shall** require phishing-resistant MFA or trusted-publishing (OIDC) from CI only. No long-lived publish token **shall** exist on developer machines.
- **Test:** Registry settings audit. An attempt to publish from a developer laptop with a token fails.

### INC-46 — Polyfill.io CDN takeover (disclosed 25 Jun 2024) [B-INC-75]
- **What failed:** A new owner (Funnull) of the polyfill.io domain and CDN served malicious, targeted JavaScript to more than 100,000 sites that embedded it.
- **Root cause:** Third-party script included by URL with no Subresource Integrity (SRI). Domain ownership changed hands.
- **Lesson / REQ-H-46:** Pages **shall** load no script, style or font from any third-party origin. All assets **shall** be self-hosted, hashed and covered by CSP.
- **Test:** A crawler plus CSP report-only telemetry in staging show zero external origins.

### INC-47 — Ledger Connect Kit (14 Dec 2023) [B-INC-76]
- **What failed:** A former employee's npm account, still able to publish, was phished (the session token bypassed 2FA). Malicious versions 1.1.5–1.1.7 injected a wallet drainer into dApps that loaded the kit from a CDN. Losses were about US$600k.
- **Root cause:** Access not revoked on offboarding. Dependents loaded "latest" at runtime.
- **Lesson / REQ-H-47:** Access to publishing and infrastructure **shall** be revoked automatically when a person leaves (HR-driven). A quarterly access review **shall** reconcile publisher lists.
- **Test:** An offboarding drill: within 1 hour of an HR termination event, registry, git and cloud access are gone.

### INC-48 — CCleaner 5.33 signed backdoor (Aug–Sep 2017) [B-INC-77]
- **What failed:** A compromised build or distribution environment shipped a validly signed CCleaner with a backdoor to about 2.27 million users. A second-stage payload targeted technology companies.
- **Lesson / REQ-H-48:** Same as REQ-H-38. In addition, the platform **shall** publish release hashes on independent channels (transparency log, a second domain, a signed announcement) so that users can verify them out of band.
- **Test:** The release checklist verifies that the hash appears on ≥ 2 independent channels.

### INC-49 — NotPetya via M.E.Doc updates (Apr–Jun 2017) [B-INC-78]
- **What failed:** Attackers used stolen admin credentials to backdoor M.E.Doc's update server. Backdoored updates were pushed in April, May and June 2017, and a destructive wiper was deployed on 27 June 2017.
- **Root cause:** An insecure update server with no code signing of updates and a weak admin credential.
- **Lesson / REQ-H-49:** Covered by REQ-H-15. Update-serving infrastructure **shall** be separate from signing keys, so that compromising the update server can only cause denial of service.
- **Test:** Replace the update-server contents with a validly formatted but unsigned or unlogged update. Clients reject it.

### INC-50 — Juniper ScreenOS Dual_EC and SSH backdoor (announced Dec 2015) [B-INC-79]
- **What failed:** Unauthorized code changed the Dual_EC Q point, which enabled passive VPN decryption, and added a hard-coded SSH password. Checkoway et al. showed the product had been passively exploitable, by whoever chooses Q, since a 2008 release.
- **Root cause:** A backdoorable RNG design plus insider or source-repository compromise.
- **Lesson / REQ-H-50:** The platform **shall** use only well-analysed CSPRNGs (the OS `getrandom`) and **shall not** use any RNG with an unexplained constant. Security-critical source files **shall** require two-person review, and signed commits **shall** be enforced.
- **Test:** A code search forbids any other RNG. Branch protection requires two reviewers and signed commits on the crypto paths.

### INC-51 — Debian OpenSSL predictable RNG, CVE-2008-0166 (2006–2008; DSA-1571-1, 13 May 2008) [B-INC-80]
- **What failed:** A Debian patch that silenced a Valgrind warning removed entropy mixing. For about 20 months, all OpenSSL-generated keys on Debian and Ubuntu came from a space of about 32,768 values (seeded by PID). This covered SSH, TLS, OpenVPN and DNSSEC keys.
- **Root cause:** A downstream patch to crypto code with no review by upstream crypto experts.
- **Lesson / REQ-H-51:** Key generation **shall** include known-answer and statistical sanity tests at startup. Generated public keys **shall** be checked against known weak-key blocklists (Debian weak keys, ROCA fingerprint).
- **Test:** Inject a deterministic RNG in a test build. The startup self-test fails closed. The ROCA and Debian blocklist detector flags seeded test keys.

### INC-52 — Linux Mint ISO compromise (20 Feb 2016) [B-INC-81][B-INC-82]
- **What failed:** Attackers breached the website and pointed download links to a backdoored ISO. The site published only MD5 checksums, which were hosted on the same compromised server.
- **Root cause:** Integrity metadata co-hosted with the artifact, with no signature.
- **Lesson / REQ-H-52:** Covered by REQ-H-48. Download pages **shall** give signature-verification instructions (key fingerprint published out of band) and never rely on a same-origin hash.
- **Test:** Documentation review. A simulated site compromise that swaps both the artifact and the hash is detected by signature verification.

---

## 6. Telemetry, logging, third parties and cloud

### INC-53 — Meta Pixel on hospital sites (Jun 2022) and tax-filing sites (Nov 2022) [B-INC-83][B-INC-84]
- **What failed:** The Markup found the Meta Pixel on 33 of Newsweek's top 100 US hospital sites, some inside patient portals, sending appointment and medication details. H&R Block, TaxAct and TaxSlayer sent income, refund and dependent data to Meta.
- **Root cause:** Marketing scripts added to sensitive flows. Automatic form-field capture.
- **Data exposed:** Health and financial data joined to Facebook identities.
- **Attacker capability:** Being the third-party script vendor, or anyone who compels that vendor.
- **Lesson:** Any third-party script in a sensitive page is a full-content wiretap.
- **REQ-H-53:** Covered by REQ-H-13 and REQ-H-46. In addition, the public marketing site **shall** be hosted separately from the submission interface, with no shared cookies or scripts, and with no analytics that identify visitors.
- **Test:** A crawler for tracker signatures across all platform origins. A cookie-scope test.

### INC-54 — Cloudbleed (13–18 Feb 2017; reported 23 Feb 2017) [B-INC-85]
- **What failed:** A Cloudflare HTML-parser bug leaked uninitialized memory into responses, including other sites' cookies, auth tokens and POST bodies. Some of it was cached by search engines.
- **Root cause:** Memory-unsafe edge code. A shared multi-tenant proxy that sees plaintext.
- **Data exposed:** Cross-customer secrets.
- **Lesson:** A CDN or WAF that terminates TLS is a plaintext intermediary: it can be compelled, it can have bugs, and it can be breached.
- **REQ-H-54:** No third-party proxy, CDN or WAF **shall** terminate TLS for, or otherwise see, source-facing traffic. The onion service **shall** be the primary source path. Any clearnet landing page **shall** be static and carry no submission functionality.
- **Test:** Architecture diagram review. The TLS certificate and DNS show no CDN on the submission path. An onion-only submission endpoint returns 403 over the clearnet.

### INC-55 — LastPass backup theft (Aug–Dec 2022) [B-INC-86]
- **What failed:** Using data from an August breach, the attacker compromised a DevOps engineer's home computer, obtained cloud keys and copied backups, including encrypted vaults. Vault URLs were unencrypted metadata. Weak or old master-password iterations increased the offline cracking risk.
- **Root cause:** Backups with production-equivalent sensitivity but weaker access control. Unencrypted metadata. Low KDF work factors for legacy accounts.
- **Lesson:** Backups are production. Any field not end-to-end encrypted will eventually leak.
- **REQ-H-55:** Backups **shall** contain only data already end-to-end encrypted to recipient keys, and **shall** be encrypted again under keys held in an HSM with m-of-n custody. No source-related metadata (timestamps, sizes, codename hashes) **shall** be stored unencrypted in backups beyond what the compelled-disclosure inventory allows.
- **Test:** Restore a backup to an isolated host without the HSM quorum: nothing is readable. Diff the backup-content inventory against REQ-H-06.

### INC-56 — Okta support-system breach via HAR files (28 Sep – 17 Oct 2023) [B-INC-87]
- **What failed:** An Okta employee saved service-account credentials in a personal Google profile on a work laptop. The attacker accessed the support system and extracted session tokens from customer-uploaded HAR files, then hijacked sessions at 5 customers.
- **Root cause:** Support artifacts containing live secrets. Personal-profile sync on managed devices.
- **Lesson:** Diagnostic uploads (HAR files, logs, crash dumps, screenshots) carry secrets. Support tooling is a privileged system.
- **REQ-H-56:** The platform **shall** never request or accept HAR files, logs or screenshots from sources. Journalist-side diagnostic bundles **shall** be automatically scrubbed of tokens, cookies and content before leaving the device. Support staff **shall** have no access to production data.
- **Test:** Generate a diagnostic bundle containing canary tokens: after scrubbing, zero canaries remain.

### INC-57 — Push-notification metadata demanded from Apple and Google (Wyden letter, Dec 2023) [B-INC-88][B-INC-89]
- **What failed:** Senator Wyden disclosed that governments were demanding push-notification records (which app and account received notifications, and when). Apple said it had been prohibited from disclosing this and began reporting push-token requests.
- **Root cause:** A centralized push infrastructure (APNs/FCM) that sees the metadata of every notification. Push tokens are linkable to an Apple or Google account.
- **Data exposed:** App usage, timing, and account identity.
- **Lesson:** Push notifications are a third-party metadata channel even when their content is encrypted.
- **REQ-H-57:** Source clients **shall not** use APNs, FCM or any third-party push service. Sources **shall** check for replies by polling over Tor at a jittered, fixed cadence. Journalist push notifications, if used, **shall** be content-free, batched and not triggered per submission.
- **Test:** Static analysis finds no push SDK or entitlement in the source client. Network capture shows no push endpoints. Timing test as REQ-H-25.

### INC-58 — Storm-0558 signing key via crash dump (key-exposure chain from Apr 2021; MSRC report 6 Sep 2023, revised Mar 2024) [B-INC-90]
- **What failed:** Microsoft's September 2023 hypothesis was that a consumer MSA signing key ended up in a crash dump through a race condition, was not detected by credential scanning, and was moved to an internet-connected debugging environment, where the actor stole it through a compromised engineer account. In March 2024 Microsoft said it had not found a crash dump containing the key, so the exact path remains uncertain.
- **Root cause:** Key material in process memory flowing into diagnostics. Weak segmentation.
- **Lesson:** Crash reports and core dumps are key-exfiltration channels.
- **REQ-H-58:** Processes handling keys or plaintext **shall** disable core dumps (`RLIMIT_CORE=0`, `prctl(PR_SET_DUMPABLE,0)`), lock key memory, and never send crash reports off-host. Long-term signing keys **shall** live only in HSMs.
- **Test:** Crash the key-handling process with SIGSEGV: no core file is produced and no crash upload occurs. HSM audit shows the key cannot be exported.

### INC-59 — Cloud-storage exposures: Deep Root Analytics S3 (Jun 2017) and Microsoft AI SAS token (2020–2023) [B-INC-91][B-INC-92]
- **What failed:** An RNC contractor left 1.1 TB of profiles on 198 million voters in a public S3 bucket. Microsoft AI researchers published a SAS token that granted full-control access to an entire storage account (38 TB, including workstation backups and more than 30,000 Teams messages), with an expiry in 2051.
- **Root cause:** Misconfigured access policies. Over-scoped, long-lived, untracked access tokens.
- **Lesson:** Cloud object stores and shareable links are frequent, silent leak sources.
- **REQ-H-59:** Source data **shall** never be stored in multi-tenant object storage in decryptable form. Any storage credential **shall** be scoped, short-lived (≤ 24 h) and inventoried. Organization policy **shall** block public ACLs.
- **Test:** A cloud-security-posture scan (e.g., Prowler/ScoutSuite) finds no public buckets. Token inventory audit. A policy test that tries to set a public ACL is denied.

### INC-60 — Plaintext secrets in internal logs: Facebook passwords (2012–2019; reported 21 Mar 2019) [B-INC-93]
- **What failed:** Internal applications logged 200–600 million user passwords in plaintext, searchable by more than 20,000 employees. About 2,000 engineers had made roughly 9 million queries touching those data.
- **Root cause:** Logging request bodies. No log-content classification.
- **Lesson:** Logs and SIEMs collect exactly the data you meant to protect.
- **REQ-H-60:** Logging **shall** follow an allow-list of fields per event type. Request bodies, headers, IP addresses and codenames **shall** never be logged. Logs **shall** be retained ≤ 7 days on source-facing components.
- **Test:** Send canary plaintext, codename and IP through every endpoint, then grep all log sinks (local, SIEM, backups): zero hits. A retention job test.

---

## 7. Cryptographic design and implementation failures

### INC-61 — ROCA, CVE-2017-15361 (Oct 2017) — URL UNVERIFIED [B-INC-101]
- **What failed:** Infineon's RSA key generation (in smartcards, TPMs and YubiKey 4 among others) produced primes with structure that allowed factoring with Coppersmith's method. About 750,000 Estonian ID cards were affected (Nemec et al., ACM CCS 2017; details from the author's knowledge).
- **Root cause:** A proprietary, unreviewed key-generation shortcut inside certified hardware.
- **Lesson / REQ-H-61:** Covered by REQ-H-51 (weak-key blocklists). In addition, the platform **shall** prefer elliptic-curve keys (X25519/Ed25519) generated in software from a vetted library, or verified hardware with public test vectors. Any RSA public key it accepts **shall** be run through the ROCA detector.
- **Test:** The ROCA detector flags the known vulnerable test keys, and they are rejected.

### INC-62 — Matrix/Element cryptographic vulnerabilities (disclosed 28 Sep 2022) [B-INC-94][B-INC-95]
- **What failed:** Albrecht, Celi, Dowling and Jones showed practical attacks, for example a malicious homeserver adding devices to or impersonating users in groups, key/IV reuse, and protocol confusion. These undermined confidentiality and authentication against a malicious server.
- **Root cause:** Server-controlled group membership and device lists. Insufficient domain separation. Complexity.
- **Lesson:** In E2EE group systems, the server controls who is "in the room" unless membership is cryptographically authenticated.
- **REQ-H-62:** Recipient-set changes (adding or removing journalists or devices) **shall** be authorized by signatures from existing trusted members or an organizational root key. Clients **shall** refuse to encrypt to unverified devices and **shall** show membership changes.
- **Test:** A malicious-server simulation injects a new device into a newsroom group. The source and recipient clients refuse to encrypt to it and raise an alert.

### INC-63 — Threema ETH Zürich analysis (2023) [B-INC-96][B-INC-97]
- **What failed:** Paterson, Scarlata and Truong found seven attacks across three threat models, including against the client-to-server protocol, key compromise impersonation, compromised-server message replay and reordering, and a backup/cloning vector. All were patched.
- **Root cause:** A custom protocol without formal analysis, with no forward secrecy in some layers and weak domain separation.
- **Lesson:** Custom crypto needs formal analysis before it goes into production.
- **REQ-H-63:** The platform **shall** use only standard, formally analysed constructions (e.g., HPKE RFC 9180, the Noise framework, MLS RFC 9420, age/OpenPGP-crypto-refresh via vetted libraries). Any new composition **shall** receive a published external cryptographic review, and ideally a machine-checked proof (ProVerif/Tamarin), before launch.
- **Test:** Artifact check: the review report and proof model are in the repository and CI re-runs the Tamarin or ProVerif model.

### INC-64 — Telegram MTProto 2.0 attacks (IEEE S&P 2022) [B-INC-98]
- **What failed:** Albrecht, Mareková, Paterson and Stepanovs showed message reordering, a theoretical attack, timing side-channels in three official clients, and a chained attack on the server key exchange enabling man-in-the-middle under conditions.
- **Root cause:** A non-standard AEAD construction, and implementation side-channels.
- **Lesson / REQ-H-64:** Covered by REQ-H-63. In addition, crypto libraries **shall** be constant-time and message ordering **shall** be authenticated (sequence numbers or transcript hashing).
- **Test:** A reorder or replay test harness is rejected by the receiver. dudect-style timing tests pass on decryption.

### INC-65 — Efail (disclosed 14 May 2018; USENIX Security 2018) — URL UNVERIFIED [B-INC-99]
- **What failed:** Direct exfiltration and CBC/CFB malleability gadgets made mail clients decrypt PGP or S/MIME ciphertext and leak the plaintext through HTML remote content (Poddebniak et al.; details from the author's knowledge).
- **Root cause:** Non-authenticated encryption modes, clients ignoring integrity failures, and rendering active content.
- **Lesson / REQ-H-65:** Decryption **shall** use AEAD only, and plaintext **shall** never be released before authentication succeeds. Decrypted content **shall** be rendered in a sandbox with no network access and no remote resources.
- **Test:** A tampered ciphertext is refused with no partial output. The sandboxed renderer's network namespace has no route.

### INC-66 — MEGA "Malleable Encryption Goes Awry" (disclosed Jun 2022; IEEE S&P 2023) — URL UNVERIFIED [B-INC-100]
- **What failed:** Backendal, Haller and Paterson showed that a malicious MEGA server could recover users' RSA private keys through a key-recovery oracle during login, then decrypt files and plant files (details from the author's knowledge).
- **Root cause:** Key material encrypted with ECB and no integrity protection. Legacy constructions. The server acted as a decryption oracle.
- **Lesson:** "Zero-knowledge cloud" claims fail against a malicious server if key blobs are malleable.
- **REQ-H-66:** All wrapped keys and key blobs **shall** use AEAD, with context binding (user, purpose, version). Clients **shall** treat the server as malicious and never return any function of decrypted secrets to it.
- **Test:** A malicious-server test harness modifies wrapped-key blobs. The client fails closed, and no oracle-dependent response differs.

### INC-67 — Nextcloud end-to-end encryption flaws (IEEE EuroS&P 2024) — URL UNVERIFIED [B-INC-102]
- **What failed:** Albrecht, Backendal, Coppola and Paterson reported attacks by which a malicious server could break the confidentiality and integrity of Nextcloud's E2EE ("Share with Care"; details from the author's knowledge).
- **Root cause:** Server-controlled key distribution and metadata, and missing authentication.
- **Lesson / REQ-H-67:** Covered by REQ-H-62 and REQ-H-66. In addition, the key directory **shall** be a verifiable transparency log (key transparency), and clients **shall** check consistency proofs.
- **Test:** A server presents a different key for a journalist to two clients. Gossip or consistency checking detects the equivocation.

---

## 8. Insider abuse

### INC-68 — NSA "LOVEINT" (NSA IG letter to Sen. Grassley, Sep 2013) — UNVERIFIED [B-INC-103]
- **What failed:** The NSA Inspector General reported about a dozen cases of employees using SIGINT systems to spy on romantic partners, several found through self-reporting or polygraphs rather than audits (from the author's knowledge).
- **Root cause:** Broad query access, with detection that was after the fact and weak.
- **Lesson / REQ-H-68:** No single operator **shall** be able to access source material or source metadata. Access to any source-linked record **shall** require the assigned recipient's key, and all administrative access **shall** be two-person, with tamper-evident logging to an external append-only store.
- **Test:** An attempt by a lone administrator to read source data fails cryptographically. Log tampering is detected by hash-chain verification.

### INC-69 — Twitter insiders spying for Saudi Arabia (conduct 2014–2015; charged Nov 2019) — UNVERIFIED [B-INC-104]
- **What failed:** Two Twitter employees accessed private account data, including the email addresses, phone numbers and IP addresses of dissidents' accounts (one of them thousands of accounts), and passed it to Saudi officials. One was convicted in 2022 (from the author's knowledge).
- **Root cause:** Support and engineering staff had broad access to identifying user data, without purpose binding.
- **Lesson / REQ-H-69:** Covered by REQ-H-05, REQ-H-06 and REQ-H-68. In addition, staff hiring for privileged roles **shall** include background checks proportionate to the threat, and anomalous-access detection **shall** alert a party independent of the accessor's management chain.
- **Test:** Red-team insider simulation: a privileged employee attempts bulk lookup, and it is blocked or alerted within 15 minutes.

### INC-70 — Uber "God View" (reported 2014; FTC settlement Aug 2017) — UNVERIFIED [B-INC-105]
- **What failed:** An internal tool let employees view riders' real-time and historical locations. It was reportedly used against a journalist. The FTC found Uber's access controls inadequate (from the author's knowledge).
- **Root cause:** Admin tools with no purpose limitation or audit.
- **Lesson / REQ-H-70:** Admin tooling **shall** not exist for source data. Operational dashboards **shall** show only aggregate counts with differential privacy or thresholding (k ≥ 20).
- **Test:** Review of admin UI endpoints. A query that returns fewer than k rows is suppressed.

### INC-71 — Snap employees abusing "SnapLion" (reported May 2019) — UNVERIFIED [B-INC-106]
- **What failed:** Reportedly, employees misused an internal tool built for law-enforcement requests to access user data (from the author's knowledge; Motherboard reporting).
- **Root cause:** A lawful-access tool usable outside of legal process.
- **Lesson / REQ-H-71:** Any legal-response tooling **shall** have access only to the compelled-disclosure inventory data (REQ-H-06), **shall** require a case ticket linked to verified legal process, and **shall** use two-person approval.
- **Test:** Use the legal-response tool without a ticket: it is denied.

### INC-72 — Tesla employees sharing customer camera recordings (2019–2022; Reuters Apr 2023) — UNVERIFIED [B-INC-107]
- **What failed:** Reuters reported that Tesla staff shared sensitive customer vehicle-camera images and videos in internal chats (from the author's knowledge).
- **Root cause:** Product telemetry and media visible to labelers and staff, with no minimization.
- **Lesson / REQ-H-72:** Covered by REQ-H-13 and REQ-H-60. The platform **shall** collect no product telemetry from source clients, and **shall** not route source media to any annotation, ML or quality-assurance pipeline.
- **Test:** Network capture shows no telemetry. Data-flow review.

---

## 9. Additional deanonymization vectors (added)

### INC-73 — Stylometry: J.K. Rowling as "Robert Galbraith" (Jul 2013) — UNVERIFIED [B-INC-108]
- **What failed:** After a tip, Patrick Juola and Peter Millican ran authorship-attribution software comparing *The Cuckoo's Calling* with Rowling's work and other authors. The results supported Rowling as the author, and she confirmed it (from the author's knowledge).
- **Root cause:** Writing style is a biometric. Small candidate sets make attribution reliable.
- **Lesson:** A whistleblower's prose, in an organization with few candidate authors, is identifying. The recipient side may republish verbatim text.
- **REQ-H-73:** Recipient guidance and the publication workflow **shall** default to paraphrasing source text. The platform **should** offer sources an optional, local-only style-normalization aid, with a clear warning that it does not replace care.
- **Test:** Editorial checklist enforced in the export flow ("verbatim quote > N words requires sign-off").

### INC-74 — Strava global heatmap exposing military bases (Jan 2018) — UNVERIFIED [B-INC-111]
- **What failed:** Aggregated fitness-tracker data revealed the layout of, and patrol routes at, sensitive bases (from the author's knowledge; an analyst's public observation).
- **Root cause:** Aggregate publication of location data with no suppression of sparse areas.
- **Lesson / REQ-H-74:** Any published statistics (transparency reports, dashboards) **shall** be thresholded or noised, so that no count below k is released and no timing detail finer than a month is disclosed.
- **Test:** The report generator suppresses cells with fewer than k items.

---

## 10. Cross-cutting architectural themes

1. **Treat the operator as compellable and seizable** (INC-01–07, 14–15, 27–28). Design so that "we can't" is true. The operator should never hold keys, IP addresses or identifiers, and the code it serves should be verifiable (REQ-H-01, 02, 03, 06, 14, 15).
2. **Metadata identifies people** (INC-03, 05, 16, 25, 31, 57). Protect IP addresses, recovery channels, push, timing, printer dots and access logs, not only content.
3. **Recipients are attack surface** (INC-16, 19, 21, 24). Sanitization, redaction verification and two-person export are platform features, not training topics.
4. **Every third party is a wiretap** (INC-13, 46, 53, 54, 57). No third-party scripts, CDNs, SDKs or push services on source paths.
5. **The supply chain is the most powerful attack path** (INC-37–52). Reproducible builds, threshold signing, transparency logs, pinned dependencies, and hardened developer endpoints.
6. **Diagnostics leak secrets** (INC-56, 58, 60). No core dumps, no body logging, scrubbed support bundles.
7. **Standard, analysed crypto and a malicious-server threat model** (INC-61–67).
8. **Insiders exist** (INC-68–72). Cryptographic access control, not policy; two-person rule; external tamper-evident audit.
9. **Human opsec failures dominate** (INC-17, 21, 31, 32, 73). Source guidance, random codenames, amnesic clients, and warnings against using employer networks or devices.

---

## Bibliography

Format: `[ID] Title — Publisher. URL — Date — Relevance`. "UNVERIFIED" means the item could not be retrieved or confirmed in this session.

- [B-INC-01] "Hushmail court orders" — The Register. https://www.theregister.com/2007/11/08/hushmail_court_orders/ — 2007-11-08 — Hushmail disclosure to DEA.
- [B-INC-02] "Hushmail Turns Data Over to Government" — Schneier on Security. https://www.schneier.com/blog/archives/2007/11/hushmail.html — 2007-11 — Analysis of server-side key mode.
- [B-INC-03] R. Singel, "Encrypted E-Mail Company Hushmail Spills to Feds" — Wired — 2007-11-07 — Original report. URL UNVERIFIED (fetch blocked). Mirror: https://attrition.org/pipermail/infowarrior/2007-November/002224.html
- [B-INC-04] *In re Under Seal (United States v. Lavabit LLC)*, No. 13-4625 — US Court of Appeals, 4th Cir. https://www.ca4.uscourts.gov/Opinions/Published/134625.P.pdf — 2014-04-16 — TLS key compulsion; contempt affirmed.
- [B-INC-05] "Fourth Circuit Decision in Lavabit" — Lawfare. https://www.lawfaremedia.org/article/fourth-circuit-decision-lavabit — 2014-04 — Legal analysis.
- [B-INC-06] "ProtonMail forced to collect an activist's IP address in police investigation" — The Record. https://therecord.media/protonmail-forced-to-collect-an-activists-ip-address-in-police-investigation — 2021-09 — Compelled IP logging.
- [B-INC-07] "ProtonMail log users' IP address" — ESET WeLiveSecurity. https://www.welivesecurity.com/2021/09/07/protonmail-log-users-ip-address/ — 2021-09-07 — Corroboration.
- [B-INC-08] "Tutanota backdoor court order" — The Register. https://www.theregister.com/2020/12/08/tutanota_backdoor_court_order/ — 2020-12-08 — Cologne order.
- [B-INC-09] "German court ruling: Tutanota email monitoring" — CyberScoop. https://cyberscoop.com/germany-court-ruling-tutanota-email-monitoring/ — 2020-12 — Corroboration; Hanover conflict.
- [B-INC-10] "Proton Mail recovery email leads to arrest of Catalan activist" — TechRadar. https://www.techradar.com/computing/cyber-security/proton-mail-fails-activists-againis-it-time-to-ditch-the-app-for-good — 2024-05 — Recovery-email disclosure chain.
- [B-INC-11] Signal "Government Communication" (Big Brother) archive — Signal. https://signal.org/bigbrother/ ; example: https://signal.org/bigbrother/central-california-grand-jury/ — 2016–2021+ — Minimal-data responses.
- [B-INC-12] Riseup Canary Statement — Riseup. https://riseup.net/about-us/press/canary-statement — 2017-02 — Sealed warrants and gag.
- [B-INC-13] "Netizen Report: How private is our email? Riseup users want to know" — Global Voices Advox. https://advox.globalvoices.org/2017/02/23/netizen-report-how-private-is-our-email-riseup-users-want-to-know/ — 2017-02-23 — Context.
- [B-INC-14] "The ethics of the Guardian's Whisper story" — Columbia Journalism Review. https://www.cjr.org/the_audit/the_ethics_of_the_guardians_wh.php — 2014-10 — Summary of, and dispute over, Guardian findings.
- [B-INC-15] P. Lewis & D. Rushe, "Revealed: how Whisper app tracks 'anonymous' users" (Guardian) — NYU Undercover Reporting archive entry. https://undercover.hosting.nyu.edu/s/undercover-reporting/item/14834 — 2014-10-16 — Original Guardian report (Guardian URL UNVERIFIED).
- [B-INC-16] "Yik Yak fixes information disclosure bug that leaked users' GPS location" — The Daily Swig (PortSwigger). https://portswigger.net/daily-swig/yik-yak-fixes-information-disclosure-bug-that-leaked-users-gps-location — 2022-05 — Precise GPS in API.
- [B-INC-17] "Anonymous bulletin app Yik Yak isn't so anonymous after all" — TechRadar. https://www.techradar.com/news/anonymous-bulletin-app-yik-yak-isnt-so-anonymous-after-all — 2022-05 — Corroboration.
- [B-INC-18] "Researchers exploit flaw to tie Secret users to their secrets" — Help Net Security. https://www.helpnetsecurity.com/2014/08/25/researchers-exploit-flaw-to-tie-secret-users-to-their-secrets — 2014-08-25 — Sybil anonymity-set attack.
- [B-INC-19] "Hack of popular app Secret…" — GeekWire. https://www.geekwire.com/2014/hack-popular-app-secret-seattle-hackers-show-digital-security-always-beta/ — 2014-08 — Rhino Security Labs details.
- [B-INC-20] "At Blind, a security lapse revealed private complaints from Silicon Valley employees" — TechCrunch. https://techcrunch.com/2018/12/20/blind-anonymous-app-data-exposure/ — 2018-12-20 — Exposed Elasticsearch.
- [B-INC-21] "Ninth Circuit affirms grand jury subpoena for identity of Glassdoor users" — Reed Smith. https://www.reedsmith.com/en/perspectives/2017/11/ninth-circuit-affirms-grand-jury-subpoena-for-identity-of-glassdoor-users — 2017-11 — *US v. Glassdoor*.
- [B-INC-22] "US v. Glassdoor: Ninth Circuit compels website to disclose anonymous users' identities" — Harvard JOLT Digest. https://jolt.law.harvard.edu/digest/us-v-glassdoor-ninth-circuit-compels-website-to-disclose-anonymous-users-identities — 2017 — Legal analysis.
- [B-INC-23] "Location leaks pose risk to users of gay dating apps" — Privacy International. https://privacyinternational.org/examples/1853/location-leaks-pose-risk-users-gay-dating-apps — 2016 — Trilateration research.
- [B-INC-24] "Grindr leaks your EXACT location even if you turn 'location privacy' on" — PinkNews. https://www.thepinknews.com/2016/05/20/grindr-leaks-your-exact-location-even-if-you-turn-location-privacy-on-cybersecurity-experts-warn — 2016-05-20 — Hoang et al.
- [B-INC-25] "Pillar Investigates: USCCB gen sec Burrill resigns…" (The Pillar, archived) — BishopAccountability.org. https://www.bishop-accountability.org/2021/07/pillar-investigates-usccb-gen-sec-burrill-resigns-after-sexual-misconduct-allegations/ — 2021-07-20 — Commercial app-signal data deanonymization.
- [B-INC-26] "Drug rings' favorite new encrypted platform had one flaw: the FBI controlled it" — NPR. https://www.npr.org/2021/06/08/1004332551/drug-rings-platform-operation-trojan-shield-anom-operation-greenlight — 2021-06-08 — Anom master key.
- [B-INC-27] "Dismantling of an encrypted network sends shockwaves through organised crime groups across Europe" — Eurojust/Europol joint press release. https://www.eurojust.europa.eu/news/dismantling-encrypted-network-sends-shockwaves-through-organised-crime-groups-across-europe — 2020-07-02 — EncroChat interception.
- [B-INC-28] "Police credit 'unlocked' SKY ECC encryption for organized crime bust" — Malwarebytes Labs. https://www.malwarebytes.com/blog/news/2021/03/police-credit-unlocked-sky-ecc-encryption-for-organized-crime-bust — 2021-03 — Sky ECC (summarizes Europol release of 2021-03-10).
- [B-INC-29] "Federal Government Contractor in Georgia Charged With Removing and Mailing Classified Materials to a News Outlet" — US DOJ. https://www.justice.gov/opa/pr/federal-government-contractor-georgia-charged-removing-and-mailing-classified-materials-news — 2017-06-05 — Reality Winner complaint.
- [B-INC-30] "The Mysterious Printer Code That May Have Led the FBI to the Alleged NSA Leaker" — Defense One. https://defenseone.com/technology/2017/06/mysterious-printer-code-may-have-led-fbi-alleged-nsa-leaker/138469 — 2017-06 — Tracking dots (cites Errata Security).
- [B-INC-31] "How the FBI got to Reality Winner" — Axios. https://www.axios.com/how-reality-winner-got-burned-2434728395.html — 2017-06 — Audit log / six printers / email contact.
- [B-INC-32] "'Bitter,' 'Angry,' 'Enraged': Reality Winner Blasts the Intercept…" — Rolling Stone. https://www.rollingstone.com/politics/politics-features/reality-winner-interview-prison-nsa-1261844/ — 2021 — Intercept "fell short" review context.
- [B-INC-33] "Computer disk may have cracked BTK case" — NBC News. https://www.nbcnews.com/id/wbna6988048 — 2005-03 — Floppy metadata.
- [B-INC-34] Nettime post relaying R.M. Smith's Iraq dossier metadata analysis — nettime-l. https://nettime.org/Lists-Archives/nettime-l-0307/msg00012.html — 2003-07-03 — Word revision log.
- [B-INC-35] "Iraq Dossier" — Wikipedia. https://en.wikipedia.org/wiki/Iraq_Dossier — n.d. — Background (fetch blocked; URL from search results).
- [B-INC-36] "Manafort, Mueller, and a redacted document" — Columbia Journalism Review. https://www.cjr.org/analysis/manafort-mueller-redacted-document-ukraine.php — 2019-01 — Failed redaction.
- [B-INC-37] "Military report secrets" — The Register. https://www.theregister.co.uk/2005/05/03/military_report_secrets — 2005-05-03 — Calipari report redaction failure.
- [B-INC-38] "Technical Error Reveals Classified Info on Death of Italian Agent" — NPR. https://www.npr.org/2005/05/02/4626839/technical-error-reveals-classified-info-on-death-of-italian-agent — 2005-05-02 — Corroboration.
- [B-INC-39] "EXIF Data May Have Revealed Location of Fugitive Software Tycoon John McAfee" — PetaPixel. https://petapixel.com/2012/12/03/exif-data-may-have-revealed-location-of-fugitive-billionaire-john-mcafee/ — 2012-12-03 — EXIF GPS.
- [B-INC-40] "What Bradley told Adrian" — Columbia Journalism Review. https://www.cjr.org/behind_the_news/what_bradley_told_adrian.php — 2011 — Manning/Lamo logs.
- [B-INC-41] "FCA and PRA jointly fine Mr James Staley and announce special requirements at Barclays" — Bank of England / PRA. https://www.bankofengland.co.uk/news/2018/may/fca-and-pra-jointly-fine-mr-james-staley-and-announce-special-requirements-at-barclays — 2018-05-11 — Whistleblower-unmasking attempt.
- [B-INC-42] "Whistleblower's home raided by ATO, federal police" — SBS News. https://www.sbs.com.au/news/article/whistleblowers-home-raided-by-ato-federal-police/qlq5xzhq1 — 2018 — Richard Boyle.
- [B-INC-43] "AFP raids Australian Tax Office whistleblower amid Four Corners investigation" — The New Daily. https://www.thenewdaily.com.au/news/national/2018/04/04/afp-raids-australian-tax-office-whistleblower — 2018-04-04 — Phone seizure.
- [B-INC-44] "CIA waterboarding case highlights need for digital security" — Committee to Protect Journalists. https://cpj.org/2012/10/cia-waterboarding-case-highlights-need-for-digital/ — 2012-10 — Kiriakou/reporter emails.
- [B-INC-45] "Former CIA Officer Sentenced to 30 Months…" — US DOJ (EDVA). https://www.justice.gov/usao-edva/pr/former-cia-officer-sentenced-30-months-revealing-identity-20-plus-year-covert-cia — 2013-01 — Outcome.
- [B-INC-46] "Firefox exploit… Tor network… Freedom Hosting" — The Hacker News. https://thehackernews.com/2013/08/Firefox-Exploit-Tor-Network-child-pornography-Freedom-Hosting.html — 2013-08 — NIT/Magneto.
- [B-INC-47] *US v. Croghan* order (Playpen NIT) — S.D. Iowa, via DocumentCloud. https://assets.documentcloud.org/documents/3111524/Croghan-Playpen-Order.pdf — 2016 — NIT warrant facts.
- [B-INC-48] "Tor security advisory: 'relay early' traffic confirmation attack" — Tor Project. https://blog.torproject.org/node/893 — 2014-07-30 — RELAY_EARLY attack.
- [B-INC-49] "Carnegie Mellon University attacked Tor, was subpoenaed by feds" — Vice/Motherboard. https://www.vice.com/en/article/carnegie-mellon-university-attacked-tor-was-subpoenaed-by-feds/ — 2016-02 — Farrell ruling.
- [B-INC-50] "FBI subpoenaed Carnegie Mellon University for Tor-using suspect's IP address" — Help Net Security. https://www.helpnetsecurity.com/2016/02/25/fbi-subpoenaed-carnegie-mellon-university-for-tor-using-suspects-ip-address/ — 2016-02-25 — Corroboration.
- [B-INC-51] "A mysterious threat actor is running hundreds of malicious Tor relays" — The Record. https://therecord.media/a-mysterious-threat-actor-is-running-hundreds-of-malicious-tor-relays/ — 2021-12 — KAX17.
- [B-INC-52] "Student charged in bomb threat" — The Harvard Crimson. https://www.thecrimson.com/article/2013/12/17/student-charged-bomb-threat — 2013-12-17 — Eldo Kim.
- [B-INC-53] "Tor User Identified by FBI" — Schneier on Security. https://www.schneier.com/blog/archives/2013/12/tor_user_identi.html — 2013-12 — Anonymity-set analysis.
- [B-INC-54] "End of Silk Road: slip-ups … led to Ross Ulbricht, court documents say" — NBC News. https://www.nbcnews.com/news/world/end-silk-road-slip-ups-building-internet-drug-market-led-flna8C11326181 — 2013-10 — Opsec failure.
- [B-INC-55] "Simple Google search outed alleged Silk Road founder" — Computerworld. https://www.computerworld.com/article/2875655/simple-google-search-outed-alleged-silk-road-founder.html — 2015-01 — "altoid" linkage.
- [B-INC-56] "Is Tor still safe to use?" — Tor Project. https://blog.torproject.org/tor-is-still-safe/ — 2024-09-18 (upd. 2024-10-10) — Ricochet guard-discovery case.
- [B-INC-57] "Tor police Germany" — The Register. https://www.theregister.com/2024/09/19/tor_police_germany/ — 2024-09-19 — BKA timing analysis / CCC review.
- [B-INC-58] "Dread Pirate Sunk By Leaky CAPTCHA" (Krebs on Security) — https://krebsonsecurity.com/?p=27719 — 2014-09-06 — Silk Road IP leak dispute. (title UNVERIFIED; URL confirmed by search)
- [B-INC-59] "Reading the Silk Road configuration" — Errata Security. https://blog.erratasec.com/2014/10/reading-silk-road-configuration.html — 2014-10-03 — nginx configuration analysis.
- [B-INC-60] "How bad are Apache mod_status leaks anyway?" — Mascherari Press (S.J. Lewis). https://mascherari.press/how-bad-are-apache-mod_status-leaks-anyway-2/ — 2016 — OnionScan findings.
- [B-INC-61] "Simple mistake exposes businessman's secret dark web drug store" — Sophos Naked Security. https://news.sophos.com/en-us/2016/10/18/simple-mistake-exposes-businessmans-secret-dark-web-drug-store/ — 2016-10-18 — Co-hosting leak.
- [B-INC-62] "Tor Browser flaw leaks users' real IP address" — Help Net Security. https://www.helpnetsecurity.com/2017/11/06/tor-browser-ip-leak/ — 2017-11-06 — TorMoil.
- [B-INC-63] "Scheme flooding fingerprint technique may deanonymize Tor users" — Security Affairs. https://securityaffairs.com/117933/digital-id/fingerprinting-technique-scheme-flooding.html — 2021-05 — Cross-browser fingerprint.
- [B-INC-64] "Tor Browser 10.0.18 fixes a bug that allows to track users…" — Security Affairs. https://securityaffairs.com/119222/deep-web/tor-browser-10-0-18.html — 2021-06 — Mitigation.
- [B-INC-65] "The xz backdoor: CVE-2024-3094" — Snyk. https://snyk.io/blog/the-xz-backdoor-cve-2024-3094/ — 2024-03/04 — Technical summary.
- [B-INC-66] A. Freund, "backdoor in upstream xz/liblzma leading to ssh server compromise" — oss-security mailing list — 2024-03-29 — Original disclosure. URL UNVERIFIED (openwall.com blocked; commonly cited as https://www.openwall.com/lists/oss-security/2024/03/29/4 — re-verify).
- [B-INC-67] "CISA demands US govt agencies to update SolarWinds Orion software" — Security Affairs. https://securityaffairs.com/112797/hacking/cisa-solarwinds-guidance-update.html — 2020-12 — ED 21-01 context.
- [B-INC-68] "Bash Uploader Security Update" — Codecov. https://about.codecov.io/security-update/ — 2021-04-15 — Official postmortem.
- [B-INC-69] "Details about the event-stream incident" — npm Blog. https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident — 2018-11 — Official postmortem.
- [B-INC-70] "3CX Software Supply Chain Compromise Initiated by a Prior Software Supply Chain Compromise" — Mandiant/Google Cloud. https://cloud.google.com/blog/topics/threat-intelligence/3cx-software-supply-chain-compromise — 2023-04-20 — Cascading attack.
- [B-INC-71] "Malware Discovered in Popular NPM Package, ua-parser-js" — CISA. https://cisa.gov/news-events/alerts/2021/10/22/malware-discovered-popular-npm-package-ua-parser-js — 2021-10-22 — Account hijack.
- [B-INC-72] "PyPI halts sign-ups amid surge of malicious package uploads" — The Hacker News. https://thehackernews.com/2024/03/pypi-halts-sign-ups-amid-surge-of.html — 2024-03 — Typosquat campaign.
- [B-INC-73] "Supply Chain Compromise of Third-Party GitHub Action, CVE-2025-30066" — CISA. https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066 — 2025-03-18 — Mutable tags; secrets in logs.
- [B-INC-74] "Widespread Supply Chain Compromise Impacting npm Ecosystem" — CISA. https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem — 2025-09-23 — Shai-Hulud worm.
- [B-INC-75] "Polyfill.io JavaScript supply chain attack impacts over 100K sites" — BleepingComputer. https://www.bleepingcomputer.com/news/security/polyfillio-javascript-supply-chain-attack-impacts-over-100K-sites/ — 2024-06-25 — CDN takeover.
- [B-INC-76] "Security Incident Report" (Connect Kit) — Ledger. https://ledger.com/blog/security-incident-report — 2023-12-14 — Official postmortem.
- [B-INC-77] "Downloaded CCleaner lately? … stuffed with malware" — The Register. https://www.theregister.co.uk/2017/09/18/tainted_ccleaner_downloads — 2017-09-18 — Signed backdoor.
- [B-INC-78] "The MeDoc Connection" — Cisco Talos. https://blog.talosintelligence.com/the-medoc-connection/ — 2017-07 — NotPetya update-server compromise.
- [B-INC-79] Checkoway et al., "A Systematic Analysis of the Juniper Dual EC Incident" — ACM CCS 2016 / IACR ePrint 2016/376. https://eprint.iacr.org/2016/376 — 2016 — RNG backdoor.
- [B-INC-80] "DSA-1571-1 openssl — predictable random number generator" — Debian Security Announce. https://lists.debian.org/debian-security-announce/2008/msg00152.html — 2008-05-13 — CVE-2008-0166.
- [B-INC-81] "Beware of hacked ISOs if you downloaded Linux Mint on February 20th!" — Linux Mint Blog. http://blog.linuxmint.com/?p=2994 — 2016-02-20 — Official notice (URL from search-result text; not fetched).
- [B-INC-82] Same notice mirrored — Full Circle Magazine. https://legacy.fullcirclemagazine.org/2016/02/21/beware-of-hacked-isos-if-you-downloaded-linux-mint-on-february-20th/ — 2016-02-21 — Mirror.
- [B-INC-83] "Facebook Is Receiving Sensitive Medical Information from Hospital Websites" — The Markup. https://themarkup.org/pixel-hunt/2022/06/16/facebook-is-receiving-sensitive-medical-information-from-hospital-websites — 2022-06-16 — Meta Pixel.
- [B-INC-84] "Tax Filing Websites Have Been Sending Users' Financial Information to Facebook" — The Markup. https://themarkup.org/pixel-hunt/2022/11/22/tax-filing-websites-have-been-sending-users-financial-information-to-facebook — 2022-11-22 — Meta Pixel.
- [B-INC-85] "Incident report on memory leak caused by Cloudflare parser bug" — Cloudflare. https://blog.cloudflare.com/incident-report-on-memory-leak-caused-by-cloudflare-parser-bug/ — 2017-02-23 — Cloudbleed.
- [B-INC-86] "Notice of Recent Security Incident" — LastPass. https://blog.lastpass.com/posts/notice-of-security-incident — 2022-12-22 — Backup theft.
- [B-INC-87] "Unauthorized Access to Okta's Support Case Management System: Root Cause and Remediation" — Okta Security. https://sec.okta.com/articles/2023/11/unauthorized-access-oktas-support-case-management-system-root-cause/ — 2023-11-03 — HAR-file tokens.
- [B-INC-88] Sen. R. Wyden, letter to DOJ on smartphone push-notification surveillance — US Senate. https://www.wyden.senate.gov/imo/media/doc/wyden_smartphone_push_notification_surveillance_letter.pdf — 2023-12 (exact day UNVERIFIED; widely reported 2023-12-06) — Push metadata.
- [B-INC-89] "Apple will now disclose government requests for push notification data" — Six Colors. https://sixcolors.com/link/2023/12/apple-will-now-disclose-government-requests-for-push-notification-data/ — 2023-12 — Apple response.
- [B-INC-90] "Results of Major Technical Investigations for Storm-0558 Key Acquisition" — Microsoft MSRC. https://msrc.microsoft.com/blog/2023/09/results-of-major-technical-investigations-for-storm-0558-key-acquisition/ — 2023-09-06 (updated 2024-03) — Crash-dump key exposure.
- [B-INC-91] "Sensitive data on 198 million US voters exposed online" — Help Net Security. https://www.helpnetsecurity.com/2017/06/19/us-voters-data-leak/ — 2017-06-19 — Deep Root Analytics S3.
- [B-INC-92] "Microsoft AI researchers mistakenly expose 38 TB of data" — TechTarget. https://www.techtarget.com/cybersecurity/news/366552399/Microsoft-AI-researchers-mistakenly-expose-38-TB-of-data — 2023-09 — SAS token (Wiz finding).
- [B-INC-93] "Facebook Stored Hundreds of Millions of User Passwords in Plain Text for Years" — Krebs on Security. https://krebsonsecurity.com/2019/03/facebook-stored-hundreds-of-millions-of-user-passwords-in-plain-text-for-years/ — 2019-03-21 — Secrets in logs.
- [B-INC-94] Albrecht, Celi, Dowling, Jones, "Practically-exploitable Cryptographic Vulnerabilities in Matrix" — Brave Research (IEEE S&P 2023; ePrint 2023/485). https://brave.com/research/practically-exploitable-cryptographic-vulnerabilities-in-matrix/ — disclosed 2022-09-28 — Malicious-server attacks.
- [B-INC-95] "Matrix encryption flaws" — The Register. https://www.theregister.com/2022/09/28/matrix_encryption_flaws/ — 2022-09-28 — Corroboration.
- [B-INC-96] Paterson, Scarlata, Truong, "Three Lessons From Threema: Analysis of a Secure Messenger" — USENIX Security 2023. https://www.usenix.org/conference/usenixsecurity23/presentation/paterson — 2023-08 — Seven attacks.
- [B-INC-97] "Breaking Threema" project site — ETH Zürich. https://breakingthe3ma.app/ — 2023-01 — Summary.
- [B-INC-98] Albrecht, Mareková, Paterson, Stepanovs, "Four Attacks and a Proof for Telegram" — IEEE S&P 2022 / IACR ePrint 2023/469. https://eprint.iacr.org/2023/469 — 2022 — MTProto 2.0.
- [B-INC-99] Poddebniak et al., "Efail: Breaking S/MIME and OpenPGP Email Encryption using Exfiltration Channels" — USENIX Security 2018 — disclosed 2018-05-14 — URL UNVERIFIED (efail.de and usenix.org blocked).
- [B-INC-100] Backendal, Haller, Paterson, "MEGA: Malleable Encryption Goes Awry" — IEEE S&P 2023 — disclosed 2022-06 — URL UNVERIFIED (mega-awry.io blocked).
- [B-INC-101] Nemec et al., "The Return of Coppersmith's Attack: Practical Factorization of Widely Used RSA Moduli" (ROCA, CVE-2017-15361) — ACM CCS 2017 — 2017-10 — URL UNVERIFIED (crocs.fi.muni.cz blocked).
- [B-INC-102] Albrecht, Backendal, Coppola, Paterson, "Share with Care: Breaking E2EE in Nextcloud" — IEEE EuroS&P 2024 — 2024 — UNVERIFIED (title, venue and URL not re-checked).
- [B-INC-103] NSA Inspector General letter to Sen. Charles Grassley on intentional SIGINT misuse ("LOVEINT") — 2013-09 — UNVERIFIED (URL not retrieved).
- [B-INC-104] US DOJ complaint/press release: former Twitter employees and a Saudi national charged as illegal agents of Saudi Arabia — 2019-11 — UNVERIFIED (justice.gov fetch blocked; URL not confirmed).
- [B-INC-105] FTC, Uber settlement over privacy/data-security claims ("God View") — 2017-08 — UNVERIFIED (ftc.gov fetch blocked).
- [B-INC-106] Motherboard/Vice reporting on Snap employees abusing internal "SnapLion" tool — 2019-05 — UNVERIFIED.
- [B-INC-107] Reuters, "Tesla workers shared sensitive images recorded by customer cars" — 2023-04-06 — UNVERIFIED (reuters.com fetch failed).
- [B-INC-108] Juola / Millican stylometric attribution of *The Cuckoo's Calling* to J.K. Rowling — 2013-07 — UNVERIFIED.
- [B-INC-109] HP board-leak "pretexting" investigation — 2006 — UNVERIFIED.
- [B-INC-110] DOJ seizure of Associated Press phone records — disclosed 2013-05 — UNVERIFIED.
- [B-INC-111] Strava global heatmap exposing military sites — 2018-01 — UNVERIFIED.

**Items requested but not covered as separate blocks:** "Apple?", "Boeing/other retaliation", "Guardian?" and "Canadian?" cases had no specific, verifiable incident to anchor them in this session. Boeing-type retaliation is covered in principle by INC-22 and INC-26. Candidates to research next: Terry Albury (FBI, 2018), Daniel Hale (2019–2021), Jeffrey Sterling (metadata-based conviction, 2015), and the James Wolfe/Ali Watkins records seizure (2018).
