# R2 — GlobaLeaks, CoverDrop, Hush Line, other open-source intake tools, and commercial whistleblowing platforms

Research notes for the design of a high-assurance whistleblowing platform (Community FOSS + Enterprise/Government editions).
Compiled 2026-09-30.

## 0. Method, source quality, and limits (read first)

- **Primary sources I actually read in this session:**
  - The GlobaLeaks source repository (shallow clone of `stable`, HEAD commit `8fe0112c…`, dated 2026-09-05). `publiccode.yml` gives softwareVersion 5.0.99 and releaseDate 2026-07-24. I read the `documentation/` tree, `CHANGELOG`, `SECURITY.md`, `scripts/install.sh` and selected backend and client code.
  - The GitHub Security Advisory pages for GlobaLeaks and Hush Line (via WebFetch).
  - The Guardian CoverDrop source repository (shallow clone, HEAD dated 2026-09-25), including `README.md` and `docs/*.md`.
  - The Hush Line repository (shallow clone, HEAD dated 2026-09-29): `README`, `SECURITY.md`, `docs/THREAT-MODEL.md`, `docs/PRIVACY.md`, `docs/ARCHITECTURE.md` and `docs/SECURITY-AUDIT-HITLIST.md`.
  - The Tella-Android README (raw.githubusercontent).
- **Blocked in this session:**
  - The egress proxy blocked docs.globaleaks.org, globaleaks.org (including the audit PDFs), opentech.fund, coverdrop.org, petsymposium.org, theguardian.com, NVD/OSV/CVE.org and every commercial vendor site.
  - The web-search budget ran out partway through.
  - Consequences:
    - The **audit PDFs were not read**. The audit table below comes from the project's own audit index, the CHANGELOG ("security enhancements following auditors suggestions"), GitHub issues and advisories. Anything beyond those is marked UNVERIFIED.
    - All **commercial-vendor claims are UNVERIFIED**. They come from background knowledge and must be re-checked against vendor security whitepapers and trust centres before anyone relies on them. I give no deep vendor URLs, to avoid fabrication.
- The WebFetch summarizer paraphrased the GHSA pages. Version strings and CVE IDs were copied from its output. One oddity is noted inline (`5.9.4`, probably a typo for 5.0.94). **Re-verify each CVE ID on cve.org before citing it externally.**

---

## 1. GlobaLeaks (Hermes Center / Whistleblowing Solutions I.S. S.r.l.)

### 1.1 Identity and governance
- The project is free/open-source (AGPL-3.0) and was started in 2011. The Hermes Center for Transparency and Digital Human Rights owns the licence and trademark. Whistleblowing Solutions Impresa Sociale S.r.l. (WBS, founded 2016) funds and hosts development [B-GL-01 GOVERNANCE.md].
  - Note: "Hermes" in the brief is **the GlobaLeaks steward organisation, not a separate drop tool**.
- The project lead is Giovanni Pellerano (evilaliv3), who is also the principal author of most advisories and fixes. This is a **bus-factor concentration** on a single maintainer.
- Release cadence: major releases twice a year (June and December); security fixes are released out of band [B-GL-02 roadmap.rst].
- Security response target (SECURITY.md): acknowledge within 8 hours; short-term fixes for critical issues within 2 days "whenever possible". Reports go to GHSA or security@globaleaks.org, encrypted to PGP key F6EF BDFA D0A3 CF4A 5508 5C3E 7BBB 231D 0319 57FA [B-GL-03].

### 1.2 Architecture
- **Backend:**
  - Python 3 on Twisted, serving a REST API. It is one process with an embedded Tor controller, an ACME client and an SMTP client.
  - Storage is SQLite through SQLAlchemy.
  - Runs as the dedicated `globaleaks` user, confined by AppArmor, with iptables rules. Recent releases add systemd sandboxing directives [B-GL-04 application-security.rst; CHANGELOG 5.0.94/5.0.96].
- **Client:**
  - A TypeScript single-page app. It began as AngularJS (1.x) and has been migrated to modern Angular; `package.json` now pins `@angular/core` 21.2.21.
  - It talks to the backend only through XHR.
  - It uses `libsodium-wrappers-sumo` (Argon2id in a Web Worker) and DOMPurify, with Trusted Types enforced by CSP [B-GL-04; client/package.json].
- **Access:**
  - A Tor Onion Service v3 is configured automatically.
  - HTTPS on the clearnet is optional, with Let's Encrypt automation, P-384 certificates, TLS 1.2+ and an A+ cipher list.
  - Per-role switches `https_whistleblower`, `https_receiver`, `https_admin`, `https_custodian` and `https_analyst` control whether each role may use HTTPS; if a switch is false, that role must come via Tor.
  - **Default is `https_whistleblower = True`**, so clearnet submission is allowed out of the box (backend `models/config_desc.py`; `handlers/base.py::connection_check`).
  - Per-role IP allow-lists exist for internal users (`ip_filter_<role>`).
  - Since 5.0.96 the backend "fails closed to Tor-only when web reachability is unknown" and "binds high ports to loopback on Tor-only platforms" (CHANGELOG).
- **Multi-site / multi-tenant:**
  - One install hosts many "sites" (tenants), selected by hostname or path. There is a root tenant, and a self-service signup module exists for SaaS use.
  - All tenants share **one process, one SQLite DB, one filesystem** and one Tor daemon. Isolation depends on `tid` filters written into each query.
- **Roles:**
  - whistleblower (anonymous, authenticated by receipt)
  - recipient (receiver)
  - administrator
  - analyst (statistics)
  - custodian (authorises recipients to unmask a whistleblower's identity)
- **Deployment:**
  - The `install.sh` script adds the signed APT repo at deb.globaleaks.org and installs the `globaleaks` .deb. A Docker image `globaleaks/globaleaks:latest` is also offered.
  - Supported distributions: Debian 11+ and Ubuntu 20.04+; the docs recommend Debian 13 and Ubuntu 26.04 [B-GL-05].
  - Upgrade is `apt update && apt install globaleaks`. For a distribution upgrade the docs say to migrate `/var/globaleaks` to a fresh OS and reinstall [B-GL-06].
- **Minimum hardware:** 1 GB RAM, 2 cores, 20 GB storage [B-GL-07].

### 1.3 Encryption protocol (as documented, and confirmed in code) [B-GL-08 encryption-protocol.rst; backend/globaleaks/utils/crypto.py]
- **Primitives (libsodium via PyNaCl):**
  - Asymmetric: SealedBox (X25519 + XSalsa20-Poly1305).
  - Symmetric: SecretBox (XSalsa20-Poly1305).
  - Files: SecretStream (XChaCha20-Poly1305 streaming) with about 5% random padding to blur file size.
  - Temporary upload files: ChaCha20 with a per-file key held only in memory.
  - A separate repo, `globaleaks-eph-fs`, provides an ephemeral ChaCha20-encrypted FUSE filesystem.
- **Per-user keys:**
  - An X25519 keypair is generated **by the backend** at a user's first login.
  - The private key is stored encrypted under a key derived with Argon2id from the user's password. Documented KDF parameters: 128 MB and about 1 second, set stronger than the authentication hash. Code: `calculate_key_and_hash` runs Argon2id(OPSLIMIT+1) for the key and Argon2id(OPSLIMIT) for the stored hash.
- **Authentication hash:**
  - Argon2id with 16 iterations and 128 MiB (`opslimit=16, memlimit=1<<27`), then SHA-256.
  - Salt is per user for internal users. For whistleblowers it is a **per-tenant `receipt_salt`**, the same for every whistleblower on that tenant.
- **Client-side pre-hash:**
  - The Angular client runs Argon2id in a Web Worker on the password or receipt with the salt from `/api/auth/type`, and sends the result. The server never receives the raw password or receipt.
  - However, the value it does receive is **password-equivalent**: it is what unlocks the private key on the server.
- **Whistleblower keys:**
  - A random 16-digit receipt (`secrets.randbelow(10**16)`, about 53.2 bits) is generated server-side.
  - A whistleblower X25519 keypair is created, and its private key is encrypted under a key derived from the receipt.
  - The receipt is formatted like a phone number so it is easy to hide.
- **Per-report key:**
  - A per-report keypair encrypts the answers, comments, attachments and metadata.
  - The report private key is wrapped (SealedBox) to each involved user's public key and to the whistleblower's key.
- **Account Recovery Key:**
  - At key generation the private key is also encrypted under a random recovery key.
  - The recovery key is itself stored encrypted server-side, so a logged-in user can re-display and print it.
  - A password reset requires the recovery key when encryption is on.
- **Optional Key Escrow:**
  - An escrow keypair is assigned to the administrator who enabled it, and every user's private key is also encrypted to the escrow key.
  - Any administrator holding escrow can recover or reset users, **and can therefore read everything**.
  - The docs *recommend enabling escrow* to prevent data loss, but advise against it where only recipients should have access.
  - Advisory GHSA-w88m (below) shows escrow backup keys were cleared across tenants by a scoping bug.
- **Session key handling:**
  - User private keys are held in the session encrypted with SecretBox under a client-held session key. The server keeps only the SHA-256 of that key and decrypts per request.
  - Since 5.0.96, sessions are bound with DPoP-style proof-of-possession (RFC 9449 adapted): a non-extractable client keypair signs each request.
- **Crucial property: the crypto is server-mediated, not end-to-end.**
  - Keys are generated on the server.
  - Plaintext answers reach the server over TLS/Tor and are encrypted there.
  - Recipients' private keys are unwrapped on the server with the password-derived key they send.
  - So **a live-compromised backend, a malicious operator or a hosting provider with memory access sees plaintext and keys**.
  - The protection is **at rest** against someone who steals a disk or backup (the "breach the backend and brute-force" threat that the doc explicitly targets).
  - The project's own design-principles document says systems "should aim at PFS, E2EE, zero-knowledge design"; the current protocol does not deliver PFS or E2EE.
- **Offline brute force of receipts (my analysis):**
  - Because the receipt salt is per tenant, an attacker holding a DB dump can test each guess against every receipt hash at once.
  - About 53 bits × about 1 s of Argon2id at 128 MB per guess is still infeasible for a mass search (about 10^16 s of core-time), so the risk is low.
  - The shared salt removes a per-target multiplier, though. Our platform should use per-submission salts and a longer secret (≥ 80 bits, or a diceware passphrase).
- **PGP (optional):** users can upload a PGP key so that e-mail notifications and exported files are PGP-encrypted on the fly. Off by default.

### 1.4 Authentication, authorisation, sessions [B-GL-04]
- **Passwords:**
  - Complexity scoring. "Acceptable" means at least 12 characters, 4 character classes and 10 distinct characters; "Strong" means at least 14, 4 classes and 12 distinct.
  - Forced change at first login.
  - Periodic change, yearly by default. This is contrary to NIST SP 800-63B guidance, so we should not copy it.
- **2FA:**
  - TOTP (RFC 6238, 160-bit secrets). Optional per user; admins can enforce it.
  - Since 5.0.96: serialized one-time-use verification, step-up 2FA for voluntary password change, step-up confirmation for deleting users, contexts and tenants.
  - **No WebAuthn/FIDO2** in docs or code as of 5.0.99.
- **Sessions:**
  - No cookies. A 256-bit session ID is sent in the `X-Session` header.
  - 30-minute inactivity timeout; the session lives only in the browser tab. The tab-only storage was changed in 5.0.94 to avoid local session storage.
  - Since 5.0.96 sessions are revoked on password change or admin update, and DPoP-bound.
- **Brute force and abuse controls:**
  - Login slowdown of up to 60 s.
  - Hashcash proof-of-work on unauthenticated requests: Argon2id, 1 iteration, 1 MB.
  - Per-IP, per-tenant and per-system rate limits, for example 5 reports per hour per tenant per IP. Since 5.0.96, per-IP limits are skipped for Tor traffic.
  - **The client IP is processed in memory** for rate-limit keys. IPv4 is used whole; IPv6 is truncated to /64 (`utils/ip.py::get_ip_identity`).
- **Authorisation:**
  - Role checks happen in handlers, and tenant checks are a `tid` filter on each query.
  - Recurring defects in exactly this area are listed in §1.10: cross-tenant escrow clearing, recipient mass-assignment, missing admin role check on network config, non-assigned report exposure, and several tenant-isolation fixes in 5.0.93, 5.0.94 and 5.0.96.

### 1.5 Web hardening [B-GL-04]
- **CSP:**
  - `default-src 'none'`; `script-src 'self'`; `style-src` with a per-response nonce.
  - `require-trusted-types-for 'script'`, with Trusted Types policies restricted to angular, dompurify and default.
  - `frame-ancestors 'none'`; `form-action 'none'`; `base-uri 'none'`.
  - CSP violation reports are rate-limited.
- **Other headers:**
  - COEP `require-corp`; COOP `same-origin`; CORP `same-origin`; `Origin-Agent-Cluster`.
  - A very restrictive Permissions-Policy (camera, microphone, geolocation and many more disabled).
  - `Referrer-Policy: no-referrer`; `Cache-Control: no-store`; `X-Robots-Tag` (noarchive or noindex); `X-Frame-Options: deny`.
  - **HSTS is implemented but disabled by default.**
- **Input validation:**
  - The backend validates every request against a regex schema and caps payloads at 1 MB.
  - Angular's DomSanitizer handles rendering; Markdown goes through DOMPurify.
  - `autocomplete=off` on forms.
- **Forensic traces:** the client never changes the URI during whistleblower navigation, so the browser history shows only the homepage. This gives plausible deniability on non-Tor browsers.
- **External links:** `target=_blank`. Since 5.0.96 URLs are defanged, and CSV exports escape formula prefixes.

### 1.6 Files, sanitisation, malware
- File attachments are encrypted at rest. The docs' data-security matrix claims "Extension blocking, Antivirus".
  - **I found no antivirus (ClamAV or similar) integration in the 5.0.99 backend code** (`grep -ri virus` only hits a zipstream comment).
  - Treat the antivirus claim as **UNVERIFIED / possibly stale**.
- **No automatic metadata stripping.** This is deliberate: metadata is treated as evidence. Recipients are told to use MAT2 or to print documents [B-GL-09 threat-model.rst].
- Malware is explicitly out of scope. Recipients are told to use air-gapped machines, Qubes or Tails, and to export a ZIP to USB.
- An in-browser "safe viewer" handles audio, CSV, image, PDF, video and TXT, sandboxed on a null origin, "for low-risk threat models".
- **Voice anonymisation** is done client-side before upload: a Web Audio channel vocoder with non-affine formant warp. The docs honestly call it best-effort and weak against a strong adversary [B-GL-04].
- Secure deletion:
  - Files are overwritten three times (0s, 1s, random) by a scheduler. 5.0.99 fixed this to overwrite the *whole* file.
  - SQLite runs with `secure_delete=ON` (per connection since 5.0.94) and `auto_vacuum=FULL`.
  - Note: overwrite-based deletion is not reliable on SSDs, copy-on-write filesystems or cloud volumes. Crypto-erasure (deleting keys) is the correct primitive, and GlobaLeaks' per-report keys partly give it.

### 1.7 Messaging, questionnaire, contexts, case management
- Two-way whistleblower–recipient comments and a file exchange. Recipients can mark files private; since 5.0.96, recipient files are restricted to their author.
- **Contexts ("channels"):**
  - Each context has its own recipient set, questionnaire and retention.
  - The whistleblower can be allowed to choose recipients.
  - Conflict-of-interest handling lets the whistleblower exclude a recipient.
- **Questionnaire builder:**
  - Conditional questions and field templates.
  - Scoring and screening; since 5.0.96, scores are computed on the backend so the client cannot manipulate them.
  - Nesting depth is bounded against denial of service (5.0.99).
- **Identity handling:**
  - Optional identity disclosure, conditional on the workflow.
  - A **custodian** role must approve a recipient's request to see an identity. Since 5.0.99 the approval is definitive and scoped to the tenant.
- **Case management:**
  - Statuses and sub-statuses, labels, search, reminders, report transfer and assisted submissions.
  - **Redaction/masking** of answers, comments and files; several redaction-bypass bugs were fixed in 5.0.96 and 5.0.99.
  - Statistics; an audit log (extended to file access, exports and redactions in 5.0.96).
  - Audit logs are deleted after 5 years or on report deletion (5.0.90).
- **Retention:** default `tip_timetolive = 90` days, configurable per context, with expiry reminders. Receipts expire with the report.

### 1.8 Logging and metadata
- Claims: "No IP address logging" and "designed to avoid logging sensitive metadata" [B-GL-10 features.rst].
- **Code reality:**
  - Whistleblower IPs are processed in memory for rate limiting but not persisted.
  - **Internal users' IP and User-Agent ARE logged by default** (`log_accesses_of_internal_users = True`; `handlers/base.py` sets `log_ip_and_ua`). This is defensible, since it gives accountability for insiders.
  - The SaaS signup handler records `client_ip_address`.
- Issue #2225 (open since 2018) proposes geolocating IP and User-Agent *if* a whistleblower discloses their identity. It is not implemented, and our platform should never do it.
- **HTTPS clearnet caveat:** when clearnet is used, the ISP, the network, any CDN/TLS-terminating proxy and the hosting provider see the source IP whatever the application logs. The docs call this the "Confidential" (not "Anonymous") level, and discourage reverse proxies in front of GlobaLeaks.

### 1.9 Backups, build and release, supply chain
- **Backups:**
  - `gl-admin backup` writes an **unencrypted** `tar.gz` of `/var/globaleaks`, including "encryption material and configuration secrets".
  - The docs tell operators to `chmod 600` it and encrypt it before copying [B-GL-11].
  - Report content inside is still per-user encrypted, but the Tor onion private key, TLS keys and the escrow-wrapped keys are included.
- **Releases:**
  - The tag is GPG-signed by a core developer, and the Debian repo `Release` is detached-signed.
  - `scripts/build.sh` builds the packages; the docs say they are "built … with reproducibility in mind", but I found **no published reproducible-build verification** [B-GL-12 release-procedure.rst].
- **CI:**
  - GitHub Actions for the unit (trial) and E2E (Cypress) tests, plus CodeQL, OpenSSF Scorecard and publiccode validation.
  - Actions and dev dependencies are pinned to commit SHAs since 5.0.94.
  - SBOM is available through the GitHub dependency graph.
  - An OSS-Fuzz fork exists in the org.
- **install.sh weaknesses observed (5.0.99 stable docs and script):**
  1. The documented integrity step is `echo "0000…0000  install.sh" | sha256sum -c`, a **literal all-zero placeholder checksum**, on both `stable` and the published doc source. As written, the step either fails or trains admins to skip it.
  2. `install.sh` fetches the repository signing key with `curl https://deb.globaleaks.org/globaleaks.asc` (**trust on first use over WebPKI TLS, with no fingerprint pinning**).
  3. It writes the key into `/etc/apt/trusted.gpg.d/`, where APT trusts it for **all** repositories. The `signed-by=` on the source line does not stop that.
  4. The Docker example uses the mutable `:latest` tag.
  5. The script runs as root.

### 1.10 Advisories and CVEs (GlobaLeaks)
See the consolidated table in §7. Key points:
- Only 5 GHSAs are published (2026-03-27 and 2026-07-30), all rated Low or Moderate by the project.
- Earlier fixes (for example "Fix SSRF issue on HTTPS Proxy", 3.3.0 on 2018-08-06, and the 4.x directory-traversal and token-decorator bypass fixes) appear only in the CHANGELOG, with no CVE.
- CVE-2024-41671 is a **dependency CVE (Twisted: pipelined requests processed out of order, CVSS 8.3)**. It was backported in 5.0.94.
- In 2026 the project commissioned an ISGroup "Source Code Audit under an LLM-Equipped Adversary Model" [B-GL-19]. A search-result snippet (globaleaks.org, not read directly) says it "led to 29 confirmed vulnerabilities" (UNVERIFIED count). The 5.0.94 through 5.0.99 changelogs list the resulting hardening.
- Lesson: **mature, frequently audited projects still ship authorisation, tenant-scoping and mass-assignment bugs**. Enforce these properties structurally, not by per-handler discipline.

### 1.11 Accessibility and i18n
- Claims adherence to WCAG 2.2, WAI-ARIA, EU Directives 2019/882 (EAA) and 2016/2102.
- An automated Lighthouse audit exists (repo `globaleaks-lighthouse-audit`).
- **No third-party WCAG conformance report or VPAT found (UNVERIFIED).**
- i18n: "more than 70 languages" through Transifex (OTF Localization Lab), with RTL support.

### 1.12 Compliance claims
- Says it is "Designed in adherence to" ISO 37002:2021, Directive (EU) 2019/1937, ISO 27001:2022, GDPR and CSA STAR.
- These are **self-declarations of design alignment, not certifications of the software**; WBS as a SaaS provider may hold ISO 27001 separately (UNVERIFIED).
- 2019/1937-relevant features:
  - acknowledgement and follow-up timers via reminders
  - bidirectional anonymous communication
  - conflict-of-interest exclusion
  - identity custodian
  - retention policies

### 1.13 Strengths
- A clear, honest threat model: it separates Anonymous from Confidential, admits traffic analysis and malware are out of scope, and treats metadata as evidence.
- Tor onion by default with per-role Tor enforcement, a Tor-only fail-closed mode, and role IP allow-lists.
- An excellent browser-hardening baseline: CSP with Trusted Types, COOP/COEP, no cookies, DPoP-bound sessions, no-store, and no URI change.
- At-rest encryption with per-user and per-report keys, an Argon2id KDF, and padding.
- Fifteen years of real deployment and eight published external audits (2013–2026).
- Deep SQLite hardening: an authorizer allow-list, defensive mode, and triggers and views disabled.
- Small footprint; a Debian package; AGPL.

### 1.14 Weaknesses
- **Server-mediated crypto.** Keys are generated and unwrapped server-side, so there is no E2EE and no forward secrecy. A live server compromise equals total compromise.
- **The server delivers the JS client.** Even the client-side Argon2 and voice anonymisation are only as trustworthy as the server that serves the code. There is no pinned or reproducible client distribution.
- Clearnet submission is allowed by default, and HSTS is off by default.
- Multi-tenancy is a shared process and DB with query-level `tid` filters, which has a history of scoping bugs. There are no per-tenant keys, processes or DBs.
- Key escrow is recommended by default; it concentrates the ability to read everything in administrators.
- Backups are plaintext archives.
- `install.sh` trust issues (§1.9).
- The 16-digit receipt with a per-tenant salt is only moderate entropy.
- The antivirus claim is not visible in the code.
- There is a single-maintainer concentration.

---

## 2. CoverDrop (The Guardian + University of Cambridge) — deployed as "Secure Messaging" in the Guardian apps

### 2.1 Provenance
- Academic paper: "CoverDrop: Blowing the Whistle Through A News App", *Proceedings on Privacy Enhancing Technologies (PoPETs)* 2022, by Mansoor Ahmed-Rengers, Diana A. Vasile, Daniel Hugenroth, Alastair R. Beresford and Ross Anderson (Cambridge) [B-GL-20].
  - UNVERIFIED in this session: the issue and page numbers and the URL (petsymposium.org was blocked).
- Implementation white paper, June 2025, linked from the repo README at `https://www.coverdrop.org/coverdrop_guardian_implementation_june_2025.pdf` [B-GL-21] (not fetched).
- Source is public under Apache-2.0 at `github.com/guardian/coverdrop`. It is a mirror of an internal repo, and pull requests are not accepted [B-GL-22].
- Launch in the Guardian apps is believed to have been June 2024 under the name "Secure Messaging" (UNVERIFIED; the Guardian site was blocked).

### 2.2 Architecture [B-GL-22 README, docs/]
- **Components:**
  - An SDK module inside the ordinary Guardian Android and iOS news apps.
  - A cloud API: a Rust REST API on AWS behind the Fastly CDN, and the `u2j-appender` service, which appends to an AWS Kinesis stream.
  - The **CoverNode**, on-premises in a Guardian-controlled location on k3s. It is pull-only: **no inbound connections**.
  - An `identity-api` for key rotation.
  - A desktop **journalist client** ("Sentinel"), storing its data in a SQLCipher **journalist vault**.
- **Cover traffic:**
  - *Every* installed app periodically sends fixed-size encrypted messages, which are cover by default.
  - A real message replaces a cover message and is indistinguishable in size, timing and encryption.
  - This gives **plausible deniability for app usage**: whistleblowers blend into millions of news readers instead of the small set of Tor users.
- **Mixing:**
  - The CoverNode strips the outer layer, discards cover, and releases fixed-size, shuffled, signed **dead drops** under a threshold and timeout mix.
  - Production user-to-journalist (U2J): thresholds of 100k minimum and 500k maximum, 1 h timeout, 500 messages per dead drop.
  - Production journalist-to-user (J2U): thresholds of 50 minimum and 100 maximum, 1 h timeout, 20 messages per dead drop.
  - A cover-traffic service injects 80,000 U2J messages per hour in production.
  - Modelled real-message ratio in the U2J input: 0.01–0.06%.
  - Mean delay: about 0.4–0.8 h [B-GL-23 covernode_mixing.md].
  - The journalist downloads every dead drop and trial-decrypts. Sources likewise download all J2U dead drops, so **retrieval is private**.
- **Message format:**
  - Fixed-size payloads: GZip, then padding to 512 bytes, fixed-length bodies whatever the message type, and a 4-byte truncated recipient tag inside the inner layer [B-GL-24 protocol_messages.md].
- **Cryptography** (libsodium) [B-GL-25 cryptography.md]:
  - X25519 and Ed25519.
  - Anonymous Box (sealed box), Two-Party Box (crypto_box), Multi-Anonymous Box (to several recipients) and SecretBox (XChaCha20-Poly1305).
  - Test vectors are provided for some primitives.
  - The docs explicitly note that encodings are *not* indistinguishable from random. This matters for cover-traffic indistinguishability and is handled by an outer encryption layer.
  - Rust types preserve the plaintext/ciphertext distinction (`SecretBox<T>`).
- **Key hierarchy and rotation:**
  - An organisation trust anchor signs provisioning keys, which sign identity keys, which sign messaging keys.
  - Journalist messaging keys are **rotated daily with a 7-day TTL**, and clients pick the key with the longest remaining TTL. This gives forward security with a roughly one-day window and post-compromise recovery, with 0-RTT [B-GL-26 key_rotation.md].
  - Keys carry `not_valid_after` and are verified along the signature chain.
  - Trust anchors ship in the app.
- **Client storage with plausible deniability:**
  - *Every* app install has an encrypted vault of the same size, modified at the same times, whether or not it is used.
  - The passphrase is generated for the user from the EFF long wordlist (7,776 words):
    - 3 words with **Sloth** (Secure Element / Secure Enclave rate-limited key stretching, IACR ePrint 2023/1792), about 38.8 bits.
    - 5 words with Argon2id (3 iterations, 256 MiB) on Android devices without a Secure Element, about 64.6 bits.
  - The target is at least 100 years of exhaustive search against an adversary with a 1000-TiB cluster, plus a 10× margin [B-GL-27 client_passphrase_configurations.md].
  - A **Private Sending Queue** is an HMAC-hinted fixed-size queue whose snapshot does not reveal how many real messages are pending [B-GL-28 client_data_structures_and_algorithms.md].
  - Background sending uses the OS schedulers (iOS BGAppRefreshTask, Android WorkManager) with exponential jitter of 5–120 minutes.
- **Journalist side:**
  - Vaults are provisioned on an **offline laptop** with a setup bundle; the provisioning key never touches the network.
  - Backups are **forward-secure cloud backups with social recovery** [B-GL-29 backups.md]:
    - the vault is padded to a 1 MiB step and encrypted with a fresh key;
    - the key is Shamir-split k-of-n to recovery contacts, then encrypted again under an offline backup key and stored in S3;
    - recovery needs the admin team (offline machine) plus k contacts.
- **Deployment:**
  - Cloud side: AWS, provisioned with CDK.
  - On-premises: Ubuntu, hardened, k3s. GitOps via ArgoCD; each deploy is a PR into a private platform repo that a developer must approve manually. Sealed secrets and Longhorn [B-GL-30 on_premises_deployment.md].
- **Group messaging:** end-to-end encrypted group messaging (OpenMLS) is in development for journalist-to-journalist use and is not yet carrying source material.

### 2.3 Threat model and limitations
- Designed against a **global passive network observer**, device seizure (plausible deniability), and compromise of the cloud tier. The cloud never sees plaintext and cannot tell real messages from cover.
- It trusts the CoverNode for unlinking.
- Stated open problems (README): side channels from *other components of the host news app* (analytics SDKs, crash reporters, UI state, notifications), "ongoing work with no existing definite solution".
- Traffic volume and latency: messages are small and text-only (roughly 512-byte padded text; **no document uploads**), and delivery is delayed by hours. It is a first-contact channel, not a document drop.
- Fastly terminates TLS and sees client IPs and timing. Because every app instance produces identical traffic, the IP reveals only "Guardian reader".
- A documented residual issue: the AWS load balancer is publicly reachable and could be hit directly, bypassing Fastly [B-GL-31 fastly_cdn.md].
- Requires control of a mass-market app. **This is not transferable to organisations without a popular app.** An enterprise analogue would be cover traffic from an employee-mandatory app (the intranet/HR app) or from a browser extension deployed fleet-wide.
- Audit: the repo refers to "equivalent services created for the security audit" and to a PROD/AUDIT environment, so an external audit took place. **No public audit report was found (UNVERIFIED).**

### 2.4 Lessons from CoverDrop
- **Adopt:**
  - Fixed-size, fixed-schedule cover traffic.
  - The rule that a server which does not need to be reachable should not be: the on-premises CoverNode pulls and never listens.
  - Trial-decryption retrieval of dead drops, for private retrieval.
  - Daily-rotated recipient keys with a signed key hierarchy and trust anchors shipped in the client.
  - Offline provisioning ceremonies.
  - Forward-secure social-recovery backups instead of admin escrow.
  - Generated passphrases with hardware rate-limiting (Sloth).
  - Uniform vaults on every install.
  - The type-safe ciphertext wrappers.
- **Do not copy blindly:**
  - Its tiny message size (unsuitable for evidence files).
  - Its reliance on a very large user base for anonymity; small deployments give a small anonymity set.
  - Mix parameters tuned to hundreds of thousands of senders per hour.

---

## 3. Hush Line (Science & Design, Inc.)

### 3.1 Design [B-GL-32 README; B-GL-33 THREAT-MODEL.md; B-GL-34 PRIVACY.md]
- Flask, Postgres and optional S3 (DigitalOcean Spaces). Hosted SaaS at `tips.hushline.app` on DigitalOcean App Platform, deployed by Terraform Cloud with manual apply; single-tenant instances and a "personal server" variant also exist.
- Tor onion support.
- A tip-line model: an anonymous sender posts to `/to/<username>` with no account.
- **Encryption:**
  - Client-side OpenPGP.js to the recipient's PGP key; a PGP key is required to receive tips.
  - A **server-side encryption fallback** exists.
  - Padded ciphertext.
  - Account data is encrypted at rest with a server `ENCRYPTION_KEY` (Fernet/AES; see the ENCRYPTED-FIELD ADRs).
- **Two-way chat:** optional E2EE account conversations. Keys are per participant, envelopes are signed, and AES-GCM AAD binds each envelope to its conversation and participants. Key-change warnings exist, but **no key-transparency log**.
- **Anonymous replies:** status and reply links use a random slug of about 51 bits that acts as a bearer secret.
- **Authentication:** scrypt password hashes; TOTP; WebAuthn MFA (rollout docs); an encrypted `__Host-` session cookie with SameSite=Strict.
- **Recipient trust:** a verified-account directory, plus sync with the SecureDrop and GlobaLeaks directories.
- **ISO 37002:** mapping document `docs/ISO-37002.md`.
- **CI:** privacy and E2EE regression workflows, a GDPR/CCPA "compliance" workflow, Lighthouse accessibility checks, workflow-security checks, a dependency audit, and W3C validators.
- **Privacy policy:**
  - "We do not store IP addresses or user-agent strings in the database". Note the qualifier *in the database*: the hosting platform and edge still see IPs.
  - Authentication logs store the **TOTP code and timecode** of successful 2FA logins. This is odd, but it is used for replay prevention.
- **The threat model honestly states:**
  - "Client-side encryption is only as trustworthy as the JS served to the submitter; a compromised server or build pipeline can bypass E2EE."
  - Compromise of `ENCRYPTION_KEY` or the DB is catastrophic.
  - Login endpoints lack global rate limiting.
- **Audit:** a pre-engagement audit hit-list (2026-02-24) targets Subgraph. No published third-party audit report was found (UNVERIFIED).

### 3.2 Advisories (see §7)
- GHSA-4v8c-r6h2-fhh3 / CVE-2024-38521: persistent XSS in the inbox. The template used `{{ message.content | safe }}`, and an attacker could set `client_side_encrypted=true` with plaintext HTML to bypass the server-side encryption path. CVSS 8.8.
- GHSA-4c38-hhxx-9mhx / CVE-2024-38523: TOTP reusable within its window, unlimited attempts (IP rate limiting only), and OTP disable / PGP key change without re-authentication. CVSS 7.5.
- GHSA-r85c-95x7-4h7q: CSP bypass (dev beta, Moderate).
- GHSA-j857-9q45-73jr: the `authentication_required` decorator did not stop requests reaching the endpoint (Low).
- GHSA-m592-g8qv-hrqx / CVE-2024-55888: **no security headers at all in production** (tips.hushline.app). The root cause was suspected to be the app or its Cloudflare configuration. Reported by evilaliv3, the GlobaLeaks lead. CVSS 7.1.
  - Implication: **production traffic was fronted by Cloudflare** at that time, so a third-party CDN terminated TLS for whistleblower traffic.
- Reporters lsd-cat and evilaliv3 show the value of peer projects cross-auditing each other.

### 3.3 Lessons
- **Adopt:**
  - A calibrated severity rubric that ranks anonymity-affecting bugs higher.
  - E2EE / privacy regression tests in CI.
  - Explicit "client JS is trusted" statements.
  - AAD-bound, signed envelopes.
- **Do not copy:**
  - A server-side encryption fallback: it creates a downgrade path, as the XSS bypass exploited.
  - Client-controlled flags that decide server security behaviour (`client_side_encrypted`).
  - Rendering with `|safe`.
  - Putting a third-party TLS-terminating CDN in front of source traffic.
  - Bearer-slug reply links of about 51 bits.

---

## 4. Other open-source / secure-intake systems (brief)

### 4.1 SecureDrop (Freedom of the Press Foundation) — the reference design (details from prior knowledge; see companion research file for depth)
- A Tor-only source interface.
- An air-gapped Secure Viewing Station (Tails), with GPG encryption to an offline key.
- A dedicated hardware firewall and a monitor server; the source interface is served only over an onion service.
- A diceware codename for the source.
- SecureDrop Workstation on Qubes, with per-document disposable VMs.
- It is the opposite trade-off to GlobaLeaks: high assurance, high operational burden, and no clearnet.

### 4.2 Tella (Horizontal) [B-GL-35]
- A mobile app for documentation, not a whistleblowing server.
- Features:
  - an encrypted gallery separate from the OS gallery
  - app camouflage (for example, a calculator icon)
  - quick delete
  - capture of verification metadata
  - submission to organisation servers (Tella Web, and also Open Data Kit / Uwazi per its docs; UNVERIFIED in this session)
- Relevant lessons: a camouflage/decoy UI, quick-erase, and verification metadata for evidentiary integrity (the opposite of metadata stripping). Store both a sanitised copy and a hash-attested original.

### 4.3 "Hermes"
- Not a separate tool. It is the Hermes Center, the steward of GlobaLeaks (see §1.1).

---

## 5. Commercial whistleblowing platforms (ALL UNVERIFIED — vendor sites unreachable this session)

**General pattern.** Nearly all commercial EU-Directive/SOX hotline products share these traits:
- Multi-tenant **clearnet SaaS** on a hyperscaler or colocated EU hosting.
- A web form plus a phone hotline and sometimes an app.
- Anonymous follow-up through a system-generated **report key or case number plus a user-chosen password**.
- "Encryption in transit (TLS) and at rest" (provider- or KMS-managed keys, not per-recipient E2EE).
- ISO 27001 and often SOC 2 certification.
- Data residency options.
- An anonymity statement of the form "we do not track or store IP addresses / we do not use cookies".

This is **policy-based anonymity**:
- the vendor, its CDN or WAF, and its cloud provider technically see the source IP, TLS fingerprint and timing;
- logs can be enabled, compelled or leaked;
- the customer (the employer being reported on) often controls the intranet, network egress, endpoint agents and SSO, and can correlate timing.

| Vendor | What they typically disclose (UNVERIFIED) | Notes |
|---|---|---|
| NAVEX EthicsPoint | Hosted web intake plus call centre. FAQ historically states EthicsPoint "does not generate or maintain any internal connection logs with IP addresses". Report key + password for anonymous follow-up. | NAVEX also acquired WhistleB (Sweden) around 2021 (UNVERIFIED). |
| EQS Integrity Line | EU-hosted SaaS (Germany/Switzerland data centres claimed). ISO 27001. Anonymous "secure mailbox". Claims encryption of reports. | Market leader in DACH. |
| Whispli | Anonymous two-way chat, AWS hosting, ISO 27001. | Australia. |
| Vault Platform | "GoTogether" feature: a report is revealed only when others report the same person (a collective-action threshold). | Interesting UX idea; the anonymity is still policy-based. |
| Convercent (now OneTrust Ethics) | Hotline + web; acquired by OneTrust around 2021 (UNVERIFIED). | |
| Speeki, Whistlelink, FaceUp, AllVoices | Clearnet SaaS; anonymous chat; ISO 27001 claims; "no IP logging" statements. | SMB/EU-Directive focus. |

**Why policy-based anonymity is weaker (for requirements):**
1. Network-level identifiers reach infrastructure the vendor does not fully control (CDN, WAF, DDoS protection, load-balancer logs, cloud flow logs), and they are enabled by default in most clouds.
2. A promise not to log can be reversed silently by configuration, compelled by legal process (subpoena or production order) or breached. The whistleblower cannot verify it.
3. Employer-controlled endpoints and networks (proxy logs, EDR, DNS logs, SSO) see the visit whatever the vendor promises.
4. Closed source means no independent verification. The GlobaLeaks lead makes the same argument in "The pitfalls of closed-source whistleblowing software" (WIN, 2022) [B-GL-36].
5. Keys are managed by the vendor or KMS, so an insider at the vendor, or legal compulsion, can reach plaintext.

The minimum bar for us is **technical anonymity**:
- Tor/onion or cover traffic;
- a client that cannot leak identifiers;
- recipient-held keys;
- verifiable builds.

Policy statements should be secondary controls.

### 5.1 Anonymous tip lines (Crime Stoppers / P3)
- Canada: *R. v. Leipert*, [1997] 1 S.C.R. 281. The Supreme Court held that informer privilege covers Crime Stoppers tips, and that editing (redacting) a tip sheet is not enough when the informer could still be identified. The tip sheet was not to be disclosed except under the innocence-at-stake exception.
  - Case citation from knowledge; URL not verified in session.
- US: several states grant Crime Stoppers tip information statutory confidentiality, for example Texas Government Code §414.008 (UNVERIFIED).
- P3 Tips (Anderson Software) marketing claims to strip or not retain IP and device identifiers (UNVERIFIED).
- Lesson: **legal privilege is jurisdiction-specific and can be overridden** (for example, the innocence-at-stake exception). Data that does not exist cannot be compelled. Design for minimal retention and technical unlinkability, not for privilege.

---

## 6. Incident entries

### INC-1 GlobaLeaks GHSA-x4cq-h872-f8wx / CVE-2026-45020 — recipient mass-assignment of `receipt_hash`
- **INCIDENT:** Authenticated recipients could modify arbitrary InternalTip attributes, including `receipt_hash`, through `/api/recipient/rtips/<id>`. Affected 4.12.1–5.0.91; fixed in 5.0.92 (2026-05-06); disclosed 2026-07-30. CVSS 6.5.
- **WHAT FAILED:** `set_internaltip_variable()` accepted attacker-chosen attribute names with no allow-list.
- **ROOT CAUSE:** A generic "set attribute by key" API (CWE-915) on a security-sensitive model.
- **DATA EXPOSED:** No confidentiality impact per the advisory. Integrity only: an attacker could invalidate or replace the whistleblower's authenticator, locking the source out or hijacking follow-up (a phishing channel via a replaced receipt is conceivable; my inference).
- **CAPABILITY REQUIRED:** A valid recipient account (a malicious or compromised insider).
- **WHY DESIGN DID NOT PREVENT IT:** Recipients are "trusted" in the threat model, so internal-user APIs got less adversarial scrutiny. Authentication material lived in the same mutable record as case metadata.
- **ARCHITECTURAL LESSON:** Separate authentication secrets from case records. Treat insiders (recipients) as adversaries to the *source*. Make update DTOs explicit.
- **REQUIREMENT:** R-AUTHZ-01: every mutation endpoint uses an explicit per-role field allow-list, and source-credential material is stored in a separate table/service that no recipient or admin API can write.
- **TEST:** A property-based API fuzz test enumerates every model attribute on each PATCH/PUT endpoint as each role and asserts that only allow-listed fields change. A dedicated test asserts that source-credential hashes are immutable except through the source's own authenticated rotation flow.

### INC-2 GlobaLeaks GHSA-w88m-4vmc-pq9g / CVE-2026-46648 — cross-tenant escrow key wipe
- **INCIDENT:** Disabling escrow on one tenant cleared `crypto_escrow_bkp2_key` for **every user in every tenant**. Affected ≤5.0.93; fixed in 5.0.94 (the advisory page as summarised said "5.9.4", probably a typo); disclosed 2026-07-30. CVSS 4.1.
- **WHAT FAILED:** Two of three UPDATE statements lacked a `tid` filter.
- **ROOT CAUSE:** Tenant isolation was implemented as per-query discipline in a shared DB.
- **DATA EXPOSED:** None. The damage is an availability/integrity loss of a recovery path across tenants.
- **CAPABILITY REQUIRED:** A (non-root) tenant administrator.
- **WHY DESIGN DID NOT PREVENT IT:** There is no structural tenant boundary: one SQLite DB, one process, one ORM session. Also see the tenant-isolation fixes in 5.0.93, 5.0.94 and 5.0.96.
- **ARCHITECTURAL LESSON:** Multi-tenant whistleblowing needs isolation enforced by the database or infrastructure (row-level security with a mandatory tenant context, or separate DBs, keys and processes per tenant), not by developer memory.
- **REQUIREMENT:** R-TEN-01 has three parts:
  - Enterprise/Gov edition: per-tenant database/schema, per-tenant KEKs and per-tenant process isolation.
  - Community multi-site mode: Postgres RLS with a `SET LOCAL app.tenant_id` enforced by a connection wrapper. Queries without a tenant context fail closed.
  - Cross-tenant bulk writes are forbidden outside a separate, audited root-maintenance tool.
- **TEST:** A CI test harness creates two tenants, runs every admin and recipient API action on tenant A, and asserts a byte-identical DB snapshot of tenant B. The RLS policy is also tested by attempting raw SQL without a tenant context and expecting an error.

### INC-3 GlobaLeaks GHSA-m5xx-3qv7-37hj / CVE-2026-46647 — missing role check on `/api/admin/network`
- **INCIDENT:** A non-admin internal user (for example a recipient) on the root tenant could read and modify network settings: HTTPS, IP filters and Tor anonymisation options. Fixed in 5.0.93.
- **WHAT FAILED:** A missing authorisation decorator (CWE-862).
- **ROOT CAUSE:** Access control was opt-in per handler.
- **DATA EXPOSED:** Configuration. The *capability* is severe for anonymity: an insider could enable clearnet for whistleblowers or alter the outbound Tor settings.
- **CAPABILITY REQUIRED:** A recipient account on the root tenant.
- **WHY DESIGN DID NOT PREVENT IT:** No deny-by-default route policy existed.
- **ARCHITECTURAL LESSON:** Deny by default. Anonymity-relevant settings are security-critical and need step-up authentication and multi-party approval.
- **REQUIREMENT:** R-AUTHZ-02: a route table with mandatory role declarations, so the build fails if any route lacks one. R-CFG-01: changes to anonymity-affecting config (Tor-only, clearnet enablement, logging level, escrow) require two-person approval, are notified to all recipients and are displayed to sources.
- **TEST:** A static route-inventory test. A per-route role matrix test covering all routes and roles. An e2e test showing that toggling clearnet by one admin stays pending until a second approver signs.

### INC-4 GlobaLeaks GHSA-9vhh-65v7-3xj6 — non-assigned reports visible on legacy unencrypted platforms
- **INCIDENT:** On platforms with encryption disabled (a legacy mode, unsupported since 3.0.0 in 2018), channel recipients could see the answers and labels of reports not assigned to them. Fixed in 5.0.97 (2026-07-07). CVSS 2.2.
- **ROOT CAUSE:** Authorisation relied implicitly on encryption: a recipient lacks the key, so they "cannot" read. The plaintext path skipped the redaction and authorisation step.
- **LESSON:** Crypto must not be the only access-control layer, and legacy modes must be removed rather than kept alive.
- **REQUIREMENT:** R-AUTHZ-03: authorisation checks apply independently of encryption state. There is no "encryption disabled" mode in our product, and migrations refuse to start on unencrypted data.
- **TEST:** Run the authorisation test suite with key material present for every user (a simulated key leak) and assert that access is still denied by policy.

### INC-5 CVE-2024-41671 — Twisted HTTP pipelining out-of-order responses (dependency)
- **INCIDENT:** twisted.web (≤24.3.0) could process pipelined HTTP/1.x requests out of order, potentially sending one request's response to another. CVSS 8.3. GlobaLeaks "backported the patch" in 5.0.94.
- **WHAT FAILED:** The HTTP framing layer in the application server.
- **DATA EXPOSED:** Potential cross-request response disclosure (for example, one user's API response delivered to another client through a shared connection or proxy).
- **CAPABILITY REQUIRED:** A network client able to pipeline requests; realistic behind reverse proxies or Tor circuits multiplexing.
- **WHY DESIGN DID NOT PREVENT IT:** The application embeds its own HTTP stack (Twisted), and security fixes depend on a niche upstream and on distribution backports.
- **LESSON:** Minimise and pin the HTTP-parsing surface; track dependency CVEs with an SBOM; prefer a hardened, widely deployed front server.
- **REQUIREMENT:** R-SUP-01: an SBOM per release, automated CVE matching blocking release on High or Critical, and a documented 72-hour patch SLA for network-facing dependencies.
- **TEST:** A CI job fails when the SBOM matches an open High or Critical CVE. An HTTP request-smuggling and pipelining conformance suite runs against the front end.

### INC-6 Hush Line GHSA-4v8c-r6h2-fhh3 / CVE-2024-38521 — stored XSS in recipient inbox via encryption-bypass flag
- **INCIDENT:** An anonymous sender set `client_side_encrypted=true` with plaintext HTML, and it was rendered with `|safe` in the recipient inbox. CVSS 8.8 (Hush Line dev beta, June 2024).
- **ROOT CAUSE:**
  1. The server trusted a client-supplied flag to decide whether to encrypt.
  2. Output encoding was disabled on the assumption that "ciphertext is safe".
- **DATA EXPOSED:** Potentially the entire inbox (JS exfiltration). Also changes to PGP keys and 2FA settings, meaning silent key substitution for all future tips.
- **CAPABILITY REQUIRED:** An anonymous submitter (no account).
- **WHY DESIGN DID NOT PREVENT IT:** There was a dual-path encryption design (client plus server fallback), there was no CSP (compare CVE-2024-55888), and security-setting changes needed no step-up.
- **LESSON:** Never let the client choose the security mode. Treat all source content as hostile active content. Key changes need re-authentication and out-of-band notification.
- **REQUIREMENT:** R-XSS-01: source content is only ever rendered as text or in a sandboxed null-origin iframe; there is no raw-HTML path. R-CRYPTO-01: the server rejects any submission not in the canonical encrypted envelope format and never stores source plaintext. R-KEY-01: a recipient key change requires WebAuthn step-up, notifies other recipients and admins, and is recorded in a transparency log.
- **TEST:** Submit a polyglot XSS corpus through every source input path (including malformed and "pre-encrypted" claims), then render in a headless browser and assert no script execution or network beacons. A key-change test asserts that step-up and notification are enforced.

### INC-7 Hush Line GHSA-m592-g8qv-hrqx / CVE-2024-55888 — production served with no security headers (CDN config)
- **INCIDENT:** tips.hushline.app responses lacked CSP, HSTS and other headers. The suspected cause was the application or its Cloudflare configuration. Patched ≥0.3.46. CVSS 7.1.
- **ROOT CAUSE:** Headers were set in a layer that the production path (the CDN) bypassed or stripped. Tests ran against dev, not production.
- **LESSON:** Test security invariants against the deployed artifact, and avoid putting third-party TLS terminators in front of source traffic.
- **REQUIREMENT:** R-OPS-01: continuous external probes against every production hostname and onion assert the header set, TLS configuration and absence of third-party origins. R-NET-01: no third-party CDN or WAF terminates TLS for the source interface.
- **TEST:** A scheduled synthetic check (from outside, over clearnet and Tor) compares headers to a golden policy and pages on drift.

### INC-8 Hush Line GHSA-4c38-hhxx-9mhx / CVE-2024-38523 — OTP reuse, no per-account throttle, no step-up
- **LESSON / REQUIREMENT:**
  - R-AUTH-01: one-time use of each OTP.
  - Per-account attempt counters with lockout and backoff.
  - WebAuthn preferred.
  - Step-up for security-setting changes.
- **TEST:** Replay the same TOTP twice (the second is rejected). Make 20 wrong codes (the account is locked). Disable 2FA without step-up (rejected).

### INC-9 GlobaLeaks Cure53 2013 GL01-002 / GL01-004 (historic)
- **INCIDENT:** GL01-002 was XSS through MIME sniffing of JSON in legacy IE. GL01-004 was possible information leakage through the browser and proxy cache. Both came from the Cure53 2013 web audit and are tracked in issues #312 and #314 (closed).
- **LESSON:** `nosniff`, `no-store` and strict content types are table stakes. GlobaLeaks' current header set comes from these findings.
- **REQUIREMENT:** R-WEB-01: the header baseline in §8 is enforced by tests.
- **TEST:** The header golden test (INC-7).

### INC-10 Policy-based anonymity failure: Barclays CEO attempt to unmask an anonymous whistleblower (2016; regulatory outcome 2018) — UNVERIFIED details
- **INCIDENT:** Barclays' CEO directed the Group Information Security team to try to identify the author of anonymous letters about a senior hire. The UK FCA and PRA fined him (reported as £642,430, May 2018; UNVERIFIED), and the bank had to report on its whistleblowing controls.
- **WHAT FAILED:** Organisational controls. The intake was a letter/e-mail channel, and the employer controlled the investigative resources.
- **ROOT CAUSE:** The anonymity relied on the organisation *choosing* not to investigate the whistleblower.
- **DATA EXPOSED:** Attempted identification (reports indicate US Postal Service assistance was sought; UNVERIFIED).
- **CAPABILITY REQUIRED:** A senior insider with command of the security team.
- **WHY DESIGN DID NOT PREVENT IT:** No technical unlinkability, and no separation of duties between those reported on and those with investigative powers.
- **LESSON:** The strongest adversary in corporate and government deployments is often the **organisation's own senior staff**. The platform must deny them identifying data by construction, and must log and alert on attempts to access identity.
- **REQUIREMENT:**
  - R-ID-01: identity data is encrypted to a custodian quorum that is distinct from the case owners.
  - Identity access requires a documented, dual-approved justification, is visible to an independent oversight role, and is never available to administrators.
  - Deployments must support placing the service operator (the hosting entity) outside the reported-on organisation.
- **TEST:** An attempt by an admin, or by a single custodian, to reveal identity fails. The audit trail entry is emitted to an append-only external log and the oversight notification is observed.

---

## 7. Audit / advisory table

| Date | ID | Finding | Severity | Lesson |
|---|---|---|---|---|
| 2013 | iSEC Partners architecture audit [B-GL-13] | Report not accessed (UNVERIFIED contents) | — | Architecture review early |
| 2013 | Cure53 web audit GL01-002 [B-GL-14] | XSS via JSON MIME sniffing on the auth page (legacy IE) | UNVERIFIED | nosniff + strict JSON |
| 2013 | Cure53 GL01-003 | Unsafe file downloads in the receiver area causing local XSS (issue #313) | UNVERIFIED | Force `Content-Disposition: attachment`; sandbox viewers |
| 2013 | Cure53 GL01-004 | Information leakage through browser and proxy cache (issue #314) | UNVERIFIED | `Cache-Control: no-store` |
| 2013 | Cure53 GL01-011 | Admin uploads functional despite content filter (issue #300) | UNVERIFIED | Validate uploads server-side |
| 2014 | LeastAuthority source audit [B-GL-15] | Findings fixed in 2.60 (2014-04-22) per CHANGELOG [verified 2026-10-01, https://github.com/globaleaks/globaleaks-whistleblowing-software/blob/main/CHANGELOG]; contents not accessed | UNVERIFIED | — |
| 2018 | Subgraph overall audit [B-GL-16] | Report not accessed; 3.3.0 (2018-08-06) "Fix SSRF issue on HTTPS Proxy", "Disable error stacktrace on production" [verified 2026-10-01, https://github.com/globaleaks/globaleaks-whistleblowing-software/blob/main/CHANGELOG] | UNVERIFIED | SSRF controls on admin-configured outbound URLs |
| 2019 | Radically Open Security: crypto, multi-tenancy, overall [B-GL-17] | Report not accessed | UNVERIFIED | Multi-tenancy was already an audit focus in 2019 |
| 2022 (Jun–Aug) | Radically Open Security: server source audit, client pentest, whistleblower and admin opsec [B-GL-18] | Per the OTF summary snippet, a "security-in-depth approach … low severity of findings" | Low (per snippet) | Defence in depth works |
| 2024 | ISGroup surface analysis + network pentest | Report not accessed | UNVERIFIED | — |
| 2026 | ISGroup "Source Code Audit under an LLM-Equipped Adversary Model" [B-GL-19] | "29 confirmed vulnerabilities", 2 High, no Critical, 12 DoS observations, audit 2026-06-01..30, fixes from 5.0.96 [verified 2026-10-01, https://globaleaks.org/2026/07/30/globaleaks-strengthens-security-against-ai-enabled-threats/]; hardening in 5.0.94–5.0.99 (tenant isolation, redaction bypasses, TOTP, DPoP, rate limits, CSV injection, SMTP cert validation) | Mixed | LLM-assisted auditing finds many authorisation and logic bugs; budget for it |
| 2018-08-06 | GL 3.3.0 changelog | SSRF on HTTPS proxy | UNVERIFIED | Egress allow-lists |
| 2024-07-29 | CVE-2024-41671 (Twisted) | Pipelined requests processed out of order; response disclosure | High 8.3 | Dependency SLA; HTTP-stack minimisation |
| 2026-03-27 | GHSA-84wr-q36q-wqhv / CVE-2026-33284 | `/api/support` forwarded arbitrary URLs in admin e-mails (phishing vector); ≤5.0.88, fixed 5.0.89 | Low 2.1 (the project); NVD-type sources show 4.3 | Defang all untrusted URLs in notifications |
| 2026-07-30 | GHSA-x4cq-h872-f8wx / CVE-2026-45020 | Recipient mass-assignment incl. `receipt_hash`; 4.12.1–5.0.91 | Moderate 6.5 | INC-1 |
| 2026-07-30 | GHSA-w88m-4vmc-pq9g / CVE-2026-46648 | Cross-tenant escrow backup-key wipe; ≤5.0.93 | Moderate 4.1 | INC-2 |
| 2026-07-30 | GHSA-m5xx-3qv7-37hj / CVE-2026-46647 | Missing admin role check on the network config endpoint; ≤5.0.92 | Low 3.3 | INC-3 |
| 2026-07-30 | GHSA-9vhh-65v7-3xj6 / CVE-2026-70655 (ID as reported by the summarizer; no record in CVE List V5 as of 2026-10-01 (https://github.com/CVEProject/cvelistV5); cite the GHSA ID only. Fix consistent with GL 5.0.97 CHANGELOG "Correct reports listing on platforms still without encryption") | Non-assigned reports visible on legacy unencrypted platforms; ≤5.0.96 | Low 2.2 | INC-4 |
| 2024-06-25 | Hush Line GHSA-4v8c-r6h2-fhh3 / CVE-2024-38521 | Stored XSS in inbox + encryption bypass flag | High 8.8 | INC-6 |
| 2024-06-25 | Hush Line GHSA-4c38-hhxx-9mhx / CVE-2024-38523 | OTP reuse, no per-account throttle, no step-up | High 7.5 | INC-8 |
| 2024-06-25 | Hush Line GHSA-r85c-95x7-4h7q | CSP bypass (dev beta) | Moderate | CSP must forbid inline scripts; use Trusted Types |
| 2024-11-27 | Hush Line GHSA-j857-9q45-73jr | Auth decorator did not stop requests reaching the handler | Low | Deny-by-default middleware |
| 2024-12-12 | Hush Line GHSA-m592-g8qv-hrqx / CVE-2024-55888 | No security headers in production (CDN/app) | High 7.1 | INC-7 |
| n/a | CoverDrop | Audit environment referenced in the repo; no public report found | UNVERIFIED | Publish audits |
| 2026-09 (observation) | GlobaLeaks install docs | All-zero placeholder sha256; repo key fetched TOFU into `trusted.gpg.d` | Observation (mine) | Pin fingerprints; publish real checksums; scope keys |

---

## 8. ADOPT list

1. **A Tor onion service as the primary source channel**, with per-role transport policy, a fail-closed Tor-only mode, and a UI that shows the source their current anonymity level (from GlobaLeaks).
2. **A strict browser-hardening baseline** (from GlobaLeaks):
   - CSP with `require-trusted-types-for 'script'` and nonce-bound styles;
   - COOP/COEP/CORP and Origin-Agent-Cluster;
   - a restrictive Permissions-Policy;
   - `no-store`, `no-referrer` and `nosniff`;
   - no cookies (header sessions);
   - **DPoP-bound sessions**;
   - no URI changes in the source flow.
3. **Per-report data keys wrapped to each recipient's key; padding of files and messages.** Upgrade this to client-side key generation (see "do not copy").
4. **SQLite/DB hardening mindset**: an authorizer allow-list of SQL operations, defensive mode, triggers and views disabled, and `secure_delete`. With Postgres, use restricted roles, RLS and no superuser for the app.
5. **Proof-of-work plus layered rate limits that exempt Tor** from per-IP keys.
6. **An identity custodian with separation of duties**; conditional identity disclosure; conflict-of-interest exclusion of recipients by the source.
7. **Honest threat-model documentation** (GlobaLeaks and Hush Line): state what is out of scope (traffic analysis, malware, metadata).
8. **CoverDrop techniques:**
   - fixed-size, fixed-schedule cover traffic;
   - a pull-only, non-listening secure core;
   - dead-drop broadcast with trial decryption;
   - a signed key hierarchy with daily-rotated, TTL-bounded recipient keys;
   - trust anchors pinned in the client;
   - offline provisioning ceremonies;
   - **forward-secure, Shamir social-recovery backups** in place of admin key escrow;
   - generated diceware passphrases with hardware rate-limiting (Sloth);
   - uniform plausibly-deniable local storage;
   - type-safe ciphertext wrappers.
9. **Hush Line practices:**
   - a severity rubric weighted to anonymity;
   - E2EE/privacy regression workflows in CI;
   - AAD-bound, signed message envelopes;
   - WebAuthn MFA;
   - directory-verified recipient identity.
10. **Published, periodic third-party audits** (GlobaLeaks: 8 audits over 13 years); the budget should include an LLM-assisted source audit.
11. **Voice anonymisation client-side**, labelled honestly as best-effort. Offer it, and default to text transcription.
12. **Short default retention (90 days) with explicit extension**; audit-log retention bounded and deleted with the case.
13. **Evidence integrity**: keep a hash-attested original plus an optionally sanitised working copy (Tella's verification metadata idea combined with GlobaLeaks' "metadata is evidence" stance).

## 9. Do NOT copy list

1. **Server-side key generation and server-side unwrapping of recipient private keys** (GlobaLeaks). A live-compromised server is total compromise, and there is no PFS. Recipient keys must be generated and used only on recipient devices, ideally hardware-backed.
2. **Security-critical crypto code delivered live from the server that holds the data** (GlobaLeaks and Hush Line JS). Provide a signed, reproducible, pinned client instead: a native or desktop app, a browser extension, or at least an SRI-pinned bundle whose hash is published in a transparency log and checked by an independent verifier.
3. **Clearnet submission enabled by default; HSTS off by default.** Clearnet should be an explicit, warned, per-deployment decision with HSTS preload.
4. **Administrator key escrow recommended by default.** Use k-of-n recovery with independent parties and offline keys (CoverDrop) instead.
5. **Shared-process, shared-DB multi-tenancy with per-query `tid` filters.**
6. **Mass-assignment ("set any attribute") APIs**; authorisation that assumes a missing key means no access; keeping an "encryption disabled" legacy mode.
7. **Unencrypted backups** containing onion and TLS keys and escrow material.
8. **`curl | gpg` into `/etc/apt/trusted.gpg.d/`, placeholder checksums, `:latest` images.**
9. **Periodic forced password rotation** (contrary to NIST 800-63B).
10. **Relying on file-overwrite "secure delete"** on SSD, copy-on-write or cloud storage. Use crypto-erasure.
11. **Server-side encryption fallback and client-controlled security flags** (Hush Line CVE-2024-38521); `|safe` rendering of any source content.
12. **Third-party CDNs or WAFs terminating TLS for source traffic** (Hush Line with Cloudflare; CoverDrop's Fastly is acceptable *only* because all traffic is uniform cover traffic).
13. **Policy-only anonymity claims** ("we don't log IPs") as the primary protection (commercial SaaS).
14. **Short bearer secrets** as the only source authenticator: 16 digits (about 53 bits) with a per-tenant salt, or about 51-bit reply slugs. Use ≥ 80 bits or diceware, with a per-submission salt.
15. **Storing TOTP codes in auth logs** (Hush Line privacy policy); log only a replay-prevention counter.

## 10. Derived requirements (summary IDs)
- R-AUTHZ-01, R-AUTHZ-02, R-AUTHZ-03
- R-TEN-01
- R-CFG-01
- R-SUP-01
- R-XSS-01
- R-CRYPTO-01
- R-KEY-01
- R-OPS-01
- R-NET-01
- R-AUTH-01
- R-WEB-01
- R-ID-01

Also proposed:
- **R-CLIENT-01:** the source client is reproducibly built, signed, and verifiable by a third party; web delivery is pinned and transparency-logged.
- **R-E2E-01:** recipient private keys never exist on the server in any form usable without the recipient device.
- **R-BKP-01:** backups are encrypted to offline k-of-n keys; restores are tested quarterly.
- **R-INST-01:** installers pin the release-key fingerprint, use scoped `signed-by` keyrings, and ship published, verified checksums and digests.
- **R-DEL-01:** deletion is crypto-erasure of per-case keys, with verification.
- **R-COVER-01 (Enterprise):** optional cover traffic from a fleet-deployed app or extension, so employee submissions blend into routine traffic.

---

## 11. Bibliography

Entries marked "(repo)" were read from a cloned repository at the commit noted in §0. Entries marked "not fetched" are URLs as listed by the project itself; I did not open them.

- [B-GL-01] GlobaLeaks GOVERNANCE.md — https://github.com/globaleaks/globaleaks-whistleblowing-software/blob/stable/GOVERNANCE.md — 2021 (text), read 2026-09-30 — governance, Hermes and WBS roles.
- [B-GL-02] GlobaLeaks Roadmap (documentation/technical/roadmap.rst) — https://github.com/globaleaks/globaleaks-whistleblowing-software/tree/stable/documentation/technical — read 2026-09-30 — release cycle.
- [B-GL-03] GlobaLeaks SECURITY.md — https://github.com/globaleaks/globaleaks-whistleblowing-software/blob/stable/SECURITY.md — read 2026-09-30 — disclosure process and SLA.
- [B-GL-04] GlobaLeaks "Application security" (documentation/technical/security/application-security.rst; published at docs.globaleaks.org, which was blocked) — https://github.com/globaleaks/globaleaks-whistleblowing-software/tree/stable/documentation/technical/security — v5.0.99, 2026 — controls, headers, sessions, DPoP, files, voice anonymisation.
- [B-GL-05] GlobaLeaks installation.rst (documentation/setup) — same repo — v5.0.99 — install script, Docker, placeholder checksum.
- [B-GL-06] GlobaLeaks update.rst — same repo — upgrade process.
- [B-GL-07] GlobaLeaks requirements.rst — same repo — hardware, OS, browsers.
- [B-GL-08] GlobaLeaks "Encryption protocol" (encryption-protocol.rst) — same repo — keys, Argon2id, receipts, recovery, escrow.
- [B-GL-09] GlobaLeaks "Threat model" (threat-model.rst) — same repo — anonymity matrix, metadata, malware, traffic analysis.
- [B-GL-10] GlobaLeaks features.rst — same repo — compliance, accessibility and "no IP logging" claims.
- [B-GL-11] GlobaLeaks backup-and-restore.rst — same repo — unencrypted backup archive.
- [B-GL-12] GlobaLeaks release-procedure.rst and continuous-integration.rst — same repo — signing, CI.
- [B-GL-13] iSEC Partners 2013 architecture audit — https://globaleaks.org/docs/pt/2013-isec.pdf — 2013 — as listed in security-audits.rst; not fetched.
- [B-GL-14] Cure53 2013 web audit — https://globaleaks.org/docs/pt/2013-cure53.pdf — 2013 — not fetched. Findings tracked in GitHub issues #312, #313, #314, #300 (https://github.com/globaleaks/globaleaks-whistleblowing-software/issues/312).
- [B-GL-15] LeastAuthority 2014 source audit — https://globaleaks.org/docs/pt/2014-leastauthority.pdf — not fetched.
- [B-GL-16] Subgraph 2018 audit — https://globaleaks.org/docs/pt/2018-subgraph.pdf — not fetched.
- [B-GL-17] Radically Open Security 2019 — https://globaleaks.org/docs/pt/2019-radicallyopensecurity.pdf — not fetched.
- [B-GL-18] Radically Open Security 2022 — https://globaleaks.org/docs/pt/2022-radicallyopensecurity.pdf; the OTF copy https://public.opentech.fund/documents/report_globaleaks-2022.pdf ("Penetration Test Report GlobaLeaks V 1.0 Amsterdam, August 18th, 2022") was found in search results but was blocked — 2022-08-18.
- [B-GL-19] ISGroup 2024 pentest and 2026 LLM-adversary source audit — https://globaleaks.org/docs/pt/2024-isgroup.pdf and https://globaleaks.org/docs/pt/2026-isgroup.pdf — not fetched; the "29 confirmed vulnerabilities" figure [verified 2026-10-01, https://globaleaks.org/2026/07/30/globaleaks-strengthens-security-against-ai-enabled-threats/].
- [B-GL-20] Ahmed-Rengers, Vasile, Hugenroth, Beresford, Anderson, "CoverDrop: Blowing the Whistle Through A News App", PoPETs 2022 — URL not verified in session — design and threat model of CoverDrop.
- [B-GL-21] CoverDrop Guardian implementation white paper, June 2025 — https://www.coverdrop.org/coverdrop_guardian_implementation_june_2025.pdf — June 2025 — linked from the repo README; not fetched.
- [B-GL-22] guardian/coverdrop repository README — https://github.com/guardian/coverdrop — HEAD 2026-09-25 — architecture, security contact, OpenMLS work.
- [B-GL-23] CoverDrop docs/covernode_mixing.md — https://github.com/guardian/coverdrop/blob/main/docs/covernode_mixing.md — mix parameters.
- [B-GL-24] CoverDrop docs/protocol_messages.md — same repo — message sizes and padding.
- [B-GL-25] CoverDrop docs/cryptography.md — same repo — primitives.
- [B-GL-26] CoverDrop docs/key_rotation.md — same repo — rotation and forward security.
- [B-GL-27] CoverDrop docs/client_passphrase_configurations.md — same repo — Sloth and Argon2 parameters. Sloth paper: IACR ePrint 2023/1792 (https://eprint.iacr.org/2023/1792, as cited in the repo).
- [B-GL-28] CoverDrop docs/client_data_structures_and_algorithms.md — same repo — Private Sending Queue, deniable storage.
- [B-GL-29] CoverDrop docs/backups.md — same repo — forward-secure social-recovery backups.
- [B-GL-30] CoverDrop docs/on_premises_deployment.md — same repo — k3s, ArgoCD GitOps with manual approval.
- [B-GL-31] CoverDrop docs/fastly_cdn.md — same repo — CDN TLS termination; load balancer bypass note.
- [B-GL-32] scidsg/hushline README — https://github.com/scidsg/hushline — HEAD 2026-09-29 — capabilities, CI.
- [B-GL-33] Hush Line docs/THREAT-MODEL.md — https://github.com/scidsg/hushline/blob/main/docs/THREAT-MODEL.md — trust boundaries, JS-trust caveat.
- [B-GL-34] Hush Line docs/PRIVACY.md — same repo — effective 2026-06-18 — "no IP in database", TOTP code logging, DigitalOcean hosting.
- [B-GL-35] Horizontal-org/Tella-Android README — https://github.com/Horizontal-org/Tella-Android — read 2026-09-30 — Tella features.
- [B-GL-36] G. Pellerano, "The pitfalls of closed-source whistleblowing software", Whistleblowing International Network, 2022 — https://whistleblowingnetwork.org/Our-Work/Spotlight/Stories/The-Pitfalls-of-Closed-Source-Whistleblowing-Softw — as cited in GlobaLeaks design-principles.rst; not fetched.
- [B-GL-37] GlobaLeaks GitHub Security Advisories — https://github.com/globaleaks/globaleaks-whistleblowing-software/security/advisories — read 2026-09-30:
  - GHSA-84wr-q36q-wqhv (2026-03-27)
  - GHSA-x4cq-h872-f8wx (2026-07-30)
  - GHSA-w88m-4vmc-pq9g (2026-07-30)
  - GHSA-m5xx-3qv7-37hj (2026-07-30)
  - GHSA-9vhh-65v7-3xj6 (2026-07-30)
- [B-GL-38] GlobaLeaks CHANGELOG — https://github.com/globaleaks/globaleaks-whistleblowing-software/blob/stable/CHANGELOG — through 5.0.99 — audit-driven hardening history.
- [B-GL-39] Hush Line GitHub Security Advisories — https://github.com/scidsg/hushline/security/advisories — read 2026-09-30:
  - GHSA-4v8c-r6h2-fhh3
  - GHSA-4c38-hhxx-9mhx
  - GHSA-r85c-95x7-4h7q
  - GHSA-j857-9q45-73jr
  - GHSA-m592-g8qv-hrqx
- [B-GL-40] CVE-2024-41671 (Twisted) — https://www.tenable.com/cve/CVE-2024-41671 (search result; not fetched) — disclosed 2024-07-29 — dependency CVE.
- [B-GL-41] GlobaLeaks install.sh — https://github.com/globaleaks/globaleaks-whistleblowing-software/blob/stable/scripts/install.sh — 5.0.99 — key-trust handling.
- [B-GL-42] GlobaLeaks design-principles.rst — same repo — PFS/E2EE/zero-knowledge aspiration; EU and ISO references.
- [B-GL-43] R. v. Leipert, [1997] 1 S.C.R. 281 (Supreme Court of Canada) — URL not verified — Crime Stoppers informer privilege; tip sheet non-disclosure.
- [B-GL-44] Commercial vendor homepages: navex.com, eqs.com, whispli.com, vaultplatform.com, onetrust.com, speeki.com, whistlelink.com, faceup.com, allvoices.co — not accessed (proxy-blocked); all claims in §5 are UNVERIFIED.
