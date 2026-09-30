# R1 — SecureDrop, SecureDrop Workstation / Inbox, SecureDrop Protocol, WEBCAT, OnionShare

Research notes for the design of a high-assurance whistleblowing platform (Community FOSS + Enterprise/Government editions).
Research date: 2026-09-30. Primary sources were used wherever the network egress policy allowed.

**Method and source-access caveats (read first)**
- Reachable: github.com (repos, advisories, issues, releases), raw.githubusercontent.com, and the Trail of Bits publications repo (the ToB PDF was downloaded and its text extracted locally, so the findings table below is verbatim).
- **Blocked by egress proxy**: securedrop.org, docs.securedrop.org, 7asecurity.com, eprint.iacr.org, osv.dev, opencve, en.wikipedia.org, opentech.fund, pentestreports.com. So the docs content comes from the `freedomofpress/securedrop-docs` GitHub source (main branch). The 7ASecurity 2024 findings come from FPF's own GitHub issue tracker and changelog. The ACM CCS 2026 paper and WEBCAT paper are cited only by the links in the FPF repos. Their contents are UNVERIFIED beyond the README text.
- The WebSearch budget ran out partway through. Items drawn from memory are marked **UNVERIFIED**.
- One summarizer run on the Trail of Bits PDF produced a findings list that was completely fabricated. The real list below comes from local text extraction. Every advisory table entry was re-read on the GitHub advisory page itself.

---

## 0. Executive orientation (state of play, Sept 2026)

- **SecureDrop Server** 2.16.1 (2026-07-08), with 2.17.0~rc1 in progress. It runs on Ubuntu 24.04 "Noble". The migration from Focal was automated and phased between 2.12.0 and 2.12.8 (May 2025). OpenPGP moved from GnuPG/python-gnupg to **Sequoia via a Rust binding ("redwood")** in 2.7.0. A **v2 Journalist API** (event-sourced sync) became the default in 2.15.0 (2026-04-16) to serve the new Inbox app. [B-SD-02, B-SD-03]
- **SecureDrop Workstation (SDW)** is Qubes OS 4.3-based. It went to open beta with 1.0.0 in July 2024. The latest release is 1.9.0 (2026-09-02), and 1.8.0 moved templates to Debian 13 "trixie". The journalist client was rewritten as **"SecureDrop Inbox", an Electron + React app** backed by a Rust proxy. SDW 1.7.1 **removed access to the legacy (Python/Qt) SecureDrop Client**. The current docs (securedrop-docs main) describe journalists and admins working on Qubes. The Tails Journalist Workstation, the air-gapped Secure Viewing Station (SVS) and the USB sneakernet are described as the "legacy approach". Migration docs exist, but `migration_overview.rst` is still a TODO. Tails 7 support was still shipped in 2.12.10 (Sept 2025). **No formal end-of-life date for the Tails/SVS workflow was found (UNVERIFIED).** [B-SD-05, B-SD-06, B-SD-07, B-SD-08]
- **SecureDrop Protocol**, FPF's next-generation end-to-end encrypted, server-blind design, is at spec/PoC v0.4. It had a preliminary crypto audit (Orrù, Dec 2023), formal analysis at ETH Zürich (Maier, Jan 2025), and a paper forthcoming at ACM CCS 2026 (Berra, Linker, Maier, Paterson, Veitch et al.). The source client is intended to be **browser-based (WASM)**. That dependency is what makes **WEBCAT**, FPF-sponsored web-app code-signing and transparency for the browser, strategically relevant. [B-SD-10, B-SD-11, B-SD-12]
- **OnionShare** 2.6.4 fixed two moderate CVEs in June 2026: a receive-mode upload bypass and symlink following. A Radically Open Security audit (OTF Red Team Lab, Sept–Oct 2021) produced advisories fixed in 2.5 (published 2022-01-18). [B-OS-01..04]

---

## 1. Per-system structured analysis

### 1.1 SecureDrop (server side: Application Server + Monitor Server; Source Interface; Journalist Interface; Admin)

| Field | Findings |
|---|---|
| **Architecture** | Two dedicated physical servers on the newsroom's premises, behind a dedicated hardware firewall and "strictly segregated from corporate environment" [B-SD-04]. **Application Server**: Apache + mod_wsgi + Flask for the Source Interface (SI) and Journalist Interface (JI) and the Journalist API. Storage is SQLite only (since 2.6.0). Redis holds server-side sessions (since 2.5.0) and is password-required (7ASecurity SEC-01-008 fix, 2.10.0). **Monitor Server**: OSSEC HIDS/file-integrity monitoring and Postfix for GPG-encrypted alert email. The threat model doc is still titled "SecureDrop 0.3 Threat Model" (stale). Everything is deployed as Debian packages plus Ansible. Since 2.13.0 the admin utility itself ships as a .deb. [B-SD-02, B-SD-04, B-SD-09] |
| **Source interface** | Tor v3 onion service (v2 removed in 2.0/2.2). TLSv1.3 is enforced on optional HTTPS SI (2.1.0), and Tor2web access is detected and warned about (2.3.0). The SI is JS-optional. A JavaScript banner warns when the Tor Browser security level is not "Safest" (PR #7587, June 2025). Optional Tor Proof-of-Work onion DoS defence arrived in 2.9.0. /robots.txt and no-index meta were added. Only GET/POST/HEAD are allowed. [B-SD-02, B-SD-04, B-SD-15] |
| **Recipient (journalist) interface** | The JI runs as a **Tor v3 onion service with client authorization** (the "ATHS"/authenticated onion). Logins use username + passphrase (argon2id since 2.6.0) + TOTP or HOTP (YubiKey). Sessions last 2 hours (`SESSION_LIFETIME`). A 2FA token-reuse guard landed in 2.4.0, the HOTP/TOTP minimum secret length in 2.2.0, and the 160-bit default 2FA secret in 2.1.0. The Journalist API (v1 token and v2 event-sync) serves Workstation/Inbox. [B-SD-02, B-SD-09] |
| **Admin interface** | Admin role in the JI (user management). Server administration uses **SSH over authenticated onion services**, driven by the `securedrop-admin` Ansible wrapper from an Admin Workstation (historically Tails, now documented on Qubes). Admins have separate 2FA per server (docs: "two separate two-factor authentication secret codes (one per server)"). 7ASecurity found missing SSH MFA hardening (SEC-01-011) and missing 2FA re-prompt for sensitive operations (SEC-01-010). Both issues were still open as of the issue listing. [B-SD-13, B-SD-14] |
| **Anonymity network** | Tor for everything: SI, JI, SSH and alerts, which go outbound via Postfix/SMTP. The Monitor Server exposes only SSH over an onion service. [B-SD-04] |
| **Clearnet policy** | Only the newsroom's **landing page** is clearnet. It publishes the .onion address and is expected to follow the "landing page" hardening guidance (HSTS, no third-party trackers, no CDN). Tor2web is actively detected and warned against. DNS lookups for the SecureDrop subdomain are an accepted unmitigated risk ("DNS correlation"). Landing-page guidance details are UNVERIFIED because securedrop.org was blocked. [B-SD-04] |
| **Encryption model** | Submissions are encrypted at rest on the server to the **Submission Key**, an offline OpenPGP key whose secret half lives only on the SVS or, now, `sd-gpg`. Encryption happens **server-side**, so plaintext transits the Application Server's memory. The threat model says plaintext stays in memory for up to 24 hours. **Per-source keypairs**: each source gets its own OpenPGP keypair generated on the server via `redwood.generate_source_key_pair(gpg_secret, filesystem_id)`. Its secret key is stored on the server, protected by a passphrase derived from the source's codename. Journalist replies are encrypted to the source key **and** the Submission Key. Since 2.7.0 the implementation is Sequoia-PGP (Rust) instead of GnuPG, and weak/SHA-1 submission keys are rejected by `securedrop-admin` and disable the interfaces. [B-SD-02, B-SD-04, B-SD-16] |
| **Codename scheme** | `PASSPHRASE_WORDS_COUNT = 7` words chosen with `random.SystemRandom` (CSPRNG) from per-language diceware-style lists of at least 7,300 words, giving roughly 7 × log2(7300) ≈ **89.8 bits** (my calculation; exact entropy depends on list size). Length is bounded 20–128 characters. The codename is **server-generated**, and sources cannot choose or reset it ("Refresh codename" was removed in 2.2.0; there is no reset). The codename is never stored. The server derives `filesystem_id = scrypt(codename, SCRYPT_ID_PEPPER)` for lookup and `gpg_secret = scrypt(codename, SCRYPT_GPG_PEPPER)` to protect the source's secret key. Defaults are **N=2^14, r=8, p=1, length 64**, and the code enforces distinct peppers. A separate human-readable *journalist designation* (adjective + noun) is shown to journalists. Offensive words were purged from lists in several releases (2.0–2.8). [B-SD-16, B-SD-17, B-SD-18] |
| **Key management** | **Submission Key**: OpenPGP, generated and kept offline. Historically it lived on the SVS with a passphrase. On SDW the docs **require removing the passphrase** (`removing_gpg_passphrase.rst`) because `sd-gpg` split-GPG is used unattended. Protection shifts to Qubes FDE and VM isolation. **Journalist Alert Key**: a public key used by the Monitor Server to encrypt the daily "submissions today?" alerts; alerts are GPG-encrypted but **not signed**. An **Admin OSSEC alert key** is analogous. The FPF release signing key lives on an air-gapped machine, with its expiry extended to 2027-05-24 in 2.9.0. [B-SD-02, B-SD-04, B-SD-19] |
| **Authentication (journalists)** | Passphrase (argon2id) + TOTP/HOTP (FreeOTP or YubiKey). Login throttling was extended to invalid usernames in 2.16.0. The API session was split from the web session, but **GHSA-78xq-8jf3-gpfx** showed that the split was broken. [B-SD-02, B-SD-20] |
| **Source authentication** | Bearer secret = codename. There is no account recovery, and a login does not reveal prior history. Sessions are 120 minutes, with the source codename session length restricted since 2.1.0. `Clear-Site-Data` is sent on SI logout (2.13.0). Separate cookie prefixes were introduced for SI and JI (2.13.0). [B-SD-02, B-SD-09] |
| **Authorization** | Flat. **Every journalist can read every source's submissions.** The only roles are journalist and admin. The GHSA-78xq advisory states this explicitly: "a compromised journalist account provides broad access to all source submissions". There is no per-desk or per-case compartmentalization. [B-SD-20] |
| **Metadata policy** | The server stores only the *latest* activity timestamp per source, with earlier timestamps overwritten (`what_makes_securedrop_unique.rst`; 2.2.0 "Source key timestamp overwriting at startup"). No browser/UA data is kept. File size and submission count are visible to the server. Stored plaintext: source *designations*, the reply-state DB, and HTTP request data in memory. [B-SD-01, B-SD-04] |
| **Logging policy** | Apache SI vhost: `ErrorLog` defaults to `/dev/null`, `LogLevel crit`, and there is **no CustomLog/access log**. Tor logs are "sanitized". OSSEC alerts are scrubbed of application data and server IPs. 7ASecurity SEC-01-016 ("Insufficient Logging and Monitoring") is open, which shows the tension between security monitoring and source-protective no-logging. [B-SD-04, B-SD-21, B-SD-13] |
| **Attachment handling** | Uploads are limited to 500 MB (`LimitRequestBody 524288000`, `MAX_CONTENT_LENGTH`), gzipped and encrypted server-side to the Submission Key. Files are never executed server-side. The JI/API serves only ciphertext. [B-SD-21, B-SD-22] |
| **Malware containment** | Classic model: the air-gapped **SVS** (Tails, offline) decrypts and opens files, and USB sneakernet goes from the Journalist Workstation to the SVS and on to an Export device. The threat model **explicitly accepts** "Journalist/Administrator gets phished from a submission or otherwise breaks the SVS airgap with malware" as unmitigated. Modern model: SDW disposable VMs (see 1.2). [B-SD-04] |
| **Document sanitization (MAT/MAT2)** | History from verifiable sources: Tails shipped MAT (v1). SecureDrop docs pointed journalists to it (PR #1159, 2015, standardized "MAT" naming). Issue #2643 (DonnchaC, closed 2018) records that MAT **had maintenance issues and left EXIF data in images embedded inside documents**. It proposed `pdf-redact-tools` rasterization on the SVS instead. On SDW, issue #26 ("file conversion and metadata removal", opened 2017-09-14) is **still open**. The current direction is **Dangerzone-based "Transform in Disposable Qube"** (securedrop-client #3706, opened 2026-08-27, design validation, blocked on Dangerzone headless language detection). Exact dates and reasons for any docs removal of MAT2 guidance are **UNVERIFIED** (docs site blocked). Takeaway: metadata-stripping tools are best-effort and format-incomplete. The trend is toward *rasterize/reconstruct* (Dangerzone/pdf-redact-tools) rather than *strip*. [B-SD-23, B-SD-24, B-SD-25] |
| **Messaging** | Two-way text between the source (codename login) and journalists. Replies are encrypted to the source key. Optional message filtering (minimum length, codename-as-message blocking) arrived in 2.3.0. The v2 API has an event table, "conversation truncation" events (2.14.0) and arbitrary metadata shard requests (2.15.0). [B-SD-02] |
| **Deletion** | Journalists delete sources and submissions; asynchronous source deletion came with the v2 API in 2.16.0. Automatic removal of "pending" sources (created but never submitted) arrived in 2.6.0. Secure-erase semantics on SSDs are UNVERIFIED. |
| **Backups** | The `securedrop-admin backup`/`restore` Ansible flow, installed as a Debian package since 2.11.0. The Redis password is regenerated on restore (2.11.0). A restore checksum-verification bug was fixed in 2.15.1. Backups contain onion keys and the database, which makes them highly sensitive. |
| **Deployment** | Ansible playbooks via `securedrop-admin` (sdconfig → install → tailsconfig/workstation). Hardware firewall (pfSense-class) + host iptables (UFW removed in 2.11.0). grsecurity/PaX kernel, AppArmor, and unattended nightly security upgrades. 7ASecurity SEC-01-017 "Lack of Full Disk Encryption" on the servers is **open** because the servers boot unattended. Whether the grsecurity kernel continues on Noble is UNVERIFIED. |
| **Upgrade architecture** | APT from `apt.freedom.press` with GPG-signed Release files. The signing key is offline, and CVE-2019-3462-era mitigations have since been removed. The kernel and app auto-update nightly. **Phased rollouts with a fixed machine-id** were used for the Focal→Noble migration (2.12.3–2.12.8: e.g., 100% of App servers, 40% of Monitor servers). Automated migration was then **disabled** in 2.12.9. The admin workstation updater verifies signed git tags. [B-SD-02, B-SD-03] |
| **Build/release security** | CI builds the debs **twice and diffs them with diffoscope** (`reproducible-debs` job). A FIXME notes that `securedrop-app-code` is *not* yet reproducible. `cargo-vet` covers Rust dependencies, and `safety`/dependency-review/guarddog cover Python. Wheels are built reproducibly with hash-pinning and signed checksums (`securedrop-builder`). Release tags and packages are signed with an air-gapped key. Branch protection and mandatory 2FA apply, with multiple reviewers. [B-SD-26, B-SD-27, B-SD-04] |
| **OPSEC requirements** | Sources: use Tor Browser at the "Safest" level, preferably on Tails. Avoid work networks and devices, do not disclose use, and memorize the codename. Journalists and admins: dedicated hardware, no mixing with corporate IT, and 2FA devices protected. Much of the threat model depends on "user behavior" (see its stated limitations). [B-SD-04] |
| **Accessibility** | Semantic HTML5/ARIA refactors (2.1.0, 2.2.0), a "skip to notification" link (2.3.0), Orca screen-reader fixes (PR #6453), and further improvements in 2.9.0 (#6536). The JS-free "Safest" mode constrains accessible UI patterns. [B-SD-02] |
| **i18n** | Weblate integration since 2.5.0. A supported-language list can be pruned (Hindi removed in 2.12.0). Localized per-language diceware lists feed codenames. [B-SD-02] |
| **Strengths** | Newsroom-owned infrastructure (no third-party subpoena target). Onion-only access. No access logs. Server-generated high-entropy codenames. Offline Submission Key. A strong public-audit culture and a paid bug bounty (Bugcrowd; $500–$2,500 awards seen). Reproducibility CI. Signed apt. Advisories are well written and include root cause. |
| **Weaknesses** | (1) **The server sees plaintext** submissions and messages before encryption, and holds per-source secret keys wrapped by a codename-derived secret. A compromised server can therefore read all *future* traffic and decrypt replies for any source that logs in. This is what the SecureDrop Protocol aims to fix. (2) Flat authorization across all journalists. (3) An enormous operational burden: two servers, a firewall, Tails USBs, an SVS and a sneakernet. The current docs estimate $2,200–$2,400 in hardware plus a Linux sysadmin. (4) No server FDE (unattended boot). (5) Relies on a Tor Browser JS-off posture that sources frequently do not follow. (6) The alert key encrypts but does not sign. (7) The threat model document is stale ("0.3"). |

### 1.2 SecureDrop Workstation (Qubes) / SecureDrop Inbox

| Field | Findings |
|---|---|
| **Architecture** | Qubes OS 4.3 (Xen) with qubes provisioned by Salt/RPM from dom0 (FPF-signed RPM repo; UNVERIFIED detail). **sd-proxy**: the only networked SD qube (via **sd-whonix**/Tor). It runs a *restricted HTTP proxy* (now Rust) that only talks to the configured JI onion, holds the JI client-auth key, and is reached from sd-app via qrexec. **sd-app**: no network. Runs the Inbox app and stores decrypted submissions and SQLite. **sd-gpg**: split-GPG holding the Submission Key; no network. **sd-viewer**: template for **disposable VMs** that open each file. **sd-devices**: USB/printing export. **sd-log**: centralized logging from all SD qubes. Templates are Debian 13 since SDW 1.8.0. The **pre-flight updater** forces all templates up to date before use. [B-SD-05, B-SD-28] |
| **Recipient UI** | **SecureDrop Inbox**: an Electron main/renderer (React) app with SQLite (dbmate migrations). It talks to sd-proxy through a qrexec RPC policy. The v2 sync design (ADR 001) uses a batch write/read loop, Snowflake IDs as idempotency keys, last-write-wins, and the server as authoritative. The legacy Python/Qt client was removed in SDW 1.7.1. The Electron sandbox/contextIsolation posture is **UNVERIFIED** (README silent). [B-SD-06, B-SD-29, B-SD-30] |
| **Admin** | The SDW admin provisions via `sdw-admin` in dom0 with `config.json` (JI onion hostname, client-auth key, Submission Key fingerprint) and the secret key. Journalists must not modify the system or install software. |
| **Encryption / keys** | The Submission Key must be **passphrase-less** (split-GPG unattended decrypt). JI client auth lives in sd-proxy. ToB-SDW-022 noted that "the authorization key [API token] is valid for 8 hours". |
| **Malware containment** | Each file opens in a fresh non-networked DispVM, and Qubes GUI isolation limits exfiltration. The SDW threat model enumerates compromise consequences per VM: sd-viewer compromise means it reads *that* submission and attempts side channels; sd-proxy means the ATHS cookie plus traffic; sd-app means all decrypted data plus JI actions; sd-gpg means decryption of anything; dom0 means everything. [B-SD-05] |
| **Export** | `.sd-export` = gzipped tar of `metadata.json` + `export_data/`, passed over qrexec to sd-devices. Targets are **LUKS (sha512/512-bit) or pre-unlocked VeraCrypt USB** only, plus IPP-over-USB printers. Preflight "disk-test" and "printer-preflight" devices run first. Folders are timestamped `sd-export-YYYYMMDD-hhmmss`. ToB-SDW-016 found a tar path traversal in exactly this unpacker (Medium), and ToB-SDW-018 found sd-app could call too many apps in sd-devices. [B-SD-31, B-SD-32] |
| **Sanitization** | Not yet built in. There is a Dangerzone-in-DispVM design (#3706, 2026). |
| **Logging** | sd-log aggregates logs from all SD qubes. GHSA-933q (CVE-2025-24889) showed that sd-log trusted the VM name *supplied by the sending VM* instead of `QREXEC_REMOTE_DOMAIN`, allowing lateral movement. |
| **Build/release** | Reproducible wheels (securedrop-builder), `cargo-vet`, piuparts, zizmor (GitHub Actions linting), and guarddog→SARIF (Sept 2026). Releases are GPG-signed tags. |
| **Hardware / usability** | Needs 16 GB RAM (32 GB recommended), Qubes-compatible hardware and Intel testing (ToB-SDW-003). Fewer devices than SVS+JW, but Qubes has a learning curve and hardware compatibility is fragile. |
| **Strengths** | Replaces the air gap with hypervisor compartmentalization and a single-purpose, network-isolated decryption domain. Disposable viewing. A restricted proxy that has **no redirects** since the 2026 fix. The server is treated as untrusted from the client's perspective: the 2025–2026 client advisories are all "malicious server → client". |
| **Weaknesses** | Heavy dependence on Qubes/Xen correctness and on qrexec policy correctness (ToB-SDW-006/011/015). The attack surface of an Electron renderer is significant. A passphrase-less Submission Key means dom0 or sd-gpg compromise is catastrophic. Hardware constraints apply. The historical path-traversal class keeps recurring (ToB-SDW-012 in 2020, CVE-2025-24888 in 2025, CVE-2026-35465 in 2026). |

### 1.3 SecureDrop Protocol (next-gen E2EE; FPF, v0.4)

| Field | Findings |
|---|---|
| **Goal** | "End-to-end encrypted whistleblowing for all". The server should learn neither plaintext nor sender/recipient relationships, and sources keep **no persistent state** beyond a passphrase. [B-SD-10, B-SD-11] |
| **Primitives** | Ed25519 signatures. HPKE with DHKEM(X25519, HKDF-SHA256). **ML-KEM-768** hybrid (PQ confidentiality). **X-Wing** (X25519+ML-KEM-768) for metadata encryption. ChaCha20-Poly1305. Ristretto255 for fetching. HKDF-SHA256. v0.3 moved to standard HPKE `mode_base` + `mode_auth_psk`. [B-SD-11] |
| **Key hierarchy** | FPF root signing key pinned in clients → newsroom Ed25519 key (signed by FPF) → journalist long-term signing, fetch and APKE keys + **one-time ephemeral key bundles** signed by the journalist. Source keys are **fully deterministic** from a **12-word BIP39 mnemonic (128-bit entropy)** via HKDF-SHA256 (salt `securedrop-source-v1`). |
| **Fetching (metadata privacy)** | A three-party DH challenge/response. For each stored message the server issues `Q_k = X_k^{r_k}` plus an AEAD-encrypted message id. The recipient tries every challenge with `sk_fetch` and downloads only its own. The server pads to a **fixed maximum message count**. Messages are deleted after fetch. |
| **Known limits (spec-stated)** | No attachments spec. No journalist key replenishment or newsroom key rotation spec. KCI (key-compromise impersonation) vulnerable. PQ protects confidentiality only (not auth/fetch). Scalability is capped by per-request challenge computation over Tor. Constant-time requirements apply to fetching. |
| **Assurance** | Orrù preliminary audit (report attached to issue #36, covering the frozen Nov 2023 protocol, delivered Jan 2024; contents UNVERIFIED). ETH Zürich Tamarin analysis (Maier 2025) led to v0.2. CCS 2026 paper led to v0.3. hax/F* verification tooling is in the repo. Benchmarks target a **browser WASM** source client. |
| **Relevance** | This is the direction to copy: remove server plaintext access, hide sender–recipient graph, PQ-hybrid. **Risk**: a browser-delivered crypto client is only as trustworthy as the code delivery, which is why WEBCAT exists. |

### 1.4 WEBCAT (Web-based Code Assurance and Transparency)

- A Firefox extension (MV2, **alpha**) that enforces **blocking** code-signing and integrity for enrolled web apps. The pieces are an enrollment consensus system (CometBFT), Sigsum/Sigstore transparency, a developer signing CLI, and CSP-based runtime policy using only WebCrypto. It started as a VU Amsterdam/UvA master's thesis and is sponsored by FPF. The paper is ePrint 2025/797 (not fetched: blocked). The README warns that it "might not yet provide the intended security guarantees". [B-SD-12]
- Relevance: this is the only credible path to shipping browser-based E2EE for sources (the SecureDrop Protocol source client) without trusting the server to serve honest JS on every load. For our platform, **plan for a WEBCAT-like signed-bundle + transparency-log model**, or a native/installable source client, and never "crypto in server-delivered JS" without it.

### 1.5 OnionShare (focus: Receive mode)

| Field | Findings |
|---|---|
| **Architecture** | A desktop/CLI app (Python, Flask/Werkzeug + Qt) that runs a local web server exposed as an **ephemeral or persistent Tor v3 onion service**. Modes: Share, Receive, Website, Chat. It runs on the recipient's own computer, so there is no third-party server. [B-OS-05, B-OS-06] |
| **Recipient UI** | The desktop app shows a history tab. Files are saved in `~/OnionShare/<timestamp>` subfolders. Optional webhook POST on submission (e.g., to Keybase). |
| **Source interface** | A Tor Browser page with upload form and text box. Files or text can be disabled independently. |
| **Authentication** | Since 2.4, **v3 onion client authorization (private key)** replaces HTTP basic-auth passwords. "Public mode" disables it for public dropboxes. [B-OS-07] |
| **Encryption** | Only Tor's onion-service transport encryption. **No at-rest encryption** of received files and no per-source keys or replies (one-way, except Chat). |
| **Metadata / logging** | No server logs by design, but files land in plaintext on the recipient's disk with timestamps. |
| **Malware containment** | Docs only warn: "someone could try to attack your computer by uploading a malicious file". They recommend Dangerzone, Tails or Qubes DispVMs for opening files. Text messages are called "safe". |
| **Sanitization** | None built in. Delegated to Dangerzone. |
| **Audits** | Radically Open Security (OTF Red Team Lab), Sept–Oct 2021. Advisories OTF-001…OTF-013 were published 2022-01-18 and fixed in 2.5 (CVE-2022-21689/21690/21692/21694/21695 confirmed; others listed in the table). |
| **Recent vulns** | CVE-2026-54707 (receive-mode `--disable-files` bypass) and CVE-2026-54706 (symlink following), both fixed in 2.6.4 (advisories published 2026-06-09). |
| **Strengths** | Minimal infrastructure. Ephemeral by default. Strong anonymity for *both* sides if the address is exchanged safely. |
| **Weaknesses** | The recipient's workstation *is* the server (always-on and exposed). Enforcement is in route handlers rather than at the parser/stream layer. No at-rest crypto. DoS in public mode. |

---

## 2. Audit and advisory table

| Date | Auditor / ID | Finding summary | Severity | Lesson |
|---|---|---|---|---|
| 2013 (UNVERIFIED month) | Univ. of Washington (Czeskis, Kohno, Schneier et al.), DeadDrop/StrongBox assessment | First academic review of the pre-FPF code (UNVERIFIED details; securedrop.org blocked) | n/a | Independent review before launch |
| late 2013 | Cure53 (2nd audit) | Details UNVERIFIED (report on securedrop.org, blocked) | n/a | — |
| summer 2014 | iSEC Partners (3rd audit) | Details UNVERIFIED | n/a | — |
| summer 2015 | iSEC Partners (4th audit) | Details UNVERIFIED | n/a | — |
| late 2018 | Leviathan Security (for SOFWERX) | Details UNVERIFIED | n/a | — |
| Nov 2018 | Include Security, SDW alpha | Details UNVERIFIED (report at pentestreports.com, blocked) | n/a | — |
| 2020-11-30 → 12-18 (final 2021-01-29) | **Trail of Bits, SDW 0.5.x, 26 findings, 6 person-weeks** | TOB-SDW-012: sd-app writes download to a server-controlled path → path traversal, possible code exec | **High** | Never trust server-supplied filenames; the client must treat the server as hostile |
| same | TOB-SDW-016 | securedrop-export in sd-devices unpacks tar allowing arbitrary paths (`TarFile.extractall`) | Medium | Safe archive extraction; ban `extractall`; Semgrep rule (ToB App. D) |
| same | TOB-SDW-017 | Arbitrary file write can add/overwrite MIME handlers in any SD VM | Medium | File-write primitives become code exec via handler/autostart config |
| same | TOB-SDW-018 | sd-app can call many apps in sd-devices (over-broad qrexec) | Medium | Least-privilege IPC allow-lists |
| same | TOB-SDW-019 | sd-viewer DispVM can DoS Qubes | Medium | Resource caps on untrusted viewers |
| same | TOB-SDW-025/026 | Sysctl hardening; application sandboxing (nsjail etc.) | Medium | Defense in depth inside VMs |
| same | TOB-SDW-004/005/009 | safe_mkdir ordering, overly broad permissions on downloads | Low | Atomic creation with restrictive modes |
| same | TOB-SDW-008 | Offline mode requires no authentication | Low | Local auth even offline |
| same | TOB-SDW-010 | Passwordless root in VMs | Low | — |
| same | TOB-SDW-015 | Backup files remain valid qrexec policies | Low | Policy directories must not load stray files |
| same | TOB-SDW-022 | API authorization key valid for 8 hours | Low | Short-lived tokens, bound to purpose |
| same | TOB-SDW-006/011 | Qubes qrexec return-value handling / policy reply misidentification (upstream Qubes) | Info | Audit the platform you depend on |
| same | TOB-SDW-001/002/003/007/013/014/020/021/023/024 | Regex, Qubes ISO verification UX, Intel-only testing, Whonix RPC, duplicate JSON keys, asserts optimized out, etc. | Info | Input-validation hygiene |
| Dec 2023 (report Jan 2024) | Michele Orrù, SecureDrop Protocol preliminary crypto audit (issue #36) | Contents UNVERIFIED | n/a | Get cryptographers in *before* implementation |
| summer 2024 (issues filed 2024-10-29) | **7ASecurity (OTF), SecureDrop server: 1 Medium, 2 Low + 15 hardening (per 7ASecurity blog snippet)** | SEC-01-001 arbitrary TOTP secret lookup via web; SEC-01-002 server-side password validation missing; SEC-01-003 GET logout/CSRF; SEC-01-008 Redis without password: **fixed in 2.10.0** | Medium/Low (per-ID mapping UNVERIFIED) | Server-side validation; CSRF on state changes; auth on internal services |
| same | SEC-01-006 file access via insecure perms (open); 007 third-party libs (not planned); 009 obsolete Redis (closed); 010 missing 2FA for sensitive ops (open); 011 SSH MFA (open); 012 network stack (open); 013 SSRF via Redis on TCP (closed); 014 onion DoS (open); 015 source-creation race (open); 016 logging/monitoring (open); 017 no server FDE (open); 018 host firewall (open) | Hardening | Many "accepted" hardening gaps remain for >2 years; track them publicly |
| Jan 2025 | ETH Zürich (Maier; Basin/Linker/Veitch), Tamarin formal analysis of SD Protocol | Led to spec v0.2 (modified HPKE auth) | n/a | Formal verification changes designs |
| 2025-02-13 | **GHSA-6c3p-chq6-q3j2 / CVE-2025-24888** (securedrop-client ≤0.14.0; fixed 0.14.1) | Reply download writes ciphertext to attacker-controlled path *before* sanitization → autostart file → code exec in sd-app | High (CVSS 8.1) | Validate before first write |
| 2025-02-13 | **GHSA-933q-fx9h-5g46 / CVE-2025-24889** (client ≤0.14.0, SDW ≤1.0.0; fixed 0.14.1 / 1.0.1) | sd-log trusted the sender-supplied VM name → path traversal → lateral movement | Moderate (4.5) | Take identity from the transport (QREXEC_REMOTE_DOMAIN), never from payload |
| 2026-04-13 | **GHSA-2jrc-x8fq-prvc / CVE-2026-35465** (client; GitHub page: ≤0.17.2 fixed 0.17.3; third-party CVE mirrors say ≤0.17.4 fixed 0.17.5; **conflict UNRESOLVED**) | gzip header filename check blocked `..` but allowed **absolute paths** → overwrite `svs.sqlite` → code exec | High (7.5) | Allow-list filename construction; never pass server strings to path joins |
| 2026-05-28 (GitHub); CVE record ~2026-08-20 | **GHSA-6qxc-pcfg-v6qv / CVE-2026-49996** (client <1.3.1) | securedrop-proxy followed HTTP redirects (reqwest default) → origin restriction bypass by malicious server | Low (3.7) | Disable library defaults you don't need; origin pinning must include redirects |
| 2026-06-24 | **GHSA-78xq-8jf3-gpfx / CVE-2026-50000** (server 2.5.0–2.15.x; fixed 2.16.0) | Mutable session-key prefix shared across workers → API token reusable as web session for up to 8h; logout may not delete Redis session | Moderate (5.0) | Immutable, per-request session namespaces; test logout invalidation |
| 2026-07-08 | **GHSA-rqwh-4873-322p / CVE-2026-71863 (from GHSA page only)** (server 2.13.0–2.16.0; fixed 2.16.1) | Ansible: empty filename var when journalist alerts disabled → copied whole dir incl. **JI/SSH onion client-auth keys to Monitor Server** | Low (2.6) | Explicit file lists, deny-by-default copying; secret-placement tests |
| 2021-09/10 → 2022-01-18 | **Radically Open Security (OTF), OnionShare, fixed in 2.5** | OTF-001 CVE-2022-21690 QLabel rich-text injection via `path` (High); OTF-003 CVE-2022-21692 chat impersonation (Mod); OTF-004 leave spoofing (Mod); OTF-012 CVE-2022-21689 receive-mode DoS via 100 dirs/sec cap (Mod); OTF-005, -006 (CVE-2022-21694 CSP not configurable), -009 (CVE-2022-21695 invisible chat user), -013 (Low) | High→Low | UI toolkits auto-interpret markup; per-second naming = DoS |
| 2026-06-09 | **GHSA-v833-3823-cmhp / CVE-2026-54707** (OnionShare 2.6.3 → 2.6.4) | `--disable-files` enforced only in route; Werkzeug multipart parser already wrote files | Moderate (5.4) | Enforce policy at the stream/parser layer |
| 2026-06-09 | **GHSA-22p9-r2f5-22mf / CVE-2026-54706** (OnionShare 2.6.3 → 2.6.4) | Symlinks in shared dir followed → disclosure of local files | Moderate (4.8) | Resolve and contain paths (O_NOFOLLOW, realpath-within-root) |
| 2021 (UNVERIFIED) | OnionShare CVE-2021-41867 / CVE-2021-41868 (2.4 fixes, from memory) | Chat user list leak / receive-mode upload auth bypass | UNVERIFIED | — |

`freedomofpress/securedrop-workstation` has **no** published GitHub advisories. SDW-affecting issues are published under `securedrop-client`.

---

## 3. Incident entries

**INCIDENT:** I-1 — CVE-2025-24888 (GHSA-6c3p-chq6-q3j2), path traversal in SecureDrop Client reply download, published 2025-02-13
**WHAT FAILED:** The client wrote the downloaded (encrypted) reply to disk using a filename from the server's HTTP headers *before* sanitizing it.
**ROOT CAUSE:** Validation happened on the move-to-storage step, not on the first write. Server-controlled strings flowed into a filesystem path.
**DATA EXPOSED:** Potentially every decrypted submission in sd-app, plus persistence, because the attacker plants an XFCE autostart file and gets code execution in sd-app.
**CAPABILITY REQUIRED BY ATTACKER:** A compromised SecureDrop Application Server (or JI-side MITM with the JI client-auth key). No user interaction beyond a routine login and sync.
**WHY THE ORIGINAL DESIGN DID NOT PREVENT IT:** The Workstation's VM isolation treats sd-app as a trusted, non-networked zone. Its only input channel (the server via the proxy) was implicitly trusted for metadata such as filenames, even though content was treated as hostile.
**ARCHITECTURAL LESSON:** The client must model the server as an adversary for *all* fields (names, sizes, counts, redirects), not just payloads. Server compromise must not become client compromise.
**REQUIREMENT FOR OUR PLATFORM:** R-PATH-1: Clients never derive local paths from server-supplied data. Storage paths are `root/<client-generated UUID>`. Any server-supplied display name is kept as data only.
**TEST THAT PROVES THE REQUIREMENT:** A malicious-server test harness (ToB App. B style) returns filenames `../../.config/autostart/x.desktop`, `/home/user/x`, `..\\x`, NUL, overlong and Unicode-normalization variants in every field. Assert that no file is created outside the storage root (inotify/fanotify audit), across all code paths, in CI.

**INCIDENT:** I-2 — CVE-2026-35465 (GHSA-2jrc-x8fq-prvc), absolute-path injection in `read_gzip_header_filename()`, 2026-04-13
**WHAT FAILED:** The fix pattern from I-1 (block `..`) did not block absolute paths embedded in the gzip header FNAME, so `/home/user/.securedrop_client/svs.sqlite` could be overwritten.
**ROOT CAUSE:** A deny-list path check. Python `os.path.join(base, "/abs")` discards `base`.
**DATA EXPOSED:** Decrypted submissions in sd-app. A malicious SQLite database gives code execution and persistence.
**CAPABILITY REQUIRED BY ATTACKER:** A compromised server plus a journalist downloading a crafted file.
**WHY THE ORIGINAL DESIGN DID NOT PREVENT IT:** The same class as I-1 and ToB-SDW-012 (2020) recurred in a different parser. There was no structural control, only per-site checks.
**ARCHITECTURAL LESSON:** Fix classes, not instances. Metadata inside *encrypted/compressed containers* (gzip FNAME, tar members, ZIP entries) is attacker input too.
**REQUIREMENT FOR OUR PLATFORM:** R-PATH-2: A single audited `safe_path(root, untrusted)` API is enforced by lint (Semgrep bans `os.path.join`/`open` with untrusted taint, and `tarfile.extractall`). Container-embedded names are ignored.
**TEST THAT PROVES THE REQUIREMENT:** A Semgrep/CodeQL rule in CI fails on any new sink. Fuzz gzip/tar/zip headers (absolute, `..`, symlink and hardlink members, device files) and assert containment.

**INCIDENT:** I-3 — CVE-2025-24889 (GHSA-933q-fx9h-5g46), sd-log trusted sender-claimed VM name, 2025-02-13
**WHAT FAILED:** The logging VM built log file paths from a VM name supplied *in the message*.
**ROOT CAUSE:** Identity was taken from the payload instead of the authenticated transport (`QREXEC_REMOTE_DOMAIN`).
**DATA EXPOSED:** Arbitrary file write in sd-log leads to code execution there (logs of all VMs) and to lateral movement.
**CAPABILITY REQUIRED BY ATTACKER:** Code execution in any SD VM, for example a compromised sd-viewer DispVM from a malicious document.
**WHY THE ORIGINAL DESIGN DID NOT PREVENT IT:** Compartmentalization assumed a compromised compartment stays contained, but the shared logging service became a bridge.
**ARCHITECTURAL LESSON:** Shared infrastructure services (logging, metrics, updates) are cross-compartment attack paths. They must authenticate peers by channel.
**REQUIREMENT FOR OUR PLATFORM:** R-IPC-1: Every IPC/RPC service derives caller identity only from the transport (mTLS SAN, qrexec, SO_PEERCRED) and never from message fields.
**TEST THAT PROVES THE REQUIREMENT:** Send log/RPC messages claiming other identities and traversal names from each compartment. Assert rejection or isolation (files only under the transport-derived identity).

**INCIDENT:** I-4 — CVE-2026-49996 (GHSA-6qxc-pcfg-v6qv), proxy origin bypass via redirects, 2026-05-28
**WHAT FAILED:** securedrop-proxy restricted the *initial* origin, but reqwest followed cross-origin redirects by default.
**ROOT CAUSE:** An unsafe library default was left enabled.
**DATA EXPOSED:** Low. The requests carried no plaintext, but the proxy could be steered to other hosts (for example, to deanonymize a journalist or probe for SSRF).
**CAPABILITY REQUIRED BY ATTACKER:** A compromised server.
**WHY THE ORIGINAL DESIGN DID NOT PREVENT IT:** The origin allow-list was checked at the request-construction layer, not at the connection layer.
**ARCHITECTURAL LESSON:** Enforce egress policy at the socket/connection layer (pinned host, pinned onion) and disable features such as redirects, cookies and proxies-from-env.
**REQUIREMENT FOR OUR PLATFORM:** R-NET-1: Recipient-side proxies connect only to the pinned endpoint, with redirects off, enforced by a firewall/netns allow-list as well as the code.
**TEST THAT PROVES THE REQUIREMENT:** A mock server returns 301/302/307/308 responses to other origins, `Location: file://`, and Alt-Svc. Assert no second connection (packet capture shows only the pinned endpoint).

**INCIDENT:** I-5 — CVE-2026-50000 (GHSA-78xq-8jf3-gpfx), API token reusable against web UI, server 2.5.0–2.15.x, 2026-06-24
**WHAT FAILED:** API and web sessions were meant to be separate Redis namespaces with different lifetimes. A *mutable* session-key prefix persisted across requests and workers, so an API token could be used as a web session. Logout might not delete the Redis session.
**ROOT CAUSE:** Shared mutable state in a custom Flask `SessionInterface`.
**DATA EXPOSED:** Journalist-level access for up to 8 hours: all (encrypted) submissions, source list, replies and deletions. Integrity impact is high.
**CAPABILITY REQUIRED BY ATTACKER:** Knowledge of the JI onion and client-auth credentials, plus a stolen recent API token.
**WHY THE ORIGINAL DESIGN DID NOT PREVENT IT:** Separation between session types was by convention (a prefix string), not by type or cryptographic binding. There were no tests of cross-context replay.
**ARCHITECTURAL LESSON:** Bind tokens to their audience and purpose cryptographically (e.g., `aud` claim or separate keys). Authorization is flat, so one token equals everything.
**REQUIREMENT FOR OUR PLATFORM:** R-AUTH-1: Tokens are audience-bound (web/API/device) and verified server-side against an immutable per-context store. Logout and revocation are synchronous and verified. R-AUTHZ-1: Recipients get case-scoped access, not global access.
**TEST THAT PROVES THE REQUIREMENT:** A cross-context replay matrix (API token → web, web cookie → API, token after logout, token after password/2FA reset, across N workers) must all return 401. A concurrency test with multiple workers is required.

**INCIDENT:** I-6 — GHSA-rqwh-4873-322p (CVE-2026-71863 per GHSA page), onion client-auth keys copied to Monitor Server, server 2.13.0–2.16.0, 2026-07-08
**WHAT FAILED:** In the Debian-packaging refactor, an Ansible `copy` source path was built from a variable that was empty when journalist alerts were disabled. Ansible copied the entire directory, including JI and SSH onion client-auth credentials, to `/var/ossec` on the Monitor Server.
**ROOT CAUSE:** String-concatenated paths with falsy/empty handling, plus a directory-copy semantic.
**DATA EXPOSED:** Onion service client-auth private keys (JI access gate and SSH gate) placed on a less-trusted host.
**CAPABILITY REQUIRED BY ATTACKER:** Compromise of the Monitor Server's `ossec` user, on a configuration with alerts disabled.
**WHY THE ORIGINAL DESIGN DID NOT PREVENT IT:** Nothing verified *which* secrets are present on *which* host. Configuration management is trusted implicitly.
**ARCHITECTURAL LESSON:** Secret placement must be an asserted invariant, not an emergent property of deployment scripts.
**REQUIREMENT FOR OUR PLATFORM:** R-DEPLOY-1: A per-host secret manifest (allow-list). Deployment fails if an unexpected secret-bearing file exists. There are no directory copies of secret stores.
**TEST THAT PROVES THE REQUIREMENT:** A post-deploy scanner (testinfra/goss) runs on every host for every feature-flag combination. It asserts the set of key files equals the manifest, searching for PEM/onion-auth/age/OpenPGP patterns.

**INCIDENT:** I-7 — CVE-2026-54707 (GHSA-v833-3823-cmhp), OnionShare receive mode writes files when disabled, 2.6.3, 2026-06-09
**WHAT FAILED:** A `--disable-files` text-only dropbox still wrote uploaded files. Enforcement was in the route handler after Werkzeug's `_get_file_stream()` had already created them.
**ROOT CAUSE:** Policy was checked after parsing (a TOCTOU between parser and handler).
**DATA EXPOSED:** No confidentiality impact, but the operator received untrusted files against policy (malware delivery, disk exhaustion).
**CAPABILITY REQUIRED BY ATTACKER:** Anyone who can reach the onion (public mode) or holds the client key.
**WHY THE ORIGINAL DESIGN DID NOT PREVENT IT:** Framework defaults (eager multipart parsing to disk) were not considered part of the attack surface.
**ARCHITECTURAL LESSON:** Enforce content policy at the earliest layer (reverse proxy/stream parser) and never let a framework write untrusted input to disk before policy.
**REQUIREMENT FOR OUR PLATFORM:** R-INGEST-1: The upload pipeline streams directly into an encrypt-on-ingest sink. Policy (allowed parts, sizes, count) is enforced before any byte is persisted, and plaintext is never written to disk.
**TEST THAT PROVES THE REQUIREMENT:** Crafted multipart requests (extra file parts, huge parts, nested multipart, missing boundaries) are sent against every disabled-feature configuration. Assert zero filesystem writes (fanotify) and correct rejection.

**INCIDENT:** I-8 — CVE-2026-54706 (GHSA-22p9-r2f5-22mf), OnionShare follows symlinks, 2.6.3, 2026-06-09
**WHAT FAILED:** Share and Website modes served symlink targets outside the shared directory.
**ROOT CAUSE:** `os.path.isfile()` and plain `open()` without containment.
**DATA EXPOSED:** Any file readable by the OnionShare user (SSH keys, wallets, configs).
**CAPABILITY REQUIRED BY ATTACKER:** Getting the victim to share a directory containing a symlink (e.g., an extracted archive).
**WHY THE ORIGINAL DESIGN DID NOT PREVENT IT:** The implementation assumed the user-selected directory is a trust boundary.
**ARCHITECTURAL LESSON:** Filesystem containment needs `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` or equivalent.
**REQUIREMENT FOR OUR PLATFORM:** Covered by R-PATH-2, plus a no-symlink policy on any served or exported tree.
**TEST THAT PROVES THE REQUIREMENT:** Place symlinks and hardlinks to /etc/passwd and to sibling dirs in export/serve trees. Assert they are not served or exported.

**INCIDENT:** I-9 — ToB-SDW-012 / ToB-SDW-016 (Trail of Bits, Dec 2020), arbitrary path writes in sd-app and the sd-devices export tar unpacker
**WHAT FAILED:** The download path was fully trusted from the server, and `TarFile.extractall` was used on the `.sd-export` archive.
**ROOT CAUSE:** Unsafe archive and path APIs.
**DATA EXPOSED:** Potential code execution in sd-app (all decrypted data) or sd-devices (the export path to USB).
**CAPABILITY REQUIRED BY ATTACKER:** A malicious server (012), or a compromised sd-app sending a crafted export (016).
**WHY THE ORIGINAL DESIGN DID NOT PREVENT IT:** VM isolation limits blast radius but not in-VM integrity. The same bug class then recurred in 2025 and 2026 (I-1, I-2), showing that the audit fixes were instance-level.
**ARCHITECTURAL LESSON:** Audits must produce *regression rules* (ToB supplied a Semgrep query for `extractall`), and these must be enforced in CI permanently.
**REQUIREMENT FOR OUR PLATFORM:** R-AUDIT-1: Every audit finding produces a failing test or static rule before closure.
**TEST THAT PROVES THE REQUIREMENT:** A CI job lists audit IDs and maps each to a test ID. The build fails if any finding lacks a linked test.

**INCIDENT:** I-10 — OTF-012 / CVE-2022-21689 (ROS 2021), OnionShare receive-mode DoS
**WHAT FAILED:** Upload directory names used one-second granularity with a 100-attempt failsafe, so parallel uploads over Tor blocked legitimate uploads (about 16% dropped in the test).
**ROOT CAUSE:** Predictable, low-resolution naming plus a hard cap.
**DATA EXPOSED:** None (availability only).
**CAPABILITY REQUIRED BY ATTACKER:** Anonymous access in public mode.
**WHY THE ORIGINAL DESIGN DID NOT PREVENT IT:** Anonymous endpoints cannot rate-limit by identity.
**ARCHITECTURAL LESSON:** Anonymous intake needs identity-free DoS controls (Tor PoW, client puzzles, queueing), as also in 7ASecurity SEC-01-014 (open for SecureDrop).
**REQUIREMENT FOR OUR PLATFORM:** R-DOS-1: Onion PoW (Tor `HiddenServicePoWDefensesEnabled`) is enabled by default. Storage names are random 128-bit. Per-circuit and global quotas with graceful queueing.
**TEST THAT PROVES THE REQUIREMENT:** A load test with at least 1,000 parallel anonymous uploads while a legitimate uploader succeeds within its SLO. No name collisions over 10^7 simulated inserts.

**INCIDENT:** I-11 — Accepted-risk design gap: SVS air-gap phishing and malware (SecureDrop threat model, "unmitigated")
**WHAT FAILED:** By design, nothing technically stops a malicious submission from exploiting the SVS viewer and exfiltrating via the next USB transfer, or from tricking a journalist into moving it to a networked machine.
**ROOT CAUSE:** Viewing and decryption live in the same (air-gapped but persistent) Tails environment, with sneakernet as the channel back.
**DATA EXPOSED:** The Submission Key and all submissions on the SVS.
**CAPABILITY REQUIRED BY ATTACKER:** A document exploit (PDF/Office/image) plus reliance on human USB transfer.
**WHY THE ORIGINAL DESIGN DID NOT PREVENT IT:** The air gap addresses network exfiltration only. USB is a bidirectional channel.
**ARCHITECTURAL LESSON:** Separate *key custody* from *document rendering* (SDW: sd-gpg vs disposable sd-viewer) and render untrusted content in disposable, no-network, no-persistence sandboxes, ideally after conversion (Dangerzone).
**REQUIREMENT FOR OUR PLATFORM:** R-VIEW-1: Decryption keys are never in the same compartment as a parser of untrusted content. Every open happens in a fresh disposable sandbox with no network and no shared writable storage.
**TEST THAT PROVES THE REQUIREMENT:** A red-team corpus of weaponized documents (known CVE PoCs). Verify with instrumentation that the rendering sandbox has no key material, no network and no persistence after close.

---

## 4. Principles to adopt

1. **Newsroom/tenant-owned deployment, with no third-party custodian of submissions** (SD). For Enterprise/Gov, this is a self-hosted option with a hardware-rooted boot.
2. **Onion-first intake**, with v3 client-auth onions for recipient/admin surfaces and Tor PoW DoS defence enabled (SD 2.9.0).
3. **No access logs by default.** ErrorLog to /dev/null at `crit`, scrubbed alerts, and only the most-recent timestamp per source (SD). Make the logging policy an explicit, testable spec (7ASecurity SEC-01-016 shows the tension).
4. **Server-generated, high-entropy source secrets** (≥7 diceware words or a 12-word BIP39 mnemonic of 128 bits). No user-chosen passwords and no recovery path. Use a memory-hard KDF (upgrade scrypt N=2^14 to Argon2id with tuned params).
5. **Move to server-blind E2EE with metadata-private fetching** (SecureDrop Protocol v0.4): hybrid PQ (ML-KEM-768 / X-Wing), a signed key hierarchy with pinned root, one-time journalist key bundles, and padded fixed-size mailbox with challenge-based retrieval.
6. **Client treats server as hostile.** All server-supplied metadata is untrusted (I-1, I-2, I-4). Proxies pin origin at the connection layer, with no redirects.
7. **Key custody separated from content rendering**: split-GPG-style decrypt domain + disposable, non-networked viewers (SDW). Add Dangerzone-style rasterization before viewing and export.
8. **Least-privilege IPC with transport-derived identity** (qrexec lessons: TOB-SDW-018, CVE-2025-24889).
9. **Reproducible builds verified in CI (build twice + diffoscope)**, hash-pinned wheels, `cargo-vet`, offline-signed releases, signed apt/RPM repos, and phased rollouts with a kill switch (SD 2.12.x).
10. **Enforced pre-flight updates** before the recipient client runs (SDW updater).
11. **Public audit program + bug bounty + detailed advisories with root cause** (FPF practice). Track every audit ID as a public issue (the SEC-01-xxx pattern).
12. **Weak-key rejection** at install and runtime (SD 2.7.0 disables interfaces with weak or SHA-1 submission keys).
13. **Accessibility and i18n as first-class** (ARIA work, Weblate, per-language wordlists).
14. **Code-delivery integrity for any browser-based crypto client** (WEBCAT model: signed bundles, transparency log, blocking verification).

## 5. Do NOT copy

1. **Server-side encryption of plaintext** (the server sees submissions in memory) and **server-held per-source secret keys** wrapped by a codename-derived secret.
2. **Flat authorization**, where every journalist sees every source. We need case/desk scoping and dual-control for sensitive exports.
3. **An air-gap + USB sneakernet as the primary malware control.** It is high-burden, error-prone and still an "unmitigated" risk in SD's own threat model.
4. **Tails-only or Qubes-only recipient workflows as the sole option.** The hardware and skill burden limits adoption (docs: $2.2–2.4k plus a Linux sysadmin). Offer a managed hardened appliance plus a Qubes high-assurance tier.
5. **Relying on sources to set the Tor Browser slider to "Safest".** Design the source UI to be fully functional without JS and verify integrity of any JS that is required.
6. **Metadata "stripping" tools (MAT/MAT2) as a guarantee.** They miss embedded-image EXIF and are format-incomplete. Use reconstruct/rasterize, and label the output as best-effort.
7. **Unsigned alert emails** (SD alerts are encrypted but not signed) and email as an alerting channel at all for Gov deployments.
8. **Deny-list path validation**, `tarfile.extractall`, and framework defaults that parse to disk.
9. **Secret distribution via generic config-management copies** (I-6). Use a secret manifest per host.
10. **Unattended-boot servers without FDE** (SEC-01-017 open). Use TPM-sealed or Tang/Clevis-style network-bound decryption for the Enterprise edition.
11. **Passphrase-less long-term decryption keys protected only by disk encryption and VM isolation** (SDW requirement). Prefer hardware-backed keys (smartcard/HSM/TPM) with per-session unlock.
12. **Session separation by string prefix** (I-5).
13. **A stale threat model** (SD still labels it "0.3"). Keep a versioned threat model tied to releases.
14. **An OnionShare-style recipient-hosted intake** (recipient laptop as the internet-exposed server, plaintext on disk).

---

## 6. Bibliography

- **[B-SD-01]** securedrop-docs `docs/introduction/what_makes_securedrop_unique.rst` (main). https://github.com/freedomofpress/securedrop-docs/blob/main/docs/introduction/what_makes_securedrop_unique.rst. Last-updated date not captured. Metadata minimization claims (only latest timestamp) and newsroom-owned server model.
- **[B-SD-02]** SecureDrop `changelog.md` (develop). https://github.com/freedomofpress/securedrop/blob/develop/changelog.md. Current as of 2026-09-30 (2.17.0~rc1). Authoritative version-by-version security changes (Sequoia, argon2id, Noble, 7ASecurity fixes, sessions).
- **[B-SD-03]** SecureDrop GitHub releases. https://github.com/freedomofpress/securedrop/releases. Latest 2.16.1, 2026-07-08. Release dates, phased Noble rollout, CVE-2026-50000 reference.
- **[B-SD-04]** securedrop-docs threat model `mitigations.rst` and `threat_model.rst`. https://github.com/freedomofpress/securedrop-docs/tree/main/docs/appendices/threat_model. Date not captured (content labelled "0.3"). Assets, assumptions, unmitigated risks (SVS phishing, DNS correlation, etc.).
- **[B-SD-05]** securedrop-workstation README. https://github.com/freedomofpress/securedrop-workstation. Current Sept 2026. VM architecture, per-VM compromise model, Qubes 4.3, pre-flight updater, 1.0.0 open beta July 2024.
- **[B-SD-06]** securedrop-client (SecureDrop Inbox) README. https://github.com/freedomofpress/securedrop-client. Current Sept 2026. Electron Inbox, Rust proxy, export, log, and keyring components.
- **[B-SD-07]** securedrop-workstation releases. https://github.com/freedomofpress/securedrop-workstation/releases. 1.9.0 on 2026-09-02; 1.8.0 on 2026-07-20; 1.7.1 page shows "May 28, 2006" (evidently a typo; probably 2026, UNVERIFIED). Debian 13 templates; legacy client removed.
- **[B-SD-08]** securedrop-docs `introduction/securedrop_workstation.rst` and `index.rst`. https://github.com/freedomofpress/securedrop-docs/tree/main/docs. Date not captured. SVS described as legacy; hardware cost $2,200–2,400; docs onion address.
- **[B-SD-09]** SecureDrop `securedrop/sdconfig.py` (develop). https://github.com/freedomofpress/securedrop/blob/develop/securedrop/sdconfig.py. Current. scrypt N=2^14,r=8,p=1; session lifetimes; 500 MB limit; Redis password required.
- **[B-SD-10]** securedrop-protocol README. https://github.com/freedomofpress/securedrop-protocol. Updated July 2026 or later. Status timeline (Orrù Dec 2023, Maier Jan 2025, CCS 2026, v0.4).
- **[B-SD-11]** securedrop-protocol `docs/protocol.md` v0.4. https://github.com/freedomofpress/securedrop-protocol/blob/main/docs/protocol.md. v0.4, 2026. Primitives, key hierarchy, fetching, stated limitations.
- **[B-SD-12]** WEBCAT repo. https://github.com/freedomofpress/webcat. Alpha, date not captured. Paper: https://eprint.iacr.org/2025/797 (not fetched, blocked). Browser code-integrity for web apps.
- **[B-SD-13]** SecureDrop 2024 audit issues (7ASecurity SEC-01-006…018). https://github.com/freedomofpress/securedrop/issues?q=%22SEC-01%22. Filed 2024-10-29. Open/closed status of audit hardening items.
- **[B-SD-14]** securedrop-docs `appendices/passphrases.rst`. https://github.com/freedomofpress/securedrop-docs/blob/main/docs/appendices/passphrases.rst. Date not captured. Credential inventory for journalists and admins (Qubes-based; per-server 2FA).
- **[B-SD-15]** SecureDrop PR #7587 "Updated SI security slider instructions". https://github.com/freedomofpress/securedrop/pull/7587. 2025-06-26/27. "Safest" guidance and JS banner.
- **[B-SD-16]** SecureDrop `securedrop/source_user.py`. https://github.com/freedomofpress/securedrop/blob/develop/securedrop/source_user.py. Current. Codename→scrypt→filesystem_id / gpg_secret; redwood per-source keys.
- **[B-SD-17]** SecureDrop `securedrop/passphrases.py`. https://github.com/freedomofpress/securedrop/blob/develop/securedrop/passphrases.py. Current. 7 words, SystemRandom, length bounds.
- **[B-SD-18]** Codename entropy calculation (this note; derived from B-SD-17). n/a. ~89.8 bits for a 7,300-word list.
- **[B-SD-19]** securedrop-docs `admin/migration/removing_gpg_passphrase.rst`. https://github.com/freedomofpress/securedrop-docs/blob/main/docs/admin/migration/removing_gpg_passphrase.rst. Date not captured. SDW requires a passphrase-less Submission Key.
- **[B-SD-20]** GHSA-78xq-8jf3-gpfx (CVE-2026-50000). https://github.com/freedomofpress/securedrop/security/advisories/GHSA-78xq-8jf3-gpfx. 2026-06-24. Session-prefix corruption / token reuse.
- **[B-SD-21]** SecureDrop Apache SI vhost template. https://github.com/freedomofpress/securedrop/blob/develop/install_files/ansible-base/roles/app/templates/sites-available/source.conf. Current. No access log, ErrorLog /dev/null, CSP/COOP/COEP headers, 500 MB limit.
- **[B-SD-22]** GHSA-rqwh-4873-322p (CVE-2026-71863 per the page, single source). https://github.com/freedomofpress/securedrop/security/advisories/GHSA-rqwh-4873-322p. 2026-07-08. Client-auth credentials copied to the Monitor Server.
- **[B-SD-23]** SecureDrop issue #2643 "Install pdf-redact-tools on the SVS". https://github.com/freedomofpress/securedrop/issues/2643. Closed 2018-03-18. MAT shortcomings (embedded image EXIF).
- **[B-SD-24]** securedrop-workstation issue #26 "file conversion and metadata removal". https://github.com/freedomofpress/securedrop-workstation/issues/26. Opened 2017-09-14, still open. No built-in sanitization on SDW.
- **[B-SD-25]** securedrop-client issue #3706 "Transform in Disposable Qube". https://github.com/freedomofpress/securedrop-client/issues/3706. 2026-08-27. Dangerzone-in-DispVM design.
- **[B-SD-26]** SecureDrop `.github/workflows/build.yml`. https://github.com/freedomofpress/securedrop/blob/develop/.github/workflows/build.yml. Current. Build-twice + diffoscope reproducibility; app-code FIXME.
- **[B-SD-27]** securedrop-builder README. https://github.com/freedomofpress/securedrop-builder. Date not captured. Reproducible, hash-pinned, signed wheels.
- **[B-SD-28]** Trail of Bits, "SecureDrop Workstation Security Assessment" (final 2021-01-29; engagement 2020-11-30 to 12-18). https://github.com/trailofbits/publications/blob/master/reviews/SecureDropWorkstation.pdf. 26 findings; 1 High (TOB-SDW-012).
- **[B-SD-29]** securedrop-client `app/README.md`. https://github.com/freedomofpress/securedrop-client/blob/main/app/README.md. Current. Electron main/renderer, SQLite, qrexec to proxy.
- **[B-SD-30]** securedrop-client ADR 001 data sync. https://github.com/freedomofpress/securedrop-client/blob/main/architecture-decisions/001-data-sync.md. Date not captured. v2 sync semantics.
- **[B-SD-31]** securedrop-client `export/README.md`. https://github.com/freedomofpress/securedrop-client/blob/main/export/README.md. Current. `.sd-export` format; LUKS/VeraCrypt/IPP printers.
- **[B-SD-32]** securedrop-client security advisories list. https://github.com/freedomofpress/securedrop-client/security/advisories. As of 2026-09-30. Four advisories (2025–2026).
- **[B-SD-33]** GHSA-6c3p-chq6-q3j2 (CVE-2025-24888). https://github.com/freedomofpress/securedrop-client/security/advisories/GHSA-6c3p-chq6-q3j2. 2025-02-13. Reply download path traversal.
- **[B-SD-34]** GHSA-933q-fx9h-5g46 (CVE-2025-24889). https://github.com/freedomofpress/securedrop-client/security/advisories/GHSA-933q-fx9h-5g46. 2025-02-13. sd-log path traversal.
- **[B-SD-35]** GHSA-2jrc-x8fq-prvc (CVE-2026-35465). https://github.com/freedomofpress/securedrop-client/security/advisories/GHSA-2jrc-x8fq-prvc. 2026-04-13. gzip FNAME absolute-path injection.
- **[B-SD-36]** GHSA-6qxc-pcfg-v6qv (CVE-2026-49996). https://github.com/freedomofpress/securedrop-client/security/advisories/GHSA-6qxc-pcfg-v6qv. 2026-05-28. Proxy redirect bypass.
- **[B-SD-37]** securedrop-protocol issue #36 (Orrù audit). https://github.com/freedomofpress/securedrop-protocol/issues/36. Report delivered Jan 2024. Preliminary crypto audit (contents UNVERIFIED).
- **[B-SD-38]** Maier, "A Formal Analysis of the SecureDrop Protocol", ETH Zürich. https://doi.org/10.3929/ethz-b-000718325. 2025 (not fetched). Tamarin analysis.
- **[B-SD-39]** Berra et al., "The SecureDrop Protocol: End-to-End Encrypted Whistleblowing for All" (ACM CCS 2026). https://eprint.iacr.org/2026/1484. 2026 (not fetched, blocked). Peer-reviewed formalization.
- **[B-SD-40]** 7ASecurity blog "SecureDrop Security Audit". https://7asecurity.com/blog/2024/10/securedrop-security-audit/. Oct 2024 (blocked; search snippet only). 1 Medium, 2 Low, 15 recommendations. Report PDF: https://7asecurity.com/reports/pentest-report-securedrop.pdf (blocked).
- **[B-SD-41]** SecureDrop `SECURITY.md`. https://github.com/freedomofpress/securedrop/blob/develop/SECURITY.md. Current. Bugcrowd program, security@freedom.press, key fingerprint.
- **[B-SD-42]** securedrop-docs `introduction/history.rst`. https://github.com/freedomofpress/securedrop-docs/blob/main/docs/introduction/history.rst. Date not captured. DeadDrop (Swartz, 2011), StrongBox (May 2013), FPF (Oct 2013).
- **[B-SD-43]** Audit history list (Cure53 2013, iSEC 2014/2015, Leviathan 2018, Include Security 2018, ToB 2020–21, 7ASecurity 2024). https://securedrop.org/research/ (blocked; list via search snippet). **UNVERIFIED** beyond the ToB and 7ASecurity entries.
- **[B-OS-01]** OnionShare security advisories list. https://github.com/onionshare/onionshare/security/advisories. As of 2026-09-30. 10 advisories (2022, 2026).
- **[B-OS-02]** GHSA-v833-3823-cmhp (CVE-2026-54707). https://github.com/onionshare/onionshare/security/advisories/GHSA-v833-3823-cmhp. 2026-06-09. Receive-mode upload bypass.
- **[B-OS-03]** GHSA-22p9-r2f5-22mf (CVE-2026-54706). https://github.com/onionshare/onionshare/security/advisories/GHSA-22p9-r2f5-22mf. 2026-06-09. Symlink following.
- **[B-OS-04]** OnionShare ROS/OTF advisories, e.g. GHSA-ch22-x2v3-v6vq (CVE-2022-21690), GHSA-jh82-c5jw-pxpc (CVE-2022-21689), GHSA-gjj5-998g-v36v (CVE-2022-21692), GHSA-h29c-wcm8-883h (CVE-2022-21694), GHSA-99p8-9p2c-49j4 (CVE-2022-21695). https://github.com/onionshare/onionshare/security/advisories. 2022-01-18. 2021 audit results.
- **[B-OS-05]** OnionShare docs `features.rst`. https://github.com/onionshare/onionshare/blob/main/docs/source/features.rst. Current. Receive mode behaviour, webhook, Dangerzone/Qubes advice.
- **[B-OS-06]** OnionShare docs `security.rst`. https://github.com/onionshare/onionshare/blob/main/docs/source/security.rst. Current. Security scope and non-goals.
- **[B-OS-07]** OnionShare `CHANGELOG.md`. https://github.com/onionshare/onionshare/blob/main/CHANGELOG.md. Current (2.6.x). 2.4 client auth; 2.5 audit fixes; 2.6.4 symlink fix.
