# 05 — Source Operational Security Specification
Status: Draft v1.0 · Edition applicability: both (CE and EE identical — source protections are never edition-gated, ADR-020) · Owner: Source Safety & Content Design team (with Security Architecture review)

## 1. Purpose and scope

Research shows that the largest risks to sources are not in the network layer. They are **what the source does** (managed devices and networks, timing, repeat visits) and **what the content reveals** (metadata, canary traps, watermarks, printer dots, stylometry) [B-AN-34..43; INC-16, INC-17, INC-20, INC-31, INC-32, INC-73]. This document specifies:

1. The **guidance content** Candor shows to sources, as normative English master text written at about US grade-8 reading level. It has two tracks, **NORMAL-RISK** and **HIGH-RISK**, and high-risk material is revealed only on request, so ordinary users are not overwhelmed.
2. **Where and when** each piece of guidance appears in the source flow (just-in-time placement).
3. The **assistance and enforcement features** the Source UI (C-06 web, C-03 Source App) must implement so that guidance is backed by product behavior.
4. The **validation method**: readability, comprehension testing, and legal and translation review.

In scope: C-06, C-03, C-37 (Clearnet Information Site) and the guidance-related content of C-38. Out of scope: onion and network configuration (`16-TOR-I2P.md`), cryptography (`04-CRYPTOGRAPHY.md`), server-side metadata policy (`03-PRIVACY-ANONYMITY.md`), the file pipeline (`10-FILE-EVIDENCE-PIPELINE.md`), and screen-level UI design (`11-FRONTEND-SOURCE.md`).

**Protection statement.** The guidance *reduces* the chance that a source is identified through their own device, network, files, words or behavior (THR-002, THR-004, THR-009, THR-010, THR-011, THR-034, THR-048). It protects against the most likely adversary, the source's own employer (R4 §1, adversary A), and partly against national-level observers (adversary B). It supports protections P-02 (network identity vs observers), P-16 (metadata removal), P-19 (timing minimisation) and P-23 (source-device residue) in `40-SECURITY-ASSUMPTIONS.md`. It assumes:
- the source uses a proxy-enforcing Tor client (ASM-004);
- the source's device is not compromised (ASM-008);
- the source follows core guidance (ASM-009);
- the passphrase stays confidential (ASM-010);
- the content is not itself uniquely identifying beyond what the source accepts (ASM-011);
- the source's observable anonymity set is larger than one (ASM-007).

Residual risk remains high where the candidate set is small, whatever the guidance says (§11).

## 2. Context and dependencies

| Document | Relationship |
|---|---|
| `DECISIONS.md` | ADR-002 (modes), ADR-003 (no fingerprinting; exit-list check on C-37), ADR-004 (Tier W / Tier V; honest statement), ADR-005 (10-word passphrase), ADR-010 (day-granularity timing), ADR-012 (no server-side parsing), ADR-013 (escrow disclosure), ADR-014 (Sealed Identity Store), ADR-023 (no source telemetry), ADR-026 (no CAPTCHA) |
| `11-FRONTEND-SOURCE.md` | Implements the screens that carry this guidance (Landing, Safety Check, Anonymity Status, Metadata Warning, Review, Recovery Credential, Return Inbox, Delete/Abandon) |
| `03-PRIVACY-ANONYMITY.md` | Owns the compelled-disclosure inventory, which GC-01 must match |
| `10-FILE-EVIDENCE-PIPELINE.md` | What recipients see (sanitized derivative by default; sealed original). The guidance in GC-22 to GC-29 must match it |
| `12-FRONTEND-RECIPIENT.md` | Shows recipients the source's answer to "how many people know" (§8.7) and bans authorship-similarity tools |
| `16-TOR-I2P.md` | Onion service, PoW, bridges context; outage behavior |
| `26-ACCESSIBILITY.md` | Plain-language rules, translation review of security-critical strings, and comprehension-test protocol |
| `40-SECURITY-ASSUMPTIONS.md` | P-02, P-16, P-19, P-23; ASM-004, ASM-007..ASM-011; ASM-112 (the "What protects you and what does not" page, implemented by GC-01 on S03) |
| `25-COMPLIANCE.md` | Jurisdiction content packs (rights, external channels, anti-gag text) inserted into GC-03 and GC-37 |
| `30-ANONYMITY-TESTING.md` | Forensic-residue tests of the source flow (Tor Browser, Tails) |

## 3. Guidance design principles

| # | Principle | Rationale / evidence |
|---|---|---|
| GP-1 | **Two tracks, one page.** Everyone sees the NORMAL-RISK essentials. HIGH-RISK additions sit in native `<details>` disclosure elements on the same page, so they work without JavaScript and **the choice of track is never sent to the server**. | Opening a separate URL would reveal a risk signal to a server that could be compelled to log it (INC-03). |
| GP-2 | **Honest, bounded claims.** Say what is protected, from whom, and what is not. No "100% anonymous" style claims (DECISIONS §0). | INC-12 (legal protection weaker than users assumed); B-GL-09 (GlobaLeaks' honest matrix). |
| GP-3 | **Action-first wording.** Each card leads with what to do, then why, then a real-world example where one exists. | COGA [B-CO-36]. |
| GP-4 | **Just-in-time repetition.** Critical items are repeated at the moment of action (attach → metadata; write → style and AI; after submit → passphrase and return visits). | Sources skip long guides (B-SD-04 "user behavior" limitations). |
| GP-5 | **No fear-mongering, no dark patterns.** Tone is calm. Nothing blocks reporting except true safety interlocks. | High abandonment harms sources who have no safer alternative. |
| GP-6 | **Never advise unlawful acts.** No advice to destroy evidence, defeat monitoring, or access data without authorization. A legal-advice pointer is always present. | Legal exposure of the source and operator. |
| GP-7 | **No external links from the onion interface.** Tools are named, and official addresses are shown as plain, non-clickable text. Only C-37 (clearnet) may hyperlink official download pages. | INC-36 / REQ-H-36. |
| GP-8 | **No feedback widgets or analytics** on guidance (no "Was this helpful?"). | ADR-023; THR-036. |
| GP-9 | **Grade-8 readability** (Flesch-Kincaid ≤ 8.0) for NORMAL-RISK text; ≤ 10.0 for HIGH-RISK text. | R6 §C (plain-language); REQ-H-16b comprehension ≥ 80 %. |
| GP-10 | **The platform does what guidance alone cannot.** Wherever a risk can be reduced by product behavior (filename neutralization, local metadata cleaning in Tier V, identity-hint checks), the UI does it by default. | REQ-H-17, REQ-H-20. |

## 4. Risk tracks

### 4.1 Definitions

| Track | Who | Typical adversary | Guidance posture |
|---|---|---|---|
| **NORMAL-RISK** | Most sources: workplace misconduct, fraud or safety reports where the organization is unlikely to run a forensic hunt and the source is one of many people who know the facts | Employer HR/IT with routine logs (R4 adversary A, passive) | Personal device + Tor Browser at Safest + non-work network + clean files + passphrase hygiene |
| **HIGH-RISK** | Few people know the facts; the subject is senior leadership, national security, law enforcement, organized crime or a state; the source faces legal, physical or immigration danger; or the source is in a censoring or monitoring country | Employer actively investigating (INC-22 Barclays), national LE/intel (R4 adversary B), censor (adversary E) | Adds Tails, bridges, physical/phone-location discipline, memorized passphrase, minimal return visits, content minimization, stylometry care |

### 4.2 Self-selection text (shown on Safety Check; answered in the head, never transmitted)

> **Are you at higher risk?** Open the "Higher risk" sections if **any** of these is true:
> - Only a few people (about 10 or fewer) know what you are reporting.
> - The report is about top managers, police, the military, intelligence, or powerful people.
> - Your organization has tried to find out who reported things before.
> - You could face arrest, violence, deportation, or a lawsuit if found.
> - You live in a country that blocks or watches internet use.
> - You have already been questioned, or you think you are being watched.

### 4.3 What changes between tracks (summary)

| Topic | NORMAL-RISK | HIGH-RISK adds |
|---|---|---|
| Device | Personal, never employer-managed | Tails from a new USB stick; avoid phones |
| Browser | Tor Browser, Safest | Verify the download signature; New Identity after use |
| Network | Home or public, never work | Bridge (WebTunnel/obfs4/Snowflake); rotate networks; network not linked to you |
| Place | Private, no screen view | Phone left at home; routine-consistent timing; cash; no repeat locations |
| Files | Retype or describe; rename; no cloud | Assume unique copies and watermarks; send only what many people had |
| Words | Short, factual | Plain neutral style; minimize facts known to fewer than 5 people |
| Passphrase | Paper hidden or non-synced password manager | Memorize, then destroy paper; Tails Persistent Storage |
| Return visits | Every few days at most | Rarely; different networks; never after a linked event |

## 5. Observation model: who can see what

| Observer | Can observe | Cannot observe (under stated assumptions) | Guidance cards |
|---|---|---|---|
| Employer network (proxy, DNS, firewall, Wi-Fi) | That Tor is used, when, and by which device (THR-002); possible website-fingerprinting leads for our portal (THR-004; B-AN-15, B-AN-16) | Destination onion or content (Tor intact) | GC-05, GC-09, GC-10, GC-34 |
| Employer endpoint (MDM, EDR, DLP, screen recording) | Everything on that device: files, clipboard, screen, keystrokes, USB (THR-048) | Nothing is safe on it | GC-04, GC-05, GC-19, GC-21 |
| Employer document systems | Who opened, downloaded, printed or emailed each document and when (INC-16) | — | GC-15, GC-19, GC-20, GC-25 |
| The document itself | Metadata, canary variants, watermarks, printer dots (THR-009, THR-010) | — | GC-22 to GC-29 |
| Recipient organization's case team (for internal channels, the same organization) | The report content and any metadata left in originals; for CONFIDENTIAL mode, identity only via custodians (ADR-014) | Source IP (ADR-001); exact submission time (ADR-010) | GC-01, GC-23, GC-30, GC-31 |
| ISP / national observer | Tor use; timing; with a bridge, less (B-AN-30, B-AN-31) | Destination (Tor intact); content | GC-09, GC-10, GC-11, GC-33 |
| Household / physical | Screens, notes, devices, phone location history | — | GC-12, GC-32, GC-35 |
| Platform operator (compelled or compromised) | See `03-PRIVACY-ANONYMITY.md` inventory. Tier W: plaintext during sealing (ADR-004) | IP, exact times, device fingerprint | GC-01, GC-38 |
| Third-party services (cloud, AI, translators) | Everything pasted or synced (THR-029-like exposure outside Candor; THR-036) | — | GC-15, GC-16 |

## 6. Guidance content (normative English master text)

**Conventions.** Each Guidance Card (GC-nn) has a string key (`sops.<card>.normal` / `.high`) used by the i18n pipeline (`26-ACCESSIBILITY.md`). All card text is a **security-critical string** class `sec:critical` (26). Placeholders in `{braces}` are filled from deployment configuration. Text in *italic brackets* is an editorial note, not displayed. "Higher risk" text is rendered inside `<details><summary>If you are at higher risk</summary>…</details>`.

### A. Before you start

**GC-01 What this site can and cannot do** — `sops.limits` — Landing, Safety Check, Anonymity Status
> **What this site does.** This site hides your internet address from us and from the people who read reports. We don't ask for your name. We only record the date a report arrives, not the time.
>
> **What this site can't do.** It can't see or clean your computer or phone. It can't stop your employer from seeing that you used Tor on a work network. It can't remove every clue from your files or your words. The steps on this page help with those risks.
>
> **When you use this website** *(Tier W only)*: your report is locked (encrypted) on our server as soon as it arrives. If someone had secretly taken control of the server at that moment, they could read it. The Candor app locks your report on your own device before sending, which avoids this.
>
> **Who reads reports:** {channel_recipient_description}. You can tick people your report is about, and they will not get a key to open it. {recovery_escrow_statement}

`{recovery_escrow_statement}` is either "No one outside the listed team can unlock reports." or "A backup key is split between {quorum_holders}. {k} of them together could unlock reports." (ADR-013).

**GC-02 Choose how careful you need to be** — `sops.track` — Safety Check
> Most people only need the **basic steps** below. Some people need more. *(The §4.2 self-selection list follows.)* If you are not sure, follow the higher-risk steps too. They take more time but give more protection.

**GC-03 Your rights and your safety** — `sops.legal` — Landing footer, Safety Check, Delete/Abandon
> This site does not give legal advice. Laws about reporting are different in each country and job. A lawyer, a union, or a whistleblower support group can explain your rights. {jurisdiction_rights_text}
>
> If you are in danger right now, contact your local emergency services.

### B. Devices and browsers

**GC-04 Use the right device** — `sops.device`
> **Use a personal computer that your employer has never managed.** Don't use a work laptop, work phone, or a shared computer that other people can look at. A computer you own and control is best.
>
> *Higher risk:* Use a computer that has never been used for work, or start it with **Tails** (see GC-08). Avoid phones if you can. Phones keep detailed records and your location history. If you must use a phone, use Tor Browser for Android.

**GC-05 Work devices are watched** — `sops.managed`
> Work computers and phones often have security software you can't see. It can record the websites you visit, the files you open or copy, and sometimes your screen. **Using Tor on a work device can itself set off an alert.**
>
> Don't use a work device for anything about this report: not to search, not to write notes, not to copy files. This also applies to a personal phone that has a work profile or a "company portal" app.
>
> *Higher risk:* Don't try to turn off or get around monitoring software. Trying is often recorded and can draw attention to you. Don't connect your personal phone to a work computer, even to charge it.

**GC-06 Use Tor Browser** — `sops.browser`
> Use **Tor Browser**. Get it only from the Tor Project's official site: torproject.org.
>
> Other tools don't protect you the same way:
> - **Private or incognito windows** only stop your own browser from keeping history. Your network and websites still see you.
> - **A VPN** hides your activity from your local network, but the VPN company can see it and may keep records.
> - **Other browsers with a "Tor window"** are not the same as Tor Browser.
> - **On iPhone or iPad**, the only choice is Onion Browser, which gives weaker protection. Use a computer or an Android phone if you can.
>
> *Higher risk:* Check the download's signature, following the steps on torproject.org. Keep Tor Browser up to date. Don't add extensions or change advanced settings. That makes your browser stand out.

**GC-07 Set Tor Browser to "Safest"** — `sops.safest`
> Click the **shield** icon, then **Settings**, and choose **Safest**. This turns off JavaScript, which blocks many attacks. This site works fully at Safest.
>
> If you see a yellow box saying "JavaScript is on", change the setting and reload the page.
>
> *Higher risk:* Check the setting before each visit. When you finish, choose **New Identity** from the Tor Browser menu, then close Tor Browser.

**GC-08 Tails: a safer system for high-risk reporting** — `sops.tails`
> *(Normal track shows one line: "If you are at higher risk, consider Tails. See below.")*
>
> *Higher risk:* **Tails** is a free system you start from a USB stick. It sends all internet traffic through Tor and forgets everything when you shut down, so it leaves almost no traces on the computer. Get it from tails.net on a device you trust, and follow its install and check steps. If you can, use a new USB stick you bought with cash. Tails includes a screen reader (Orca) and a screen magnifier.

**GC-38 Website or app?** — `sops.tier`
> You can use this **website** in Tor Browser, or the **Candor app**. The app locks your report on your own device before sending it, checks that it is talking to the right team, and can clean hidden data from photos and documents. But an installed app is a sign that you used it if someone searches your device. If your device could be searched, use the website in Tor Browser, ideally on Tails.

### C. Networks and places

**GC-09 Your network can see that you use Tor** — `sops.torvisible`
> The people who run your network can see **that** you use Tor, but not **which** sites you visit. At home, that is your internet provider. At work or school, it is your employer, and very few people there may use Tor.
>
> *Real case:* A student who used Tor on his university's Wi-Fi was found because he was one of very few Tor users on that network at that time.
>
> **Never use a work or school network**, including work Wi-Fi, office guest Wi-Fi, or a work VPN.
>
> *Higher risk:* Use a network that isn't linked to you, or use a bridge (GC-10). Don't use the same network every time.

**GC-10 Bridges hide that you use Tor** — `sops.bridges`
> A **bridge** is a less visible way into the Tor network. It makes it harder for your network to tell that you use Tor. In Tor Browser, go to **Settings → Connection → Bridges** and choose a built-in bridge. **WebTunnel** looks like ordinary web browsing. **obfs4** and **Snowflake** are other choices. A bridge does **not** make a work device safe.
>
> *Higher risk:* Built-in bridges are publicly listed and can be recognized. Use **Request a bridge** in Tor Browser to get a less-known one. Don't request bridges from an email or chat account linked to you.

**GC-11 If Tor is blocked** — `sops.censorship`
> If Tor Browser can't connect, your country or network may be blocking Tor. Use Tor Browser's **Connection Assist**. It suggests a bridge that works where you are.
>
> If this site is down, **don't use another "anonymous" address you find elsewhere.** We never offer an anonymous version of this site outside Tor. Check the address again later at {info_site_address}.
>
> *Higher risk:* Where using Tor is dangerous, think about your personal safety before you try. A digital-safety group you trust can help.

**GC-12 Where you are** — `sops.place`
> Choose a private place where no one can see your screen. Watch for cameras, windows and mirrors behind you. Don't do this at work, in a work car, or near work colleagues.
>
> *Higher risk:* **Your phone records where you go.** If you travel somewhere to send your report, leave your phone at home. Go at a time that fits your usual routine. Pay with cash. Avoid seats in view of cameras, and don't go back to the same place each time.

### D. Research and accounts

**GC-13 Look things up safely** — `sops.research`
> You may want to look up how to report, what the law says, or this site's address. **Do that in Tor Browser too, on your personal device.** Searches on work devices, or while logged in to Google, Microsoft, Apple or similar accounts, are saved and can be seen later.
>
> *Higher risk:* In the days before you report, don't look at pages about the issue in a way that stands out, especially at work. That includes internal pages, news stories and company pages.

**GC-14 Don't log in to anything** — `sops.accounts`
> Don't log in to email, social media, work accounts, or any account with your name while you use Tor Browser for this report. Never use work email, work chat or a work calendar for anything about your report.
>
> *Higher risk:* Don't create new accounts (like a new email address) for your report unless you really need one. Every account is another trail.

**GC-15 Keep files out of the cloud** — `sops.cloud`
> Files in OneDrive, Google Drive, iCloud, Dropbox or SharePoint are copied to company servers, often with a record of who opened, downloaded or shared them. **Don't save report files or notes in any cloud folder.** Check that your personal device doesn't copy your Desktop or Documents folders to the cloud. Don't email files to yourself.
>
> Only use information you had a lawful reason to access. Ask a lawyer if you are not sure.
>
> *Higher risk:* Assume your organization's systems record who opened, downloaded, copied, printed or emailed each document, and when. That list can be very short. In your report, say roughly how many people could have had the same information. This helps the team protect you.

**GC-16 Never paste into AI tools, translators or grammar checkers** — `sops.ai`
> **Never paste your report, notes or documents into:**
> - AI chatbots or writing assistants (for example ChatGPT, Copilot, Gemini or Claude),
> - online translators (for example Google Translate or DeepL),
> - grammar or spelling services (for example Grammarly),
> - AI features built into office apps, email, browsers or phone keyboards.
>
> These services send your text to a company that may keep it. **Your employer may be able to see what you typed into work versions of these tools.**
>
> *Higher risk:* Turn off cloud-based keyboard features on your phone, such as online prediction and voice typing.

### E. Traces on your own devices

**GC-17 History and downloads** — `sops.history`
> Tor Browser forgets your browsing when you close it. Other browsers don't. If you used another browser to find this site or read about reporting, clear that browser's history. This site never asks you to download anything.
>
> *Higher risk:* Deleted files can often be brought back with special tools, especially from USB sticks and older hard drives. Tails avoids creating these files in the first place.

**GC-18 Recent files, previews and system records** — `sops.traces`
> Your computer keeps lists of recently opened files and small preview pictures (thumbnails). Word, PDF readers, the Windows "Recent" list and the Mac "Recents" folder can show which files you opened for your report.
>
> *Higher risk:* Computers also keep system records: which USB drives were connected and when, which programs ran, search indexes of file contents, and backups (like Windows File History or Mac Time Machine). An expert can read these. You cannot reliably remove them all on a normal computer. Tails is designed to avoid them.

### F. What your organization may record

**GC-19 Security monitoring at work** — `sops.monitoring`
> Many organizations use security tools (sometimes called **EDR** or **DLP**) on work computers, email and networks. These tools can record files you open, copy, upload, print or email, the websites you visit, USB drives you plug in, and sometimes screenshots or keystrokes. They can alert security staff when someone copies sensitive files. **Assume anything you did on work systems can be looked at later.**
>
> *Higher risk:* These records are often kept for months. If you copied or printed documents in the past, that may already be recorded. Think about this before you decide what to send.

**GC-20 Don't print** — `sops.print`
> **Don't print documents to send them.** Work printers and copiers keep records of who printed what and when.
>
> *Real case:* A leaked document was traced partly because the organization's records showed only six people had printed it.
>
> *Higher risk:* Don't use work scanners or copiers either. They keep records and sometimes copies.

**GC-21 USB drives and memory cards** — `sops.usb`
> Work computers often record every USB drive that is plugged in, including its serial number. Don't plug personal drives into work computers, and don't plug work drives into your personal device.
>
> *Higher risk:* USB sticks and memory cards keep deleted files and hidden records. *Real case:* police found a deleted file with a church name and a first name on a floppy disk the sender believed could not be traced. If you must move files, use a new drive that has never touched a work device, and don't send the drive itself to anyone.

### G. What files reveal

**GC-22 Hidden data in photos** — `sops.exif`
> Photos from phones and cameras usually hold hidden information: the **exact location**, the date and time, and the phone model. *Real case:* a published photo's hidden location data showed where a man in hiding was.
>
> Turn off location for your camera before taking photos. When possible, **describe or retype** what a picture shows instead of sending it.
>
> {tier_clean_statement}
>
> *Higher risk:* Even with hidden data removed, experts can sometimes match a photo to the camera that took it, because each camera sensor leaves a tiny unique pattern. Don't send photos from a phone whose other photos are online or on work systems.

`{tier_clean_statement}`. Tier W: "On this website, we can't remove hidden data before your file is locked. The team normally views a cleaned copy, but your original file is kept as evidence." Tier V: "The Candor app removes this hidden data before sending and shows you what it removed."

**GC-23 Hidden data in documents** — `sops.docmeta`
> Word, Excel, PowerPoint and PDF files carry hidden details: **author names, company name, "last edited by", your computer's user name, folder names like C:\Users\jsmith, comments, tracked changes, and older versions of the text.** Opening and saving a file on your own computer can add your name.
>
> The safest way to share what a document says is to **copy the important parts into the form as plain text.**
>
> *Higher risk:* Some hidden details can link a file to the exact computer that edited it. PDFs can hold older versions inside them. The "remove personal information" features in office software don't remove everything. The team normally reads a cleaned copy, but the original is kept as evidence and may still hold these details.

**GC-24 File names and file dates** — `sops.filenames`
> File names can give you away, like "JSmith_notes.docx" or "Copy of budget (2).xlsx". **This site replaces your file names with plain ones like "file-01.pdf" unless you choose to keep them.**
>
> *Higher risk:* Files also carry dates for when they were created and changed. Zip files store names, dates and sometimes user names for every file inside, and zip files made on a Mac may include hidden extra files. Don't send zip files unless you need to.

**GC-25 Unique copies ("canary traps")** — `sops.canary`
> Some organizations give different people slightly different versions of a document, with different words, spacing or numbers. If you send your copy, those small differences can show it was yours. **If only a few people had a document, describe what it says instead of sending it**, or retype a short part in plain words.
>
> *Higher risk:* Retyping removes some hidden marks, but not differences in wording or numbers. Don't go looking for extra copies you don't normally use. That access may be recorded.

**GC-26 Invisible watermarks** — `sops.watermark`
> Documents, images and even your work screen can carry **invisible marks** that show who received or viewed them. Some are hidden characters in text. Some are tiny changes in pictures. Some screen tools add your user ID to everything shown on your work screen. You can't see or check for these marks yourself.
>
> *Higher risk:* Retyping text by hand removes hidden characters, but not unique wording. A photo of a work screen can capture an invisible screen watermark.

**GC-27 Printer tracking dots** — `sops.dots`
> Many color laser printers add tiny yellow dots to every page. The dots can show the printer's serial number and the print time. Photos and scans of printed pages carry the dots too. If you send a picture of a printed page, **tell the team it was printed** so they can handle it carefully.

**GC-28 Screenshots** — `sops.screenshots`
> Screenshots can show much more than you expect: your user name, email, open tabs, messages that pop up, the time, and your desktop picture. On work computers, taking a screenshot can be recorded. **Crop tightly** to the part that matters, or better, **retype** it.
>
> *Higher risk:* Screenshot files hold hidden data such as the device name and time. A screen's layout can be matched to one computer or one account.

**GC-29 Photos of documents and what's in the background** — `sops.background`
> Before you take a photo, check what else is in it: your desk, hands, rings, tattoos, a view from a window, reflections in the screen or in glasses, an ID badge, or a sticker on a monitor. Use a plain background and photograph only what you need.
>
> *Higher risk:* The room, angle, lighting and even the type of paper can point to a place. Photos of a work screen may show your login name or an invisible watermark (GC-26).

### H. What your words reveal

**GC-30 Details that point to you** — `sops.content`
> Details can point to you even without your name. For example: "I was in the meeting on 4 May", "as the only night-shift nurse", your job title, or something only you were told.
>
> The team needs facts to act, so you don't have to leave everything out. Instead:
> - Say **what happened** and **where evidence can be found**.
> - Use "early May" instead of an exact date if the exact date would point to you.
> - Say which details **only a few people know**. The team can then be careful when they investigate.
>
> *Higher risk:* For each detail, think about who could have known it. If fewer than about five people know it, ask yourself whether the team needs it now. The team can ask questions later through your secure mailbox, and you decide what to share.

**GC-31 Your writing style** — `sops.style`
> Your writing style, meaning your favorite words, spelling, punctuation, greetings and emojis, can be matched to emails you wrote at work. Your employer has a lot of your writing. **Keep messages short and factual.** Use simple sentences or lists. Leave out greetings, sign-offs, jokes and your usual phrases. Don't use online AI tools to rewrite your text (GC-16).
>
> *Higher risk:* Computers can now match writing styles well, especially when only a few people could be the writer. Write as plainly as you can. If someone you trust helps you reword your report, remember that they then know about it.

### I. After you send your report

**GC-32 Keep your passphrase safe** — `sops.passphrase`
> After you send your report, you get a **passphrase of 10 words**. It is the only way to read replies and add information. **No one can reset it or send it to you again**, not us and not the team.
> - Write it on paper and keep it somewhere private, away from work things. Or save it in a password manager on a personal device that doesn't sync to a work account.
> - Don't keep it in email, notes apps, photos, chats or cloud documents.
> - Don't share it. Anyone who has it can read replies and write as you.
>
> *Higher risk:* Try to learn it by heart. Practice it over the next few days, then destroy the paper. If you use Tails, you can keep it in Tails' encrypted Persistent Storage.

**GC-33 Checking for replies** — `sops.return`
> Replies can take days or weeks. The team aims to confirm they received your report within {ack_days} days. **Come back after a few days, not every hour.** Follow the same steps each time: personal device, Tor Browser, not a work network. Replies show the date only.
>
> *Higher risk:* Each visit is another chance for someone watching a network to link you to this site. Visit rarely, at times that fit your usual routine, and from different networks when you can. Don't visit right after an event others know about, such as the day after a meeting where the issue came up.

**GC-34 Timing** — `sops.timing`
> *When* you do things can point to you. Don't send your report from work or during your work hours. Avoid sending it right after you opened or copied documents at work.
>
> *Higher risk:* If someone knows when a report arrived, they may compare that with who was off work, who used Tor, or who opened files. **This site stores only the date a report arrives, not the time.** But your own network or device may record the exact time. Consider waiting some days after gathering information before you send it.

**GC-35 If your device is taken or searched** — `sops.seizure`
> If your device is taken or searched, or you are asked to hand it over:
> - Get legal advice before you answer questions, if you can.
> - **Don't destroy or hide anything that may be evidence.** That can be a crime.
> - This site does not store your name. What can be found depends on your device: files you saved, your passphrase if you wrote it down, and browser traces.
> - If someone may have seen your passphrase, they can read replies. When it is safe and legal to do so, you can **close your mailbox** so the passphrase no longer opens it, or send a message telling the team the passphrase may be known. Closing your mailbox does not delete your report.
>
> *Higher risk:* Plan ahead. If your device could be searched, use Tails and don't keep files or notes. In some places you can more easily be forced to unlock a phone with your face or fingerprint than with a passcode.

**GC-36 Keep the conversation here** — `sops.sidechannel`
> Only talk about your report through this secure mailbox. The team should never ask you to move to email, phone, chat or social media. If a message asks you to, be careful. Don't tell friends or colleagues about your report.
>
> *Real case:* someone shared secrets in an online chat with a person they trusted, and that person reported them to the authorities.

**GC-37 If you are treated unfairly** — `sops.retaliation`
> If you think you are being treated badly because someone suspects you reported, you can tell the team through your mailbox. Keep a private record of what happens, not on a work device. {jurisdiction_retaliation_text}

## 7. Placement map (just-in-time)

| Screen (`11-FRONTEND-SOURCE.md`) | Always visible (short form) | Linked full cards |
|---|---|---|
| S01 Landing | GC-01 summary; "Don't use a work device or work network" (from GC-04/GC-09) in the first viewport; JS-on warning (§8.2) | GC-01..GC-07 |
| S02 Safety Check | Checklist of NORMAL essentials (8 items, §7.1); track self-selection (§4.2) | All cards, grouped A–I; HIGH in `<details>` |
| S03 Anonymity Status | Mode, tier, escrow, recipient role labels (GC-01 dynamic parts); ASM-112 "What protects you and what does not" list | GC-38 |
| S04b "Is your report about any of these people?" (ADR-030) | Plain explanation that ticked roles get no key; empty by default | GC-30 |
| S05 Questionnaire | Beside long-text fields: "Keep it factual; don't paste into AI tools" | GC-16, GC-30, GC-31 |
| S06 Attach Evidence | "File names are replaced by default"; "Describe or retype when you can" | GC-22..GC-29 |
| S07 Metadata Warning | Per-file-type risk list (§7.2) | GC-22..GC-29 |
| S08 Review | Identity-hint results (§8.5); style checklist (§8.6) | GC-30, GC-31, GC-34 |
| S10 Recovery Credential | GC-32 normal text in full | GC-33, GC-35 |
| S11 Return Inbox (login) | "Tor Browser at Safest, not a work network"; visit-cadence reminder | GC-33 |
| S12 Conversation | "Keep the conversation here" (GC-36 short) | GC-30, GC-36, GC-37 |
| S13 Delete/Abandon | GC-35 short; GC-03 | GC-35 |
| Logout / Leave page | "Choose New Identity in Tor Browser, then close it." | GC-07, GC-33 |
| C-37 Info site | GC-01, GC-04..GC-11, with hyperlinks to official Tor Project/Tails pages and signature-check instructions | all |

### 7.1 Safety Check essentials (normative list, NORMAL track)
1. I am on a personal device, not a work device. (GC-04, GC-05)
2. I am not on a work or school network. (GC-09)
3. I am using Tor Browser, set to Safest. (GC-06, GC-07)
4. No one can see my screen. (GC-12)
5. I have not pasted anything into AI tools, translators or grammar checkers. (GC-16)
6. I will describe or retype information rather than send files when I can. (GC-22..GC-26)
7. I have not printed documents to send. (GC-20)
8. I am ready to keep a 10-word passphrase safe. (GC-32)

These are **plain list items, not checkboxes** (no form data is sent). A single "Continue" link follows. No item is enforced.

### 7.2 Metadata Warning content by file class (Tier W: class from file extension only; server never parses files, ADR-012)

| Class | Extensions (lower-cased) | Warning lines |
|---|---|---|
| Photo | jpg, jpeg, heic, heif, png, webp, tiff, dng, avif | Location, time and camera model (GC-22); background (GC-29); camera fingerprint (GC-22 high) |
| Screenshot-like | png (always shown with Photo) | GC-28 |
| Office | doc, docx, xls, xlsx, ppt, pptx, odt, ods, odp, rtf | Author, company, user name, paths, comments, tracked changes, old versions (GC-23); canary variants (GC-25) |
| PDF | pdf | Author, software, older versions inside, scanner/printer data; printer dots in scans (GC-23, GC-27) |
| Scan | pdf, tiff, jpg (additional line) | "If this is a scan or photo of paper: printer dots (GC-27)" |
| Audio/video | mp3, m4a, wav, ogg, mp4, mov, webm, mkv | Location, device, date; voices and background sounds can identify people |
| Archive | zip, 7z, rar, tar, gz | Names, dates, user names of every file inside (GC-24) |
| Email | eml, msg | Full headers: names, addresses, servers, times; forwarding chain |
| Other | anything else | "Files can hold hidden information about who made them." |

Tier V (C-03) replaces extension-based guesses with **actual local findings** (§8.4).

## 8. Platform assistance features (UI obligations)

**8.1 Local-only track choice.** The track choice is made by reading `<details>` elements. No request, cookie or form field records it. Both tracks are in the same HTML response.

**8.2 JavaScript-on warning without JavaScript.** The warning box is shown via CSS `@media (scripting: enabled) { .js-warning { display:block } }` and hidden otherwise. No script and no conditional resource load are used, so the server learns nothing. This is a no-JS implementation of REQ-H-27 [B-SD-15; INC-27]. Knowledge (unverified): the `scripting` media feature is supported in Firefox ESR 128-based Tor Browser. Verify per release (TST below). If it is unsupported, fall back to a `<noscript>`-free design in which the warning text is always shown in a collapsed `<details>` saying "Check: is Tor Browser set to Safest?".

**8.3 Filename neutralization.** The default is ON. On receipt, C-07 (Tier W) or C-03 (Tier V) replaces the original filename with `file-NN.<ext>` before sealing, where `<ext>` is lower-cased and restricted to `[a-z0-9]{1,8}`, otherwise `bin`. The source may untick "Replace file names with plain names (recommended)" on S06. The original name is then sealed as display metadata only (ADR-027). The original name is never logged.

**8.4 Metadata cleaning.**
- **Tier W:** no server-side cleaning (ADR-012). S07 shows the §7.2 warnings and the honest statement in GC-22.
- **Tier V (C-03):** before encryption, the app analyses each file **locally, in a sandboxed worker process with no network** and lists findings: "GPS location: 51.5°N…; Camera: …; Author: J. Smith; 3 comments; 12 tracked changes". It offers **Clean (recommended)**, **Send original**, or **Remove file**. Cleaning covers JPEG/HEIC/PNG/WebP (EXIF/XMP/IPTC/MakerNote/thumbnail removal and pixel re-encode), PDF (drop `/Info`, XMP, incremental updates, JavaScript, embedded files, annotations; linearize) and OOXML/ODF (docProps, custom XML, comments, revisions and rsids, via rebuild). After cleaning, the file is re-scanned and the remaining findings are shown. The app labels cleaning as **best-effort**: "Cleaning removes known hidden data. It can't remove watermarks, unique wording, or printer dots" [B-CR-53 threat model; B-SD-23].

**8.5 Identity-hint check at Review.** Before rendering S08, the Review renderer scans only the source's own typed text fields (not files):
- email addresses (RFC 5322 simplified);
- phone numbers (E.164 plus common national formats, ≥ 7 digits);
- URLs with user-like path segments;
- `@handles`;
- channel-configured patterns (for example employee-ID regex `^[A-Z]{2}\d{6}$`);
- first-person identity phrases (localized list, for example "my name is", "I am the only", "my manager told me");
- sign-off lines (a line of 1–3 capitalized words at the end of the text).

Matches are shown as a **non-blocking** notice: "Your text may contain details that point to you: an email address in 'What happened', line 3. [Edit] [Keep as is]." Tier W runs the check in C-07 RAM. Results exist only in the rendered response. They are never stored, logged, counted, or sent to recipients. Tier V runs it locally.

**8.6 Writing-style checklist.** S08 shows a static checklist (GC-31). Tier V MAY add deterministic local highlights: emoji, greeting/sign-off lines, repeated distinctive punctuation (for example "!!", "..."), and the text's top 5 rare words relative to a bundled frequency list. No ML model and no network are used. It is labelled "a reminder, not a protection" [B-AN-35, B-AN-39].

**8.7 "How many people know" question.** The default questionnaire includes an optional question: "About how many people could know the facts in your report? ○ 1–5 ○ 6–20 ○ more than 20 ○ not sure". Its help text is: "This helps the team avoid actions that could point to you." `12-FRONTEND-RECIPIENT.md` surfaces the answer in the case risk panel.

**8.8 Passphrase handling.** S10 shows the passphrase once. It offers no download, no print button, no email, and no QR code. Text is selectable, so copying is allowed. There is no persistent storage (cookies are session-only; no Web Storage) [ADR-005; INC-05, INC-23].

**8.9 No persistence.** No "remember me", no persistent cookies, no `localStorage`/IndexedDB/Service Worker, `Cache-Control: no-store`. Logout and "Leave" send `Clear-Site-Data: "cache", "cookies", "storage"` [B-SD-02 2.13.0].

**8.10 Clearnet Information Site (C-37) Tor check.** C-37 MAY compare the connecting IP with the public Tor exit list **in memory, without logging**. It then shows either "You are not using Tor Browser. Don't report from this browser. Get Tor Browser" or the onion address with `Onion-Location` (ADR-003; R4 §7.1(3), Knowledge (unverified) of exit-list mechanics).

**8.11 Leave and clear.** Every source page has a "Leave" control (a form POST) that ends the session, sends `Clear-Site-Data`, and shows a neutral page with the GC-07 "New Identity" instruction. The neutral page has no external redirect (GP-7).

**8.12 Close mailbox.** After submission, the source can close the mailbox (S13). The passphrase then no longer authenticates, and replies are no longer served. The report stays with the case team, and the case team is told "the source closed the mailbox". This supports GC-35 and does not delete evidence.

## 9. Validation

| Check | Method | Pass criterion |
|---|---|---|
| Readability | CI job `sops-readability` computes Flesch-Kincaid grade on the EN master for each `sops.*.normal` and `sops.*.high` string | normal ≤ 8.0; high ≤ 10.0 (placeholders substituted with typical values) |
| Comprehension | Moderated study (`26-ACCESSIBILITY.md` §Testing). n ≥ 20 per major copy release, including ≥ 5 AT users, with scenario questions for key messages K1–K8 | ≥ 80 % correct per key message (REQ-H-16b) |
| Legal | Counsel review per jurisdiction pack | No advice that could constitute obstruction, unauthorized access, or evidence destruction |
| Accuracy | Security review per release: statements match actual behavior (03, 10, 11, 12) | Zero mismatches |
| Translation | `26-ACCESSIBILITY.md` critical-string review (2 reviewers + back-translation) | All `sec:critical` strings reviewed before the locale is enabled |

Key messages: **K1** don't use work devices or networks; **K2** use Tor Browser at Safest; **K3** Tor use is visible on a network; bridges help; **K4** files carry hidden data, so describe or retype; **K5** don't paste into AI, translators or grammar tools; **K6** the passphrase can't be recovered and must be kept safely; **K7** return rarely, the same careful way; **K8** the website cannot protect against a compromised device.

## 10. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| SOPS-001 | The Source UI SHALL include Guidance Cards GC-01..GC-38 with the §6 English master text as normative content. Wording changes SHALL pass the §9 accuracy and legal checks before release. | REQ-H-16b (INC-16); INC-31; B-SD-04 | THR-002, THR-009, THR-010, THR-048 | C-06, C-03 | INSP: content diff review per release; DEMO: §9 comprehension study |
| SOPS-002 | Guidance SHALL present NORMAL-RISK text by default and HIGH-RISK additions inside native `<details>` elements in the same HTML response. The track choice SHALL NOT be transmitted to or inferable by the server (no distinct URL, request, cookie or form field). | INC-03; ADR-003 | THR-001, THR-016 | C-06 | TST: e2e `sops-track-no-request` asserts identical request sequence whether or not `<details>` are opened |
| SOPS-003 | NORMAL-RISK English strings SHALL score Flesch-Kincaid grade ≤ 8.0 and HIGH-RISK strings ≤ 10.0, enforced in CI. | B-CO-36; REQ-H-16b | THR-040 | C-06, C-03 | TST: CI job `sops-readability` |
| SOPS-004 | The UI SHALL place guidance according to the §7 placement map, including the first-viewport "don't use a work device or work network" statement on S01. | REQ-H-31 (INC-31); REQ-H-16b | THR-002, THR-048 | C-06, C-03 | INSP: screen-by-screen checklist; TST: snapshot test for S01 first viewport at 320×568 and 1280×800 |
| SOPS-005 | The onion-served Source UI SHALL contain no hyperlinks to non-onion or third-party origins. Tool and site names SHALL be plain, non-clickable text. Only C-37 MAY hyperlink official Tor Project and Tails pages. | REQ-H-36 (INC-36); INC-46 | THR-006, THR-008, THR-036 | C-06, C-37 | TST: HTML lint `no-external-href` over all rendered templates |
| SOPS-006 | The UI SHALL warn when JavaScript is enabled using only the CSS `scripting` media feature (or the §8.2 fallback), with no script and no conditional resource load. | REQ-H-27 (INC-27); B-SD-15 | THR-008, THR-006 | C-06 | TST: Tor Browser e2e at Standard and Safest: warning visible or hidden; request log identical |
| SOPS-007 | S01, S02 and S03 SHALL display GC-01, including the ADR-004 Tier W statement when served in Tier W and the ADR-013 escrow statement generated from the signed key directory state. | ADR-004; ADR-013; B-GL-09 | THR-007, THR-014, THR-040 | C-06, C-03, C-14 | TST: render tests with escrow on and off; INSP: text matches ADR-004 wording |
| SOPS-008 | GC-01 and GC-38 statements about what the operator can see SHALL match the compelled-disclosure inventory in `03-PRIVACY-ANONYMITY.md`. | REQ-H-06, REQ-H-12 (INC-06, INC-12) | THR-026, THR-040 | C-06 | INSP: per-release cross-check signed by the privacy lead |
| SOPS-009 | All guidance SHALL be reachable before any session exists or any data is entered, served as static pages in the same response size classes as other source pages (`11-FRONTEND-SOURCE.md`). | B-AN-15, B-AN-16 | THR-004 | C-06 | TST: size-class test over all guidance routes |
| SOPS-010 | The Source UI SHALL recommend bridges (GC-10) and Connection Assist (GC-11) and SHALL state that bridges do not make work devices safe. | REQ-H-31; B-AN-30, B-AN-31 | THR-002 | C-06, C-37 | INSP: copy review |
| SOPS-011 | When the onion service or intake is unavailable, no page, notice or C-37 content SHALL offer an alternative anonymous address or a clearnet form. GC-11 wording SHALL be shown on C-37 status. | ADR-002; INC-03 | THR-040, THR-001 | C-37, C-06 | TST: outage drill: C-37 shows status text only; lint forbids forms on C-37 |
| SOPS-012 | Long-text fields (S05, S12) SHALL display the GC-16 short warning ("Don't paste into AI tools, translators or grammar checkers") adjacent to the field and programmatically associated with it (`aria-describedby`). | R4 §2.2 stylometry row (B-AN-37, B-AN-38) | THR-010, THR-029 | C-06, C-03 | TST: a11y tree assertion; INSP |
| SOPS-013 | No source-facing component SHALL send source-entered text to any remote service other than the Candor intake (no remote spellcheck, translation, AI or grammar service). Tier V apps SHALL disable OS cloud text services for their input fields where the platform permits. | INC-13; INC-53; B-AN-35 | THR-036, THR-010 | C-03, C-06 | TST: network sandbox test (no egress except onion); INSP: platform flags |
| SOPS-014 | Filename neutralization (§8.3) SHALL be ON by default. The original filename SHALL be sealed only if the source opts out, and SHALL never be logged. | INC-17; INC-18; ADR-027 | THR-009, THR-016 | C-07, C-03 | TST: upload `JSmith_notes.docx`; decrypt in test recipient: name `file-01.docx`; log grep for "JSmith" = 0 |
| SOPS-015 | S07 Metadata Warning SHALL be shown whenever ≥ 1 file is attached, with the §7.2 class-specific lines. The source SHALL actively choose "Continue with these files" or "Change files". | REQ-H-17 (INC-17), REQ-H-20 (INC-20) | THR-009 | C-06, C-03 | TST: flow test cannot reach S08 with files without passing S07 |
| SOPS-016 | Tier V SHALL analyze attachments locally (sandboxed, no network), list findings, and offer "Clean (recommended)", "Send original" or "Remove". Cleaning SHALL cover the §8.4 formats. Findings after cleaning SHALL be shown. The label SHALL state best-effort limits. | REQ-H-20; B-CR-53; B-SD-23 | THR-009 | C-03, C-11 | TST: canary corpus (GPS, author, comments, revisions, XMP, incremental PDF) → 0 canaries after clean; DEMO |
| SOPS-017 | Tier W SHALL state that no cleaning occurs before encryption and that recipients view a cleaned copy while the original is retained (GC-22 `tier_clean_statement`). | ADR-012; ADR-004 | THR-009, THR-040 | C-06 | INSP: copy review against `10-FILE-EVIDENCE-PIPELINE.md` |
| SOPS-018 | The Review screen SHALL run the §8.5 identity-hint check on source-typed text and show non-blocking notices. Results SHALL NOT be stored, logged, counted or transmitted to recipients. | INC-32; REQ-H-05; INC-73 | THR-010, THR-016 | C-07, C-03 | TST: canary email in text → notice rendered; log/DB grep = 0; recipient envelope contains no hint flag |
| SOPS-019 | The Review screen SHALL show the GC-31 style checklist. Tier V local highlights (§8.6) SHALL use deterministic rules only, with no ML model and no network. | B-AN-34..40; REQ-H-73 | THR-010 | C-06, C-03 | INSP: code review; TST: network sandbox |
| SOPS-020 | The default questionnaire template SHALL include the optional §8.7 "how many people know" question. | INC-16; INC-10 | THR-010, THR-019 | C-06, C-10 | TST: template fixture; INSP |
| SOPS-021 | Questionnaires for ANONYMOUS mode SHALL NOT contain fields of type name, email, phone, employee number or address. The builder SHALL reject them. Identity can only be provided via the explicit identity-disclosure step (ADR-014). | REQ-H-05 (INC-05); ADR-002 | THR-040, THR-034 | C-06, C-19 | TST: builder API rejects identity field types for anonymous channels; fuzz submit email in every field → none persisted outside sealed envelope |
| SOPS-022 | S10 SHALL present the passphrase with GC-32 text and SHALL NOT offer download, print, email, QR or any storage mechanism. | ADR-005; INC-23; INC-05 | THR-034, THR-048 | C-06, C-03 | TST: DOM contains no download/print controls; forensic diff (30) shows no passphrase on disk after flow |
| SOPS-023 | The Source UI SHALL NOT use persistent cookies, Web Storage, IndexedDB, Cache API or Service Workers, and SHALL send `Clear-Site-Data: "cache", "cookies", "storage"` on logout, Leave, submit completion and mailbox close. | REQ-H-23 (INC-23); B-SD-02 | THR-048, THR-006 | C-06 | TST: header assertions; forensic-residue suite (30) in Tor Browser and Tails |
| SOPS-024 | Every source page SHALL offer the §8.11 "Leave" control. The resulting page SHALL instruct "New Identity" and SHALL NOT redirect to any external site. | GC-07; REQ-H-36; INC-36 | THR-048 | C-06 | TST: e2e; header test |
| SOPS-025 | C-37 MAY check the connecting IP against the Tor exit list only in memory, and SHALL NOT log, store or count that result. | ADR-003 | THR-001, THR-016 | C-37 | TST: log grep after 1,000 requests; INSP config |
| SOPS-026 | C-37 SHALL publish the onion address, an `Onion-Location` header, a signed copy of the onion address, and GC-01..GC-11, with signature-verification instructions for Tor Browser and Tails downloads. | REQ-H-52 (INC-52); ADR-003 | THR-044, THR-002 | C-37 | INSP; TST: header check |
| SOPS-027 | No guidance SHALL advise destroying evidence, disabling or evading monitoring, or accessing information without authorization. Guidance SHALL include GC-03 on S01, S02 and S13. | GP-6; INC-23; B-CO-02 | THR-040 | C-06 | INSP: counsel review per jurisdiction pack (25) |
| SOPS-028 | Deployments MAY add jurisdiction text via placeholders and MAY add cards, but SHALL NOT remove or edit GC-01..GC-38 core text. The admin UI SHALL enforce this. | ADR-020 edition charter; B-GL-09 | THR-035 | C-19, C-06 | TST: admin API rejects edits to `sops.*` core keys |
| SOPS-029 | Guidance pages SHALL contain no feedback widgets, counters, ratings or analytics. | ADR-023; INC-53 | THR-036 | C-06 | TST: template lint; network capture |
| SOPS-030 | Before any major release that changes K1–K8 copy, a comprehension study (§9) SHALL show ≥ 80 % correct per key message, including AT-user participants. | REQ-H-16b; INC-16 | THR-040, THR-002 | C-06 | DEMO: study report archived in release evidence |
| SOPS-031 | GC-33 and S11 SHALL state that replies show the date only and appear only when the source logs in. The UI SHALL NOT display exact times, "last login", "unread since" or presence information. | ADR-010; INC-35; B-AN-21 | THR-011, THR-003 | C-06, C-03 | TST: render tests; DB schema check for last-seen fields = none |
| SOPS-032 | The Source UI SHALL provide "Close mailbox" (§8.12) with GC-35 text, and SHALL state that closing does not delete the report. | GC-35; INC-23 | THR-034 | C-06, C-07, C-10 | TST: after close, login with the passphrase fails with a generic message; recipient sees the "mailbox closed" event |
| SOPS-033 | GC-36 SHALL be displayed on S12. Recipient-side reply composition SHALL warn on side-channel invitations (`12-FRONTEND-RECIPIENT.md`). | REQ-H-21 (INC-21); INC-24 | THR-019, THR-028 | C-06, C-15 | INSP; TST: RUI warning test |
| SOPS-034 | GC-38 SHALL state the trade-off that an installed Source App is discoverable on a searched device, and the Tier V web bundle SHALL be presented only when a WEBCAT-capable browser verifies it. The page itself SHALL never claim to be verified. | ADR-004; B-CR-37, B-CR-38; B-SD-12 | THR-007, THR-048 | C-06, C-03 | INSP; TST: no "verified" badge string in C-06 templates |
| SOPS-035 | Tier W pages SHALL NOT instruct or require sources to lower Tor Browser's security level for any feature. | REQ-H-27; ADR-004 | THR-008 | C-06 | INSP: copy lint for "Safer"/"Standard" instructions outside GC-07 |
| SOPS-036 | The Source UI SHALL be fully usable in Tails' bundled Tor Browser at Safest, including with the Orca screen reader. | REQ-H-23; B-SD-02 (Orca fixes) | THR-048 | C-06 | TST: CI e2e in Tails image; DEMO: Orca walkthrough per release |
| SOPS-037 | GC-06 SHALL state that Onion Browser on iOS gives weaker protection. The UI SHALL NOT fingerprint or block any browser (ADR-003). | R4 §3.3 (Knowledge (unverified) Onion Browser status); ADR-003 | THR-006 | C-06 | INSP; TST: no UA-dependent rendering (diff responses across UAs = identical) |
| SOPS-038 | Guidance on canary traps, watermarks and printer dots (GC-25..GC-27) SHALL appear on S07 for the relevant file classes and in S02. | B-AN-41, B-AN-42; B-CR-54; INC-16 | THR-010 | C-06, C-03 | INSP; TST: S07 rendering per class |
| SOPS-039 | Security-critical guidance (`sops.*`) SHALL only be shown in a language whose `sec:critical` strings passed review (`26-ACCESSIBILITY.md`). Otherwise the default language version SHALL be shown with a notice. | B-SD-02 (Weblate) | THR-040 | C-06 | TST: locale gate test |
| SOPS-040 | Timing statements (GC-34) SHALL be consistent with ADR-010. Any change to stored timing granularity SHALL trigger review of GC-34 and GC-01. | ADR-010; INC-16 | THR-011 | C-06 | INSP: release checklist item |
| SOPS-041 | Recipient-facing tools SHALL NOT offer authorship attribution, stylometric similarity or metadata-based cross-report linking. This backs the GC-31 promise. | REQ-H-08; INC-73 | THR-010, THR-019 | C-15 | INSP: feature review; see `12-FRONTEND-RECIPIENT.md` |
| SOPS-042 | The Source UI SHALL provide the Safety Check essentials (§7.1) as a non-interactive list with no data collection. | GP-1, GP-5; INC-03 | THR-016 | C-06 | TST: S02 contains no `<input>` except navigation |
| SOPS-043 | Guidance card string keys SHALL be versioned. Each release SHALL publish a changelog of `sops.*` changes for translators and auditors. | B-SD-02 | THR-040 | C-06 | INSP: release artifact present |
| SOPS-044 | Clearnet-intake deployments (C-38) SHALL show a reduced guidance set that begins with "This form is NOT ANONYMOUS" and links the onion option where the channel offers one. | ADR-002 | THR-040 | C-38 | TST: C-38 template check; INSP |
| SOPS-045 | GC-01 (with S03) SHALL implement the ASM-112 page "What protects you and what does not", covering in plain language the source-facing consequences of ASM-001, ASM-004..ASM-011 and ASM-013 (Tier W), and SHALL be re-reviewed whenever those assumptions change. | ASM-112; ADR-004 | THR-040 | C-06, C-03 | INSP: per-release mapping table (assumption → sentence) signed by the privacy lead |
| SOPS-046 | GC-01 SHALL state that sources can keep people their report concerns from receiving any key (ADR-030 checklist), and that if no one eligible is left, they will be pointed to an independent channel. | ADR-030; INC-22 | THR-020, THR-040 | C-06 | INSP: copy review |

## 11. Residual risks and limitations

1. **Guidance is not enforcement.** Candor cannot detect a managed device, a work network, a printer log, or pasted AI text. A source who ignores guidance may be identified by the employer (THR-002, THR-048). The UI cannot and must not probe the device (ADR-003).
2. **Small candidate sets defeat anonymity.** If only 2–5 people know a fact or had a document, content alone may identify the source whatever the network protection (INC-10, INC-16). The guidance reduces this but cannot remove it.
3. **Tier W has no pre-encryption cleaning.** Originals with metadata reach recipients, who may belong to the reported-on organization. The protection is access control on the original plus the sanitized-derivative default (10). A malicious recipient with original access can read metadata (THR-019).
4. **Stylometry** against an employer's full email corpus with LLM tools is practical [B-AN-37, B-AN-38]. Simple advice ("be plain") is of limited, author-dependent effectiveness [B-AN-39].
5. **Website fingerprinting** of our single portal by the employer or ISP can give an investigative lead even with correct guidance (B-AN-16). Bridges and page uniformity reduce this but do not eliminate it.
6. **Camera sensor fingerprints (PRNU), content watermarks, canary variants and printer dots** survive metadata cleaning (B-CR-53 threat model; B-CR-54).
7. **Comprehension varies** with language, stress and literacy. The 80 % target means some readers still misunderstand.
8. **The `scripting` media query** may be unsupported or spoofed in some browser versions (§8.2 fallback).
9. **Tails, bridges and Onion Browser** status and UI labels change over time. Card text that names UI elements ("shield icon", "Connection Assist") needs per-release verification (Knowledge (unverified) for current Tor Browser menu labels).
10. **Close mailbox after seizure** may have legal implications in some jurisdictions. The copy defers to legal advice.

## 12. Open issues

- **OI-05-1:** (Resolved) The protection statement now cites P-02, P-16, P-19, P-23 and ASM-004, ASM-007..ASM-011.
- **OI-05-2:** Validate the Flesch-Kincaid thresholds against real translated text. Grade metrics do not transfer across languages (see `26-ACCESSIBILITY.md` I18N rules).
- **OI-05-3:** Decide whether Tier V should offer **optional local LLM paraphrasing** (an on-device model, no network). The evidence is bimodal [B-AN-39]. Model size and trust issues apply. Currently excluded (SOPS-019).
- **OI-05-4:** Research whether a CoverDrop-style cover-traffic channel (R4 §6; B-GL-22) could remove "Tor use is a signal" for employer networks in EE deployments (R-COVER-01, R2 §10).
- **OI-05-5:** Localized passphrase wordlists (see `26-ACCESSIBILITY.md` Open issues; ADR-005 fixes the EFF English list). GC-32 usability for non-English speakers is a concern.

### Open Issues for ADR revision
- **ADR-012 vs REQ-H-17 (Tier W cleaning):** REQ-H-17 asks that sources be *offered* automatic metadata removal. ADR-012 forbids server-side parsing, so Tier W sources cannot be offered cleaning before encryption. This document conforms (SOPS-017 honest statement; Tier V cleaning in SOPS-016). A possible ADR amendment: an **optional, source-initiated, sandboxed cleaning step inside C-07** (a microVM with no network, output re-sealed, original discarded at the source's choice). Cost: server-side parser attack surface in Z-INTAKE, and Tier W plaintext exposure widens from "sealing" to "parsing". Recommendation: keep ADR-012 as is and invest in Tier V adoption.
