# 11a — Source Safety Tips on Every Screen
Status: Draft v0.1 (2026-10-01) · Edition applicability: both (Trust Path, AGPL, ADR-020) · Owner: Source Experience team (with Security Architecture) · Component: C-06 (Tier W); C-03 follows the same table in Tier V · Requirement prefix: `TIP-` (to be registered in DECISIONS §3)

## 1. Purpose and scope

Owner request: "create tips on how not to be identified into every aspect of the GUI for the whistleblower".

This document places short, practical safety tips on **every** source screen of `11-FRONTEND-SOURCE.md` (S01–S13, S04b, S04b‑X, S05b, S10/S10c/S10s, S11 login and inbox, S11r, S12, S13 variants, Leave, S90–S94, 405) plus one new help page, **S02b "Safety tips for each step"**.

For each screen it states the identification risks present **at that moment**, and one to three tips. Each tip has two parts:
- a **NORMAL** tip: always visible, ≤ 25 words, grade 6–8 reading level, action first, calm;
- a **HIGHER-RISK** detail: inside a native `<details>` element, ≤ 80 words, grade ≤ 10.

Ownership:
- Guidance **content** is owned by `05-SOURCE-OPSEC.md` (cards GC-01..GC-43). Tips are short, just-in-time restatements of that content (05 GP-4) and SHALL NOT contradict it. When a GC text changes, the matching tip is reviewed (TIP-012).
- Rendering, page contract, size classes and anti-dark-patterns are owned by `11-FRONTEND-SOURCE.md`. This document adds a region to the 11 §5.1 page template and one GET route.
- Plain language and COGA rules come from `26-ACCESSIBILITY.md`.

Out of scope: Tier V local findings (05 §8.4); C-37 info site layout (05 §7 already places GC cards there).

## 2. How sources were actually identified (evidence summary)

The tips target the vectors that identified real sources, not the ones that are easiest to explain. Network de-anonymisation of Tor itself is rare in the record; behaviour, documents and logs dominate (R4 "User behavior correlation: PRACTICAL, dominant real-world vector").

| Vector | What happened | Evidence | Threats |
|---|---|---|---|
| Access and print logs | Investigators listed the few people who printed a document, then checked who had contact with the outlet. | INC-16 (Reality Winner); B-AN-43 | THR-010, THR-011 |
| Printer tracking dots | Microdots on a scanned printout gave printer serial and print time. | INC-16; B-AN-41, B-AN-42 | THR-010 |
| Document metadata | Author/user names, revision history, disk labels. | INC-17 (BTK), INC-18 ("dodgy dossier"), INC-19 (overlay redaction) | THR-009 |
| Photo metadata and background | EXIF GPS placed a person; background and angle identify places. | INC-20 (McAfee); INC-74 (Strava, UNVERIFIED) | THR-009 |
| Unique copies / watermarks | Per-recipient variants identify whose copy leaked. | R4 "Document fingerprinting / canary traps" (PRACTICAL) | THR-010 |
| Writing style | Stylometry and LLM attribution match text to known authors. | INC-73 (UNVERIFIED); B-AN-34, B-AN-35, B-AN-36, B-AN-37, B-AN-38 | THR-010 |
| Timing and network visibility | Only Tor user on a campus network at the time of the event. | INC-31 (Eldo Kim); INC-35 (BKA Ricochet timing); B-AN-06; B-AN-21, B-AN-22 | THR-002, THR-003, THR-011 |
| Employer hunts | Senior management tried to unmask a whistleblower using internal resources. | INC-22 (Barclays), INC-23 (Boyle), INC-26 (HP pretexting, UNVERIFIED) | THR-019, THR-020 |
| Talking about it | Source confided in a contact who reported him; emails to a journalist were obtained. | INC-21 (Manning/Lamo), INC-24 (Kiriakou), INC-25 (AP call records, UNVERIFIED) | THR-019, THR-028 |
| Accounts and linking | Logged-in identities and reused accounts tied anonymous activity to a person. | INC-32 (Ulbricht); INC-05 (recovery e-mail); INC-03 (IP logs at provider) | THR-001, THR-006 |
| Browser exploits / JavaScript | NITs relied on JavaScript in Tor Browser. | INC-27, INC-28, INC-36 | THR-008 |
| Device seizure | Notes, codenames and history on seized devices. | 05 GC-35; THR-048 | THR-034, THR-048 |
| Compelled or compromised server | Providers compelled to log or modify service. | INC-01 (Hushmail), INC-02 (Lavabit), INC-04 (Tutanota); ADR-035(5) | THR-007, THR-014, THR-026 |

### 2.1 Current public guidance checked (2026-10-01)

| Source | What it says (relevant to tips) | Status |
|---|---|---|
| SecureDrop, *SecureDrop for Sources* — `https://docs.securedrop.org/en/stable/source.html` | Never use a work computer or a personal computer on a work network; a public Wi-Fi place and a computer you own are preferred; timing of Tor use can be correlated with a leak. | Verified via search result summary 2026-10-01 |
| Tor Project, *Tor Browser manual: Bridges* — `https://tb-manual.torproject.org/bridges/`; manual issue tpo/web/manual#181 | Bridges and pluggable transports **help conceal** Tor use but do not hide that a private channel is used from a party monitoring your network. Tips therefore say "harder to spot, not fully hidden". | Verified via search result summary 2026-10-01 |
| Freedom of the Press Foundation, *Metadata 101* — `https://freedom.press/digisec/blog/metadata-101/` | Printers add tracking dots; recreate documents by retyping or summarising; remove metadata before sharing. | Verified via search result summary 2026-10-01 |
| EFF, *Surveillance Self-Defense* — `https://ssd.eff.org/` | Tor Browser for anonymity; threat-model-first approach. | UNVERIFIED (current page text not retrieved; only secondary references found) |

These URLs appear **only in this document**. They SHALL NOT appear as clickable links in the onion UI (05 GP-7, SUI-006).

## 3. Tip catalog (normative English master)

Catalog file: `crates/candor-source-ui/locales/en/tips.ftl`; keys `tip-<topic>-title`, `tip-<topic>-n` (NORMAL), `tip-<topic>-h` (HIGHER-RISK). All are `sec:critical`; `tip-limits-h` is `tier0`.

| Topic | GC source | NORMAL (always visible) | HIGHER-RISK (`<details>`) |
|---|---|---|---|
| limits | GC-01, GC-38; ADR-035(5) | No tool can hide you completely. This site cannot hide what your files and words reveal, or what a watched device sees. | On this website version, someone who takes over or legally forces the server while you use it could capture what you type and your passphrase. For the highest risk, use the Candor Source App, downloaded over Tor, ideally on Tails. |
| device | GC-04, GC-05, GC-41 | Use your own computer, not one from work. Work devices can record what you type and which sites you open. | Use a computer that has never been used for work or joined to a work account, or start it from Tails on a new USB stick. Phones are harder to keep private because they record location and app use. If you only have a phone, use Tor Browser for Android at Safest and close it when you finish. |
| network | GC-09, GC-10 | Don't use a work or school network. Whoever runs a network can see that you use Tor, and when. | A bridge in Tor Browser makes Tor harder to spot, but it does not fully hide it. Use a network that is not linked to your name, and don't use the same one every time. On public Wi-Fi, sit away from cameras and other screens, and leave your phone at home so its location history does not place you there. |
| browser | GC-06, GC-07 | Use Tor Browser set to Safest. A VPN or a "private window" in another browser does not protect you in the same way. | Get Tor Browser only from the Tor Project, over Tor if you can, and check its signature. If a yellow JavaScript warning shows on this page, set the security level to Safest before you go on. When you finish, choose New Identity and close the browser. |
| place | GC-12 | Make sure no one can see your screen. Think about people behind you, windows and cameras. | Places can be checked against camera footage, card payments and phone location records. Switch off or leave your phone before you set out, not when you arrive. Pay cash, and don't keep going back to the same place. Pick times that fit your normal routine. |
| accounts | GC-13, GC-14 | Don't log in to email, social media or any other account while you use this site. | Logging in links what you do to you. Don't look up the people or the subject of your report from work or personal accounts around the time you report. If you need to look something up, do it in Tor Browser without logging in, and not only right before you send. |
| timing | GC-34; ADR-038(4) | Don't send right after you open, copy or print documents. Systems often record who looked at what, and when. | Investigations often start with a list of who opened a file and then look at who did something unusual soon after. Wait days or weeks if you safely can, and don't send right after a meeting or a news story. On the review step you can choose to deliver your report after a random delay of 1 to 3 days. |
| files | GC-22..GC-26 | Describe or retype what you know when you can. Original files can carry hidden names, dates and device details. | A document may be a unique copy made for only a few people. Small changes in wording, spacing or hidden marks can show whose copy it was. Send only what many people had, or describe it in your own words. Never send something only you could open. |
| metadata | GC-22, GC-23, GC-24, GC-29; 05 §8.3 | Photos and documents can hide author names, places and the camera or computer used. File names are replaced by default. | Cleaning does not remove everything. A camera leaves its own pattern in every photo, and the background, a reflection or a user name on a screen can point to you. Office files can keep tracked changes and old versions. Keep originals out of cloud folders and synced phones. |
| print | GC-20, GC-27, GC-28 | Don't print documents to send them. Printers keep records, and many add tiny tracking dots to each page. | A printed page, or a scan of it, can show which printer made it, and print servers log who printed what. A US contractor was identified this way in 2017. Screenshots and photos of a work screen can show your name, your windows or the time. |
| writing | GC-30 | Write only what is needed. Leave out details that only you, or a few people, would know. | For each fact, ask who else knew it, and when. If fewer than five people knew it, leave it out or make it less exact. Meetings you attended, your role and words said only to you can all point to you. |
| style | GC-31 | Write in short, plain sentences. Your usual words, spelling and greetings can be matched to emails you wrote at work. | Computer tools can compare writing across many people. Avoid your favorite phrases, usual mistakes, emojis and sign-offs. Don't copy text from your own work messages. |
| ai | GC-16 | Don't paste your report into AI tools, translators or grammar checkers. They can keep what you type. | Online writing tools often keep text and link it to your account, device or network. Spell-check add-ons may send text too. Type your report here, in Tor Browser. If you write a draft first, do it on a device you control, never a work device. |
| mode | ADR-002, ADR-047(5); ADP-01 | Anonymous is the default. Share who you are only if you choose to. You can still send a report without it. | In Confidential mode your name is sealed, but the custodians named on this site can open it. If you give contact details, use ones that are not linked to work or to your usual accounts. |
| concerns | GC-40; ADR-037 | Who you name, or tick here, can hint at where you work. Tick only what you need. | If only a few people work with the person you tick, your choice narrows down who you might be. The triage team sees your ticks. Name only the roles you need kept away from your report. |
| passphrase | GC-32 | Keep your passphrase in your head, or on paper hidden at home. Never in work email, notes apps or cloud storage. | Learn it by heart, then destroy the paper. A password manager is fine only if it does not sync online. Anyone with your passphrase can read your replies and write as you. Never type it into any other site, and the team will never ask for it. |
| return | GC-33 | Check for replies every few days at most. Take the same care each time: own device, Tor Browser, no work network. | The days you visit could be compared with who used Tor on those days. Visit rarely, from different networks, and never right after an event linked to your report. Put everything into one message rather than many. |
| conversation | GC-36 | Reply only here. Don't move to email, phone or chat, even if someone asks you to. | A message asking you to use another channel, or asking for your passphrase, may be fake. Calls, emails and meetings leave records that can be linked to you. If you must meet, get legal advice first. |
| after | GC-37; INC-21, INC-24 | Act as you normally would. Don't tell anyone, including coworkers, and don't hint that you know about a report. | Don't search for news of your report from work devices or accounts you log in to. People who show unusual interest can be noticed. If you are questioned, you can ask to speak to a lawyer first. Keep notes about your report off work systems. |
| seizure | GC-35; GC-03 | Don't keep notes, drafts, downloads or bookmarks about your report on devices other people can check. | A checked device can show Tor Browser, downloads and recent files. Tails keeps nothing after shutdown unless you set it to. Don't destroy anything you may be legally required to keep. Get legal advice if you are under investigation. |
| leave | GC-07, GC-17 | When you finish, choose New Identity in Tor Browser, then close it. | Also check your Downloads folder and any notes you made. On a shared computer, make sure no one sees Tor Browser open and that it is not set to start on its own. |
| errors | 11 §5.9; ADR-002 | If something goes wrong, don't retry many times in a row. Come back later, with the same care. | Many attempts in a short time can stand out on a network. Close Tor Browser and try again another day if you need to. Never switch to a work device, a normal browser or a non-Tor link to make it work. |

"Destroy the paper" (passphrase) and "remove notes" refer only to the source's own credential and drafts; the seizure tip states explicitly not to destroy anything the source may be legally required to keep (05 GP-6).

## 4. Per-screen placement: risks at that moment and tips shown

Tips are a static function of the screen (TIP-011). The order is the display order.

| Screen | Identification risks at this moment | Tips |
|---|---|---|
| S01 Landing | First contact: work device or network, Tor visibility, wrong browser, false belief in total anonymity | device, network, limits |
| S02 Safety Check | Reader is planning; the timing vector is the one most often missed by the essentials list | timing (NORMAL only) + link to S02b |
| S02b Safety tips | Reference page; visiting it must not reveal the track | all topics (§3) + limits |
| S03 Anonymity Status | Over-trust of displayed values; browser not at Safest; logged-in accounts in the same browser | limits, browser, accounts |
| S04 Create Report | Mode choice; being observed while typing | mode, place |
| S04b Concerns | Ticked roles narrow down the reporting line (GC-40) | concerns |
| S04b‑X No reader | Reporting about everyone who could read it; small-group inference; platform limits | concerns, limits |
| S05 Questionnaire | Few-people facts, stylometry, pasting into AI/translators | writing, style, ai |
| S05b‑1/2/3 Identity | Disclosure pressure; contact details linked to work | mode |
| S06 Attach Evidence | Metadata, unique copies, printouts/scans, screenshots, upload size | files, metadata, print |
| S07 Metadata Warning | File-class specific metadata; canary copies | metadata, files |
| S08 Review | Sending right after document access; delivery delay choice; few-people facts | timing, writing |
| S10 / S11r-2 Recovery Credential | Passphrase written into work or cloud storage; device seizure | passphrase, seizure |
| S10c / S11r-3 Confirm | Passphrase typed or stored elsewhere | passphrase |
| S10s Sent | Behaviour change, talking, searching for coverage, frequent checking | after, return |
| S11 login | Visit-day intersection; work network | return, network |
| S11 inbox | Frequent visits; behaviour after replies | return, after |
| S11r-1/4 Change passphrase | Old/new passphrase handling | passphrase |
| S12 Conversation | Side channels, impersonation, writing style in replies | conversation, style |
| S13 Discard / discarded | Drafts and notes left on device | seizure |
| S13 Close / closed | Device residue; behaviour after closing | seizure, after |
| S13 Ask to delete / requested | Behaviour after; device residue | after, seizure |
| Leave | Browser state left open | leave (no link) |
| S90 Busy, S91, S92, S93, 405 | Retry storms; temptation to fall back to unsafe paths | errors |
| S94 Signed out | Browser state; return-visit care | leave, return |

## 5. Rendering contract (Tier W)

1. **Region.** After the screen's own `<main>` content and before the session notes, C-06 renders `<aside class="box tips" aria-labelledby="tips-h">` with an `<h2>` "Staying safe on this page" and the screen's tips. The region follows the task content so it never sits between the `<h1>`/error summary and the form (26 COGA).
2. **Tip partial.** Each tip is `<div class="tip"><p>NORMAL</p><details><summary>If you are at higher risk</summary><p>HIGHER-RISK</p></details></div>`. No JavaScript; `<details>` state is never sent (05 §8.1).
3. **Link to S02b.** Every screen except S02b and Leave ends the region with a same-origin link "All safety tips, step by step" to `/{lang}/safety/tips`.
4. **S02 exception (ADR-051(2)).** S02 already holds every GC card and has about 1 KB headroom in `en-XA`. S02 shows NORMAL text only; details are on S02b.
5. **S02b.** Route `GET /{lang}/safety/tips`, no state, no query string, size class per 11 §5.4 (P1 without session cookie). It lists **every** tip with both tracks, so visiting it does not single out higher-risk readers (05 GP-1). Back link to S02.
6. **Links.** Only allow-listed same-origin routes. Tool names (Tor Browser, Tails) are plain text. No URLs, no clearnet hyperlinks (05 GP-7).

## 6. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| TIP-001 | Every Tier W screen (S01–S13 incl. S04b, S04b‑X, S05b, S11r, S13 variants, Leave, S90–S94, 405, S02b) SHALL render a tips region with 1–3 tips as placed in §4. | INC-16, INC-22, INC-31; R4 behaviour row | THR-002, THR-009, THR-010, THR-011 | C-06 | TST: `tips::every_screen_has_tips` (all screens × locales × modes × error state) |
| TIP-002 | Each tip SHALL show its NORMAL text always and its HIGHER-RISK text only inside a native `<details>`; the track SHALL NOT be sent, stored or inferred server-side. | 05 GP-1; INC-03 | THR-001, THR-016 | C-06 | TST: `tips::tip_structure`; template review |
| TIP-003 | NORMAL text SHALL be ≤ 25 words and HIGHER-RISK text ≤ 80 words (English master); readability target FK grade ≤ 8 NORMAL, ≤ 10 HIGHER-RISK (05 GP-9). | 26 COGA; 05 GP-9 | THR-040 | C-06 | TST: `tips::word_limits`, `tips::readability` (heuristic FK) |
| TIP-004 | Every page carrying tips SHALL stay within its 11 §5.4 size class in every shipped locale, including pseudo-locales; overflow SHALL fail the build, never truncate; S02 SHALL use the S02b link instead of inline details. | ADR-011, ADR-051(2) | THR-004 | C-06 | TST: `tips::budgets_all_locales`; `render::s02_budget_report` |
| TIP-005 | Tips SHALL contain no external or absolute URLs, no clickable clearnet links and no links except allow-listed same-origin routes; the Leave page tip SHALL contain no link. | 05 GP-7; INC-36 | THR-006, THR-036 | C-06 | TST: `tips::no_external_urls`; `render::no_script_handlers_external_urls_or_inline_styles` |
| TIP-006 | Tip strings SHALL live in Fluent catalogs tagged `sec:critical` (`tip-limits-h` `tier0`) and follow the 26 §12.2 review process. | 26 §12.2 | THR-040 | C-06 | TST: `tips::catalog_classes`; `render::every_screen_renders_for_every_locale` |
| TIP-007 | Tip wording SHALL be honest and bounded: no absolute claims ("guaranteed", "untraceable", "100%", "completely anonymous", etc.), no fear language or exclamation marks, no unlawful advice. | DECISIONS §0; 05 GP-2, GP-5, GP-6; INC-12 | THR-040 | C-06 | TST: `tips::honest_wording_lint` |
| TIP-008 | The tips region SHALL contain no form controls, no pre-ticked boxes, no feedback widgets and no counters. | 11 ADP-05, ADP-10; 05 GP-8 | THR-036, THR-039 | C-06 | TST: `tips::no_controls_in_tips` |
| TIP-009 | Every topic in §3 SHALL be placed on at least one screen besides S02b, and the topics SHALL cover device, network, browser, place, accounts, timing, files, metadata, printing/screens, content, style, AI tools, passphrase, return visits, conversation, after-sending behaviour, seizure, leaving, errors and platform limits. | §2 | THR-002, THR-009, THR-010, THR-011, THR-034, THR-048 | C-06 | TST: `tips::every_tip_is_placed` |
| TIP-010 | S02b SHALL be a stateless GET route listing every tip with both tracks and SHALL be reachable from every screen's tips region except Leave and S02b itself. | ADR-051(2); 05 GP-1 | THR-004 | C-06 | TST: `tips::s02b_lists_all`; route allow-list |
| TIP-011 | The tips on a screen SHALL depend only on the screen, never on mode, content, locale-specific logic or source input. | ADR-011 | THR-004, THR-011 | C-06 | TST: `tips::static_per_screen` (same tip keys across modes and error state) |
| TIP-012 | A change to a GC card text in 05 SHALL trigger review of the tips listed against it in §3, and tips SHALL NOT contradict 05. | 05 GP-4 | THR-040 | C-06 | Process: catalog review checklist |
| TIP-013 | The tips region SHALL be a labelled complementary landmark placed after the task content; `<details>` SHALL be keyboard operable with visible focus. | 26 A11Y; WCAG 2.2 1.3.1, 2.4.7 | THR-040 | C-06 | TST: `render::well_formed_and_structured`; manual AT pass |

## 7. Residual risks and limitations

- Tips are advice. They cannot stop a source who is already under targeted surveillance, who uses a monitored device, or whose content is unique to them (GC-01).
- S02b is a separate URL: a compelled C-06 operator could log that someone opened it. It lists both tracks, so it reveals interest in safety, not the track.
- The heuristic readability check approximates Flesch–Kincaid in English only; translations need human review (26 §12.2).
- Placement at the end of `<main>` means NORMAL tips may be below the first viewport on long forms. Critical moment-of-action warnings that 11 already places inline (S06 size honesty, S07, S10) are unchanged.
- Bridge advice is bounded: bridges make Tor use harder to spot but do not hide it from a party watching the network (Tor Project manual).

## 8. Open issues

- OI-11a-1: register `TIP-` prefix for `11a-SOURCE-SAFETY-TIPS` in DECISIONS §3 and add TIP-* to `39-REQUIREMENTS-TRACEABILITY.md`.
- OI-11a-2: add `GET /safety/tips` (S02b) to 11 §5.5 and 08 SW route list.
- OI-11a-3: Tier V (C-03) should show the same tips with local findings (05 §8.4).
