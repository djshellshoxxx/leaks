# AUDIT — RM-1 `candor-source-ui` and RM-0 repository infrastructure

- **Steps:** RM-1 (C-06 source web UI crate) and RM-0 (CI, scripts, supply-chain policy)
- **Audited commit:** `55f3356f1fc4544edef6398f8126731bbc1649b0`. No in-scope file differs from `60e732f` or from the working tree; out-of-scope working-tree edits were ignored.
- **Auditor:** independent security auditor (not the author), following `process/AUDIT-CHECKLIST.md` v1.0 and `research/R9-secure-code-audit.md`
- **Date:** 2026-10-01
- **Scope A (T1, source-facing):** `crates/candor-source-ui/` (src, templates, locales, `static/source.css`, tests, examples), plus the safety tips in `specs/11a-SOURCE-SAFETY-TIPS.md`
- **Scope B (T2, build/trust-path policy):** `.github/` (workflow, composite actions, dependabot, CODEOWNERS), `scripts/`, `Makefile`, `deny.toml`, `supply-chain/`, `.dco-epoch`, `clippy.toml`, `rustfmt.toml`, `rust-toolchain.toml`, `SECURITY.md`, `CONTRIBUTING.md`, `.gitignore`
- **Specs and ADRs used:** 11 §5.1–§5.9, §10, §13 (SUI-*); 11a (TIP-*); 05; 26; ADR-002/003/011/034/035/051(2); BUILD-BRIEF "Security and OPSEC bar"; IMPL-RM0 §4 and IMPL-RM1 §4; 28 §5–§8; 36 §4/§6
- **Time spent (approx.):** scope 10 %, threat model 10 %, manual review 55 %, tools and harness 20 %, report 5 %

## Summary

| Severity | Scope A (SUI) | Scope B (INF) | Total |
|---|---|---|---|
| Critical | 0 | 0 | 0 |
| High | 1 | 0 | 1 |
| Medium | 2 | 5 | 7 |
| Low | 5 | 3 | 8 |
| Info | 2 | 1 | 3 |

**Gate (§F): FAIL.** One High is open (AUD-RM1-SUI-01). Seven Mediums are open and each needs a fix or the lead's written acceptance. In addition, `cargo vet` and `cargo deny` fail on the audited commit (AUD-RM0-INF-01).

**Positive observations (verified, not assumed):**
- Every `|safe` in the templates (39 uses) goes through `escape`, `escape_marked`, `marked`, `text_html` or `block_html`. All five of these escape `& < > " '`.
- In marked messages, untrusted placeables have `*` shielded, so `<strong>` can only come from catalog text.
- Fluent bidi isolation is on.
- All attribute values are quoted. Ids and form values are allow-listed (`[a-z0-9_]{1,32}` and `[A-Za-z0-9_-]{1,64}`).
- There is no `<script>`, no event handlers, no `style=` attributes, no external URLs and no `url()`/`@import`/`@font-face`.
- The CSP and headers match 11 §5.3 byte for byte. Prohibited headers are absent.
- Padding is exact and fails closed (proptest covered).
- Sizes are rounded and dates are day-only.
- Tips are a static function of the screen.
- No logging, filesystem, network, env or clock access in `src/`.
- No panicking constructs. The audit clippy run reports only 8 `integer_division` warnings, all intentional (`size_parts`, `abs_warn_class`).
- In CI: `permissions: {}`, every job is `contents: read`, there is no `pull_request_target`, `persist-credentials: false`, there are no caches, every `github.event` value reaches `run:` blocks through `env`, and both external actions are SHA-pinned. I checked upstream that `3d3c42e…` = actions/checkout v7.0.1 and `043fb46…` = actions/upload-artifact v7.0.1.

## Tool runs (A4)

| Tool | Version | Command | Result / triage |
|---|---|---|---|
| clippy (deny set) | 1.94.1 | `cargo clippy -p candor-source-ui --all-targets --locked -- -D warnings` | clean |
| clippy (audit extras) | 1.94.1 | checklist §C extras list on `-p candor-source-ui` | 8× `integer_division`: false positives (intended rounding: `view.rs` `size_parts`, `abs_warn_class`) |
| tests | 1.94.1 | `cargo test -p candor-source-ui --locked` | 14 + 30 + 11 passed. The suites do not cover the worst-case escaped size (SUI-01) |
| audit harness | — | scratch crate (outside repo) rendering S08/S12/S05 at the spec input limits with escapable characters; header-size measurement | showed SUI-01; data for SUI-05 |
| zizmor | 1.26.1 | `zizmor --offline --persona=auditor .github` | "No findings". The online audits did not run (INF-07) |
| pin checker | in-repo | `sh scripts/check-actions-pinned.sh` | `pin-check: OK`. SHAs then checked online with `git ls-remote` |
| shellcheck | 0.9.0 | `shellcheck -S style scripts/*.sh` | 5× SC2317 in `repro-check.sh` `cleanup()`: false positive (called through `trap`) |
| cargo-deny | 0.20.2 | `cargo deny --offline --locked check advisories bans licenses sources` | **bans FAILED**: duplicate crypto-set `sha2` (0.10.9 via sqlx-core; 0.11.0). Advisories, licences and sources ok. 7 `multiple-versions` warnings and 5 `license-not-encountered` warnings (benign) → INF-01 |
| cargo-vet | 0.10.2 | `cargo vet --locked` | **FAILED: 101 unvetted crates** (sqlx, tokio, tracing, url, uuid, whoami, wasm-bindgen…) → INF-01 |
| cargo-audit | 0.22.1 | `cargo audit --db <advisory-db 9b3a3b7, 2026-09-30> --no-fetch --deny warnings` | 1,277 advisories, 300 crates, no findings |
| DCO script | in-repo | `sh scripts/check-dco.sh <root> HEAD` | 43 commits, all signed off. Logic weakness → INF-03 |
| secret scan | — | `git log -p --all \| grep` for key/token patterns | only synthetic test-fixture patterns (deploy tooling); no real secrets |

## Threat model (A2): attacker goals

| # | Attacker goal (adversary) | Outcome |
|---|---|---|
| G1 | Inject script/markup via source text, a team message, deployment labels or a filename (insider ADV, operator config) | Refuted: all sinks escaped; tests `hostile_content_is_escaped`, `arbitrary_text_is_inert`; |safe audit above |
| G2 | Make page size reveal secret state (has messages, long report, failed login) | Body: refuted (class depends only on method and cookie; exact padding). Header block: partially open → **SUI-05** (Low) |
| G3 | Stop the source from reviewing or sending a report, or lock them out of the mailbox, using in-spec input | **Finding SUI-01 (High)** |
| G4 | Exfiltrate the passphrase or plaintext through `Debug`, logs or heap residue | **SUI-02, SUI-03** (Medium) |
| G5 | Load an external resource or run JS, so the source is fingerprinted or deanonymised | Refuted: CSP `default-src 'none'`, sandbox without scripts, no sub-resources, tests `no_script_handlers_external_urls_or_inline_styles` |
| G6 | Mislead the source into unsafe behaviour through wording or tips | Tips are mostly sound. **SUI-07, SUI-08, SUI-10** (Low/Info) |
| G7 | Crash the renderer (panic = abort) with hostile view-model data | Refuted: no indexing/unwrap; checked arithmetic; catalog init fails closed |
| G8 | CSRF / login CSRF | Server-side (Origin + token). Crate-side gap → **SUI-06** (Low) |
| G9 | Run code with a write token or secrets from a fork PR | Refuted: `pull_request` only, read-only token, no secrets, no caches, no `GITHUB_ENV` writes from input |
| G10 | Poison a cache or artifact consumed by release | Refuted: no caches; artifacts are uploaded and never consumed |
| G11 | Merge unsigned (non-DCO) commits | **INF-03** (Medium) |
| G12 | Land code that fails supply-chain policy / bypass crypto review | **INF-01, INF-02, INF-05** |
| G13 | Make the reproducibility gate pass without comparing anything | **INF-04** |
| G14 | Escalate from the unprivileged test job | Refuted (INF-09 notes the residual risk) |

---

## Scope A — `candor-source-ui`

### AUD-RM1-SUI-01: Escaping expansion breaks the P2 budget within spec input limits (failed review/send; insider can lock a source out of the mailbox)
- **Severity:** High
- **Location:** `crates/candor-source-ui/src/page.rs:366-391` (`pad_html` budget), `src/lib.rs:157`; templates `s08_review.html:23`, `messages.html:7` (used by `s11_inbox.html` and `s12_conversation.html`), `s12_conversation.html:31`, `question.html:14,17`
- **Category:** B2.3 / B1.7 (CWE-400, availability on a source-facing path)
- **Description:** The size budget is checked on the *escaped* HTML: `pad_html` fails with `OverBudget` above 129,024 bytes for P2. The spec input limits are in *raw* bytes: report text ≤ 98,304 B; one message ≤ 64 KiB on an S12 page (11 §5.4 rule 2); long text 60,000 chars. Askama escaping grows `'` `"` `&` `<` `>` to 5–6 bytes each. Measured with the audit harness (sample view models, locale `en`):

  | Case (at the spec limit) | Unpadded | Result |
  |---|---|---|
  | S08, 98,304 B of plain text | 115,079 | OK |
  | S08, same length, **10 % `"`** | 154,395 | **OverBudget** |
  | S08, all `"` or `&` | 508,295 | **OverBudget** |
  | S12, one 64 KiB team message, all `&` | 342,573 | **OverBudget** |
  | S12, restored 60,000-char draft, all `"` | 314,414 | **OverBudget** |

  Ordinary English (apostrophes, quotation marks, "&") hits the 10 % case well before the 96 KiB limit. The test `max_content_fits_size_classes` covers only optional *deployment* text, never maximum source or team text.
- **Exploit scenario:**
  1. A source writes a long report with normal punctuation. S08 cannot render and C-06 answers with S92 ("Something went wrong… your draft is lost"). The source cannot review or send a report that the server accepted as within limits (fail-closed, but a loss of the core function and misleading text).
  2. A malicious or careless case-team member (insider ADV) sends one in-limit message made mostly of `&`/`<`. Every S11 inbox and S12 render for that mailbox then fails, so the source can never read replies again. A broken mailbox may push the source toward unsafe out-of-band contact, which the "conversation" tip warns against.
- **Fix recommendation:**
  - Make the budget content-aware where the content enters. C-07/C-06 should measure escaped length when enforcing per-field and per-report limits, and paginate S12 and the inbox by *rendered* size, not raw size.
  - Expose a `pub fn escaped_len(&str) -> usize` (or `fits(screen, vm)`) so callers can pre-check before rendering.
  - Option: escape only `&` and `<` in element content (quotes need escaping only in attributes), which cuts expansion for the most common characters.
  - Add regression tests: S08 at 98,304 B of `'`; S12 with a 65,536 B message of `&`; S12 draft at 60,000 `"`; S05 step at its maximum. All must render or paginate, never S92.
  - Spec feedback: 11 §5.4 rule 2 and §5.7 limits should be stated in rendered bytes.
- **Spec / requirement reference:** 11 §5.4 (P2, rule 2), §5.7 (input limits; "No POST error path may discard text"), SUI-005/SUI-069/SUI-078; BUILD-BRIEF "Fail closed" and "Input handling"
- **Status:** Open

### AUD-RM1-SUI-02: `#[derive(Debug)]` on view-model types that carry source plaintext, identity, filenames, team messages and the form token
- **Severity:** Medium
- **Location:** `crates/candor-source-ui/src/model.rs:318` (`PageContext`, includes `form_token`), `:539` (`IdentityData`: `full_name`, `contact_other_value`), `:554` (`AttachedFile.name`, `description`), `:580` (`ReviewAnswer.answer`), `:513` (`Question.value`), `:732` (`InboxMessage.text`), `:763` (`ConversationData.draft_text`), `:793` (`ViewModel`)
- **Category:** B1.3 / B3.1 (CWE-532, CWE-209)
- **Description:** `Passphrase` and `Page` have redacting `Debug` impls. Every other type that holds source-typed text, the identity block, original filenames or the CSRF token derives `Debug`. The crate does not print these values itself. But any `{:?}` in C-06/C-07 does: an error context, `panic!` payload, `assert!` message or future typed-log adapter would write the source's name or report text to the journal. The workspace lint `missing_debug_implementations = "warn"` pushes authors toward deriving.
- **Exploit scenario:** A later intake handler logs `"{vm:?}"` on a render error, or panics with it (panic = abort writes the message to stderr). The identity and plaintext then reach journald, which the operator or a seizing party (ADV-insider/legal) can read.
- **Fix recommendation:** Give every type carrying input-derived strings a hand-written `Debug` that prints lengths or `[redacted]`. Keep `derive(Debug)` only for enums and plain flags. Add a test that formats a maximal `ViewModel` with `{:?}` and asserts no sentinel string appears (SG-21).
- **Spec / requirement reference:** BUILD-BRIEF Metadata bullet; 27 §12.3; IMPL-RM1 §4
- **Status:** Open

### AUD-RM1-SUI-03: Passphrase and source text leave unzeroized heap copies during rendering
- **Severity:** Medium
- **Location:** `crates/candor-source-ui/src/lib.rs:145-147` (askama `render()` into a growing `String`, wrapped in `Zeroizing` only afterwards); `src/view.rs:786-789` (`spell()` returns a plain `String` of passphrase letters); `view.rs:18-31` (`escape` temporaries for custom text); `locale.rs:208-226` (Fluent results with untrusted args)
- **Category:** B3.2 (CWE-226/244)
- **Description:** Askama appends into a `String` whose capacity grows by reallocation. Each reallocation frees a buffer that still holds a prefix of the page: on S10 that includes the passphrase words, and on S05/S08/S12 it includes source text. Only the final buffer is zeroized. `spell()` builds a non-zeroizing `String` per word. `passphrase_line()` is correctly `Zeroizing`.
- **Exploit scenario:** After S10 is served, the C-06 process heap still holds stale passphrase fragments. A later memory-capture event (11 WB-2c "capture performed", or a compromise of the C-06 process) recovers a passphrase the spec says is "zeroized immediately after S10 is rendered" (11 §5.6).
- **Fix recommendation:** Render with `Template::render_into` into a `Zeroizing<String>` pre-reserved to `SizeClass::P2.bytes()`, so no reallocation happens, and fail closed on overflow. Make `spell()` write directly into the output, or return `Zeroizing<String>`. Document that C-06 must hold the view model in zeroizing storage.
- **Spec / requirement reference:** 11 §5.6 ("passphrase string zeroized immediately after S10 is rendered"); BUILD-BRIEF Secrets bullet; 27 §12.3
- **Status:** Open

### AUD-RM1-SUI-04: Pseudo-locales are compiled in and offered by default
- **Severity:** Low
- **Location:** `src/view.rs:338-343` (empty `offered_locales` ⇒ `Locale::ALL`), `src/locale.rs:84-87` (`from_tag` accepts `en-XA`/`ar-XB`/`en-XL`)
- **Category:** B5 hygiene (fail-open default)
- **Description:** `Locale::is_pseudo` says pseudo-locales must not be enabled in production (26 I18N-005). Yet the default language list shows all four, and `from_tag` resolves them, so the routing layer must remember to filter them out.
- **Exploit scenario:** A deployment that forgets `offered_locales` shows the RLO-wrapped and padded pseudo-locales to real sources. This harms trust and accessibility, and a source may give up on the site.
- **Fix recommendation:** Default to `[Locale::En]`. Put pseudo-locales behind a `pseudo-locales` cargo feature, or have `from_tag` reject them unless that feature is on. Add a test.
- **Spec / requirement reference:** 26 I18N-005; 11 SUI-041
- **Status:** Open

### AUD-RM1-SUI-05: Only the body is padded; the header block length varies by screen and locale
- **Severity:** Low
- **Location:** `src/page.rs:394-422` (`Clear-Site-Data` adds 48 bytes on S10s, Leave, S13 closed/discarded and S94; `Content-Language` length varies with the locale); session-layer `Set-Cookie` and the status reason phrase also vary
- **Category:** B1.7 (CWE-203)
- **Description:** Measured serialized header bytes: 1,073 (S08/S11/S90/S92), 1,121 (S10s/Leave/S94) and +3 for `en-XA`. With body 131,072 the total is 132,145–132,196 bytes. That is 266 RELAY cells in all measured cases, about 270 bytes below the next boundary. So no cell-count difference exists today, but nothing enforces this. A longer `Set-Cookie`, an extra header or a reason phrase could make "report sent" (S10s) one cell larger than other P2 responses.
- **Exploit scenario:** A network observer at the client or guard (ADV-network) counts cells per response and spots the submit-completion or leave response.
- **Fix recommendation:** Make the serialized header block a constant length per class, for example with a fixed-width padding header that C-06 fills last. Add a test that asserts constant serialized header length across all screens, locales and session states, including the session cookie.
- **Spec / requirement reference:** ADR-011; 11 §5.4 ("An observer therefore cannot tell from response size…"); SUI-005
- **Status:** Open

### AUD-RM1-SUI-06: Session-less forms carry no CSRF token; the field name diverges from spec 11
- **Severity:** Low
- **Location:** `templates/ft.html:2` (token omitted when `form_token` is `None`), used by `s11_login.html` (login POST), the footer Leave form and `s02_safety.html` Leave; `src/lib.rs:40` (`FORM_TOKEN_FIELD = "csrf"`, while 11 §5.7 names it `ft`)
- **Category:** B5.3 (CWE-352)
- **Description:** 11 §5.7 says "Every form carries a hidden `ft`". Login is a pre-session form, so it never has one. Login CSRF (a hostile page POSTs the attacker's passphrase to the victim's onion, putting the victim into the attacker's mailbox) is then blocked only by the server's `Origin` check.
- **Exploit scenario:** If C-07 ever relaxes the Origin check (for example, accepts a missing Origin), a third-party page can log a source into an attacker-controlled mailbox. The source's later messages and files then go to the attacker.
- **Fix recommendation:** Issue a pre-session token for S11 login (and Leave). If not, record in SPEC-NOTES that login relies on the Origin check and add a C-07 negative test (missing, foreign or `null` Origin → reject). Align the field name with specs 08 and 11.
- **Spec / requirement reference:** 11 §5.7; 08 SW-10
- **Status:** Open

### AUD-RM1-SUI-07: The copy-friendly passphrase field has no clipboard-history warning
- **Severity:** Low
- **Location:** `templates/s10_credential.html:24` (readonly `phrase_line` input, "All N words on one line, to copy")
- **Category:** accessibility vs OPSEC (THR-034/THR-048)
- **Description:** The page offers the passphrase on one line for copying (an accessibility aid, WCAG 3.3.8). Clipboard history and cloud clipboard sync (Windows clipboard sync, mobile keyboards) can keep or sync it off-device. That contradicts the GC-32 "passphrase" tip shown on the same page ("never in … cloud storage").
- **Fix recommendation:** Add a `sec:critical` sentence next to the field, for example: "If you copy it, some computers and phones keep or sync what you copy. Clear it afterwards." Mirror it in 05 GC-32.
- **Spec / requirement reference:** 05 GC-32; 11 S10; 11a TIP-012 (no contradiction)
- **Status:** Open

### AUD-RM1-SUI-08: Absolute anonymity statements in the S03/S04 copy
- **Severity:** Info (spec-sourced)
- **Location:** `locales/en/sui.ftl:228` (`sui-new-mode-anon-consequence` "We won't know who you are unless you tell us later."), `:170` (`sui-status-mode-anonymous` "we don't know who you are unless you tell us."), `:159` (`sui-status-connection-dd` "This site cannot see your internet address.")
- **Category:** honest-language rules (DECISIONS §0; 05 GP-2; 11a TIP-007)
- **Description:** Both "won't know who you are" lines contradict the mode banner ("Your writing and files can still identify you"). The connection line is a static server claim that is false when the site is reached through a Tor2web-style gateway. The wording matches 11 §7 S03/S04 exactly, so this is spec feedback rather than a crate defect.
- **Fix recommendation:** Spec owners: change to "Candor does not collect who you are. Your writing and files can still identify you." and "In Tor Browser, this site cannot see your internet address." Then update the catalog.
- **Status:** Open (spec feedback)

### AUD-RM1-SUI-09: Preview and sample data in the production library; unpadded length exposed
- **Severity:** Info
- **Location:** `src/lib.rs:18` (`pub mod preview`, sample view models including fixed sample passphrase words and fake onion addresses); `src/page.rs:326` (`Page::unpadded_len` is public)
- **Description:** Sample data is compiled into the production C-06 binary. `unpadded_len` is the true content size; if a consumer logs or exports it as a metric, it leaks length.
- **Fix recommendation:** Gate `preview` behind a cargo feature or `cfg(any(test, feature = "preview"))`. Document `unpadded_len` as CI-only, or make it `#[doc(hidden)]`/feature-gated.
- **Status:** Open

### AUD-RM1-SUI-10: Bidi override and spoofing content in team messages is not neutralised; one tip wording could mislead
- **Severity:** Low
- **Location:** `templates/messages.html:7` (`<p class="ut" dir="auto">{{ m.text }}</p>`); `locales/en/tips.ftl` (`tip-passphrase-h`, "A password manager is fine only if it does not sync online")
- **Category:** UI spoofing (CWE-451), tip honesty
- **Description:**
  - **Bidi override:** `dir="auto"` isolates the paragraph's direction, but RLO/LRO/PDF and line breaks inside the message are kept. A malicious team member can write text that reads as a different sender heading or a system notice (for example, "Security check: reply with your passphrase") inside the thread. S08 counts invisible characters only for *source* text.
  - **Tip wording:** The password-manager clause sits next to the seizure tip without saying the device must be one only the source controls.
- **Exploit scenario:** An insider phishes the passphrase by imitating UI text. The "conversation" tip mitigates this but does not remove it.
- **Fix recommendation:**
  - Render team-message text with bidi controls shown visibly (replace U+202A–U+202E and U+2066–U+2069 with visible markers) or stripped.
  - Visually frame each message body, for example with "Message text:" and a border, so it cannot pass for page chrome.
  - Change the tip to "…fine only on a device only you use, and only if it does not sync online."
- **Spec / requirement reference:** 11 §5.7 output encoding; 05 GC-32/GC-36; 11a TIP-007
- **Status:** Open

---

## Scope B — repository infrastructure

### AUD-RM0-INF-01: Supply-chain gates are red on the audited commit; `[skip ci]` pushes bypass them
- **Severity:** Medium
- **Location:** `Cargo.lock` / `crates/candor-intake-store/Cargo.toml` (sqlx 0.9.0 graph); `deny.toml:101` (`sha2` deny-multiple-versions); `supply-chain/config.toml` (no exemptions or audits for the new graph); commits `55f3356`, `60e732f`, `d8870f3` (`[skip ci]`)
- **Category:** B11.1–B11.3 (CWE-1395)
- **Description:**
  - **cargo vet:** `cargo vet --locked` fails with 101 unvetted crates.
  - **cargo deny:** `cargo deny check bans` fails because `sha2 0.10.9` (via `sqlx-core`) and `sha2 0.11.0` coexist in the crypto set, which 28 §5.2 forbids.
  - **New dependency:** `whoami` 2.1.3 enters through sqlx-postgres. It reads the OS user and host names, which matters for OPSEC on the intake host.
  - **CI bypass:** The commits that brought these in were pushed with `[skip ci]`, so the push-triggered gate never ran.
  - **Attribution:** The cause is in the RM-2 crate, but the result is that the RM-0 gate does not hold on `main`.
- **Exploit scenario:** Unvetted code (including a second SHA-2 implementation and an async runtime) sits on the default branch. Later PRs inherit a red baseline and reviewers learn to ignore failures.
- **Fix recommendation:**
  - Resolve before integration: pin sqlx features so `sha2` is unified (or a dated ADR exception with expiry), add a cargo-vet policy and audits or exemptions with expiry notes, and review `whoami`.
  - Require the `ci` checks in branch protection and forbid direct pushes and `[skip ci]` to `main` (or run the gate on `merge_group` and scheduled runs).
- **Spec / requirement reference:** 28 §5.1–§5.2, §6; 27 SG-05; ST-010/ST-011
- **Status:** Open

### AUD-RM0-INF-02: CODEOWNERS precedence bug drops Crypto Reviewers from T0 crates; key files have no owner
- **Severity:** Medium
- **Location:** `.github/CODEOWNERS:12-13` vs `:16`
- **Category:** B11.5 / governance (36 §6.1, 27 §11.1)
- **Description:** On GitHub the *last* matching pattern wins, as the file itself says on line 6. `/crates/` (line 16) comes after `/crates/candor-core/` and `/crates/candor-safefs/` (lines 12–13). So the T0 crates resolve to `@candor-project/trust-path-maintainers` only, and the Crypto Reviewer requirement is silently lost. The following have no specific owner, which leaves the default maintainers or release only:
  - `/.dco-epoch` (see INF-03)
  - `/clippy.toml` and `/rustfmt.toml` (lint policy)
  - `/deploy/`
  - `/CONTRIBUTING.md`
  - `/scripts/`, which lacks the security team even though `repro-check.sh` and `check-dco.sh` are gate logic

  All teams are placeholders today (documented), so nothing is enforced yet. That is exactly when the bug should be fixed.
- **Exploit scenario:** Once the teams exist, a change to `candor-core` crypto merges with trust-path approval only, and no Crypto Reviewer is asked.
- **Fix recommendation:** Move the T0 lines below `/crates/` (and keep source-ui and log after it). Add owners for `/.dco-epoch` (security-lead), `/clippy.toml`, `/rustfmt.toml`, `/deploy/` and `/scripts/` (+security-team). Add a CI check that resolves owners for sample paths (for example `crates/candor-core/src/lib.rs` must include crypto-reviewers).
- **Status:** Open

### AUD-RM0-INF-03: The DCO check trusts PR-controlled `.dco-epoch` and script; merge commits are never checked
- **Severity:** Medium
- **Location:** `scripts/check-dco.sh:20-28` (`EPOCH` read from the checked-out PR head; `git merge-base --is-ancestor "$c" "$EPOCH"`), `:26` (`--no-merges`); `.github/workflows/ci.yml:254-263` (checkout of `head.sha`, script run from the PR tree)
- **Category:** B11.5 (CWE-807 reliance on untrusted input)
- **Description:**
  - **Epoch bypass:** A PR that changes `.dco-epoch` to its own head SHA, or to the literal `HEAD`, makes every PR commit an "ancestor of the epoch", so all are exempt.
  - **Script replacement:** The PR can also edit `scripts/check-dco.sh` itself.
  - **Merge commits:** `--no-merges` means an "evil merge" that carries content changes is never checked for sign-off.
- **Exploit scenario:** A contributor submits unsigned commits plus a one-line `.dco-epoch` change. `dco` passes and the OSG-003 provenance record is defeated. Since `.dco-epoch` has no CODEOWNERS entry (INF-02), the change can slip past review.
- **Fix recommendation:**
  - Read the epoch from the base: `git show "$BASE_SHA:.dco-epoch"`.
  - Require it to be 40-hex and an ancestor of `BASE_SHA`.
  - Fail if the PR diff touches `.dco-epoch` or `scripts/check-dco.sh` without a security-lead label/approval. Better: run the checker from the base revision.
  - Check merge commits too, or reject merge commits in PR branches.
  - Add tests (a fixture repo) for each bypass (SG-21).
- **Spec / requirement reference:** 36 §4 OSG-003; CONTRIBUTING §1
- **Status:** Open

### AUD-RM0-INF-04: The reproducibility gate can pass vacuously and does not compare shipped artefacts
- **Severity:** Medium
- **Location:** `scripts/repro-check.sh:27-34` (exit 0 when there are no crates), `:95-97,123-128` (exit 0 "SKIP" when `target-N/release` is missing or empty); `.github/workflows/ci.yml:287` (creates an empty `SHA256SUMS` and uploads it)
- **Category:** B11 (gate fail-open; 28 §8.2, SG-13)
- **Description:**
  - **Vacuous pass:** If artefacts land somewhere other than `target-N/release`, the check prints SKIP and succeeds. That happens with `CARGO_BUILD_TARGET` in the environment, `build.target` in a future `.cargo/config.toml`, or a renamed profile. The workflow then publishes an empty sums file that looks like evidence.
  - **Not shipped artefacts:** The workspace has no binary targets today, so only intermediate `.rlib`s are compared, not anything that ships.
  - **Flags differ from release:** The script sets its own `RUSTFLAGS`, which override any project rustflags, so the published sums can never match release artefacts.
  - **Scope of the smoke test:** Both builds share one host, user, `CARGO_HOME` and toolchain. This is documented as a smoke test only.
- **Exploit scenario:** A change introduces non-determinism together with a target-dir change. CI stays green and the release pipeline inherits a false SG-13 signal.
- **Fix recommendation:**
  - Once `crates/*` exists, treat zero artefacts as **FAIL**.
  - Hash `target-N/**/release` (all triples).
  - Assert an expected list of shipped binaries (from a manifest) once bins exist.
  - Unset `CARGO_BUILD_TARGET`, or pass `--target` explicitly.
  - Share one flags file with the release pipeline.
  - In the workflow, do not create an empty `SHA256SUMS`; fail instead.
- **Status:** Open

### AUD-RM0-INF-05: The cargo-vet crypto criterion is satisfied by baseline exemptions; new crates have no policy; imports unapproved
- **Severity:** Medium
- **Location:** `supply-chain/config.toml` (68 `[[exemptions.*]]` entries granting `candor-crypto-reviewed`: hpke, ml-kem, x-wing, chacha20poly1305, ed25519-dalek, curve25519-dalek, argon2, blake3, hkdf, hmac, sha2, sha3, subtle, zeroize, getrandom, rand_core…); `supply-chain/audits.toml` (zero audits); no `[policy.candor-sealer]` or `[policy.candor-intake-store]`; `supply-chain/trusted-importers.toml` (all four imports `approved-by = "TODO"`); `[[exemptions.tar]] 0.4.45` (no expiry note; the lockfile has 0.4.46)
- **Category:** B11.3; B4.11
- **Description:**
  - **Hollow crypto criterion:** The `candor-crypto-reviewed` criterion (28 §5.2, 27 §11.3) is met by exemption for every crypto-set crate. `cargo vet` passing therefore says nothing about crypto review.
  - **Missing policies:** `candor-sealer` (T0, it holds keys) and `candor-intake-store` have no policy, so their direct crypto deps need only `safe-to-deploy`.
  - **Unapproved imports:** Imported audit sets are active without the required Security Lead approval record.
- **Exploit scenario:** A crypto dependency bump goes through `cargo vet regenerate exemptions`, or uses the existing exemption pattern, without a Crypto Reviewer ever certifying it.
- **Fix recommendation:**
  - Exempt crypto-set crates only for `safe-to-deploy`, so `candor-crypto-reviewed` is never granted by exemption. Record real `candor-crypto-reviewed` audits (or track the missing reviews explicitly as a release blocker).
  - Add policies for `candor-sealer` and `candor-intake-store`.
  - Fill in the import approvals.
  - Run `cargo vet prune` and add expiry notes.
  - Add a CI lint that rejects any exemption granting `candor-crypto-reviewed` or lacking `expires YYYY-MM-DD`.
- **Spec / requirement reference:** 28 §5.2; supply-chain/README "Policy"
- **Status:** Open

### AUD-RM0-INF-06: cargo-deny policy gaps
- **Severity:** Low
- **Location:** `deny.toml:132-136` (`allow-build-scripts` not populated), `:86-87` (`external-default-features = "allow"`); `.github/workflows/ci.yml` (no `cargo audit` second reader)
- **Description:**
  - **Build scripts:** Any new dependency's `build.rs` is accepted, against 28 §5.2 "new build.rs … require explicit approval". The check is deferred and documented, but open.
  - **Default features:** Default features of external crates are allowed, although BUILD-BRIEF rule 4 wants them off.
  - **Single advisory reader:** Only one RustSec reader runs in CI.
- **Fix recommendation:** Populate `allow-build-scripts` from `cargo deny list` now (the graph is known). Set `external-default-features = "warn"` with a reviewed allow-list. Add `cargo audit --deny warnings` to the scheduled job.
- **Status:** Open

### AUD-RM0-INF-07: Workflow lint covers format only (zizmor offline; pin-checker blind spots)
- **Severity:** Low
- **Location:** `.github/workflows/ci.yml:244` (`zizmor --offline`), `scripts/check-actions-pinned.sh:18,21,44`
- **Description:**
  - **zizmor offline:** `--offline` disables impostor-commit, ref-confusion and known-vulnerable-actions audits. A SHA from a fork network would pass both checks. I verified the current two SHAs manually.
  - **Pin checker:** Matches only `*.yml`/`*.yaml` (not `.YML`). Splits file lists on whitespace (`for f in $files`). Detects only `curl|sh`-style pipes; misses `bash <(curl …)`, `curl -o x && sh x` and `wget -O- … | python`.
- **Fix recommendation:** Add a scheduled job that runs online `zizmor` with a read-only `GITHUB_TOKEN`. Harden the checker (null-delimited `find`, case-insensitive extensions, broader remote-exec patterns) and add fixtures.
- **Status:** Open

### AUD-RM0-INF-08: `.gitignore` claims a secret-scanning control that does not exist
- **Severity:** Low
- **Location:** `.gitignore:19` ("secret scanning runs in CI"); `.github/workflows/ci.yml` (no such job)
- **Description:** Documentation asserts a control that is absent. A history scan found only synthetic test fixtures.
- **Fix recommendation:** Add a pinned secret-scanning job (patterns for age/OpenPGP/OpenSSH/HPKE keys, with an allow-list for the test fixtures), or correct the comment.
- **Status:** Open

### AUD-RM0-INF-09: Unprivileged test job: isolation reviewed; residual notes
- **Severity:** Info
- **Location:** `.github/workflows/ci.yml:97-167`
- **Description:** The job does what it claims:
  - fresh account, uid ≠ 0
  - privileged-group check and `sudo -n` check (fail closed)
  - root-owned, non-writable toolchain
  - `env -i`, so no runner tokens or env reach the tests
  - its own copy of the checkout without `target/`
  - home directory 0700

  Residual risks:
  1. The ordinary `test` job still runs PR code as `runner`, with passwordless sudo, network access and the job's read-only token. This is standard for GitHub-hosted runners and acceptable (no secrets, no caches, no consumed artifacts).
  2. Processes started by `candor-test` can outlive the step. There are no later steps today; if steps are added, kill them with `sudo pkill -u "$TEST_USER"` first.
  3. The rustup binary copied into `$RUST_PREFIX` is the runner's own, not separately verified.
- **Status:** Info (no action required)

---

## Variant notes (G3)
- **SUI-01:** checked other sinks with unbounded custom text: `p.vm.landing.purpose`, `jurisdiction_*`, `inc.text`, the S04 channel descriptions and the S04b role labels. These are deployment-controlled and short, covered by `max_content_fits_size_classes`. The source- and team-controlled sinks are S05, S06 (descriptions ≤ 500), S08, S11, S12 and the S05b identity fields (≤ 200/500).
- **SUI-02:** the same derive pattern should be checked in `candor-intake-store` and `candor-sealer::proto` during their audits.

---

## Re-test (round 2), 2026-10-01

- **Re-test commit:** `7d340f68794c76cff22277641765fb02d84d74fb`. The fixes were committed in `ab3170e`, `132e108`, `d73cff5`, `db1d234` and `3c1717e`. All of them were pushed with `[skip ci]`, so CI has not run on any of them.
- **Inputs:** `crates/candor-source-ui/SPEC-NOTES.md` § "Fixes for AUD-RM1-SUI"; `process/audits/FIXES-RM0-INF.md`; DECISIONS ADR-052(8).
- **Method (§G):**
  1. Read each fix diff (`git diff 55f3356..7d340f6` over the scope).
  2. Ran the new regression tests on the fix commit.
  3. Ran them on the audited commit `55f3356`, using a scratch worktree and the old scripts extracted with `git show`.
  4. Hunted for variants.
  5. Did a manual delta review of the new `paging`/`items` code and templates as new attack surface.
  6. Re-ran the §C tools.

  No repository code was changed by the auditor.

### Tool re-runs (round 2)

| Tool | Result |
|---|---|
| `cargo test -p candor-source-ui --locked` | 21 + 9 (content_limits) + 2 (debug_redaction) + 35 (render) + 11 (tips): all pass |
| `cargo clippy -p candor-source-ui --all-targets -- -D warnings` | clean. The audit extras show 9× `integer_division`, all intentional (adds `paging::split_escaped` `budget / 2`) |
| Auditor harness (scratch crate, `features=["preview"]`) | Every round-1 failing case now renders in every part, at exactly the class size: S08 at 98,304 B of `"`/`&`/`'`/10 % `"` gives 2–7 parts; S12 64 KiB hostile message, 4 parts; S11 inbox with all messages hostile, 6 parts. An out-of-range `part` is clamped. A 74 KB draft with CR LF, `&`, `"`, `<`, `é`, 😀 gives 3 pieces; the reassembled textarea contents equal the input, and every `piece` range is a valid char boundary |
| `tests/debug_redaction.rs` on `55f3356` | **fails** (2/2; the old `{:?}` prints identity, answers, draft and the form token). Passes on the fix commit |
| `tests/content_limits.rs` on `55f3356` | does not compile (it uses the new `part`/`escaped_len` API). The failing evidence on the old code is the round-1 harness (`OverBudget`) |
| `scripts/tests/test-check-dco.sh` | 13/13 on the fix. Against the audited `check-dco.sh`: **7 fail** (epoch→head, epoch=`HEAD`, unsigned merge, 3 epoch fail-closed cases, invalid revision) |
| `scripts/tests/test-repro-check.sh` | 6/6 on the fix; **0/6** on the audited script |
| `scripts/tests/test-check-actions-pinned.sh` | 20/20 on the fix; **3/20** on the audited script |
| `check-codeowners.py --self-test` / run | OK (23 paths) |
| `check-secrets.py` / `--history` | OK (441 files / 1,160 blobs) |
| `check-vet-policy.py` | FAIL (12): the four import approvals are `TODO`. Expected; Security Lead action |
| `cargo vet --locked` | FAIL: 169 crates (101 `safe-to-deploy` from the INF-01 graph; 68 `candor-crypto-reviewed`) |
| `cargo deny --offline --locked check advisories bans licenses sources` | **aborts: stack overflow (rc 134)**, deterministic, also with `RUST_MIN_STACK=64M` and `ulimit -s unlimited` → new **INF-10**. advisories/licenses/sources run alone: rc 0. bans with the audited `deny.toml`: rc 2 (`sha2` duplicate only) |
| `cargo audit` (advisory-db 9b3a3b7) | no findings |
| `zizmor --offline --persona=auditor .github` | no findings |
| `shellcheck -S style scripts/*.sh scripts/tests/*.sh` | clean |

### Status of round-1 findings

| ID | Sev | Round-2 status | Evidence / notes |
|---|---|---|---|
| SUI-01 | High | **Fixed** (7d340f6; `tests/content_limits.rs`, `paging::tests::split_covers_and_fits`) | Paging is by escaped length. Chrome is measured with every container and the widest navigation. Pieces go one per part. Final `pad_html` still fails closed. My cases pass; delta review below. Old code fails (round-1 harness). |
| SUI-02 | Medium | **Fixed** (`tests/debug_redaction.rs`, fails on 55f3356) | Remaining `derive(Debug)`s are deployment/config types, `Text`, enums, `ConfirmData` positions and `CredentialData` (whose `Passphrase` is redacted). `PieceRef` Debug prints only the field id and offsets. |
| SUI-03 | Medium | **Fixed** | `CappedWriter` is allocated once at the class budget and errors instead of growing. `Zeroizing<String>` zeroizes the full capacity. Item copies are exactly sized. `escape_z`, `spell` and `passphrase_line` each use one zeroizing allocation, and `q_value` clone was removed. The documented residual (Fluent temporaries for label/number arguments only) is accepted as Low residual. |
| SUI-04 | Low | **Fixed** | `from_tag` accepts only `PRODUCTION`; the default language list is `PRODUCTION`; the pseudo parser is behind `preview`. |
| SUI-05 | Low | **Accepted-pending** (spec decision 11 §5.3) | Guard test `header_block_spread_is_bounded` (spread ≤ 64 B; same cell count with a 200-B cookie allowance). Needs lead sign-off and a spec owner decision on a padding header. |
| SUI-06 | Low | **Accepted-pending** | It depends on a C-07 negative test: missing/foreign/`null` `Origin` on POST `/login` → reject. Check this in the RM-2 C-07 audit. |
| SUI-07 | Low | **Fixed** | `sui-cred-copy-warning` is linked by `aria-describedby`; test `passphrase_copy_warning`. |
| SUI-08 | Info | **Accepted-pending** (spec feedback) | No change, by design (spec-verbatim). |
| SUI-09 | Info | **Fixed** | Note: CI and `repro-check.sh` build with `--all-features`, so `preview` is compiled into those artefacts. The release build must not use `--all-features` (see SUI-13). |
| SUI-10 | Low | **Fixed** | Bidi controls are replaced by U+FFFD in messages and labels; messages are framed; the tip wording is changed. Variant: LRM/RLM/ALM (U+200E/F, U+061C) are not neutralised. They are weak marks, not overrides, and are acceptable. |
| INF-01 | Medium | **Open** (deferred to lead) | vet fails on 169 crates, and deny bans fails on `sha2`. ADR-052(8) says PR CI requires only `safe-to-deploy`, but the PR `cargo-vet` job uses the same policy that demands `candor-crypto-reviewed`. So the staging that ADR-052(8) decided is **not implemented**, and PR CI is red by construction. Fixes are still landing via `[skip ci]` commits. |
| INF-02 | Medium | **Fixed** | Order corrected (T0 after `/crates/`). Owners added for `.dco-epoch`, the checkers, the lint configs, `deploy/` and `CONTRIBUTING.md`. Resolver self-test in CI. |
| INF-03 | Medium | **Fixed** (old script fails 7/13 fixtures) | The epoch comes from BASE (40-hex, exists, ancestor of BASE). Merges are checked. CI runs the BASE copy of the checker. Residual, acknowledged by the builder: a PR can still edit `ci.yml`, so this needs required status checks plus CODEOWNERS on `/.github/`. |
| INF-04 | Medium | **Fixed** (old script fails 6/6) | No SKIP path; expected artefacts come from `cargo metadata`; explicit `--target`; ambient overrides cleared; no empty sums file. Info: in library mode the per-crate "source-set" hashes are equal by construction (both copies come from the same tree), so the real signal is the rlib comparison. |
| INF-05 | Medium | **Fixed** (policy and lint) / **Accepted-pending** (import approvals: Security Lead) | No exemption grants `candor-crypto-reviewed`; policies were added for sealer and intake-store; `check-vet-policy.py` is in CI. Gate state is tracked under INF-01 and ADR-052(8). |
| INF-06 | Low | **Open** | The `allow-build-scripts` list (42 entries) makes cargo-deny crash (INF-10), so the claimed rejection of an unlisted build script could not be reproduced. `external-default-features` stays `allow` (acceptable with the stated reason). Scheduled `cargo audit` was added. |
| INF-07 | Low | **Fixed** (old checker fails 17/20) | Online zizmor runs in the scheduled job with a read-only token, never on PR code. |
| INF-08 | Low | **Fixed** | `secret-scan` job; per-path + line-hash allow-list; history clean. |
| INF-09 | Info | **Fixed** (residual 2); residuals 1 and 3 accepted | `if: always()` `pkill -KILL -u candor-test`. |

### Delta review of the new paging and piece code (fresh attack surface)

1. **Escaping.**
   - All item text goes through `escape_z` (same five-character set as askama, `&#34;`/`&#39;`), and `escaped_len` matches it (unit test).
   - `|safe` is used only on crate-escaped item HTML.
   - The `piece` value is built from a validated id plus digits.
   - Textarea/input values are pre-escaped, so `</textarea>` and quote breakout are impossible.
   - The newline after `<textarea>` keeps a leading newline.
   - Refuted: injection through the piece or `shown` fields.
2. **Piece-range tampering.**
   - `parse_piece` is strict: ≤ 64 chars, `[a-z0-9_]` id, ≤ 9-digit numbers, `start ≤ end ≤ total`, no extra fields.
   - `splice_piece` checks `stored.len()==total` and char boundaries via `get`, and does not panic.
   - A forged range only affects the source's own draft and needs a valid CSRF token.
   - Weakness: staleness is detected by **length only** → **SUI-11**.
3. **Part navigation and leakage.**
   - Every part is exactly the class size. `part` is clamped. The part count is visible only inside the encrypted page.
   - Navigation adds requests the same way the existing S12 older/newer pagination does.
   - Request bodies of navigation POSTs carry the form's fields. This is not new: no-JS form posts were already unpadded (11 §15).
   - End-of-flow controls (S07 continue, S08 send) are only on the last part. This is good: the source sees all content before sending.
   - Issue in S12 → **SUI-12**.
4. **Size invariant.** The chrome is measured with the maximum navigation and all containers. Items are packed with 128-B slack plus 512-B page slack. `pad_html` is still the final fail-closed check. The tests cover every screen × locale × `& " ' <`. No input within the spec limits produced `OverBudget` in my runs.
5. **DoS.** Every request rebuilds and escapes every item of the screen (O(total content) per part view), bounded by the C-07 mailbox and report limits. `MAX_PARTS` = 9,999, and `pack` fails closed above it. No recursion, no panics (clippy deny set clean).

### New findings (round 2)

#### AUD-RM1-SUI-11: `splice_piece` detects stale pieces by length only; a same-length change is silently overwritten
- **Severity:** Low
- **Location:** `crates/candor-source-ui/src/paging.rs:180-202` (`if stored.len() != piece.total { Stale }`)
- **Category:** B5 / data integrity (CWE-367 analogue: check on length, use on content)
- **Description:** A `piece` value names a byte range and the *length* of the stored value at render time. The stored value can change with its length unchanged: a second tab, the browser Back button re-posting an older part (Tor Browser re-POSTs `no-store` pages), or a same-length edit of an earlier piece. The stale page's text is then spliced over content the source never saw on that page. Harness: `splice_piece("XYZdef", "text-0-3-6", "123")` → `Ok("123def")`.
- **Exploit scenario:** No adversary is involved. The source's own report silently loses or duplicates text before sending, which undermines the "nothing is left out" promise (`sui-part-status`).
- **Fix recommendation:** Bind each piece to a revision of the stored value. Options: a per-field RAM-only counter in the sealer session record, incremented on every write and carried as a fifth `piece` component; or a keyed MAC (session key) over the stored value, compared in constant time. Never put an unkeyed hash of plaintext in the page. Return `Stale` on mismatch (C-07 re-renders, keeping the posted text). Add a test: same-length change → `Stale`.
- **Status:** Open

#### AUD-RM1-SUI-12: S12 multi-part reply form: navigation re-posts a chosen file, and the send-with-piece contract is implicit
- **Severity:** Low
- **Location:** `templates/s12_conversation.html` (the `parts_nav.html` buttons sit inside `reply-form`, which is `multipart/form-data` and holds the file input on the last part); SPEC-NOTES "Contract for C-06/C-07" item 3
- **Description:**
  1. **File re-posted on navigation.** On the last part, a source who has chosen a file and then presses "Previous part" submits the reply form, so the browser uploads the whole file. The contract says navigation never uploads, but the bytes still cross Tor: a large, network-visible upload (11 §15; the `sui-files-size-visible` warning). The server then discards the file and the source silently loses the selection.
  2. **Send-with-piece is implicit.** When the restored draft is split, `action=send` on the last part carries only the last piece plus `piece`. If C-07 sends `text` without first applying `splice_piece`, only the final piece is sent. That is a partial message the source believes was sent whole. Contract item 3 covers splicing generally but does not say "before send".
- **Fix recommendation:** Put the part-navigation buttons on S12 in a separate, non-multipart form (`navform`) that carries only `csrf`, `part`, `page` and the composer piece (`form=` attribute), so the file input is never in it. State in the contract (and test in C-07) that every action, including `send`, applies `splice_piece` first and sends the spliced value; a send with a `Stale` piece is refused and re-rendered.
- **Status:** Open

#### AUD-RM1-SUI-13: `preview` is compiled into `--all-features` builds, including the reproducibility artefacts
- **Severity:** Info
- **Location:** `crates/candor-source-ui/Cargo.toml` (feature `preview`); `scripts/repro-check.sh` and the CI build with `--all-features`
- **Description:** Sample view models (fixed sample passphrase words) and `from_tag_including_pseudo` are part of every `--all-features` artefact. The current `SHA256SUMS` therefore describe a build that contains preview code. Nothing ships yet.
- **Fix recommendation:** Build release and repro artefacts with an explicit feature list (from the same file the release pipeline uses), not `--all-features`. Alternatively, have `deny.toml` or a test assert that no release target enables `preview`.
- **Status:** Open

#### AUD-RM0-INF-10: cargo-deny 0.20.2 aborts with a stack overflow on the new `deny.toml`; the bans gate never completes
- **Severity:** Medium
- **Location:** `deny.toml` `[bans.build] allow-build-scripts` (42 entries) with `include-dependencies`/`include-archives`; `.github/workflows/ci.yml` cargo-deny job (one invocation for all four checks)
- **Category:** B11.1 / gate integrity
- **Description:**
  - `cargo deny --offline --locked check … bans …` terminates with `fatal runtime error: stack overflow` (rc 134). It does so on every run, with a 64 MiB `RUST_MIN_STACK` and with `ulimit -s unlimited`.
  - Removing only `allow-build-scripts` restores normal behaviour (rc 2, `sha2` duplicate).
  - The build-script allow-list, the "unlisted crate is rejected" claim (INF-06) and every other bans rule (OpenSSL denies, crypto-set duplicates, wildcards) are therefore **not evaluated**.
  - Because one command runs all four checks, the `licenses` and `sources` results after the crash are not reported either.
  - The job fails closed (red), but it cannot tell a crash from a real violation, so any later violation is masked.
- **Fix recommendation:**
  - Reproduce minimally and report upstream.
  - Until fixed: bump cargo-deny through the 14-day cooling process if a fixed release exists; otherwise move the allow-list to a form that does not crash (bisect: `include-archives`, `include-dependencies`, entry count).
  - Run each check as a separate step so one crash does not hide the others.
  - Treat rc ≥ 128 as "gate broken", not as a policy result.
  - Add a fixture test: an unlisted crate with `build.rs` must give a `build-script-not-allowed` error.
- **Status:** Open

### Round-2 summary

| Severity | Open | Accepted-pending | Fixed |
|---|---|---|---|
| High | 0 | 0 | 1 (SUI-01) |
| Medium | 2 (INF-01, INF-10) | 0 | 6 (SUI-02, SUI-03, INF-02, INF-03, INF-04, INF-05*) |
| Low | 3 (INF-06, SUI-11, SUI-12) | 2 (SUI-05, SUI-06) | 5 (SUI-04, SUI-07, SUI-10, INF-07, INF-08) |
| Info | 1 (SUI-13) | 1 (SUI-08) | 2 (SUI-09, INF-09) |

\* INF-05: the import approvals are Accepted-pending (Security Lead).

### Gate verdict (round 2)

- **Scope A, `candor-source-ui`: PASS-conditional.** There are no open Critical, High or Medium findings.
  - SUI-05, SUI-06 and SUI-08 need the lead's written acceptance, as recorded above.
  - SUI-11, SUI-12 and SUI-13 are Low/Info: they are tracked and do not block.
  - Integration also requires the C-07 obligations to be tested in the RM-2 C-07 audit: Origin check (SUI-06), splice-before-send (SUI-12), and absent-field semantics.
- **Scope B, infrastructure: FAIL.**
  - **INF-01 (Medium, Open):** vet/deny are red, and the ADR-052(8) PR/release staging is not implemented in CI.
  - **INF-10 (Medium, new, Open):** cargo-deny crashes, so the bans policy is unevaluated.

  Both need a fix or the lead's written acceptance, and the §C tools must complete without untriaged output.

`Gate: FAIL 2026-10-01 7d340f6` (infra). Scope A may be integrated once the lead records the acceptances for SUI-05, SUI-06 and SUI-08.
