# SPEC-NOTES: candor-source-ui

Spec ambiguities, conflicts and implementation decisions. No protection was weakened. Where
specs disagreed, the stricter or more specific rule won, as recorded below.

## Conflicts between the assignment and the spec

1. **CSP `style-src`.**
   * The assignment brief says `style-src 'self'`.
   * 11 §5.3 (canonical, RVW-A-21) says the CSS is inline and hash-pinned, there is no static
     sub-resource route (SW-19 withdrawn), and no `style-src 'self'` exists.
   * Implemented: the 11 §5.3 policy verbatim, `style-src 'sha256-…'`, which also carries
     `img-src 'self' data:`, `sandbox allow-forms allow-same-origin` and
     `require-trusted-types-for 'script'`.
   * The "single small CSS file" is `static/source.css`. It is served inline after minification
     (comments and line breaks stripped) to save P1 bytes, and the hash covers the served bytes.
2. **Padding position.** 11 §5.4 rule 1 places the HTML comment of spaces before `</body>`, which
   the brief allows ("or as specified"). Implemented as rule 1 says.

## Spec conflicts and ambiguities

3. **Name of the form-token field.**
   * 11 §5.7 and ADP-14 call it `ft`. 08 SW-* lists `csrf`.
   * Implemented: `csrf` (08 owns the form fields; constant `FORM_TOKEN_FIELD`).
   * Spec feedback: align the two documents.
4. **File input.**
   * 11 S06 and SUI-025 require `<input type="file" multiple>` with name `f`.
   * 08 SW-06 (canonical for the upload protocol, ADR-046 §4) and 08 §4 say "Tier W: one file
     per request", with field `file`.
   * Implemented: a single `file` input, without `multiple`, `accept` or `capture`, plus the
     hint "Add one file at a time".
5. **Session cookie name.** 11 §5.6 says `__Host-cs`; 08 SW-03 says `__Host-s`. Not used by this
   crate. Flagged for alignment.
6. **POST `/new` response.** 11 says it renders S04b; 08 SW-03 says S05. Not this crate's
   decision, since C-06 chooses the screen. S04b follows S04 per 11 §6.
7. **Mode field on S04.** 08 SW-02/03 lists no mode field. Implemented as `mode`, with values
   `anonymous`, `confidential` and `identified`.
8. **Error title versus mode-first title.**
   * 11 §5.2 rule 2 says the mode word is the first word of `<title>`.
   * §5.7 says the title is prefixed with "Error: ".
   * Implemented: `Error: {Mode} · …`, so the error prefix comes first and the mode word comes
     first after it.
9. **Leave page versus banner and footer.**
   * The Leave page allows "No links except Back to start", but every page must show the mode
     banner, whose tier line has a link.
   * Implemented: Leave keeps the banner text but drops the tier-line link, the warning-banner
     links and the footer.
10. **S05b button labels.**
    * 11 S05b: "Yes, share who I am" / "No, stay anonymous".
    * 03 §7: "Share my identity" / "Keep anonymous" (default focus).
    * Implemented: the 11 labels and the 03 confirmation body text. "No, stay anonymous" comes
      first in DOM order.
    * `autofocus` is not used there, because without JavaScript it is only advisory and the
      `h1` is the announced outcome.
11. **Mode-change page.** 11 says "the `<h1>` of the next page reads 'Your report is now …'" but
    also requires one `h1` per page and §5.2 rule 3 ("dedicated confirmation page").
    Implemented: a dedicated page (`Screen::ModeChanged`).
12. **Placement of the ADR-035(5) statement.**
    * 03 §7 also requires it on "the step before final Submit".
    * Shown on S01, S03, S11 login (SUI-064) and S10c, together with the ANON-022 passphrase
      sentence.
13. **Progress links and the S08 "Edit" links.**
    * DP-13 forbids state in query strings, so a GET link cannot target a questionnaire step.
    * Progress links point at the step's route; for `/q`, C-06 re-renders the current step.
    * S08 "Edit: {question}" controls are small POST forms (`nav=goto`, `step=n`) styled as
      links.
    * Missing required answers on S08 are reported through `page_error` (summary without field
      links), because those fields are not on the page.
14. **Language switch on POST-only screens** (S10, S10c, S90).
    * The link targets the nearest GET route of the flow (`/review`).
    * On S10 this means the passphrase is not shown again. A new one is generated on the next
      "Continue to send", consistent with ADR-034 (never re-displayed).
15. **Rotation confirmation route.** 11 lists POST `/rotate/confirm` for the 3-word check but no
    route that renders the S10c-style form. Implemented: the S11r credential page posts "Next" to
    `/check` (08 SW-24, PENDING_CONFIRM state), and the rendered form posts to `/rotate/confirm`.
16. **Ask-to-delete.** No 08 route exists. Implemented as POST `/end` with `action=ask-delete`
    (confirmation page) and `action=ask-delete-confirm`.
17. **`Clear-Site-Data` on S10s** (SUI-036 "submit completion") also clears the session cookie.
    The S10s "Open my mailbox" link therefore goes to `/login`, not directly to the inbox
    (11 §6 shows S10s → Inbox). The SHALL in SUI-036 was followed.

## Implementation decisions

18. **Onion address on S03.**
    * 11 asks for `aria-label` on a `<span>`, but ARIA 1.2 prohibits `aria-label` on generic
      elements.
    * Implemented: a visually hidden full address (`lang="en" dir="ltr"`) plus an `aria-hidden`
      `<code>` showing 4-character groups. Screen readers read the address once.
19. **Mode banner element.** `role="status"` per 03 §7, with `aria-label="Protection mode"`.
    It is not sticky.
20. **JavaScript-state indicator on S03.**
    * "JavaScript is off ✓" appears only under `@media (scripting: none)`.
    * If the media feature is unsupported, a neutral "Check: is Tor Browser set to Safest?" is
      shown instead (05 §8.2 fallback), so the page never shows a false ✓.
21. **Absolute-timeout reveal.** The delay is rounded **down** to 5-minute classes, so the
    warning can come early but never late. The minimum is 0, which reveals the warning
    immediately.
22. **Pre-session pages.**
    * A page without a token (`form_token: None`) renders the Leave form without a hidden token.
    * Leave on a session-less page has nothing to protect except the cache, and C-06 decides
      whether to accept it.
23. **Locale fallback.**
    * Any missing key fails the render (`RenderError::MissingStrings`). The 26 §12.2 per-string
      fallback for stale `critical` strings is not implemented, because only English and
      generated pseudo-locales exist.
    * Pseudo-locales are complete by construction and are marked `is_pseudo()` so that they
      are never enabled in production (I18N-005).
24. **Fluent ids.** Fluent forbids dots in ids, so spec key `sui.mode.anonymous` is
    `sui-mode-anonymous`. Classes come from `# @class` comments, read with the full
    `fluent-syntax` parser, because the runtime parser drops comments.
25. **en-XA expansion is +40 % in UTF-8 bytes per text element** (vowels accented, `~` padding,
    `⟦…⟧` delimiters), rather than +40 % in characters with every letter accented. Byte growth is
    what the §5.4 budgets see. The fully accented variant roughly doubled the byte size, which
    is not representative of real translations.
26. **Bidi isolation.** Fluent's FSI/PDI isolation is kept on for all placeables (26 §9). They
    appear in `<title>` and text.
27. **Number and date formatting.** Dates are always `YYYY-MM-DD (UTC)`. ICU4X localized long
    dates and numerals (26 §12.1) are not wired in. Sizes use decimal MB/GB, rounded.
28. **Questionnaire field names.**
    * Question ids are the form names: `category`, `what`, `when_month`, `when_year`,
      `when_ongoing`, `when_unsure`, `where`, `who`, `how_know`, `people_know`,
      `reported_before`, `anything_else`.
    * S05b uses `full_name`, `role_dept`, `contact` and `contact_other`.
    * S06 description fields are `desc_N` (associated through the `form` attribute).
    * Ids and values are validated (`[a-z0-9_]{1,32}`, `[A-Za-z0-9_-]{1,64}`), and anything
      else fails the render.
29. **Identity hints on S08** show only an Edit control. The 05 §8.5 "[Keep as is]" is implicit,
    since the notice is non-blocking and needs no action.
30. **HIGH-profile rotation offer.** "Not now" is a link to GET `/inbox`, which C-06 renders
    without the offer.
31. **S11 multi-report list** (optional per ADR-005) is not implemented.
32. **C-38 CLEARNET mode** is rendered by the banner for completeness. The onion templates never
    offer it as a choice (SUI-018). The C-38 theme is out of scope.

## Spec risk: S02 page weight (needs a spec decision)

33. S02 must carry all GC cards on one P1 page (61,440 bytes unpadded).
    * Measured with every optional statement and every warning banner:
      * en: 47.1 KB
      * en-XL: 51.6 KB
      * ar-XB: 48.8 KB
      * en-XA (+40 % bytes): **60.4 KB, about 1 KB of headroom**
    * A real translation in a non-Latin script would not fit. Arabic, Persian, Russian and
      Ukrainian use 2 bytes per letter, and Chinese uses 3 bytes per character. Long Latin
      translations (German, French) would not fit either.
    * Rendering then fails closed with `RenderError::OverBudget`. Nothing is truncated.
    * Suggested spec resolution (11 §5.4 / §14, `05` §7):
      * split S02 into an essentials page plus one P1 page per card group, all GET without a
        cookie; or
      * allow a P1 budget per locale; or
      * move the card set to P2.
    * CI should run `s02_budget_report` for every enabled locale.

## Safety tips on every screen (`specs/11a-SOURCE-SAFETY-TIPS.md`)

34. **Prefix registration (for the lead).** New document and prefix to add to DECISIONS §3:

    | Doc | Prefixes |
    |---|---|
    | 11a-SOURCE-SAFETY-TIPS | TIP- |

    TIP-001..TIP-013 also need rows in `39-REQUIREMENTS-TRACEABILITY.md`.
35. **New route and screen (spec feedback for 11 §5.5 and 08 SW-*).** S02b "Safety tips for each
    step" is `GET /{lang}/safety/tips` (`Route::SafetyTips`, `Screen::SafetyTips`, spec id
    `S02b`). It is stateless, has no query string and takes its size class from 11 §5.4 like any
    other GET (P1 without a session cookie). C-06 must add the route. `Screen::ALL` now has 37
    entries.
36. **Implementation decision: S02 shows NORMAL tip text only.** S02 already carries every GC
    card and measures 60,839 of 61,440 bytes in `en-XA` with worst-case content (600 bytes of
    headroom, down from about 1 KB). Its tip has no `<details>`; the region links to S02b, as
    ADR-051(2) allows. S02b lists **every** tip with both tracks, so opening it shows interest in
    safety, not the higher-risk track (05 GP-1). The S02 risk in note 33 still stands for real
    translations; the S02 tip can be dropped first if a locale overflows.
37. **Implementation decision: placement.** The tips region (`<aside class="box tips">`, `<h2>`
    "Staying safe on this page") is rendered by `layout.html` after each screen's own content and
    before the session notes. It never sits between the `<h1>`/error summary and the form, and it
    reuses existing CSS (no stylesheet or CSP-hash change). Tips are a static function of the
    screen (`Screen::tips()`), never of mode, content or input, so they cannot vary page size.
38. **Leave page.** Its tip has no link, which keeps "no links except Back to start".
39. **Readability check.** `tests/tips.rs` uses a heuristic Flesch–Kincaid grade (vowel-group
    syllables). It is English-only and approximate; translations still need human review
    (26 §12.2).

### Security self-review (tips)

* No JavaScript, no new form controls, no `open` details, no query strings. Links in tips are
  only the allow-listed same-origin `/safety/tips` route (tested). Tip strings contain no URLs
  or domain names (tested). Tool names are plain text (05 GP-7).
* `<details>` state never reaches the server, so the risk track is not observable. Visiting S02b
  is observable to a compelled C-06, which is why S02b holds both tracks.
* Tips do not depend on the view model, so they add a constant number of bytes per screen and
  locale and do not affect the size-class invariant. Budgets were checked for every screen and
  locale with worst-case content.
* Wording lint: no absolute claims, fear words, exclamation marks or all-caps. The seizure tip
  says not to destroy anything the source may be legally required to keep (05 GP-6).
* Residual: placing tips at the end of `<main>` puts them below the fold on long forms. The
  inline JIT warnings that 11 already requires (S06, S07, S10) are unchanged.

## Dependencies (exact versions)

* `askama =0.16.1` (derive, std): compile-time-checked templates with auto-escaping, as required
  by the brief.
* `fluent-bundle =0.16.0`: Fluent formatting, plural selectors and bidi isolation (26 §12.1).
* `fluent-syntax =0.12.0`: the full parser, used to read `# @class` comments from the catalogs.
* `unic-langid =0.9.6`: the locale identifiers that `fluent-bundle` requires.
* `sha2 =0.11.0`: the CSP `sha256-` source for the inline stylesheet (workspace pin).
* `base64 =0.22.1` (alloc): base64 encoding of the CSP hash.
* `zeroize =1.8.2`: zeroizes page bodies and passphrase words.
* dev `scraper =0.27.0` (errors): html5ever-based well-formedness and DOM assertions.
* dev `proptest =1.11.0`: property tests (workspace pin).
