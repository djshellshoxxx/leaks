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
   * 11 §5.7 and ADP-14 call it `ft`. 08 SW-* lists `csrf`, and ADR-051(4) decides `csrf`.
   * Implemented: `csrf` (constant `FORM_TOKEN_FIELD`).
   * **For the lead / spec owners:** 11 §5.7 ("Every form carries a hidden `ft`") and ADP-14
     still say `ft`; update them to `csrf` per ADR-051(4).
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
22. **Pre-session pages (superseded by the AUD-RM1-SUI-06 fix).** Every form carries a `csrf`
    token, including the pre-session forms (S11 login, Leave, the S01–S03 footer Leave). A page
    that contains a form and has `form_token: None` fails closed
    (`RenderError::MissingData("form token")`). See the C-06/C-07 contract, item 6.
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

## Fixes for AUD-RM1-SUI (audit `process/audits/AUDIT-RM0-RM1-sourceui-infra.md`)

| Finding | Change | Tests |
|---|---|---|
| **SUI-01** (High) escaping breaks P2 | New `paging` + `items` modules. Paged screens (S05, S06, S07, S08, S11 inbox, S12) render the chrome once in *measure* mode (all containers, widest part navigation, end-of-flow controls), and the rest of the class budget goes to items. Each item (answer, message, draft, question, file row, hint) is rendered alone into a fixed buffer. An item that does not fit is split into **pieces** cut by *escaped* length (character boundaries, preferably after whitespace, never inside CR LF). Each piece fills a part on its own and is labelled "(part i of n)". Items are packed into parts; `PageContext::part` selects one (clamped). Navigation: `part` submit buttons inside the screen's form, so edits are saved on the way. Nothing is truncated. Sizes never change: class still depends only on method and cookie, and every part is padded to it. End-of-flow controls (S07 continue, S08 send, S12 send/file/delivery) appear only on the last part, so the source passes every part first. Labels that are not source content (team sender, file names) are shortened visibly ("…") past 256 characters, so one label cannot fill a page. `escape` now emits `&#34;` (5 bytes, same as askama), and `escaped_len()` is public. | `tests/content_limits.rs`: S05 and S08 at the 98,304-byte report limit; S12 with a hostile 64 KiB staff message plus a 60,000-char draft; S11 inbox; S06/S07 with 60 files, long names and 500-char descriptions; the audit's own cases (10 % `"`, all `"`/`&`, 60,000 `"` draft); **every screen × every locale × each of `& " ' <`** with all fields at their maximum; a 1 MiB message (beyond limits). Each checks every part for exact class size, parse cleanliness, unique ids and prev/next buttons, and that the text is complete across parts: concatenated display text equals the input, and editable pieces map back exactly to their byte ranges. `paging` unit tests and a proptest (`split_covers_and_fits`). These tests fail on the audited code with `OverBudget`. |
| **SUI-02** (Medium) `derive(Debug)` on sensitive types | `PageContext`, `FieldError`, `Msg`, `Arg`, `NewReportData`, `ConcernsData`, `Question`, `QuestionnaireData`, `IdentityData`, `AttachedFile`, `FilesData`, `ReviewAnswer`, `IdentityHint`, `ReviewData`, `SentData`, `InboxMessage`, `InboxData`, `ConversationData` and `ViewModel` now print only `Type { [redacted] }`. `Msg` and `FieldError` show the catalog key, field id and argument count only. `Page` no longer prints `unpadded_len`. | `tests/debug_redaction.rs`: a lint over `src/model.rs` (only allow-listed types may derive `Debug`), and a sentinel test that formats a fully populated view model and its parts. |
| **SUI-03** (Medium) heap copies | Pages and items are rendered with `render_into` into a `CappedWriter`. It is allocated once at the class budget (zeroizing) and **fails instead of reallocating**, so no stale prefix of a page (passphrase, source text) is freed unzeroized. Item HTML is copied into an exactly sized zeroizing buffer, and the large one is zeroized. Source and team text is escaped by `escape_z` into one pre-sized zeroizing buffer. `spell()` and `passphrase_line()` build into one pre-sized `Zeroizing<String>`. `q_value()` (which cloned the answer) was removed. `splice_piece` returns `Zeroizing`. | `paging::tests::capped_writer_never_grows`; `render::oversized_chrome_fails_closed`; the existing passphrase tests. |
| SUI-04 (Low) pseudo-locales offered | `Locale::from_tag` accepts only `Locale::PRODUCTION` (`[En]`). `from_tag_including_pseudo` exists only with the `preview` feature. An empty `offered_locales` now means `PRODUCTION`, not `ALL`. | `render::locale_allow_list` |
| **SUI-05** (Low) header block length | **Fixed (lead decision).** `render()` ends the header list with a fixed-width padding header `X-Pad` (visible `0`s, since HTTP strips leading/trailing whitespace) so the serialized HTTP/1.1 head (status line with the standard reason phrase, `Name: value` lines, blank line) is exactly `SizeClass::head_bytes()` = 2,048 bytes for every screen, locale and session state. `finalize_headers(&mut Page, Option<&str>)` puts the session/pre-session `Set-Cookie` (≤ `MAX_SET_COOKIE_BYTES` = 256, visible ASCII, no CR/LF) into a reserved slot and recomputes the padding; it fails closed (`HeaderError`) instead of sending a head of another length. `Page::head_len()`, `reason_phrase()`. `Page`'s `Debug` prints header names only, and header values are zeroized on drop and on replacement (the cookie is a secret). Spec feedback: 11 §5.3 should list `X-Pad` and the fixed head length. | `render::response_head_length_is_constant` (every screen × locale × {GET, POST} × {cookie, none} × {no cookie, short, expiry, 256-byte cookie}, also serialized byte for byte); `page::tests::finalize_rejects_bad_cookies_and_keeps_length` |
| **SUI-06** (Low) no pre-session CSRF token | **Fixed (lead decision).** Every form renders the hidden `csrf` field, pre-session forms included (S11 login, Leave, footer Leave on S01–S03 and error pages). A page with a form and no `form_token` fails closed (`MissingData("form token")`). The field name is `csrf` (ADR-051(4); 11 §5.7 `ft` recorded for the lead, note 3). C-06 obligations: contract item 6. | `render::every_form_carries_a_token` |
| SUI-07 (Low) clipboard warning | S10/S11r: `sui-cred-copy-warning` (tier0) under the one-line field, linked by `aria-describedby`. Spec feedback: mirror it in 05 GC-32. | `render::passphrase_copy_warning` |
| **SUI-08** (Info) absolute anonymity copy | **Fixed (lead decision).** Rewritten to conditional language (DECISIONS §0, ADR-035(5)): S03 `sui-status-mode-anonymous` and S04 `sui-new-mode-anon-consequence` now read "Candor does not collect who you are. Your writing and files can still identify you." (matching the mode banner); `sui-status-connection-dd` and S01 `sui-landing-b3` say "In Tor Browser, this site cannot/can't see your internet address"; GC `sops-limits-n1` says "When you use Tor Browser, your internet address is hidden from us …". All three catalogs were grepped; no other absolute anonymity claims. Spec feedback: change 11 §7 S01/S03/S04 and 05 GC limits text the same way. | `tips::catalog_anonymity_claims_are_conditional` (every catalog line: banned "won't/don't/… know who you are", "no one will know", "you are anonymous", …; any "cannot see / hides … internet address" sentence must name Tor Browser); the phrases are also added to `tips::honest_wording_lint` |
| SUI-09 (Info) preview data in production | Superseded by the SUI-13 fix: there is no `preview` module or feature in the library any more. `Page::unpadded_len` is `#[doc(hidden)]` and documented as CI-only. `Page::parts` is documented as never to be logged or exported. | builds: `cargo clippy -p candor-source-ui --all-targets --all-features` |
| SUI-10 (Low) bidi spoofing; tip wording | Team message text and sender labels have U+202A–U+202E and U+2066–U+2069 replaced by a visible U+FFFD. Each message is an `article.msg` framed with a full border (CSS hash updates automatically). File names get the same treatment through `label()`. The tip now reads "A password manager is fine only on a device only you use, and only if it does not sync online." Spec feedback: mirror this in 11a's passphrase row. | `render::team_message_bidi_neutralised`, `render::password_manager_tip_wording` |
| **SUI-11** (Low) stale piece by length only | Each `piece` value is now `{field}-{start}-{end}-{total}-{tag}`, where `tag` is HMAC-SHA256 (truncated to 128 bits, lowercase hex) under a per-session `PieceKey` over a domain label, the field, the offsets, the length and the **whole stored value**. `render` takes the key from `PageContext::piece_key` and fails closed (`MissingData("piece key")`) if a value must be split and no key is set. `splice_piece(key, field, stored, piece, edited)` recomputes the MAC over the current stored value and compares in constant time (`verify_truncated_left`): any change since rendering, of any length, a piece from another session, or one applied to another field returns `Stale`. No unkeyed hash of plaintext is ever put in the page. | `paging::tests::same_length_change_is_stale` (the audit's `XYZdef` case), `splice_checks`, proptest `any_change_is_stale`; `content_limits` `rebuild` now splices every rendered piece back under the session key and checks a same-length change is `Stale` |
| **SUI-12** (Low) S12 navigation re-posts the file | The S12 reply form is now url-encoded (08 SW-12): `csrf`, `page`, the composer `text`/`piece` (tied by `form="reply-form"`), delivery choice, Send and the part buttons. The file input moved to its own multipart form `file-form` (08 SW-13: `csrf`, `file`, button `action=upload`) on the last part, with no navigation or send button, so moving between parts never uploads a file. A hint (`sui-conv-file-separate`) says adding a file does not send or save the message text. Splice-before-send is now explicit in the contract (item 3). | `render::s12_navigation_never_posts_a_file` |
| **SUI-13** (Info) `preview` in `--all-features` builds | The `preview` feature, the `preview` module, the self dev-dependency and `Locale::from_tag_including_pseudo` are removed from the library. The sample view models are `tests/support/preview.rs`, included with `#[path]` by the integration tests and the `render_all` example only (dev targets, never linked into the server), so `--all-features` CI and repro builds keep working and contain no sample data. | `cargo clippy -p candor-source-ui --all-targets --all-features -- -D warnings`; `cargo test -p candor-source-ui` |

### Contract for C-06/C-07 (new; implementation decisions)

1. **Part navigation.** Any POST that carries `part=k` applies the form's own fields as usual and
   then re-renders the same screen with `ctx.part = k`. New POST targets:
   * POST `/review` and POST `/inbox`, each with only `csrf` and `part`;
   * POST `/files/check` with `part`;
   * POST `/files` (desc-form) with `part`;
   * POST `/q` with `part`;
   * POST `/conversation` (reply form) with `part` and `page`.
   C-06 must accept POST `/inbox`. That response is P2, like the GET with a session cookie, so the
   size class does not change. Following a `part` button never sends a message, a report or an
   upload: those happen only through the existing `action`/`nav` buttons.
2. **Absent fields mean "unchanged" on a multi-part page.**
   * S06: `desc_N` of files on other parts is not posted. Continue is now a named button
     (`nav=continue`) rather than a hidden field.
   * S05: questions not listed in `shown` are untouched. Absent checkboxes clear only the
     questions listed in `shown`.
   * S12: a POST without `text` (for example from a part without the text field) leaves the
     draft unchanged.
3. **Pieces.** A part with a piece of a long value carries exactly one control for that field and
   one `piece=field-start-end-total-tag` (byte offsets into the stored value at render time and a keyed MAC of that value).
   * C-07 parses the value with `parse_piece` and applies the edit with `splice_piece`.
   * `splice_piece` fails closed (`Stale`/`Boundary`) if the stored value changed in any way
     (keyed MAC, AUD-RM1-SUI-11) or the offsets are not character boundaries. C-07 then
     re-renders with the posted text kept (11 §5.7), never discarding it.
   * C-06/C-07 create one `PieceKey` per session from a CSPRNG, keep it in RAM with the session
     record only, pass it as `PageContext::piece_key` on every render and to every
     `splice_piece` call, and drop it with the session.
   * **Splice before every action, including send (AUD-RM1-SUI-12).** A POST that carries
     `piece` first applies `splice_piece` to the stored value, then performs its action on the
     spliced value. `action=send` on the last part of a split draft carries only the last piece:
     C-07 must send the **spliced whole draft** (all pieces), never the posted `text` alone. A
     send whose piece is `Stale` or `Boundary` is refused and S12 is re-rendered with the posted
     text kept; nothing is sent.
   * Browsers send textarea line breaks as CR LF. C-07 normalises line breaks before it stores
     or splices a value.
4. **Errors on other parts.** An error-summary link to a field shown on another part points
   nowhere on the current part. C-07 should render the part that holds the first invalid field.
5. **View-model zeroization.** The crate zeroizes everything it allocates for the page except
   Fluent's formatting temporaries (see residuals). `ViewModel` strings are owned by C-06. C-06
   must hold the RAM draft and passphrase in zeroizing storage and must not keep view models
   longer than one render.
6. **Form tokens before login (AUD-RM1-SUI-06).** Every form carries `csrf`. For pre-session
   pages (S01, S02, S02b, S03, S11 login, Leave, error pages) C-06 issues a single-use
   pre-session token bound (by MAC) to a short-lived, random pre-session cookie
   (`__Host-` prefix, `Secure; HttpOnly; SameSite=Strict; Path=/`, a few minutes, RAM only), sent
   through `finalize_headers`. POST `/login` and `/leave` are accepted only with a token that
   matches that cookie. C-06/C-07 **also** enforce `Origin` (exact own onion origin; missing,
   foreign or `null` → reject) and `Sec-Fetch-Site: same-origin` when present, on every POST.
   C-07 tests: missing/foreign/`null` Origin, cross-site `Sec-Fetch-Site`, missing or foreign
   token on POST `/login` → reject.
7. **Response head (AUD-RM1-SUI-05).** C-06 calls `finalize_headers(&mut page, cookie)` last,
   writes `HTTP/1.1 {status} {reason_phrase(status)}`, the headers in order as `Name: value`
   lines and the blank line, adds no header of its own and serves HTTP/1.1 only (HPACK/QPACK
   would change header sizes). The head is then exactly 2,048 bytes for both classes. HEAD
   responses send the same head.

### Security self-review (AUD-RM1-SUI fixes)

* **Escaping.** Every item is still escaped: `escape_z` (same rules as askama) or askama
  auto-escaping, with `|safe` only on crate-escaped HTML. Hidden `piece` values are crate-built
  (`[a-z0-9_]` id and digits). Textareas get a newline after the start tag, so a leading newline
  in a piece survives parsing. The hostile-content and `arbitrary_text_is_inert` tests pass
  unchanged.
* **Size side channel.** The size class is unchanged and every part is exactly the class size.
  The number of parts depends on content length, and it shows in the page text and the
  navigation, both inside the encrypted response. A network observer sees only fixed-size
  responses and, as before, the number of requests. Navigating between parts is extra requests,
  equivalent to the existing S12 older/newer pagination (11 §5.4 rule 2).
* **No truncation or loss.** Tests reassemble every value from all parts. Splicing fails closed
  on stale offsets. A label past 256 characters is shortened with a visible "…". This applies
  only to team-sender labels and file names, never to report, message or draft text.
* **Fail closed remains.** Chrome that alone exceeds the class (deployment text), or a single
  unsplittable item larger than a part (a choice question with huge deployment labels), still
  returns `OverBudget`. No source- or team-controlled input within the spec limits can cause it.
  The tests cover every screen and locale.
* **Panics.** None. `paging` and `items` use `get`, checked/saturating arithmetic and no indexing.
  The capped writer reports overflow as an error.
* **Residuals.**
  1. Fluent formatting allocates temporaries that are not zeroized for messages with arguments.
     Those arguments are sender labels, file names, deployment labels and numbers, never answer,
     message, draft or passphrase text.
  2. The allocator may copy freed blocks before our zeroizing drop (no `mlock` here). C-06
     process hardening (no core dumps, no swap) is still required.
  3. `askama`'s internal buffers and the caller's `ViewModel` are outside this crate's control.
  4. The fixed response head length holds only if C-06 serializes it exactly as contract item 7
     says; a server library that adds headers (`Date`, `Transfer-Encoding`) breaks it. C-06 must
     test the bytes on the wire.
  5. Adding a file on S12 is a separate request (08 SW-13), so unsent text typed before adding a
     file is not posted with it. The page says so (`sui-conv-file-separate`).

### Security self-review (round-2 fixes: SUI-05, -06, -08, -11, -12, -13)

* **Header padding.** The cookie value is validated (visible ASCII and space, no CR/LF, ≤ 256
  bytes), so it cannot inject headers. It is never printed (`Page` `Debug` shows header names only)
  and is zeroized on drop and when replaced. Padding uses checked arithmetic and fails closed.
* **Piece MAC.** HMAC-SHA256 from RustCrypto (`hmac`), domain-separated, covering field, offsets,
  length and the full value; constant-time verification; the key is `Zeroizing` and redacted in
  `Debug`. The tag is not a hash of plaintext without the key, so it reveals nothing about the
  text.
* **Forms.** `<form` in the rendered page is only ever template markup (all content is escaped),
  so the token check cannot be triggered or bypassed by content.
* **Residual.** Pre-session CSRF depends on C-06 issuing and checking the pre-session token and
  Origin (contract item 6); the crate can only make the field mandatory.

### Dependencies

* `hmac =0.13.0` (no default features): keyed MAC binding `piece` fields to the stored value
  (AUD-RM1-SUI-11). Already a workspace dependency (candor-core, candor-log) at this version.
* The former self dev-dependency (for the `preview` feature) is removed.
