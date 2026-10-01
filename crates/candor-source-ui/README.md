# candor-source-ui

Licence: AGPL-3.0-or-later (Trust Path, ADR-020/031).

Server-rendered, **zero-JavaScript** source web UI for the Tier W path (component C-06),
implementing `specs/11-FRONTEND-SOURCE.md` with guidance content from `05-SOURCE-OPSEC.md` and
the accessibility/i18n rules of `26-ACCESSIBILITY.md`.

This crate only renders. It holds no session state, does no cryptography and performs no
validation of submitted forms. C-06/C-07 own those. The crate turns a view model into exact
response bytes and headers.

## API

```rust
use candor_source_ui::{render, Locale, Screen, ViewModel};

let page = render(Screen::Landing, &view_model, &Locale::En)?;
// page.status, page.headers (exact §5.3 set), page.body (padded to P1/P2), page.class
```

* `Screen` is every screen in 11 §7: S01–S13, including S04b, S04b‑X, the two S05b pages and the
  mode-change page, S10/S10c/S10s, S11 login and inbox, the S11r steps, the three S13 variants
  with their result pages, Leave, S90–S94, and a 405 page.
* `ViewModel` holds a common `PageContext` (method, session-cookie presence, mode, org,
  form token, session timers, warning-banner inputs, errors), the `DeploymentInfo` statements,
  and one data struct per screen. All strings are treated as untrusted and are HTML-escaped.
* `Locale` is one of `en` (master), `en-XA`, `ar-XB` (RTL) or `en-XL`. The last three are
  pseudo-locales (`is_pseudo()`) for CI and previews only. A locale is chosen only by the path
  prefix (`Locale::from_tag`).
* `Page` contains the status, the headers, a body padded to exactly 65,536 or 131,072 bytes
  (`Zeroizing`, redacted in `Debug`), the size class and the unpadded length.
* `RenderError` makes rendering fail closed. Causes: a missing catalog string, an id or value
  that is not allow-listed, missing screen data (for example S10 without words), or a page over
  its class budget. C-06 answers with S92. Rendering never panics.
* Helpers:
  * `SizeClass::for_request(method, has_cookie)`: the class depends only on these two inputs.
  * `content_security_policy()`, `stylesheet()`, `stylesheet_hash()`, `PROHIBITED_HEADERS`.
  * `robots_txt()`: SW-20, padded to P1.
  * `classify(file_name)`: the 05 §7.2 file classes.
  * `default_questionnaire_step()`: the 11 §S05 default template.
  * `string_class(key)` / `catalog_keys()`: the review class of each string (tier0 / critical / ui).
  * `preview::sample_view_model()`: fictional fixtures.

The server must add only the `__Host-cs` cookie (§5.6). It must not add `Date`, `Server`, `ETag`,
`Last-Modified` or `Content-Encoding`. For HEAD it sends the same headers without a body.

## Design

* **askama** templates (`templates/`), compile-time checked with auto-escaping: one template per
  screen, plus `layout.html` (mode banner, warning banners, progress, footer) and small partials.
  Bold markup from catalogs (`**…**`) is applied after escaping, and untrusted placeables are
  shielded from it.
* **Stylesheet**: one hand-written file, `static/source.css`. It uses system fonts, logical
  properties only, a 3 px `:focus-visible` outline, `prefers-reduced-motion`, `forced-colors`,
  a dark scheme, and reflow at 320 CSS px. It is served inline after minification and pinned
  by `sha256` in the CSP.
* **No external resources.** The page has a `data:,` favicon and one decorative inline SVG.
  Every link or form action is built from the `Route` allow-list, with no query strings.
* **CSS-only behaviour.**
  * The JavaScript-on warning uses `@media (scripting: enabled)`.
  * The session timeout warnings use 0 s animations delayed to `T_IDLE − 5 min` and
    `T_ABS − 10 min`.
  * Guidance cards use `<details>`, and the higher-risk text sits in a nested `<details>`.
* **Catalogs**: Fluent (`locales/en/sui.ftl`, `locales/en/sops.ftl`), compiled in. Each message
  carries `# @class tier0` or `# @class critical`; messages without one are `ui`.

## Previews

```
cargo run -p candor-source-ui --example render_all
```

This writes every screen × locale × {anonymous, anonymous with errors, confidential,
identified} to `target/source-ui-preview/`, with an `index.html` that lists each page's
unpadded size and class.

## Tests

`cargo test -p candor-source-ui` runs unit tests, proptests and `tests/render.rs`. The checks are:

* Every screen renders for every locale, mode and error state, with no missing catalog keys.
* An output scan finds none of the following: `<script`, `on*=` attributes, `javascript:`,
  external or absolute-origin URLs, query strings, `style` attributes, a second `<style>`,
  iframe/object/embed/media/img elements, meta refresh, or storage APIs.
* html5ever parses every page with zero errors, and ids are unique.
* ARIA references and `#` links all resolve.
* Every control has a label, every fieldset has a legend, and every page has `lang`, `dir`,
  one `h1` and a skip link.
* Padding lands exactly on P1 or P2, and the size does not depend on content.
* The §5.3 header set is exact, and the CSP hash matches the served `<style>`.
* The mode banner text is correct for each mode, and the mode word leads `<title>`.
* Required honesty and warning strings appear on the screens that need them.
* Privacy defaults hold: ANONYMOUS is pre-selected, no COI tick, plain names on, next-pickup
  delivery.
* The passphrase display rules hold.
* The error-summary pattern is followed.
* Hostile content is escaped (fixed corpus plus proptest).
* RTL output is correct.
* Templates contain no hard-coded user-facing text.
* Tier‑0 and critical strings are flagged.
