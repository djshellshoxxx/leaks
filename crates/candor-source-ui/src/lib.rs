// SPDX-License-Identifier: AGPL-3.0-or-later
//! Candor Tier W source web UI (component C-06; spec `11-FRONTEND-SOURCE.md`).
//!
//! Server-rendered, zero-JavaScript pages built from compile-time-checked `askama`
//! templates with auto-escaping, a single hash-pinned inline stylesheet, Fluent message
//! catalogs, and the §5.4 response size classes.
//!
//! The entry point is [`render`]: it takes a [`Screen`], a [`ViewModel`] and a [`Locale`] and
//! returns a [`Page`] with the HTTP status, the exact §5.3 header set and the body padded to
//! its size class. Rendering fails closed ([`RenderError`]) on a missing catalog string, an
//! invalid id, or content over the class budget; it never panics.

mod files;
mod guidance;
mod locale;
mod model;
mod page;
mod routes;
mod screens;
mod view;

use core::fmt;

use zeroize::Zeroizing;

pub use files::{FileClass, classify};
pub use locale::{CatalogError, Dir, Locale, StringClass, catalog_keys, string_class};
pub use model::*;
pub use page::{
    MAX_CSS_BYTES, MAX_SVG_BYTES, OverBudget, PERMISSIONS_POLICY, PROHIBITED_HEADERS, Page,
    STYLESHEET, SizeClass, content_security_policy, pad_html, robots_txt, stylesheet_hash,
};
pub use routes::Route;
pub use screens::Screen;

/// Name of the hidden single-use form-token field (11 §5.7 `ft`; 08 SW-* `csrf`).
pub const FORM_TOKEN_FIELD: &str = "csrf";

/// Rendering failure. All variants are deployment or programming defects; C-06 answers with
/// the generic S92 page (itself rendered by [`render`]) and never shows details to the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    /// The catalog failed to build.
    Catalog(CatalogError),
    /// A catalog key or argument is missing for this locale (locale gate, 26 I18N-005).
    MissingStrings(Vec<String>),
    /// An id or form value in the view model is not allow-listed.
    InvalidId(String),
    /// Required screen data is missing (e.g. S10 without a passphrase).
    MissingData(&'static str),
    /// Template engine error.
    Template(String),
    /// The page exceeds its size-class budget.
    OverBudget(OverBudget),
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never include view-model content (it may hold source text or a passphrase).
        match self {
            RenderError::Catalog(_) => f.write_str("catalog error"),
            RenderError::MissingStrings(k) => write!(f, "{} missing catalog string(s)", k.len()),
            RenderError::InvalidId(_) => f.write_str("invalid id in view model"),
            RenderError::MissingData(what) => write!(f, "missing screen data: {what}"),
            RenderError::Template(_) => f.write_str("template error"),
            RenderError::OverBudget(o) => write!(f, "page over budget ({} bytes)", o.len),
        }
    }
}

impl std::error::Error for RenderError {}

fn validate(screen: Screen, vm: &ViewModel) -> Result<(), RenderError> {
    let bad = |what: &str| RenderError::InvalidId(what.to_owned());
    for e in &vm.ctx.errors {
        if !view::valid_id(&e.field) {
            return Err(bad("error field"));
        }
    }
    if let Some(t) = &vm.ctx.form_token {
        if !view::valid_value(t) {
            return Err(bad("form token"));
        }
    }
    match screen {
        Screen::Questionnaire => {
            for q in &vm.questionnaire.questions {
                if !view::valid_id(&q.id) {
                    return Err(bad("question id"));
                }
                if let QuestionKind::SingleChoice(opts) | QuestionKind::MultiChoice(opts) = &q.kind
                {
                    if opts.iter().any(|o| !view::valid_value(&o.value)) {
                        return Err(bad("choice value"));
                    }
                }
            }
        }
        Screen::NewReport => {
            if vm.new_report.channels.iter().any(|c| !view::valid_value(&c.id)) {
                return Err(bad("channel id"));
            }
        }
        Screen::Credential | Screen::RotateCredential => {
            let words = &vm.credential.passphrase.words;
            if words.is_empty() {
                return Err(RenderError::MissingData("passphrase"));
            }
            let lang = vm.credential.passphrase.wordlist_lang.as_str();
            if !lang.is_empty() && !view::valid_value(lang) {
                return Err(bad("wordlist language"));
            }
        }
        Screen::Confirm | Screen::RotateConfirm => {
            if vm.confirm.positions.contains(&0) {
                return Err(RenderError::MissingData("word positions"));
            }
        }
        Screen::Sent => {
            if vm.sent.is_none() {
                return Err(RenderError::MissingData("sent day"));
            }
        }
        _ => {}
    }
    Ok(())
}

/// Renders `screen` for `locale` and pads it to its size class.
///
/// The size class comes only from `vm.ctx.method` and `vm.ctx.has_session_cookie`
/// (11 §5.4), except the 405 page, which is always P1 (SUI-056).
pub fn render(screen: Screen, vm: &ViewModel, locale: &Locale) -> Result<Page, RenderError> {
    let cat = locale::catalog().map_err(RenderError::Catalog)?;
    validate(screen, vm)?;
    let mut pv = view::PageView::new(*locale, vm, screen, cat, STYLESHEET);
    pv.title = build_title(&pv, screen, vm);
    let html = Zeroizing::new(
        screens::render_template(&pv).map_err(|e| RenderError::Template(e.to_string()))?,
    );
    let missing = pv.take_missing();
    if !missing.is_empty() {
        return Err(RenderError::MissingStrings(missing));
    }
    let class = if screen == Screen::MethodNotAllowed {
        SizeClass::P1
    } else {
        SizeClass::for_request(vm.ctx.method, vm.ctx.has_session_cookie)
    };
    let body = pad_html(&html, class).map_err(RenderError::OverBudget)?;
    let headers = page::html_headers(locale.tag(), body.len(), screen.clears_site_data());
    Ok(Page {
        status: screen.status(),
        headers,
        body,
        class,
        unpadded_len: html.len(),
    })
}

fn build_title(pv: &view::PageView<'_>, screen: Screen, vm: &ViewModel) -> String {
    let mode = pv.t(vm.ctx.mode.word_key());
    let step = pv.t(&screen.title_key(vm));
    let title = pv.fmt_title(&mode, &step);
    if pv.has_error_summary() {
        pv.t1("sui-title-error", "title", title)
    } else {
        title
    }
}
